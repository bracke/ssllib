with SSL.Cipher_Suites;
with SSL.Errors;
with SSL.Secrets;

--  @summary The TLS 1.2 key derivation: the PRF, the extended master secret,
--  the key block, and the Finished verify data.
--
--  A separate package from `SSL.Key_Schedule` because TLS 1.2 and TLS 1.3
--  derive keys in entirely different ways, and a single package covering both
--  would be two implementations sharing a name. TLS 1.2 has one function --
--  P_hash, iterated HMAC -- applied to everything, whereas TLS 1.3 has a
--  labelled chain of extractions and expansions. Nothing about one informs the
--  other.
--
--  **This library's TLS 1.2 is deliberately restricted**, and the restrictions
--  are what make it defensible to implement at all:
--
--    * **ECDHE only.** No static RSA, no static or anonymous DH. Every
--      handshake has forward secrecy.
--    * **AEAD only.** No CBC, so no MAC-then-encrypt, so none of the padding
--      oracles that decade of attacks was about.
--    * **Extended master secret is mandatory.** RFC 7627. A peer that will not
--      negotiate it is refused, because without it the master secret is not
--      bound to the handshake and the triple-handshake attack works.
--    * **SHA-256 and SHA-384 only.** No MD5, no SHA-1, and no MD5/SHA-1
--      concatenation.
private package SSL.TLS12 is

   ---------------------------------------------------------------------------
   --  What a TLS 1.2 machine answers with
   ---------------------------------------------------------------------------

   --  One thing the driver must do, in the order it must do it.
   --
   --  The vocabulary is close to TLS 1.3's and deliberately separate from it,
   --  because one item differs and the difference is the whole epoch model.
   --  `Send_Change_Cipher_Spec` here is the real epoch switch: the record after
   --  it uses the new keys, and a driver that treated it as the decorative
   --  TLS 1.3 one would send its Finished in the clear.
   type Step_Kind is
     (Send_Handshake,
      --  A span of the output buffer holding one complete handshake message,
      --  already absorbed into the transcript.

      Send_Change_Cipher_Spec,
      --  The epoch switch. Not in the transcript -- it is not a handshake
      --  message -- and everything after it is protected.

      Install_Write_Keys,
      Install_Read_Keys,
      --  The write keys go in immediately after the ChangeCipherSpec is
      --  queued; the read keys when the peer's arrives.

      Handshake_Complete);

   type Step is record
      Kind  : Step_Kind := Handshake_Complete;
      First : Byte_Index := 1;
      Last  : Byte_Index := 0;
   end record;

   Maximum_Steps : constant := 16;

   type Step_Array is array (1 .. Maximum_Steps) of Step;

   type Plan is record
      Count : Natural range 0 .. Maximum_Steps := 0;
      Steps : Step_Array := [others => <>];
   end record;

   function Is_Empty (Item : Plan) return Boolean is (Item.Count = 0);

   procedure Add
     (Item  : in out Plan;
      Kind  : Step_Kind;
      First : Byte_Index := 1;
      Last  : Byte_Index := 0)
     with Pre => Item.Count < Maximum_Steps;

   ---------------------------------------------------------------------------
   --  The pseudo-random function
   ---------------------------------------------------------------------------

   --  RFC 5246 section 5: P_hash expanded to the requested length, under the
   --  suite's own hash.
   --
   --      PRF(secret, label, seed) = P_hash(secret, label || seed)
   --      P_hash(secret, seed) = HMAC(secret, A(1) || seed)
   --                          || HMAC(secret, A(2) || seed) || ...
   --      A(0) = seed, A(i) = HMAC(secret, A(i-1))
   --
   --  TLS 1.2 replaced 1.1's MD5/SHA-1 split with a single hash chosen by the
   --  cipher suite, which is why this takes the algorithm rather than assuming
   --  one.
   --  @param Algorithm the suite's hash
   --  @param Secret    the secret to expand from
   --  @param Label     the ASCII label, which is part of the seed
   --  @param Seed      the rest of the seed
   --  @param Into      out: exactly Into'Length octets of output
   --  @param Error     out: No_Error, or a derivation failure
   procedure PRF
     (Algorithm : SSL.Cipher_Suites.Hash_Algorithm;
      Secret    : SSL.Secrets.Secret;
      Label     : String;
      Seed      : Byte_Array;
      Into      : out Byte_Array;
      Error     : out SSL.Errors.Error_Information)
     with Pre => Label'Length > 0 and then Into'Length in 1 .. 512;

   ---------------------------------------------------------------------------
   --  The master secret
   ---------------------------------------------------------------------------

   --  A TLS 1.2 master secret is always 48 octets, whatever the hash.
   Master_Secret_Length : constant Byte_Index := 48;

   --  Derive the extended master secret (RFC 7627).
   --
   --      master_secret = PRF(pre_master_secret,
   --                          "extended master secret",
   --                          session_hash)
   --
   --  The session hash is the handshake transcript through ClientKeyExchange.
   --  This is the *only* master-secret derivation here: the original RFC 5246
   --  form, which seeds with the two randoms instead, is not implemented and
   --  will not be. Without the transcript in the derivation the master secret
   --  is not bound to the handshake that produced it, and two connections can
   --  be made to share one -- which is the triple-handshake attack.
   --  @param Algorithm    the suite's hash
   --  @param Premaster    the ECDHE shared secret
   --  @param Session_Hash the transcript hash through ClientKeyExchange
   --  @param Into         in out: receives the 48-octet master secret
   --  @param Error        out: No_Error, or a derivation failure
   procedure Derive_Extended_Master
     (Algorithm    : SSL.Cipher_Suites.Hash_Algorithm;
      Premaster    : SSL.Secrets.Secret;
      Session_Hash : Byte_Array;
      Into         : in out SSL.Secrets.Secret;
      Error        : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  The key block
   ---------------------------------------------------------------------------

   --  What one direction needs to protect records.
   --
   --  An AEAD suite has no MAC key -- the AEAD provides the authentication --
   --  so the block is two keys and two fixed IV halves and nothing else. A CBC
   --  suite would need MAC keys as well, and this library has no CBC suites.
   type Direction_Keys is limited record
      Key : SSL.Secrets.Secret (SSL.Secrets.Traffic_Capacity);

      --  The four-octet fixed half of the nonce. TLS 1.2's AEAD nonce is this
      --  followed by an eight-octet explicit part, which is a real difference
      --  from TLS 1.3's twelve-octet static IV exclusive-ored with the
      --  sequence number.
      Fixed_IV        : Byte_Array (1 .. 12) := [others => 0];
      Fixed_IV_Length : Byte_Index range 0 .. 12 := 0;
   end record;

   procedure Wipe (Item : in out Direction_Keys);

   --  Expand the key block and split it, in the order RFC 5246 section 6.3
   --  fixes: client write key, server write key, client write IV, server write
   --  IV. Getting the order wrong yields two ends that each encrypt with the
   --  other's key, which fails at the first record and gives no clue why.
   --  @param Suite         the negotiated suite
   --  @param Master        the master secret
   --  @param Client_Random the client's 32 random octets
   --  @param Server_Random the server's 32 random octets
   --  @param Client_Side   in out: the client's write keys
   --  @param Server_Side   in out: the server's write keys
   --  @param Error         out: No_Error, or a derivation failure
   procedure Derive_Key_Block
     (Suite         : SSL.Cipher_Suites.Cipher_Suite;
      Master        : SSL.Secrets.Secret;
      Client_Random : Byte_Array;
      Server_Random : Byte_Array;
      Client_Side   : in out Direction_Keys;
      Server_Side   : in out Direction_Keys;
      Error         : out SSL.Errors.Error_Information)
     with Pre => Client_Random'Length = 32 and then Server_Random'Length = 32;

   ---------------------------------------------------------------------------
   --  Finished
   ---------------------------------------------------------------------------

   --  TLS 1.2 verify data is twelve octets for every suite, which is shorter
   --  than the hash and is the specification's own choice.
   Verify_Data_Length : constant Byte_Index := 12;

   type Finished_Party is (Client_Finished, Server_Finished);

   --  Compute a Finished message's verify data.
   --
   --      PRF(master_secret, "client finished" | "server finished",
   --          Hash(handshake_messages))[0 .. 11]
   --
   --  @param Algorithm       the suite's hash
   --  @param Master          the master secret
   --  @param Which           whose Finished
   --  @param Transcript_Hash the handshake transcript hash at this point
   --  @param Into            out: the twelve octets
   --  @param Error           out: No_Error, or a derivation failure
   procedure Compute_Finished
     (Algorithm       : SSL.Cipher_Suites.Hash_Algorithm;
      Master          : SSL.Secrets.Secret;
      Which           : Finished_Party;
      Transcript_Hash : Byte_Array;
      Into            : out Byte_Array;
      Error           : out SSL.Errors.Error_Information)
     with Pre => Into'Length = Verify_Data_Length;

   ---------------------------------------------------------------------------
   --  The signed ServerKeyExchange parameters
   ---------------------------------------------------------------------------

   --  The exact octets a ServerKeyExchange signature covers.
   --
   --      client_random || server_random || ServerECDHParams
   --
   --  where ServerECDHParams is the curve type, the named curve and the
   --  length-prefixed public point, exactly as they appear in the message. The
   --  two randoms are what stop a signature being replayed into another
   --  handshake; the parameters are what it is actually about. Assembling this
   --  from anything other than the octets that were sent -- re-encoding the
   --  parameters, say -- produces a signature over something the peer did not
   --  sign.
   --  @param Client_Random the client's 32 random octets
   --  @param Server_Random the server's 32 random octets
   --  @param Parameters    the ServerECDHParams exactly as they appeared
   --  @return the octets to sign or verify
   function Key_Exchange_Signed_Content
     (Client_Random : Byte_Array;
      Server_Random : Byte_Array;
      Parameters    : Byte_Array) return Byte_Array
     with Pre => Client_Random'Length = 32 and then Server_Random'Length = 32,
          Post => Key_Exchange_Signed_Content'Result'Length = 64 + Parameters'Length;

end SSL.TLS12;
