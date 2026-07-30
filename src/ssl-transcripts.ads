private with SSL.Crypto;

with SSL.Cipher_Suites;

--  @summary The handshake transcript: the exact octets of every handshake
--  message, in order, hashed.
--
--  The transcript is what binds a TLS 1.3 handshake together. Every derived
--  secret after the first is bound to it, both Finished messages authenticate
--  it, and CertificateVerify signs it. If two endpoints disagree about the
--  transcript by one octet they disagree about every key that follows, which is
--  the property that makes tampering with a handshake message detectable. So
--  the rules here are exacting, and they are all rules about exactness:
--
--    * what is absorbed is the handshake message -- one type octet, a
--      three-octet length, and the body -- and never the record header. Records
--      are a framing layer the transcript does not see, which is why a message
--      split across three records and the same message in one record produce
--      the same transcript.
--    * what is absorbed for a received message is the octets as received, not a
--      re-encoding of the parsed structure. A canonical re-encode would differ
--      from what the peer hashed wherever the peer's encoder differed from
--      ours, and the handshake would fail with no way to see why.
--    * what is absorbed for a sent message is the octets queued, for the same
--      reason from the other side.
--    * a snapshot does not finalize. TLS 1.3 derives from the transcript at
--      several named points and goes on hashing afterwards.
--
--  Both hash algorithms run in parallel until the cipher suite is chosen.
--
--  A client sends its ClientHello before it knows which suite the server will
--  pick, and the transcript hash is the negotiated suite's hash -- so at the
--  moment the first message is hashed, which hash to use is not yet known. The
--  alternatives are to buffer the ClientHello until ServerHello arrives, or to
--  hash it under both. Hashing under both costs one extra SHA of a two-hundred
--  octet message and removes a buffer whose size a peer would influence.
private package SSL.Transcripts is

   type Transcript is limited private;

   --  Begin a transcript. Both hashes start; neither is selected yet, so
   --  Hash must not be called until Select_Algorithm has been.
   procedure Start (Item : out Transcript);

   --  Fix which hash the transcript reports, once the cipher suite is known.
   --  Both hashes go on being fed, so this may be called at any point and the
   --  answer is the same as if it had been called first.
   --  @param Item      the transcript
   --  @param Algorithm the negotiated suite's hash
   procedure Select_Algorithm
     (Item : in out Transcript; Algorithm : SSL.Cipher_Suites.Hash_Algorithm)
     with Post => Has_Algorithm (Item);

   --  Has the hash been fixed?
   function Has_Algorithm (Item : Transcript) return Boolean;

   function Algorithm_Of (Item : Transcript) return SSL.Cipher_Suites.Hash_Algorithm
     with Pre => Has_Algorithm (Item);

   --  Absorb one complete handshake message: type, three-octet length, body.
   --
   --  The caller passes the exact octets. This procedure does not check that
   --  the length field agrees with the octet count, because the parser that
   --  produced the octets has already done so and a second check here would be
   --  a second opinion about the same bytes.
   --  @param Item the transcript
   --  @param Data the handshake message, at least four octets
   procedure Absorb (Item : in out Transcript; Data : Byte_Array)
     with Pre => Data'Length >= 4;

   --  How many octets have been absorbed, for bounding a transcript against a
   --  peer that sends an unbounded run of handshake messages.
   function Absorbed (Item : Transcript) return Byte_Index;

   --  The transcript hash as it stands, without finalizing.
   --  @param Item the transcript
   --  @param Into out: receives exactly the selected hash's digest length
   procedure Hash (Item : Transcript; Into : out Byte_Array)
     with Pre => Has_Algorithm (Item)
                 and then Into'Length
                          = SSL.Cipher_Suites.Digest_Length (Algorithm_Of (Item));

   --  The transcript hash as a value, for passing straight to a derivation.
   function Hash (Item : Transcript) return Byte_Array
     with Pre => Has_Algorithm (Item),
          Post => Hash'Result'Length
                  = SSL.Cipher_Suites.Digest_Length (Algorithm_Of (Item));

   --  Replace the transcript with the synthetic message_hash form that
   --  HelloRetryRequest requires (RFC 8446 section 4.4.1).
   --
   --  After a HelloRetryRequest the transcript is not ClientHello1 followed by
   --  everything else; it is
   --
   --      Hash(message_hash || 00 00 <Hash.length> || Hash(ClientHello1))
   --
   --  followed by HelloRetryRequest and the rest. The reason is not
   --  cosmetic: the server has to be able to reconstruct the transcript from
   --  the second ClientHello alone, because a stateless server that answered
   --  with a cookie has kept nothing else, and a digest of the first
   --  ClientHello is what the cookie can carry.
   --
   --  Called exactly once, immediately after ClientHello1 has been absorbed and
   --  before HelloRetryRequest is. Both hash states are transformed, since which
   --  one will be selected may still be open.
   --  @param Item the transcript, holding exactly ClientHello1
   procedure Apply_Hello_Retry_Transform (Item : in out Transcript)
     with Pre => not Transformed (Item);

   --  Has the HelloRetryRequest transform been applied? Used to enforce that it
   --  happens at most once, which is the check that stops a peer from driving
   --  an unbounded retry loop.
   function Transformed (Item : Transcript) return Boolean;

private

   --  The message type of the synthetic message_hash message
   --  (RFC 8446 section 4.4.1).
   Message_Hash_Type : constant := 254;

   type Transcript is limited record
      Selected  : Boolean := False;
      Algorithm : SSL.Cipher_Suites.Hash_Algorithm := SSL.Cipher_Suites.SHA_256;
      Changed   : Boolean := False;
      Count     : Byte_Index := 0;

      --  One context per candidate hash. SSL.Crypto.Hash_Context already holds
      --  both CryptoLib states internally, so this is two of those and not
      --  four; the duplication is in the interface, not the storage.
      SHA256_State : SSL.Crypto.Hash_Context;
      SHA384_State : SSL.Crypto.Hash_Context;
   end record;

end SSL.Transcripts;
