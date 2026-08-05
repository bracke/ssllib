private with CryptoLib.Curve25519;
private with CryptoLib.Hashes;
private with CryptoLib.Random;

with SSL.Cipher_Suites;
with SSL.Errors;
with SSL.Secrets;
with SSL.Signature_Schemes;
with SSL.Supported_Groups;

--  @summary The single seam between this library and CryptoLib.
--
--  Every hash, MAC, KDF, AEAD, key agreement, signature and random draw goes
--  through here, and nowhere else in ssllib calls CryptoLib directly for those
--  operations. That is what makes the ownership boundary checkable rather than
--  aspirational: a dependency audit greps for "CryptoLib." outside this unit and
--  the certificate/trust adapters, and expects to find nothing.
--
--  The translation this package does is narrow on purpose. It maps ssllib's
--  algorithm identities onto CryptoLib's, turns CryptoLib.Errors.Status into
--  structured SSL.Errors values, and keeps secret material inside
--  SSL.Secrets.Secret so that no intermediate is left on a stack frame nobody
--  scrubs. It implements no cryptography: there is no arithmetic in the body of
--  this package, only calls and error mapping.
--
--  Randomness comes from a source the caller holds, so that a test can supply a
--  deterministic one without this library reading the operating system behind
--  the test's back.
private package SSL.Crypto is

   ---------------------------------------------------------------------------
   --  Randomness
   ---------------------------------------------------------------------------

   --  A source of random octets. Wraps CryptoLib.Random.Random_Source so that
   --  the engine holds one by value and a test can install a deterministic one.
   type Random_Source is limited private;

   --  Draw from the operating-system CSPRNG. The only mode a production
   --  configuration uses.
   procedure Use_System_Entropy (Item : out Random_Source);

   --  Repeat a fixed pattern. Tests only, and the type carries the fact so a
   --  diagnostic can say a connection was built on a test source.
   procedure Use_Fixed_Pattern (Item : out Random_Source; Pattern : Byte_Array);

   --  Fail every draw. Tests only, for the fail-closed paths.
   procedure Use_Failing_Source (Item : out Random_Source);

   --  Is this a production source?
   function Is_System_Entropy (Item : Random_Source) return Boolean;

   --  Fill a buffer with random octets.
   --  @param Item   the source, advanced
   --  @param Into   out: the octets; zeroed on failure
   --  @param Error  out: No_Error, or a Code_Random_Source_Failed failure
   procedure Fill
     (Item  : in out Random_Source;
      Into  : out Byte_Array;
      Error : out SSL.Errors.Error_Information);

   --  Fill a secret with random octets, without an intermediate named copy.
   procedure Fill_Secret
     (Item   : in out Random_Source;
      Target : in out SSL.Secrets.Secret;
      Length : SSL.Secrets.Secret_Length;
      Error  : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  Hashing
   ---------------------------------------------------------------------------

   subtype Hash_Algorithm is SSL.Cipher_Suites.Hash_Algorithm;

   --  A running hash over a byte stream. Used for the handshake transcript,
   --  which is hashed incrementally and snapshotted without being finalized.
   type Hash_Context is private;

   procedure Start (Item : out Hash_Context; Algorithm : Hash_Algorithm);

   procedure Update (Item : in out Hash_Context; Data : Byte_Array);

   --  The digest of everything absorbed so far, leaving the context able to
   --  absorb more. This is what a transcript snapshot needs: TLS 1.3 derives
   --  secrets from the transcript at several points and then keeps hashing.
   --  @param Item the context, unchanged
   --  @param Into out: receives exactly the algorithm's digest length
   procedure Snapshot (Item : Hash_Context; Into : out Byte_Array)
     with Pre => Into'Length = SSL.Cipher_Suites.Digest_Length (Algorithm_Of (Item));

   --  A snapshot as a value, for the call sites that pass it straight on.
   function Snapshot (Item : Hash_Context) return Byte_Array
     with Post => Snapshot'Result'Length
                  = SSL.Cipher_Suites.Digest_Length (Algorithm_Of (Item));

   function Algorithm_Of (Item : Hash_Context) return Hash_Algorithm;

   --  How many octets absorbed. For bounding a transcript.
   function Absorbed (Item : Hash_Context) return Byte_Index;

   --  One-shot digest.
   function Digest (Algorithm : Hash_Algorithm; Data : Byte_Array) return Byte_Array
     with Post => Digest'Result'Length = SSL.Cipher_Suites.Digest_Length (Algorithm);

   --  SHA-256, SHA-384 and SHA-512 one-shot, for the signature hashes and for
   --  fingerprints. Separate from Hash_Algorithm because a signature hash and a
   --  key-schedule hash are different choices and SHA-512 is not a
   --  key-schedule hash.
   function SHA_256 (Data : Byte_Array) return Byte_Array
     with Post => SHA_256'Result'Length = 32;
   function SHA_384 (Data : Byte_Array) return Byte_Array
     with Post => SHA_384'Result'Length = 48;
   function SHA_512 (Data : Byte_Array) return Byte_Array
     with Post => SHA_512'Result'Length = 64;

   ---------------------------------------------------------------------------
   --  MAC
   ---------------------------------------------------------------------------

   --  HMAC under the key-schedule hash, keyed by a secret. Used for the
   --  Finished messages and the PSK binder.
   --  @param Algorithm the hash
   --  @param Key       the Finished or binder key
   --  @param Data      the transcript hash being authenticated
   --  @param Into      out: receives exactly the digest length
   procedure HMAC
     (Algorithm : Hash_Algorithm;
      Key       : SSL.Secrets.Secret;
      Data      : Byte_Array;
      Into      : out Byte_Array)
     with Pre => Into'Length = SSL.Cipher_Suites.Digest_Length (Algorithm);

   --  HMAC keyed by octets rather than a secret, for the TLS 1.2 PRF where the
   --  key is a secret already held elsewhere and an intermediate copy would be
   --  the leak.
   procedure HMAC_Octets
     (Algorithm : Hash_Algorithm;
      Key       : Byte_Array;
      Data      : Byte_Array;
      Into      : out Byte_Array)
     with Pre => Into'Length = SSL.Cipher_Suites.Digest_Length (Algorithm);

   --  Constant-time comparison, for every place a MAC or tag is checked.
   function Equal (Left : Byte_Array; Right : Byte_Array) return Boolean;

   --  Overwrite a local buffer that has held secret material, through volatile
   --  stores the optimizer may not remove.
   --
   --  A plain "Buffer := [others => 0]" before a return is a dead store and is
   --  deleted at -O2 and above: it zeroes nothing. Every unit in this library
   --  that puts a secret in a local Byte_Array scrubs it through here.
   --  @param Data the buffer to overwrite
   procedure Scrub (Data : in out Byte_Array);

   ---------------------------------------------------------------------------
   --  Key derivation
   --
   --  These are the TLS 1.3 primitives, not the schedule: composing them into
   --  the early/handshake/master chain is SSL.Key_Schedule's job, and CryptoLib
   --  deliberately declines to do it.
   ---------------------------------------------------------------------------

   --  HKDF-Extract (RFC 5869 section 2.2).
   procedure Extract
     (Algorithm : Hash_Algorithm;
      Salt      : Byte_Array;
      Input     : Byte_Array;
      Target    : in out SSL.Secrets.Secret;
      Error     : out SSL.Errors.Error_Information);

   --  HKDF-Extract where the input keying material is itself a secret.
   procedure Extract_From_Secret
     (Algorithm : Hash_Algorithm;
      Salt      : Byte_Array;
      Input     : SSL.Secrets.Secret;
      Target    : in out SSL.Secrets.Secret;
      Error     : out SSL.Errors.Error_Information);

   --  HKDF-Expand-Label (RFC 8446 section 7.1). The "tls13 " prefix is added by
   --  CryptoLib, so Label is passed as the RFC writes it.
   procedure Expand_Label
     (Algorithm : Hash_Algorithm;
      Secret    : SSL.Secrets.Secret;
      Label     : String;
      Context   : Byte_Array;
      Target    : in out SSL.Secrets.Secret;
      Length    : SSL.Secrets.Secret_Length;
      Error     : out SSL.Errors.Error_Information);

   --  Expand-Label writing into caller octets, for exporter output which the
   --  application owns.
   procedure Expand_Label_Into
     (Algorithm : Hash_Algorithm;
      Secret    : SSL.Secrets.Secret;
      Label     : String;
      Context   : Byte_Array;
      Into      : out Byte_Array;
      Error     : out SSL.Errors.Error_Information);

   --  Derive-Secret (RFC 8446 section 7.1) from a transcript hash the caller
   --  already holds.
   procedure Derive_Secret
     (Algorithm       : Hash_Algorithm;
      Secret          : SSL.Secrets.Secret;
      Label           : String;
      Transcript_Hash : Byte_Array;
      Target          : in out SSL.Secrets.Secret;
      Error           : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  AEAD
   ---------------------------------------------------------------------------

   subtype AEAD_Algorithm is SSL.Cipher_Suites.AEAD_Algorithm;

   --  Seal: encrypt and authenticate.
   --  @param Algorithm  which AEAD
   --  @param Key        the traffic key, exactly the AEAD's key length
   --  @param Nonce      the per-record nonce, twelve octets, never repeated
   --  @param Additional the record header, authenticated and not encrypted
   --  @param Plaintext  the inner plaintext
   --  @param Wire       out: ciphertext followed by the tag, exactly
   --    Plaintext'Length + 16 octets; zeroed on failure
   --  @param Error      out: No_Error, or Code_AEAD_Operation_Failed
   procedure Seal
     (Algorithm  : AEAD_Algorithm;
      Key        : SSL.Secrets.Secret;
      Nonce      : Byte_Array;
      Additional : Byte_Array;
      Plaintext  : Byte_Array;
      Wire       : out Byte_Array;
      Error      : out SSL.Errors.Error_Information)
     with Pre => Nonce'Length = 12
                 and then Wire'Length = Plaintext'Length + 16;

   --  Open: authenticate and decrypt. The tag is verified before any plaintext
   --  is produced, so a forgery yields nothing to discard. On failure the
   --  output is zeroed and the caller must not treat it as plaintext.
   --  @param Algorithm  which AEAD
   --  @param Key        the traffic key
   --  @param Nonce      the per-record nonce
   --  @param Additional the record header as received
   --  @param Wire       ciphertext followed by the tag
   --  @param Plaintext  out: exactly Wire'Length - 16 octets; zeroed on failure
   --  @param Error      out: No_Error, or Code_Record_Authentication_Failed
   procedure Open
     (Algorithm  : AEAD_Algorithm;
      Key        : SSL.Secrets.Secret;
      Nonce      : Byte_Array;
      Additional : Byte_Array;
      Wire       : Byte_Array;
      Plaintext  : out Byte_Array;
      Error      : out SSL.Errors.Error_Information)
     with Pre => Nonce'Length = 12
                 and then Wire'Length >= 16
                 and then Plaintext'Length = Wire'Length - 16;

   ---------------------------------------------------------------------------
   --  Key agreement
   ---------------------------------------------------------------------------

   --  One ephemeral key-exchange keypair. Limited and controlled: it holds a
   --  private scalar, and it scrubs it.
   type Key_Exchange_Pair is limited private;

   --  Generate a keypair for a group.
   --  @param Item   out: the keypair
   --  @param Group  which group
   --  @param Source the random source
   --  @param Error  out: No_Error, or Code_Key_Agreement_Failed
   procedure Generate
     (Item   : in out Key_Exchange_Pair;
      Group  : SSL.Supported_Groups.Named_Group;
      Source : in out Random_Source;
      Error  : out SSL.Errors.Error_Information);

   --  Has a keypair been generated?
   function Is_Generated (Item : Key_Exchange_Pair) return Boolean;

   --  Which group the keypair is for.
   function Group_Of (Item : Key_Exchange_Pair) return SSL.Supported_Groups.Named_Group
     with Pre => Is_Generated (Item);

   --  The public share, in the encoding a key_share entry carries.
   function Public_Share (Item : Key_Exchange_Pair) return Byte_Array
     with Pre => Is_Generated (Item),
          Post => Public_Share'Result'Length
                  = SSL.Supported_Groups.Share_Length (Group_Of (Item));

   --  Compute the shared secret from a peer's share.
   --
   --  The peer's share is validated for the group first, and each family has its
   --  own answer to what that means. Length always. For the NIST curves, the
   --  point encoding and the on-curve check, which CryptoLib does. For X25519, a
   --  result of all zeroes is rejected, as RFC 7748 section 6.1 and RFC 8446
   --  section 7.4.2 require. For the finite-field groups, 1 < Y < p-1 as
   --  RFC 8446 section 4.2.8.1 requires, and a shared secret of 1 or p-1, both
   --  of which CryptoLib checks.
   --  @param Item       the local keypair
   --  @param Peer_Share the peer's key_share entry
   --  @param Target     in out: receives the shared secret
   --  @param Error      out: No_Error, or Code_Key_Agreement_Failed
   procedure Agree
     (Item       : Key_Exchange_Pair;
      Peer_Share : Byte_Array;
      Target     : in out SSL.Secrets.Secret;
      Error      : out SSL.Errors.Error_Information)
     with Pre => Is_Generated (Item);

   --  Scrub the private scalar now rather than at end of scope.
   procedure Wipe (Item : in out Key_Exchange_Pair);

   ---------------------------------------------------------------------------
   --  Signature verification
   --
   --  Signing lives in SSL.Credentials, because it needs the private key and
   --  the external-signer seam. Verification is here, because it needs only a
   --  public key and is used from the certificate path as well as from
   --  CertificateVerify.
   ---------------------------------------------------------------------------

   --  Verify a handshake signature against a public key.
   --  @param Scheme       the signature scheme, which fixes padding and hash
   --  @param Public_Key   the key, in the encoding CryptoLib's X.509 layer
   --    produces: a point for ECDSA and EdDSA, a DER RSAPublicKey for RSA
   --  @param Signed_Data  the exact octets that were signed
   --  @param Signature    the signature as it arrived on the wire
   --  @param Error        out: No_Error, or Code_Signature_Verification_Failed
   procedure Verify_Signature
     (Scheme      : SSL.Signature_Schemes.Signature_Scheme;
      Public_Key  : Byte_Array;
      Signed_Data : Byte_Array;
      Signature   : Byte_Array;
      Error       : out SSL.Errors.Error_Information);

private

   --  The private parts hold CryptoLib types directly, reached through private
   --  with clauses so that they are nameable here and nowhere else. That is the
   --  boundary this package exists to hold: a unit outside SSL.Crypto cannot
   --  name a CryptoLib cryptographic type even by accident.

   type Source_Kind is (System_Entropy, Fixed_Pattern, Failing);

   type Random_Source is limited record
      Kind  : Source_Kind := System_Entropy;
      State : CryptoLib.Random.Random_Source;
   end record;

   --  Both hash states are held rather than a variant, because a variant on the
   --  algorithm would make the record mutably discriminated and the saving is
   --  two hundred octets on an object there is one of per connection.
   --
   --  Snapshot copies the context and finalizes the copy: CryptoLib's Finalize
   --  pads and consumes, and a transcript has to be readable at several points
   --  and go on absorbing afterwards.
   type Hash_Context is record
      Algorithm : Hash_Algorithm := SSL.Cipher_Suites.SHA_256;
      Count     : Byte_Index := 0;
      SHA256    : CryptoLib.Hashes.SHA256_Context;
      SHA384    : CryptoLib.Hashes.SHA384_Context;
   end record;

   --  The widest key share this library will produce or accept: an ffdhe4096
   --  public value, at 512 octets. The elliptic-curve shares are at most 133.
   Maximum_Share_Length : constant Byte_Index := 512;

   type Key_Exchange_Pair is limited record
      Generated : Boolean := False;
      Group     : SSL.Supported_Groups.Named_Group := SSL.Supported_Groups.X25519;

      --  X25519 keeps its private key in CryptoLib's own opaque type, which
      --  clears itself. The NIST curves and the finite-field groups hand back a
      --  private scalar or exponent as octets, which is held in a Secret so that
      --  it is scrubbed on the same terms as everything else secret here.
      Montgomery_Private : CryptoLib.Curve25519.Private_Key;
      Scalar             : SSL.Secrets.Secret (SSL.Secrets.Agreement_Capacity);

      Share      : Byte_Array (1 .. Maximum_Share_Length) := [others => 0];
      Share_Used : Byte_Index range 0 .. Maximum_Share_Length := 0;
   end record;

end SSL.Crypto;
