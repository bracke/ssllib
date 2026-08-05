private with Ada.Finalization;
private with CryptoLib.Identities;
private with CryptoLib.PKCS8;
private with SSL.Secrets;

with SSL.Errors;
with SSL.Limits;
with SSL.Server_Names;
with SSL.Signature_Schemes;

--  @summary A local certificate chain and the signing capability that goes with
--  it: what this endpoint presents, and what proves it owns it.
--
--  A credential holds a private key, so it is limited and controlled and it
--  scrubs itself. There is no operation that returns the key, no operation that
--  returns any parameter of it, and no operation that returns anything from
--  which it could be reconstructed. What a caller can do is ask what the
--  credential is capable of and ask it to sign; the key never leaves.
--
--  **Everything expensive happens at load time.** Reading a file, decrypting a
--  PKCS#8 blob, deriving a key from a password, checking that the certificate
--  and the key belong together, checking the chain hangs together, working out
--  which signature schemes the key can actually produce -- all of it happens
--  when the credential is built, and none of it happens during a handshake. A
--  handshake that had to read a file would be a handshake that could block on a
--  disk, and one that had to prompt for a password would be one that could
--  block on a human.
--
--  The structural checks are CryptoLib's. `CryptoLib.Identities` answers whether
--  the key matches the leaf and whether the chain is in the right order, which
--  are the two configuration mistakes that otherwise surface at the first
--  handshake against the first peer that cares.
package SSL.Credentials is

   ---------------------------------------------------------------------------
   --  What a credential can do
   ---------------------------------------------------------------------------

   --  The key types this library can hold and present.
   type Key_Kind is (RSA_Key, ECDSA_P256, ECDSA_P384, ECDSA_P521, Ed25519_Key, Ed448_Key);

   function Image (Item : Key_Kind) return String;

   --  A credential, complete with its chain and its key.
   type Credential is limited private;

   --  Has this credential been loaded and checked?
   function Is_Loaded (Item : Credential) return Boolean;

   --  What kind of key it holds.
   function Key_Type (Item : Credential) return Key_Kind
     with Pre => Is_Loaded (Item);

   --  How many certificates the chain holds, leaf first.
   function Chain_Length (Item : Credential) return Positive
     with Pre => Is_Loaded (Item);

   --  One certificate's DER, leaf at index one. Public material; a chain is
   --  sent in the clear in TLS 1.2 and under handshake keys in TLS 1.3, and
   --  either way the peer sees it.
   function Certificate_At (Item : Credential; Index : Positive) return Byte_Array
     with Pre => Is_Loaded (Item) and then Index <= Chain_Length (Item);

   --  The leaf's SHA-256 fingerprint, and its SubjectPublicKeyInfo
   --  fingerprint, for pinning and for diagnostics.
   function Leaf_Fingerprint (Item : Credential) return Certificate_Fingerprint
     with Pre => Is_Loaded (Item);
   function Public_Key_Fingerprint (Item : Credential) return Certificate_Fingerprint
     with Pre => Is_Loaded (Item);

   --  Can this credential produce a signature under this scheme?
   --
   --  Decided at load time from the key type, the key size and, for ECDSA, the
   --  curve -- RFC 8446 section 4.2.3 binds each ECDSA scheme to one curve, so a
   --  P-256 key can produce ecdsa_secp256r1_sha256 and nothing else.
   function Supports
     (Item : Credential; Scheme : SSL.Signature_Schemes.Signature_Scheme) return Boolean
     with Pre => Is_Loaded (Item);

   --  The schemes this credential can produce, in this library's preference
   --  order. Empty is impossible for a loaded credential: a key that could sign
   --  nothing is refused at load.
   function Supported_Schemes (Item : Credential) return SSL.Signature_Schemes.Scheme_List
     with Pre => Is_Loaded (Item),
          Post => not SSL.Signature_Schemes.Is_Empty (Supported_Schemes'Result);

   --  The identities this credential may be presented for: the leaf's
   --  subjectAltName DNS entries, as a server uses them to route on SNI.
   function Identity_Count (Item : Credential) return Natural
     with Pre => Is_Loaded (Item);
   function Identity_At (Item : Credential; Index : Positive) return SSL.Server_Names.DNS_Name
     with Pre => Is_Loaded (Item) and then Index <= Identity_Count (Item);

   --  Does this credential cover a name, and how specifically?
   --
   --  Zero means it does not. Higher is more specific, so a server choosing
   --  between several credentials for one SNI name takes the highest -- an exact
   --  match ahead of any wildcard, and a narrower wildcard ahead of a broader
   --  one. See SSL.Server_Names.Match_Specificity.
   function Covers (Item : Credential; Name : SSL.Server_Names.DNS_Name) return Natural
     with Pre => Is_Loaded (Item);

   ---------------------------------------------------------------------------
   --  Loading
   --
   --  No entry point here reads a file. The caller supplies the octets, which
   --  keeps the filesystem the caller's business and makes a credential
   --  loadable from a secret manager, an environment the caller controls, or a
   --  test fixture, with no code path in this library that touches a disk.
   ---------------------------------------------------------------------------

   --  Load from PEM: a certificate chain, leaf first, and an unencrypted
   --  PKCS#8 private key.
   --  @param Item      the credential to load into
   --  @param Chain_PEM one or more CERTIFICATE blocks, leaf first
   --  @param Key_PEM   one PRIVATE KEY block
   --  @param Bounds    the limits in force
   --  @param Error     out: No_Error, or what is wrong with the material
   procedure Load_PEM
     (Item      : in out Credential;
      Chain_PEM : String;
      Key_PEM   : String;
      Bounds    : SSL.Limits.Resource_Limits;
      Error     : out SSL.Errors.Error_Information);

   --  Load from PEM with an encrypted PKCS#8 key.
   --
   --  The password is copied into a scrubbed buffer immediately and the copy is
   --  wiped before this returns. The caller's own copy is the caller's to wipe;
   --  this library cannot do it for them, and says so rather than pretending.
   --  @param Item      the credential to load into
   --  @param Chain_PEM one or more CERTIFICATE blocks, leaf first
   --  @param Key_PEM   one ENCRYPTED PRIVATE KEY block
   --  @param Password  the password, used and wiped here
   --  @param Bounds    the limits in force
   --  @param Error     out: No_Error, or what is wrong
   procedure Load_Encrypted_PEM
     (Item      : in out Credential;
      Chain_PEM : String;
      Key_PEM   : String;
      Password  : String;
      Bounds    : SSL.Limits.Resource_Limits;
      Error     : out SSL.Errors.Error_Information);

   --  Scrub the key and release the chain now rather than at end of scope.
   procedure Wipe (Item : in out Credential);

   ---------------------------------------------------------------------------
   --  Signing
   ---------------------------------------------------------------------------

   --  Sign the exact octets a CertificateVerify covers.
   --
   --  The input is the complete signed structure -- sixty-four spaces, the
   --  context string, a zero separator and the transcript hash -- assembled by
   --  the caller, because only the caller knows the context and the transcript.
   --  Nothing is hashed or wrapped here beyond what the scheme itself does.
   --  Signing does not change the credential: the private key is read and
   --  nothing is recorded. The parameter is a plain `in` for that reason, which
   --  is what lets a server sign through the read-only reference its
   --  configuration hands out -- a configuration is immutable once built, and
   --  a signing operation that needed to mutate it would mean it was not.
   --  @param Item        the credential
   --  @param Scheme      the scheme, which must be one Supports accepts
   --  @param Signed_Data the exact octets to sign
   --  @param Signature   out: the signature in the encoding TLS carries
   --  @param Length      out: how many octets of Signature hold it
   --  @param Error       out: No_Error, or a signing failure
   procedure Sign
     (Item        : Credential;
      Scheme      : SSL.Signature_Schemes.Signature_Scheme;
      Signed_Data : Byte_Array;
      Signature   : out Byte_Array;
      Length      : out Byte_Index;
      Error       : out SSL.Errors.Error_Information)
     with Pre => Is_Loaded (Item) and then Signature'Length >= Maximum_Signature_Length;

   --  The largest signature any supported scheme produces: a 4096-bit RSA
   --  signature at 512 octets.
   Maximum_Signature_Length : constant Byte_Index := 512;

private

   Maximum_Chain : constant := 8;
   Maximum_Chain_Octets : constant Byte_Index := 32 * 1024;
   Maximum_Identities : constant := 16;

   type Span is record
      First : Byte_Index := 1;
      Last  : Byte_Index := 0;
   end record;

   type Span_Array is array (1 .. Maximum_Chain) of Span;
   type Identity_Array is array (1 .. Maximum_Identities) of SSL.Server_Names.DNS_Name;

   type Credential is new Ada.Finalization.Limited_Controlled with record
      Loaded : Boolean := False;
      Kind   : Key_Kind := RSA_Key;

      --  The chain as DER, concatenated, with a span per certificate. Held as
      --  octets rather than as parsed certificates because that is what goes on
      --  the wire and what a fingerprint is taken over; parsing happens where
      --  a parsed certificate is needed.
      Count  : Natural range 0 .. Maximum_Chain := 0;
      Spans  : Span_Array := [others => <>];
      Held   : Byte_Index := 0;
      Chain  : Byte_Array (1 .. Maximum_Chain_Octets) := [others => 0];

      Leaf_Digest : Certificate_Fingerprint;
      Key_Digest  : Certificate_Fingerprint;

      Schemes : SSL.Signature_Schemes.Scheme_List := SSL.Signature_Schemes.No_Schemes;

      Identity_Total : Natural range 0 .. Maximum_Identities := 0;
      Identities     : Identity_Array := [others => SSL.Server_Names.No_Name];

      --  The structural check -- key matches leaf, chain in order -- is
      --  CryptoLib's, and its Local_Identity is kept so that the check is not
      --  re-derived here.
      Structure : CryptoLib.Identities.Local_Identity;

      --  The signing key. Separate from Structure because Local_Identity
      --  deliberately exposes no signing operation, and this library needs one.
      Key : CryptoLib.PKCS8.Private_Key;

      --  Ed25519 and Ed448 signing takes the public key as well as the seed,
      --  and the public key comes from the leaf certificate rather than from
      --  the PKCS#8 blob.
      Public_Key : SSL.Secrets.Secret (SSL.Secrets.Agreement_Capacity);
   end record;

   overriding procedure Finalize (Item : in out Credential);

end SSL.Credentials;
