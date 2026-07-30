with Interfaces;

with SSL.Cipher_Suites;
with SSL.Supported_Groups;
with SSL.Versions;

--  @summary The signature schemes this library will produce or verify, and
--  ordered lists of them.
--
--  A scheme in TLS 1.3 names the whole operation: the key type, the padding
--  where there is any, the curve where the key type has one, and the hash. That
--  is a deliberate change from TLS 1.2, where a hash and a signature algorithm
--  were chosen independently and the combinations that were not meant to exist
--  had to be excluded case by case. This package uses the TLS 1.3 shape for
--  both versions and derives the TLS 1.2 encoding from it, so there is one set
--  of rules about what may sign what.
--
--  MD2, MD5, SHA-1 and DSA are absent, not disabled. RSA PKCS#1 v1.5 is present
--  only for TLS 1.2, where it is still the most widely deployed server
--  signature; in TLS 1.3 it exists on the wire solely to describe certificate
--  signatures and is never accepted for a CertificateVerify (RFC 8446 section
--  4.2.3).
package SSL.Signature_Schemes is
   pragma Preelaborate;

   type Signature_Scheme is
     (Ed25519,
      Ed448,
      ECDSA_Secp256r1_SHA256,
      ECDSA_Secp384r1_SHA384,
      ECDSA_Secp521r1_SHA512,
      RSA_PSS_RSAE_SHA256,
      RSA_PSS_RSAE_SHA384,
      RSA_PSS_RSAE_SHA512,
      RSA_PSS_PSS_SHA256,
      RSA_PSS_PSS_SHA384,
      RSA_PSS_PSS_SHA512,
      RSA_PKCS1_SHA256,
      RSA_PKCS1_SHA384,
      RSA_PKCS1_SHA512);

   type Scheme_Value is new Interfaces.Unsigned_16;

   Ed25519_Value                : constant Scheme_Value := 16#0807#;
   Ed448_Value                  : constant Scheme_Value := 16#0808#;
   ECDSA_Secp256r1_SHA256_Value : constant Scheme_Value := 16#0403#;
   ECDSA_Secp384r1_SHA384_Value : constant Scheme_Value := 16#0503#;
   ECDSA_Secp521r1_SHA512_Value : constant Scheme_Value := 16#0603#;
   RSA_PSS_RSAE_SHA256_Value    : constant Scheme_Value := 16#0804#;
   RSA_PSS_RSAE_SHA384_Value    : constant Scheme_Value := 16#0805#;
   RSA_PSS_RSAE_SHA512_Value    : constant Scheme_Value := 16#0806#;
   RSA_PSS_PSS_SHA256_Value     : constant Scheme_Value := 16#0809#;
   RSA_PSS_PSS_SHA384_Value     : constant Scheme_Value := 16#080A#;
   RSA_PSS_PSS_SHA512_Value     : constant Scheme_Value := 16#080B#;
   RSA_PKCS1_SHA256_Value       : constant Scheme_Value := 16#0401#;
   RSA_PKCS1_SHA384_Value       : constant Scheme_Value := 16#0501#;
   RSA_PKCS1_SHA512_Value       : constant Scheme_Value := 16#0601#;

   --  Values this library recognizes only to refuse: everything using SHA-1 or
   --  MD5, and everything using DSA. Named so that a negotiation failure can
   --  say which weak scheme a peer offered.
   RSA_PKCS1_SHA1_Value   : constant Scheme_Value := 16#0201#;
   ECDSA_SHA1_Value       : constant Scheme_Value := 16#0203#;
   DSA_SHA1_Value         : constant Scheme_Value := 16#0202#;
   DSA_SHA256_Value       : constant Scheme_Value := 16#0402#;
   DSA_SHA384_Value       : constant Scheme_Value := 16#0502#;
   DSA_SHA512_Value       : constant Scheme_Value := 16#0602#;
   RSA_PKCS1_MD5_Value    : constant Scheme_Value := 16#0101#;

   --  What kind of key a scheme signs with.
   type Key_Kind is (EdDSA_Key, ECDSA_Key, RSA_Key);

   --  How an RSA scheme pads. Meaningless for the other key kinds.
   type RSA_Padding is (Not_RSA, PKCS1_V1_5, PSS_With_RSAE_Key, PSS_With_PSS_Key);

   function Value_Of (Item : Signature_Scheme) return Scheme_Value;

   function Scheme_For (Item : Scheme_Value; Value : out Signature_Scheme) return Boolean;

   --  Is this a scheme an RFC defines that this library refuses on strength
   --  grounds -- SHA-1, MD5 or DSA?
   function Is_Refused_Weak (Item : Scheme_Value) return Boolean;

   function Key_Kind_Of (Item : Signature_Scheme) return Key_Kind;
   function Padding_Of (Item : Signature_Scheme) return RSA_Padding;

   --  The hash the scheme signs over. SHA-512 appears here even though the
   --  cipher-suite hash type has only two members: a signature hash and a key
   --  schedule hash are different choices, and P-521 signs over SHA-512.
   type Signature_Hash is (SHA_256, SHA_384, SHA_512, Hash_In_Algorithm);

   --  Ed25519 and Ed448 hash internally as part of the signature algorithm and
   --  take the message, not a digest; they report Hash_In_Algorithm.
   function Hash_Of (Item : Signature_Scheme) return Signature_Hash;

   --  For an ECDSA scheme, the curve the key must be on. RFC 8446 section 4.2.3
   --  binds each ECDSA scheme to one curve, which TLS 1.2 did not, and this
   --  library applies the TLS 1.3 rule in both versions: an ECDSA P-256 key
   --  never signs under ecdsa_secp384r1_sha384.
   --  @param Item  the scheme
   --  @param Value out: the required curve
   --  @return True for the ECDSA schemes, False otherwise
   function Required_Curve
     (Item : Signature_Scheme; Value : out SSL.Supported_Groups.Named_Group) return Boolean;

   --  May this scheme be used in a CertificateVerify for this version?
   --
   --  The PKCS#1 v1.5 schemes are usable in TLS 1.2 and never in TLS 1.3.
   --  Everything else is usable in both.
   function Usable_For_Handshake
     (Item : Signature_Scheme; Value : SSL.Versions.Protocol_Version) return Boolean;

   --  May this scheme appear in signature_algorithms_cert -- that is, may a
   --  certificate in the chain be signed with it? PKCS#1 v1.5 is permitted here
   --  in both versions, because the great majority of deployed certificates are
   --  signed that way and refusing them would refuse the public web.
   function Usable_For_Certificate (Item : Signature_Scheme) return Boolean
     with Post => Usable_For_Certificate'Result;

   --  Is this scheme compatible with a TLS 1.2 cipher suite's authentication
   --  kind? A TLS_ECDHE_RSA suite cannot be authenticated by an Ed25519 key.
   function Matches_Authentication
     (Item : Signature_Scheme;
      Kind : SSL.Cipher_Suites.Authentication_Kind) return Boolean;

   function Image (Item : Signature_Scheme) return String;
   function Image (Item : Scheme_Value) return String;

   ---------------------------------------------------------------------------
   --  Ordered scheme lists
   ---------------------------------------------------------------------------

   Maximum_Schemes : constant := 14;

   subtype Scheme_Count is Natural range 0 .. Maximum_Schemes;
   subtype Scheme_Position is Positive range 1 .. Maximum_Schemes;

   type Scheme_List is private;

   function No_Schemes return Scheme_List
     with Post => Length (No_Schemes'Result) = 0;

   --  The default handshake preference. EdDSA first (smallest and fastest to
   --  verify), then ECDSA by strength, then RSA-PSS. PKCS#1 v1.5 is included
   --  because a TLS 1.2 peer with an RSA certificate may have nothing else, and
   --  it is last so it is chosen only when nothing better overlaps. It is never
   --  offered for TLS 1.3, which Restricted_To enforces.
   function Default_Schemes return Scheme_List;

   --  The default for signature_algorithms_cert: the same set, since every
   --  scheme here is acceptable on a certificate.
   function Default_Certificate_Schemes return Scheme_List;

   function Length (Item : Scheme_List) return Scheme_Count;
   function Is_Empty (Item : Scheme_List) return Boolean;

   function Element (Item : Scheme_List; Index : Scheme_Position) return Signature_Scheme
     with Pre => Index <= Length (Item);

   function Contains (Item : Scheme_List; Value : Signature_Scheme) return Boolean;
   function Position (Item : Scheme_List; Value : Signature_Scheme) return Scheme_Count;

   procedure Append (Item : in out Scheme_List; Value : Signature_Scheme; Ok : out Boolean);

   --  Those schemes usable in a CertificateVerify for a version, in order.
   function Restricted_To
     (Item : Scheme_List; Value : SSL.Versions.Protocol_Version) return Scheme_List;

   --  Does the list hold a scheme usable with this version?
   function Supports (Item : Scheme_List; Value : SSL.Versions.Protocol_Version) return Boolean;

   function Image (Item : Scheme_List) return String;

private

   type Scheme_Array is array (Scheme_Position) of Signature_Scheme;

   type Scheme_List is record
      Count : Scheme_Count := 0;
      Items : Scheme_Array := [others => Ed25519];
   end record;

end SSL.Signature_Schemes;
