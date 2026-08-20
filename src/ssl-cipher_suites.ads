with Interfaces;

with SSL.Versions;

--  @summary The cipher suites this library implements, what each one is made
--  of, and ordered lists of them.
--
--  Nine suites: three for TLS 1.3 and six for the restricted TLS 1.2. Every one
--  of them is AEAD, and every TLS 1.2 one is ECDHE. There is no suite here that
--  uses RC4, DES, 3DES, CBC-with-HMAC, or NULL encryption, no export suite, and
--  no static-RSA or static/anonymous-DH key exchange; those are not disabled by
--  default, they are absent, so no configuration can reach them.
--
--  A suite in TLS 1.3 names an AEAD and a hash and nothing else -- key exchange
--  and authentication moved into their own extensions. A suite in TLS 1.2 names
--  key exchange, authentication, AEAD and PRF hash together. Both shapes are
--  represented here, and Version_Of says which shape a suite has, because
--  offering a TLS 1.2 suite in a TLS 1.3 ClientHello or the reverse is a
--  configuration error this library refuses rather than lets the peer discover.
package SSL.Cipher_Suites is
   pragma Preelaborate;

   ---------------------------------------------------------------------------
   --  Building blocks
   ---------------------------------------------------------------------------

   --  The AEAD a suite protects records with.
   type AEAD_Algorithm is (AES_128_GCM, AES_256_GCM, ChaCha20_Poly1305);

   --  The hash a suite's key schedule, transcript and (in TLS 1.2) PRF run on.
   type Hash_Algorithm is (SHA_256, SHA_384);

   --  How the peers agree a shared secret. Only ECDHE is present: TLS 1.3 has
   --  nothing else, and the TLS 1.2 subset here deliberately has nothing else
   --  either.
   type Key_Exchange_Kind is (ECDHE, TLS13_Key_Schedule);

   --  What authenticates the server, and optionally the client. TLS 1.3 suites
   --  do not name this -- signature_algorithms does -- so they report
   --  Signature_In_Extension.
   type Authentication_Kind is (ECDSA_Or_EdDSA, RSA_Signature, Signature_In_Extension);

   --  Octets of key, static IV and authentication tag an AEAD takes.
   function Key_Length (Item : AEAD_Algorithm) return Byte_Index
     with Post => Key_Length'Result in 16 | 32;

   function IV_Length (Item : AEAD_Algorithm) return Byte_Index
     with Post => IV_Length'Result = 12;

   function Tag_Length (Item : AEAD_Algorithm) return Byte_Index
     with Post => Tag_Length'Result = 16;

   --  Octets a hash produces, which is also the width of every secret in the
   --  TLS 1.3 key schedule for a suite using it.
   function Digest_Length (Item : Hash_Algorithm) return Byte_Index
     with Post => Digest_Length'Result in 32 | 48;

   function Image (Item : AEAD_Algorithm) return String;
   function Image (Item : Hash_Algorithm) return String;

   ---------------------------------------------------------------------------
   --  Suites
   ---------------------------------------------------------------------------

   type Cipher_Suite is
     (
      --  TLS 1.3, RFC 8446 appendix B.4
      TLS_AES_128_GCM_SHA256,
      TLS_AES_256_GCM_SHA384,
      TLS_CHACHA20_POLY1305_SHA256,

      --  Restricted TLS 1.2: ECDHE key exchange, AEAD record protection
      TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);

   --  A suite's two octets on the wire.
   type Suite_Value is new Interfaces.Unsigned_16;

   --  Wire values, written out rather than derived from positions.
   TLS_AES_128_GCM_SHA256_Value       : constant Suite_Value := 16#1301#;
   TLS_AES_256_GCM_SHA384_Value       : constant Suite_Value := 16#1302#;
   TLS_CHACHA20_POLY1305_SHA256_Value : constant Suite_Value := 16#1303#;

   TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_Value       : constant Suite_Value := 16#C02B#;
   TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_Value       : constant Suite_Value := 16#C02C#;
   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256_Value         : constant Suite_Value := 16#C02F#;
   TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384_Value         : constant Suite_Value := 16#C030#;
   TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_Value : constant Suite_Value := 16#CCA9#;
   TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_Value   : constant Suite_Value := 16#CCA8#;

   --  The TLS_EMPTY_RENEGOTIATION_INFO_SCSV signalling value (RFC 5746). Not a
   --  suite: a marker a TLS 1.2 client may send to say it understands secure
   --  renegotiation. This library parses it in an initial handshake and never
   --  renegotiates, so it is recognized here only to be excluded from
   --  negotiation.
   Renegotiation_Info_SCSV : constant Suite_Value := 16#00FF#;

   --  The TLS_FALLBACK_SCSV downgrade sentinel (RFC 7507). Recognized so a
   --  server can refuse a client that has downgraded itself.
   Fallback_SCSV : constant Suite_Value := 16#5600#;

   function Value_Of (Item : Cipher_Suite) return Suite_Value;

   --  The suite a wire value names, when this library implements it.
   --  @param Item  the wire value
   --  @param Value out: the suite, unchanged when the result is False
   --  @return True when the value names an implemented suite
   function Suite_For (Item : Suite_Value; Value : out Cipher_Suite) return Boolean;

   --  Is this one of the two signalling values rather than a suite?
   function Is_Signalling (Item : Suite_Value) return Boolean;

   --  Which protocol version a suite belongs to. A suite is usable with exactly
   --  one version: the numbering spaces overlap in neither direction, and
   --  RFC 8446 section 4.1.2 forbids offering a TLS 1.3 suite for TLS 1.2 use.
   function Version_Of (Item : Cipher_Suite) return SSL.Versions.Protocol_Version;

   function AEAD_Of (Item : Cipher_Suite) return AEAD_Algorithm;
   function Hash_Of (Item : Cipher_Suite) return Hash_Algorithm;
   function Key_Exchange_Of (Item : Cipher_Suite) return Key_Exchange_Kind;
   function Authentication_Of (Item : Cipher_Suite) return Authentication_Kind;

   --  The RFC name, lower case, for diagnostics and reports.
   function Image (Item : Cipher_Suite) return String;

   --  Text naming a wire value, including unimplemented ones, so a diagnostic
   --  can report what a peer offered.
   function Image (Item : Suite_Value) return String;

   ---------------------------------------------------------------------------
   --  Ordered suite lists
   --
   --  Order is preference order, and it is preserved exactly: a client sends
   --  its list in this order and a server with server-preference negotiation
   --  walks its own list in this order. Duplicates are refused rather than
   --  ignored, because a duplicate in a configured preference list is a
   --  mistake whose effect is invisible.
   ---------------------------------------------------------------------------

   Maximum_Suites : constant := 9;

   subtype Suite_Count is Natural range 0 .. Maximum_Suites;
   subtype Suite_Position is Positive range 1 .. Maximum_Suites;

   type Suite_List is private;

   function No_Suites return Suite_List
     with Post => Length (No_Suites'Result) = 0;

   --  The three TLS 1.3 suites in this library's default preference order:
   --  AES-128-GCM first because it is the fastest on hardware with AES
   --  instructions and the most widely implemented; ChaCha20-Poly1305 second
   --  because it is the fastest on hardware without them; AES-256-GCM last
   --  because its extra margin is not the bottleneck in any current threat
   --  model and it is measurably slower.
   function Default_TLS_1_3_Suites return Suite_List
     with Post => Length (Default_TLS_1_3_Suites'Result) = 3;

   --  The six restricted TLS 1.2 suites, ECDSA before RSA at each strength
   --  because an ECDSA signature is cheaper to verify and the credential is
   --  smaller.
   function Default_TLS_1_2_Suites return Suite_List
     with Post => Length (Default_TLS_1_2_Suites'Result) = 6;

   function Length (Item : Suite_List) return Suite_Count;
   function Is_Empty (Item : Suite_List) return Boolean;

   function Element (Item : Suite_List; Index : Suite_Position) return Cipher_Suite
     with Pre => Index <= Length (Item);

   function Contains (Item : Suite_List; Value : Cipher_Suite) return Boolean;

   --  The position of a suite in the list, or zero when absent. Used by a
   --  server negotiating in client-preference order.
   function Position (Item : Suite_List; Value : Cipher_Suite) return Suite_Count;

   --  Append a suite. Returns a new list.
   --  @param Item  the list
   --  @param Value the suite to append
   --  @param Ok    out: False when Value is already present or the list is full
   procedure Append (Item : in out Suite_List; Value : Cipher_Suite; Ok : out Boolean);

   --  Every suite in the list belonging to a given version, in the same order.
   function Restricted_To
     (Item : Suite_List; Value : SSL.Versions.Protocol_Version) return Suite_List;

   --  Does the list hold at least one suite usable with this version?
   function Supports (Item : Suite_List; Value : SSL.Versions.Protocol_Version) return Boolean;

   --  Comma-separated names, for diagnostics.
   function Image (Item : Suite_List) return String;

private

   type Suite_Array is array (Suite_Position) of Cipher_Suite;

   type Suite_List is record
      Count : Suite_Count := 0;
      Items : Suite_Array := [others => TLS_AES_128_GCM_SHA256];
   end record;

end SSL.Cipher_Suites;
