
with SSL;
with SSL.Alerts;
with SSL.Diagnostics;
with SSL.Unsafe.Key_Logging;
with SSL.ALPN;
with SSL.Cipher_Suites;
with SSL.Errors;
with SSL.Limits;
with SSL.Server_Names;
with SSL.Signature_Schemes;
with SSL.Supported_Groups;
with SSL.Versions;

with Tests_Support;

package body Tests_Public is

   use Tests_Support;

   use type SSL.Byte;
   use type SSL.Byte_Array;
   use type SSL.Byte_Index;
   use type SSL.Security_Context_ID;
   use type SSL.Certificate_Fingerprint;
   use type SSL.Fingerprint_Subject;
   use type SSL.Versions.Protocol_Version;
   use type SSL.Cipher_Suites.Cipher_Suite;
   use type SSL.Cipher_Suites.Hash_Algorithm;
   use type SSL.Cipher_Suites.Authentication_Kind;
   use type SSL.Cipher_Suites.Key_Exchange_Kind;
   use type SSL.Supported_Groups.Named_Group;
   use type SSL.Supported_Groups.Group_Value;
   use type SSL.Supported_Groups.Group_Family;
   use type SSL.Signature_Schemes.Signature_Scheme;
   use type SSL.Signature_Schemes.Scheme_Value;
   use type SSL.Signature_Schemes.Key_Kind;
   use type SSL.Signature_Schemes.RSA_Padding;
   use type SSL.Signature_Schemes.Signature_Hash;
   use type SSL.Versions.Version_Value;
   use type SSL.Alerts.Alert_Value;
   use type SSL.Alerts.Alert_Level;
   use type SSL.Alerts.Alert_Description;
   use type SSL.Errors.Error_Code;
   use type SSL.Errors.Error_Category;
   use type SSL.Errors.Error_Origin;
   use type SSL.Errors.Retry_Class;
   use type SSL.Errors.Disclosure_Class;
   use type SSL.Server_Names.Name_Status;
   use type SSL.Limits.Limit_Kind;

   --  These checks call the "does this wire value name something we implement"
   --  functions for their answer and deliberately discard the value, because the
   --  point of a negative check is that there is no value. GNAT reads the
   --  discarded out parameter as a useless assignment; it is the check's whole
   --  subject.
   pragma Warnings (Off, "*useless assignment*");

   ----------
   -- Name --
   ----------

   overriding function Name (T : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (T);
   begin
      return Tests_Support.Message ("ssllib public API: registries, names, policy, errors");
   end Name;

   ---------------------------------------------------------------------------
   --  Versions
   ---------------------------------------------------------------------------

   procedure Run_Versions (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Versions (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      use SSL.Versions;
      Value : Protocol_Version;
      Values : Version_Value_Array;
      Last   : Natural;
   begin
      Expect (Value_Of (TLS_1_3) = 16#0304#, "TLS 1.3 wire value");
      Expect (Value_Of (TLS_1_2) = 16#0303#, "TLS 1.2 wire value");
      --  Legacy_Record_Value is the TLS 1.2 value by declaration, which the
      --  compiler already knows; asserting it here would be a tautology. What
      --  is worth stating is that it is not the negotiated version, which the
      --  record-layer checks in SSL.Internal_Tests establish.

      Expect (Version_For (16#0304#, Value) and then Value = TLS_1_3, "0x0304 names TLS 1.3");
      Expect (Version_For (16#0303#, Value) and then Value = TLS_1_2, "0x0303 names TLS 1.2");

      --  The obsolete versions must be recognized as obsolete and never
      --  produced as a usable Protocol_Version. There is no configuration path
      --  to them because there is no value to configure.
      Expect (not Version_For (16#0302#, Value), "TLS 1.1 is not an implemented version");
      Expect (not Version_For (16#0301#, Value), "TLS 1.0 is not an implemented version");
      Expect (not Version_For (16#0300#, Value), "SSL 3.0 is not an implemented version");
      Expect (Is_Refused_Legacy (16#0302#), "TLS 1.1 is recognized as refused legacy");
      Expect (Is_Refused_Legacy (16#0300#), "SSL 3.0 is recognized as refused legacy");
      Expect (not Is_Refused_Legacy (16#0304#), "TLS 1.3 is not refused legacy");

      Expect_Equal (Image (16#0302#), "tls1.1", "TLS 1.1 image");

      --  Version sets.
      Expect (Count (TLS_1_3_Only) = 1, "the TLS 1.3-only set has one member");
      Expect (Contains (TLS_1_3_Only, TLS_1_3), "the TLS 1.3-only set contains TLS 1.3");
      Expect (not Contains (TLS_1_3_Only, TLS_1_2), "the TLS 1.3-only set excludes TLS 1.2");
      Expect (Is_Empty (No_Versions), "the empty set is empty");
      Expect (Highest (TLS_1_3_And_1_2) = TLS_1_3, "TLS 1.3 is the highest of both");
      Expect (Lowest (TLS_1_3_And_1_2) = TLS_1_2, "TLS 1.2 is the lowest of both");

      --  supported_versions is listed newest first.
      Ordered_Values (TLS_1_3_And_1_2, Values, Last);
      Expect (Last = 2, "both versions are listed");
      Expect (Values (1) = 16#0304#, "TLS 1.3 is listed first");
      Expect (Values (2) = 16#0303#, "TLS 1.2 is listed second");
   end Run_Versions;

   ---------------------------------------------------------------------------
   --  Cipher suites
   ---------------------------------------------------------------------------

   procedure Run_Cipher_Suites (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Cipher_Suites (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      use SSL.Cipher_Suites;
      Suite : Cipher_Suite;
      List  : Suite_List;
   begin
      --  Wire values, which must match RFC 8446 appendix B.4 and RFC 5289.
      Expect (Value_Of (TLS_AES_128_GCM_SHA256) = 16#1301#, "TLS_AES_128_GCM_SHA256 value");
      Expect (Value_Of (TLS_AES_256_GCM_SHA384) = 16#1302#, "TLS_AES_256_GCM_SHA384 value");
      Expect (Value_Of (TLS_CHACHA20_POLY1305_SHA256) = 16#1303#, "chacha20 suite value");
      Expect (Value_Of (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) = 16#C02B#, "ecdhe-ecdsa value");
      Expect (Value_Of (TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256) = 16#CCA8#, "ecdhe-rsa value");

      Expect (Suite_For (16#1301#, Suite) and then Suite = TLS_AES_128_GCM_SHA256,
              "0x1301 names TLS_AES_128_GCM_SHA256");

      --  The suites this library refuses to implement must not be nameable. A
      --  CBC suite, a 3DES suite and an RC4 suite are each checked by their
      --  registered code point.
      Expect (not Suite_For (16#002F#, Suite), "TLS_RSA_WITH_AES_128_CBC_SHA is absent");
      Expect (not Suite_For (16#000A#, Suite), "TLS_RSA_WITH_3DES_EDE_CBC_SHA is absent");
      Expect (not Suite_For (16#0005#, Suite), "TLS_RSA_WITH_RC4_128_SHA is absent");
      Expect (not Suite_For (16#0001#, Suite), "TLS_RSA_WITH_NULL_MD5 is absent");
      Expect (not Suite_For (16#C013#, Suite), "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA is absent");
      Expect (not Suite_For (16#0018#, Suite), "TLS_DH_anon_WITH_RC4_128_MD5 is absent");

      --  The two signalling values are recognized as such and are never suites.
      Expect (Is_Signalling (16#00FF#), "the renegotiation SCSV is recognized");
      Expect (Is_Signalling (16#5600#), "the fallback SCSV is recognized");
      Expect (not Suite_For (16#00FF#, Suite), "the renegotiation SCSV is not a suite");
      Expect (not Suite_For (16#5600#, Suite), "the fallback SCSV is not a suite");

      --  Composition.
      Expect (Version_Of (TLS_AES_128_GCM_SHA256) = SSL.Versions.TLS_1_3, "1.3 suite version");
      Expect (Version_Of (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) = SSL.Versions.TLS_1_2,
              "1.2 suite version");
      Expect (Hash_Of (TLS_AES_256_GCM_SHA384) = SHA_384, "AES-256-GCM uses SHA-384");
      Expect (Hash_Of (TLS_CHACHA20_POLY1305_SHA256) = SHA_256, "ChaCha20 uses SHA-256");
      Expect (Key_Length (AES_128_GCM) = 16, "AES-128 key length");
      Expect (Key_Length (AES_256_GCM) = 32, "AES-256 key length");
      Expect (Key_Length (ChaCha20_Poly1305) = 32, "ChaCha20 key length");
      Expect (IV_Length (AES_128_GCM) = 12, "AEAD nonce length");
      Expect (Tag_Length (ChaCha20_Poly1305) = 16, "AEAD tag length");
      Expect (Authentication_Of (TLS_AES_128_GCM_SHA256) = Signature_In_Extension,
              "a TLS 1.3 suite does not name an authentication algorithm");
      Expect (Authentication_Of (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) = ECDSA_Or_EdDSA,
              "an ECDSA suite names ECDSA authentication");
      Expect (Key_Exchange_Of (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) = ECDHE,
              "every TLS 1.2 suite here is ECDHE");

      --  Default preference order, as documented.
      List := Default_TLS_1_3_Suites;
      Expect (Length (List) = 3, "three TLS 1.3 suites");
      Expect (Element (List, 1) = TLS_AES_128_GCM_SHA256, "AES-128-GCM is preferred first");
      Expect (Element (List, 2) = TLS_CHACHA20_POLY1305_SHA256, "ChaCha20 is preferred second");
      Expect (Element (List, 3) = TLS_AES_256_GCM_SHA384, "AES-256-GCM is preferred last");

      --  Restriction by version keeps the two families from mixing.
      List := Default_TLS_1_3_Suites;
      Expect (Restricted_To (List, SSL.Versions.TLS_1_2) = No_Suites
              or else Length (Restricted_To (List, SSL.Versions.TLS_1_2)) = 0,
              "TLS 1.3 suites are not usable for TLS 1.2");
      Expect (Supports (Default_TLS_1_2_Suites, SSL.Versions.TLS_1_2),
              "the TLS 1.2 defaults support TLS 1.2");
      Expect (not Supports (Default_TLS_1_2_Suites, SSL.Versions.TLS_1_3),
              "the TLS 1.2 defaults do not support TLS 1.3");

      --  Duplicates are refused rather than silently ignored.
      declare
         Ok : Boolean;
      begin
         List := No_Suites;
         Append (List, TLS_AES_128_GCM_SHA256, Ok);
         Expect (Ok, "the first append succeeds");
         Append (List, TLS_AES_128_GCM_SHA256, Ok);
         Expect (not Ok, "a duplicate suite is refused");
         Expect (Length (List) = 1, "a refused append did not change the list");
      end;
   end Run_Cipher_Suites;

   ---------------------------------------------------------------------------
   --  Groups and signature schemes
   ---------------------------------------------------------------------------

   procedure Run_Groups (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Groups (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      use SSL.Supported_Groups;
      Group : Named_Group;
   begin
      Expect (Value_Of (X25519) = 29, "x25519 code point");
      Expect (Value_Of (Secp256r1) = 23, "secp256r1 code point");
      Expect (Value_Of (Secp384r1) = 24, "secp384r1 code point");
      Expect (Value_Of (Secp521r1) = 25, "secp521r1 code point");

      Expect (Group_For (29, Group) and then Group = X25519, "29 names x25519");
      Expect (Group_For (256, Group) and then Group = FFDHE2048, "256 names ffdhe2048");
      Expect (Group_For (258, Group) and then Group = FFDHE4096, "258 names ffdhe4096");

      --  ffdhe6144 and ffdhe8192 are implemented by cryptolib and deliberately
      --  not offered here; they are recognized only so a diagnostic can name
      --  them rather than printing a bare number.
      Expect (not Group_For (259, Group), "ffdhe6144 is not offered");
      Expect (Is_Known_Unoffered (259), "ffdhe6144 is a known but unoffered group");
      Expect (not Is_Known_Unoffered (256), "ffdhe2048 is offered, so not unoffered");
      Expect (not Is_Known_Unoffered (12_345), "an arbitrary number is not a known group");
      Expect_Equal (Image (Group_Value (259)), "ffdhe6144", "unoffered group image");
      Expect_Equal (Image (Group_Value (256)), "ffdhe2048", "offered group image");

      --  Families, and the sizes that follow from them.
      Expect (Is_Elliptic_Curve (X25519), "x25519 is a curve");
      Expect (not Is_Elliptic_Curve (FFDHE2048), "ffdhe2048 is not a curve");
      Expect (Family_Of (FFDHE4096) = Finite_Field, "ffdhe4096 is finite field");
      Expect (Family_Of (Secp521r1) = Elliptic_Curve, "secp521r1 is elliptic curve");

      --  Share lengths bound a peer's key_share before any curve arithmetic.
      Expect (Share_Length (X25519) = 32, "x25519 share length");
      Expect (Share_Length (Secp256r1) = 65, "P-256 uncompressed point length");
      Expect (Share_Length (Secp384r1) = 97, "P-384 uncompressed point length");
      Expect (Share_Length (Secp521r1) = 133, "P-521 uncompressed point length");
      Expect (Secret_Length (Secp521r1) = 66, "P-521 shared secret length");

      --  The finite-field share is the width of p, left-padded, never
      --  abbreviated (RFC 8446 section 4.2.8.1).
      Expect (Share_Length (FFDHE2048) = 256, "ffdhe2048 share length");
      Expect (Share_Length (FFDHE3072) = 384, "ffdhe3072 share length");
      Expect (Share_Length (FFDHE4096) = 512, "ffdhe4096 share length");
      Expect (Secret_Length (FFDHE4096) = 512, "ffdhe4096 shared secret length");

      Expect (Length (Default_Groups) = 3, "three default groups");
      Expect (Element (Default_Groups, 1) = X25519, "x25519 is preferred first");
      Expect (Length (Default_Key_Share_Groups) = 2, "two default key shares");
      Expect (Is_Subset (Default_Key_Share_Groups, Default_Groups),
              "the default key shares are a subset of the default groups, "
              & "which RFC 8446 4.2.8 requires");

      --  The finite-field groups are offered but never default: a caller that
      --  does not need them should not pay 512 octets and a 4096-bit
      --  exponentiation because a default said so.
      Expect (not Contains (Default_Groups, FFDHE2048),
              "the default group set holds no finite-field group");
      Expect (Length (Finite_Field_Groups) = 3, "three finite-field groups are offered");
      Expect (Contains (Finite_Field_Groups, FFDHE4096),
              "the finite-field set holds ffdhe4096");
      Expect (not Is_Subset (Finite_Field_Groups, Default_Groups),
              "the finite-field groups are not in the default set");
   end Run_Groups;

   procedure Run_Signature_Schemes (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Signature_Schemes (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      use SSL.Signature_Schemes;
      Scheme : Signature_Scheme;
      Curve  : SSL.Supported_Groups.Named_Group;
   begin
      Expect (Value_Of (Ed25519) = 16#0807#, "ed25519 code point");
      Expect (Value_Of (ECDSA_Secp256r1_SHA256) = 16#0403#, "ecdsa_secp256r1_sha256 code point");
      Expect (Value_Of (RSA_PSS_RSAE_SHA256) = 16#0804#, "rsa_pss_rsae_sha256 code point");
      Expect (Value_Of (RSA_PSS_PSS_SHA512) = 16#080B#, "rsa_pss_pss_sha512 code point");
      Expect (Value_Of (RSA_PKCS1_SHA256) = 16#0401#, "rsa_pkcs1_sha256 code point");

      --  The weak schemes must not be nameable, and must be recognized as
      --  deliberately refused so a negotiation failure can say why.
      Expect (not Scheme_For (16#0201#, Scheme), "rsa_pkcs1_sha1 is absent");
      Expect (not Scheme_For (16#0203#, Scheme), "ecdsa_sha1 is absent");
      Expect (not Scheme_For (16#0202#, Scheme), "dsa_sha1 is absent");
      Expect (not Scheme_For (16#0402#, Scheme), "dsa_sha256 is absent");
      Expect (Is_Refused_Weak (16#0201#), "rsa_pkcs1_sha1 is recognized as weak");
      Expect (Is_Refused_Weak (16#0402#), "dsa_sha256 is recognized as weak");
      Expect (Is_Refused_Weak (16#0101#), "rsa_pkcs1_md5 is recognized as weak");

      --  RFC 8446 section 4.2.3: PKCS#1 v1.5 is for certificates only in
      --  TLS 1.3, and usable in a CertificateVerify only in TLS 1.2.
      Expect (Usable_For_Handshake (RSA_PKCS1_SHA256, SSL.Versions.TLS_1_2),
              "PKCS#1 v1.5 is usable in a TLS 1.2 CertificateVerify");
      Expect (not Usable_For_Handshake (RSA_PKCS1_SHA256, SSL.Versions.TLS_1_3),
              "PKCS#1 v1.5 is not usable in a TLS 1.3 CertificateVerify");
      Expect (Usable_For_Handshake (RSA_PSS_RSAE_SHA256, SSL.Versions.TLS_1_3),
              "RSA-PSS is usable in TLS 1.3");
      Expect (Usable_For_Certificate (RSA_PKCS1_SHA256),
              "PKCS#1 v1.5 is acceptable on a certificate");

      --  Each ECDSA scheme is bound to one curve, the TLS 1.3 rule, applied in
      --  both versions.
      Expect (Required_Curve (ECDSA_Secp256r1_SHA256, Curve)
              and then Curve = SSL.Supported_Groups.Secp256r1,
              "ecdsa_secp256r1_sha256 requires P-256");
      Expect (Required_Curve (ECDSA_Secp521r1_SHA512, Curve)
              and then Curve = SSL.Supported_Groups.Secp521r1,
              "ecdsa_secp521r1_sha512 requires P-521");
      Expect (not Required_Curve (Ed25519, Curve), "ed25519 has no required NIST curve");

      Expect (Key_Kind_Of (Ed25519) = EdDSA_Key, "ed25519 is an EdDSA key");
      Expect (Padding_Of (RSA_PSS_PSS_SHA256) = PSS_With_PSS_Key, "pss_pss padding");
      Expect (Padding_Of (RSA_PSS_RSAE_SHA256) = PSS_With_RSAE_Key, "pss_rsae padding");
      Expect (Hash_Of (Ed25519) = Hash_In_Algorithm, "EdDSA hashes internally");

      --  Suite compatibility: an ECDSA suite is not authenticated by an RSA key.
      Expect (Matches_Authentication (Ed25519, SSL.Cipher_Suites.ECDSA_Or_EdDSA),
              "ed25519 matches an ECDSA suite");
      Expect (not Matches_Authentication (RSA_PSS_RSAE_SHA256, SSL.Cipher_Suites.ECDSA_Or_EdDSA),
              "RSA does not match an ECDSA suite");
      Expect (Matches_Authentication (RSA_PSS_RSAE_SHA256, SSL.Cipher_Suites.RSA_Signature),
              "RSA matches an RSA suite");
      Expect (Matches_Authentication (RSA_PKCS1_SHA256, SSL.Cipher_Suites.Signature_In_Extension),
              "a TLS 1.3 suite constrains nothing about the key type");

      --  Restriction to TLS 1.3 drops exactly the PKCS#1 v1.5 schemes.
      declare
         All_Schemes : constant Scheme_List := Default_Schemes;
         For_13      : constant Scheme_List := Restricted_To (All_Schemes, SSL.Versions.TLS_1_3);
      begin
         Expect (Length (All_Schemes) = 14, "fourteen default schemes");
         Expect (Length (For_13) = 11, "eleven of them are usable in TLS 1.3");
         Expect (not Contains (For_13, RSA_PKCS1_SHA256),
                 "the TLS 1.3 set excludes PKCS#1 v1.5");
         Expect (Element (All_Schemes, 1) = Ed25519, "EdDSA is preferred first");
      end;
   end Run_Signature_Schemes;

   ---------------------------------------------------------------------------
   --  ALPN
   ---------------------------------------------------------------------------

   procedure Run_ALPN (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_ALPN (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      use SSL.ALPN;
      H2      : constant Protocol_Name := Protocol ("h2");
      HTTP11  : constant Protocol_Name := Protocol ("http/1.1");
      Upper   : Protocol_Name;
      Server  : Protocol_List := No_Protocols;
      Client  : Protocol_List := No_Protocols;
      Chosen  : Protocol_Name;
      Ok      : Boolean;
   begin
      Expect (Length (H2) = 2, "h2 is two octets");
      Expect_Equal (Image (H2), "h2", "h2 image");

      --  Names are opaque octets: no case folding, and no UTF-8 assumption.
      Expect (Make ("H2", Upper), "an upper-case name is a valid name");
      Expect (not (Upper = H2), "ALPN names are compared as octets, not case-folded");

      --  Bounds.
      Expect (not Make ("", Upper), "an empty name is refused");
      declare
         Long : constant String (1 .. 256) := [others => 'a'];
      begin
         Expect (not Make (Long, Upper), "a 256-octet name is refused");
      end;
      declare
         Exact : constant String (1 .. 255) := [others => 'a'];
      begin
         Expect (Make (Exact, Upper), "a 255-octet name is accepted");
      end;

      --  Non-ASCII characters are refused rather than silently encoded, and a
      --  name with unprintable octets renders as hexadecimal so a log line
      --  cannot be poisoned by a peer.
      Expect (not Make (Character'Val (200) & "x", Upper), "a non-ASCII character is refused");
      declare
         Raw : Protocol_Name;
      begin
         Expect (Make (SSL.Byte_Array'(1 => 0, 2 => 1), Raw), "arbitrary octets make a valid name");
         Expect_Equal (Image (Raw), "0x0001", "unprintable names render as hex");
      end;

      --  Selection, both orders.
      Append (Server, H2, Ok);
      Append (Server, HTTP11, Ok);
      Append (Client, HTTP11, Ok);
      Append (Client, H2, Ok);

      Expect (Select_Protocol (Server_Order, Server, Client, Chosen), "server order finds overlap");
      Expect (Chosen = H2, "server order chooses the server's first preference");

      Expect (Select_Protocol (Client_Order, Server, Client, Chosen), "client order finds overlap");
      Expect (Chosen = HTTP11, "client order chooses the client's first preference");

      --  No overlap is reported, not guessed at.
      declare
         Other : Protocol_List := No_Protocols;
      begin
         Append (Other, Protocol ("imap"), Ok);
         Expect (not Select_Protocol (Server_Order, Server, Other, Chosen),
                 "no overlap selects nothing");
         Expect (not Is_Present (Chosen), "nothing selected means no protocol");
      end;

      --  Duplicates refused.
      Append (Server, H2, Ok);
      Expect (not Ok, "a duplicate protocol is refused");

      --  Policy validity: Required with an empty list can never succeed and is
      --  refused at configuration time.
      Expect (not Is_Valid_Policy (Required, No_Protocols), "required ALPN with no list is invalid");
      Expect (not Is_Valid_Policy (Optional, No_Protocols), "optional ALPN with no list is invalid");
      Expect (Is_Valid_Policy (Not_Offered, No_Protocols), "not offering ALPN needs no list");
      Expect (Is_Valid_Policy (Required, Server), "required ALPN with a list is valid");
   end Run_ALPN;

   ---------------------------------------------------------------------------
   --  Server names
   ---------------------------------------------------------------------------

   procedure Run_Server_Names (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Server_Names (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      use SSL.Server_Names;
      Item   : DNS_Name;
      Status : Name_Status;
   begin
      --  Normalization: case folded, trailing dot dropped.
      Parse ("WWW.Example.COM.", Item, Status);
      Expect (Status = Ok, "a mixed-case fully-qualified name parses");
      Expect_Equal (Image (Item), "www.example.com", "the name is normalized");
      Expect (Label_Count (Item) = 3, "three labels");
      Expect (not Is_Wildcard (Item), "an exact name is not a wildcard");

      --  Refusals.
      Parse ("", Item, Status);
      Expect (Status = Empty_Name, "an empty name is refused");
      Parse ("a..b", Item, Status);
      Expect (Status = Empty_Label, "an empty label is refused");
      Parse ("-bad.example.com", Item, Status);
      Expect (Status = Leading_Or_Trailing_Hyphen, "a leading hyphen is refused");
      Parse ("bad-.example.com", Item, Status);
      Expect (Status = Leading_Or_Trailing_Hyphen, "a trailing hyphen is refused");
      Parse ("a b.example.com", Item, Status);
      Expect (Status = Invalid_Character, "a space is refused");

      --  An IP literal is not a DNS name and must never go in SNI
      --  (RFC 6066 section 3).
      Parse ("192.0.2.1", Item, Status);
      Expect (Status = Looks_Like_IP_Address, "an IPv4 literal is refused as a DNS name");
      Parse ("2001:db8::1", Item, Status);
      Expect (Status = Looks_Like_IP_Address, "an IPv6 literal is refused as a DNS name");

      --  Non-ASCII must arrive as an A-label; this library does not guess at
      --  IDNA.
      Parse ("ex" & Character'Val (228) & "mple.com", Item, Status);
      Expect (Status = Not_ASCII, "a non-ASCII name is refused rather than guessed at");
      Parse ("xn--exmple-cua.com", Item, Status);
      Expect (Status = Ok, "an A-label passes through");

      --  Bounds.
      declare
         Long_Label : constant String (1 .. 64) := [others => 'a'];
      begin
         Parse (Long_Label & ".com", Item, Status);
         Expect (Status = Label_Too_Long, "a 64-octet label is refused");
      end;

      --  A wildcard is only a wildcard where one is expected.
      Parse ("*.example.com", Item, Status);
      Expect (Status = Wildcard_Not_Permitted, "a wildcard is refused as an exact name");

      Parse_Pattern ("*.example.com", Item, Status);
      Expect (Status = Ok, "a leftmost wildcard is a valid pattern");
      Expect (Is_Wildcard (Item), "the pattern is a wildcard");

      Parse_Pattern ("a*.example.com", Item, Status);
      Expect (Status = Wildcard_Label_Not_Alone, "a partial wildcard is refused");
      Parse_Pattern ("www.*.example.com", Item, Status);
      Expect (Status = Wildcard_Not_Leftmost, "a non-leftmost wildcard is refused");
      Parse_Pattern ("*.com", Item, Status);
      Expect (Status = Too_Few_Labels_For_Wildcard, "a registry-wide wildcard is refused");

      --  Matching, per RFC 6125 section 6.4.3.
      declare
         Pattern : DNS_Name;
         Narrow  : DNS_Name;
         Exact   : DNS_Name;
      begin
         Parse_Pattern ("*.example.com", Pattern, Status);
         Parse_Pattern ("*.a.example.com", Narrow, Status);
         Parse ("www.example.com", Exact, Status);

         Expect (Matches (Name ("www.example.com"), Pattern), "a wildcard matches one label");
         Expect (not Matches (Name ("example.com"), Pattern),
                 "a wildcard does not match the bare parent");
         Expect (not Matches (Name ("a.b.example.com"), Pattern),
                 "a wildcard does not match across a dot");
         Expect (not Matches (Name ("www.other.com"), Pattern),
                 "a wildcard does not match a different parent");

         --  An exact match is always more specific than any wildcard, and a
         --  narrower wildcard beats a broader one.
         Expect (Match_Specificity (Name ("www.example.com"), Exact)
                 > Match_Specificity (Name ("www.example.com"), Pattern),
                 "an exact match outranks a wildcard");
         Expect (Match_Specificity (Name ("x.a.example.com"), Narrow)
                 > Match_Specificity (Name ("x.a.example.com"), Pattern),
                 "a narrower wildcard outranks a broader one");
      end;

      --  IP identities.
      declare
         Address : IP_Address;
      begin
         Expect (Parse_Address ("192.0.2.1", Address), "an IPv4 literal parses");
         Expect (Octets (Address)'Length = 4, "an IPv4 address is four octets");
         Expect_Equal (Image (Address), "192.0.2.1", "IPv4 image round-trips");

         Expect (Parse_Address ("2001:db8::1", Address), "an IPv6 literal parses");
         Expect (Octets (Address)'Length = 16, "an IPv6 address is sixteen octets");

         Expect (not Parse_Address ("192.0.2.256", Address), "an octet above 255 is refused");
         Expect (not Parse_Address ("192.0.2", Address), "a three-part dotted quad is refused");
         Expect (not Parse_Address ("2001:db8::1::2", Address), "two gaps are refused");
         Expect (not Parse_Address ("", Address), "an empty address is refused");
      end;
   end Run_Server_Names;

   ---------------------------------------------------------------------------
   --  Limits
   ---------------------------------------------------------------------------

   procedure Run_Limits (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Limits (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      use SSL.Limits;
      Item : Resource_Limits;
   begin
      Expect (Is_Valid (Default_Limits), "the defaults are consistent");
      Expect (Is_Valid (Constrained_Limits), "the constrained profile is consistent");
      Expect_Equal (Invalidity (Default_Limits), "", "the defaults have no complaint");

      --  The documented suggested defaults.
      Expect (Default_Limits.Maximum_Plaintext_Record = 16_384, "plaintext record default");
      Expect (Default_Limits.Maximum_Handshake_Message = 1024 * 1024, "handshake message default");
      Expect (Default_Limits.Maximum_Certificate_Message = 4 * 1024 * 1024,
              "certificate message default");
      Expect (Default_Limits.Maximum_Certificate = 1024 * 1024, "individual certificate default");
      Expect (Default_Limits.Maximum_Certificate_Count = 16, "certificate count default");
      Expect (Default_Limits.Maximum_Extension_Block = 64 * 1024, "extension block default");
      Expect (Default_Limits.Maximum_Extension_Count = 64, "extension count default");
      --  The queues are what the engine reserves per connection, so these two
      --  numbers are a memory decision. They read a megabyte each while the
      --  engine reserved constants of its own and neither number reached a
      --  buffer; now that they do, they say what has always been reserved.
      Expect (Default_Limits.Maximum_Ciphertext_Queue = 8 * (16_384 + 256 + 5),
              "ciphertext queue default");
      Expect (Default_Limits.Maximum_Plaintext_Queue = 4 * 16_384,
              "plaintext queue default");
      Expect (Default_Limits.Maximum_Input_Buffer = 2 * (16_384 + 256 + 5),
              "input buffer default");
      Expect (Default_Limits.Maximum_Path_Depth = 12, "path depth default");

      --  Each inconsistency is refused with a named reason rather than
      --  deadlocking later.
      Item := Default_Limits;
      Item.Maximum_Plaintext_Record := 16_385;
      Expect (not Is_Valid (Item), "a record above the TLS ceiling is refused");

      Item := Default_Limits;
      Item.Maximum_Ciphertext_Queue := 100;
      Expect (not Is_Valid (Item), "a queue too small for one record is refused");

      Item := Default_Limits;
      Item.Key_Update_Record_Threshold := Item.Hard_Record_Limit;
      Expect (not Is_Valid (Item), "a soft threshold at the hard limit is refused");

      Item := Default_Limits;
      Item.Maximum_Certificate := Item.Maximum_Certificate_Message + 1;
      Expect (not Is_Valid (Item), "a certificate larger than its message is refused");

      Item := Default_Limits;
      Item.Maximum_Path_Depth := 1;
      Expect (not Is_Valid (Item), "a path shorter than leaf plus anchor is refused");

      --  Limit names are stable text and Value reads the matching field.
      Expect_Equal (Image (Certificate_Count), "certificate_count", "limit name");
      Expect (Value (Default_Limits, Certificate_Count) = 16, "limit value reads the right field");
      Expect (Value (Default_Limits, Path_Depth) = 12, "path depth value");
   end Run_Limits;

   ---------------------------------------------------------------------------
   --  Alerts and errors
   ---------------------------------------------------------------------------

   procedure Run_Alerts (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Alerts (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      use SSL.Alerts;
      Item : Alert;
   begin
      Expect (not Is_Present (No_Alert), "no alert is absent");

      Item := Local_Alert (Close_Notify);
      Expect (Level_Of (Item) = Warning_Level, "close_notify is a warning");
      Expect (not Is_Terminal (Item), "close_notify is not terminal");
      Expect (Is_Close_Notify (Item), "close_notify is recognized");
      Expect (Encode (Item) = SSL.Byte_Array'(1 => 1, 2 => 0), "close_notify encodes as 01 00");

      Item := Local_Alert (Handshake_Failure);
      Expect (Level_Of (Item) = Fatal_Level, "handshake_failure is fatal");
      Expect (Is_Terminal (Item), "handshake_failure is terminal");
      Expect (Value_Of (Item) = 40, "handshake_failure wire value");

      --  Wire values, written out rather than derived from positions.
      Expect (Value_For (Bad_Record_MAC) = 20, "bad_record_mac value");
      Expect (Value_For (Unknown_CA) = 48, "unknown_ca value");
      Expect (Value_For (No_Application_Protocol) = 120, "no_application_protocol value");
      Expect (Value_For (Certificate_Required) = 116, "certificate_required value");

      --  A peer's unknown alert keeps its number and gains no invented meaning.
      Item := Peer_Alert (Level_Octet => 2, Description_Octet => 200);
      Expect (Description_Of (Item) = Unknown_Alert, "an unknown description is not guessed at");
      Expect (Value_Of (Item) = 200, "the peer's number is preserved");
      Expect_Equal (Image (Item), "alert_200", "an unknown alert renders with its number");
      Expect (Is_Terminal (Item), "an uninterpretable alert is treated as terminal");

      --  A peer claiming that a fatal alert is only a warning does not make it
      --  survivable: the decision is on the description.
      Item := Peer_Alert (Level_Octet => 1, Description_Octet => 40);
      Expect (Is_Terminal (Item),
              "handshake_failure at warning level is still terminal");
   end Run_Alerts;

   procedure Run_Errors (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Errors (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      use SSL.Errors;
      Item   : Error_Information;
      Record_Of_Failures : Failure_Record := No_Failures;
   begin
      Expect (not Is_Error (No_Error), "no error is not an error");
      Expect_Equal (Image (No_Error), "ok", "no error renders as ok");

      --  Central alert mapping: the failure names a code and the table chooses
      --  the alert, the fatality, the retry class and the disclosure class.
      Item := Make (Code_Record_Authentication_Failed, Peer_Message);
      Expect (Is_Error (Item), "a made failure is a failure");
      Expect (Is_Fatal (Item), "an authentication failure is fatal");
      Expect (Category_Of (Item) = Record_Layer, "it is a record-layer failure");
      Expect (SSL.Alerts.Description_Of (Alert_Of (Item)) = SSL.Alerts.Bad_Record_MAC,
              "it maps to bad_record_mac");
      Expect (Disclosure_Of (Item) = Restricted, "its detail is restricted");

      --  A restricted failure renders without its parameters even in a local
      --  log, because logs are shipped.
      Item := Make (Code       => Code_Record_Authentication_Failed,
                    Origin     => Peer_Message,
                    Parameters => [Text_Parameter ("stage", "padding")]);
      Expect (Parameter_Count_Of (Item) = 1, "the parameter was recorded");
      declare
         Rendered : constant String := Image (Item);
      begin
         for Index in Rendered'First .. Rendered'Last - 6 loop
            Expect (Rendered (Index .. Index + 6) /= "padding",
                    "a restricted failure leaked a parameter into its image");
         end loop;
      end;

      --  A negotiation failure is safe to describe to the peer, and says so.
      Item := Make (Code_No_Application_Protocol_Overlap, Local_Policy);
      Expect (Disclosure_Of (Item) = Safe_For_Peer, "no ALPN overlap is safe to disclose");
      Expect (SSL.Alerts.Description_Of (Alert_Of (Item))
              = SSL.Alerts.No_Application_Protocol,
              "no ALPN overlap maps to no_application_protocol");
      Expect_Equal (Peer_Image (Item), "no_application_protocol", "the peer-facing account");

      --  A ticket that cannot be used is not fatal: it means a full handshake.
      Item := Make (Code_Ticket_Expired, Local_Policy);
      Expect (not Is_Fatal (Item), "an expired ticket is not fatal");
      Expect (Category_Of (Item) = Session, "an expired ticket is a session failure");
      Expect (not SSL.Alerts.Is_Present (Alert_Of (Item)),
              "an unusable ticket sends no alert, so it is no forgery oracle");

      --  A configuration failure has no alert: there is no peer yet.
      Item := Make (Code_Invalid_Limits, Local_Policy);
      Expect (not SSL.Alerts.Is_Present (Alert_Of (Item)), "a configuration failure sends nothing");
      Expect (Retry_Of (Item) = Retry_After_Reconfiguration, "it needs reconfiguration");

      --  Limit failures carry the limit's name, the bound and the request.
      Item := Limit_Failure (SSL.Limits.Certificate_Count, 16, 40);
      Expect (Parameter_Count_Of (Item) = 3, "a limit failure carries three facts");
      Expect (Category_Of (Item) = Resource, "a limit failure is a resource failure");

      --  First-terminal-error preservation: a soft failure is displaced by the
      --  first fatal one, and after that the primary never changes.
      Record_Failure (Record_Of_Failures, Make (Code_Ticket_Expired, Local_Policy));
      Expect (Code_Of (Primary (Record_Of_Failures)) = Code_Ticket_Expired,
              "the first failure is the primary while nothing fatal has happened");

      Record_Failure (Record_Of_Failures, Make (Code_Handshake_Message_Malformed, Peer_Message));
      Expect (Code_Of (Primary (Record_Of_Failures)) = Code_Handshake_Message_Malformed,
              "the first terminal failure becomes the primary");

      Record_Failure (Record_Of_Failures, Make (Code_Transport_Failed, Caller_Transport));
      Expect (Code_Of (Primary (Record_Of_Failures)) = Code_Handshake_Message_Malformed,
              "the primary terminal failure is never displaced");
      Expect (Secondary_Count (Record_Of_Failures) = 2, "later failures are counted");
      Expect (Has_Failure (Record_Of_Failures), "the record reports a failure");

      --  Application and provider failures an application can build itself.
      Item := Application_Refusal ("no route for that name");
      Expect (Category_Of (Item) = Application_Policy, "an application refusal is application policy");
      Expect (Origin_Of (Item) = Application_Callback, "its origin is the callback");
      Expect_Equal (Provider_Text (Item), "no route for that name", "the reason is carried");

      Item := Provider_Failure ("signer offline", Fatal => False);
      Expect (not Is_Fatal (Item), "a provider may declare its failure non-fatal");
      Item := Provider_Failure ("signer offline");
      Expect (Is_Fatal (Item), "a provider failure is fatal by default");
   end Run_Errors;


   ---------------------------------------------------------------------------
   --  Diagnostics and key logging
   ---------------------------------------------------------------------------

   --  A sink that remembers what it was given, and one that refuses to work.
   type Recording_Sink is limited new SSL.Diagnostics.Sink with record
      Seen  : Natural := 0;
      Last  : String (1 .. 256) := [others => ' '];
      Length : Natural := 0;
   end record;

   overriding procedure Emit
     (Item : in out Recording_Sink; What : SSL.Diagnostics.Event);
   overriding function Description (Item : Recording_Sink) return String;

   overriding procedure Emit
     (Item : in out Recording_Sink; What : SSL.Diagnostics.Event)
   is
      Line : constant String :=
        SSL.Diagnostics.Image (What, SSL.Diagnostics.Operational);
   begin
      Item.Seen := Item.Seen + 1;
      Item.Length := Natural'Min (Line'Length, Item.Last'Length);
      Item.Last := [others => ' '];
      Item.Last (1 .. Item.Length) := Line (Line'First .. Line'First + Item.Length - 1);
   end Emit;

   overriding function Description (Item : Recording_Sink) return String is
     ("recording sink" & (if Item.Seen = 0 then "" else ""));

   type Failing_Sink is limited new SSL.Diagnostics.Sink with null record;

   overriding procedure Emit
     (Item : in out Failing_Sink; What : SSL.Diagnostics.Event);
   overriding function Description (Item : Failing_Sink) return String;

   overriding procedure Emit
     (Item : in out Failing_Sink; What : SSL.Diagnostics.Event)
   is
      pragma Unreferenced (Item, What);
   begin
      raise Program_Error with "a sink that misbehaves";
   end Emit;

   overriding function Description (Item : Failing_Sink) return String is
     ("failing sink");

   type Key_Log_Sink is limited new SSL.Unsafe.Key_Logging.Sink with record
      Lines  : Natural := 0;
      Last   : String (1 .. 512) := [others => ' '];
      Length : Natural := 0;
   end record;

   overriding procedure Write_Line (Item : in out Key_Log_Sink; Line : String);
   overriding function Description (Item : Key_Log_Sink) return String;

   overriding procedure Write_Line (Item : in out Key_Log_Sink; Line : String) is
   begin
      Item.Lines := Item.Lines + 1;
      Item.Length := Natural'Min (Line'Length, Item.Last'Length);
      Item.Last := [others => ' '];
      Item.Last (1 .. Item.Length) := Line (Line'First .. Line'First + Item.Length - 1);
   end Write_Line;

   overriding function Description (Item : Key_Log_Sink) return String is
     ("key log sink" & (if Item.Lines = 0 then "" else ""));

   type Failing_Key_Log is limited new SSL.Unsafe.Key_Logging.Sink with null record;

   overriding procedure Write_Line (Item : in out Failing_Key_Log; Line : String);
   overriding function Description (Item : Failing_Key_Log) return String;

   overriding procedure Write_Line (Item : in out Failing_Key_Log; Line : String) is
      pragma Unreferenced (Item, Line);
   begin
      raise Constraint_Error with "a key log sink that misbehaves";
   end Write_Line;

   overriding function Description (Item : Failing_Key_Log) return String is
     ("failing key log");

   procedure Run_Diagnostics (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Diagnostics (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      package Diagnostics renames SSL.Diagnostics;

      Recorder : Recording_Sink;
      Broken   : Failing_Sink;

      Failure : constant SSL.Errors.Error_Information :=
        SSL.Errors.Make (SSL.Errors.Code_Certificate_Expired, SSL.Errors.Peer_Message);
   begin
      --  Nothing is emitted at Off, whatever the event is. A library that
      --  logged by default would be writing into an application's output
      --  uninvited.
      declare
         What : Diagnostics.Event :=
           Diagnostics.Make (Diagnostics.Connection_Failed, Failure);
      begin
         Diagnostics.Add (What, "reason", "expired");
         Diagnostics.Emit_Safely (Recorder, What, Diagnostics.Off, Diagnostics.Operational);
         Expect_Equal (Recorder.Seen, 0, "nothing is emitted at Off");

         --  A failure reaches an Errors_Only sink.
         Diagnostics.Emit_Safely
           (Recorder, What, Diagnostics.Errors_Only, Diagnostics.Operational);
         Expect_Equal (Recorder.Seen, 1, "a failure reaches an Errors_Only sink");
      end;

      --  A per-message event does not, because it is a Detailed_Protocol event
      --  and the level is the filter.
      declare
         What : constant Diagnostics.Event :=
           Diagnostics.Make (Diagnostics.Handshake_Message_Sent);
      begin
         Diagnostics.Emit_Safely
           (Recorder, What, Diagnostics.Errors_Only, Diagnostics.Operational);
         Expect_Equal (Recorder.Seen, 1, "a protocol event does not reach an Errors_Only sink");

         Diagnostics.Emit_Safely
           (Recorder, What, Diagnostics.Detailed_Protocol, Diagnostics.Operational);
         Expect_Equal (Recorder.Seen, 2, "it does reach a Detailed_Protocol sink");
      end;

      --  Strict redaction says the kind and the failure and no named facts,
      --  because a named fact is by definition something about this particular
      --  connection.
      declare
         What : Diagnostics.Event :=
           Diagnostics.Make (Diagnostics.Certificate_Refused, Failure);
         Strict_Line : String := Diagnostics.Image (What, Diagnostics.Strict);
      begin
         Diagnostics.Add (What, "name", "www.example.com");
         Strict_Line := Diagnostics.Image (What, Diagnostics.Strict);
         Expect (Index_Of (Strict_Line, "www.example.com") = 0,
                 "strict redaction withholds the server name");
         Expect (Index_Of (Diagnostics.Image (What, Diagnostics.Operational),
                           "www.example.com") > 0,
                 "operational redaction includes it");
      end;

      --  At most four facts, and a fifth is dropped rather than raising: an
      --  event that raised while being built would turn a diagnostic into a
      --  failure.
      declare
         What : Diagnostics.Event := Diagnostics.Make (Diagnostics.Handshake_Completed);
      begin
         Diagnostics.Add (What, "a", "1");
         Diagnostics.Add (What, "b", "2");
         Diagnostics.Add (What, "c", "3");
         Diagnostics.Add (What, "d", "4");
         Diagnostics.Add (What, "e", "5");
         Expect (Index_Of (Diagnostics.Image (What, Diagnostics.Operational), "e=5") = 0,
                 "a fifth fact is dropped");
         Expect (Index_Of (Diagnostics.Image (What, Diagnostics.Operational), "d=4") > 0,
                 "the fourth is kept");
      end;

      --  A sink that raises loses its event and nothing else. Turning that into
      --  a connection failure would let an application break its own
      --  connections by writing a bad logger.
      declare
         What : constant Diagnostics.Event :=
           Diagnostics.Make (Diagnostics.Connection_Failed, Failure);
      begin
         Diagnostics.Emit_Safely
           (Broken, What, Diagnostics.Detailed_Protocol, Diagnostics.Operational);
         Expect (True, "a sink that raises does not propagate");
      end;
   end Run_Diagnostics;

   procedure Run_Key_Logging (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Key_Logging (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      package Logging renames SSL.Unsafe.Key_Logging;

      Recorder : Key_Log_Sink;
      Broken   : Failing_Key_Log;

      Client_Random : constant SSL.Byte_Array (1 .. 32) := [others => 16#AB#];
      Secret        : constant SSL.Byte_Array (1 .. 32) := [others => 16#01#];
      Error         : SSL.Errors.Error_Information;
   begin
      --  The labels are the reference implementation's, exactly. The whole
      --  point of the format is that an existing capture tool can read it, and
      --  a label of this library's own invention would produce a line no tool
      --  understands.
      Expect_Equal (Logging.Image (Logging.Client_Traffic_Secret_0),
                    "CLIENT_TRAFFIC_SECRET_0", "the label is the standard one");
      Expect_Equal (Logging.Image (Logging.Client_Random_To_Master),
                    "CLIENT_RANDOM", "the TLS 1.2 label is CLIENT_RANDOM");

      Logging.Emit (Recorder, Logging.Client_Traffic_Secret_0, Client_Random, Secret, Error);
      Expect (not SSL.Errors.Is_Error (Error), "emitting a key log line succeeds");
      Expect_Equal (Recorder.Lines, 1, "one line was written");
      --  Thirty-two octets of 16#AB# and thirty-two of 16#01#, in lower-case
      --  hexadecimal, written out rather than computed: a rendering checked
      --  against a rendering produced the same way would pass however wrong
      --  both were.
      Expect_Equal
        (Recorder.Last (1 .. Recorder.Length),
         "CLIENT_TRAFFIC_SECRET_0 "
         & "abababababababababababababababababababababababababababababababab"
         & " "
         & "0101010101010101010101010101010101010101010101010101010101010101",
         "the line is label, client random, secret");

      --  A sink that raises becomes a structured provider failure naming it,
      --  rather than an exception unwinding a connection with keys installed.
      Logging.Emit (Broken, Logging.Server_Traffic_Secret_0, Client_Random, Secret, Error);
      Expect (SSL.Errors.Is_Error (Error), "a key log sink that raises is caught");
      Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Application_Callback_Raised,
              "it is reported as a callback that raised");
      Expect (Index_Of (SSL.Errors.Image (Error), "failing key log") > 0,
              "the failure names the sink");
   end Run_Key_Logging;

   procedure Run_Identifiers (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Identifiers (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Fingerprint : SSL.Certificate_Fingerprint;
      Text : constant String (1 .. 64) := [others => 'a'];
   begin
      Expect (not SSL.Is_Present (SSL.No_Connection), "no connection is absent");
      Expect (not SSL.Is_Present (SSL.No_Credential), "no credential is absent");
      Expect (not SSL.Is_Present (SSL.No_Session), "no session is absent");
      Expect_Equal (SSL.Image (SSL.No_Connection), "-", "no connection renders as a dash");

      Expect (SSL.Security_Context ("tenant-a") /= SSL.Security_Context ("tenant-b"),
              "different context labels give different contexts");
      Expect (SSL.Security_Context ("") = SSL.Default_Security_Context,
              "an empty label is the default context");

      Expect (SSL.Parse_Fingerprint (Text, SSL.Whole_Certificate, Fingerprint),
              "a 64-character hexadecimal fingerprint parses");
      Expect_Equal (SSL.Image (Fingerprint), Text, "the fingerprint image round-trips");
      Expect (SSL.Subject_Of (Fingerprint) = SSL.Whole_Certificate, "the subject is recorded");

      Expect (not SSL.Parse_Fingerprint ("abcd", SSL.Whole_Certificate, Fingerprint),
              "a short fingerprint is refused");
      declare
         Bad : constant String (1 .. 64) := [others => 'z'];
      begin
         Expect (not SSL.Parse_Fingerprint (Bad, SSL.Whole_Certificate, Fingerprint),
                 "a non-hexadecimal fingerprint is refused");
      end;

      --  A certificate fingerprint and an SPKI fingerprint over the same digest
      --  are different values, so a pin cannot be matched against the wrong
      --  kind of digest.
      declare
         As_Certificate : SSL.Certificate_Fingerprint;
         As_Key         : SSL.Certificate_Fingerprint;
      begin
         Expect (SSL.Parse_Fingerprint (Text, SSL.Whole_Certificate, As_Certificate), "cert pin");
         Expect (SSL.Parse_Fingerprint (Text, SSL.Public_Key_Info, As_Key), "spki pin");
         Expect (As_Certificate /= As_Key,
                 "a certificate pin and an SPKI pin over the same digest are distinct");
      end;
   end Run_Identifiers;

   ---------------------
   -- Register_Tests --
   ---------------------

   overriding procedure Register_Tests (T : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Run_Versions'Access, "versions: values, sets, legacy refusal");
      Register_Routine (T, Run_Cipher_Suites'Access, "suites: values, composition, absences");
      Register_Routine (T, Run_Groups'Access, "groups: code points and share lengths");
      Register_Routine (T, Run_Signature_Schemes'Access, "schemes: values, version rules, absences");
      Register_Routine (T, Run_ALPN'Access, "alpn: opaque names, selection, policy");
      Register_Routine (T, Run_Server_Names'Access, "names: normalization, wildcards, addresses");
      Register_Routine (T, Run_Limits'Access, "limits: defaults and consistency");
      Register_Routine (T, Run_Alerts'Access, "alerts: values, terminality, unknown peer alerts");
      Register_Routine (T, Run_Errors'Access, "errors: mapping, disclosure, accumulation");
      Register_Routine (T, Run_Identifiers'Access, "identifiers: contexts and fingerprints");
      Register_Routine (T, Run_Diagnostics'Access,
                        "diagnostics: levels, redaction, bounded facts, a sink that raises");
      Register_Routine (T, Run_Key_Logging'Access,
                        "key logging: standard labels, line format, a sink that raises");
   end Register_Tests;

end Tests_Public;
