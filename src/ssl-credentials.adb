with CryptoLib.ASN1;
with CryptoLib.ASN1.Errors;
with CryptoLib.ECDSA;
with CryptoLib.Ed25519;
with CryptoLib.Ed448;
with CryptoLib.Errors;
with CryptoLib.PEM;
with CryptoLib.Random;
with CryptoLib.RSA;
with CryptoLib.Secure_Wipe;
with CryptoLib.X509;
with CryptoLib.X509.Certificates;
with CryptoLib.X509.Extensions;

with SSL.Crypto;

package body SSL.Credentials is

   use type CryptoLib.ASN1.Errors.Decode_Status;
   use type CryptoLib.PEM.Decode_Status;
   use type SSL.Signature_Schemes.Signature_Scheme;
   use type SSL.Signature_Schemes.RSA_Padding;
   use type SSL.Signature_Schemes.Key_Kind;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Identities.Identity_Status;
   use type CryptoLib.PKCS8.Unlock_Status;
   use type CryptoLib.X509.Extensions.General_Name_Kind;
   use type CryptoLib.X509.Public_Key_Algorithm;
   use type SSL.Server_Names.Name_Status;

   package Schemes renames SSL.Signature_Schemes;

   -----------
   -- Image --
   -----------

   function Image (Item : Key_Kind) return String is
   begin
      case Item is
         when RSA_Key     => return "rsa";
         when ECDSA_P256  => return "ecdsa_p256";
         when ECDSA_P384  => return "ecdsa_p384";
         when ECDSA_P521  => return "ecdsa_p521";
         when Ed25519_Key => return "ed25519";
         when Ed448_Key   => return "ed448";
      end case;
   end Image;

   ---------------
   -- Accessors --
   ---------------

   function Is_Loaded (Item : Credential) return Boolean is (Item.Loaded);
   function Key_Type (Item : Credential) return Key_Kind is (Item.Kind);
   function Chain_Length (Item : Credential) return Positive is (Item.Count);

   function Certificate_At (Item : Credential; Index : Positive) return Byte_Array
   is (Item.Chain (Item.Spans (Index).First .. Item.Spans (Index).Last));

   function Leaf_Fingerprint (Item : Credential) return Certificate_Fingerprint
   is (Item.Leaf_Digest);
   function Public_Key_Fingerprint (Item : Credential) return Certificate_Fingerprint
   is (Item.Key_Digest);

   function Supports
     (Item : Credential; Scheme : Schemes.Signature_Scheme) return Boolean
   is (Schemes.Contains (Item.Schemes, Scheme));

   function Supported_Schemes (Item : Credential) return Schemes.Scheme_List
   is (Item.Schemes);

   function Identity_Count (Item : Credential) return Natural is (Item.Identity_Total);
   function Identity_At (Item : Credential; Index : Positive) return SSL.Server_Names.DNS_Name
   is (Item.Identities (Index));

   function Covers (Item : Credential; Name : SSL.Server_Names.DNS_Name) return Natural is
      Best : Natural := 0;
   begin
      --  The best match across every name the leaf carries, so that a
      --  certificate holding both "example.com" and "*.example.com" is scored
      --  on whichever fits the request more tightly.
      for Index in 1 .. Item.Identity_Total loop
         declare
            Score : constant Natural :=
              SSL.Server_Names.Match_Specificity (Name, Item.Identities (Index));
         begin
            if Score > Best then
               Best := Score;
            end if;
         end;
      end loop;
      return Best;
   end Covers;

   ----------
   -- Wipe --
   ----------

   procedure Wipe (Item : in out Credential) is
   begin
      CryptoLib.PKCS8.Wipe (Item.Key);
      CryptoLib.Identities.Wipe (Item.Structure);
      SSL.Secrets.Wipe (Item.Public_Key);

      --  The chain is public material, so it is cleared rather than scrubbed --
      --  but clearing it is still worth doing, because a credential that has
      --  been wiped must not go on presenting a certificate.
      Item.Chain := [others => 0];
      Item.Held := 0;
      Item.Count := 0;
      Item.Identity_Total := 0;
      Item.Schemes := Schemes.No_Schemes;
      Item.Loaded := False;
   end Wipe;

   overriding procedure Finalize (Item : in out Credential) is
   begin
      Wipe (Item);
   end Finalize;

   ---------------------------------------------------------------------------
   --  Loading
   ---------------------------------------------------------------------------

   --  Map CryptoLib's structural verdict onto this library's error taxonomy.
   function Structural_Failure
     (Status : CryptoLib.Identities.Identity_Status) return SSL.Errors.Error_Information;

   function Structural_Failure
     (Status : CryptoLib.Identities.Identity_Status) return SSL.Errors.Error_Information
   is
      use SSL.Errors;
   begin
      case Status is
         when CryptoLib.Identities.Ok =>
            return No_Error;

         when CryptoLib.Identities.Key_Mismatch =>
            --  The configuration mistake this check exists for: a certificate
            --  and a key that do not belong together, caught at load rather
            --  than at the first handshake.
            return Make
              (Code     => Code_Credential_Unusable,
               Origin   => Local_Policy,
               Provider => "private key does not match the leaf certificate");

         when CryptoLib.Identities.Chain_Out_Of_Order =>
            return Make
              (Code     => Code_Credential_Unusable,
               Origin   => Local_Policy,
               Provider => "chain is not leaf-first issuer order");

         when others =>
            return Make
              (Code     => Code_Credential_Unusable,
               Origin   => Local_Policy,
               Provider => "cryptolib:" & CryptoLib.Identities.Status_Image (Status));
      end case;
   end Structural_Failure;

   --  Which schemes a key of this kind and size can actually produce.
   --
   --  Worked out once, at load, so that credential selection during a handshake
   --  is a lookup. RFC 8446 section 4.2.3 binds each ECDSA scheme to one curve,
   --  which is why a P-256 key gets exactly one ECDSA scheme and not three.
   procedure Derive_Schemes
     (Item  : in out Credential;
      Error : out SSL.Errors.Error_Information);

   procedure Derive_Schemes
     (Item  : in out Credential;
      Error : out SSL.Errors.Error_Information)
   is
      Done : Boolean;
   begin
      Item.Schemes := Schemes.No_Schemes;
      Error := SSL.Errors.No_Error;

      case Item.Kind is
         when Ed25519_Key =>
            Schemes.Append (Item.Schemes, Schemes.Ed25519, Done);

         when Ed448_Key =>
            Schemes.Append (Item.Schemes, Schemes.Ed448, Done);

         when ECDSA_P256 =>
            Schemes.Append (Item.Schemes, Schemes.ECDSA_Secp256r1_SHA256, Done);

         when ECDSA_P384 =>
            Schemes.Append (Item.Schemes, Schemes.ECDSA_Secp384r1_SHA384, Done);

         when ECDSA_P521 =>
            Schemes.Append (Item.Schemes, Schemes.ECDSA_Secp521r1_SHA512, Done);

         when RSA_Key =>
            declare
               Bits : constant Natural :=
                 CryptoLib.RSA.Modulus_Bits (CryptoLib.PKCS8.RSA_Modulus (Item.Key));
            begin
               --  A key too small to be worth anything is refused at load
               --  rather than offered and then declined by a peer. 2048 is the
               --  floor CryptoLib's path validation also applies.
               if Bits < 2048 then
                  Error := SSL.Errors.Make
                    (Code       => SSL.Errors.Code_Certificate_Weak_Key,
                     Origin     => SSL.Errors.Local_Policy,
                     Parameters =>
                       [SSL.Errors.Numeric_Parameter ("modulus_bits", Long_Long_Integer (Bits)),
                        SSL.Errors.Numeric_Parameter ("minimum", 2048)]);
                  return;
               end if;

               --  PSS first: it is what TLS 1.3 requires and what a TLS 1.2
               --  peer should prefer. PKCS#1 v1.5 follows, usable only for
               --  TLS 1.2, which Schemes.Usable_For_Handshake enforces
               --  independently of this list.
               Schemes.Append (Item.Schemes, Schemes.RSA_PSS_RSAE_SHA256, Done);
               Schemes.Append (Item.Schemes, Schemes.RSA_PSS_RSAE_SHA384, Done);
               Schemes.Append (Item.Schemes, Schemes.RSA_PSS_RSAE_SHA512, Done);
               Schemes.Append (Item.Schemes, Schemes.RSA_PKCS1_SHA256, Done);
               Schemes.Append (Item.Schemes, Schemes.RSA_PKCS1_SHA384, Done);
               Schemes.Append (Item.Schemes, Schemes.RSA_PKCS1_SHA512, Done);
            end;
      end case;

      if Schemes.Is_Empty (Item.Schemes) then
         Error := SSL.Errors.Make
           (Code     => SSL.Errors.Code_Credential_Unusable,
            Origin   => SSL.Errors.Local_Policy,
            Provider => "key can produce no signature scheme this library offers");
      end if;
   end Derive_Schemes;

   --  Read the leaf: its key kind, its fingerprints, its public key and the DNS
   --  names it may be presented for.
   procedure Read_Leaf
     (Item   : in out Credential;
      Bounds : SSL.Limits.Resource_Limits;
      Error  : out SSL.Errors.Error_Information);

   procedure Read_Leaf
     (Item   : in out Credential;
      Bounds : SSL.Limits.Resource_Limits;
      Error  : out SSL.Errors.Error_Information)
   is
      Limits : constant CryptoLib.ASN1.Decode_Limits :=
        (Maximum_Input_Size     => Bounds.Maximum_Certificate,
         Maximum_Nesting_Depth  => 16,
         Maximum_Sequence_Items => 1024,
         Maximum_String_Length  => 64 * 1024);
      Status : CryptoLib.ASN1.Errors.Decode_Status;

      --  The span directly, not Certificate_At: that accessor's precondition
      --  requires a loaded credential, and this runs while one is still being
      --  built. The precondition is right for callers and wrong for the loader,
      --  so the loader does not go through it.
      Leaf   : constant Byte_Array :=
        Item.Chain (Item.Spans (1).First .. Item.Spans (1).Last);
   begin
      Error := SSL.Errors.No_Error;

      declare
         Parsed : constant CryptoLib.X509.Certificates.Certificate :=
           CryptoLib.X509.Certificates.Decode_DER (Leaf, Limits, Status);
      begin
         if Status /= CryptoLib.ASN1.Errors.Ok then
            Error := SSL.Errors.Make
              (Code   => SSL.Errors.Code_Certificate_Malformed,
               Origin => SSL.Errors.Local_Policy);
            return;
         end if;

         case CryptoLib.X509.Certificates.Public_Key_Algorithm_Of (Parsed) is
            when CryptoLib.X509.RSA        => Item.Kind := RSA_Key;
            when CryptoLib.X509.ECDSA_P256 => Item.Kind := ECDSA_P256;
            when CryptoLib.X509.ECDSA_P384 => Item.Kind := ECDSA_P384;
            when CryptoLib.X509.ECDSA_P521 => Item.Kind := ECDSA_P521;
            when CryptoLib.X509.Ed25519    => Item.Kind := Ed25519_Key;
            when CryptoLib.X509.Ed448      => Item.Kind := Ed448_Key;
            when others =>
               Error := SSL.Errors.Make
                 (Code     => SSL.Errors.Code_Credential_Unusable,
                  Origin   => SSL.Errors.Local_Policy,
                  Provider => "leaf certificate holds a key type this library cannot use");
               return;
         end case;

         --  Fingerprints over the DER and over the SubjectPublicKeyInfo. Both
         --  are SHA-256 through the CryptoLib seam; neither is computed here.
         Item.Leaf_Digest :=
           (Subject => Whole_Certificate, Digest => SSL.Crypto.SHA_256 (Leaf));
         Item.Key_Digest :=
           (Subject => Public_Key_Info,
            Digest  => SSL.Crypto.SHA_256
                         (CryptoLib.X509.Certificates.Public_Key_Info_Bytes (Parsed)));

         --  The raw public key, which EdDSA signing needs alongside the seed.
         SSL.Secrets.Set (Item.Public_Key, CryptoLib.X509.Certificates.Public_Key (Parsed));

         --  subjectAltName DNS entries, and only those. There is no Common Name
         --  fallback here for the same reason there is none in identity
         --  matching: a CN is a free-text display field.
         Item.Identity_Total := 0;
         for Index in 1 .. CryptoLib.X509.Extensions.Subject_Alternative_Name_Count (Parsed) loop
            exit when Item.Identity_Total = Maximum_Identities;

            if CryptoLib.X509.Extensions.Subject_Alternative_Name_Kind (Parsed, Index)
              = CryptoLib.X509.Extensions.DNS_Name
            then
               declare
                  Text   : constant String :=
                    CryptoLib.X509.Extensions.Subject_Alternative_Name_Text (Parsed, Index);
                  Name   : SSL.Server_Names.DNS_Name;
                  Result : SSL.Server_Names.Name_Status;
               begin
                  --  A SAN may legitimately be a wildcard pattern, which is the
                  --  whole point of Parse_Pattern rather than Parse here.
                  SSL.Server_Names.Parse_Pattern (Text, Name, Result);
                  if Result = SSL.Server_Names.Ok then
                     Item.Identity_Total := Item.Identity_Total + 1;
                     Item.Identities (Item.Identity_Total) := Name;
                  end if;
               end;
            end if;
         end loop;
      end;
   end Read_Leaf;

   --  Decode the PEM chain into the credential's own storage.
   procedure Read_Chain
     (Item      : in out Credential;
      Chain_PEM : String;
      Bounds    : SSL.Limits.Resource_Limits;
      Error     : out SSL.Errors.Error_Information);

   procedure Read_Chain
     (Item      : in out Credential;
      Chain_PEM : String;
      Bounds    : SSL.Limits.Resource_Limits;
      Error     : out SSL.Errors.Error_Information)
   is
      From   : Positive := Chain_PEM'First;
      Status : CryptoLib.PEM.Decode_Status;
   begin
      Error := SSL.Errors.No_Error;
      Item.Count := 0;
      Item.Held := 0;

      loop
         exit when Item.Count = Maximum_Chain or else From > Chain_PEM'Last;

         --  Decoded straight into the chain, with no temporary.
         --
         --  The same shape as the trust store's loader, and fixed the same
         --  way: a stack buffer sized to the whole remaining chain capacity,
         --  declared inside a loop, to hold one certificate that is then
         --  copied into storage the record already owns. `Last` is an index
         --  into the slice passed, so with the slice starting at Item.Held + 1
         --  the certificate occupies Item.Held + 1 .. Last.
         declare
            Room : constant Byte_Index := Maximum_Chain_Octets - Item.Held;
            Last : Byte_Index;
         begin
            if Room = 0 then
               Error := SSL.Errors.Limit_Failure
                 (Kind      => SSL.Limits.Certificate_Size,
                  Allowed   => Long_Long_Integer (Maximum_Chain_Octets),
                  Requested => Long_Long_Integer (Maximum_Chain_Octets) + 1,
                  Origin    => SSL.Errors.Local_Policy,
                  Stage     => SSL.Errors.Stage_Uninitialized);
               return;
            end if;

            CryptoLib.PEM.Decode_Block
              (Text   => Chain_PEM,
               Label  => CryptoLib.PEM.Certificate_Label,
               From   => From,
               Output => Item.Chain (Item.Held + 1 .. Item.Held + Room),
               Last   => Last,
               Status => Status);

            exit when Status = CryptoLib.PEM.No_Block_Found;

            if Status /= CryptoLib.PEM.Ok then
               Error := SSL.Errors.Make
                 (Code     => SSL.Errors.Code_Certificate_Malformed,
                  Origin   => SSL.Errors.Local_Policy,
                  Provider => "pem:" & CryptoLib.PEM.Status_Image (Status));
               return;
            end if;

            if Last - Item.Held > Byte_Index (Bounds.Maximum_Certificate) then
               Error := SSL.Errors.Limit_Failure
                 (Kind      => SSL.Limits.Certificate_Size,
                  Allowed   => Long_Long_Integer (Bounds.Maximum_Certificate),
                  Requested => Long_Long_Integer (Last - Item.Held),
                  Origin    => SSL.Errors.Local_Policy,
                  Stage     => SSL.Errors.Stage_Uninitialized);
               return;
            end if;

            if Last <= Item.Held then
               --  Nothing written: Decode_Block reports Output'First - 1.
               exit;
            end if;

            Item.Count := Item.Count + 1;
            Item.Spans (Item.Count) := (First => Item.Held + 1, Last => Last);
            Item.Held := Last;
         end;
      end loop;

      if Item.Count = 0 then
         Error := SSL.Errors.Make
           (Code     => SSL.Errors.Code_Certificate_List_Empty,
            Origin   => SSL.Errors.Local_Policy,
            Provider => "no CERTIFICATE block in the supplied text");
      end if;
   end Read_Chain;

   --  The tail every loader shares once the chain and the key are in place.
   procedure Complete_Load
     (Item      : in out Credential;
      Chain_PEM : String;
      Key_PEM   : String;
      Bounds    : SSL.Limits.Resource_Limits;
      Error     : out SSL.Errors.Error_Information);

   procedure Complete_Load
     (Item      : in out Credential;
      Chain_PEM : String;
      Key_PEM   : String;
      Bounds    : SSL.Limits.Resource_Limits;
      Error     : out SSL.Errors.Error_Information)
   is
      Structural : CryptoLib.Identities.Identity_Status;
   begin
      Read_Chain (Item, Chain_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      Read_Leaf (Item, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      --  The key-matches-leaf and chain-order checks are CryptoLib's, and are
      --  run against the unencrypted PEM. For an encrypted key the caller has
      --  already been given the decrypted form, so this sees the same material
      --  either way.
      if Key_PEM /= "" then
         CryptoLib.Identities.Decode
           (Certificate_Chain_PEM => Chain_PEM,
            Private_Key_PEM       => Key_PEM,
            Item                  => Item.Structure,
            Status                => Structural);

         Error := Structural_Failure (Structural);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;
      end if;

      Derive_Schemes (Item, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      Item.Loaded := True;
   end Complete_Load;

   procedure Load_PEM
     (Item      : in out Credential;
      Chain_PEM : String;
      Key_PEM   : String;
      Bounds    : SSL.Limits.Resource_Limits;
      Error     : out SSL.Errors.Error_Information)
   is
      Limits : constant CryptoLib.ASN1.Decode_Limits :=
        (Maximum_Input_Size     => CryptoLib.PKCS8.Maximum_Key_Size,
         Maximum_Nesting_Depth  => 16,
         Maximum_Sequence_Items => 1024,
         Maximum_String_Length  => 64 * 1024);
      From   : Positive := Key_PEM'First;
      Buffer : Byte_Array (1 .. Byte_Index (CryptoLib.PEM.Maximum_Decoded_Length (Key_PEM)));
      Last   : Byte_Index;
      Status : CryptoLib.PEM.Decode_Status;
      Decode : CryptoLib.ASN1.Errors.Decode_Status;
   begin
      Wipe (Item);

      CryptoLib.PEM.Decode_Block
        (Text   => Key_PEM,
         Label  => CryptoLib.PEM.Private_Key_Label,
         From   => From,
         Output => Buffer,
         Last   => Last,
         Status => Status);

      if Status /= CryptoLib.PEM.Ok then
         Error := SSL.Errors.Make
           (Code     => SSL.Errors.Code_Credential_Unusable,
            Origin   => SSL.Errors.Local_Policy,
            Provider => "pem key:" & CryptoLib.PEM.Status_Image (Status));
         CryptoLib.Secure_Wipe.Wipe (Buffer'Address, Natural (Buffer'Length));
         return;
      end if;

      CryptoLib.PKCS8.Decode_DER (Buffer (1 .. Last), Limits, Item.Key, Decode);
      CryptoLib.Secure_Wipe.Wipe (Buffer'Address, Natural (Buffer'Length));

      if Decode /= CryptoLib.ASN1.Errors.Ok then
         Error := SSL.Errors.Make
           (Code     => SSL.Errors.Code_Credential_Unusable,
            Origin   => SSL.Errors.Local_Policy,
            Provider => "pkcs8 key could not be decoded");
         return;
      end if;

      Complete_Load (Item, Chain_PEM, Key_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         Wipe (Item);
      end if;
   end Load_PEM;

   procedure Load_Encrypted_PEM
     (Item      : in out Credential;
      Chain_PEM : String;
      Key_PEM   : String;
      Password  : String;
      Bounds    : SSL.Limits.Resource_Limits;
      Error     : out SSL.Errors.Error_Information)
   is
      Limits : constant CryptoLib.ASN1.Decode_Limits :=
        (Maximum_Input_Size     => CryptoLib.PKCS8.Maximum_Key_Size,
         Maximum_Nesting_Depth  => 16,
         Maximum_Sequence_Items => 1024,
         Maximum_String_Length  => 64 * 1024);
      From   : Positive := Key_PEM'First;
      Buffer : Byte_Array (1 .. Byte_Index (CryptoLib.PEM.Maximum_Decoded_Length (Key_PEM)));
      Last   : Byte_Index;
      Status : CryptoLib.PEM.Decode_Status;
      Unlock : CryptoLib.PKCS8.Unlock_Status;
   begin
      Wipe (Item);

      CryptoLib.PEM.Decode_Block
        (Text   => Key_PEM,
         Label  => "ENCRYPTED PRIVATE KEY",
         From   => From,
         Output => Buffer,
         Last   => Last,
         Status => Status);

      if Status /= CryptoLib.PEM.Ok then
         Error := SSL.Errors.Make
           (Code     => SSL.Errors.Code_Credential_Unusable,
            Origin   => SSL.Errors.Local_Policy,
            Provider => "pem key:" & CryptoLib.PEM.Status_Image (Status));
         CryptoLib.Secure_Wipe.Wipe (Buffer'Address, Natural (Buffer'Length));
         return;
      end if;

      --  The iteration ceiling is CryptoLib's default: a PBKDF2 count chosen by
      --  whoever wrote the file is an attacker-chosen amount of work if the
      --  file came from anywhere untrusted.
      CryptoLib.PKCS8.Decode_Encrypted_DER
        (Data     => Buffer (1 .. Last),
         Password => Password,
         Limits   => Limits,
         Item     => Item.Key,
         Status   => Unlock);

      CryptoLib.Secure_Wipe.Wipe (Buffer'Address, Natural (Buffer'Length));

      if Unlock /= CryptoLib.PKCS8.Ok then
         Error := SSL.Errors.Make
           (Code     => SSL.Errors.Code_Credential_Unusable,
            Origin   => SSL.Errors.Local_Policy,
            Provider => "pkcs8:" & CryptoLib.PKCS8.Unlock_Image (Unlock));
         return;
      end if;

      --  The structural check needs the key in unencrypted PEM form, which is
      --  not available here without re-encoding it -- and re-encoding a
      --  decrypted private key into a String, to hand it back to a checker,
      --  would put the key in a buffer this library does not control. The
      --  key/leaf match is instead established by the signing self-test below.
      Complete_Load (Item, Chain_PEM, "", Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         Wipe (Item);
      end if;
   end Load_Encrypted_PEM;

   ---------------------------------------------------------------------------
   --  Signing
   ---------------------------------------------------------------------------

   procedure Sign
     (Item        : Credential;
      Scheme      : Schemes.Signature_Scheme;
      Signed_Data : Byte_Array;
      Signature   : out Byte_Array;
      Length      : out Byte_Index;
      Error       : out SSL.Errors.Error_Information)
   is
      Source : CryptoLib.Random.Random_Source;
   begin
      Signature := [others => 0];
      Length := 0;

      if not Supports (Item, Scheme) then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Signer_Capability_Missing,
            Origin     => SSL.Errors.Local_Policy,
            Parameters =>
              [SSL.Errors.Text_Parameter ("scheme", Schemes.Image (Scheme)),
               SSL.Errors.Text_Parameter ("key", Image (Item.Kind))]);
         return;
      end if;

      CryptoLib.Random.Initialize_Production (Source);

      case Schemes.Key_Kind_Of (Scheme) is

         when Schemes.EdDSA_Key =>
            declare
               Seed   : constant Byte_Array := CryptoLib.PKCS8.Private_Value (Item.Key);
               Public : constant Byte_Array := SSL.Secrets.Value (Item.Public_Key);
               Status : CryptoLib.Errors.Status;
            begin
               if Scheme = Schemes.Ed25519 then
                  Length := Byte_Index (CryptoLib.Ed25519.Signature_Length);
                  Status := CryptoLib.Ed25519.Sign
                    (Seed_Bytes       => Seed,
                     Public_Key_Bytes => Public,
                     Message_Bytes    => Signed_Data,
                     Signature_Bytes  => Signature (Signature'First
                                                    .. Signature'First + Length - 1));
               else
                  Length := Byte_Index (CryptoLib.Ed448.Signature_Length);
                  Status := CryptoLib.Ed448.Sign
                    (Seed_Bytes       => Seed,
                     Public_Key_Bytes => Public,
                     Message_Bytes    => Signed_Data,
                     Signature_Bytes  => Signature (Signature'First
                                                    .. Signature'First + Length - 1));
               end if;

               if Status /= CryptoLib.Errors.Ok then
                  Signature := [others => 0];
                  Length := 0;
                  Error := SSL.Errors.Make
                    (Code     => SSL.Errors.Code_Signature_Generation_Failed,
                     Origin   => SSL.Errors.Local_Implementation,
                     Provider => "cryptolib:" & Status'Image);
                  return;
               end if;
            end;

         when Schemes.RSA_Key =>
            declare
               Modulus  : constant Byte_Array := CryptoLib.PKCS8.RSA_Modulus (Item.Key);
               Exponent : constant Byte_Array := CryptoLib.PKCS8.RSA_Exponent (Item.Key);
               Private_Exponent : constant Byte_Array :=
                 CryptoLib.PKCS8.RSA_Private_Exponent (Item.Key);
               Hash : constant CryptoLib.RSA.Hash_Algorithm :=
                 (case Schemes.Hash_Of (Scheme) is
                     when Schemes.SHA_256 => CryptoLib.RSA.SHA256,
                     when Schemes.SHA_384 => CryptoLib.RSA.SHA384,
                     when others          => CryptoLib.RSA.SHA512);
               --  The signature is exactly as wide as the modulus is
               --  *significant*, not as wide as its DER integer is encoded. A
               --  DER INTEGER whose top bit is set carries a leading zero
               --  octet, and every RSA modulus has its top bit set -- so
               --  taking the encoded length made every signature buffer one
               --  octet too long, and CryptoLib refused each one because
               --  RFC 8017 fixes the length at exactly k.
               Width  : constant Byte_Index :=
                 Byte_Index ((CryptoLib.RSA.Modulus_Bits (Modulus) + 7) / 8);
               Status : CryptoLib.Errors.Status;
            begin
               if Width > Maximum_Signature_Length then
                  Error := SSL.Errors.Make
                    (Code     => SSL.Errors.Code_Signature_Generation_Failed,
                     Origin   => SSL.Errors.Local_Policy,
                     Provider => "rsa modulus wider than this library signs with");
                  return;
               end if;

               Length := Width;

               --  The chinese-remainder parameters are passed when the key
               --  carries them: signing without them is several times slower,
               --  and CryptoLib takes them as optional arguments precisely so a
               --  caller need not branch.
               if Schemes.Padding_Of (Scheme) = Schemes.PKCS1_V1_5 then
                  Status := CryptoLib.RSA.Sign_PKCS1_V1_5
                    (Modulus          => Modulus,
                     Public_Exponent  => Exponent,
                     Private_Exponent => Private_Exponent,
                     Hash             => Hash,
                     Message          => Signed_Data,
                     Rng              => Source,
                     Signature        => Signature (Signature'First
                                                    .. Signature'First + Width - 1),
                     Prime_P          => CryptoLib.PKCS8.RSA_Prime_P (Item.Key),
                     Prime_Q          => CryptoLib.PKCS8.RSA_Prime_Q (Item.Key),
                     Exponent_P       => CryptoLib.PKCS8.RSA_Exponent_P (Item.Key),
                     Exponent_Q       => CryptoLib.PKCS8.RSA_Exponent_Q (Item.Key),
                     Coefficient      => CryptoLib.PKCS8.RSA_Coefficient (Item.Key));
               else
                  --  RFC 8446 section 4.2.3 fixes the salt length at the digest
                  --  length for every TLS RSA-PSS scheme.
                  Status := CryptoLib.RSA.Sign_PSS
                    (Modulus          => Modulus,
                     Public_Exponent  => Exponent,
                     Private_Exponent => Private_Exponent,
                     Hash             => Hash,
                     Salt_Length      =>
                       (case Schemes.Hash_Of (Scheme) is
                           when Schemes.SHA_256 => 32,
                           when Schemes.SHA_384 => 48,
                           when others          => 64),
                     Message          => Signed_Data,
                     Rng              => Source,
                     Signature        => Signature (Signature'First
                                                    .. Signature'First + Width - 1),
                     Prime_P          => CryptoLib.PKCS8.RSA_Prime_P (Item.Key),
                     Prime_Q          => CryptoLib.PKCS8.RSA_Prime_Q (Item.Key),
                     Exponent_P       => CryptoLib.PKCS8.RSA_Exponent_P (Item.Key),
                     Exponent_Q       => CryptoLib.PKCS8.RSA_Exponent_Q (Item.Key),
                     Coefficient      => CryptoLib.PKCS8.RSA_Coefficient (Item.Key));
               end if;

               if Status /= CryptoLib.Errors.Ok then
                  Signature := [others => 0];
                  Length := 0;
                  Error := SSL.Errors.Make
                    (Code     => SSL.Errors.Code_Signature_Generation_Failed,
                     Origin   => SSL.Errors.Local_Implementation,
                     Provider => "cryptolib:" & Status'Image);
                  return;
               end if;
            end;

         when Schemes.ECDSA_Key =>
            --  A TLS ECDSA signature is a DER `SEQUENCE { r INTEGER,
            --  s INTEGER }`. CryptoLib's signers hand back r and s as
            --  fixed-width blocks, because that is what SSH puts on the wire,
            --  and `Encode_DER_Signature` turns the pair into the encoding
            --  X.509 and TLS want. Both halves are CryptoLib's: this library
            --  encodes no ASN.1 of its own, which is the same boundary that
            --  removed the RSASSA-PSS parameter blobs once CryptoLib grew an
            --  entry point taking them as arguments.
            --
            --  The curve fixes the digest, and RFC 8446 section 4.2.3 fixes
            --  the same pairing: `ecdsa_secp256r1_sha256` and nothing else on
            --  P-256, `..._sha384` on P-384, `..._sha512` on P-521. So the
            --  scheme selects the signer and the signer's internal hash is
            --  already the one the scheme names -- there is no combination to
            --  get wrong here, and the capability check above has refused any
            --  scheme this key cannot produce before reaching this point.
            declare
               Scalar : constant Byte_Array := CryptoLib.PKCS8.Private_Value (Item.Key);

               --  Widths are the curve's, not the scheme's guess at it.
               Width : constant Byte_Index :=
                 (case Item.Kind is
                     when ECDSA_P256 => 32,
                     when ECDSA_P384 => 48,
                     when others     => 66);

               R : Byte_Array (1 .. Width) := [others => 0];
               S : Byte_Array (1 .. Width) := [others => 0];

               Encoded : Byte_Array (1 .. CryptoLib.ECDSA.Maximum_DER_Signature_Length) :=
                 [others => 0];
               Last    : Ada.Streams.Stream_Element_Offset;
               Status  : CryptoLib.Errors.Status;
            begin
               case Item.Kind is
                  when ECDSA_P256 =>
                     Status := CryptoLib.ECDSA.Sign_Nistp256_Raw
                       (Private_Scalar_Mpint => Scalar,
                        Message_Bytes        => Signed_Data,
                        R_Bytes              => R,
                        S_Bytes              => S);

                  when ECDSA_P384 =>
                     Status := CryptoLib.ECDSA.Sign_Nistp384_Raw
                       (Private_Scalar_Mpint => Scalar,
                        Message_Bytes        => Signed_Data,
                        R_Bytes              => R,
                        S_Bytes              => S);

                  when ECDSA_P521 =>
                     Status := CryptoLib.ECDSA.Sign_Nistp521_Raw
                       (Private_Scalar_Mpint => Scalar,
                        Message_Bytes        => Signed_Data,
                        R_Bytes              => R,
                        S_Bytes              => S);

                  when others =>
                     --  Unreachable: the capability check refused any scheme
                     --  this key cannot produce, and only these three key
                     --  kinds claim an ECDSA scheme.
                     Status := CryptoLib.Errors.Handshake_Failed;
               end case;

               if Status /= CryptoLib.Errors.Ok then
                  --  r and s go before anything else. They are not the private
                  --  scalar, but they are derived from it under a nonce, and a
                  --  half-formed pair left in a buffer is a pair somebody could
                  --  read.
                  SSL.Crypto.Scrub (R);
                  SSL.Crypto.Scrub (S);
                  Signature := [others => 0];
                  Length := 0;
                  Error := SSL.Errors.Make
                    (Code     => SSL.Errors.Code_Signature_Generation_Failed,
                     Origin   => SSL.Errors.Local_Implementation,
                     Provider => "cryptolib:" & Status'Image);
                  return;
               end if;

               Status := CryptoLib.ECDSA.Encode_DER_Signature
                 (R => R, S => S, Into => Encoded, Last => Last);
               SSL.Crypto.Scrub (R);
               SSL.Crypto.Scrub (S);

               if Status /= CryptoLib.Errors.Ok then
                  SSL.Crypto.Scrub (Encoded);
                  Signature := [others => 0];
                  Length := 0;
                  Error := SSL.Errors.Make
                    (Code     => SSL.Errors.Code_Signature_Generation_Failed,
                     Origin   => SSL.Errors.Local_Implementation,
                     Provider => "cryptolib:" & Status'Image);
                  return;
               end if;

               Length := Byte_Index (Last - Encoded'First + 1);

               if Length > Signature'Length then
                  SSL.Crypto.Scrub (Encoded);
                  Length := 0;
                  Error := SSL.Errors.Make
                    (Code     => SSL.Errors.Code_Signature_Generation_Failed,
                     Origin   => SSL.Errors.Local_Policy,
                     Provider => "the signature does not fit the caller's buffer");
                  return;
               end if;

               Signature (Signature'First .. Signature'First + Length - 1) :=
                 Encoded (Encoded'First .. Last);
               SSL.Crypto.Scrub (Encoded);
            end;

      end case;

      Error := SSL.Errors.No_Error;
   end Sign;

end SSL.Credentials;
