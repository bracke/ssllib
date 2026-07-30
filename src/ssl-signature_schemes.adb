package body SSL.Signature_Schemes is

   use type SSL.Cipher_Suites.Authentication_Kind;
   use type SSL.Versions.Protocol_Version;

   --------------
   -- Value_Of --
   --------------

   function Value_Of (Item : Signature_Scheme) return Scheme_Value is
   begin
      case Item is
         when Ed25519                => return Ed25519_Value;
         when Ed448                  => return Ed448_Value;
         when ECDSA_Secp256r1_SHA256 => return ECDSA_Secp256r1_SHA256_Value;
         when ECDSA_Secp384r1_SHA384 => return ECDSA_Secp384r1_SHA384_Value;
         when ECDSA_Secp521r1_SHA512 => return ECDSA_Secp521r1_SHA512_Value;
         when RSA_PSS_RSAE_SHA256    => return RSA_PSS_RSAE_SHA256_Value;
         when RSA_PSS_RSAE_SHA384    => return RSA_PSS_RSAE_SHA384_Value;
         when RSA_PSS_RSAE_SHA512    => return RSA_PSS_RSAE_SHA512_Value;
         when RSA_PSS_PSS_SHA256     => return RSA_PSS_PSS_SHA256_Value;
         when RSA_PSS_PSS_SHA384     => return RSA_PSS_PSS_SHA384_Value;
         when RSA_PSS_PSS_SHA512     => return RSA_PSS_PSS_SHA512_Value;
         when RSA_PKCS1_SHA256       => return RSA_PKCS1_SHA256_Value;
         when RSA_PKCS1_SHA384       => return RSA_PKCS1_SHA384_Value;
         when RSA_PKCS1_SHA512       => return RSA_PKCS1_SHA512_Value;
      end case;
   end Value_Of;

   ----------------
   -- Scheme_For --
   ----------------

   function Scheme_For (Item : Scheme_Value; Value : out Signature_Scheme) return Boolean is
   begin
      Value := Ed25519;
      case Item is
         when Ed25519_Value                => Value := Ed25519;
         when Ed448_Value                  => Value := Ed448;
         when ECDSA_Secp256r1_SHA256_Value => Value := ECDSA_Secp256r1_SHA256;
         when ECDSA_Secp384r1_SHA384_Value => Value := ECDSA_Secp384r1_SHA384;
         when ECDSA_Secp521r1_SHA512_Value => Value := ECDSA_Secp521r1_SHA512;
         when RSA_PSS_RSAE_SHA256_Value    => Value := RSA_PSS_RSAE_SHA256;
         when RSA_PSS_RSAE_SHA384_Value    => Value := RSA_PSS_RSAE_SHA384;
         when RSA_PSS_RSAE_SHA512_Value    => Value := RSA_PSS_RSAE_SHA512;
         when RSA_PSS_PSS_SHA256_Value     => Value := RSA_PSS_PSS_SHA256;
         when RSA_PSS_PSS_SHA384_Value     => Value := RSA_PSS_PSS_SHA384;
         when RSA_PSS_PSS_SHA512_Value     => Value := RSA_PSS_PSS_SHA512;
         when RSA_PKCS1_SHA256_Value       => Value := RSA_PKCS1_SHA256;
         when RSA_PKCS1_SHA384_Value       => Value := RSA_PKCS1_SHA384;
         when RSA_PKCS1_SHA512_Value       => Value := RSA_PKCS1_SHA512;
         when others                       => return False;
      end case;
      return True;
   end Scheme_For;

   ----------------------
   -- Is_Refused_Weak --
   ----------------------

   function Is_Refused_Weak (Item : Scheme_Value) return Boolean is
   begin
      return Item in RSA_PKCS1_SHA1_Value
                   | ECDSA_SHA1_Value
                   | DSA_SHA1_Value
                   | DSA_SHA256_Value
                   | DSA_SHA384_Value
                   | DSA_SHA512_Value
                   | RSA_PKCS1_MD5_Value;
   end Is_Refused_Weak;

   -----------------
   -- Key_Kind_Of --
   -----------------

   function Key_Kind_Of (Item : Signature_Scheme) return Key_Kind is
   begin
      case Item is
         when Ed25519 | Ed448 =>
            return EdDSA_Key;
         when ECDSA_Secp256r1_SHA256 | ECDSA_Secp384r1_SHA384 | ECDSA_Secp521r1_SHA512 =>
            return ECDSA_Key;
         when others =>
            return RSA_Key;
      end case;
   end Key_Kind_Of;

   ----------------
   -- Padding_Of --
   ----------------

   function Padding_Of (Item : Signature_Scheme) return RSA_Padding is
   begin
      case Item is
         when RSA_PKCS1_SHA256 | RSA_PKCS1_SHA384 | RSA_PKCS1_SHA512 =>
            return PKCS1_V1_5;
         when RSA_PSS_RSAE_SHA256 | RSA_PSS_RSAE_SHA384 | RSA_PSS_RSAE_SHA512 =>
            return PSS_With_RSAE_Key;
         when RSA_PSS_PSS_SHA256 | RSA_PSS_PSS_SHA384 | RSA_PSS_PSS_SHA512 =>
            return PSS_With_PSS_Key;
         when others =>
            return Not_RSA;
      end case;
   end Padding_Of;

   -------------
   -- Hash_Of --
   -------------

   function Hash_Of (Item : Signature_Scheme) return Signature_Hash is
   begin
      case Item is
         when Ed25519 | Ed448 =>
            return Hash_In_Algorithm;
         when ECDSA_Secp256r1_SHA256 | RSA_PSS_RSAE_SHA256 | RSA_PSS_PSS_SHA256
            | RSA_PKCS1_SHA256 =>
            return SHA_256;
         when ECDSA_Secp384r1_SHA384 | RSA_PSS_RSAE_SHA384 | RSA_PSS_PSS_SHA384
            | RSA_PKCS1_SHA384 =>
            return SHA_384;
         when ECDSA_Secp521r1_SHA512 | RSA_PSS_RSAE_SHA512 | RSA_PSS_PSS_SHA512
            | RSA_PKCS1_SHA512 =>
            return SHA_512;
      end case;
   end Hash_Of;

   ---------------------
   -- Required_Curve --
   ---------------------

   function Required_Curve
     (Item : Signature_Scheme; Value : out SSL.Supported_Groups.Named_Group) return Boolean
   is
   begin
      Value := SSL.Supported_Groups.Secp256r1;
      case Item is
         when ECDSA_Secp256r1_SHA256 =>
            Value := SSL.Supported_Groups.Secp256r1;
         when ECDSA_Secp384r1_SHA384 =>
            Value := SSL.Supported_Groups.Secp384r1;
         when ECDSA_Secp521r1_SHA512 =>
            Value := SSL.Supported_Groups.Secp521r1;
         when others =>
            return False;
      end case;
      return True;
   end Required_Curve;

   ---------------------------
   -- Usable_For_Handshake --
   ---------------------------

   function Usable_For_Handshake
     (Item : Signature_Scheme; Value : SSL.Versions.Protocol_Version) return Boolean
   is
   begin
      if Padding_Of (Item) = PKCS1_V1_5 then
         --  RFC 8446 section 4.2.3: the PKCS#1 v1.5 code points "refer solely
         --  to signatures which appear in certificates" and MUST NOT be used in
         --  a CertificateVerify.
         return Value = SSL.Versions.TLS_1_2;
      end if;
      return True;
   end Usable_For_Handshake;

   -----------------------------
   -- Usable_For_Certificate --
   -----------------------------

   function Usable_For_Certificate (Item : Signature_Scheme) return Boolean is
      pragma Unreferenced (Item);
   begin
      return True;
   end Usable_For_Certificate;

   -----------------------------
   -- Matches_Authentication --
   -----------------------------

   function Matches_Authentication
     (Item : Signature_Scheme;
      Kind : SSL.Cipher_Suites.Authentication_Kind) return Boolean
   is
   begin
      case Kind is
         when SSL.Cipher_Suites.Signature_In_Extension =>
            --  TLS 1.3: the suite says nothing about authentication, so every
            --  handshake-usable scheme matches.
            return True;
         when SSL.Cipher_Suites.ECDSA_Or_EdDSA =>
            return Key_Kind_Of (Item) in ECDSA_Key | EdDSA_Key;
         when SSL.Cipher_Suites.RSA_Signature =>
            return Key_Kind_Of (Item) = RSA_Key;
      end case;
   end Matches_Authentication;

   -----------
   -- Image --
   -----------

   function Image (Item : Signature_Scheme) return String is
   begin
      case Item is
         when Ed25519                => return "ed25519";
         when Ed448                  => return "ed448";
         when ECDSA_Secp256r1_SHA256 => return "ecdsa_secp256r1_sha256";
         when ECDSA_Secp384r1_SHA384 => return "ecdsa_secp384r1_sha384";
         when ECDSA_Secp521r1_SHA512 => return "ecdsa_secp521r1_sha512";
         when RSA_PSS_RSAE_SHA256    => return "rsa_pss_rsae_sha256";
         when RSA_PSS_RSAE_SHA384    => return "rsa_pss_rsae_sha384";
         when RSA_PSS_RSAE_SHA512    => return "rsa_pss_rsae_sha512";
         when RSA_PSS_PSS_SHA256     => return "rsa_pss_pss_sha256";
         when RSA_PSS_PSS_SHA384     => return "rsa_pss_pss_sha384";
         when RSA_PSS_PSS_SHA512     => return "rsa_pss_pss_sha512";
         when RSA_PKCS1_SHA256       => return "rsa_pkcs1_sha256";
         when RSA_PKCS1_SHA384       => return "rsa_pkcs1_sha384";
         when RSA_PKCS1_SHA512       => return "rsa_pkcs1_sha512";
      end case;
   end Image;

   function Image (Item : Scheme_Value) return String is
      Scheme : Signature_Scheme;
   begin
      if Scheme_For (Item, Scheme) then
         return Image (Scheme);
      end if;

      case Item is
         when RSA_PKCS1_SHA1_Value => return "rsa_pkcs1_sha1";
         when ECDSA_SHA1_Value     => return "ecdsa_sha1";
         when DSA_SHA1_Value       => return "dsa_sha1";
         when DSA_SHA256_Value     => return "dsa_sha256";
         when DSA_SHA384_Value     => return "dsa_sha384";
         when DSA_SHA512_Value     => return "dsa_sha512";
         when RSA_PKCS1_MD5_Value  => return "rsa_pkcs1_md5";
         when others =>
            declare
               Hex  : constant String := "0123456789abcdef";
               High : constant Natural := Natural (Item / 256);
               Low  : constant Natural := Natural (Item mod 256);
            begin
               return "scheme_0x"
                 & Hex (1 + High / 16) & Hex (1 + High mod 16)
                 & Hex (1 + Low / 16) & Hex (1 + Low mod 16);
            end;
      end case;
   end Image;

   ---------------------------------------------------------------------------
   --  Lists
   ---------------------------------------------------------------------------

   -----------------
   -- No_Schemes --
   -----------------

   function No_Schemes return Scheme_List is
   begin
      return (Count => 0, Items => [others => Ed25519]);
   end No_Schemes;

   ------------
   -- Append --
   ------------

   procedure Append (Item : in out Scheme_List; Value : Signature_Scheme; Ok : out Boolean) is
   begin
      if Contains (Item, Value) or else Item.Count = Maximum_Schemes then
         Ok := False;
         return;
      end if;
      Item.Count := Item.Count + 1;
      Item.Items (Item.Count) := Value;
      Ok := True;
   end Append;

   ------------
   -- Length --
   ------------

   function Length (Item : Scheme_List) return Scheme_Count is
   begin
      return Item.Count;
   end Length;

   --------------
   -- Is_Empty --
   --------------

   function Is_Empty (Item : Scheme_List) return Boolean is
   begin
      return Item.Count = 0;
   end Is_Empty;

   -------------
   -- Element --
   -------------

   function Element (Item : Scheme_List; Index : Scheme_Position) return Signature_Scheme is
   begin
      return Item.Items (Index);
   end Element;

   --------------
   -- Contains --
   --------------

   function Contains (Item : Scheme_List; Value : Signature_Scheme) return Boolean is
   begin
      for Index in 1 .. Item.Count loop
         if Item.Items (Index) = Value then
            return True;
         end if;
      end loop;
      return False;
   end Contains;

   --------------
   -- Position --
   --------------

   function Position (Item : Scheme_List; Value : Signature_Scheme) return Scheme_Count is
   begin
      for Index in 1 .. Item.Count loop
         if Item.Items (Index) = Value then
            return Index;
         end if;
      end loop;
      return 0;
   end Position;

   --------------------
   -- Restricted_To --
   --------------------

   function Restricted_To
     (Item : Scheme_List; Value : SSL.Versions.Protocol_Version) return Scheme_List
   is
      Result : Scheme_List := No_Schemes;
      Done   : Boolean;
   begin
      for Index in 1 .. Item.Count loop
         if Usable_For_Handshake (Item.Items (Index), Value) then
            Append (Result, Item.Items (Index), Done);
         end if;
      end loop;
      return Result;
   end Restricted_To;

   --------------
   -- Supports --
   --------------

   function Supports (Item : Scheme_List; Value : SSL.Versions.Protocol_Version) return Boolean is
   begin
      for Index in 1 .. Item.Count loop
         if Usable_For_Handshake (Item.Items (Index), Value) then
            return True;
         end if;
      end loop;
      return False;
   end Supports;

   ----------------------
   -- Default_Schemes --
   ----------------------

   function Default_Schemes return Scheme_List is
      Result : Scheme_List := No_Schemes;
      Done   : Boolean;
   begin
      Append (Result, Ed25519, Done);
      Append (Result, ECDSA_Secp256r1_SHA256, Done);
      Append (Result, ECDSA_Secp384r1_SHA384, Done);
      Append (Result, RSA_PSS_RSAE_SHA256, Done);
      Append (Result, RSA_PSS_RSAE_SHA384, Done);
      Append (Result, RSA_PSS_RSAE_SHA512, Done);
      Append (Result, RSA_PSS_PSS_SHA256, Done);
      Append (Result, RSA_PSS_PSS_SHA384, Done);
      Append (Result, RSA_PSS_PSS_SHA512, Done);
      Append (Result, ECDSA_Secp521r1_SHA512, Done);
      Append (Result, Ed448, Done);

      --  TLS 1.2 only, and last: a peer with nothing but a PKCS#1 v1.5 RSA
      --  capability still interoperates, and no better-equipped peer ever
      --  chooses these.
      Append (Result, RSA_PKCS1_SHA256, Done);
      Append (Result, RSA_PKCS1_SHA384, Done);
      Append (Result, RSA_PKCS1_SHA512, Done);
      return Result;
   end Default_Schemes;

   ---------------------------------
   -- Default_Certificate_Schemes --
   ---------------------------------

   function Default_Certificate_Schemes return Scheme_List is
   begin
      return Default_Schemes;
   end Default_Certificate_Schemes;

   -----------
   -- Image --
   -----------

   function Image (Item : Scheme_List) return String is
   begin
      if Item.Count = 0 then
         return "none";
      end if;

      declare
         Text   : String (1 .. 512) := [others => ' '];
         Length : Natural := 0;

         procedure Append_Text (Value : String);

         procedure Append_Text (Value : String) is
            Room : constant Natural := Natural'Min (Value'Length, Text'Length - Length);
         begin
            if Room > 0 then
               Text (Length + 1 .. Length + Room) :=
                 Value (Value'First .. Value'First + Room - 1);
               Length := Length + Room;
            end if;
         end Append_Text;

      begin
         for Index in 1 .. Item.Count loop
            if Index > 1 then
               Append_Text (",");
            end if;
            Append_Text (Image (Item.Items (Index)));
         end loop;
         return Text (1 .. Length);
      end;
   end Image;

end SSL.Signature_Schemes;
