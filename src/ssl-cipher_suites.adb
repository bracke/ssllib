package body SSL.Cipher_Suites is

   use type SSL.Versions.Protocol_Version;

   ----------------
   -- Key_Length --
   ----------------

   function Key_Length (Item : AEAD_Algorithm) return Byte_Index is
   begin
      case Item is
         when AES_128_GCM       => return 16;
         when AES_256_GCM       => return 32;
         when ChaCha20_Poly1305 => return 32;
      end case;
   end Key_Length;

   ---------------
   -- IV_Length --
   ---------------

   function IV_Length (Item : AEAD_Algorithm) return Byte_Index is
      pragma Unreferenced (Item);
   begin
      --  All three AEADs here take a 96-bit nonce, and TLS 1.3 fixes the
      --  static IV at that width (RFC 8446 section 5.3). The uniformity is why
      --  the record layer needs no per-suite nonce code.
      return 12;
   end IV_Length;

   ----------------
   -- Tag_Length --
   ----------------

   function Tag_Length (Item : AEAD_Algorithm) return Byte_Index is
      pragma Unreferenced (Item);
   begin
      return 16;
   end Tag_Length;

   --------------------
   -- Digest_Length --
   --------------------

   function Digest_Length (Item : Hash_Algorithm) return Byte_Index is
   begin
      case Item is
         when SHA_256 => return 32;
         when SHA_384 => return 48;
      end case;
   end Digest_Length;

   -----------
   -- Image --
   -----------

   function Image (Item : AEAD_Algorithm) return String is
   begin
      case Item is
         when AES_128_GCM       => return "aes-128-gcm";
         when AES_256_GCM       => return "aes-256-gcm";
         when ChaCha20_Poly1305 => return "chacha20-poly1305";
      end case;
   end Image;

   function Image (Item : Hash_Algorithm) return String is
   begin
      case Item is
         when SHA_256 => return "sha256";
         when SHA_384 => return "sha384";
      end case;
   end Image;

   --------------
   -- Value_Of --
   --------------

   function Value_Of (Item : Cipher_Suite) return Suite_Value is
   begin
      case Item is
         when TLS_AES_128_GCM_SHA256 =>
            return TLS_AES_128_GCM_SHA256_Value;
         when TLS_AES_256_GCM_SHA384 =>
            return TLS_AES_256_GCM_SHA384_Value;
         when TLS_CHACHA20_POLY1305_SHA256 =>
            return TLS_CHACHA20_POLY1305_SHA256_Value;
         when TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 =>
            return TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_Value;
         when TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 =>
            return TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_Value;
         when TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 =>
            return TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256_Value;
         when TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 =>
            return TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384_Value;
         when TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 =>
            return TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_Value;
         when TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 =>
            return TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_Value;
      end case;
   end Value_Of;

   ---------------
   -- Suite_For --
   ---------------

   function Suite_For (Item : Suite_Value; Value : out Cipher_Suite) return Boolean is
   begin
      Value := TLS_AES_128_GCM_SHA256;
      case Item is
         when TLS_AES_128_GCM_SHA256_Value =>
            Value := TLS_AES_128_GCM_SHA256;
         when TLS_AES_256_GCM_SHA384_Value =>
            Value := TLS_AES_256_GCM_SHA384;
         when TLS_CHACHA20_POLY1305_SHA256_Value =>
            Value := TLS_CHACHA20_POLY1305_SHA256;
         when TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_Value =>
            Value := TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
         when TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_Value =>
            Value := TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
         when TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256_Value =>
            Value := TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
         when TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384_Value =>
            Value := TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
         when TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_Value =>
            Value := TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
         when TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_Value =>
            Value := TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
         when others =>
            return False;
      end case;
      return True;
   end Suite_For;

   -------------------
   -- Is_Signalling --
   -------------------

   function Is_Signalling (Item : Suite_Value) return Boolean is
   begin
      return Item in Renegotiation_Info_SCSV | Fallback_SCSV;
   end Is_Signalling;

   ----------------
   -- Version_Of --
   ----------------

   function Version_Of (Item : Cipher_Suite) return SSL.Versions.Protocol_Version is
   begin
      case Item is
         when TLS_AES_128_GCM_SHA256
            | TLS_AES_256_GCM_SHA384
            | TLS_CHACHA20_POLY1305_SHA256 =>
            return SSL.Versions.TLS_1_3;
         when others =>
            return SSL.Versions.TLS_1_2;
      end case;
   end Version_Of;

   -------------
   -- AEAD_Of --
   -------------

   function AEAD_Of (Item : Cipher_Suite) return AEAD_Algorithm is
   begin
      case Item is
         when TLS_AES_128_GCM_SHA256
            | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 =>
            return AES_128_GCM;
         when TLS_AES_256_GCM_SHA384
            | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 =>
            return AES_256_GCM;
         when TLS_CHACHA20_POLY1305_SHA256
            | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            | TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 =>
            return ChaCha20_Poly1305;
      end case;
   end AEAD_Of;

   -------------
   -- Hash_Of --
   -------------

   function Hash_Of (Item : Cipher_Suite) return Hash_Algorithm is
   begin
      case Item is
         when TLS_AES_256_GCM_SHA384
            | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 =>
            return SHA_384;
         when others =>
            return SHA_256;
      end case;
   end Hash_Of;

   ---------------------
   -- Key_Exchange_Of --
   ---------------------

   function Key_Exchange_Of (Item : Cipher_Suite) return Key_Exchange_Kind is
   begin
      case Version_Of (Item) is
         when SSL.Versions.TLS_1_3 => return TLS13_Key_Schedule;
         when SSL.Versions.TLS_1_2 => return ECDHE;
      end case;
   end Key_Exchange_Of;

   -----------------------
   -- Authentication_Of --
   -----------------------

   function Authentication_Of (Item : Cipher_Suite) return Authentication_Kind is
   begin
      case Item is
         when TLS_AES_128_GCM_SHA256
            | TLS_AES_256_GCM_SHA384
            | TLS_CHACHA20_POLY1305_SHA256 =>
            --  TLS 1.3 decouples authentication from the suite entirely; what
            --  signs is decided by signature_algorithms and the credential.
            return Signature_In_Extension;
         when TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 =>
            return ECDSA_Or_EdDSA;
         when TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            | TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 =>
            return RSA_Signature;
      end case;
   end Authentication_Of;

   -----------
   -- Image --
   -----------

   function Image (Item : Cipher_Suite) return String is
   begin
      case Item is
         when TLS_AES_128_GCM_SHA256 =>
            return "tls_aes_128_gcm_sha256";
         when TLS_AES_256_GCM_SHA384 =>
            return "tls_aes_256_gcm_sha384";
         when TLS_CHACHA20_POLY1305_SHA256 =>
            return "tls_chacha20_poly1305_sha256";
         when TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 =>
            return "tls_ecdhe_ecdsa_with_aes_128_gcm_sha256";
         when TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 =>
            return "tls_ecdhe_ecdsa_with_aes_256_gcm_sha384";
         when TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 =>
            return "tls_ecdhe_rsa_with_aes_128_gcm_sha256";
         when TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 =>
            return "tls_ecdhe_rsa_with_aes_256_gcm_sha384";
         when TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 =>
            return "tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256";
         when TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 =>
            return "tls_ecdhe_rsa_with_chacha20_poly1305_sha256";
      end case;
   end Image;

   function Image (Item : Suite_Value) return String is
      Suite : Cipher_Suite;
      Hex   : constant String := "0123456789abcdef";
      High  : constant Natural := Natural (Item / 256);
      Low   : constant Natural := Natural (Item mod 256);
   begin
      if Suite_For (Item, Suite) then
         return Image (Suite);
      end if;

      if Item = Renegotiation_Info_SCSV then
         return "tls_empty_renegotiation_info_scsv";
      end if;

      if Item = Fallback_SCSV then
         return "tls_fallback_scsv";
      end if;

      return "suite_0x"
        & Hex (1 + High / 16) & Hex (1 + High mod 16)
        & Hex (1 + Low / 16) & Hex (1 + Low mod 16);
   end Image;

   ---------------------------------------------------------------------------
   --  Lists
   ---------------------------------------------------------------------------

   ----------------
   -- No_Suites --
   ----------------

   function No_Suites return Suite_List is
   begin
      return (Count => 0, Items => [others => TLS_AES_128_GCM_SHA256]);
   end No_Suites;

   ------------
   -- Append --
   ------------

   procedure Append (Item : in out Suite_List; Value : Cipher_Suite; Ok : out Boolean) is
   begin
      if Contains (Item, Value) or else Item.Count = Maximum_Suites then
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

   function Length (Item : Suite_List) return Suite_Count is
   begin
      return Item.Count;
   end Length;

   --------------
   -- Is_Empty --
   --------------

   function Is_Empty (Item : Suite_List) return Boolean is
   begin
      return Item.Count = 0;
   end Is_Empty;

   -------------
   -- Element --
   -------------

   function Element (Item : Suite_List; Index : Suite_Position) return Cipher_Suite is
   begin
      return Item.Items (Index);
   end Element;

   --------------
   -- Contains --
   --------------

   function Contains (Item : Suite_List; Value : Cipher_Suite) return Boolean is
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

   function Position (Item : Suite_List; Value : Cipher_Suite) return Suite_Count is
   begin
      for Index in 1 .. Item.Count loop
         if Item.Items (Index) = Value then
            return Index;
         end if;
      end loop;
      return 0;
   end Position;

   ---------------------
   -- Restricted_To --
   ---------------------

   function Restricted_To
     (Item : Suite_List; Value : SSL.Versions.Protocol_Version) return Suite_List
   is
      Result : Suite_List := No_Suites;
      Done   : Boolean;
   begin
      for Index in 1 .. Item.Count loop
         if Version_Of (Item.Items (Index)) = Value then
            Append (Result, Item.Items (Index), Done);
         end if;
      end loop;
      return Result;
   end Restricted_To;

   --------------
   -- Supports --
   --------------

   function Supports (Item : Suite_List; Value : SSL.Versions.Protocol_Version) return Boolean is
   begin
      for Index in 1 .. Item.Count loop
         if Version_Of (Item.Items (Index)) = Value then
            return True;
         end if;
      end loop;
      return False;
   end Supports;

   -----------------------------
   -- Default_TLS_1_3_Suites --
   -----------------------------

   function Default_TLS_1_3_Suites return Suite_List is
      Result : Suite_List := No_Suites;
      Done   : Boolean;
   begin
      Append (Result, TLS_AES_128_GCM_SHA256, Done);
      Append (Result, TLS_CHACHA20_POLY1305_SHA256, Done);
      Append (Result, TLS_AES_256_GCM_SHA384, Done);
      return Result;
   end Default_TLS_1_3_Suites;

   -----------------------------
   -- Default_TLS_1_2_Suites --
   -----------------------------

   function Default_TLS_1_2_Suites return Suite_List is
      Result : Suite_List := No_Suites;
      Done   : Boolean;
   begin
      Append (Result, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, Done);
      Append (Result, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, Done);
      Append (Result, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, Done);
      Append (Result, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, Done);
      Append (Result, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, Done);
      Append (Result, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, Done);
      return Result;
   end Default_TLS_1_2_Suites;

   -----------
   -- Image --
   -----------

   function Image (Item : Suite_List) return String is
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

end SSL.Cipher_Suites;
