with CryptoLib.ChaCha20_Poly1305;
with CryptoLib.Ciphers;
with CryptoLib.Constant_Time;
with CryptoLib.EC_Curves;
with CryptoLib.ECDH;
with CryptoLib.Ed25519;
with CryptoLib.Ed448;
with CryptoLib.Errors;
with CryptoLib.FFDHE;
with CryptoLib.HKDF;
with CryptoLib.Macs;
with CryptoLib.Secure_Wipe;
with CryptoLib.TLS13_KDF;
with CryptoLib.X509;
with CryptoLib.RSA;
with CryptoLib.X509.Signatures;

package body SSL.Crypto is

   use SSL.Cipher_Suites;
   use type CryptoLib.Errors.Status;
   use type SSL.Signature_Schemes.Signature_Scheme;
   use type SSL.Supported_Groups.Group_Family;
   use type SSL.Supported_Groups.Named_Group;

   ---------------------------------------------------------------------------
   --  Mapping helpers
   ---------------------------------------------------------------------------

   function HKDF_Hash (Algorithm : Hash_Algorithm) return CryptoLib.HKDF.Hash_Algorithm
   is (case Algorithm is
          when SSL.Cipher_Suites.SHA_256 => CryptoLib.HKDF.SHA256,
          when SSL.Cipher_Suites.SHA_384 => CryptoLib.HKDF.SHA384);

   --  The CryptoLib AES-GCM entry points select the key size from an algorithm
   --  name string. The names are SSH spellings because that is where the code
   --  came from; the AEAD they select is plain AES-GCM, which is what TLS uses.
   function GCM_Name (Algorithm : AEAD_Algorithm) return String
   is (case Algorithm is
          when AES_128_GCM       => "aes128-gcm@openssh.com",
          when AES_256_GCM       => "aes256-gcm@openssh.com",
          when ChaCha20_Poly1305 => "");

   function ECDH_Curve
     (Group : SSL.Supported_Groups.Named_Group) return CryptoLib.ECDH.Curve_Id
   is (case Group is
          when SSL.Supported_Groups.Secp384r1 => CryptoLib.EC_Curves.Nistp384,
          when SSL.Supported_Groups.Secp521r1 => CryptoLib.EC_Curves.Nistp521,
          when others                         => CryptoLib.EC_Curves.Nistp256);

   --  The RFC 7919 groups. Deliberately not CryptoLib.Diffie_Hellman, whose
   --  primes are the SSH MODP ones: the names collide in conversation and the
   --  primes do not, so a value from one is meaningless in the other.
   function FFDHE_Group
     (Group : SSL.Supported_Groups.Named_Group) return CryptoLib.FFDHE.Group_Id
   is (case Group is
          when SSL.Supported_Groups.FFDHE3072 => CryptoLib.FFDHE.FFDHE3072,
          when SSL.Supported_Groups.FFDHE4096 => CryptoLib.FFDHE.FFDHE4096,
          when others                         => CryptoLib.FFDHE.FFDHE2048);

   function Is_Finite_Field (Group : SSL.Supported_Groups.Named_Group) return Boolean
   is (SSL.Supported_Groups.Family_Of (Group) = SSL.Supported_Groups.Finite_Field);

   -----------
   -- Scrub --
   -----------

   procedure Scrub (Data : in out Byte_Array) is
   begin
      if Data'Length > 0 then
         CryptoLib.Secure_Wipe.Wipe (Data'Address, Natural (Data'Length));
      end if;
   end Scrub;

   --  Map a CryptoLib status onto a structured failure under a chosen code.
   function Mapped
     (Status : CryptoLib.Errors.Status;
      Code   : SSL.Errors.Error_Code;
      Origin : SSL.Errors.Error_Origin := SSL.Errors.Local_Implementation)
      return SSL.Errors.Error_Information;

   function Mapped
     (Status : CryptoLib.Errors.Status;
      Code   : SSL.Errors.Error_Code;
      Origin : SSL.Errors.Error_Origin := SSL.Errors.Local_Implementation)
      return SSL.Errors.Error_Information
   is
   begin
      if Status = CryptoLib.Errors.Ok then
         return SSL.Errors.No_Error;
      end if;

      --  The CryptoLib status name is carried as provider text, because it is
      --  the only account of what the primitive objected to and it is not
      --  secret. It is not mapped onto a distinct ssllib code: a caller
      --  branching on which primitive failed is a caller about to build an
      --  oracle.
      return SSL.Errors.Make
        (Code     => Code,
         Origin   => Origin,
         Provider => "cryptolib:" & Status'Image);
   end Mapped;

   ---------------------------------------------------------------------------
   --  Randomness
   ---------------------------------------------------------------------------

   ---------------------------
   -- Use_System_Entropy --
   ---------------------------

   procedure Use_System_Entropy (Item : out Random_Source) is
   begin
      Item.Kind := System_Entropy;
      CryptoLib.Random.Initialize_Production (Item.State);
   end Use_System_Entropy;

   -------------------------
   -- Use_Fixed_Pattern --
   -------------------------

   procedure Use_Fixed_Pattern (Item : out Random_Source; Pattern : Byte_Array) is
   begin
      Item.Kind := Fixed_Pattern;
      CryptoLib.Random.Initialize_Deterministic (Item.State, Pattern);
   end Use_Fixed_Pattern;

   --------------------------
   -- Use_Failing_Source --
   --------------------------

   procedure Use_Failing_Source (Item : out Random_Source) is
   begin
      Item.Kind := Failing;
      CryptoLib.Random.Initialize_Failing (Item.State);
   end Use_Failing_Source;

   -------------------------
   -- Is_System_Entropy --
   -------------------------

   function Is_System_Entropy (Item : Random_Source) return Boolean is
   begin
      return Item.Kind = System_Entropy;
   end Is_System_Entropy;

   ----------
   -- Fill --
   ----------

   procedure Fill
     (Item  : in out Random_Source;
      Into  : out Byte_Array;
      Error : out SSL.Errors.Error_Information)
   is
      Status : constant CryptoLib.Errors.Status :=
        CryptoLib.Random.Fill (Item.State, Into);
   begin
      Error := Mapped (Status, SSL.Errors.Code_Random_Source_Failed);
   end Fill;

   ------------------
   -- Fill_Secret --
   ------------------

   procedure Fill_Secret
     (Item   : in out Random_Source;
      Target : in out SSL.Secrets.Secret;
      Length : SSL.Secrets.Secret_Length;
      Error  : out SSL.Errors.Error_Information)
   is
      Buffer : Byte_Array (1 .. Length) := [others => 0];
   begin
      SSL.Secrets.Wipe (Target);
      Fill (Item, Buffer, Error);
      if not SSL.Errors.Is_Error (Error) then
         SSL.Secrets.Set (Target, Buffer);
      end if;
      Scrub (Buffer);
   end Fill_Secret;

   ---------------------------------------------------------------------------
   --  Hashing
   ---------------------------------------------------------------------------

   -----------
   -- Start --
   -----------

   procedure Start (Item : out Hash_Context; Algorithm : Hash_Algorithm) is
   begin
      Item.Algorithm := Algorithm;
      Item.Count := 0;
      CryptoLib.Hashes.Initialize_SHA256 (Item.SHA256);
      CryptoLib.Hashes.Initialize_SHA384 (Item.SHA384);
   end Start;

   ------------
   -- Update --
   ------------

   procedure Update (Item : in out Hash_Context; Data : Byte_Array) is
   begin
      if Data'Length = 0 then
         return;
      end if;

      case Item.Algorithm is
         when SSL.Cipher_Suites.SHA_256 => CryptoLib.Hashes.Update (Item.SHA256, Data);
         when SSL.Cipher_Suites.SHA_384 => CryptoLib.Hashes.Update (Item.SHA384, Data);
      end case;
      Item.Count := Item.Count + Data'Length;
   end Update;

   --------------
   -- Snapshot --
   --------------

   procedure Snapshot (Item : Hash_Context; Into : out Byte_Array) is
   begin
      case Item.Algorithm is
         when SSL.Cipher_Suites.SHA_256 =>
            declare
               Copy : CryptoLib.Hashes.SHA256_Context := Item.SHA256;
            begin
               Into := Byte_Array (CryptoLib.Hashes.Finalize (Copy));
            end;
         when SSL.Cipher_Suites.SHA_384 =>
            declare
               Copy : CryptoLib.Hashes.SHA384_Context := Item.SHA384;
            begin
               Into := Byte_Array (CryptoLib.Hashes.Finalize (Copy));
            end;
      end case;
   end Snapshot;

   function Snapshot (Item : Hash_Context) return Byte_Array is
      Result : Byte_Array (1 .. Digest_Length (Item.Algorithm));
   begin
      Snapshot (Item, Result);
      return Result;
   end Snapshot;

   ------------------
   -- Algorithm_Of --
   ------------------

   function Algorithm_Of (Item : Hash_Context) return Hash_Algorithm is
   begin
      return Item.Algorithm;
   end Algorithm_Of;

   --------------
   -- Absorbed --
   --------------

   function Absorbed (Item : Hash_Context) return Byte_Index is
   begin
      return Item.Count;
   end Absorbed;

   ------------
   -- Digest --
   ------------

   function Digest (Algorithm : Hash_Algorithm; Data : Byte_Array) return Byte_Array is
   begin
      case Algorithm is
         when SSL.Cipher_Suites.SHA_256 => return Byte_Array (CryptoLib.Hashes.SHA256 (Data));
         when SSL.Cipher_Suites.SHA_384 => return Byte_Array (CryptoLib.Hashes.SHA384 (Data));
      end case;
   end Digest;

   function SHA_256 (Data : Byte_Array) return Byte_Array is
   begin
      return Byte_Array (CryptoLib.Hashes.SHA256 (Data));
   end SHA_256;

   function SHA_384 (Data : Byte_Array) return Byte_Array is
   begin
      return Byte_Array (CryptoLib.Hashes.SHA384 (Data));
   end SHA_384;

   function SHA_512 (Data : Byte_Array) return Byte_Array is
   begin
      return Byte_Array (CryptoLib.Hashes.SHA512 (Data));
   end SHA_512;

   ---------------------------------------------------------------------------
   --  MAC
   ---------------------------------------------------------------------------

   ------------------
   -- HMAC_Octets --
   ------------------

   procedure HMAC_Octets
     (Algorithm : Hash_Algorithm;
      Key       : Byte_Array;
      Data      : Byte_Array;
      Into      : out Byte_Array)
   is
   begin
      case Algorithm is
         when SSL.Cipher_Suites.SHA_256 =>
            Into := Byte_Array (CryptoLib.Macs.HMAC_SHA256 (Key, Data));
         when SSL.Cipher_Suites.SHA_384 =>
            Into := Byte_Array (CryptoLib.Macs.HMAC_SHA384 (Key, Data));
      end case;
   end HMAC_Octets;

   ----------
   -- HMAC --
   ----------

   procedure HMAC
     (Algorithm : Hash_Algorithm;
      Key       : SSL.Secrets.Secret;
      Data      : Byte_Array;
      Into      : out Byte_Array)
   is
      Key_Octets : Byte_Array (1 .. SSL.Secrets.Length (Key));
   begin
      SSL.Secrets.Get (Key, Key_Octets);
      HMAC_Octets (Algorithm, Key_Octets, Data, Into);
      Scrub (Key_Octets);
   end HMAC;

   -----------
   -- Equal --
   -----------

   function Equal (Left : Byte_Array; Right : Byte_Array) return Boolean is
   begin
      return CryptoLib.Constant_Time.Equal (Left, Right);
   end Equal;

   ---------------------------------------------------------------------------
   --  Key derivation
   ---------------------------------------------------------------------------

   -------------
   -- Extract --
   -------------

   procedure Extract
     (Algorithm : Hash_Algorithm;
      Salt      : Byte_Array;
      Input     : Byte_Array;
      Target    : in out SSL.Secrets.Secret;
      Error     : out SSL.Errors.Error_Information)
   is
      Width  : constant Byte_Index := Digest_Length (Algorithm);
      Buffer : Byte_Array (1 .. Width) := [others => 0];
      Status : constant CryptoLib.Errors.Status :=
        CryptoLib.HKDF.Extract (HKDF_Hash (Algorithm), Salt, Input, Buffer);
   begin
      SSL.Secrets.Wipe (Target);
      Error := Mapped (Status, SSL.Errors.Code_Key_Derivation_Failed);
      if not SSL.Errors.Is_Error (Error) then
         SSL.Secrets.Set (Target, Buffer);
      end if;
      Scrub (Buffer);
   end Extract;

   ------------------------
   -- Extract_From_Secret --
   ------------------------

   procedure Extract_From_Secret
     (Algorithm : Hash_Algorithm;
      Salt      : Byte_Array;
      Input     : SSL.Secrets.Secret;
      Target    : in out SSL.Secrets.Secret;
      Error     : out SSL.Errors.Error_Information)
   is
      Input_Octets : Byte_Array (1 .. SSL.Secrets.Length (Input));
   begin
      SSL.Secrets.Get (Input, Input_Octets);
      Extract (Algorithm, Salt, Input_Octets, Target, Error);
      Scrub (Input_Octets);
   end Extract_From_Secret;

   -------------------
   -- Expand_Label --
   -------------------

   procedure Expand_Label
     (Algorithm : Hash_Algorithm;
      Secret    : SSL.Secrets.Secret;
      Label     : String;
      Context   : Byte_Array;
      Target    : in out SSL.Secrets.Secret;
      Length    : SSL.Secrets.Secret_Length;
      Error     : out SSL.Errors.Error_Information)
   is
      Buffer : Byte_Array (1 .. Length) := [others => 0];
   begin
      Expand_Label_Into (Algorithm, Secret, Label, Context, Buffer, Error);
      SSL.Secrets.Wipe (Target);
      if not SSL.Errors.Is_Error (Error) then
         SSL.Secrets.Set (Target, Buffer);
      end if;
      Scrub (Buffer);
   end Expand_Label;

   ------------------------
   -- Expand_Label_Into --
   ------------------------

   procedure Expand_Label_Into
     (Algorithm : Hash_Algorithm;
      Secret    : SSL.Secrets.Secret;
      Label     : String;
      Context   : Byte_Array;
      Into      : out Byte_Array;
      Error     : out SSL.Errors.Error_Information)
   is
      Secret_Octets : Byte_Array (1 .. SSL.Secrets.Length (Secret));
      Status        : CryptoLib.Errors.Status;
   begin
      SSL.Secrets.Get (Secret, Secret_Octets);
      Status := CryptoLib.TLS13_KDF.Expand_Label
        (Hash    => HKDF_Hash (Algorithm),
         Secret  => Secret_Octets,
         Label   => Label,
         Context => Context,
         Output  => Into);
      Scrub (Secret_Octets);
      Error := Mapped (Status, SSL.Errors.Code_Key_Derivation_Failed);
   end Expand_Label_Into;

   --------------------
   -- Derive_Secret --
   --------------------

   procedure Derive_Secret
     (Algorithm       : Hash_Algorithm;
      Secret          : SSL.Secrets.Secret;
      Label           : String;
      Transcript_Hash : Byte_Array;
      Target          : in out SSL.Secrets.Secret;
      Error           : out SSL.Errors.Error_Information)
   is
      Width         : constant Byte_Index := Digest_Length (Algorithm);
      Secret_Octets : Byte_Array (1 .. SSL.Secrets.Length (Secret));
      Buffer        : Byte_Array (1 .. Width) := [others => 0];
      Status        : CryptoLib.Errors.Status;
   begin
      SSL.Secrets.Get (Secret, Secret_Octets);
      Status := CryptoLib.TLS13_KDF.Derive_Secret_From_Transcript
        (Hash            => HKDF_Hash (Algorithm),
         Secret          => Secret_Octets,
         Label           => Label,
         Transcript_Hash => Transcript_Hash,
         Output          => Buffer);
      Scrub (Secret_Octets);

      SSL.Secrets.Wipe (Target);
      Error := Mapped (Status, SSL.Errors.Code_Key_Derivation_Failed);
      if not SSL.Errors.Is_Error (Error) then
         SSL.Secrets.Set (Target, Buffer);
      end if;
      Scrub (Buffer);
   end Derive_Secret;

   ---------------------------------------------------------------------------
   --  AEAD
   ---------------------------------------------------------------------------

   ----------
   -- Seal --
   ----------

   procedure Seal
     (Algorithm  : AEAD_Algorithm;
      Key        : SSL.Secrets.Secret;
      Nonce      : Byte_Array;
      Additional : Byte_Array;
      Plaintext  : Byte_Array;
      Wire       : out Byte_Array;
      Error      : out SSL.Errors.Error_Information)
   is
      Key_Octets : Byte_Array (1 .. SSL.Secrets.Length (Key));
      Status     : CryptoLib.Errors.Status;
   begin
      Wire := [others => 0];
      SSL.Secrets.Get (Key, Key_Octets);

      case Algorithm is
         when AES_128_GCM | AES_256_GCM =>
            Status := CryptoLib.Ciphers.Seal_AEAD
              (Algorithm_Name  => GCM_Name (Algorithm),
               Key_Data        => Key_Octets,
               IV_Data         => Nonce,
               Associated_Data => Additional,
               Plain_Packet    => Plaintext,
               Wire_Packet     => Wire);
         when ChaCha20_Poly1305 =>
            Status := CryptoLib.ChaCha20_Poly1305.Seal_AEAD
              (Key_Data        => Key_Octets,
               Nonce           => Nonce,
               Associated_Data => Additional,
               Plaintext       => Plaintext,
               Wire            => Wire);
      end case;

      Scrub (Key_Octets);
      Error := Mapped (Status, SSL.Errors.Code_AEAD_Operation_Failed);
      if SSL.Errors.Is_Error (Error) then
         Wire := [others => 0];
      end if;
   end Seal;

   ----------
   -- Open --
   ----------

   procedure Open
     (Algorithm  : AEAD_Algorithm;
      Key        : SSL.Secrets.Secret;
      Nonce      : Byte_Array;
      Additional : Byte_Array;
      Wire       : Byte_Array;
      Plaintext  : out Byte_Array;
      Error      : out SSL.Errors.Error_Information)
   is
      Key_Octets : Byte_Array (1 .. SSL.Secrets.Length (Key));
      Status     : CryptoLib.Errors.Status;
   begin
      if Plaintext'Length > 0 then
         Plaintext := [others => 0];
      end if;
      SSL.Secrets.Get (Key, Key_Octets);

      case Algorithm is
         when AES_128_GCM | AES_256_GCM =>
            Status := CryptoLib.Ciphers.Open_AEAD
              (Algorithm_Name  => GCM_Name (Algorithm),
               Key_Data        => Key_Octets,
               IV_Data         => Nonce,
               Associated_Data => Additional,
               Wire_Packet     => Wire,
               Plain_Packet    => Plaintext);
         when ChaCha20_Poly1305 =>
            Status := CryptoLib.ChaCha20_Poly1305.Open_AEAD
              (Key_Data        => Key_Octets,
               Nonce           => Nonce,
               Associated_Data => Additional,
               Wire            => Wire,
               Plaintext       => Plaintext);
      end case;

      Scrub (Key_Octets);

      --  A tag that does not verify is Code_Record_Authentication_Failed, which
      --  the central table maps to bad_record_mac. No other outcome is
      --  distinguished, and no alternate key or sequence number is tried: the
      --  record is finished and so is the connection.
      Error := Mapped
        (Status, SSL.Errors.Code_Record_Authentication_Failed, SSL.Errors.Peer_Message);
      if SSL.Errors.Is_Error (Error) and then Plaintext'Length > 0 then
         Plaintext := [others => 0];
      end if;
   end Open;

   ---------------------------------------------------------------------------
   --  Key agreement
   ---------------------------------------------------------------------------

   --------------
   -- Generate --
   --------------

   procedure Generate
     (Item   : in out Key_Exchange_Pair;
      Group  : SSL.Supported_Groups.Named_Group;
      Source : in out Random_Source;
      Error  : out SSL.Errors.Error_Information)
   is
      Width : constant Byte_Index := SSL.Supported_Groups.Share_Length (Group);
   begin
      Wipe (Item);
      Item.Group := Group;
      Error := SSL.Errors.No_Error;

      if Is_Finite_Field (Group) then
         declare
            Exponent : Byte_Array
              (1 .. Byte_Index (CryptoLib.FFDHE.Exponent_Length (FFDHE_Group (Group))))
              := [others => 0];
            Value    : Byte_Array (1 .. Width) := [others => 0];
            Status   : CryptoLib.Errors.Status;
         begin
            Status := CryptoLib.FFDHE.Generate_Keypair
              (Group         => FFDHE_Group (Group),
               Rng           => Source.State,
               Private_Value => Exponent,
               Public_Value  => Value);
            Error := Mapped (Status, SSL.Errors.Code_Key_Agreement_Failed);
            if not SSL.Errors.Is_Error (Error) then
               SSL.Secrets.Set (Item.Scalar, Exponent);
               Item.Share (1 .. Width) := Value;
               Item.Share_Used := Width;
            end if;
            Scrub (Exponent);
         end;

      elsif Group = SSL.Supported_Groups.X25519 then
         declare
            Public : CryptoLib.Curve25519.Public_Key;
            Status : constant CryptoLib.Errors.Status :=
              CryptoLib.Curve25519.Generate_Keypair
                (Source_Item  => Source.State,
                 Private_Item => Item.Montgomery_Private,
                 Public_Item  => Public);
         begin
            Error := Mapped (Status, SSL.Errors.Code_Key_Agreement_Failed);
            if SSL.Errors.Is_Error (Error) then
               return;
            end if;
            Item.Share (1 .. 32) := Byte_Array (Public);
            Item.Share_Used := 32;
         end;
      else
         declare
            Scalar_Octets : Byte_Array (1 .. SSL.Supported_Groups.Secret_Length (Group))
              := [others => 0];
            Point         : Byte_Array (1 .. Width) := [others => 0];
            Status        : CryptoLib.Errors.Status;
         begin
            Status := CryptoLib.ECDH.Generate_Keypair
              (Curve          => ECDH_Curve (Group),
               Rng            => Source.State,
               Private_Scalar => Scalar_Octets,
               Public_Point   => Point);
            Error := Mapped (Status, SSL.Errors.Code_Key_Agreement_Failed);
            if not SSL.Errors.Is_Error (Error) then
               SSL.Secrets.Set (Item.Scalar, Scalar_Octets);
               Item.Share (1 .. Width) := Point;
               Item.Share_Used := Width;
            end if;
            Scrub (Scalar_Octets);
         end;
      end if;

      Item.Generated := not SSL.Errors.Is_Error (Error);
   end Generate;

   -------------------
   -- Is_Generated --
   -------------------

   function Is_Generated (Item : Key_Exchange_Pair) return Boolean is
   begin
      return Item.Generated;
   end Is_Generated;

   --------------
   -- Group_Of --
   --------------

   function Group_Of (Item : Key_Exchange_Pair) return SSL.Supported_Groups.Named_Group is
   begin
      return Item.Group;
   end Group_Of;

   -------------------
   -- Public_Share --
   -------------------

   function Public_Share (Item : Key_Exchange_Pair) return Byte_Array is
   begin
      return Item.Share (1 .. Item.Share_Used);
   end Public_Share;

   -------------
   -- Agree --
   -------------

   procedure Agree
     (Item       : Key_Exchange_Pair;
      Peer_Share : Byte_Array;
      Target     : in out SSL.Secrets.Secret;
      Error      : out SSL.Errors.Error_Information)
   is
      Expected : constant Byte_Index := SSL.Supported_Groups.Share_Length (Item.Group);
      Width    : constant Byte_Index := SSL.Supported_Groups.Secret_Length (Item.Group);
   begin
      SSL.Secrets.Wipe (Target);

      --  The length is checked against the group before the octets reach any
      --  curve arithmetic. A share of the wrong size for the group it was
      --  offered under is rejected on that alone.
      if Peer_Share'Length /= Expected then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Key_Exchange_Value_Invalid,
            Origin     => SSL.Errors.Peer_Message,
            Parameters =>
              [SSL.Errors.Text_Parameter ("group", SSL.Supported_Groups.Image (Item.Group)),
               SSL.Errors.Numeric_Parameter ("expected", Long_Long_Integer (Expected)),
               SSL.Errors.Numeric_Parameter ("received", Long_Long_Integer (Peer_Share'Length))]);
         return;
      end if;

      if Is_Finite_Field (Item.Group) then
         declare
            Exponent : Byte_Array (1 .. SSL.Secrets.Length (Item.Scalar));
            Shared   : Byte_Array (1 .. Width) := [others => 0];
            Status   : CryptoLib.Errors.Status;
         begin
            --  1 < Y < p-1, checked before the exponent touches the value.
            --  CryptoLib checks it again inside Shared_Secret, and also refuses
            --  a shared secret of 1 or p-1; doing it here as well means a
            --  malformed share is refused without an exponentiation.
            if not CryptoLib.FFDHE.Valid_Peer_Value (FFDHE_Group (Item.Group), Peer_Share) then
               Error := SSL.Errors.Make
                 (Code   => SSL.Errors.Code_Key_Exchange_Value_Invalid,
                  Origin => SSL.Errors.Peer_Message);
               return;
            end if;

            SSL.Secrets.Get (Item.Scalar, Exponent);
            Status := CryptoLib.FFDHE.Shared_Secret
              (Group         => FFDHE_Group (Item.Group),
               Private_Value => Exponent,
               Peer_Value    => Peer_Share,
               Secret        => Shared);
            Scrub (Exponent);

            Error := Mapped
              (Status, SSL.Errors.Code_Key_Agreement_Failed, SSL.Errors.Peer_Message);
            if not SSL.Errors.Is_Error (Error) then
               SSL.Secrets.Set (Target, Shared);
            end if;
            Scrub (Shared);
         end;

      elsif Item.Group = SSL.Supported_Groups.X25519 then
         declare
            Peer   : CryptoLib.Curve25519.Public_Key;
            Result : CryptoLib.Curve25519.Public_Key;
            Status : CryptoLib.Errors.Status;
            Zero   : constant Byte_Array (1 .. 32) := [others => 0];
         begin
            Peer := CryptoLib.Curve25519.Public_Key (Peer_Share);
            Status := CryptoLib.Curve25519.Shared_Secret
              (Private_Item => Item.Montgomery_Private,
               Peer_Public  => Peer,
               Secret_Item  => Result);
            Error := Mapped
              (Status, SSL.Errors.Code_Key_Agreement_Failed, SSL.Errors.Peer_Message);

            if not SSL.Errors.Is_Error (Error) then
               --  RFC 7748 section 6.1 and RFC 8446 section 7.4.2: an all-zero
               --  X25519 output means the peer sent a small-order point, and
               --  the handshake must abort rather than continue with a shared
               --  secret the peer chose.
               if CryptoLib.Constant_Time.Equal (Byte_Array (Result), Zero) then
                  Error := SSL.Errors.Make
                    (Code   => SSL.Errors.Code_Key_Exchange_Value_Invalid,
                     Origin => SSL.Errors.Peer_Message);
               else
                  SSL.Secrets.Set (Target, Byte_Array (Result));
               end if;
            end if;

            CryptoLib.Curve25519.Clear (Result);
         end;
      else
         declare
            Scalar_Octets : Byte_Array (1 .. SSL.Secrets.Length (Item.Scalar));
            Shared        : Byte_Array (1 .. Width) := [others => 0];
            Status        : CryptoLib.Errors.Status;
         begin
            --  CryptoLib validates the encoding and the on-curve condition; a
            --  point off the curve or not in uncompressed form is refused here
            --  before any scalar multiplication happens.
            if not CryptoLib.ECDH.Valid_Peer_Point (ECDH_Curve (Item.Group), Peer_Share) then
               Error := SSL.Errors.Make
                 (Code   => SSL.Errors.Code_Key_Exchange_Value_Invalid,
                  Origin => SSL.Errors.Peer_Message);
               return;
            end if;

            SSL.Secrets.Get (Item.Scalar, Scalar_Octets);
            Status := CryptoLib.ECDH.Shared_Secret
              (Curve          => ECDH_Curve (Item.Group),
               Private_Scalar => Scalar_Octets,
               Peer_Point     => Peer_Share,
               Secret         => Shared);
            Scrub (Scalar_Octets);

            Error := Mapped
              (Status, SSL.Errors.Code_Key_Agreement_Failed, SSL.Errors.Peer_Message);
            if not SSL.Errors.Is_Error (Error) then
               SSL.Secrets.Set (Target, Shared);
            end if;
            Scrub (Shared);
         end;
      end if;
   end Agree;

   ----------
   -- Wipe --
   ----------

   procedure Wipe (Item : in out Key_Exchange_Pair) is
   begin
      CryptoLib.Curve25519.Clear (Item.Montgomery_Private);
      SSL.Secrets.Wipe (Item.Scalar);
      Item.Share := [others => 0];
      Item.Share_Used := 0;
      Item.Generated := False;
   end Wipe;

   ---------------------------------------------------------------------------
   --  Signature verification
   ---------------------------------------------------------------------------

   -----------------------
   -- Verify_Signature --
   -----------------------

   procedure Verify_Signature
     (Scheme      : SSL.Signature_Schemes.Signature_Scheme;
      Public_Key  : Byte_Array;
      Signed_Data : Byte_Array;
      Signature   : Byte_Array;
      Error       : out SSL.Errors.Error_Information)
   is
      package Schemes renames SSL.Signature_Schemes;
      use type CryptoLib.X509.Signatures.Verification_Result;

      Outcome : CryptoLib.X509.Signatures.Verification_Result :=
        CryptoLib.X509.Signatures.Invalid_Signature;
   begin
      case Schemes.Key_Kind_Of (Scheme) is

         when Schemes.EdDSA_Key =>
            --  EdDSA verification takes the message, not a digest, and the
            --  signature is fixed width. CryptoLib's own entry points are the
            --  direct route; the X.509 layer would only unwrap the same call.
            declare
               Status : CryptoLib.Errors.Status;
            begin
               if Scheme = Schemes.Ed25519 then
                  if Public_Key'Length /= 32 or else Signature'Length /= 64 then
                     Error := SSL.Errors.Make
                       (SSL.Errors.Code_Signature_Verification_Failed, SSL.Errors.Peer_Message);
                     return;
                  end if;
                  Status := CryptoLib.Ed25519.Verify (Public_Key, Signature, Signed_Data);
               else
                  if Public_Key'Length /= 57 or else Signature'Length /= 114 then
                     Error := SSL.Errors.Make
                       (SSL.Errors.Code_Signature_Verification_Failed, SSL.Errors.Peer_Message);
                     return;
                  end if;
                  Status := CryptoLib.Ed448.Verify (Public_Key, Signature, Signed_Data);
               end if;

               Error := Mapped
                 (Status,
                  SSL.Errors.Code_Signature_Verification_Failed,
                  SSL.Errors.Peer_Message);
               return;
            end;

         when Schemes.ECDSA_Key =>
            declare
               Curve : SSL.Supported_Groups.Named_Group;
               Key_Kind : CryptoLib.X509.Public_Key_Algorithm;
               Algorithm : CryptoLib.X509.Signature_Algorithm;
               Ignored : constant Boolean := Schemes.Required_Curve (Scheme, Curve);
            begin
               pragma Assert (Ignored);
               case Curve is
                  when SSL.Supported_Groups.Secp256r1 =>
                     Key_Kind := CryptoLib.X509.ECDSA_P256;
                     Algorithm := CryptoLib.X509.ECDSA_With_SHA256;
                  when SSL.Supported_Groups.Secp384r1 =>
                     Key_Kind := CryptoLib.X509.ECDSA_P384;
                     Algorithm := CryptoLib.X509.ECDSA_With_SHA384;
                  when SSL.Supported_Groups.Secp521r1 =>
                     Key_Kind := CryptoLib.X509.ECDSA_P521;
                     Algorithm := CryptoLib.X509.ECDSA_With_SHA512;
                  when SSL.Supported_Groups.X25519
                     | SSL.Supported_Groups.FFDHE2048
                     | SSL.Supported_Groups.FFDHE3072
                     | SSL.Supported_Groups.FFDHE4096 =>
                     --  Unreachable: Required_Curve yields only the three ECDSA
                     --  curves. Listed rather than covered by an "others" so
                     --  that a new group added to the registry is a compile
                     --  error here and not a silent fall-through.
                     Error := SSL.Errors.Make
                       (SSL.Errors.Code_Internal_Not_Reachable,
                        SSL.Errors.Local_Implementation);
                     return;
               end case;

               --  The DER (r, s) decode is CryptoLib's; ssllib does no ASN.1.
               Outcome := CryptoLib.X509.Signatures.Verify_With_Key
                 (Signed     => Signed_Data,
                  Signature  => Signature,
                  Algorithm  => Algorithm,
                  Key_Kind   => Key_Kind,
                  Public_Key => Public_Key);
            end;

         when Schemes.RSA_Key =>
            case Schemes.Padding_Of (Scheme) is
               when Schemes.PKCS1_V1_5 =>
                  declare
                     Algorithm : constant CryptoLib.X509.Signature_Algorithm :=
                       (case Schemes.Hash_Of (Scheme) is
                           when Schemes.SHA_256 => CryptoLib.X509.SHA256_With_RSA,
                           when Schemes.SHA_384 => CryptoLib.X509.SHA384_With_RSA,
                           when others          => CryptoLib.X509.SHA512_With_RSA);
                  begin
                     Outcome := CryptoLib.X509.Signatures.Verify_With_Key
                       (Signed     => Signed_Data,
                        Signature  => Signature,
                        Algorithm  => Algorithm,
                        Key_Kind   => CryptoLib.X509.RSA,
                        Public_Key => Public_Key);
                  end;

               when Schemes.PSS_With_RSAE_Key | Schemes.PSS_With_PSS_Key =>
                  --  RFC 8446 section 4.2.3 fixes the PSS parameters per
                  --  signature scheme -- MGF1 with the same hash, a salt equal
                  --  to the digest length -- and a CertificateVerify carries no
                  --  AlgorithmIdentifier to read them from. They are passed as
                  --  arguments. This used to encode three constant DER blobs
                  --  purely so cryptolib could parse them straight back out.
                  declare
                     Hash : constant CryptoLib.X509.Signatures.PSS_Hash :=
                       (case Schemes.Hash_Of (Scheme) is
                           when Schemes.SHA_256 => CryptoLib.RSA.SHA256,
                           when Schemes.SHA_384 => CryptoLib.RSA.SHA384,
                           when others          => CryptoLib.RSA.SHA512);
                  begin
                     Outcome := CryptoLib.X509.Signatures.Verify_PSS_With_Key
                       (Signed      => Signed_Data,
                        Signature   => Signature,
                        Hash        => Hash,
                        Salt_Length =>
                          CryptoLib.X509.Signatures.Digest_Length (Hash),
                        Public_Key  => Public_Key);
                  end;

               when Schemes.Not_RSA =>
                  Error := SSL.Errors.Make
                    (SSL.Errors.Code_Internal_Not_Reachable, SSL.Errors.Local_Implementation);
                  return;
            end case;
      end case;

      if Outcome = CryptoLib.X509.Signatures.Valid then
         Error := SSL.Errors.No_Error;
      else
         --  Every non-valid outcome maps to the one code. Distinguishing a
         --  malformed signature from a wrong one would tell a peer how far its
         --  forgery got.
         Error := SSL.Errors.Make
           (Code     => SSL.Errors.Code_Signature_Verification_Failed,
            Origin   => SSL.Errors.Peer_Message,
            Provider => "cryptolib:" & CryptoLib.X509.Signatures.Result_Image (Outcome));
      end if;
   end Verify_Signature;

end SSL.Crypto;
