with Ada.Streams;

with SSL.Crypto;
with SSL.Wire;

package body SSL.Records is

   use SSL.Cipher_Suites;
   use type Ada.Streams.Stream_Element;

   ---------------------------------------------------------------------------
   --  Content types
   ---------------------------------------------------------------------------

   -----------------
   -- Content_For --
   -----------------

   function Content_For (Octet : Byte) return Content_Type is
   begin
      case Natural (Octet) is
         when Change_Cipher_Spec_Octet => return Change_Cipher_Spec;
         when Alert_Octet              => return Alert_Content;
         when Handshake_Octet          => return Handshake_Content;
         when Application_Data_Octet   => return Application_Content;
         when others                   => return Invalid_Content;
      end case;
   end Content_For;

   ---------------
   -- Octet_For --
   ---------------

   function Octet_For (Item : Content_Type) return Byte is
   begin
      case Item is
         when Change_Cipher_Spec  => return Byte (Change_Cipher_Spec_Octet);
         when Alert_Content       => return Byte (Alert_Octet);
         when Handshake_Content   => return Byte (Handshake_Octet);
         when Application_Content => return Byte (Application_Data_Octet);
         when Invalid_Content     => return 0;
      end case;
   end Octet_For;

   -----------
   -- Image --
   -----------

   function Image (Item : Content_Type) return String is
   begin
      case Item is
         when Change_Cipher_Spec  => return "change_cipher_spec";
         when Alert_Content       => return "alert";
         when Handshake_Content   => return "handshake";
         when Application_Content => return "application_data";
         when Invalid_Content     => return "invalid";
      end case;
   end Image;

   ---------------------------------------------------------------------------
   --  Header
   ---------------------------------------------------------------------------

   ------------------
   -- Parse_Header --
   ------------------

   procedure Parse_Header
     (Data  : Byte_Array;
      Item  : out Record_Header;
      Error : out SSL.Errors.Error_Information)
   is
      First : constant Byte_Index := Data'First;
   begin
      --  Field by field, out of named octet positions. Nothing is overlaid.
      Item.Content := Content_For (Data (First));
      Item.Version := SSL.Versions.Version_Value
        (256 * Natural (Data (First + 1)) + Natural (Data (First + 2)));
      Item.Length := 256 * Byte_Index (Data (First + 3)) + Byte_Index (Data (First + 4));

      if Item.Content = Invalid_Content then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Record_Header_Malformed,
            Origin     => SSL.Errors.Peer_Message,
            Parameters =>
              [SSL.Errors.Numeric_Parameter ("content_type", Long_Long_Integer (Data (First)))]);
         return;
      end if;

      Error := SSL.Errors.No_Error;
   end Parse_Header;

   -------------------
   -- Encode_Header --
   -------------------

   function Encode_Header (Item : Record_Header) return Byte_Array is
      Result : Byte_Array (1 .. Header_Length);
   begin
      Result (1) := Octet_For (Item.Content);
      Result (2) := Byte (Natural (Item.Version) / 256);
      Result (3) := Byte (Natural (Item.Version) mod 256);
      Result (4) := Byte (Item.Length / 256);
      Result (5) := Byte (Item.Length mod 256);
      return Result;
   end Encode_Header;

   ---------------------------------------------------------------------------
   --  Nonce
   ---------------------------------------------------------------------------

   -----------
   -- Nonce --
   -----------

   function Nonce
     (Static_IV : Byte_Array;
      Sequence  : Interfaces.Unsigned_64) return Byte_Array
   is
      Result  : Byte_Array (1 .. Static_IV'Length) := [others => 0];
      Encoded : constant Byte_Array := SSL.Wire.Encode_UInt64 (Sequence);
      Offset  : constant Byte_Index := Static_IV'Length - 8;
   begin
      --  Left-pad the eight sequence octets to the IV's width, then exclusive-or
      --  with the static IV. RFC 8446 section 5.3.
      Result (1 + Offset .. Result'Last) := Encoded;

      for Index in Result'Range loop
         Result (Index) := Result (Index) xor Static_IV (Static_IV'First + Index - 1);
      end loop;

      return Result;
   end Nonce;

   ---------------------------------------------------------------------------
   --  Traffic state
   ---------------------------------------------------------------------------

   ---------------
   -- Is_Active --
   ---------------

   function Is_Active (Item : Traffic_State) return Boolean is
   begin
      return Item.Active;
   end Is_Active;

   -------------
   -- Install --
   -------------

   procedure Install
     (Item       : in out Traffic_State;
      Suite      : SSL.Cipher_Suites.Cipher_Suite;
      Key        : Byte_Array;
      IV         : Byte_Array;
      Generation : Natural)
   is
   begin
      SSL.Secrets.Set (Item.Key, Key);
      Item.Static_IV := IV;
      Item.Suite := Suite;
      Item.Active := True;

      --  The sequence number returns to zero here and only here, together with a
      --  new key. That pairing is the whole no-nonce-reuse argument.
      Item.Next := 0;
      Item.Generation := Generation;
      Item.Records := 0;
      Item.Octets := 0;
   end Install;

   ----------
   -- Wipe --
   ----------

   procedure Wipe (Item : in out Traffic_State) is
   begin
      SSL.Secrets.Wipe (Item.Key);
      SSL.Crypto.Scrub (Item.Static_IV);
      Item.Active := False;
   end Wipe;

   -----------
   -- Close --
   -----------

   procedure Close (Item : in out Traffic_State) is
   begin
      Item.Closed := True;
   end Close;

   ---------------
   -- Is_Closed --
   ---------------

   function Is_Closed (Item : Traffic_State) return Boolean is
   begin
      return Item.Closed;
   end Is_Closed;

   --------------
   -- Sequence --
   --------------

   function Sequence (Item : Traffic_State) return Interfaces.Unsigned_64 is
   begin
      return Item.Next;
   end Sequence;

   -------------------
   -- Generation_Of --
   -------------------

   function Generation_Of (Item : Traffic_State) return Natural is
   begin
      return Item.Generation;
   end Generation_Of;

   ------------------
   -- Record_Count --
   ------------------

   function Record_Count (Item : Traffic_State) return Long_Long_Integer is
   begin
      return Item.Records;
   end Record_Count;

   -----------------
   -- Octet_Count --
   -----------------

   function Octet_Count (Item : Traffic_State) return Long_Long_Integer is
   begin
      return Item.Octets;
   end Octet_Count;

   -------------------
   -- Suite_Of --
   -------------------

   function Suite_Of (Item : Traffic_State) return SSL.Cipher_Suites.Cipher_Suite is
   begin
      return Item.Suite;
   end Suite_Of;

   ----------------------
   -- Update_Advisable --
   ----------------------

   function Update_Advisable
     (Item : Traffic_State; Bounds : SSL.Limits.Resource_Limits) return Boolean
   is
   begin
      return Item.Records >= Long_Long_Integer (Bounds.Key_Update_Record_Threshold)
        or else Item.Octets >= Bounds.Key_Update_Octet_Threshold;
   end Update_Advisable;

   ---------------------
   -- Update_Required --
   ---------------------

   function Update_Required
     (Item : Traffic_State; Bounds : SSL.Limits.Resource_Limits) return Boolean
   is
   begin
      return Item.Records >= Long_Long_Integer (Bounds.Hard_Record_Limit)
        or else Item.Octets >= Bounds.Hard_Octet_Limit
        --  Equality rather than ">=": Maximum_Sequence is Unsigned_64'Last, so
        --  nothing can exceed it, and Protect refuses at exactly this value
        --  rather than wrapping.
        or else Item.Next = Maximum_Sequence;
   end Update_Required;

   ---------------------------------------------------------------------------
   --  Protection
   ---------------------------------------------------------------------------

   -------------
   -- Protect --
   -------------

   procedure Protect
     (Item      : in out Traffic_State;
      Inner     : Content_Type;
      Plaintext : Byte_Array;
      Padding   : Byte_Index;
      Into      : out Byte_Array;
      Written   : out Byte_Index;
      Error     : out SSL.Errors.Error_Information)
   is
      AEAD        : constant AEAD_Algorithm := AEAD_Of (Item.Suite);
      Tag_Size    : constant Byte_Index := Tag_Length (AEAD);
      Inner_Size  : constant Byte_Index := Plaintext'Length + 1 + Padding;
      Wire_Size   : constant Byte_Index := Inner_Size + Tag_Size;
      Header      : Record_Header;
      Header_Bits : Byte_Array (1 .. Header_Length);
   begin
      Written := 0;
      if Into'Length > 0 then
         Into := [others => 0];
      end if;

      --  Refuse before doing anything, not after. At the ceiling the sequence
      --  number must not advance and the key must not be used again.
      if Item.Next = Maximum_Sequence then
         Error := SSL.Errors.Make
           (Code   => SSL.Errors.Code_Record_Sequence_Exhausted,
            Origin => SSL.Errors.Local_Implementation);
         return;
      end if;

      if Wire_Size > Maximum_Ciphertext_Length then
         Error := SSL.Errors.Limit_Failure
           (Kind      => SSL.Limits.Plaintext_Record,
            Allowed   => Long_Long_Integer (Maximum_Ciphertext_Length),
            Requested => Long_Long_Integer (Wire_Size),
            Origin    => SSL.Errors.Local_Implementation);
         return;
      end if;

      --  RFC 8446 section 5.2: the outer type is application_data and the outer
      --  version is 0x0303, whatever the inner type and whatever was
      --  negotiated. The header is what the AEAD authenticates, so it is built
      --  before the encryption and passed in unchanged.
      Header := (Content => Application_Content,
                 Version => SSL.Versions.Legacy_Record_Value,
                 Length  => Wire_Size);
      Header_Bits := Encode_Header (Header);

      declare
         Inner_Text : Byte_Array (1 .. Inner_Size) := [others => 0];
         Sealed     : Byte_Array (1 .. Wire_Size) := [others => 0];
         Per_Record : constant Byte_Array := Nonce (Item.Static_IV, Item.Next);
      begin
         --  content || inner content type || zero padding
         if Plaintext'Length > 0 then
            Inner_Text (1 .. Plaintext'Length) := Plaintext;
         end if;
         Inner_Text (Plaintext'Length + 1) := Octet_For (Inner);

         SSL.Crypto.Seal
           (Algorithm  => AEAD,
            Key        => Item.Key,
            Nonce      => Per_Record,
            Additional => Header_Bits,
            Plaintext  => Inner_Text,
            Wire       => Sealed,
            Error      => Error);

         SSL.Crypto.Scrub (Inner_Text);

         if SSL.Errors.Is_Error (Error) then
            --  The sequence number does not advance on failure, and the caller
            --  is expected to fail the connection rather than retry: retrying
            --  would protect a second record under the same nonce.
            return;
         end if;

         Into (Into'First .. Into'First + Header_Length - 1) := Header_Bits;
         Into (Into'First + Header_Length .. Into'First + Header_Length + Wire_Size - 1) := Sealed;
         Written := Header_Length + Wire_Size;
      end;

      --  Advance only after success.
      Item.Next := Item.Next + 1;
      Item.Records := Item.Records + 1;
      Item.Octets := Item.Octets + Long_Long_Integer (Wire_Size);
      Error := SSL.Errors.No_Error;
   end Protect;

   ----------
   -- Open --
   ----------

   procedure Open
     (Item       : in out Traffic_State;
      Header     : Byte_Array;
      Ciphertext : Byte_Array;
      Into       : out Byte_Array;
      Written    : out Byte_Index;
      Inner      : out Content_Type;
      Error      : out SSL.Errors.Error_Information)
   is
      AEAD       : constant AEAD_Algorithm := AEAD_Of (Item.Suite);
      Tag_Size   : constant Byte_Index := Tag_Length (AEAD);
      Inner_Size : constant Byte_Index := Ciphertext'Length - Tag_Size;
   begin
      Written := 0;
      Inner := Invalid_Content;
      if Into'Length > 0 then
         Into := [others => 0];
      end if;

      if Item.Next = Maximum_Sequence then
         Error := SSL.Errors.Make
           (Code   => SSL.Errors.Code_Record_Sequence_Exhausted,
            Origin => SSL.Errors.Local_Implementation);
         return;
      end if;

      if Ciphertext'Length > Maximum_Ciphertext_Length then
         Error := SSL.Errors.Limit_Failure
           (Kind      => SSL.Limits.Plaintext_Record,
            Allowed   => Long_Long_Integer (Maximum_Ciphertext_Length),
            Requested => Long_Long_Integer (Ciphertext'Length));
         return;
      end if;

      declare
         Recovered  : Byte_Array (1 .. Inner_Size) := [others => 0];
         Per_Record : constant Byte_Array := Nonce (Item.Static_IV, Item.Next);
         Last        : Byte_Index;
      begin
         SSL.Crypto.Open
           (Algorithm  => AEAD,
            Key        => Item.Key,
            Nonce      => Per_Record,
            Additional => Header,
            Wire       => Ciphertext,
            Plaintext  => Recovered,
            Error      => Error);

         if SSL.Errors.Is_Error (Error) then
            --  No plaintext is exposed, no alternate key or sequence number is
            --  tried, and the sequence number does not advance. The connection
            --  is finished; this failure maps to bad_record_mac centrally.
            SSL.Crypto.Scrub (Recovered);
            return;
         end if;

         --  Only now, with the tag verified, is the padding removed. Scanning
         --  back for the last non-zero octet on authenticated plaintext cannot
         --  be a padding oracle: an attacker who could influence the outcome
         --  would have had to forge the tag first.
         Last := Inner_Size;
         while Last >= 1 and then Recovered (Last) = 0 loop
            Last := Last - 1;
         end loop;

         if Last < 1 then
            --  Every octet was zero, so there is no inner content type at all.
            --  RFC 8446 section 5.4 requires this to be an unexpected_message;
            --  it is reported as an authentication failure so that it is
            --  indistinguishable from a bad tag.
            SSL.Crypto.Scrub (Recovered);
            Error := SSL.Errors.Make
              (Code   => SSL.Errors.Code_Record_Inner_Type_Invalid,
               Origin => SSL.Errors.Peer_Message);
            return;
         end if;

         Inner := Content_For (Recovered (Last));
         if Inner = Invalid_Content then
            SSL.Crypto.Scrub (Recovered);
            Error := SSL.Errors.Make
              (Code   => SSL.Errors.Code_Record_Inner_Type_Invalid,
               Origin => SSL.Errors.Peer_Message);
            return;
         end if;

         Written := Last - 1;
         if Written > 0 then
            Into (Into'First .. Into'First + Written - 1) := Recovered (1 .. Written);
         end if;
         SSL.Crypto.Scrub (Recovered);
      end;

      Item.Next := Item.Next + 1;
      Item.Records := Item.Records + 1;
      Item.Octets := Item.Octets + Long_Long_Integer (Ciphertext'Length);
      Error := SSL.Errors.No_Error;
   end Open;

   ----------------------
   -- Emit_Plaintext --
   ----------------------

   procedure Emit_Plaintext
     (Content   : Content_Type;
      Version   : SSL.Versions.Version_Value;
      Plaintext : Byte_Array;
      Into      : out Byte_Array;
      Written   : out Byte_Index;
      Error     : out SSL.Errors.Error_Information)
   is
      Header : Record_Header;
   begin
      Written := 0;
      if Into'Length > 0 then
         Into := [others => 0];
      end if;

      if Plaintext'Length > SSL.Limits.Protocol_Plaintext_Record_Limit then
         Error := SSL.Errors.Limit_Failure
           (Kind      => SSL.Limits.Plaintext_Record,
            Allowed   => SSL.Limits.Protocol_Plaintext_Record_Limit,
            Requested => Long_Long_Integer (Plaintext'Length),
            Origin    => SSL.Errors.Local_Implementation);
         return;
      end if;

      Header := (Content => Content, Version => Version, Length => Plaintext'Length);
      Into (Into'First .. Into'First + Header_Length - 1) := Encode_Header (Header);
      if Plaintext'Length > 0 then
         Into (Into'First + Header_Length
               .. Into'First + Header_Length + Plaintext'Length - 1) := Plaintext;
      end if;
      Written := Header_Length + Plaintext'Length;
      Error := SSL.Errors.No_Error;
   end Emit_Plaintext;

end SSL.Records;
