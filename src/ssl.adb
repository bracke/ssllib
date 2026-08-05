with Ada.Streams;

package body SSL is

   Hex_Digits : constant String := "0123456789abcdef";

   --  Render a digest as lower-case hexadecimal.
   function Digest_Image (Digest : Digest_Bytes) return String;

   --  Value of one hexadecimal character, or -1 when it is not one.
   function Hex_Value (Character_Item : Character) return Integer;

   ------------------
   -- Digest_Image --
   ------------------

   function Digest_Image (Digest : Digest_Bytes) return String is
      Result : String (1 .. 2 * Fingerprint_Digest_Length);
      Cursor : Positive := Result'First;
   begin
      for Index in Digest'Range loop
         declare
            Value : constant Natural := Natural (Digest (Index));
         begin
            Result (Cursor) := Hex_Digits (1 + Value / 16);
            Result (Cursor + 1) := Hex_Digits (1 + Value mod 16);
         end;
         Cursor := Cursor + 2;
      end loop;
      return Result;
   end Digest_Image;

   ---------------
   -- Hex_Value --
   ---------------

   function Hex_Value (Character_Item : Character) return Integer is
   begin
      case Character_Item is
         when '0' .. '9' => return Character'Pos (Character_Item) - Character'Pos ('0');
         when 'a' .. 'f' => return 10 + Character'Pos (Character_Item) - Character'Pos ('a');
         when 'A' .. 'F' => return 10 + Character'Pos (Character_Item) - Character'Pos ('A');
         when others     => return -1;
      end case;
   end Hex_Value;

   -------------------
   -- No_Connection --
   -------------------

   function No_Connection return Connection_ID is
   begin
      return Connection_ID (0);
   end No_Connection;

   -------------------
   -- No_Credential --
   -------------------

   function No_Credential return Credential_ID is
   begin
      return Credential_ID (0);
   end No_Credential;

   ----------------
   -- No_Session --
   ----------------

   function No_Session return Session_ID is
   begin
      return Session_ID (0);
   end No_Session;

   -------------------------------
   -- Default_Security_Context --
   -------------------------------

   function Default_Security_Context return Security_Context_ID is
   begin
      return (Length => 0, Text => [others => ' ']);
   end Default_Security_Context;

   ----------------
   -- Is_Present --
   ----------------

   function Is_Present (Item : Connection_ID) return Boolean is
   begin
      return Item /= Connection_ID (0);
   end Is_Present;

   function Is_Present (Item : Credential_ID) return Boolean is
   begin
      return Item /= Credential_ID (0);
   end Is_Present;

   function Is_Present (Item : Session_ID) return Boolean is
   begin
      return Item /= Session_ID (0);
   end Is_Present;

   ----------------------
   -- Security_Context --
   ----------------------

   function Security_Context (Label : String) return Security_Context_ID is
      Result : Security_Context_ID;
   begin
      Result.Length := Label'Length;
      if Label'Length > 0 then
         Result.Text (1 .. Label'Length) := Label;
      end if;
      return Result;
   end Security_Context;

   -----------
   -- Image --
   -----------

   function Image (Item : Certificate_Fingerprint) return String is
   begin
      return Digest_Image (Item.Digest);
   end Image;

   function Image (Item : Configuration_Fingerprint) return String is
   begin
      return Digest_Image (Item.Digest);
   end Image;

   function Image (Item : Trust_Fingerprint) return String is
   begin
      return Digest_Image (Item.Digest);
   end Image;

   function Image (Item : Connection_ID) return String is
   begin
      if not Is_Present (Item) then
         return "-";
      end if;
      declare
         Text : constant String := Natural (Item)'Image;
      begin
         --  'Image leads with a space for a non-negative value.
         return Text (Text'First + 1 .. Text'Last);
      end;
   end Image;

   ----------------
   -- Subject_Of --
   ----------------

   function Subject_Of (Item : Certificate_Fingerprint) return Fingerprint_Subject is
   begin
      return Item.Subject;
   end Subject_Of;

   -----------------------
   -- Parse_Fingerprint --
   -----------------------

   function Parse_Fingerprint
     (Text    : String;
      Subject : Fingerprint_Subject;
      Item    : out Certificate_Fingerprint) return Boolean
   is
      Digest : Digest_Bytes := Null_Digest;
      Cursor : Natural := Text'First;
   begin
      Item := (Subject => Subject, Digest => Null_Digest);

      if Text'Length /= 2 * Fingerprint_Digest_Length then
         return False;
      end if;

      for Index in Digest'Range loop
         declare
            High : constant Integer := Hex_Value (Text (Cursor));
            Low  : constant Integer := Hex_Value (Text (Cursor + 1));
         begin
            if High < 0 or else Low < 0 then
               return False;
            end if;
            Digest (Index) := Byte (16 * High + Low);
         end;
         Cursor := Cursor + 2;
      end loop;

      Item := (Subject => Subject, Digest => Digest);
      return True;
   end Parse_Fingerprint;

   -------------------
   -- Digest_Of --
   -------------------

   function Digest_Of (Item : Certificate_Fingerprint) return Byte_Array is (Item.Digest);

   --------------------
   -- Is_Present --
   --------------------

   function Is_Present (Item : Certificate_Fingerprint) return Boolean is
      use type Ada.Streams.Stream_Element_Array;
   begin
      return Item.Digest /= Null_Digest;
   end Is_Present;

   function Digest_Of (Item : Configuration_Fingerprint) return Byte_Array is (Item.Digest);
   function Digest_Of (Item : Trust_Fingerprint) return Byte_Array is (Item.Digest);

   function Configuration_From_Digest
     (Digest : Byte_Array) return Configuration_Fingerprint
   is ((Digest => Digest));

   function Trust_From_Digest (Digest : Byte_Array) return Trust_Fingerprint is
     ((Digest => Digest));

   function Label_Of (Item : Security_Context_ID) return String is
     (Item.Text (1 .. Item.Length));

end SSL;
