package body SSL.Supported_Groups is

   --------------
   -- Value_Of --
   --------------

   function Value_Of (Item : Named_Group) return Group_Value is
   begin
      case Item is
         when X25519    => return X25519_Value;
         when Secp256r1 => return Secp256r1_Value;
         when Secp384r1 => return Secp384r1_Value;
         when Secp521r1 => return Secp521r1_Value;
         when FFDHE2048 => return FFDHE2048_Value;
         when FFDHE3072 => return FFDHE3072_Value;
         when FFDHE4096 => return FFDHE4096_Value;
      end case;
   end Value_Of;

   ---------------
   -- Group_For --
   ---------------

   function Group_For (Item : Group_Value; Value : out Named_Group) return Boolean is
   begin
      Value := X25519;
      case Item is
         when X25519_Value    => Value := X25519;
         when Secp256r1_Value => Value := Secp256r1;
         when Secp384r1_Value => Value := Secp384r1;
         when Secp521r1_Value => Value := Secp521r1;
         when FFDHE2048_Value => Value := FFDHE2048;
         when FFDHE3072_Value => Value := FFDHE3072;
         when FFDHE4096_Value => Value := FFDHE4096;
         when others          => return False;
      end case;
      return True;
   end Group_For;

   --------------------------
   -- Is_Known_Unoffered --
   --------------------------

   function Is_Known_Unoffered (Item : Group_Value) return Boolean is
   begin
      return Item in FFDHE6144_Value | FFDHE8192_Value;
   end Is_Known_Unoffered;

   ----------------
   -- Family_Of --
   ----------------

   function Family_Of (Item : Named_Group) return Group_Family is
   begin
      case Item is
         when X25519 | Secp256r1 | Secp384r1 | Secp521r1 => return Elliptic_Curve;
         when FFDHE2048 | FFDHE3072 | FFDHE4096          => return Finite_Field;
      end case;
   end Family_Of;

   -------------------
   -- Share_Length --
   -------------------

   function Share_Length (Item : Named_Group) return Byte_Index is
   begin
      case Item is
         when X25519    => return 32;
         when Secp256r1 => return 65;    --  0x04 || X(32) || Y(32)
         when Secp384r1 => return 97;    --  0x04 || X(48) || Y(48)
         when Secp521r1 => return 133;   --  0x04 || X(66) || Y(66)

         --  The width of p, which is how RFC 8446 section 4.2.8.1 encodes a
         --  finite-field share: left-padded with zeroes, never abbreviated.
         when FFDHE2048 => return 256;
         when FFDHE3072 => return 384;
         when FFDHE4096 => return 512;
      end case;
   end Share_Length;

   --------------------
   -- Secret_Length --
   --------------------

   function Secret_Length (Item : Named_Group) return Byte_Index is
   begin
      case Item is
         when X25519    => return 32;
         when Secp256r1 => return 32;
         when Secp384r1 => return 48;
         when Secp521r1 => return 66;

         --  Y**x mod p, the width of p and unhashed. TLS 1.3 feeds exactly
         --  these octets into the key schedule.
         when FFDHE2048 => return 256;
         when FFDHE3072 => return 384;
         when FFDHE4096 => return 512;
      end case;
   end Secret_Length;

   ------------------------
   -- Is_Elliptic_Curve --
   ------------------------

   function Is_Elliptic_Curve (Item : Named_Group) return Boolean is
   begin
      return Family_Of (Item) = Elliptic_Curve;
   end Is_Elliptic_Curve;

   -----------
   -- Image --
   -----------

   function Image (Item : Named_Group) return String is
   begin
      case Item is
         when X25519    => return "x25519";
         when Secp256r1 => return "secp256r1";
         when Secp384r1 => return "secp384r1";
         when Secp521r1 => return "secp521r1";
         when FFDHE2048 => return "ffdhe2048";
         when FFDHE3072 => return "ffdhe3072";
         when FFDHE4096 => return "ffdhe4096";
      end case;
   end Image;

   function Image (Item : Group_Value) return String is
      Group : Named_Group;
   begin
      if Group_For (Item, Group) then
         return Image (Group);
      end if;

      case Item is
         when FFDHE6144_Value => return "ffdhe6144";
         when FFDHE8192_Value => return "ffdhe8192";
         when others =>
            declare
               Text : constant String := Natural (Item)'Image;
            begin
               return "group_" & Text (Text'First + 1 .. Text'Last);
            end;
      end case;
   end Image;

   ---------------------------------------------------------------------------
   --  Lists
   ---------------------------------------------------------------------------

   ----------------
   -- No_Groups --
   ----------------

   function No_Groups return Group_List is
   begin
      return (Count => 0, Items => [others => X25519]);
   end No_Groups;

   ------------
   -- Append --
   ------------

   procedure Append (Item : in out Group_List; Value : Named_Group; Ok : out Boolean) is
   begin
      if Contains (Item, Value) or else Item.Count = Maximum_Groups then
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

   function Length (Item : Group_List) return Group_Count is
   begin
      return Item.Count;
   end Length;

   --------------
   -- Is_Empty --
   --------------

   function Is_Empty (Item : Group_List) return Boolean is
   begin
      return Item.Count = 0;
   end Is_Empty;

   -------------
   -- Element --
   -------------

   function Element (Item : Group_List; Index : Group_Position) return Named_Group is
   begin
      return Item.Items (Index);
   end Element;

   --------------
   -- Contains --
   --------------

   function Contains (Item : Group_List; Value : Named_Group) return Boolean is
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

   function Position (Item : Group_List; Value : Named_Group) return Group_Count is
   begin
      for Index in 1 .. Item.Count loop
         if Item.Items (Index) = Value then
            return Index;
         end if;
      end loop;
      return 0;
   end Position;

   ----------------
   -- Is_Subset --
   ----------------

   function Is_Subset (Subset : Group_List; Item : Group_List) return Boolean is
   begin
      for Index in 1 .. Subset.Count loop
         if not Contains (Item, Subset.Items (Index)) then
            return False;
         end if;
      end loop;
      return True;
   end Is_Subset;

   ---------------------
   -- Default_Groups --
   ---------------------

   function Default_Groups return Group_List is
      Result : Group_List := No_Groups;
      Done   : Boolean;
   begin
      Append (Result, X25519, Done);
      Append (Result, Secp256r1, Done);
      Append (Result, Secp384r1, Done);
      return Result;
   end Default_Groups;

   ---------------------------
   -- Finite_Field_Groups --
   ---------------------------

   function Finite_Field_Groups return Group_List is
      Result : Group_List := No_Groups;
      Done   : Boolean;
   begin
      Append (Result, FFDHE2048, Done);
      Append (Result, FFDHE3072, Done);
      Append (Result, FFDHE4096, Done);
      return Result;
   end Finite_Field_Groups;

   --------------------------------
   -- Default_Key_Share_Groups --
   --------------------------------

   function Default_Key_Share_Groups return Group_List is
      Result : Group_List := No_Groups;
      Done   : Boolean;
   begin
      Append (Result, X25519, Done);
      Append (Result, Secp256r1, Done);
      return Result;
   end Default_Key_Share_Groups;

   -----------
   -- Image --
   -----------

   function Image (Item : Group_List) return String is
   begin
      if Item.Count = 0 then
         return "none";
      end if;

      declare
         Text   : String (1 .. 192) := [others => ' '];
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

end SSL.Supported_Groups;
