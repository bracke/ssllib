with Ada.Streams;

package body SSL.ALPN is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;

   Hex_Digits : constant String := "0123456789abcdef";

   -----------------
   -- No_Protocol --
   -----------------

   function No_Protocol return Protocol_Name is
   begin
      return (Used => 0, Octets => [others => 0]);
   end No_Protocol;

   ----------------
   -- Is_Present --
   ----------------

   function Is_Present (Item : Protocol_Name) return Boolean is
   begin
      return Item.Used > 0;
   end Is_Present;

   ----------
   -- Make --
   ----------

   function Make (Value : Byte_Array; Item : out Protocol_Name) return Boolean is
   begin
      Item := No_Protocol;
      if Value'Length < Minimum_Name_Length or else Value'Length > Maximum_Name_Length then
         return False;
      end if;
      Item.Used := Value'Length;
      Item.Octets (1 .. Value'Length) := Value;
      return True;
   end Make;

   function Make (Value : String; Item : out Protocol_Name) return Boolean is
   begin
      Item := No_Protocol;
      if Value'Length < 1 or else Byte_Index (Value'Length) > Maximum_Name_Length then
         return False;
      end if;

      for Character_Item of Value loop
         --  Above 127 there is no single answer to what octet a Character is,
         --  so refusing is the only honest behaviour: the caller who wants a
         --  non-ASCII protocol name must say which octets it means.
         if Character'Pos (Character_Item) > 127 then
            return False;
         end if;
      end loop;

      Item.Used := Byte_Index (Value'Length);
      for Index in 1 .. Value'Length loop
         Item.Octets (Byte_Index (Index)) :=
           Byte (Character'Pos (Value (Value'First + Index - 1)));
      end loop;
      return True;
   end Make;

   --------------
   -- Protocol --
   --------------

   function Protocol (Value : String) return Protocol_Name is
      Result : Protocol_Name;
   begin
      if not Make (Value, Result) then
         --  A literal in the program text that is not a valid ALPN name is a
         --  programming error, and this is one of the few places this library
         --  raises: there is no caller to hand a result to.
         raise Constraint_Error with "invalid ALPN protocol name literal";
      end if;
      return Result;
   end Protocol;

   --------------
   -- Value_Of --
   --------------

   function Value_Of (Item : Protocol_Name) return Byte_Array is
   begin
      return Item.Octets (1 .. Item.Used);
   end Value_Of;

   ------------
   -- Length --
   ------------

   function Length (Item : Protocol_Name) return Byte_Index is
   begin
      return Item.Used;
   end Length;

   ---------
   -- "=" --
   ---------

   function "=" (Left, Right : Protocol_Name) return Boolean is
   begin
      return Left.Used = Right.Used
        and then Left.Octets (1 .. Left.Used) = Right.Octets (1 .. Right.Used);
   end "=";

   -----------
   -- Image --
   -----------

   function Image (Item : Protocol_Name) return String is
   begin
      if Item.Used = 0 then
         return "none";
      end if;

      --  Printable ASCII goes through as itself; anything else is rendered as
      --  hexadecimal, because in the server role this string came from the peer
      --  and a log line is not a safe place for arbitrary octets.
      declare
         Printable : Boolean := True;
      begin
         for Index in 1 .. Item.Used loop
            if Item.Octets (Index) < 32 or else Item.Octets (Index) > 126 then
               Printable := False;
               exit;
            end if;
         end loop;

         if Printable then
            declare
               Text : String (1 .. Natural (Item.Used));
            begin
               for Index in Text'Range loop
                  Text (Index) := Character'Val (Natural (Item.Octets (Byte_Index (Index))));
               end loop;
               return Text;
            end;
         end if;

         declare
            Text   : String (1 .. 2 + 2 * Natural (Item.Used));
            Cursor : Positive := 3;
         begin
            Text (1 .. 2) := "0x";
            for Index in 1 .. Item.Used loop
               declare
                  Octet : constant Natural := Natural (Item.Octets (Index));
               begin
                  Text (Cursor) := Hex_Digits (1 + Octet / 16);
                  Text (Cursor + 1) := Hex_Digits (1 + Octet mod 16);
               end;
               Cursor := Cursor + 2;
            end loop;
            return Text;
         end;
      end;
   end Image;

   ---------------------------------------------------------------------------
   --  Lists
   ---------------------------------------------------------------------------

   -------------------
   -- No_Protocols --
   -------------------

   function No_Protocols return Protocol_List is
   begin
      return (Count => 0, Items => [others => <>]);
   end No_Protocols;

   ------------
   -- Length --
   ------------

   function Length (Item : Protocol_List) return Protocol_Count is
   begin
      return Item.Count;
   end Length;

   --------------
   -- Is_Empty --
   --------------

   function Is_Empty (Item : Protocol_List) return Boolean is
   begin
      return Item.Count = 0;
   end Is_Empty;

   -------------
   -- Element --
   -------------

   function Element (Item : Protocol_List; Index : Protocol_Position) return Protocol_Name is
   begin
      return Item.Items (Index);
   end Element;

   --------------
   -- Contains --
   --------------

   function Contains (Item : Protocol_List; Value : Protocol_Name) return Boolean is
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

   function Position (Item : Protocol_List; Value : Protocol_Name) return Protocol_Count is
   begin
      for Index in 1 .. Item.Count loop
         if Item.Items (Index) = Value then
            return Index;
         end if;
      end loop;
      return 0;
   end Position;

   ------------
   -- Append --
   ------------

   procedure Append (Item : in out Protocol_List; Value : Protocol_Name; Ok : out Boolean) is
   begin
      if not Is_Present (Value)
        or else Contains (Item, Value)
        or else Item.Count = Maximum_Protocols
      then
         Ok := False;
         return;
      end if;
      Item.Count := Item.Count + 1;
      Item.Items (Item.Count) := Value;
      Ok := True;
   end Append;

   -----------
   -- Image --
   -----------

   function Image (Item : Protocol_List) return String is
   begin
      if Item.Count = 0 then
         return "none";
      end if;

      declare
         Text   : String (1 .. 512) := [others => ' '];
         Used   : Natural := 0;

         procedure Append_Text (Value : String);

         procedure Append_Text (Value : String) is
            Room : constant Natural := Natural'Min (Value'Length, Text'Length - Used);
         begin
            if Room > 0 then
               Text (Used + 1 .. Used + Room) := Value (Value'First .. Value'First + Room - 1);
               Used := Used + Room;
            end if;
         end Append_Text;

      begin
         for Index in 1 .. Item.Count loop
            if Index > 1 then
               Append_Text (",");
            end if;
            Append_Text (Image (Item.Items (Index)));
         end loop;
         return Text (1 .. Used);
      end;
   end Image;

   ---------------------------------------------------------------------------
   --  Policy
   ---------------------------------------------------------------------------

   ---------------------
   -- Select_Protocol --
   ---------------------

   function Select_Protocol
     (Policy      : Selection_Policy;
      Server_List : Protocol_List;
      Client_List : Protocol_List;
      Selected    : out Protocol_Name) return Boolean
   is
   begin
      Selected := No_Protocol;

      case Policy is
         when Server_Order =>
            for Index in 1 .. Server_List.Count loop
               if Contains (Client_List, Server_List.Items (Index)) then
                  Selected := Server_List.Items (Index);
                  return True;
               end if;
            end loop;

         when Client_Order =>
            for Index in 1 .. Client_List.Count loop
               if Contains (Server_List, Client_List.Items (Index)) then
                  Selected := Client_List.Items (Index);
                  return True;
               end if;
            end loop;

         when Application_Selector =>
            --  Excluded by the precondition; the branch exists so the case is
            --  complete without an others that would hide a new policy.
            return False;
      end case;

      return False;
   end Select_Protocol;

   ----------------------
   -- Is_Valid_Policy --
   ----------------------

   function Is_Valid_Policy
     (Requirement : ALPN_Requirement; Item : Protocol_List) return Boolean
   is
   begin
      case Requirement is
         when Not_Offered =>
            --  An unused list is not an error; it is a list that will not be
            --  sent, which an application may reasonably leave configured.
            return True;
         when Optional | Required =>
            return not Is_Empty (Item);
      end case;
   end Is_Valid_Policy;

end SSL.ALPN;
