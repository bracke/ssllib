package body SSL.Versions is

   --------------
   -- Value_Of --
   --------------

   function Value_Of (Item : Protocol_Version) return Version_Value is
   begin
      case Item is
         when TLS_1_2 => return TLS_1_2_Value;
         when TLS_1_3 => return TLS_1_3_Value;
      end case;
   end Value_Of;

   -----------------
   -- Version_For --
   -----------------

   function Version_For (Item : Version_Value; Value : out Protocol_Version) return Boolean is
   begin
      case Item is
         when TLS_1_2_Value =>
            Value := TLS_1_2;
            return True;
         when TLS_1_3_Value =>
            Value := TLS_1_3;
            return True;
         when others =>
            Value := TLS_1_3;
            return False;
      end case;
   end Version_For;

   -------------------------
   -- Is_Refused_Legacy --
   -------------------------

   function Is_Refused_Legacy (Item : Version_Value) return Boolean is
   begin
      return Item in SSL_3_0_Value | TLS_1_0_Value | TLS_1_1_Value
        or else Item < SSL_3_0_Value;
   end Is_Refused_Legacy;

   -----------
   -- Image --
   -----------

   function Image (Item : Protocol_Version) return String is
   begin
      case Item is
         when TLS_1_2 => return "tls1.2";
         when TLS_1_3 => return "tls1.3";
      end case;
   end Image;

   function Image (Item : Version_Value) return String is
   begin
      case Item is
         when TLS_1_3_Value => return "tls1.3";
         when TLS_1_2_Value => return "tls1.2";
         when TLS_1_1_Value => return "tls1.1";
         when TLS_1_0_Value => return "tls1.0";
         when SSL_3_0_Value => return "ssl3.0";
         when others =>
            declare
               High : constant Natural := Natural (Item / 256);
               Low  : constant Natural := Natural (Item mod 256);
               Hex  : constant String := "0123456789abcdef";
            begin
               return "version_0x"
                 & Hex (1 + High / 16) & Hex (1 + High mod 16)
                 & Hex (1 + Low / 16) & Hex (1 + Low mod 16);
            end;
      end case;
   end Image;

   ------------------
   -- No_Versions --
   ------------------

   function No_Versions return Version_Set is
   begin
      return (Has_1_2 => False, Has_1_3 => False);
   end No_Versions;

   -------------------
   -- TLS_1_3_Only --
   -------------------

   function TLS_1_3_Only return Version_Set is
   begin
      return (Has_1_2 => False, Has_1_3 => True);
   end TLS_1_3_Only;

   ----------------------
   -- TLS_1_3_And_1_2 --
   ----------------------

   function TLS_1_3_And_1_2 return Version_Set is
   begin
      return (Has_1_2 => True, Has_1_3 => True);
   end TLS_1_3_And_1_2;

   ----------
   -- Only --
   ----------

   function Only (Item : Protocol_Version) return Version_Set is
   begin
      return (Has_1_2 => Item = TLS_1_2, Has_1_3 => Item = TLS_1_3);
   end Only;

   --------------
   -- Contains --
   --------------

   function Contains (Item : Version_Set; Value : Protocol_Version) return Boolean is
   begin
      case Value is
         when TLS_1_2 => return Item.Has_1_2;
         when TLS_1_3 => return Item.Has_1_3;
      end case;
   end Contains;

   ---------------
   -- Including --
   ---------------

   function Including (Item : Version_Set; Value : Protocol_Version) return Version_Set is
      Result : Version_Set := Item;
   begin
      case Value is
         when TLS_1_2 => Result.Has_1_2 := True;
         when TLS_1_3 => Result.Has_1_3 := True;
      end case;
      return Result;
   end Including;

   ---------------
   -- Excluding --
   ---------------

   function Excluding (Item : Version_Set; Value : Protocol_Version) return Version_Set is
      Result : Version_Set := Item;
   begin
      case Value is
         when TLS_1_2 => Result.Has_1_2 := False;
         when TLS_1_3 => Result.Has_1_3 := False;
      end case;
      return Result;
   end Excluding;

   -----------
   -- Count --
   -----------

   function Count (Item : Version_Set) return Natural is
   begin
      return (if Item.Has_1_2 then 1 else 0) + (if Item.Has_1_3 then 1 else 0);
   end Count;

   --------------
   -- Is_Empty --
   --------------

   function Is_Empty (Item : Version_Set) return Boolean is
   begin
      return not Item.Has_1_2 and then not Item.Has_1_3;
   end Is_Empty;

   -------------
   -- Highest --
   -------------

   function Highest (Item : Version_Set) return Protocol_Version is
   begin
      return (if Item.Has_1_3 then TLS_1_3 else TLS_1_2);
   end Highest;

   ------------
   -- Lowest --
   ------------

   function Lowest (Item : Version_Set) return Protocol_Version is
   begin
      return (if Item.Has_1_2 then TLS_1_2 else TLS_1_3);
   end Lowest;

   -----------
   -- Image --
   -----------

   function Image (Item : Version_Set) return String is
   begin
      if Item.Has_1_2 and then Item.Has_1_3 then
         return "tls1.2+tls1.3";
      elsif Item.Has_1_3 then
         return "tls1.3";
      elsif Item.Has_1_2 then
         return "tls1.2";
      else
         return "none";
      end if;
   end Image;

   ---------------------
   -- Ordered_Values --
   ---------------------

   procedure Ordered_Values
     (Item : Version_Set;
      Into : out Version_Value_Array;
      Last : out Natural)
   is
   begin
      Into := [others => 0];
      Last := 0;

      --  Highest first: RFC 8446 section 4.2.1 says the list is in order of
      --  preference, and this library's preference is always the newer
      --  protocol.
      if Item.Has_1_3 then
         Last := Last + 1;
         Into (Last) := TLS_1_3_Value;
      end if;

      if Item.Has_1_2 then
         Last := Last + 1;
         Into (Last) := TLS_1_2_Value;
      end if;
   end Ordered_Values;

end SSL.Versions;
