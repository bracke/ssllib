with CryptoLib.Constant_Time;
with CryptoLib.Secure_Wipe;

package body SSL.Secrets is

   ---------
   -- Set --
   ---------

   procedure Set (Item : in out Secret; Data : Byte_Array) is
   begin
      Wipe (Item);
      Item.Used := Data'Length;
      if Data'Length > 0 then
         Item.Octets (1 .. Data'Length) := Data;
      end if;
   end Set;

   ----------------
   -- Set_Length --
   ----------------

   procedure Set_Length (Item : in out Secret; Length : Secret_Length) is
   begin
      Wipe (Item);
      Item.Used := Length;
   end Set_Length;

   ------------
   -- Length --
   ------------

   function Length (Item : Secret) return Secret_Length is
   begin
      return Item.Used;
   end Length;

   ----------------
   -- Is_Present --
   ----------------

   function Is_Present (Item : Secret) return Boolean is
   begin
      return Item.Used > 0;
   end Is_Present;

   -----------
   -- Value --
   -----------

   function Value (Item : Secret) return Byte_Array is
   begin
      return Item.Octets (1 .. Item.Used);
   end Value;

   ---------
   -- Get --
   ---------

   procedure Get (Item : Secret; Into : out Byte_Array) is
   begin
      if Into'Length > 0 then
         Into := Item.Octets (1 .. Item.Used);
      end if;
   end Get;

   ---------
   -- Put --
   ---------

   procedure Put (Item : in out Secret; Data : Byte_Array) is
   begin
      if Data'Length > 0 then
         Item.Octets (1 .. Item.Used) := Data;
      end if;
   end Put;

   ----------
   -- Wipe --
   ----------

   procedure Wipe (Item : in out Secret) is
   begin
      --  Through the object's own address, and over the whole buffer rather
      --  than the used prefix: a shorter secret set over a longer one would
      --  otherwise leave the longer one's tail behind.
      CryptoLib.Secure_Wipe.Wipe (Item.Octets'Address, Natural (Maximum_Length));
      Item.Used := 0;
   end Wipe;

   -----------
   -- Equal --
   -----------

   function Equal (Left : Secret; Right : Secret) return Boolean is
   begin
      --  Constant time in the contents. The lengths are not secret -- they are
      --  fixed by the negotiated cipher suite -- so comparing them directly
      --  reveals nothing an observer does not already know.
      if Left.Used /= Right.Used then
         return False;
      end if;
      return CryptoLib.Constant_Time.Equal
        (Left.Octets (1 .. Left.Used), Right.Octets (1 .. Right.Used));
   end Equal;

   function Equal (Item : Secret; Data : Byte_Array) return Boolean is
   begin
      if Item.Used /= Data'Length then
         return False;
      end if;
      return CryptoLib.Constant_Time.Equal (Item.Octets (1 .. Item.Used), Data);
   end Equal;

   ----------
   -- Copy --
   ----------

   procedure Copy (Target : in out Secret; Source : Secret) is
   begin
      Wipe (Target);
      Target.Used := Source.Used;
      if Source.Used > 0 then
         Target.Octets (1 .. Source.Used) := Source.Octets (1 .. Source.Used);
      end if;
   end Copy;

   --------------
   -- Finalize --
   --------------

   overriding procedure Finalize (Item : in out Secret) is
   begin
      Wipe (Item);
   end Finalize;

end SSL.Secrets;
