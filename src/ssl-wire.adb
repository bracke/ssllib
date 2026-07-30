package body SSL.Wire is

   use Interfaces;

   ---------------------------------------------------------------------------
   --  Reading
   ---------------------------------------------------------------------------

   ------------
   -- Reader --
   ------------

   function Reader (Data : Byte_Array) return Cursor is
   begin
      return (Position => Data'First, Last => Data'Last, Valid => True);
   end Reader;

   function Reader (First : Byte_Index; Last : Byte_Index) return Cursor is
   begin
      return (Position => First, Last => Last, Valid => True);
   end Reader;

   --------------
   -- Is_Valid --
   --------------

   function Is_Valid (Item : Cursor) return Boolean is
   begin
      return Item.Valid;
   end Is_Valid;

   ---------------
   -- Remaining --
   ---------------

   function Remaining (Item : Cursor) return Byte_Index is
   begin
      if not Item.Valid or else Item.Position > Item.Last then
         return 0;
      end if;
      return Item.Last - Item.Position + 1;
   end Remaining;

   ------------
   -- At_End --
   ------------

   function At_End (Item : Cursor) return Boolean is
   begin
      return Item.Valid and then Item.Position > Item.Last;
   end At_End;

   ----------
   -- Fail --
   ----------

   procedure Fail (Item : in out Cursor) is
   begin
      Item.Valid := False;
   end Fail;

   --  Can Count more octets be read? Fails the cursor when not, which is what
   --  makes the flag sticky: one refusal poisons every later read.
   function Available (Item : in out Cursor; Count : Byte_Index) return Boolean;

   ---------------
   -- Available --
   ---------------

   function Available (Item : in out Cursor; Count : Byte_Index) return Boolean is
   begin
      if not Item.Valid then
         return False;
      end if;
      if Count < 0 or else Remaining (Item) < Count then
         Item.Valid := False;
         return False;
      end if;
      return True;
   end Available;

   --------------
   -- Get_Byte --
   --------------

   procedure Get_Byte (Data : Byte_Array; Item : in out Cursor; Value : out Byte) is
   begin
      Value := 0;
      if not Available (Item, 1) then
         return;
      end if;
      Value := Data (Item.Position);
      Item.Position := Item.Position + 1;
   end Get_Byte;

   ----------------
   -- Get_UInt8 --
   ----------------

   procedure Get_UInt8 (Data : Byte_Array; Item : in out Cursor; Value : out Natural) is
      Octet : Byte;
   begin
      Get_Byte (Data, Item, Octet);
      Value := Natural (Octet);
   end Get_UInt8;

   -----------------
   -- Get_UInt16 --
   -----------------

   procedure Get_UInt16 (Data : Byte_Array; Item : in out Cursor; Value : out Natural) is
   begin
      Value := 0;
      if not Available (Item, 2) then
         return;
      end if;
      Value := 256 * Natural (Data (Item.Position)) + Natural (Data (Item.Position + 1));
      Item.Position := Item.Position + 2;
   end Get_UInt16;

   -----------------
   -- Get_UInt24 --
   -----------------

   procedure Get_UInt24 (Data : Byte_Array; Item : in out Cursor; Value : out Byte_Index) is
   begin
      Value := 0;
      if not Available (Item, 3) then
         return;
      end if;
      Value :=
        65_536 * Byte_Index (Data (Item.Position))
        + 256 * Byte_Index (Data (Item.Position + 1))
        + Byte_Index (Data (Item.Position + 2));
      Item.Position := Item.Position + 3;
   end Get_UInt24;

   -----------------
   -- Get_UInt32 --
   -----------------

   procedure Get_UInt32
     (Data : Byte_Array; Item : in out Cursor; Value : out Interfaces.Unsigned_32)
   is
   begin
      Value := 0;
      if not Available (Item, 4) then
         return;
      end if;
      for Offset in Byte_Index range 0 .. 3 loop
         Value := Shift_Left (Value, 8) or Unsigned_32 (Data (Item.Position + Offset));
      end loop;
      Item.Position := Item.Position + 4;
   end Get_UInt32;

   -----------------
   -- Get_UInt64 --
   -----------------

   procedure Get_UInt64
     (Data : Byte_Array; Item : in out Cursor; Value : out Interfaces.Unsigned_64)
   is
   begin
      Value := 0;
      if not Available (Item, 8) then
         return;
      end if;
      for Offset in Byte_Index range 0 .. 7 loop
         Value := Shift_Left (Value, 8) or Unsigned_64 (Data (Item.Position + Offset));
      end loop;
      Item.Position := Item.Position + 8;
   end Get_UInt64;

   --------------
   -- Get_Span --
   --------------

   procedure Get_Span
     (Data  : Byte_Array;
      Item  : in out Cursor;
      Count : Byte_Index;
      First : out Byte_Index;
      Last  : out Byte_Index)
   is
      pragma Unreferenced (Data);
   begin
      First := 1;
      Last := 0;
      if not Available (Item, Count) then
         return;
      end if;
      if Count = 0 then
         --  A null range the caller can still use as a slice bound.
         First := Item.Position;
         Last := Item.Position - 1;
         return;
      end if;
      First := Item.Position;
      Last := Item.Position + Count - 1;
      Item.Position := Item.Position + Count;
   end Get_Span;

   ---------------
   -- Get_Bytes --
   ---------------

   procedure Get_Bytes (Data : Byte_Array; Item : in out Cursor; Into : out Byte_Array) is
   begin
      if Into'Length > 0 then
         Into := [others => 0];
      end if;
      if not Available (Item, Into'Length) then
         return;
      end if;
      if Into'Length > 0 then
         Into := Data (Item.Position .. Item.Position + Into'Length - 1);
         Item.Position := Item.Position + Into'Length;
      end if;
   end Get_Bytes;

   ----------
   -- Skip --
   ----------

   procedure Skip (Data : Byte_Array; Item : in out Cursor; Count : Byte_Index) is
      pragma Unreferenced (Data);
   begin
      if not Available (Item, Count) then
         return;
      end if;
      Item.Position := Item.Position + Count;
   end Skip;

   --  Shared body of the three vector openers: the prefix width differs, the
   --  bound check and the sub-cursor construction do not.
   procedure Open_Vector
     (Data        : Byte_Array;
      Item        : in out Cursor;
      Limit       : Byte_Index;
      Length      : Byte_Index;
      Body_Cursor : out Cursor);

   -----------------
   -- Open_Vector --
   -----------------

   procedure Open_Vector
     (Data        : Byte_Array;
      Item        : in out Cursor;
      Limit       : Byte_Index;
      Length      : Byte_Index;
      Body_Cursor : out Cursor)
   is
      pragma Unreferenced (Data);
   begin
      Body_Cursor := (Position => 1, Last => 0, Valid => False);

      if not Item.Valid then
         return;
      end if;

      --  The bound is checked against the declared length before a single
      --  octet of the body is touched.
      if Length > Limit then
         Item.Valid := False;
         return;
      end if;

      if not Available (Item, Length) then
         return;
      end if;

      Body_Cursor := (Position => Item.Position,
                      Last     => Item.Position + Length - 1,
                      Valid    => True);
      Item.Position := Item.Position + Length;
   end Open_Vector;

   -------------------
   -- Open_Vector_8 --
   -------------------

   procedure Open_Vector_8
     (Data        : Byte_Array;
      Item        : in out Cursor;
      Limit       : Byte_Index;
      Body_Cursor : out Cursor)
   is
      Length : Natural;
   begin
      Get_UInt8 (Data, Item, Length);
      Open_Vector (Data, Item, Limit, Byte_Index (Length), Body_Cursor);
   end Open_Vector_8;

   --------------------
   -- Open_Vector_16 --
   --------------------

   procedure Open_Vector_16
     (Data        : Byte_Array;
      Item        : in out Cursor;
      Limit       : Byte_Index;
      Body_Cursor : out Cursor)
   is
      Length : Natural;
   begin
      Get_UInt16 (Data, Item, Length);
      Open_Vector (Data, Item, Limit, Byte_Index (Length), Body_Cursor);
   end Open_Vector_16;

   --------------------
   -- Open_Vector_24 --
   --------------------

   procedure Open_Vector_24
     (Data        : Byte_Array;
      Item        : in out Cursor;
      Limit       : Byte_Index;
      Body_Cursor : out Cursor)
   is
      Length : Byte_Index;
   begin
      Get_UInt24 (Data, Item, Length);
      Open_Vector (Data, Item, Limit, Length, Body_Cursor);
   end Open_Vector_24;

   ---------------------------------------------------------------------------
   --  Writing
   ---------------------------------------------------------------------------

   ------------
   -- Writer --
   ------------

   function Writer (Data : Byte_Array) return Emitter is
   begin
      return (Origin   => Data'First,
              Position => Data'First,
              Last     => Data'Last,
              Valid    => True);
   end Writer;

   --------------
   -- Is_Valid --
   --------------

   function Is_Valid (Item : Emitter) return Boolean is
   begin
      return Item.Valid;
   end Is_Valid;

   -------------
   -- Written --
   -------------

   function Written (Item : Emitter) return Byte_Index is
   begin
      return Item.Position - Item.Origin;
   end Written;

   ----------------
   -- Free_Space --
   ----------------

   function Free_Space (Item : Emitter) return Byte_Index is
   begin
      if not Item.Valid or else Item.Position > Item.Last then
         return 0;
      end if;
      return Item.Last - Item.Position + 1;
   end Free_Space;

   ----------
   -- Fail --
   ----------

   procedure Fail (Item : in out Emitter) is
   begin
      Item.Valid := False;
   end Fail;

   function Room (Item : in out Emitter; Count : Byte_Index) return Boolean;

   ----------
   -- Room --
   ----------

   function Room (Item : in out Emitter; Count : Byte_Index) return Boolean is
   begin
      if not Item.Valid then
         return False;
      end if;
      if Count < 0 or else Free_Space (Item) < Count then
         Item.Valid := False;
         return False;
      end if;
      return True;
   end Room;

   --------------
   -- Put_Byte --
   --------------

   procedure Put_Byte (Data : in out Byte_Array; Item : in out Emitter; Value : Byte) is
   begin
      if not Room (Item, 1) then
         return;
      end if;
      Data (Item.Position) := Value;
      Item.Position := Item.Position + 1;
   end Put_Byte;

   ----------------
   -- Put_UInt8 --
   ----------------

   procedure Put_UInt8 (Data : in out Byte_Array; Item : in out Emitter; Value : Natural) is
   begin
      Put_Byte (Data, Item, Byte (Value));
   end Put_UInt8;

   -----------------
   -- Put_UInt16 --
   -----------------

   procedure Put_UInt16 (Data : in out Byte_Array; Item : in out Emitter; Value : Natural) is
   begin
      if not Room (Item, 2) then
         return;
      end if;
      Data (Item.Position) := Byte (Value / 256);
      Data (Item.Position + 1) := Byte (Value mod 256);
      Item.Position := Item.Position + 2;
   end Put_UInt16;

   -----------------
   -- Put_UInt24 --
   -----------------

   procedure Put_UInt24 (Data : in out Byte_Array; Item : in out Emitter; Value : Byte_Index) is
   begin
      if not Room (Item, 3) then
         return;
      end if;
      Data (Item.Position) := Byte (Value / 65_536);
      Data (Item.Position + 1) := Byte ((Value / 256) mod 256);
      Data (Item.Position + 2) := Byte (Value mod 256);
      Item.Position := Item.Position + 3;
   end Put_UInt24;

   -----------------
   -- Put_UInt32 --
   -----------------

   procedure Put_UInt32
     (Data : in out Byte_Array; Item : in out Emitter; Value : Interfaces.Unsigned_32)
   is
   begin
      if not Room (Item, 4) then
         return;
      end if;
      for Offset in Byte_Index range 0 .. 3 loop
         Data (Item.Position + Offset) :=
           Byte (Shift_Right (Value, Natural (8 * (3 - Offset))) and 16#FF#);
      end loop;
      Item.Position := Item.Position + 4;
   end Put_UInt32;

   -----------------
   -- Put_UInt64 --
   -----------------

   procedure Put_UInt64
     (Data : in out Byte_Array; Item : in out Emitter; Value : Interfaces.Unsigned_64)
   is
   begin
      if not Room (Item, 8) then
         return;
      end if;
      for Offset in Byte_Index range 0 .. 7 loop
         Data (Item.Position + Offset) :=
           Byte (Shift_Right (Value, Natural (8 * (7 - Offset))) and 16#FF#);
      end loop;
      Item.Position := Item.Position + 8;
   end Put_UInt64;

   ---------------
   -- Put_Bytes --
   ---------------

   procedure Put_Bytes (Data : in out Byte_Array; Item : in out Emitter; Value : Byte_Array) is
   begin
      if Value'Length = 0 then
         return;
      end if;
      if not Room (Item, Value'Length) then
         return;
      end if;
      Data (Item.Position .. Item.Position + Value'Length - 1) := Value;
      Item.Position := Item.Position + Value'Length;
   end Put_Bytes;

   ----------------
   -- Put_Zeroes --
   ----------------

   procedure Put_Zeroes (Data : in out Byte_Array; Item : in out Emitter; Count : Byte_Index) is
   begin
      if Count <= 0 then
         return;
      end if;
      if not Room (Item, Count) then
         return;
      end if;
      Data (Item.Position .. Item.Position + Count - 1) := [others => 0];
      Item.Position := Item.Position + Count;
   end Put_Zeroes;

   -------------------
   -- Open_Vector_8 --
   -------------------

   procedure Open_Vector_8
     (Data : in out Byte_Array; Item : in out Emitter; Mark : out Byte_Index)
   is
   begin
      Mark := Item.Position;
      Put_UInt8 (Data, Item, 0);
   end Open_Vector_8;

   --------------------
   -- Open_Vector_16 --
   --------------------

   procedure Open_Vector_16
     (Data : in out Byte_Array; Item : in out Emitter; Mark : out Byte_Index)
   is
   begin
      Mark := Item.Position;
      Put_UInt16 (Data, Item, 0);
   end Open_Vector_16;

   --------------------
   -- Open_Vector_24 --
   --------------------

   procedure Open_Vector_24
     (Data : in out Byte_Array; Item : in out Emitter; Mark : out Byte_Index)
   is
   begin
      Mark := Item.Position;
      Put_UInt24 (Data, Item, 0);
   end Open_Vector_24;

   --------------------
   -- Close_Vector_8 --
   --------------------

   procedure Close_Vector_8
     (Data : in out Byte_Array; Item : in out Emitter; Mark : Byte_Index)
   is
      Length : Byte_Index;
   begin
      if not Item.Valid then
         return;
      end if;
      Length := Item.Position - Mark - 1;
      if Length > 255 then
         Item.Valid := False;
         return;
      end if;
      Data (Mark) := Byte (Length);
   end Close_Vector_8;

   ---------------------
   -- Close_Vector_16 --
   ---------------------

   procedure Close_Vector_16
     (Data : in out Byte_Array; Item : in out Emitter; Mark : Byte_Index)
   is
      Length : Byte_Index;
   begin
      if not Item.Valid then
         return;
      end if;
      Length := Item.Position - Mark - 2;
      if Length > 65_535 then
         Item.Valid := False;
         return;
      end if;
      Data (Mark) := Byte (Length / 256);
      Data (Mark + 1) := Byte (Length mod 256);
   end Close_Vector_16;

   ---------------------
   -- Close_Vector_24 --
   ---------------------

   procedure Close_Vector_24
     (Data : in out Byte_Array; Item : in out Emitter; Mark : Byte_Index)
   is
      Length : Byte_Index;
   begin
      if not Item.Valid then
         return;
      end if;
      Length := Item.Position - Mark - 3;
      if Length > 16#FF_FFFF# then
         Item.Valid := False;
         return;
      end if;
      Data (Mark) := Byte (Length / 65_536);
      Data (Mark + 1) := Byte ((Length / 256) mod 256);
      Data (Mark + 2) := Byte (Length mod 256);
   end Close_Vector_24;

   ---------------------------------------------------------------------------
   --  Fixed-width helpers
   ---------------------------------------------------------------------------

   --------------------
   -- Encode_UInt64 --
   --------------------

   function Encode_UInt64 (Value : Interfaces.Unsigned_64) return Byte_Array is
      Result : Byte_Array (1 .. 8);
   begin
      for Index in Result'Range loop
         Result (Index) :=
           Byte (Shift_Right (Value, Natural (8 * (8 - Index))) and 16#FF#);
      end loop;
      return Result;
   end Encode_UInt64;

   --------------------
   -- Encode_UInt16 --
   --------------------

   function Encode_UInt16 (Value : Natural) return Byte_Array is
   begin
      return [1 => Byte (Value / 256), 2 => Byte (Value mod 256)];
   end Encode_UInt16;

   --------------------
   -- Decode_UInt16 --
   --------------------

   function Decode_UInt16 (Data : Byte_Array) return Natural is
   begin
      return 256 * Natural (Data (Data'First)) + Natural (Data (Data'First + 1));
   end Decode_UInt16;

   --------------------
   -- Decode_UInt24 --
   --------------------

   function Decode_UInt24 (Data : Byte_Array) return Byte_Index is
   begin
      return 65_536 * Byte_Index (Data (Data'First))
        + 256 * Byte_Index (Data (Data'First + 1))
        + Byte_Index (Data (Data'First + 2));
   end Decode_UInt24;

end SSL.Wire;
