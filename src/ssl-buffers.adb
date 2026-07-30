with Ada.Unchecked_Deallocation;

with CryptoLib.Secure_Wipe;

package body SSL.Buffers is

   procedure Free is new Ada.Unchecked_Deallocation (Byte_Array, Storage);

   --  Scrub through the object's own address. A plain "X := [others => 0]" on
   --  storage about to be released is a dead store and is removed by the
   --  optimizer; CryptoLib.Secure_Wipe uses volatile stores that are not.
   procedure Scrub (Data : Storage);

   -----------
   -- Scrub --
   -----------

   procedure Scrub (Data : Storage) is
   begin
      if Data /= null and then Data'Length > 0 then
         CryptoLib.Secure_Wipe.Wipe (Data.all'Address, Natural (Data'Length));
      end if;
   end Scrub;

   ---------------------------------------------------------------------------
   --  Store
   ---------------------------------------------------------------------------

   -------------
   -- Reserve --
   -------------

   procedure Reserve (Item : in out Store; Capacity : Byte_Index; Ok : out Boolean) is
   begin
      Release (Item);
      begin
         Item.Data := new Byte_Array (1 .. Capacity);
         Item.Data.all := [others => 0];
         Ok := True;
      exception
         when Storage_Error =>
            --  Reported as a result, not propagated: a caller sizing buffers
            --  from configured limits needs to refuse the configuration, not
            --  to unwind through the middle of connection setup.
            Item.Data := null;
            Ok := False;
      end;
   end Reserve;

   -----------------
   -- Is_Reserved --
   -----------------

   function Is_Reserved (Item : Store) return Boolean is
   begin
      return Item.Data /= null;
   end Is_Reserved;

   --------------
   -- Capacity --
   --------------

   function Capacity (Item : Store) return Byte_Index is
   begin
      return (if Item.Data = null then 0 else Item.Data'Length);
   end Capacity;

   ----------
   -- Wipe --
   ----------

   procedure Wipe (Item : in out Store) is
   begin
      Scrub (Item.Data);
   end Wipe;

   -------------
   -- Release --
   -------------

   procedure Release (Item : in out Store) is
   begin
      if Item.Data /= null then
         Scrub (Item.Data);
         Free (Item.Data);
      end if;
   end Release;

   --------------
   -- Finalize --
   --------------

   overriding procedure Finalize (Item : in out Store) is
   begin
      Release (Item);
   end Finalize;

   ---------
   -- Put --
   ---------

   procedure Put
     (Item  : in out Store;
      First : Byte_Index;
      Data  : Byte_Array)
   is
   begin
      if Data'Length > 0 then
         Item.Data.all (First .. First + Data'Length - 1) := Data;
      end if;
   end Put;

   ---------
   -- Get --
   ---------

   procedure Get
     (Item  : Store;
      First : Byte_Index;
      Into  : out Byte_Array)
   is
   begin
      if Into'Length > 0 then
         Into := Item.Data.all (First .. First + Into'Length - 1);
      end if;
   end Get;

   -----------
   -- Slice --
   -----------

   function Slice (Item : Store; First : Byte_Index; Last : Byte_Index) return Byte_Array is
   begin
      if Last < First then
         return Empty_Bytes;
      end if;
      return Item.Data.all (First .. Last);
   end Slice;

   -------------
   -- Element --
   -------------

   function Element (Item : Store; Index : Byte_Index) return Byte is
   begin
      return Item.Data.all (Index);
   end Element;

   ---------------------------------------------------------------------------
   --  Queue
   ---------------------------------------------------------------------------

   --  Move the queued octets back to position one, so that the free space at
   --  the front becomes free space at the back. Called only when appending
   --  needs the room, so a queue that is drained as fast as it is filled never
   --  pays for it.
   procedure Compact (Item : in out Queue);

   -------------
   -- Compact --
   -------------

   procedure Compact (Item : in out Queue) is
      Held : constant Byte_Index := Item.Tail - Item.Head;
   begin
      if Item.Head = 1 then
         return;
      end if;

      if Held > 0 then
         --  Overlapping move: Head > 1, so the destination is strictly below
         --  the source and a forward copy is safe. Ada slice assignment
         --  handles overlap correctly in either direction, but writing it as a
         --  slice assignment keeps that the compiler's problem and not this
         --  code's.
         Item.Data.all (1 .. Held) := Item.Data.all (Item.Head .. Item.Tail - 1);
      end if;

      --  The octets left behind above Held are stale copies of what was just
      --  moved. For a queue that has held plaintext or a secret that is a
      --  second copy nobody accounted for, so scrub the tail region.
      if Item.Tail - 1 > Held then
         CryptoLib.Secure_Wipe.Wipe
           (Item.Data.all (Held + 1)'Address, Natural (Item.Tail - 1 - Held));
      end if;

      Item.Head := 1;
      Item.Tail := Held + 1;
   end Compact;

   -------------
   -- Reserve --
   -------------

   procedure Reserve (Item : in out Queue; Capacity : Byte_Index; Ok : out Boolean) is
   begin
      Release (Item);
      begin
         Item.Data := new Byte_Array (1 .. Capacity);
         Item.Data.all := [others => 0];
         Item.Head := 1;
         Item.Tail := 1;
         Ok := True;
      exception
         when Storage_Error =>
            Item.Data := null;
            Item.Head := 1;
            Item.Tail := 1;
            Ok := False;
      end;
   end Reserve;

   -----------------
   -- Is_Reserved --
   -----------------

   function Is_Reserved (Item : Queue) return Boolean is
   begin
      return Item.Data /= null;
   end Is_Reserved;

   --------------
   -- Capacity --
   --------------

   function Capacity (Item : Queue) return Byte_Index is
   begin
      return (if Item.Data = null then 0 else Item.Data'Length);
   end Capacity;

   ------------
   -- Length --
   ------------

   function Length (Item : Queue) return Byte_Index is
   begin
      return Item.Tail - Item.Head;
   end Length;

   -----------
   -- Space --
   -----------

   function Space (Item : Queue) return Byte_Index is
   begin
      return Capacity (Item) - Length (Item);
   end Space;

   --------------
   -- Is_Empty --
   --------------

   function Is_Empty (Item : Queue) return Boolean is
   begin
      return Item.Head = Item.Tail;
   end Is_Empty;

   ------------
   -- Append --
   ------------

   procedure Append (Item : in out Queue; Data : Byte_Array; Ok : out Boolean) is
   begin
      if Data'Length = 0 then
         Ok := True;
         return;
      end if;

      if Data'Length > Space (Item) then
         Ok := False;
         return;
      end if;

      if Item.Data'Last - (Item.Tail - 1) < Data'Length then
         Compact (Item);
      end if;

      Item.Data.all (Item.Tail .. Item.Tail + Data'Length - 1) := Data;
      Item.Tail := Item.Tail + Data'Length;
      Ok := True;
   end Append;

   ---------------------
   -- Append_Partial --
   ---------------------

   procedure Append_Partial
     (Item     : in out Queue;
      Data     : Byte_Array;
      Accepted : out Byte_Index)
   is
      Room : constant Byte_Index := Byte_Index'Min (Data'Length, Space (Item));
      Done : Boolean;
   begin
      Accepted := 0;
      if Room = 0 then
         return;
      end if;

      Append (Item, Data (Data'First .. Data'First + Room - 1), Done);
      if Done then
         Accepted := Room;
      end if;
   end Append_Partial;

   ----------
   -- Peek --
   ----------

   procedure Peek (Item : Queue; Into : out Byte_Array; Copied : out Byte_Index) is
      Take_Count : constant Byte_Index := Byte_Index'Min (Into'Length, Length (Item));
   begin
      if Into'Length > 0 then
         Into := [others => 0];
      end if;
      Copied := Take_Count;
      if Take_Count > 0 then
         Into (Into'First .. Into'First + Take_Count - 1) :=
           Item.Data.all (Item.Head .. Item.Head + Take_Count - 1);
      end if;
   end Peek;

   -------------
   -- Peek_At --
   -------------

   procedure Peek_At
     (Item   : Queue;
      Offset : Byte_Index;
      Into   : out Byte_Array;
      Ok     : out Boolean)
   is
      Start : Byte_Index;
   begin
      if Into'Length > 0 then
         Into := [others => 0];
      end if;

      if Offset + Into'Length > Length (Item) then
         Ok := False;
         return;
      end if;

      Ok := True;
      if Into'Length = 0 then
         return;
      end if;

      Start := Item.Head + Offset;
      Into := Item.Data.all (Start .. Start + Into'Length - 1);
   end Peek_At;

   -------------
   -- Consume --
   -------------

   procedure Consume (Item : in out Queue; Count : Byte_Index) is
   begin
      if Count <= 0 then
         return;
      end if;

      --  Scrub what is being dropped. The record layer consumes ciphertext
      --  here, but the plaintext queue uses the same code, and the cost of
      --  scrubbing a consumed run is a memset the caller already paid for
      --  when it copied the octets out.
      CryptoLib.Secure_Wipe.Wipe (Item.Data.all (Item.Head)'Address, Natural (Count));

      Item.Head := Item.Head + Count;
      if Item.Head = Item.Tail then
         Item.Head := 1;
         Item.Tail := 1;
      end if;
   end Consume;

   ----------
   -- Take --
   ----------

   procedure Take (Item : in out Queue; Into : out Byte_Array) is
      Copied : Byte_Index;
   begin
      Peek (Item, Into, Copied);
      Consume (Item, Copied);
   end Take;

   --------------
   -- Contents --
   --------------

   function Contents (Item : Queue) return Byte_Array is
   begin
      if Is_Empty (Item) then
         return Empty_Bytes;
      end if;
      return Item.Data.all (Item.Head .. Item.Tail - 1);
   end Contents;

   ----------
   -- Wipe --
   ----------

   procedure Wipe (Item : in out Queue) is
   begin
      Scrub (Item.Data);
      Item.Head := 1;
      Item.Tail := 1;
   end Wipe;

   -----------
   -- Clear --
   -----------

   procedure Clear (Item : in out Queue) is
   begin
      Item.Head := 1;
      Item.Tail := 1;
   end Clear;

   -------------
   -- Release --
   -------------

   procedure Release (Item : in out Queue) is
   begin
      if Item.Data /= null then
         Scrub (Item.Data);
         Free (Item.Data);
      end if;
      Item.Head := 1;
      Item.Tail := 1;
   end Release;

   --------------
   -- Finalize --
   --------------

   overriding procedure Finalize (Item : in out Queue) is
   begin
      Release (Item);
   end Finalize;

end SSL.Buffers;
