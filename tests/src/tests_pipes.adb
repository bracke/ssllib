package body Tests_Pipes is

   ----------------
   -- Reset --
   ----------------

   procedure Reset (Item : in out Pipe) is
   begin
      Item.Held := 0;
      Item.Bytes := [others => 0];
   end Reset;

   -----------------
   -- Attach --
   -----------------

   procedure Attach
     (Item     : in out Pipe_Transport;
      Outgoing : not null access Pipe;
      Incoming : not null access Pipe;
      Label    : Character)
   is
   begin
      Item.Outgoing := Outgoing;
      Item.Incoming := Incoming;
      Item.Label := Label;
      Item.Stall := False;
      Item.Ended := False;
      Item.Broken := False;
   end Attach;

   ------------------
   -- Receive --
   ------------------

   overriding procedure Receive
     (Item   : in out Pipe_Transport;
      Into   : out SSL.Byte_Array;
      Count  : out SSL.Byte_Index;
      Status : out SSL.Transports.Transport_Status)
   is
   begin
      Into := [others => 0];
      Count := 0;

      if Item.Broken then
         Status := SSL.Transports.Failed;
         return;
      end if;

      --  Every other read refuses, whether or not anything is waiting. A
      --  connection layer that only worked when reads succeeded would pass a
      --  friendlier test and fail against a real socket.
      Item.Stall := not Item.Stall;
      if Item.Stall then
         Status := SSL.Transports.Would_Block;
         return;
      end if;

      if Item.Incoming.Held = 0 then
         Status := (if Item.Ended
                    then SSL.Transports.End_Of_Stream
                    else SSL.Transports.Would_Block);
         return;
      end if;

      Count := SSL.Byte_Index'Min (Into'Length, Item.Incoming.Held);
      Into (Into'First .. Into'First + Count - 1) := Item.Incoming.Bytes (1 .. Count);

      --  Shift the remainder down. Quadratic and entirely fine: this is a test
      --  fixture, and a ring buffer here would be a second buffer implementation
      --  to get right.
      Item.Incoming.Bytes (1 .. Item.Incoming.Held - Count) :=
        Item.Incoming.Bytes (Count + 1 .. Item.Incoming.Held);
      Item.Incoming.Held := Item.Incoming.Held - Count;

      Status := SSL.Transports.Ok;
   end Receive;

   ---------------
   -- Send --
   ---------------

   overriding procedure Send
     (Item   : in out Pipe_Transport;
      Data   : SSL.Byte_Array;
      Count  : out SSL.Byte_Index;
      Status : out SSL.Transports.Transport_Status)
   is
   begin
      Count := 0;

      if Item.Broken then
         Status := SSL.Transports.Failed;
         return;
      end if;

      if Item.Outgoing.Held = Capacity then
         Status := SSL.Transports.Would_Block;
         return;
      end if;

      --  A deliberately small bite. A real socket's send buffer fills, and a
      --  caller that assumed its whole write went through would be off by
      --  everything after the first partial one.
      Count := SSL.Byte_Index'Min (Write_Chunk, Data'Length);
      Count := SSL.Byte_Index'Min (Count, Capacity - Item.Outgoing.Held);

      Item.Outgoing.Bytes (Item.Outgoing.Held + 1 .. Item.Outgoing.Held + Count) :=
        Data (Data'First .. Data'First + Count - 1);
      Item.Outgoing.Held := Item.Outgoing.Held + Count;

      Status := SSL.Transports.Ok;
   end Send;

   ----------------------
   -- Description --
   ----------------------

   overriding function Description (Item : Pipe_Transport) return String is
     ("test pipe " & Item.Label);

   -------------------------
   -- Close_Incoming --
   -------------------------

   procedure Close_Incoming (Item : in out Pipe_Transport) is
   begin
      Item.Ended := True;
   end Close_Incoming;

   ----------------
   -- Break --
   ----------------

   procedure Break (Item : in out Pipe_Transport) is
   begin
      Item.Broken := True;
   end Break;

end Tests_Pipes;
