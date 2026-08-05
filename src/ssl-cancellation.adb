package body SSL.Cancellation is

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize (Item : out Token) is
   begin
      Item.Cancelled := False;
   end Initialize;

   ------------
   -- Cancel --
   ------------

   procedure Cancel (Item : in out Token) is
   begin
      --  Idempotent by construction: the only transition is False to True, so a
      --  second call writes the value that is already there and two tasks
      --  calling concurrently cannot disagree about the outcome.
      Item.Cancelled := True;
   end Cancel;

   -------------------
   -- Is_Cancelled --
   -------------------

   function Is_Cancelled (Item : Token) return Boolean is
   begin
      return Item.Cancelled;
   end Is_Cancelled;

end SSL.Cancellation;
