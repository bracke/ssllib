package body SSL.Transports is

   ---------------
   -- Image --
   ---------------

   function Image (Item : Transport_Status) return String is
     (case Item is
         when Ok            => "ok",
         when Would_Block   => "would block",
         when End_Of_Stream => "end of stream",
         when Interrupted   => "interrupted",
         when Timed_Out     => "timed out",
         when Failed        => "failed");

   --  The failure a transport that misbehaved produces. One place, so the two
   --  operations below cannot describe the same misbehaviour differently.
   function Misbehaved
     (Item : Transport'Class; What : String) return SSL.Errors.Error_Information
   is (SSL.Errors.Make
         (Code     => SSL.Errors.Code_Transport_Failed,
          Origin   => SSL.Errors.Caller_Transport,
          Provider => Item.Description & ": " & What));

   ---------------------------
   -- Receive_Safely --
   ---------------------------

   procedure Receive_Safely
     (Item   : in out Transport'Class;
      Into   : out Byte_Array;
      Count  : out Byte_Index;
      Status : out Transport_Status;
      Error  : out SSL.Errors.Error_Information)
   is
   begin
      Into := [others => 0];
      Count := 0;
      Status := Failed;
      Error := SSL.Errors.No_Error;

      begin
         Item.Receive (Into, Count, Status);
      exception
         when others =>
            --  Deliberately no exception occurrence in the message: it would be
            --  the application's own text, and this failure's rendering reaches
            --  logs that travel.
            Into := [others => 0];
            Count := 0;
            Status := Failed;
            Error := SSL.Errors.Make
              (Code     => SSL.Errors.Code_Application_Callback_Raised,
               Origin   => SSL.Errors.Caller_Transport,
               Provider => Item.Description);
            return;
      end;

      if Status /= Ok then
         --  A count on a non-Ok status is a transport describing octets it did
         --  not move. Zeroing it is the safe reading: acting on it would mean
         --  feeding uninitialized buffer contents into the record layer.
         Count := 0;
         return;
      end if;

      if Count > Into'Length then
         --  A transport claiming to have written past the end of the buffer it
         --  was given. Nothing about the result can be trusted, including the
         --  part that would have fitted.
         Into := [others => 0];
         Count := 0;
         Status := Failed;
         Error := Misbehaved (Item, "reported reading more than the buffer holds");
      end if;
   end Receive_Safely;

   ------------------------
   -- Send_Safely --
   ------------------------

   procedure Send_Safely
     (Item   : in out Transport'Class;
      Data   : Byte_Array;
      Count  : out Byte_Index;
      Status : out Transport_Status;
      Error  : out SSL.Errors.Error_Information)
   is
   begin
      Count := 0;
      Status := Failed;
      Error := SSL.Errors.No_Error;

      begin
         Item.Send (Data, Count, Status);
      exception
         when others =>
            Count := 0;
            Status := Failed;
            Error := SSL.Errors.Make
              (Code     => SSL.Errors.Code_Application_Callback_Raised,
               Origin   => SSL.Errors.Caller_Transport,
               Provider => Item.Description);
            return;
      end;

      if Status /= Ok then
         Count := 0;
         return;
      end if;

      if Count > Data'Length then
         --  A transport claiming to have sent more than it was handed. The
         --  connection cannot continue: this library would then believe octets
         --  had left that never did, and every subsequent record would be
         --  offset.
         Count := 0;
         Status := Failed;
         Error := Misbehaved (Item, "reported sending more than it was given");
      end if;
   end Send_Safely;

end SSL.Transports;
