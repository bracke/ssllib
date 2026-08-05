package body SSL.Engines.Events is

   ---------------
   -- Image --
   ---------------

   function Image (Item : Event_Kind) return String is
     (case Item is
         when Need_Transport_Input          => "need transport input",
         when Transport_Output_Available    => "transport output available",
         when Application_Data_Available    => "application data available",
         when Application_Data_Accepted     => "application data accepted",
         when Handshake_Completed           => "handshake completed",
         when Peer_Close_Notify             => "peer close_notify",
         when Local_Shutdown_Completed      => "local shutdown completed",
         when Application_Decision_Required => "application decision required",
         when Deadline_Reached              => "deadline reached",
         when Failed                        => "failed");

   ------------------
   -- Contains --
   ------------------

   function Contains (Item : Event_List; Kind : Event_Kind) return Boolean is
   begin
      for Index in 1 .. Item.Count loop
         if Item.Events (Index) = Kind then
            return True;
         end if;
      end loop;
      return False;
   end Contains;

   -----------------
   -- Current --
   -----------------

   function Current (Item : Engine) return Event_List is
      Result : Event_List;
      Status : constant Readiness := Ready (Item);

      procedure Add (Kind : Event_Kind);

      procedure Add (Kind : Event_Kind) is
      begin
         if Result.Count < Maximum_Events then
            Result.Count := Result.Count + 1;
            Result.Events (Result.Count) := Kind;
         end if;
      end Add;
   begin
      --  Ordered most-terminal first, so that a caller taking only the first
      --  event still sees the one that matters. A failed connection with data
      --  still queued is a failed connection.
      if State_Of (Item) = SSL.Engines.Failed then
         Add (Failed);
         return Result;
      end if;

      if Status.Handshake_Complete then
         Add (Handshake_Completed);
      end if;
      if Status.Has_Plaintext then
         Add (Application_Data_Available);
      end if;
      if Status.Wants_Transport_Write then
         Add (Transport_Output_Available);
      end if;
      if Status.Peer_Closed then
         Add (Peer_Close_Notify);
      end if;
      if State_Of (Item) = Closed then
         Add (Local_Shutdown_Completed);
      end if;
      if Status.Wants_Transport_Read and then not Status.Has_Plaintext then
         --  Only when there is nothing already here to work with: an engine
         --  holding readable data does not need more input to make progress,
         --  and saying it did would send a caller to a socket it need not wait
         --  on.
         Add (Need_Transport_Input);
      end if;
      if Status.Accepts_Plaintext then
         Add (Application_Data_Accepted);
      end if;

      return Result;
   end Current;

end SSL.Engines.Events;
