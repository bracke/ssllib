--  @summary What an engine has to say after a step, as a bounded ordered list.
--
--  `SSL.Engines.Ready` answers "what can I do now"; this answers "what just
--  happened". The two are different questions and an application usually wants
--  both: readiness drives an event loop's next select, events drive its
--  logging, its metrics and its decisions.
--
--  Events are produced by draining, not by a callback. A callback would be
--  application code running inside the protocol driver, which is the thing this
--  library's provider boundary exists to prevent -- and an event that raised
--  would then unwind a connection with traffic keys installed.
package SSL.Engines.Events is

   --  The specification's event set, exactly.
   type Event_Kind is
     (Need_Transport_Input,
      --  The engine cannot progress without more encrypted octets.

      Transport_Output_Available,
      --  Encrypted octets are queued and want sending.

      Application_Data_Available,
      --  Authenticated application data is waiting to be read.

      Application_Data_Accepted,
      --  Plaintext offered earlier has been turned into records.

      Handshake_Completed,
      --  The handshake finished; the metadata is now meaningful.

      Peer_Close_Notify,
      --  The peer closed cleanly. Nothing more will arrive.

      Local_Shutdown_Completed,
      --  This endpoint's close_notify has actually been sent.

      Application_Decision_Required,
      --  The engine is waiting on something only the application can decide.

      Deadline_Reached,
      --  The deadline the caller set has passed. Reported, never enforced.

      Failed);
      --  The connection ended. The cause is in Failure_Of.

   function Image (Item : Event_Kind) return String;

   --  How many events one step can produce. A step is one Advance or one
   --  operation, and there is a small fixed number of things that can be true
   --  after one; an unbounded list would be a place for a peer to make this
   --  endpoint allocate.
   Maximum_Events : constant := 12;

   type Event_Array is array (1 .. Maximum_Events) of Event_Kind;

   type Event_List is record
      Count  : Natural range 0 .. Maximum_Events := 0;
      Events : Event_Array := [others => Failed];
   end record;

   function Is_Empty (Item : Event_List) return Boolean is (Item.Count = 0);

   function Contains (Item : Event_List; Kind : Event_Kind) return Boolean;

   --  What an engine's current state amounts to, as events.
   --
   --  Derived from the engine rather than accumulated in it, so that asking
   --  twice gives the same answer and asking never loses anything. An engine
   --  that queued events would need somewhere to put the ones nobody drained.
   --  @param Item the engine
   --  @return the events true of it now, in a stable order
   function Current (Item : Engine) return Event_List;

end SSL.Engines.Events;
