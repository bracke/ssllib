with SSL.Blocking;

package body SSL.Synchronized_Connections is

   ---------------------------------------------------------------------------
   --  The two protected objects
   ---------------------------------------------------------------------------

   protected body Exclusion is

      entry Acquire when Free is
      begin
         Free := False;
      end Acquire;

      procedure Release is
      begin
         Free := True;
      end Release;

   end Exclusion;

   protected body Requests is

      procedure Ask_Shutdown is
      begin
         Shutdown := True;
      end Ask_Shutdown;

      procedure Ask_Cancel is
      begin
         Cancelled := True;
      end Ask_Cancel;

      function Shutdown_Asked return Boolean is (Shutdown);
      function Cancel_Asked return Boolean is (Cancelled);

      procedure Take_Cancel (Present : out Boolean) is
      begin
         Present := Cancelled and then not Delivered;
         if Present then
            Delivered := True;
         end if;
      end Take_Cancel;

   end Requests;

   ---------------------------------------------------------------------------
   --  Holding the lock for one step
   ---------------------------------------------------------------------------

   --  Everything below follows one shape: acquire, do exactly one bounded
   --  thing, release. The release is not in a handler because nothing called
   --  between them propagates -- `SSL.Connections` catches a transport's
   --  exceptions at its own boundary and answers with a structured failure,
   --  which is the whole reason that boundary exists.

   --  Carry out whatever the controller has asked for. Called with the lock
   --  held, at the start of every step, so that a request made while a task was
   --  waiting takes effect at the first opportunity rather than at the end.
   procedure Apply_Requests (Item : in out Synchronized_Connection);

   procedure Apply_Requests (Item : in out Synchronized_Connection) is
      Present : Boolean;
      Ignored : SSL.Errors.Error_Information;
   begin
      Item.Asked.Take_Cancel (Present);
      if Present then
         SSL.Cancellation.Cancel (Item.Reason);
         SSL.Connections.Cancel (Item.Base, Item.Reason);
      end if;

      if Item.Asked.Shutdown_Asked
        and then not SSL.Connections.Is_Terminal (Item.Base)
        and then SSL.Connections.Is_Established (Item.Base)
      then
         SSL.Connections.Begin_Shutdown (Item.Base, Ignored);
      end if;
   end Apply_Requests;

   ---------------------------------------------------------------------------
   --  Starting one
   ---------------------------------------------------------------------------

   procedure Connect
     (Item     : in out Synchronized_Connection;
      Config   : not null access constant SSL.Configurations.Client_Configuration;
      Medium   : not null SSL.Transports.Transport_Reference;
      Identity : Connection_ID;
      Now      : SSL.Clocks.Wall_Time;
      Error    : out SSL.Errors.Error_Information)
   is
   begin
      Item.Lock.Acquire;
      SSL.Connections.Connect (Item.Base, Config, Medium, Identity, Now, Error);
      Item.Lock.Release;
   end Connect;

   procedure Accept_Connection
     (Item     : in out Synchronized_Connection;
      Config   : not null access constant SSL.Configurations.Server_Configuration;
      Medium   : not null SSL.Transports.Transport_Reference;
      Identity : Connection_ID;
      Now      : SSL.Clocks.Wall_Time;
      Error    : out SSL.Errors.Error_Information)
   is
   begin
      Item.Lock.Acquire;
      SSL.Connections.Accept_Connection
        (Item.Base, Config, Medium, Identity, Now, Error);
      Item.Lock.Release;
   end Accept_Connection;

   procedure Handshake
     (Item  : in out Synchronized_Connection;
      Expires : SSL.Clocks.Deadline;
      Error : out SSL.Errors.Error_Information)
   is
   begin
      Item.Lock.Acquire;
      SSL.Blocking.Handshake (Item.Base, Expires, Error);
      Item.Lock.Release;
   end Handshake;

   ---------------------------------------------------------------------------
   --  The reader
   ---------------------------------------------------------------------------

   procedure Read
     (Item  : in out Synchronized_Connection;
      Into  : out Byte_Array;
      Count : out Byte_Index;
      Expires : SSL.Clocks.Deadline;
      Error : out SSL.Errors.Error_Information)
   is
      Finished : Boolean := False;
   begin
      Into := [others => 0];
      Count := 0;
      Error := SSL.Errors.No_Error;

      loop
         Item.Lock.Acquire;

         Apply_Requests (Item);

         declare
            Moved : Boolean;
            Local : SSL.Errors.Error_Information;
         begin
            SSL.Connections.Read_Available (Item.Base, Into, Count, Local);

            if SSL.Errors.Is_Error (Local) then
               Error := Local;
               Finished := True;

            elsif Count > 0 then
               Finished := True;

            elsif SSL.Connections.Is_Terminal (Item.Base) then
               --  The peer closed, or the connection failed. Either way there
               --  is nothing more to wait for, and the failure -- if there was
               --  one -- is the connection's own.
               Error := SSL.Connections.Failure_Of (Item.Base);
               Finished := True;

            else
               SSL.Connections.Step (Item.Base, Moved, Local);
               if SSL.Errors.Is_Error (Local) then
                  Error := Local;
                  Finished := True;
               else
                  SSL.Connections.Read_Available (Item.Base, Into, Count, Local);
                  if SSL.Errors.Is_Error (Local) then
                     Error := Local;
                     Finished := True;
                  elsif Count > 0 then
                     Finished := True;
                  end if;
               end if;
            end if;
         end;

         Item.Lock.Release;

         exit when Finished;

         --  The deadline is checked outside the lock, so that a task that has
         --  run out of time releases the driver before it stops rather than
         --  after.
         exit when SSL.Clocks.Has_Expired (Expires, SSL.Clocks.Current_Monotonic);

         --  And the sleep is outside the lock too, which is the only reason
         --  the writer gets a turn at all.
         delay Poll_Interval;
      end loop;
   end Read;

   ---------------------------------------------------------------------------
   --  The writer
   ---------------------------------------------------------------------------

   procedure Write
     (Item    : in out Synchronized_Connection;
      Data    : Byte_Array;
      Written : out Byte_Index;
      Expires : SSL.Clocks.Deadline;
      Error   : out SSL.Errors.Error_Information)
   is
      Cursor   : Byte_Index := Data'First;
      Finished : Boolean := False;
   begin
      Written := 0;
      Error := SSL.Errors.No_Error;

      if Data'Length = 0 then
         return;
      end if;

      loop
         Item.Lock.Acquire;

         Apply_Requests (Item);

         declare
            Taken : Byte_Index;
            Moved : Boolean;
            Local : SSL.Errors.Error_Information;
         begin
            if SSL.Connections.Is_Terminal (Item.Base) then
               Error := SSL.Connections.Failure_Of (Item.Base);
               Finished := True;

            else
               SSL.Connections.Write_Available
                 (Item.Base, Data (Cursor .. Data'Last), Taken, Local);
               if SSL.Errors.Is_Error (Local) then
                  Error := Local;
                  Finished := True;
               else
                  Cursor := Cursor + Taken;
                  Written := Written + Taken;

                  --  Pushed out before the lock is released, because octets
                  --  sitting in the output queue of a connection nobody is
                  --  stepping are octets the peer never sees.
                  SSL.Connections.Step (Item.Base, Moved, Local);
                  if SSL.Errors.Is_Error (Local) then
                     Error := Local;
                     Finished := True;
                  elsif Cursor > Data'Last then
                     Finished := True;
                  end if;
               end if;
            end if;
         end;

         Item.Lock.Release;

         exit when Finished;
         exit when SSL.Clocks.Has_Expired (Expires, SSL.Clocks.Current_Monotonic);

         delay Poll_Interval;
      end loop;
   end Write;

   ---------------------------------------------------------------------------
   --  The controller
   ---------------------------------------------------------------------------

   procedure Request_Shutdown (Item : in out Synchronized_Connection) is
   begin
      Item.Asked.Ask_Shutdown;
   end Request_Shutdown;

   procedure Cancel (Item : in out Synchronized_Connection) is
   begin
      Item.Asked.Ask_Cancel;
   end Cancel;

   function Shutdown_Requested (Item : Synchronized_Connection) return Boolean is
     (Item.Asked.Shutdown_Asked);

   function Cancel_Requested (Item : Synchronized_Connection) return Boolean is
     (Item.Asked.Cancel_Asked);

   procedure Close
     (Item  : in out Synchronized_Connection;
      Expires : SSL.Clocks.Deadline;
      Error : out SSL.Errors.Error_Information)
   is
   begin
      Item.Lock.Acquire;
      Apply_Requests (Item);
      SSL.Blocking.Shutdown (Item.Base, Expires, Error, Await_Peer => True);
      Item.Lock.Release;
   end Close;

   ---------------------------------------------------------------------------
   --  Asking about it
   ---------------------------------------------------------------------------

   function State_Of (Item : in out Synchronized_Connection)
     return SSL.Engines.Lifecycle
   is
      Answer : SSL.Engines.Lifecycle;
   begin
      Item.Lock.Acquire;
      Answer := SSL.Connections.State_Of (Item.Base);
      Item.Lock.Release;
      return Answer;
   end State_Of;

   function Is_Established (Item : in out Synchronized_Connection) return Boolean is
      Answer : Boolean;
   begin
      Item.Lock.Acquire;
      Answer := SSL.Connections.Is_Established (Item.Base);
      Item.Lock.Release;
      return Answer;
   end Is_Established;

   function Is_Terminal (Item : in out Synchronized_Connection) return Boolean is
      Answer : Boolean;
   begin
      Item.Lock.Acquire;
      Answer := SSL.Connections.Is_Terminal (Item.Base);
      Item.Lock.Release;
      return Answer;
   end Is_Terminal;

   function Metadata_Of (Item : in out Synchronized_Connection)
     return SSL.Connection_Metadata.Metadata
   is
      Answer : SSL.Connection_Metadata.Metadata;
   begin
      Item.Lock.Acquire;
      Answer := SSL.Connections.Metadata_Of (Item.Base);
      Item.Lock.Release;
      return Answer;
   end Metadata_Of;

   function Failure_Of (Item : in out Synchronized_Connection)
     return SSL.Errors.Error_Information
   is
      Answer : SSL.Errors.Error_Information;
   begin
      Item.Lock.Acquire;
      Answer := SSL.Connections.Failure_Of (Item.Base);
      Item.Lock.Release;
      return Answer;
   end Failure_Of;

   procedure Wipe (Item : in out Synchronized_Connection) is
   begin
      Item.Lock.Acquire;
      SSL.Connections.Wipe (Item.Base);
      Item.Lock.Release;
   end Wipe;

end SSL.Synchronized_Connections;
