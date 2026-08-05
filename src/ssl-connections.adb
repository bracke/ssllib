package body SSL.Connections is

   use type SSL.Transports.Transport_Status;
   use type SSL.Transports.Transport_Reference;

   --  The current monotonic time, taken once per operation. Deadlines are
   --  monotonic and certificate validity is wall-clock, and the two are never
   --  substituted for one another: a system whose wall clock moves must not
   --  thereby change when a read gives up.
   function Tick return SSL.Clocks.Monotonic_Time is (SSL.Clocks.Current_Monotonic);

   ------------------
   -- Connect --
   ------------------

   procedure Connect
     (Item     : in out Connection;
      Config   : not null access constant SSL.Configurations.Client_Configuration;
      Medium   : not null SSL.Transports.Transport_Reference;
      Identity : Connection_ID;
      Now      : SSL.Clocks.Wall_Time;
      Error    : out SSL.Errors.Error_Information)
   is
   begin
      Item.Medium := Medium;
      Item.Ident := Identity;
      SSL.Engines.Start_Client (Item.Driver, Config, Identity, Now, Error);
   end Connect;

   ----------------------------
   -- Accept_Connection --
   ----------------------------

   procedure Accept_Connection
     (Item     : in out Connection;
      Config   : not null access constant SSL.Configurations.Server_Configuration;
      Medium   : not null SSL.Transports.Transport_Reference;
      Identity : Connection_ID;
      Now      : SSL.Clocks.Wall_Time;
      Error    : out SSL.Errors.Error_Information)
   is
   begin
      Item.Medium := Medium;
      Item.Ident := Identity;
      SSL.Engines.Start_Server (Item.Driver, Config, Identity, Now, Error);
   end Accept_Connection;

   ---------------------------------------------------------------------------
   --  Moving octets
   ---------------------------------------------------------------------------

   procedure Pump_Input
     (Item   : in out Connection;
      Status : out SSL.Transports.Transport_Status;
      Error  : out SSL.Errors.Error_Information)
   is
      Chunk    : Byte_Array (1 .. Read_Chunk) := [others => 0];
      Count    : Byte_Index;
      Consumed : Byte_Index;
      Local    : SSL.Errors.Error_Information;
   begin
      Status := SSL.Transports.Would_Block;
      Error := SSL.Errors.No_Error;

      if Item.Medium = null then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Transport_Not_Set, SSL.Errors.Caller_Request);
         return;
      end if;

      if Is_Terminal (Item) then
         Status := SSL.Transports.Failed;
         Error := Failure_Of (Item);
         return;
      end if;

      SSL.Transports.Receive_Safely (Item.Medium.all, Chunk, Count, Status, Local);

      case Status is
         when SSL.Transports.Ok =>
            if Count = 0 then
               --  Ok with nothing read is a transport saying nothing happened,
               --  which is Would_Block by another name. Reported as what it is,
               --  so a caller looping on Ok does not spin.
               Status := SSL.Transports.Would_Block;
               return;
            end if;

            SSL.Engines.Supply_Encrypted (Item.Driver, Chunk (1 .. Count), Consumed, Error);
            if SSL.Errors.Is_Error (Error) then
               return;
            end if;
            SSL.Engines.Advance (Item.Driver, Tick, Error);

         when SSL.Transports.End_Of_Stream =>
            SSL.Engines.Report_End_Of_Stream (Item.Driver, Error);

         when SSL.Transports.Failed =>
            SSL.Engines.Report_Transport_Failure
              (Item.Driver,
               (if SSL.Errors.Is_Error (Local)
                then SSL.Errors.Provider_Text (Local)
                else Item.Medium.all.Description));
            Error := Failure_Of (Item);

         when SSL.Transports.Would_Block
            | SSL.Transports.Interrupted
            | SSL.Transports.Timed_Out =>
            --  Nothing moved and nothing is wrong. The connection is untouched
            --  and the caller decides whether to wait, retry or give up.
            null;
      end case;
   end Pump_Input;

   procedure Pump_Output
     (Item   : in out Connection;
      Status : out SSL.Transports.Transport_Status;
      Error  : out SSL.Errors.Error_Information)
   is
      Chunk : Byte_Array (1 .. Read_Chunk) := [others => 0];
      Have  : Byte_Index;
      Took  : Byte_Index;
      Local : SSL.Errors.Error_Information;
   begin
      Status := SSL.Transports.Would_Block;
      Error := SSL.Errors.No_Error;

      if Item.Medium = null then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Transport_Not_Set, SSL.Errors.Caller_Request);
         return;
      end if;

      if SSL.Engines.Pending_Encrypted (Item.Driver) = 0 then
         Status := SSL.Transports.Ok;
         return;
      end if;

      SSL.Engines.Peek_Encrypted (Item.Driver, Chunk, Have);
      if Have = 0 then
         Status := SSL.Transports.Ok;
         return;
      end if;

      SSL.Transports.Send_Safely (Item.Medium.all, Chunk (1 .. Have), Took, Status, Local);

      case Status is
         when SSL.Transports.Ok =>
            --  A partial write is normal and is not an error. Only what the
            --  transport actually took is dropped; the rest stays queued and
            --  goes out on the next call.
            SSL.Engines.Consume_Encrypted (Item.Driver, Took);

         when SSL.Transports.Failed =>
            SSL.Engines.Report_Transport_Failure
              (Item.Driver,
               (if SSL.Errors.Is_Error (Local)
                then SSL.Errors.Provider_Text (Local)
                else Item.Medium.all.Description));
            Error := Failure_Of (Item);

         when SSL.Transports.End_Of_Stream =>
            --  The peer closed while this endpoint still had octets to send.
            --  Whether that is orderly is decided by whether a close_notify
            --  arrived, which the engine knows and this does not.
            SSL.Engines.Report_End_Of_Stream (Item.Driver, Error);

         when SSL.Transports.Would_Block
            | SSL.Transports.Interrupted
            | SSL.Transports.Timed_Out =>
            null;
      end case;
   end Pump_Output;

   ---------------
   -- Step --
   ---------------

   procedure Step
     (Item     : in out Connection;
      Progress : out Boolean;
      Error    : out SSL.Errors.Error_Information)
   is
      Before : constant Byte_Index := SSL.Engines.Pending_Encrypted (Item.Driver);
      Held   : constant Byte_Index := SSL.Engines.Pending_Plaintext (Item.Driver);
      Status : SSL.Transports.Transport_Status;
   begin
      Progress := False;
      Error := SSL.Errors.No_Error;

      --  Output first. A peer waiting on this endpoint's flight sends nothing
      --  until it arrives, so an implementation that read first would deadlock
      --  against another doing the same.
      if Before > 0 then
         Pump_Output (Item, Status, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;
         Progress := SSL.Engines.Pending_Encrypted (Item.Driver) /= Before;
      end if;

      if Is_Terminal (Item) then
         return;
      end if;

      Pump_Input (Item, Status, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      Progress := Progress
        or else Status = SSL.Transports.Ok
        or else SSL.Engines.Pending_Plaintext (Item.Driver) /= Held
        or else SSL.Engines.Pending_Encrypted (Item.Driver) > 0;
   end Step;

   ---------------------------------------------------------------------------
   --  Application data
   ---------------------------------------------------------------------------

   procedure Read_Available
     (Item  : in out Connection;
      Into  : out Byte_Array;
      Count : out Byte_Index;
      Error : out SSL.Errors.Error_Information)
   is
   begin
      Into := [others => 0];
      Count := 0;
      Error := SSL.Errors.No_Error;

      SSL.Engines.Peek_Plaintext (Item.Driver, Into, Count);
      if Count > 0 then
         SSL.Engines.Consume_Plaintext (Item.Driver, Count);
         return;
      end if;

      --  Nothing to hand over. Whether that is temporary or final is the
      --  difference between an empty read and a closed connection, and the
      --  caller needs to be able to tell.
      if Is_Terminal (Item) then
         Error := Failure_Of (Item);
      elsif Peer_Closed (Item) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Read_After_Peer_Close, SSL.Errors.Caller_Request);
      end if;
   end Read_Available;

   procedure Write_Available
     (Item     : in out Connection;
      Data     : Byte_Array;
      Accepted : out Byte_Index;
      Error    : out SSL.Errors.Error_Information)
   is
   begin
      SSL.Engines.Write_Plaintext (Item.Driver, Data, Accepted, Error);
   end Write_Available;

   ---------------------------------------------------------------------------
   --  Post-handshake operations
   ---------------------------------------------------------------------------

   procedure Export_Keying_Material
     (Item        : Connection;
      Label       : String;
      Context     : Byte_Array;
      Has_Context : Boolean;
      Into        : out Byte_Array;
      Error       : out SSL.Errors.Error_Information)
   is
   begin
      SSL.Engines.Export_Keying_Material
        (Item.Driver, Label, Context, Has_Context, Into, Error);
   end Export_Keying_Material;

   procedure Request_Key_Update
     (Item     : in out Connection;
      Ask_Peer : Boolean;
      Error    : out SSL.Errors.Error_Information)
   is
   begin
      SSL.Engines.Request_Key_Update (Item.Driver, Ask_Peer, Error);
   end Request_Key_Update;

   ---------------------------------------------------------------------------
   --  Ending one
   ---------------------------------------------------------------------------

   procedure Begin_Shutdown
     (Item  : in out Connection;
      Error : out SSL.Errors.Error_Information)
   is
   begin
      SSL.Engines.Begin_Shutdown (Item.Driver, Error);
   end Begin_Shutdown;

   procedure Cancel (Item : in out Connection; Reason : SSL.Cancellation.Token) is
   begin
      SSL.Engines.Cancel (Item.Driver, Reason);
   end Cancel;

   procedure Set_Deadline (Item : in out Connection; Value : SSL.Clocks.Deadline) is
   begin
      SSL.Engines.Set_Deadline (Item.Driver, Value);
   end Set_Deadline;

   procedure Wipe (Item : in out Connection) is
   begin
      SSL.Engines.Wipe (Item.Driver);
   end Wipe;

end SSL.Connections;
