with Ada.Real_Time;

with SSL.Engines;

package body SSL.Blocking is

   package Connections renames SSL.Connections;

   use type SSL.Engines.Lifecycle;

   --  Wait the retry interval. A plain delay, because this library has no idea
   --  what a transport is made of and therefore nothing to select on.
   procedure Pause;

   procedure Pause is
      use Ada.Real_Time;
   begin
      delay until Clock + Milliseconds (Retry_Interval_Milliseconds);
   end Pause;

   --  Has the deadline passed? A deadline that was never set never passes,
   --  which is the caller having said they will wait indefinitely.
   function Expired (Until_At : SSL.Clocks.Deadline) return Boolean is
     (SSL.Clocks.Is_Set (Until_At)
      and then SSL.Clocks.Has_Expired (Until_At, SSL.Clocks.Current_Monotonic));

   function Timed_Out return SSL.Errors.Error_Information is
     (SSL.Errors.Make (SSL.Errors.Code_Deadline_Reached, SSL.Errors.Caller_Request));

   ------------------------
   -- Handshake --
   ------------------------

   procedure Handshake
     (Item     : in out SSL.Connections.Connection;
      Until_At : SSL.Clocks.Deadline;
      Error    : out SSL.Errors.Error_Information)
   is
      Progress : Boolean;
   begin
      Error := SSL.Errors.No_Error;
      Connections.Set_Deadline (Item, Until_At);

      loop
         if Connections.Is_Established (Item) then
            return;
         end if;
         if Connections.Is_Terminal (Item) then
            Error := Connections.Failure_Of (Item);
            return;
         end if;
         if Expired (Until_At) then
            Error := Timed_Out;
            return;
         end if;

         Connections.Step (Item, Progress, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;

         if not Progress then
            Pause;
         end if;
      end loop;
   end Handshake;

   ------------------------
   -- Read_Some --
   ------------------------

   procedure Read_Some
     (Item     : in out SSL.Connections.Connection;
      Into     : out Byte_Array;
      Count    : out Byte_Index;
      Until_At : SSL.Clocks.Deadline;
      Error    : out SSL.Errors.Error_Information)
   is
      Progress : Boolean;
      Local    : SSL.Errors.Error_Information;
   begin
      Into := [others => 0];
      Count := 0;
      Error := SSL.Errors.No_Error;
      Connections.Set_Deadline (Item, Until_At);

      loop
         Connections.Read_Available (Item, Into, Count, Local);
         if Count > 0 then
            --  Data in hand. A failure alongside it is reported next time: the
            --  octets were authenticated before whatever went wrong, and
            --  discarding them would lose data the peer really sent.
            return;
         end if;

         if Connections.Peer_Closed (Item) then
            --  A clean end of stream. Zero and no failure, which is what a
            --  caller loop tests for.
            return;
         end if;
         if Connections.Is_Terminal (Item) then
            Error := Connections.Failure_Of (Item);
            return;
         end if;
         if Expired (Until_At) then
            Error := Timed_Out;
            return;
         end if;

         Connections.Step (Item, Progress, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;

         if not Progress then
            Pause;
         end if;
      end loop;
   end Read_Some;

   ---------------------------
   -- Read_Exactly --
   ---------------------------

   procedure Read_Exactly
     (Item     : in out SSL.Connections.Connection;
      Into     : out Byte_Array;
      Until_At : SSL.Clocks.Deadline;
      Error    : out SSL.Errors.Error_Information)
   is
      Filled : Byte_Index := 0;
   begin
      Into := [others => 0];
      Error := SSL.Errors.No_Error;

      while Filled < Into'Length loop
         declare
            Chunk : Byte_Array (1 .. Into'Length - Filled) := [others => 0];
            Count : Byte_Index;
         begin
            Read_Some (Item, Chunk, Count, Until_At, Error);
            if SSL.Errors.Is_Error (Error) then
               return;
            end if;

            if Count = 0 then
               --  The peer closed with the request unfinished. Unlike
               --  Read_Some, that is a failure here: a caller that asked for a
               --  fixed number of octets and got fewer holds an incomplete
               --  structure, and calling that success is how a truncation
               --  becomes a parse of half a message.
               Error := SSL.Errors.Make
                 (SSL.Errors.Code_Transport_Truncated, SSL.Errors.Caller_Transport);
               return;
            end if;

            Into (Into'First + Filled .. Into'First + Filled + Count - 1) :=
              Chunk (1 .. Count);
            Filled := Filled + Count;
         end;
      end loop;
   end Read_Exactly;

   -------------------------
   -- Write_Some --
   -------------------------

   procedure Write_Some
     (Item     : in out SSL.Connections.Connection;
      Data     : Byte_Array;
      Count    : out Byte_Index;
      Until_At : SSL.Clocks.Deadline;
      Error    : out SSL.Errors.Error_Information)
   is
      Progress : Boolean;
   begin
      Count := 0;
      Error := SSL.Errors.No_Error;
      Connections.Set_Deadline (Item, Until_At);

      if Data'Length = 0 then
         return;
      end if;

      loop
         Connections.Write_Available (Item, Data, Count, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;
         if Count > 0 then
            --  Accepted into the output queue. Getting it onto the transport is
            --  the next Step's business, and Write_All's problem rather than
            --  this one's.
            return;
         end if;

         if Connections.Is_Terminal (Item) then
            Error := Connections.Failure_Of (Item);
            return;
         end if;
         if Expired (Until_At) then
            Error := Timed_Out;
            return;
         end if;

         Connections.Step (Item, Progress, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;

         if not Progress then
            Pause;
         end if;
      end loop;
   end Write_Some;

   ------------------------
   -- Write_All --
   ------------------------

   procedure Write_All
     (Item     : in out SSL.Connections.Connection;
      Data     : Byte_Array;
      Until_At : SSL.Clocks.Deadline;
      Error    : out SSL.Errors.Error_Information)
   is
      Cursor   : Byte_Index := Data'First;
      Count    : Byte_Index;
      Progress : Boolean;
   begin
      Error := SSL.Errors.No_Error;

      while Cursor <= Data'Last loop
         Write_Some (Item, Data (Cursor .. Data'Last), Count, Until_At, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;
         Cursor := Cursor + Count;
      end loop;

      --  Drain. Returning while octets are still queued would leave them in a
      --  buffer the application has no reason to know exists, and a caller that
      --  then closed the transport would truncate its own message.
      loop
         exit when Connections.Ready (Item).Wants_Transport_Write = False;

         if Connections.Is_Terminal (Item) then
            Error := Connections.Failure_Of (Item);
            return;
         end if;
         if Expired (Until_At) then
            Error := Timed_Out;
            return;
         end if;

         Connections.Step (Item, Progress, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;

         if not Progress then
            Pause;
         end if;
      end loop;
   end Write_All;

   ----------------------
   -- Shutdown --
   ----------------------

   procedure Shutdown
     (Item       : in out SSL.Connections.Connection;
      Until_At   : SSL.Clocks.Deadline;
      Error      : out SSL.Errors.Error_Information;
      Await_Peer : Boolean := True)
   is
      Progress : Boolean;
      Ignored  : Byte_Array (1 .. 1) := [others => 0];
      Count    : Byte_Index;
      Local    : SSL.Errors.Error_Information;
   begin
      Error := SSL.Errors.No_Error;
      Connections.Set_Deadline (Item, Until_At);

      if Connections.Is_Terminal (Item) then
         return;
      end if;

      Connections.Begin_Shutdown (Item, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      loop
         if Connections.State_Of (Item) = SSL.Engines.Closed then
            return;
         end if;
         if Connections.Is_Terminal (Item) then
            Error := Connections.Failure_Of (Item);
            return;
         end if;
         if Expired (Until_At) then
            Error := Timed_Out;
            return;
         end if;

         if not Await_Peer
           and then not Connections.Ready (Item).Wants_Transport_Write
         then
            --  This endpoint's close_notify has left. The caller said they do
            --  not need the peer's, which is right when the application
            --  protocol has framing of its own.
            return;
         end if;

         Connections.Step (Item, Progress, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;

         --  Drain anything the peer sent before its own close_notify. Data that
         --  arrives during a shutdown is data the application asked to stop
         --  reading, and discarding it here is what lets the close complete.
         Connections.Read_Available (Item, Ignored, Count, Local);

         if not Progress and then Count = 0 then
            Pause;
         end if;
      end loop;
   end Shutdown;

end SSL.Blocking;
