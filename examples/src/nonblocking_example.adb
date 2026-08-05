with Ada.Text_IO;

with SSL;
with SSL.Clients;
with SSL.Configurations;
with SSL.Connections;
with SSL.Credentials;
with SSL.Engines;
with SSL.Engines.Events;
with SSL.Errors;
with SSL.Servers;
with SSL.Trust;

with Example_Support;

--  Driving a connection the way an application with its own event loop would:
--  ask what it is waiting for, do that, come back.
--
--  The transport here refuses every other read, which is what a non-blocking
--  socket does when its receive buffer is empty. An application that could not
--  cope with that could not use a real socket, so the example makes it happen.
procedure Nonblocking_Example is

   use type SSL.Byte_Index;
   use type SSL.Engines.Lifecycle;

   package Events renames SSL.Engines.Events;

   --  All the long-lived objects live in Example_Support, at library level;
   --  see the comment there for why that is a rule and not a convenience.
   Client : SSL.Connections.Connection;
   Server : SSL.Connections.Connection;
   Error  : SSL.Errors.Error_Information;

   --  What a real event loop would do with the answer: register the
   --  connection's file descriptor for reading, for writing, or both, and come
   --  back when the operating system says so. Here it just says what it would
   --  have waited for.
   procedure Describe (Label : String; Item : SSL.Connections.Connection);

   procedure Describe (Label : String; Item : SSL.Connections.Connection) is
      Status : constant SSL.Engines.Readiness := SSL.Connections.Ready (Item);
      What   : constant Events.Event_List := SSL.Connections.Events (Item);
   begin
      Ada.Text_IO.Put (Label & ": ");
      if Status.Wants_Transport_Write then
         Ada.Text_IO.Put ("wants to write; ");
      end if;
      if Status.Wants_Transport_Read then
         Ada.Text_IO.Put ("wants to read; ");
      end if;
      if Status.Has_Plaintext then
         Ada.Text_IO.Put ("has data; ");
      end if;
      for Index in 1 .. What.Count loop
         Ada.Text_IO.Put (Events.Image (What.Events (Index)) & "; ");
      end loop;
      Ada.Text_IO.New_Line;
   end Describe;

begin
   Example_Support.Connect_Pipes;

   --  Half the reads will report Would_Block. Nothing about the code below
   --  changes to accommodate that, which is the point.
   Example_Support.Set_Stalling (Example_Support.Client_Medium, True);
   Example_Support.Set_Stalling (Example_Support.Server_Medium, True);

   Example_Support.Load_Fixtures
     (Example_Support.Anchors, Example_Support.Credential,
      Example_Support.Example_Time, Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("loading the certificate", Error);
      return;
   end if;

   Example_Support.Build_Client
     (Example_Support.Client_Policy, Example_Support.Anchors'Access, Error);
   Example_Support.Build_Server
     (Example_Support.Server_Policy, Example_Support.Credential'Access, Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("building the policies", Error);
      return;
   end if;

   SSL.Servers.Accept_Connection
     (Server, Example_Support.Server_Policy'Access, Example_Support.Server_Medium'Access,
      Now => Example_Support.Example_Time, Error => Error);
   SSL.Clients.Connect
     (Client, Example_Support.Client_Policy'Access, Example_Support.Client_Medium'Access,
      Now => Example_Support.Example_Time, Error => Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("starting the connections", Error);
      return;
   end if;

   Describe ("client, before anything", Client);
   Describe ("server, before anything", Server);

   --  The loop. A real one would block in `select` or `epoll_wait` between
   --  iterations; this one simply goes round again, because there is nothing
   --  to wait on when both ends are in the same process.
   declare
      Moved  : Boolean;
      Rounds : Natural := 0;
   begin
      loop
         Rounds := Rounds + 1;
         if Rounds > 1_000 then
            Ada.Text_IO.Put_Line ("the handshake did not converge");
            return;
         end if;

         SSL.Connections.Step (Client, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            Example_Support.Report ("the client", Error);
            return;
         end if;

         SSL.Connections.Step (Server, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            Example_Support.Report ("the server", Error);
            return;
         end if;

         exit when SSL.Connections.Is_Established (Client)
           and then SSL.Connections.Is_Established (Server);
      end loop;

      Ada.Text_IO.Put_Line
        ("established after" & Natural'Image (Rounds)
         & " turns round the loop, with half the reads refused");
   end;

   Describe ("client, established", Client);
   Describe ("server, established", Server);

   SSL.Connections.Wipe (Client);
   SSL.Connections.Wipe (Server);
end Nonblocking_Example;
