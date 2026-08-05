with Ada.Text_IO;

with SSL;
with SSL.Clients;
with SSL.Connection_Metadata;
with SSL.Configurations;
with SSL.Connections;
with SSL.Credentials;
with SSL.Errors;
with SSL.Servers;
with SSL.Trust;

with Example_Support;

--  A TLS 1.3 connection from end to end: secure defaults, the server's identity
--  verified against the name the client asked for, application data in both
--  directions, and an orderly shutdown.
--
--  The transport is a pair of in-memory buffers so that this runs anywhere. Swap
--  it for one around a socket and nothing else changes.
procedure Handshake_Example is

   use type SSL.Byte_Array;
   use type SSL.Byte_Index;

   package Meta renames SSL.Connection_Metadata;

   --  The anchors, the credential, the two policies and the two transports all
   --  live in Example_Support, at library level. That is the lifetime
   --  obligation made visible: a connection holds a reference to its
   --  configuration, which holds one to its trust snapshot, and each must
   --  outlive what points at it. Declaring them here -- inside a subprogram --
   --  fails an accessibility check at run time, immediately and loudly, which
   --  is the language enforcing the rule rather than trusting anyone to
   --  remember it.
   Client : SSL.Connections.Connection;
   Server : SSL.Connections.Connection;
   Error  : SSL.Errors.Error_Information;
begin
   Example_Support.Connect_Pipes;

   Example_Support.Load_Fixtures
     (Example_Support.Anchors, Example_Support.Credential,
      Example_Support.Example_Time, Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("loading the certificate", Error);
      return;
   end if;

   Example_Support.Build_Client
     (Example_Support.Client_Policy, Example_Support.Anchors'Access, Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("building the client policy", Error);
      return;
   end if;

   Example_Support.Build_Server
     (Example_Support.Server_Policy, Example_Support.Credential'Access, Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("building the server policy", Error);
      return;
   end if;

   --  The server first: it says nothing until it hears a ClientHello, so
   --  starting it costs nothing and having it ready avoids an ordering
   --  question that does not exist in a real deployment.
   SSL.Servers.Accept_Connection
     (Item   => Server,
      Config => Example_Support.Server_Policy'Access,
      Medium => Example_Support.Server_Medium'Access,
      Now    => Example_Support.Example_Time,
      Error  => Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("starting the server", Error);
      return;
   end if;

   SSL.Clients.Connect
     (Item   => Client,
      Config => Example_Support.Client_Policy'Access,
      Medium => Example_Support.Client_Medium'Access,
      Now    => Example_Support.Example_Time,
      Error  => Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("starting the client", Error);
      return;
   end if;

   Example_Support.Run_Handshake (Client, Server, Error);
   if SSL.Errors.Is_Error (Error) then
      --  Everything that can go wrong here is a structured failure with a code
      --  and a category, not an exception and not a return of -1.
      Example_Support.Report ("the handshake", Error);
      return;
   end if;

   Ada.Text_IO.Put_Line
     ("client sees: " & Meta.Image (SSL.Connections.Metadata_Of (Client)));
   Ada.Text_IO.Put_Line
     ("server sees: " & Meta.Image (SSL.Connections.Metadata_Of (Server)));

   --  Application data. The client's request reaches the server, and the
   --  server's answer reaches the client.
   declare
      Request  : constant SSL.Byte_Array := [1 .. 11 => 16#41#];
      Answer   : constant SSL.Byte_Array := [1 .. 5 => 16#42#];
      Landed   : SSL.Byte_Array (1 .. 256) := [others => 0];
      Count    : SSL.Byte_Index;
      Accepted : SSL.Byte_Index;
   begin
      SSL.Connections.Write_Available (Client, Request, Accepted, Error);
      if SSL.Errors.Is_Error (Error) then
         Example_Support.Report ("writing the request", Error);
         return;
      end if;

      Example_Support.Deliver (Client, Server, Landed, Count, Error);
      if SSL.Errors.Is_Error (Error) then
         Example_Support.Report ("delivering the request", Error);
         return;
      end if;
      Ada.Text_IO.Put_Line
        ("server received" & SSL.Byte_Index'Image (Count) & " octets, intact: "
         & Boolean'Image (Landed (1 .. Count) = Request));

      SSL.Connections.Write_Available (Server, Answer, Accepted, Error);
      Example_Support.Deliver (Server, Client, Landed, Count, Error);
      if SSL.Errors.Is_Error (Error) then
         Example_Support.Report ("delivering the answer", Error);
         return;
      end if;
      Ada.Text_IO.Put_Line
        ("client received" & SSL.Byte_Index'Image (Count) & " octets, intact: "
         & Boolean'Image (Landed (1 .. Count) = Answer));
   end;

   --  An orderly shutdown. The close_notify has to actually leave before the
   --  connection is closed, which is why this is a request followed by a step
   --  rather than a single call that pretends the octets have gone.
   declare
      Moved : Boolean;
   begin
      SSL.Connections.Begin_Shutdown (Client, Error);
      if SSL.Errors.Is_Error (Error) then
         Example_Support.Report ("beginning the shutdown", Error);
         return;
      end if;

      for Round in 1 .. 100 loop
         SSL.Connections.Step (Client, Moved, Error);
         SSL.Connections.Step (Server, Moved, Error);
         exit when SSL.Connections.Peer_Closed (Server);
      end loop;

      Ada.Text_IO.Put_Line
        ("server saw a clean close: "
         & Boolean'Image (SSL.Connections.Peer_Closed (Server)
                          and then not SSL.Connections.Was_Truncated (Server)));
   end;

   SSL.Connections.Wipe (Client);
   SSL.Connections.Wipe (Server);
end Handshake_Example;
