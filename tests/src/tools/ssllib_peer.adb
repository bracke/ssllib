with Ada.Command_Line;
with Ada.Directories;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;

with GNAT.Sockets;

with SSL;
with SSL.ALPN;
with SSL.Cipher_Suites;
with SSL.Blocking;
with SSL.Clients;
with SSL.Clocks;
with SSL.Configurations;
with SSL.Connection_Metadata;
with SSL.Connections;
with SSL.Credentials;
with SSL.Errors;
with SSL.Limits;
with SSL.Server_Names;
with SSL.Servers;
with SSL.Supported_Groups;
with SSL.Transports;
with SSL.Trust;
with SSL.Versions;

with SSLLib_Peer_State;

--  A command-line peer, so that another implementation can be pointed at this
--  one and this one at it.
--
--  This exists only for interoperability testing and lives in the test crate.
--  It is the one place in the repository that opens a socket, and it does so
--  through `GNAT.Sockets` -- the Ada standard library, in a test executable.
--  The runtime library still does no input or output of any kind: this program
--  writes a `SSL.Transports.Transport` around a socket exactly as an
--  application would, which is also the point of having it.
--
--  What it prints is the negotiated outcome, one fact per line, in a form a
--  controller can compare against what it asked for. A peer that printed only
--  "connected" would let a stack that quietly fell back to an older version, or
--  agreed no application protocol, look like success.
--
--  Usage:
--    ssllib_peer client <port> <ca-pem-file> <expected-name> [alpn] [tls12]
--    ssllib_peer server <port> <cert-pem-file> <key-pem-file> [marker] [tls12]
--
--  `tls12` anywhere in the arguments selects restricted TLS 1.2 instead of
--  TLS 1.3, so that an interoperability run can prove the TLS 1.2 path rather
--  than a TLS 1.3 one that happened to be selected.
procedure SSLLib_Peer is

   package IO renames Ada.Text_IO;
   package Sockets renames GNAT.Sockets;

   use type SSL.Byte_Index;

   Usage_Status  : constant := 2;
   Failure_Status : constant := 1;

   --  A transport over a connected stream socket. Twenty lines, which is the
   --  claim `SSL.Transports` makes about what it costs to attach this library
   --  to something real.
   type Socket_Transport is limited new SSL.Transports.Transport with record
      Peer   : Sockets.Socket_Type := Sockets.No_Socket;
      Closed : Boolean := False;
   end record;

   overriding procedure Receive
     (Item   : in out Socket_Transport;
      Into   : out SSL.Byte_Array;
      Count  : out SSL.Byte_Index;
      Status : out SSL.Transports.Transport_Status);

   overriding procedure Send
     (Item   : in out Socket_Transport;
      Data   : SSL.Byte_Array;
      Count  : out SSL.Byte_Index;
      Status : out SSL.Transports.Transport_Status);

   overriding function Description (Item : Socket_Transport) return String;

   overriding procedure Receive
     (Item   : in out Socket_Transport;
      Into   : out SSL.Byte_Array;
      Count  : out SSL.Byte_Index;
      Status : out SSL.Transports.Transport_Status)
   is
      Last : Ada.Streams.Stream_Element_Offset;
   begin
      Into := [others => 0];
      Count := 0;

      if Item.Closed then
         Status := SSL.Transports.End_Of_Stream;
         return;
      end if;

      Sockets.Receive_Socket (Item.Peer, Into, Last);

      if Last < Into'First then
         --  A zero-length read on a stream socket is the peer having closed.
         Item.Closed := True;
         Status := SSL.Transports.End_Of_Stream;
         return;
      end if;

      Count := SSL.Byte_Index (Last - Into'First + 1);
      Status := SSL.Transports.Ok;
   exception
      when Sockets.Socket_Error =>
         --  Converted rather than propagated: the library's own boundary would
         --  catch it, but reporting it here keeps the transport's contract --
         --  "return a status" -- true rather than nearly true.
         Status := SSL.Transports.Failed;
   end Receive;

   overriding procedure Send
     (Item   : in out Socket_Transport;
      Data   : SSL.Byte_Array;
      Count  : out SSL.Byte_Index;
      Status : out SSL.Transports.Transport_Status)
   is
      Last : Ada.Streams.Stream_Element_Offset;
   begin
      Count := 0;

      if Item.Closed then
         Status := SSL.Transports.End_Of_Stream;
         return;
      end if;

      Sockets.Send_Socket (Item.Peer, Data, Last);
      Count := SSL.Byte_Index (Last - Data'First + 1);
      Status := SSL.Transports.Ok;
   exception
      when Sockets.Socket_Error =>
         Status := SSL.Transports.Failed;
   end Send;

   overriding function Description (Item : Socket_Transport) return String is
     ("loopback socket" & (if Item.Closed then " (closed)" else ""));

   --  Read a whole file. Small by construction -- a certificate or a key -- so
   --  a bounded read is enough and there is nothing to stream.
   function Read_File (Path : String) return String;

   function Read_File (Path : String) return String is
      Handle : IO.File_Type;
      Buffer : String (1 .. 65_536);
      Used   : Natural := 0;
   begin
      IO.Open (Handle, IO.In_File, Path);
      while not IO.End_Of_File (Handle) and then Used < Buffer'Last loop
         declare
            Line : constant String := IO.Get_Line (Handle);
         begin
            exit when Used + Line'Length + 1 > Buffer'Last;
            Buffer (Used + 1 .. Used + Line'Length) := Line;
            Used := Used + Line'Length;
            Used := Used + 1;
            Buffer (Used) := ASCII.LF;
         end;
      end loop;
      IO.Close (Handle);
      return Buffer (1 .. Used);
   exception
      when others =>
         if IO.Is_Open (Handle) then
            IO.Close (Handle);
         end if;
         return "";
   end Read_File;

   --  Where a launched peer writes what it would have printed.
   --
   --  A controller that launches this and returns has no pipe to read, so
   --  standard output reaches nobody. Everything printed is also written here
   --  when a path is given, which is what lets a failure say what the peer
   --  actually did rather than only that it never became ready.
   Transcript_Path : Ada.Strings.Unbounded.Unbounded_String;

   procedure Say (Line : String);

   procedure Say (Line : String) is
      use Ada.Strings.Unbounded;
   begin
      --  The file first, and the console second inside a handler.
      --
      --  A peer a controller *launched* rather than ran has no standard output
      --  anybody holds open, and writing to a closed one raises. Doing it first
      --  killed this program before it could record anything, which made every
      --  failure look like "it never became ready" whatever had actually
      --  happened.
      if Transcript_Path /= Null_Unbounded_String then
         declare
            Handle : IO.File_Type;
            Path   : constant String := To_String (Transcript_Path);
         begin
            if Ada.Directories.Exists (Path) then
               IO.Open (Handle, IO.Append_File, Path);
            else
               IO.Create (Handle, IO.Out_File, Path);
            end if;
            IO.Put_Line (Handle, Line);
            IO.Close (Handle);
         exception
            when others =>
               null;
         end;
      end if;

      begin
         IO.Put_Line (Line);
         IO.Flush;
      exception
         when others =>
            null;
      end;
   end Say;

   --  Print what was actually negotiated, one fact per line. A controller
   --  compares these against what it asked for; "connected" alone would let a
   --  silent downgrade pass.
   procedure Report (Item : SSL.Connections.Connection);

   procedure Report (Item : SSL.Connections.Connection) is
      package Meta renames SSL.Connection_Metadata;
      Facts : constant Meta.Metadata := SSL.Connections.Metadata_Of (Item);
   begin
      if not Meta.Is_Established (Facts) then
         Say ("established=no");
         return;
      end if;

      Say ("established=yes");
      Say ("version=" & SSL.Versions.Image (Meta.Version (Facts)));
      Say ("suite=" & SSL.Cipher_Suites.Image (Meta.Cipher_Suite (Facts)));
      Say ("group=" & SSL.Supported_Groups.Image (Meta.Group (Facts)));
      if Meta.Has_Protocol (Facts) then
         Say ("protocol=" & SSL.ALPN.Image (Meta.Protocol (Facts)));
      else
         Say ("protocol=-");
      end if;
      Say ("peer="
           & (if Meta.Peer_Authenticated (Facts) then "authenticated" else "anonymous"));
      Say ("resumed=" & (if Meta.Resumed (Facts) then "yes" else "no"));
   end Report;

   --  The long-lived objects live in SSLLib_Peer_State, at library level; see
   --  the comment there for why that is a rule and not a convenience.
   Anchors      : SSL.Trust.Snapshot renames SSLLib_Peer_State.Anchors;
   Credential   : SSL.Credentials.Credential renames SSLLib_Peer_State.Credential;
   Client_Setup : SSL.Configurations.Client_Configuration
     renames SSLLib_Peer_State.Client_Setup;
   Server_Setup : SSL.Configurations.Server_Configuration
     renames SSLLib_Peer_State.Server_Setup;

   Medium : aliased Socket_Transport;

   Error : SSL.Errors.Error_Information;
   Ok    : Boolean;

   --  Restricted TLS 1.2 rather than TLS 1.3, selected by the literal word
   --  `tls12` anywhere in the arguments.
   Restricted_Legacy : Boolean := False;

   --  A client credential, for proving that this end holds a key when a server
   --  asks. Given as `clientcert=<path>` and `clientkey=<path>` anywhere in the
   --  arguments; absent means this client declines a request, which is the
   --  conforming answer and a different thing to test.
   Client_Cert_Path : Ada.Strings.Unbounded.Unbounded_String;
   Client_Key_Path  : Ada.Strings.Unbounded.Unbounded_String;
begin
   --  Scanned rather than positional, because the two roles already differ in
   --  what their fourth and fifth arguments mean and a sixth with two meanings
   --  would be one more thing to get wrong at a call site.
   for Index in 1 .. Ada.Command_Line.Argument_Count loop
      declare
         Argument : constant String := Ada.Command_Line.Argument (Index);
      begin
         if Argument = "tls12" then
            Restricted_Legacy := True;

         elsif Argument'Length > 11
           and then Argument (Argument'First .. Argument'First + 10) = "clientcert="
         then
            Client_Cert_Path := Ada.Strings.Unbounded.To_Unbounded_String
              (Argument (Argument'First + 11 .. Argument'Last));

         elsif Argument'Length > 10
           and then Argument (Argument'First .. Argument'First + 9) = "clientkey="
         then
            Client_Key_Path := Ada.Strings.Unbounded.To_Unbounded_String
              (Argument (Argument'First + 10 .. Argument'Last));
         end if;
      end;
   end loop;

   if Ada.Command_Line.Argument_Count < 4 then
      IO.Put_Line ("usage: ssllib_peer client <port> <ca-pem> <expected-name> [alpn]");
      IO.Put_Line ("       ssllib_peer server <port> <cert-pem> <key-pem> [alpn]");
      Ada.Command_Line.Set_Exit_Status (Usage_Status);
      return;
   end if;

   --  No `Sockets.Initialize`: GNAT declares it obsolescent, the runtime does
   --  it itself, and calling it is a warning under the switches this repository
   --  builds with.

   --  A launched peer has no pipe anybody reads, so everything it says also
   --  goes beside the marker it was given.
   if Ada.Command_Line.Argument_Count >= 5 then
      Transcript_Path :=
        Ada.Strings.Unbounded.To_Unbounded_String
          (Ada.Command_Line.Argument (5) & ".log");
   end if;

   declare
      Role : constant String := Ada.Command_Line.Argument (1);
      Port : constant Sockets.Port_Type :=
        Sockets.Port_Type'Value (Ada.Command_Line.Argument (2));
      Now  : constant SSL.Clocks.Wall_Time := SSL.Clocks.Current_UTC;
   begin
      if Role = "client" then
         declare
            Trust_PEM : constant String := Read_File (Ada.Command_Line.Argument (3));
            Expected  : constant String := Ada.Command_Line.Argument (4);
            Address   : Sockets.Sock_Addr_Type;
            Builder   : SSL.Configurations.Client_Builder;
            Item      : SSL.Connections.Connection;
         begin
            if Trust_PEM = "" then
               Say ("error=cannot read the trust anchors");
               Ada.Command_Line.Set_Exit_Status (Failure_Status);
               return;
            end if;

            SSL.Trust.Load_Explicit_Anchors
              (Anchors, Trust_PEM, Now, SSL.Limits.Default_Limits, Error);
            if SSL.Errors.Is_Error (Error) then
               Say ("error=" & SSL.Errors.Image (Error));
               Ada.Command_Line.Set_Exit_Status (Failure_Status);
               return;
            end if;

            if Restricted_Legacy then
               --  Restricted TLS 1.2 and nothing else, so that what is proved
               --  is the TLS 1.2 path rather than a TLS 1.3 one that happened
               --  to be selected.
               SSL.Configurations.Modern_Compatibility_Client (Builder);
               SSL.Configurations.Set_Versions
                 (Builder, SSL.Versions.Only (SSL.Versions.TLS_1_2), Ok);
            else
               SSL.Configurations.Secure_Client_Defaults (Builder);
            end if;
            SSL.Configurations.Set_Expected_Name
              (Builder, SSL.Server_Names.Name (Expected), Ok => Ok);
            SSL.Configurations.Set_Anchors (Builder, SSLLib_Peer_State.Anchors'Access, Ok);

            if Ada.Strings.Unbounded.Length (Client_Cert_Path) > 0
              and then Ada.Strings.Unbounded.Length (Client_Key_Path) > 0
            then
               SSL.Credentials.Load_PEM
                 (SSLLib_Peer_State.Client_Credential,
                  Read_File (Ada.Strings.Unbounded.To_String (Client_Cert_Path)),
                  Read_File (Ada.Strings.Unbounded.To_String (Client_Key_Path)),
                  SSL.Limits.Default_Limits, Error);
               if SSL.Errors.Is_Error (Error) then
                  Say ("error=" & SSL.Errors.Image (Error));
                  Ada.Command_Line.Set_Exit_Status (Failure_Status);
                  return;
               end if;

               SSL.Configurations.Set_Client_Credential
                 (Builder, SSLLib_Peer_State.Client_Credential'Access, Ok);
               if not Ok then
                  Say ("error=the client credential was refused");
                  Ada.Command_Line.Set_Exit_Status (Failure_Status);
                  return;
               end if;
            end if;
            SSL.Configurations.Build (Builder, Client_Setup, Error);
            if SSL.Errors.Is_Error (Error) then
               Say ("error=" & SSL.Errors.Image (Error));
               Ada.Command_Line.Set_Exit_Status (Failure_Status);
               return;
            end if;

            --  Loopback only. No name resolution, no outside address, nothing a
            --  firewall or a proxy could be doing.
            Address :=
              (Family => Sockets.Family_Inet,
               Addr   => Sockets.Loopback_Inet_Addr,
               Port   => Port);

            --  Retry briefly. A client started at the same moment as its server
            --  races the server's bind, and a refused connection in that window
            --  is a race rather than a failure -- so it is retried rather than
            --  reported, and reported only once the window has closed. Fifteen
            --  seconds, because one of the servers this is pointed at is a Java
            --  program compiled from source at every run.
            declare
               Connected : Boolean := False;
            begin
               for Attempt in 1 .. 150 loop
                  begin
                     Sockets.Create_Socket (Medium.Peer);
                     Sockets.Connect_Socket (Medium.Peer, Address);
                     Connected := True;
                     exit;
                  exception
                     when Sockets.Socket_Error =>
                        Sockets.Close_Socket (Medium.Peer);
                        delay 0.1;
                  end;
               end loop;

               if not Connected then
                  Say ("established=no");
                  Say ("error=cannot connect to the loopback port");
                  Ada.Command_Line.Set_Exit_Status (Failure_Status);
                  return;
               end if;
            end;

            SSL.Clients.Connect
              (Item   => Item,
               Config => SSLLib_Peer_State.Client_Setup'Access,
               Medium => Medium'Unchecked_Access,
               Now    => Now,
               Error  => Error);
            if not SSL.Errors.Is_Error (Error) then
               SSL.Blocking.Handshake
                 (Item, SSL.Clocks.In_Milliseconds (10_000), Error);
            end if;

            if SSL.Errors.Is_Error (Error) then
               Say ("established=no");
               Say ("error=" & SSL.Errors.Image (Error));
               Ada.Command_Line.Set_Exit_Status (Failure_Status);
            else
               Report (Item);

               declare
                  Closing : SSL.Errors.Error_Information;
               begin
                  SSL.Blocking.Shutdown
                    (Item, SSL.Clocks.In_Milliseconds (5_000), Closing,
                     Await_Peer => False);
               end;
            end if;

            SSL.Connections.Wipe (Item);
            Sockets.Close_Socket (Medium.Peer);
         end;

      elsif Role = "server" then
         declare
            Certificate : constant String := Read_File (Ada.Command_Line.Argument (3));
            Private_Key : constant String := Read_File (Ada.Command_Line.Argument (4));
            Listener    : Sockets.Socket_Type;
            Address     : Sockets.Sock_Addr_Type;
            Builder     : SSL.Configurations.Server_Builder;
            Item        : SSL.Connections.Connection;
         begin
            if Certificate = "" or else Private_Key = "" then
               Say ("error=cannot read the credential");
               Ada.Command_Line.Set_Exit_Status (Failure_Status);
               return;
            end if;

            SSL.Credentials.Load_PEM
              (Credential, Certificate, Private_Key,
               SSL.Limits.Default_Limits, Error);
            if SSL.Errors.Is_Error (Error) then
               Say ("error=" & SSL.Errors.Image (Error));
               Ada.Command_Line.Set_Exit_Status (Failure_Status);
               return;
            end if;

            if Restricted_Legacy then
               SSL.Configurations.Modern_Compatibility_Server (Builder);
               SSL.Configurations.Set_Versions
                 (Builder, SSL.Versions.Only (SSL.Versions.TLS_1_2), Ok);
            else
               SSL.Configurations.Secure_Server_Defaults (Builder);
            end if;
            SSL.Configurations.Add_Credential (Builder, SSLLib_Peer_State.Credential'Access, Ok);
            SSL.Configurations.Build (Builder, Server_Setup, Error);
            if SSL.Errors.Is_Error (Error) then
               Say ("error=" & SSL.Errors.Image (Error));
               Ada.Command_Line.Set_Exit_Status (Failure_Status);
               return;
            end if;

            --  Bind reported rather than raised. A port already in use is an
            --  ordinary thing to meet -- another run, a straggler, something
            --  else on the machine -- and a controller reading a crash dump
            --  learns much less from it than from a line saying so.
            begin
               Sockets.Create_Socket (Listener);
               Sockets.Set_Socket_Option
                 (Listener, Sockets.Socket_Level, (Sockets.Reuse_Address, True));
               Address :=
                 (Family => Sockets.Family_Inet,
                  Addr   => Sockets.Loopback_Inet_Addr,
                  Port   => Port);
               Sockets.Bind_Socket (Listener, Address);
               Sockets.Listen_Socket (Listener, 1);
            exception
               when Sockets.Socket_Error =>
                  Say ("established=no");
                  Say ("error=cannot bind the loopback port");
                  Ada.Command_Line.Set_Exit_Status (Failure_Status);
                  return;
            end;

            --  Ready, and said so on standard output so that a controller can
            --  wait for the line rather than sleeping and hoping.
            Say ("listening");

            --  And in a file, when a fifth argument names one, so that a
            --  controller can wait for a real readiness signal rather than
            --  sleeping for a while and hoping. Standard output is not enough:
            --  a controller that launched this and then read its pipe would be
            --  waiting on a process it also has to outlive.
            if Ada.Command_Line.Argument_Count >= 5 then
               declare
                  Marker : IO.File_Type;
               begin
                  IO.Create (Marker, IO.Out_File, Ada.Command_Line.Argument (5));
                  IO.Put_Line (Marker, "listening");
                  IO.Close (Marker);
               exception
                  when others =>
                     null;
               end;
            end if;

            Sockets.Accept_Socket (Listener, Medium.Peer, Address);

            SSL.Servers.Accept_Connection
              (Item   => Item,
               Config => SSLLib_Peer_State.Server_Setup'Access,
               Medium => Medium'Unchecked_Access,
               Now    => Now,
               Error  => Error);
            if not SSL.Errors.Is_Error (Error) then
               SSL.Blocking.Handshake
                 (Item, SSL.Clocks.In_Milliseconds (10_000), Error);
            end if;

            if SSL.Errors.Is_Error (Error) then
               Say ("established=no");
               Say ("error=" & SSL.Errors.Image (Error));
               Ada.Command_Line.Set_Exit_Status (Failure_Status);
            else
               Report (Item);

               --  An orderly shutdown, not just a closed socket. A peer that
               --  dropped the connection without a close_notify would look to
               --  the other end exactly like a truncation attack -- and every
               --  correct implementation reports it as one, which is how this
               --  omission was found.
               declare
                  Closing : SSL.Errors.Error_Information;
               begin
                  SSL.Blocking.Shutdown
                    (Item, SSL.Clocks.In_Milliseconds (5_000), Closing,
                     Await_Peer => False);
               end;
            end if;

            SSL.Connections.Wipe (Item);
            Sockets.Close_Socket (Medium.Peer);
            Sockets.Close_Socket (Listener);
         end;

      else
         IO.Put_Line ("usage: ssllib_peer client|server ...");
         Ada.Command_Line.Set_Exit_Status (Usage_Status);
      end if;
   end;
end SSLLib_Peer;
