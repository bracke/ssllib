with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Text_IO;

with Hostkit;
with Hostkit.FS;
with Hostkit.Process;

package body SSLLib_Interop is

   package IO renames Ada.Text_IO;

   package String_Vectors renames Hostkit.String_Vectors;

   --  One helper so that every argument list reads as the command line it is,
   --  rather than as a run of conversions.
   procedure Add (Into : in out String_Vectors.Vector; Value : String);

   procedure Add (Into : in out String_Vectors.Vector; Value : String) is
   begin
      Into.Append (Ada.Strings.Unbounded.To_Unbounded_String (Value));
   end Add;

   --  A port as text, without the leading space 'Image puts on a non-negative
   --  number.
   function Port_Text (Value : Natural) return String;

   function Port_Text (Value : Natural) return String is
      Text : constant String := Natural'Image (Value);
   begin
      return Text (Text'First + 1 .. Text'Last);
   end Port_Text;

   ---------------
   -- Image --
   ---------------

   function Image (Item : External_Stack) return String is
     (case Item is
         when OpenSSL      => "openssl",
         when GnuTLS       => "gnutls",
         when LibreSSL     => "libressl",
         when BoringSSL    => "boringssl",
         when Java_Keytool => "java");

   function Image (Item : Direction) return String is
     (case Item is
         when Ours_As_Client => "ssllib client -> external server",
         when Ours_As_Server => "external client -> ssllib server");

   function Image (Item : Profile) return String is
     (case Item is
         when Modern            => "tls1.3",
         when Restricted_Legacy => "tls1.2");

   function Image (Item : Outcome) return String is
     (case Item is
         when Passed     => "pass",
         when Skipped    => "skip",
         when Refused    => "REFUSED",
         when Mismatched => "MISMATCHED");

   --  The program that drives each stack. Locating first and running second is
   --  deliberate: a spawn that cannot resolve a name fails in a way that looks
   --  exactly like a program that ran and returned non-zero, and the two need
   --  different reports.
   --
   --  LibreSSL is located under its own name rather than as `openssl`, because
   --  on a host where both are installed the one on the path is whichever was
   --  installed last, and a matrix that reported LibreSSL results obtained from
   --  OpenSSL would be worse than one that reported nothing.
   function Program_Of (Item : External_Stack) return String is
     (case Item is
         when OpenSSL      => "openssl",
         when GnuTLS       => "gnutls-cli",
         when LibreSSL     => "libressl",
         when BoringSSL    => "bssl",
         when Java_Keytool => "java");

   --  Presence is decided by locating the program, not by running it. Running
   --  something to find out whether it exists is how a test suite ends up
   --  executing whatever happens to be on the path under that name.

   --  Whether a driver has been written for a stack at all.
   --
   --  A stack with no driver is reported as skipped with a reason that says so,
   --  rather than as a pass for a handshake that never ran. BoringSSL's `bssl`
   --  has a command line of its own that nobody here has been able to exercise,
   --  and a driver written from documentation and never run is a driver that
   --  claims coverage it does not have.
   function Has_Driver (Item : External_Stack) return Boolean is
     (case Item is
         when OpenSSL | GnuTLS | LibreSSL | Java_Keytool => True,
         when BoringSSL                                  => False);

   ---------------------------------------------------------------------------
   --  Driving one stack
   ---------------------------------------------------------------------------

   --  Ports high enough that two runs on one machine do not collide, fixed
   --  rather than random so that a failure is reproducible, and four apart per
   --  stack so that a straggler from one stack's run cannot be mistaken for
   --  another's server. Loopback only, always.
   Base_Port : constant := 14_640;

   function Server_Port (Item : External_Stack; Which : Profile) return Natural is
     (Base_Port + 4 * External_Stack'Pos (Item) + 2 * Profile'Pos (Which));
   --  Where the *external* stack listens, with `ssllib` connecting to it.

   function Client_Port (Item : External_Stack; Which : Profile) return Natural is
     (Base_Port + 4 * External_Stack'Pos (Item) + 2 * Profile'Pos (Which) + 1);
   --  Where `ssllib` listens, with the external stack connecting to it.

   --  A directory per stack and profile, so that two runs' credentials and logs
   --  cannot be confused for one another when a run is being read afterwards.
   function Folder_Of (Item : External_Stack; Which : Profile) return String is
     (Hostkit.FS.Temp_Directory & "/ssllib-interop-" & Image (Item)
      & "-" & Image (Which));

   --  Cancellation for an external server that has no "stop after one
   --  connection" of its own.
   --
   --  `openssl s_server` has `-naccept 1` and stops by itself; `gnutls-serv`
   --  does not, and a controller that left it running would leave a listening
   --  socket behind on every run. So the run is cancelled once the direction it
   --  was started for has been decided.
   Stop_External : Boolean := False
     with Volatile;

   function External_Cancelled return Boolean;

   function External_Cancelled return Boolean is (Stop_External);

   --  Read the peer's report and decide whether it is what was asked for.
   --
   --  The whole reason a peer prints facts rather than "connected": a stack
   --  that fell back to TLS 1.2, or agreed no application protocol, or skipped
   --  verification would all have exited zero.
   function Judge (Report_Path : String; Which : Profile) return Outcome;

   function Judge (Report_Path : String; Which : Profile) return Outcome is
      Handle        : IO.File_Type;
      Established   : Boolean := False;
      Right_Version : Boolean := False;
   begin
      begin
         IO.Open (Handle, IO.In_File, Report_Path);
      exception
         when others =>
            return Refused;
      end;

      while not IO.End_Of_File (Handle) loop
         declare
            Line : constant String := IO.Get_Line (Handle);
         begin
            if Line = "established=yes" then
               Established := True;
            elsif Line = (if Which = Modern then "version=tls1.3" else "version=tls1.2")
            then
               Right_Version := True;
            end if;
         end;
      end loop;
      IO.Close (Handle);

      if not Established then
         return Refused;
      end if;

      --  A handshake that completed under the wrong version is the outcome a
      --  socket-success check would have called a pass.
      if not Right_Version then
         return Mismatched;
      end if;

      return Passed;
   end Judge;

   --  Whether a file contains a piece of text.
   --
   --  Used to hold an external client to the same standard the peer is held to:
   --  its exit status says the handshake completed, and this says it completed
   --  under the version that was demanded.
   function File_Contains (Path : String; Needle : String) return Boolean;

   function File_Contains (Path : String; Needle : String) return Boolean is
      use Ada.Strings.Fixed;
      Handle : IO.File_Type;
      Found  : Boolean := False;
   begin
      begin
         IO.Open (Handle, IO.In_File, Path);
      exception
         when others =>
            return False;
      end;

      while not IO.End_Of_File (Handle) loop
         if Index (IO.Get_Line (Handle), Needle) > 0 then
            Found := True;
         end if;
      end loop;
      IO.Close (Handle);
      return Found;
   end File_Contains;

   --  Print a captured file into the report, one prefixed line at a time.
   --
   --  A report that says a command failed without saying what it said asks its
   --  reader to reproduce the failure before they can start on it.
   procedure Echo (Path : String; Prefix : String);

   procedure Echo (Path : String; Prefix : String) is
      Handle : IO.File_Type;
   begin
      if not Ada.Directories.Exists (Path) then
         return;
      end if;

      IO.Open (Handle, IO.In_File, Path);
      while not IO.End_Of_File (Handle) loop
         IO.Put_Line ("        " & Prefix & ": " & IO.Get_Line (Handle));
      end loop;
      IO.Close (Handle);
   exception
      when others =>
         null;
   end Echo;

   --  Print the command a failure came from.
   procedure Echo_Command (Program : String; Arguments : String_Vectors.Vector);

   procedure Echo_Command
     (Program : String; Arguments : String_Vectors.Vector)
   is
      Line : Ada.Strings.Unbounded.Unbounded_String :=
        Ada.Strings.Unbounded.To_Unbounded_String ("        ran: " & Program);
   begin
      for Argument of Arguments loop
         Ada.Strings.Unbounded.Append
           (Line, " " & Ada.Strings.Unbounded.To_String (Argument));
      end loop;
      IO.Put_Line (Ada.Strings.Unbounded.To_String (Line));
   end Echo_Command;

   ---------------------------------------------------------------------------
   --  Generating a credential
   ---------------------------------------------------------------------------

   --  Generate a credential for one run, in a directory of its own.
   --
   --  Generated with an external tool rather than committed, because a
   --  committed certificate expires and an interop suite that starts failing on
   --  a date nobody chose is an interop suite people stop believing.
   --
   --  `ssllib` deliberately cannot do this itself: it has no certificate
   --  issuance, by design, and adding some so that its own test suite could
   --  generate credentials would be adding a feature to satisfy a test.
   function Make_Credential (Folder : String) return Boolean;

   function Make_Credential_With_OpenSSL (Folder : String) return Boolean;

   function Make_Credential_With_OpenSSL (Folder : String) return Boolean is
      Arguments : String_Vectors.Vector;
      Program   : constant String := Hostkit.Process.Locate ("openssl");
   begin
      if Program = "" then
         return False;
      end if;

      Add (Arguments, "req");
      Add (Arguments, "-x509");
      Add (Arguments, "-newkey");
      Add (Arguments, "ed25519");
      Add (Arguments, "-nodes");
      Add (Arguments, "-keyout");
      Add (Arguments, Folder & "/key.pem");
      Add (Arguments, "-out");
      Add (Arguments, Folder & "/cert.pem");
      Add (Arguments, "-days");
      Add (Arguments, "2");
      Add (Arguments, "-subj");
      Add (Arguments, "/CN=www.example.com");
      Add (Arguments, "-addext");
      Add (Arguments, "subjectAltName=DNS:www.example.com");

      --  Its output goes to a file rather than to this report: `openssl req`
      --  prints progress dots, and a matrix with them in it is a matrix nobody
      --  can read.
      declare
         Result : constant Hostkit.Process.Process_Outcome :=
           Hostkit.Process.Run_Captured
             (Program     => Program,
              Arguments   => Arguments,
              Stdout_Path => Folder & "/issue.log",
              Stderr_Path => Folder & "/issue.log",
              Timeout_Ms  => 20_000);
      begin
         return Result.Started
           and then not Result.Timed_Out
           and then Result.Exit_Status = 0;
      end;
   end Make_Credential_With_OpenSSL;

   --  The same credential from GnuTLS's `certtool`, for a host that has GnuTLS
   --  and no OpenSSL. Two ways of issuing one certificate is not duplication
   --  worth avoiding: it is the difference between a matrix that runs on such a
   --  host and one that skips everything with "cannot generate a credential".
   function Make_Credential_With_Certtool (Folder : String) return Boolean;

   function Make_Credential_With_Certtool (Folder : String) return Boolean is
      Program : constant String := Hostkit.Process.Locate ("certtool");
   begin
      if Program = "" then
         return False;
      end if;

      declare
         Arguments : String_Vectors.Vector;
      begin
         Add (Arguments, "--generate-privkey");
         Add (Arguments, "--key-type=ed25519");
         Add (Arguments, "--outfile");
         Add (Arguments, Folder & "/key.pem");

         declare
            Result : constant Hostkit.Process.Process_Outcome :=
              Hostkit.Process.Run_Captured
                (Program     => Program,
                 Arguments   => Arguments,
                 Stdout_Path => Folder & "/issue.log",
                 Stderr_Path => Folder & "/issue.log",
                 Timeout_Ms  => 20_000);
         begin
            if not Result.Started
              or else Result.Timed_Out
              or else Result.Exit_Status /= 0
            then
               return False;
            end if;
         end;
      end;

      --  A template, because `certtool` asks its questions interactively
      --  otherwise, and a controller that answered them down a pipe would be a
      --  controller that hung the first time the questions changed.
      declare
         Template : IO.File_Type;
      begin
         IO.Create (Template, IO.Out_File, Folder & "/template.txt");
         IO.Put_Line (Template, "cn = ""www.example.com""");
         IO.Put_Line (Template, "dns_name = ""www.example.com""");
         IO.Put_Line (Template, "expiration_days = 2");
         IO.Put_Line (Template, "tls_www_server");
         IO.Put_Line (Template, "tls_www_client");
         IO.Put_Line (Template, "signing_key");
         IO.Put_Line (Template, "ca");
         IO.Close (Template);
      exception
         when others =>
            return False;
      end;

      declare
         Arguments : String_Vectors.Vector;
      begin
         Add (Arguments, "--generate-self-signed");
         Add (Arguments, "--load-privkey");
         Add (Arguments, Folder & "/key.pem");
         Add (Arguments, "--template");
         Add (Arguments, Folder & "/template.txt");
         Add (Arguments, "--outfile");
         Add (Arguments, Folder & "/cert.pem");

         declare
            Result : constant Hostkit.Process.Process_Outcome :=
              Hostkit.Process.Run_Captured
                (Program     => Program,
                 Arguments   => Arguments,
                 Stdout_Path => Folder & "/issue.log",
                 Stderr_Path => Folder & "/issue.log",
                 Timeout_Ms  => 20_000);
         begin
            return Result.Started
              and then not Result.Timed_Out
              and then Result.Exit_Status = 0;
         end;
      end;
   end Make_Credential_With_Certtool;

   function Make_Credential (Folder : String) return Boolean is
   begin
      if Make_Credential_With_OpenSSL (Folder) then
         return True;
      end if;

      return Make_Credential_With_Certtool (Folder);
   end Make_Credential;

   ---------------------------------------------------------------------------
   --  The two directions, once each
   ---------------------------------------------------------------------------

   --  `ssllib` as the client, against an external server.
   --
   --  The external server is run under a cancellable capture rather than
   --  launched and forgotten, so that a server with no "stop after one
   --  connection" of its own still stops. The `ssllib` peer retries its connect
   --  for a few seconds, which is what removes the need to guess how long the
   --  external server takes to bind.
   --  @param External  the external server program
   --  @param Arguments its command line, already carrying the port
   --  @param Folder    the run's directory
   --  @param Peer      the `ssllib` peer executable
   --  @param Port      the port the external server was told to listen on
   function Drive_Ours_As_Client
     (External  : String;
      Arguments : String_Vectors.Vector;
      Folder    : String;
      Peer      : String;
      Port      : Natural;
      Which     : Profile) return Outcome;

   function Drive_Ours_As_Client
     (External  : String;
      Arguments : String_Vectors.Vector;
      Folder    : String;
      Peer      : String;
      Port      : Natural;
      Which     : Profile) return Outcome
   is
      Report_Path      : constant String := Folder & "/client-report.txt";
      Server_Log       : constant String := Folder & "/external-server.log";
      Client_Arguments : String_Vectors.Vector;
      Verdict          : Outcome := Refused;
   begin
      if Peer = "" then
         return Skipped;
      end if;

      Stop_External := False;

      --  The run happens in the task's *statements*, not its declarations. A
      --  block does not execute its own first statement until every task it
      --  activates has finished elaborating its declarative part, so a
      --  Run_Captured in the declarative part would run the server to
      --  completion before this thread reached the line that drives the client.
      declare
         task Serve;

         task body Serve is
            Result : Hostkit.Process.Process_Outcome;
            pragma Unreferenced (Result);
         begin
            Result :=
              Hostkit.Process.Run_Captured
                (Program     => External,
                 Arguments   => Arguments,
                 Stdout_Path => Server_Log,
                 Stderr_Path => Server_Log,
                 Timeout_Ms  => 30_000,
                 Cancelled   => External_Cancelled'Access);
         end Serve;
      begin
         --  The credential is passed explicitly and the host's trust store is
         --  never consulted: an interop test that installed a root would be a
         --  test that changed the machine it ran on.
         Add (Client_Arguments, "client");
         Add (Client_Arguments, Port_Text (Port));
         Add (Client_Arguments, Folder & "/cert.pem");
         Add (Client_Arguments, "www.example.com");
         if Which = Restricted_Legacy then
            Add (Client_Arguments, "tls12");
         end if;

         --  Bounded: a peer that hangs must not hang the matrix.
         declare
            Result : constant Hostkit.Process.Process_Outcome :=
              Hostkit.Process.Run_Captured
                (Program     => Peer,
                 Arguments   => Client_Arguments,
                 Stdout_Path => Report_Path,
                 Stderr_Path => Report_Path,
                 Timeout_Ms  => 20_000);
         begin
            if not Result.Started or else Result.Timed_Out then
               Verdict := Refused;
            else
               Verdict := Judge (Report_Path, Which);
            end if;
         end;

         --  Decided, so the server can stop. Set before the block ends, since
         --  the block ends by waiting for the task that is running it.
         Stop_External := True;
      end;

      if Verdict /= Passed then
         Echo (Report_Path, "peer");
         Echo (Server_Log, "server");
      end if;

      return Verdict;
   end Drive_Ours_As_Client;

   --  An external client against an `ssllib` server.
   --
   --  @param External  the external client program
   --  @param Arguments its command line, already carrying the port
   --  @param Folder    the run's directory
   --  @param Peer      the `ssllib` peer executable
   --  @param Port      the port the `ssllib` server is told to listen on
   --  @param Version   text the client's own output must contain for the run to
   --                   count, so that a client which fell back to TLS 1.2 and
   --                   exited zero is not read as a pass
   function Drive_Ours_As_Server
     (External  : String;
      Arguments : String_Vectors.Vector;
      Folder    : String;
      Peer      : String;
      Port      : Natural;
      Version   : String;
      Which     : Profile) return Outcome;

   function Drive_Ours_As_Server
     (External  : String;
      Arguments : String_Vectors.Vector;
      Folder    : String;
      Peer      : String;
      Port      : Natural;
      Version   : String;
      Which     : Profile) return Outcome
   is
      Server_Arguments : String_Vectors.Vector;
      Report_Path      : constant String := Folder & "/server-report.txt";
      Peer_Log         : constant String := Folder & "/peer.log";
      Marker           : constant String := Folder & "/listening";
      Verdict          : Outcome := Refused;
   begin
      if Peer = "" then
         return Skipped;
      end if;

      --  An empty standard input for the external client, created before
      --  anything is launched so that its absence cannot be mistaken for a
      --  handshake failure. Without the redirect the client would inherit this
      --  program's own standard input and wait on it for ever.
      declare
         Empty : IO.File_Type;
      begin
         IO.Create (Empty, IO.Out_File, Folder & "/empty");
         IO.Close (Empty);
      exception
         when others =>
            return Skipped;
      end;

      Add (Server_Arguments, "server");
      Add (Server_Arguments, Port_Text (Port));
      Add (Server_Arguments, Folder & "/cert.pem");
      Add (Server_Arguments, Folder & "/key.pem");
      Add (Server_Arguments, Marker);
      if Which = Restricted_Legacy then
         Add (Server_Arguments, "tls12");
      end if;

      --  Removed first. A readiness signal that could be left over from an
      --  earlier run is not a readiness signal: it would be found immediately
      --  and the client would race a server that has not bound.
      begin
         if Ada.Directories.Exists (Marker) then
            Ada.Directories.Delete_File (Marker);
         end if;
      exception
         when others =>
            null;
      end;

      declare
         task Serve;

         task body Serve is
            Result : Hostkit.Process.Process_Outcome;
            pragma Unreferenced (Result);
         begin
            Result :=
              Hostkit.Process.Run_Captured
                (Program     => Peer,
                 Arguments   => Server_Arguments,
                 Stdout_Path => Peer_Log,
                 Stderr_Path => Peer_Log,
                 Timeout_Ms  => 30_000);
         end Serve;
      begin
         --  Wait for the marker the peer writes once it has bound. A real
         --  readiness signal rather than a delay long enough to probably work:
         --  the latter is slow when it is too long and flaky when it is too
         --  short.
         declare
            Ready : Boolean := False;
         begin
            for Attempt in 1 .. 100 loop
               pragma Unreferenced (Attempt);
               if Ada.Directories.Exists (Marker) then
                  Ready := True;
                  exit;
               end if;
               delay 0.05;
            end loop;

            if not Ready then
               IO.Put_Line
                 ("        the ssllib peer never reported that it was listening");
               Echo (Peer_Log, "peer");
               return Refused;
            end if;
         end;

         declare
            Result : constant Hostkit.Process.Process_Outcome :=
              Hostkit.Process.Run_Captured
                (Program     => External,
                 Arguments   => Arguments,
                 Stdin_Path  => Folder & "/empty",
                 Stdout_Path => Report_Path,
                 Stderr_Path => Report_Path,
                 Timeout_Ms  => 20_000);
         begin
            if not Result.Started then
               IO.Put_Line ("        the external client did not start");
               Verdict := Refused;

            elsif Result.Timed_Out then
               IO.Put_Line ("        the external client timed out");
               Verdict := Refused;

            elsif Result.Exit_Status /= 0 then
               --  Its exit status is the check. A socket that connected proves
               --  almost nothing; a client that verified the certificate and
               --  negotiated TLS 1.3 and then exited zero proves what was
               --  asked.
               IO.Put_Line
                 ("        the external client exited"
                  & Integer'Image (Result.Exit_Status));
               Verdict := Refused;

            elsif Version /= "" and then not File_Contains (Report_Path, Version)
            then
               --  Completed, under something else. The outcome a
               --  socket-success check would have called a pass.
               Verdict := Mismatched;

            else
               Verdict := Passed;
            end if;
         end;
      end;

      if Verdict /= Passed then
         Echo_Command (External, Arguments);
         Echo (Peer_Log, "peer");
         Echo (Report_Path, "client");
      end if;

      return Verdict;
   end Drive_Ours_As_Server;

   ---------------------------------------------------------------------------
   --  Per-stack command lines
   ---------------------------------------------------------------------------

   --  OpenSSL, and LibreSSL through the same command line.
   --
   --  `-tls1_3` is passed to OpenSSL and not to LibreSSL: LibreSSL's `openssl`
   --  has no such option, and the version it negotiated is checked from the
   --  reports either way, which is the stronger check of the two.
   procedure OpenSSL_Server_Command
     (Into      : in out String_Vectors.Vector;
      Folder    : String;
      Port      : Natural;
      Which     : Profile;
      Force_Version : Boolean);

   procedure OpenSSL_Server_Command
     (Into      : in out String_Vectors.Vector;
      Folder    : String;
      Port      : Natural;
      Which     : Profile;
      Force_Version : Boolean)
   is
   begin
      --  `-naccept 1` so the server stops on its own as well as on
      --  cancellation: two ways of stopping, because the one that depends on
      --  this controller still being alive is the one that leaves sockets
      --  behind when it is not.
      Add (Into, "s_server");
      Add (Into, "-accept");
      Add (Into, Port_Text (Port));
      Add (Into, "-cert");
      Add (Into, Folder & "/cert.pem");
      Add (Into, "-key");
      Add (Into, Folder & "/key.pem");
      if Force_Version then
         Add (Into, (if Which = Modern then "-tls1_3" else "-tls1_2"));
      end if;
      Add (Into, "-quiet");
      Add (Into, "-naccept");
      Add (Into, "1");
   end OpenSSL_Server_Command;

   procedure OpenSSL_Client_Command
     (Into      : in out String_Vectors.Vector;
      Folder    : String;
      Port      : Natural;
      Which     : Profile;
      Force_Version : Boolean);

   procedure OpenSSL_Client_Command
     (Into      : in out String_Vectors.Vector;
      Folder    : String;
      Port      : Natural;
      Which     : Profile;
      Force_Version : Boolean)
   is
   begin
      --  `-verify_return_error` is what makes this a real check: without it
      --  OpenSSL reports a verification failure and connects anyway, and the
      --  test would pass against a server presenting anything at all.
      Add (Into, "s_client");
      Add (Into, "-connect");
      Add (Into, "127.0.0.1:" & Port_Text (Port));
      Add (Into, "-CAfile");
      Add (Into, Folder & "/cert.pem");
      Add (Into, "-verify_return_error");
      if Force_Version then
         Add (Into, (if Which = Modern then "-tls1_3" else "-tls1_2"));
      end if;
      Add (Into, "-servername");
      Add (Into, "www.example.com");
      Add (Into, "-brief");
   end OpenSSL_Client_Command;

   --  GnuTLS.
   --
   --  One thing this does not get to control: `gnutls-serv` binds every
   --  interface, having no option to bind one. It is the only place in this
   --  controller where something other than loopback is listening, it lasts as
   --  long as one handshake, and it is written down here rather than left for
   --  somebody to discover.
   procedure GnuTLS_Server_Command
     (Into   : in out String_Vectors.Vector;
      Folder : String;
      Port   : Natural;
      Which  : Profile);

   procedure GnuTLS_Server_Command
     (Into   : in out String_Vectors.Vector;
      Folder : String;
      Port   : Natural;
      Which  : Profile)
   is
   begin
      Add (Into, "--x509certfile");
      Add (Into, Folder & "/cert.pem");
      Add (Into, "--x509keyfile");
      Add (Into, Folder & "/key.pem");
      Add (Into, "-p");
      Add (Into, Port_Text (Port));
      Add (Into, "--priority");
      Add (Into,
           (if Which = Modern
            then "NORMAL:-VERS-ALL:+VERS-TLS1.3"
            else "NORMAL:-VERS-ALL:+VERS-TLS1.2"));
   end GnuTLS_Server_Command;

   procedure GnuTLS_Client_Command
     (Into   : in out String_Vectors.Vector;
      Folder : String;
      Port   : Natural;
      Which  : Profile);

   procedure GnuTLS_Client_Command
     (Into   : in out String_Vectors.Vector;
      Folder : String;
      Port   : Natural;
      Which  : Profile)
   is
   begin
      --  The address is the loopback literal and the name is passed separately,
      --  so that the name is what gets verified and sent in SNI while nothing
      --  is ever resolved.
      Add (Into, "--x509cafile");
      Add (Into, Folder & "/cert.pem");
      Add (Into, "-p");
      Add (Into, Port_Text (Port));
      Add (Into, "--priority");
      Add (Into,
           (if Which = Modern
            then "NORMAL:-VERS-ALL:+VERS-TLS1.3"
            else "NORMAL:-VERS-ALL:+VERS-TLS1.2"));
      Add (Into, "--sni-hostname=www.example.com");
      Add (Into, "--verify-hostname=www.example.com");
      Add (Into, "127.0.0.1");
   end GnuTLS_Client_Command;

   ---------------------------------------------------------------------------
   --  Run_Matrix
   ---------------------------------------------------------------------------

   procedure Run_Matrix (Root : String; Succeeded : out Boolean) is
      --  Built by `ssllib_tools build`, so it is beside the other executables.
      Peer_Path : constant String := Root & "/tests/bin/ssllib_peer";

      --  Shipped in the repository and run from source, because the Java
      --  driver is a driver for an external stack rather than project tooling:
      --  nothing in this repository is built with it.
      Java_Source : constant String :=
        Root & "/tests/src/tools/java/SSLLibJavaPeer.java";

      Any_Failure : Boolean := False;
      Any_Present : Boolean := False;

      procedure Report
        (Stack  : External_Stack;
         Which  : Profile;
         Way    : Direction;
         Result : Outcome;
         Reason : String);

      procedure Report
        (Stack  : External_Stack;
         Which  : Profile;
         Way    : Direction;
         Result : Outcome;
         Reason : String)
      is
      begin
         IO.Put_Line
           ("  " & Image (Result) & "  " & Image (Stack) & " " & Image (Which)
            & ": " & Image (Way)
            & (if Reason = "" then "" else " -- " & Reason));

         if Result in Refused | Mismatched then
            Any_Failure := True;
         end if;
      end Report;

      --  The server side of a stack, which is not always the same program as
      --  its client side.
      function Server_Program_Of (Stack : External_Stack) return String;

      function Server_Program_Of (Stack : External_Stack) return String is
        (case Stack is
            when GnuTLS => Hostkit.Process.Locate ("gnutls-serv"),
            when others => Hostkit.Process.Locate (Program_Of (Stack)));

   begin
      IO.Put_Line ("ssllib_tools test-interop");

      for Stack in External_Stack loop
       for Which in Profile loop
         declare
            Located : constant String :=
              Hostkit.Process.Locate (Program_Of (Stack));
         begin
            if Located = "" then
               --  A stable skip reason, so that a report can be compared across
               --  machines and across time. "not installed" means exactly that
               --  and never anything else.
               Report (Stack, Which, Ours_As_Client, Skipped, "not installed");
               Report (Stack, Which, Ours_As_Server, Skipped, "not installed");

            elsif not Has_Driver (Stack) then
               Any_Present := True;
               Report (Stack, Which, Ours_As_Client, Skipped, "no driver for this stack");
               Report (Stack, Which, Ours_As_Server, Skipped, "no driver for this stack");

            elsif Stack = Java_Keytool
              and then not Ada.Directories.Exists (Java_Source)
            then
               Any_Present := True;
               Report (Stack, Which, Ours_As_Client, Skipped, "the Java driver is missing");
               Report (Stack, Which, Ours_As_Server, Skipped, "the Java driver is missing");

            else
               Any_Present := True;

               declare
                  Folder : constant String := Folder_Of (Stack, Which);
                  Server : constant String := Server_Program_Of (Stack);
               begin
                  --  A directory of its own per stack, removed first so that a
                  --  previous run's files cannot be read as this one's.
                  begin
                     if Ada.Directories.Exists (Folder) then
                        Ada.Directories.Delete_Tree (Folder);
                     end if;
                     Ada.Directories.Create_Path (Folder);
                  exception
                     when others =>
                        Report (Stack, Which, Ours_As_Client, Skipped,
                                "cannot create a temporary directory");
                        Report (Stack, Which, Ours_As_Server, Skipped,
                                "cannot create a temporary directory");
                        goto Continue;
                  end;

                  if not Make_Credential (Folder) then
                     Report (Stack, Which, Ours_As_Client, Skipped,
                             "no tool on this host could issue a credential");
                     Report (Stack, Which, Ours_As_Server, Skipped,
                             "no tool on this host could issue a credential");
                  else
                     declare
                        Server_Arguments : String_Vectors.Vector;
                        Client_Arguments : String_Vectors.Vector;
                        Version_Text     : Ada.Strings.Unbounded.Unbounded_String;
                     begin
                        case Stack is
                           when OpenSSL =>
                              OpenSSL_Server_Command
                                (Server_Arguments, Folder,
                                 Server_Port (Stack, Which), Which,
                                 Force_Version => True);
                              OpenSSL_Client_Command
                                (Client_Arguments, Folder,
                                 Client_Port (Stack, Which), Which,
                                 Force_Version => True);
                              Version_Text :=
                                Ada.Strings.Unbounded.To_Unbounded_String
                                  (if Which = Modern then "TLSv1.3" else "TLSv1.2");

                           when LibreSSL =>
                              OpenSSL_Server_Command
                                (Server_Arguments, Folder,
                                 Server_Port (Stack, Which), Which,
                                 Force_Version => False);
                              OpenSSL_Client_Command
                                (Client_Arguments, Folder,
                                 Client_Port (Stack, Which), Which,
                                 Force_Version => False);
                              Version_Text :=
                                Ada.Strings.Unbounded.To_Unbounded_String
                                  (if Which = Modern then "TLSv1.3" else "TLSv1.2");

                           when GnuTLS =>
                              GnuTLS_Server_Command
                                (Server_Arguments, Folder,
                                 Server_Port (Stack, Which), Which);
                              GnuTLS_Client_Command
                                (Client_Arguments, Folder,
                                 Client_Port (Stack, Which), Which);
                              Version_Text :=
                                Ada.Strings.Unbounded.To_Unbounded_String
                                  (if Which = Modern then "TLS1.3" else "TLS1.2");

                           when Java_Keytool =>
                              Add (Server_Arguments, Java_Source);
                              Add (Server_Arguments, "server");
                              Add (Server_Arguments,
                                   Port_Text (Server_Port (Stack, Which)));
                              Add (Server_Arguments, Folder & "/cert.pem");
                              Add (Server_Arguments, Folder & "/key.pem");
                              Add (Server_Arguments, Image (Which));

                              Add (Client_Arguments, Java_Source);
                              Add (Client_Arguments, "client");
                              Add (Client_Arguments,
                                   Port_Text (Client_Port (Stack, Which)));
                              Add (Client_Arguments, Folder & "/cert.pem");
                              Add (Client_Arguments, Image (Which));
                              Version_Text :=
                                Ada.Strings.Unbounded.To_Unbounded_String
                                  (if Which = Modern
                                   then "version=TLSv1.3" else "version=TLSv1.2");

                           when BoringSSL =>
                              --  Unreachable: BoringSSL has no driver and was
                              --  reported as skipped above.
                              null;
                        end case;

                        if Server = "" then
                           Report (Stack, Which, Ours_As_Client, Skipped,
                                   "the server program is not installed");
                        else
                           Report (Stack, Which, Ours_As_Client,
                                   Drive_Ours_As_Client
                                     (Server, Server_Arguments, Folder,
                                      Peer_Path, Server_Port (Stack, Which), Which),
                                   "");
                        end if;

                        Report (Stack, Which, Ours_As_Server,
                                Drive_Ours_As_Server
                                  (Located, Client_Arguments, Folder,
                                   Peer_Path, Client_Port (Stack, Which),
                                   Ada.Strings.Unbounded.To_String (Version_Text),
                                   Which),
                                "");
                     end;
                  end if;

                  --  Removed afterwards, whatever happened. A credential left
                  --  in a shared temporary directory is a private key left in a
                  --  shared temporary directory -- so it goes even when the run
                  --  failed, and the failure is described in the report rather
                  --  than left on disk to be read later.
                  begin
                     Ada.Directories.Delete_Tree (Folder);
                  exception
                     when others =>
                        null;
                  end;
               end;
            end if;

            <<Continue>>
         end;
       end loop;
      end loop;

      IO.New_Line;
      if not Any_Present then
         IO.Put_Line ("no external stack was found on this host");
      end if;

      Succeeded := not Any_Failure;
   end Run_Matrix;

end SSLLib_Interop;
