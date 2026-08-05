with SSL;
with SSL.Clocks;
with SSL.Configurations;
with SSL.Connections;
with SSL.Errors;
with SSL.Transports;
with SSL.Trust;
with SSL.Credentials;

--  @summary What every example needs: a transport made of memory, a committed
--  certificate, and a loop that drives two connections against each other.
--
--  None of this is part of `ssllib`. It is the twenty lines an application
--  writes to attach the library to whatever actually moves its octets -- here a
--  pair of in-memory buffers, so that an example runs anywhere with no network,
--  no ports and no privileges. An application using a socket writes the same
--  shape around `read` and `write`.
package Example_Support is

   use type SSL.Byte_Index;

   ---------------------------------------------------------------------------
   --  A transport made of memory
   ---------------------------------------------------------------------------

   Capacity : constant SSL.Byte_Index := 256 * 1024;

   --  Both records are public rather than private, which is right for a
   --  fixture: there is nothing here to protect, and an example that hid its
   --  own plumbing would be hiding the part a reader most wants to see.
   type Pipe is limited record
      Held  : SSL.Byte_Index := 0;
      Bytes : SSL.Byte_Array (1 .. Capacity) := [others => 0];
   end record;

   Name_Limit : constant := 32;

   --  A transport that writes into one pipe and reads from another. Two of
   --  these with the pipes crossed make a connected pair.
   type Memory_Transport is limited new SSL.Transports.Transport with record
      Outgoing : access Pipe;
      Incoming : access Pipe;
      Length   : Natural range 0 .. Name_Limit := 0;
      Name     : String (1 .. Name_Limit) := [others => ' '];
      Stalling : Boolean := False;
      Stalled  : Boolean := False;
   end record;

   procedure Attach
     (Item     : in out Memory_Transport;
      Outgoing : not null access Pipe;
      Incoming : not null access Pipe;
      Name     : String);

   --  Refuse every other read, the way a non-blocking socket does. Off by
   --  default so that the simplest example stays simple; the non-blocking
   --  example turns it on.
   procedure Set_Stalling (Item : in out Memory_Transport; Value : Boolean);

   overriding procedure Receive
     (Item   : in out Memory_Transport;
      Into   : out SSL.Byte_Array;
      Count  : out SSL.Byte_Index;
      Status : out SSL.Transports.Transport_Status);

   overriding procedure Send
     (Item   : in out Memory_Transport;
      Data   : SSL.Byte_Array;
      Count  : out SSL.Byte_Index;
      Status : out SSL.Transports.Transport_Status);

   overriding function Description (Item : Memory_Transport) return String;

   ---------------------------------------------------------------------------
   --  The long-lived objects, at library level
   ---------------------------------------------------------------------------

   --  Every example uses these rather than declaring its own, and that is not
   --  laziness -- it is the lifetime obligation made visible.
   --
   --  A configuration holds a reference to its trust snapshot and its
   --  credentials; a connection holds a reference to its configuration and its
   --  transport. Each of those must outlive what points at it. Ada's
   --  accessibility rules *enforce* that rather than trusting the programmer to
   --  remember it: an anchor declared inside a subprogram and handed to a
   --  configuration fails an accessibility check at run time, immediately and
   --  loudly.
   --
   --  A main procedure's own declarations are inside a subprogram too, so these
   --  live here, at library level, where they genuinely outlive everything that
   --  refers to them. A real application would put them in whatever package
   --  owns its configuration -- which is the same shape.
   Anchors    : aliased SSL.Trust.Snapshot;
   Credential : aliased SSL.Credentials.Credential;

   Client_Policy : aliased SSL.Configurations.Client_Configuration;
   Server_Policy : aliased SSL.Configurations.Server_Configuration;

   --  A second client policy, for the examples that compare two.
   Other_Client_Policy : aliased SSL.Configurations.Client_Configuration;

   --  Two connected transports, and a second pair for an example that needs
   --  to run two connections in turn.
   To_Server : aliased Pipe;
   To_Client : aliased Pipe;
   Client_Medium : aliased Memory_Transport;
   Server_Medium : aliased Memory_Transport;

   Second_To_Server : aliased Pipe;
   Second_To_Client : aliased Pipe;
   Second_Client_Medium : aliased Memory_Transport;
   Second_Server_Medium : aliased Memory_Transport;

   --  Wire the first pair together and empty them.
   procedure Connect_Pipes;

   --  The same for the second pair.
   procedure Connect_Second_Pipes;

   ---------------------------------------------------------------------------
   --  A certificate to run with
   ---------------------------------------------------------------------------

   --  A self-signed Ed25519 certificate for www.example.com, generated once and
   --  written into the source. It protects nothing: it was made for these
   --  examples, has never been used, and names a domain RFC 2606 reserves for
   --  exactly this. A real deployment loads its own from wherever it keeps it.
   Certificate_PEM : constant String;
   Private_Key_PEM : constant String;

   --  Load the certificate as a credential and as a trust anchor.
   procedure Load_Fixtures
     (Anchors    : in out SSL.Trust.Snapshot;
      Credential : in out SSL.Credentials.Credential;
      Now        : SSL.Clocks.Wall_Time;
      Error      : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  Driving two connections against each other
   ---------------------------------------------------------------------------

   --  Step both until they are established, or until something fails.
   --
   --  A real application drives one connection from its own event loop; both
   --  ends are here because an example with no network needs both.
   procedure Run_Handshake
     (Client : in out SSL.Connections.Connection;
      Server : in out SSL.Connections.Connection;
      Error  : out SSL.Errors.Error_Information);

   --  Step both until the receiver has some application data, and hand it over.
   procedure Deliver
     (From  : in out SSL.Connections.Connection;
      To    : in out SSL.Connections.Connection;
      Into  : out SSL.Byte_Array;
      Count : out SSL.Byte_Index;
      Error : out SSL.Errors.Error_Information);

   --  Report a failure and stop. Examples are meant to be read, so they say
   --  what went wrong rather than raising.
   procedure Report (Label : String; Error : SSL.Errors.Error_Information);

   --  The wall clock the examples use, fixed so that they do not start failing
   --  on a date nobody chose.
   function Example_Time return SSL.Clocks.Wall_Time;

   --  Secure defaults plus this example's anchor and expected name.
   procedure Build_Client
     (Into    : out SSL.Configurations.Client_Configuration;
      Anchors : not null access constant SSL.Trust.Snapshot;
      Error   : out SSL.Errors.Error_Information);

   procedure Build_Server
     (Into       : out SSL.Configurations.Server_Configuration;
      Credential : not null access constant SSL.Credentials.Credential;
      Error      : out SSL.Errors.Error_Information);

private

   Certificate_PEM : constant String :=
     "-----BEGIN CERTIFICATE-----" & ASCII.LF
     & "MIIBpzCCAVmgAwIBAgIUIBiL9TITIQVBhzTergGMWKLOiR8wBQYDK2VwMBoxGDAW" & ASCII.LF
     & "BgNVBAMMD3d3dy5leGFtcGxlLmNvbTAgFw0yNjA3MzAxODAzNTNaGA8yMTI2MDcw" & ASCII.LF
     & "NjE4MDM1M1owGjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCowBQYDK2VwAyEA" & ASCII.LF
     & "tSCd/v8oVcfUyKtkpjhvvKihzuTaZuuGMuxvHe16teijga4wgaswHQYDVR0OBBYE" & ASCII.LF
     & "FJ3vYTfuje2D1uR+srJJDxMzWjFnMB8GA1UdIwQYMBaAFJ3vYTfuje2D1uR+srJJ" & ASCII.LF
     & "DxMzWjFnMA8GA1UdEwEB/wQFMAMBAf8wKQYDVR0RBCIwIIIPd3d3LmV4YW1wbGUu" & ASCII.LF
     & "Y29tgg0qLmV4YW1wbGUuY29tMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggr" & ASCII.LF
     & "BgEFBQcDAQYIKwYBBQUHAwIwBQYDK2VwA0EAHzRbOWV27EsELzrT34OJVQ8xp6d2" & ASCII.LF
     & "B/ju8j65rM9QKEsLYh0n6XDJFLIpg1OfVnAeKVMYbw5KVF8YP4zWpqWKBw==" & ASCII.LF
     & "-----END CERTIFICATE-----" & ASCII.LF;

   Private_Key_PEM : constant String :=
     "-----BEGIN PRIVATE KEY-----" & ASCII.LF
     & "MC4CAQAwBQYDK2VwBCIEINf8wh6nGfnaz8ID+vfApw5tmfpK+UYqxMANsWgMuY++" & ASCII.LF
     & "-----END PRIVATE KEY-----" & ASCII.LF;

end Example_Support;
