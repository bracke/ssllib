with SSL.Cancellation;
with SSL.Clocks;
with SSL.Configurations;
with SSL.Connection_Metadata;
with SSL.Engines;
with SSL.Engines.Events;
with SSL.Errors;
with SSL.Transports;

private with SSL.Limits;

use type SSL.Engines.Lifecycle;

--  @summary A TLS connection: an engine with a transport bound to it, and the
--  operations that move octets between the two.
--
--  This is the type most applications hold. It adds exactly one thing to
--  `SSL.Engines`: knowing where the octets come from and go. Everything else --
--  the protocol, the lifecycle, the metadata -- is the engine's and is passed
--  straight through.
--
--  **Still nothing blocks.** Every operation here does what can be done with
--  what is available and returns; a transport that says `Would_Block` ends the
--  call, not the connection. `SSL.Blocking` puts a wait around these for
--  callers who want one, and an application with its own event loop uses
--  `Ready` and calls back in when its poll says so.
--
--  **One task at a time.** A connection is a state machine with buffers; two
--  tasks calling into one concurrently is a programming error, not a race this
--  type defends against. Serializing is the application's, or
--  `SSL.Synchronized_Connections`'.
package SSL.Connections is

   ---------------------------------------------------------------------------
   --  The connection
   ---------------------------------------------------------------------------

   type Connection is limited private;

   --  Where it is. The engine's lifecycle, unchanged.
   function State_Of (Item : Connection) return SSL.Engines.Lifecycle;
   function Is_Established (Item : Connection) return Boolean;
   function Is_Terminal (Item : Connection) return Boolean;

   function Metadata_Of (Item : Connection) return SSL.Connection_Metadata.Metadata;
   function Failure_Of (Item : Connection) return SSL.Errors.Error_Information;
   function Identifier (Item : Connection) return Connection_ID;

   function Ready (Item : Connection) return SSL.Engines.Readiness;
   function Events (Item : Connection) return SSL.Engines.Events.Event_List;

   --  Did the peer close cleanly, and did the stream end without one?
   function Peer_Closed (Item : Connection) return Boolean;
   function Was_Truncated (Item : Connection) return Boolean;

   ---------------------------------------------------------------------------
   --  Setting one up
   ---------------------------------------------------------------------------

   --  Begin a client connection.
   --
   --  Both the configuration and the transport must outlive the connection.
   --  They are referenced rather than copied: a configuration is immutable and
   --  shareable after Build, and a transport is the application's own object
   --  with its own lifetime.
   --  @param Item      out: the connection, handshaking
   --  @param Config    the client policy
   --  @param Medium    where the octets go
   --  @param Identity  this connection's stable identifier
   --  @param Now       the wall clock, for certificate validity
   --  @param Error     out: No_Error, or why it could not start
   procedure Connect
     (Item     : in out Connection;
      Config   : not null access constant SSL.Configurations.Client_Configuration;
      Medium   : not null SSL.Transports.Transport_Reference;
      Identity : Connection_ID;
      Now      : SSL.Clocks.Wall_Time;
      Error    : out SSL.Errors.Error_Information)
     with Pre => State_Of (Item) = SSL.Engines.Uninitialized;

   --  Begin a server connection. Nothing is sent until a ClientHello arrives.
   procedure Accept_Connection
     (Item     : in out Connection;
      Config   : not null access constant SSL.Configurations.Server_Configuration;
      Medium   : not null SSL.Transports.Transport_Reference;
      Identity : Connection_ID;
      Now      : SSL.Clocks.Wall_Time;
      Error    : out SSL.Errors.Error_Information)
     with Pre => State_Of (Item) = SSL.Engines.Uninitialized;

   ---------------------------------------------------------------------------
   --  Moving octets
   ---------------------------------------------------------------------------

   --  Read from the transport into the engine, once.
   --
   --  Reads at most one buffer's worth and processes it. Returns what the
   --  transport said, so a caller can tell "nothing there" from "connection
   --  gone" without inspecting the connection.
   --  @param Item   the connection
   --  @param Status out: what the transport reported
   --  @param Error  out: No_Error, or the failure that ended the connection
   procedure Pump_Input
     (Item   : in out Connection;
      Status : out SSL.Transports.Transport_Status;
      Error  : out SSL.Errors.Error_Information);

   --  Write queued encrypted octets to the transport, once.
   --
   --  Writes as much as the transport takes and keeps the rest. A transport
   --  that takes nothing is not a failure; it is a caller that should wait for
   --  writability and come back.
   procedure Pump_Output
     (Item   : in out Connection;
      Status : out SSL.Transports.Transport_Status;
      Error  : out SSL.Errors.Error_Information);

   --  Do one round of whatever is possible: drain output, take input, advance.
   --
   --  The order is deliberate. Output goes first, because a peer waiting on
   --  this endpoint's flight will not send anything until it arrives, and an
   --  implementation that read first would deadlock against one that did the
   --  same.
   --  @param Item     the connection
   --  @param Progress out: True when anything at all moved
   --  @param Error    out: No_Error, or the failure
   procedure Step
     (Item     : in out Connection;
      Progress : out Boolean;
      Error    : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  Application data
   ---------------------------------------------------------------------------

   --  Take application data that has already arrived.
   --
   --  Never waits and never reads the transport: it hands over what is already
   --  authenticated and decrypted. A caller that gets zero should `Step` and
   --  ask again.
   --  @param Item  the connection
   --  @param Into  out: the data
   --  @param Count out: how much, possibly zero
   --  @param Error out: No_Error, or a terminal failure
   procedure Read_Available
     (Item  : in out Connection;
      Into  : out Byte_Array;
      Count : out Byte_Index;
      Error : out SSL.Errors.Error_Information);

   --  Offer plaintext. Accepted may be less than offered, or zero, when the
   --  output queue is full; the caller should `Pump_Output` and offer the rest.
   procedure Write_Available
     (Item     : in out Connection;
      Data     : Byte_Array;
      Accepted : out Byte_Index;
      Error    : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  Post-handshake operations
   ---------------------------------------------------------------------------

   --  Derive exported keying material bound to this connection.
   --
   --  `SSL.Exporters` is the interface applications should use; this is what it
   --  is built on, and it is here rather than there because the engine is this
   --  package's to reach.
   procedure Export_Keying_Material
     (Item        : Connection;
      Label       : String;
      Context     : Byte_Array;
      Has_Context : Boolean;
      Into        : out Byte_Array;
      Error       : out SSL.Errors.Error_Information);

   --  Ask the peer to update its keys, and replace this endpoint's write key.
   --
   --  Rarely needed: the connection schedules its own updates as usage
   --  approaches the configured thresholds. This is for an application with a
   --  policy of its own.
   procedure Request_Key_Update
     (Item     : in out Connection;
      Ask_Peer : Boolean;
      Error    : out SSL.Errors.Error_Information);

   --  How many times each direction's key has been replaced, and how many
   --  updates the peer has asked for.
   function Write_Generation (Item : Connection) return Natural;
   function Read_Generation (Item : Connection) return Natural;
   function Peer_Key_Updates (Item : Connection) return Natural;

   ---------------------------------------------------------------------------
   --  Ending one
   ---------------------------------------------------------------------------

   --  Queue a close_notify. The connection is not closed until it has actually
   --  been sent, which takes at least one Pump_Output.
   procedure Begin_Shutdown
     (Item  : in out Connection;
      Error : out SSL.Errors.Error_Information);

   --  Give up now. Nothing is queued and nothing is waited for.
   procedure Cancel (Item : in out Connection; Reason : SSL.Cancellation.Token);

   --  Set a deadline. Reported by the operations above once the monotonic clock
   --  passes it; never enforced by waiting, because nothing here waits.
   procedure Set_Deadline (Item : in out Connection; Value : SSL.Clocks.Deadline);

   --  Scrub every key and buffer now rather than at end of scope.
   procedure Wipe (Item : in out Connection);

private

   --  One transport read at a time. Sized to a whole record plus its expansion
   --  so that a single read usually delivers a record the engine can act on,
   --  and bounded so that a transport with a great deal buffered cannot make
   --  one call do unbounded work.
   Read_Chunk : constant Byte_Index := SSL.Limits.Protocol_Plaintext_Record_Limit + 512;

   type Connection is limited record
      Driver : SSL.Engines.Engine;
      Medium : SSL.Transports.Transport_Reference;
      Ident  : Connection_ID := No_Connection;

      --  What the transport delivered and the engine could not take yet.
      --
      --  The engine's input queue is bounded, so supplying it a chunk is a
      --  *partial* operation: it takes what fits and says how much. This held
      --  the octets it took and dropped the rest -- and a dropped octet is not
      --  a lost octet, it is a stream that no longer parses. The next record
      --  header lands mid-record, its length is nonsense, and what is fed to
      --  the AEAD authenticates as a forgery: bad_record_mac, at whatever
      --  offset the queue first filled.
      --
      --  Which is why it looked like an unreliable network. It needed a
      --  transfer long enough for the application to fall behind the socket --
      --  82 MB from a fast CDN did it, 40 kB in a test never did -- and it
      --  arrived at a different offset every time, on the hosts whose reads
      --  are largest, while a slower peer never saw it at all.
      --
      --  So the remainder waits here and goes in first next time, and nothing
      --  new is read while any of it is outstanding.
      Held       : Byte_Array (1 .. Read_Chunk) := [others => 0];
      Held_First : Byte_Index := 1;
      Held_Last  : Byte_Index := 0;
   end record;

   function State_Of (Item : Connection) return SSL.Engines.Lifecycle is
     (SSL.Engines.State_Of (Item.Driver));
   function Is_Established (Item : Connection) return Boolean is
     (SSL.Engines.Is_Established (Item.Driver));
   function Is_Terminal (Item : Connection) return Boolean is
     (SSL.Engines.Is_Terminal (SSL.Engines.State_Of (Item.Driver)));
   function Metadata_Of (Item : Connection) return SSL.Connection_Metadata.Metadata is
     (SSL.Engines.Metadata_Of (Item.Driver));
   function Failure_Of (Item : Connection) return SSL.Errors.Error_Information is
     (SSL.Engines.Failure_Of (Item.Driver));
   function Identifier (Item : Connection) return Connection_ID is (Item.Ident);
   function Ready (Item : Connection) return SSL.Engines.Readiness is
     (SSL.Engines.Ready (Item.Driver));
   function Events (Item : Connection) return SSL.Engines.Events.Event_List is
     (SSL.Engines.Events.Current (Item.Driver));
   function Peer_Closed (Item : Connection) return Boolean is
     (SSL.Engines.Peer_Closed (Item.Driver));
   function Was_Truncated (Item : Connection) return Boolean is
     (SSL.Engines.Was_Truncated (Item.Driver));
   function Write_Generation (Item : Connection) return Natural is
     (SSL.Engines.Write_Generation (Item.Driver));
   function Read_Generation (Item : Connection) return Natural is
     (SSL.Engines.Read_Generation (Item.Driver));
   function Peer_Key_Updates (Item : Connection) return Natural is
     (SSL.Engines.Peer_Key_Updates (Item.Driver));

end SSL.Connections;
