with SSL.Alerts;
with SSL.Cancellation;
with SSL.Clocks;
with SSL.Configurations;
with SSL.Connection_Metadata;
with SSL.Diagnostics;
with SSL.Sessions;
with SSL.Errors;
with SSL.Limits;
with SSL.Versions;

private with SSL.Buffers;
private with SSL.Records;
private with SSL.Sessions.Client_Caches;
private with SSL.Ticket_Keys;
private with SSL.TLS12;
private with SSL.TLS12.Client;
private with SSL.TLS12.Records;
private with SSL.TLS12.Server;
private with SSL.TLS13;
private with SSL.TLS13.Client;
private with SSL.TLS13.Server;

--  @summary The protocol driver: encrypted octets in, encrypted octets out,
--  application data in between. No transport, no tasking, no waiting.
--
--  An engine is the whole of TLS with the I/O taken out. It is fed the octets a
--  transport read, and it produces the octets a transport should write; it is
--  given plaintext to send, and it hands back plaintext that arrived. It never
--  calls a socket, never blocks, and never starts a task. `SSL.Blocking` puts a
--  transport and a loop around one for callers who want that, and an
--  application with its own event loop can drive one directly.
--
--  **Everything is partial.** Every operation reports how much it actually
--  consumed or produced, and every one of them may report zero without that
--  being a failure. A transport that delivered half a record, an application
--  that offered more plaintext than the output queue can hold, an output queue
--  that a transport accepted only part of -- all of these are ordinary, and an
--  engine that treated any of them as an error would be unusable with
--  non-blocking I/O.
--
--  **Nothing here waits, so nothing here can time out on its own.** Deadlines
--  are the caller's: `Advance` is given the current monotonic time and reports
--  a deadline as reached, and the caller decides what that means. The wall
--  clock is a separate thing and is used only for certificate validity, because
--  the two answer different questions and a system whose wall clock moves must
--  not thereby change when a read gives up.
package SSL.Engines is

   ---------------------------------------------------------------------------
   --  Lifecycle
   ---------------------------------------------------------------------------

   --  Where a connection is. The specification's lifecycle, exactly.
   --
   --  These are one-way. A connection that has failed does not return to
   --  handshaking, and a closed one does not reopen: an engine is single-use,
   --  and reuse is a new engine. That is what stops a connection from carrying
   --  state across a failure it was supposed to have ended.
   type Lifecycle is
     (Uninitialized,
      Ready,
      Handshaking,
      Established,
      Closing,
      Closed,
      Failed);

   function Image (Item : Lifecycle) return String;

   --  Is this a state from which nothing more will happen?
   function Is_Terminal (Item : Lifecycle) return Boolean is (Item in Closed | Failed);

   ---------------------------------------------------------------------------
   --  The engine
   ---------------------------------------------------------------------------

   --  Limited and single-use. It holds traffic keys and a key schedule, so it
   --  cannot be copied; it scrubs them, so it is controlled.
   type Engine is limited private;

   function State_Of (Item : Engine) return Lifecycle;
   function Is_Established (Item : Engine) return Boolean;

   --  What was negotiated. Meaningful once the handshake has completed; before
   --  that it reports itself as not established.
   function Metadata_Of (Item : Engine) return SSL.Connection_Metadata.Metadata;

   --  The first failure this connection suffered, preserved. Later failures are
   --  counted but never displace it, because the first one is the cause and the
   --  rest are usually consequences.
   function Failure_Of (Item : Engine) return SSL.Errors.Error_Information;

   ---------------------------------------------------------------------------
   --  Starting one
   ---------------------------------------------------------------------------

   --  Prepare a client engine.
   --
   --  The configuration must outlive the engine. It is referenced rather than
   --  copied: a configuration is immutable after Build and shareable between
   --  connections, and copying it per connection would be a copy to keep in
   --  step with the original for no gain.
   --  @param Item     out: the engine, in Ready
   --  @param Config   the client policy
   --  @param Identity this connection's stable identifier, for correlating logs
   --  @param Now      the wall clock, for certificate validity
   --  @param Error    out: No_Error, or why it could not start
   procedure Start_Client
     (Item     : in out Engine;
      Config   : not null access constant SSL.Configurations.Client_Configuration;
      Identity : Connection_ID;
      Now      : SSL.Clocks.Wall_Time;
      Error    : out SSL.Errors.Error_Information)
     with Pre => State_Of (Item) = Uninitialized;

   --  Prepare a server engine.
   procedure Start_Server
     (Item     : in out Engine;
      Config   : not null access constant SSL.Configurations.Server_Configuration;
      Identity : Connection_ID;
      Now      : SSL.Clocks.Wall_Time;
      Error    : out SSL.Errors.Error_Information)
     with Pre => State_Of (Item) = Uninitialized;

   ---------------------------------------------------------------------------
   --  Encrypted input
   ---------------------------------------------------------------------------

   --  Supply octets a transport read.
   --
   --  Consumed may be fewer than Data'Length: the input buffer is bounded, and
   --  a caller that read more than fits should keep the rest and offer it after
   --  the next Advance. It may be zero when the buffer is already full, which
   --  is backpressure and not a failure.
   --  @param Item     the engine
   --  @param Data     the octets read from the transport
   --  @param Consumed out: how many were taken
   --  @param Error    out: No_Error, or a terminal failure
   procedure Supply_Encrypted
     (Item     : in out Engine;
      Data     : Byte_Array;
      Consumed : out Byte_Index;
      Error    : out SSL.Errors.Error_Information);

   --  Tell the engine the transport reached end of stream.
   --
   --  Whether that is orderly is this library's judgement and not the
   --  transport's: a stream that ended after a close_notify closed properly,
   --  and one that ended before it was truncated -- which is an attack when the
   --  application protocol has no length of its own.
   procedure Report_End_Of_Stream
     (Item  : in out Engine;
      Error : out SSL.Errors.Error_Information);

   --  Tell the engine the transport failed. The connection ends; the
   --  description is recorded and never interpreted.
   procedure Report_Transport_Failure
     (Item   : in out Engine;
      Reason : String);

   ---------------------------------------------------------------------------
   --  Encrypted output
   ---------------------------------------------------------------------------

   --  How many encrypted octets are waiting to be sent.
   function Pending_Encrypted (Item : Engine) return Byte_Index;

   --  Look at the queued encrypted output without consuming it.
   --
   --  Peek and consume are separate because a transport that accepted only part
   --  of a write must be able to say so, and a design where peeking consumed
   --  would lose the remainder.
   --  @param Item  the engine
   --  @param Into  out: receives up to Into'Length octets
   --  @param Count out: how many were copied
   procedure Peek_Encrypted
     (Item  : Engine;
      Into  : out Byte_Array;
      Count : out Byte_Index);

   --  Drop octets a transport has accepted.
   --  @param Item  the engine
   --  @param Count how many the transport took; must not exceed what is pending
   procedure Consume_Encrypted (Item : in out Engine; Count : Byte_Index)
     with Pre => Count <= Pending_Encrypted (Item);

   ---------------------------------------------------------------------------
   --  Application data
   ---------------------------------------------------------------------------

   --  Offer plaintext to send.
   --
   --  Accepted may be fewer than Data'Length, or zero, when the output queue is
   --  full. Nothing is sent until the caller drains the encrypted output, so an
   --  application that never drains will find this returning zero rather than
   --  growing a buffer without limit.
   --  @param Item     the engine, which must be Established
   --  @param Data     the plaintext
   --  @param Accepted out: how much was taken
   --  @param Error    out: No_Error, or a terminal failure
   procedure Write_Plaintext
     (Item     : in out Engine;
      Data     : Byte_Array;
      Accepted : out Byte_Index;
      Error    : out SSL.Errors.Error_Information);

   --  How much authenticated application data is waiting to be read.
   function Pending_Plaintext (Item : Engine) return Byte_Index;

   --  Look at received application data without consuming it.
   procedure Peek_Plaintext
     (Item  : Engine;
      Into  : out Byte_Array;
      Count : out Byte_Index);

   --  Drop application data the caller has taken.
   procedure Consume_Plaintext (Item : in out Engine; Count : Byte_Index)
     with Pre => Count <= Pending_Plaintext (Item);

   ---------------------------------------------------------------------------
   --  Driving it
   ---------------------------------------------------------------------------

   --  Do whatever can be done with what is already here.
   --
   --  This is where records are parsed, handshake messages are processed,
   --  alerts are acted on and output is produced. It never waits: given nothing
   --  to work with it does nothing and says so.
   --  @param Item  the engine
   --  @param Now   the current monotonic time, for deadlines
   --  @param Error out: No_Error, or the failure that ended the connection
   procedure Advance
     (Item  : in out Engine;
      Now   : SSL.Clocks.Monotonic_Time;
      Error : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  Sessions
   ---------------------------------------------------------------------------

   --  Issue a session ticket, if this endpoint is a server that may.
   --
   --  Called by the engine itself when a handshake completes; exposed so that
   --  an application with a reason to issue another one can. A server with no
   --  active ticket key, or with ticket issuance disabled, does nothing and
   --  reports no failure: not issuing is a state, not an error.
   procedure Issue_Ticket
     (Item  : in out Engine;
      Error : out SSL.Errors.Error_Information);

   --  How many tickets this connection has issued.
   function Tickets_Issued (Item : Engine) return Natural;

   --  Ask the peer to update its keys, and update this endpoint's own write key.
   --
   --  RFC 8446 section 7.2. The KeyUpdate message itself goes out under the
   --  *old* key -- installing the new one first would produce a message the
   --  peer cannot read -- so the message is queued and the key is installed
   --  immediately afterwards, in that order and in one operation, because a
   --  caller who could do one without the other could desynchronize the
   --  connection.
   --
   --  A caller need not do this: the engine schedules its own updates as usage
   --  approaches the configured thresholds. This exists for an application with
   --  a policy of its own -- a long-lived connection that updates on a timer,
   --  say.
   --  @param Item          the engine, which must be Established
   --  @param Ask_Peer      True to require an answering KeyUpdate from the peer
   --  @param Error         out: No_Error, or the failure
   procedure Request_Key_Update
     (Item     : in out Engine;
      Ask_Peer : Boolean;
      Error    : out SSL.Errors.Error_Information);

   --  How many times each direction's key has been replaced. Part of the
   --  no-nonce-reuse argument, and something an operator watching a long-lived
   --  connection wants to see.
   function Write_Generation (Item : Engine) return Natural;
   function Read_Generation (Item : Engine) return Natural;

   --  How many KeyUpdates the peer has asked for. Bounded: answering an
   --  unbounded run of them is unbounded work for this endpoint and almost
   --  none for the peer.
   function Peer_Key_Updates (Item : Engine) return Natural;

   ---------------------------------------------------------------------------
   --  Exported key material
   ---------------------------------------------------------------------------

   --  Derive exported key material from this connection (RFC 8446 section 7.5).
   --
   --  Available only after the handshake has completed, because before that
   --  there is no exporter master secret and anything this produced would not
   --  be bound to a connection either end had authenticated.
   --
   --  There is no getter for the exporter master secret itself, here or
   --  anywhere: a caller can ask for material derived under a label, and cannot
   --  ask for the thing it is derived from.
   --  @param Item        the engine, which must be Established
   --  @param Label       the exporter label
   --  @param Context     the context octets
   --  @param Has_Context whether a context was supplied at all. Under TLS 1.3
   --                     this makes no difference to the output: RFC 8446
   --                     section 7.5 defines an absent context as the empty
   --                     string. It is a parameter because TLS 1.2's exporter
   --                     (RFC 5705) does distinguish them
   --  @param Into        out: the exported material
   --  @param Error       out: No_Error, or the failure
   procedure Export_Keying_Material
     (Item        : Engine;
      Label       : String;
      Context     : Byte_Array;
      Has_Context : Boolean;
      Into        : out Byte_Array;
      Error       : out SSL.Errors.Error_Information);

   --  Begin an orderly shutdown: queue a close_notify.
   --
   --  The connection is not closed until the queued alert has actually been
   --  sent, which is why this is a request and not an action.
   procedure Begin_Shutdown
     (Item  : in out Engine;
      Error : out SSL.Errors.Error_Information);

   --  Give up on this connection now.
   --
   --  Not the same as a shutdown: nothing is queued and nothing is waited for.
   --  For a caller whose own deadline has passed or whose user has cancelled.
   procedure Cancel (Item : in out Engine; Reason : SSL.Cancellation.Token);

   --  Set a deadline. Advance reports it as reached once the monotonic clock
   --  passes it; nothing here enforces it, because nothing here waits.
   procedure Set_Deadline (Item : in out Engine; Value : SSL.Clocks.Deadline);

   ---------------------------------------------------------------------------
   --  Readiness
   ---------------------------------------------------------------------------

   --  What the caller should do next. Several may be true at once, which is why
   --  this is a set of questions rather than one answer.
   type Readiness is record
      Wants_Transport_Read  : Boolean := False;
      --  The engine cannot make progress without more encrypted input.

      Wants_Transport_Write : Boolean := False;
      --  There are encrypted octets queued for the transport.

      Accepts_Plaintext     : Boolean := False;
      --  Write_Plaintext would take something.

      Has_Plaintext         : Boolean := False;
      --  Application data is waiting.

      Handshake_Complete    : Boolean := False;
      Peer_Closed           : Boolean := False;
      Terminal              : Boolean := False;
   end record;

   function Ready (Item : Engine) return Readiness;

   ---------------------------------------------------------------------------
   --  Scrubbing
   ---------------------------------------------------------------------------

   --  Scrub every key and buffer now rather than at end of scope.
   procedure Wipe (Item : in out Engine);

   --  Did the peer send a close_notify?
   function Peer_Closed (Item : Engine) return Boolean;

   --  Did the transport end without one? The truncation this library detects
   --  when the configuration asks it to.
   function Was_Truncated (Item : Engine) return Boolean;

   --  The alert this endpoint sent, when it sent one. For diagnostics: an
   --  operator correlating two ends of a failed connection needs to know which
   --  alert travelled.
   function Sent_Alert (Item : Engine) return SSL.Alerts.Alert_Description;
   function Has_Sent_Alert (Item : Engine) return Boolean;

private

   --  The largest a record can be on the wire: the plaintext limit, plus what
   --  TLS 1.3 adds -- one inner content-type octet, the AEAD tag, and the
   --  padding an implementation is permitted -- plus the five-octet header.
   Ciphertext_Limit : constant Byte_Index :=
     SSL.Limits.Protocol_Plaintext_Record_Limit + 256 + SSL.Records.Header_Length;

   --  What the three queues used to be reserved at, whatever an endpoint had
   --  configured. They are SSL.Limits' defaults now, and the engine reserves
   --  what it was configured with; these are kept as the floor a caller can
   --  compare against, and as the record of what a default connection costs.
   Input_Capacity  : constant Byte_Index := 2 * Ciphertext_Limit;
   Output_Capacity : constant Byte_Index := 8 * Ciphertext_Limit;
   Plain_Capacity  : constant Byte_Index := 4 * SSL.Limits.Protocol_Plaintext_Record_Limit;

   --  A staging buffer for the handshake messages a state machine produces in
   --  one call. A whole server flight -- EncryptedExtensions through Finished,
   --  with a certificate chain in the middle -- goes in here before being cut
   --  into records.
   Flight_Capacity : constant Byte_Index := 4 * Ciphertext_Limit;

   type Endpoint_Kind is (Not_Chosen, Client_Endpoint, Server_Endpoint);

   --  Which protocol this connection is actually running.
   --
   --  A connection starts optimistic: a client that may speak TLS 1.3 sends a
   --  hello that serves both versions and runs the TLS 1.3 machine until the
   --  ServerHello says otherwise. A server decides when it reads the hello.
   --  There is no third state and no "either": at every moment exactly one
   --  machine owns the connection.
   type Running_Protocol is (TLS13_Protocol, TLS12_Protocol);

   type Engine is limited record
      State : Lifecycle := Uninitialized;
      Kind  : Endpoint_Kind := Not_Chosen;

      Bounds : SSL.Limits.Resource_Limits := SSL.Limits.Default_Limits;
      Now    : SSL.Clocks.Wall_Time := SSL.Clocks.No_Wall_Time;
      Expires_At : SSL.Clocks.Deadline := SSL.Clocks.No_Deadline;

      Identity : Connection_ID := No_Connection;
      Context  : Security_Context_ID := Default_Security_Context;

      --  Where diagnostics go, and how much of them. Copied from the
      --  configuration at start rather than reached through it, so that
      --  emitting an event does not need the configuration in hand on every
      --  path that might want one.
      --  Sessions. A server holds the ring it seals tickets with; a client
      --  holds the cache it keeps them in. Copied from the configuration at
      --  start, for the same reason the diagnostics are.
      Ring   : SSL.Ticket_Keys.Ring_Reference := null;
      Cache  : SSL.Sessions.Client_Caches.Cache_Reference := null;
      Issues : Boolean := False;

      --  How many tickets this server has issued on this connection. Bounded,
      --  because each one costs a derivation and a seal and the peer pays
      --  nothing for them.
      Tickets_Issued : Natural := 0;

      --  The two fingerprints a ticket binds to. Taken at start, because a
      --  configuration is immutable after Build and reading them once is
      --  cheaper than reaching through the reference on every ticket.
      Setup   : Configuration_Fingerprint;
      Anchors : Trust_Fingerprint;

      --  Somewhere to build a session before handing it to the cache. Here
      --  rather than on the stack because it holds a secret and this record is
      --  the thing that gets scrubbed.
      Pending_Session : SSL.Sessions.Session;

      --  A TLS 1.2 session found in the cache, kept whole rather than as the
      --  ticket alone. The ticket goes into the hello through the TLS 1.3
      --  machine that writes it, but the master secret inside the session is
      --  what the TLS 1.2 machine needs if the server selects TLS 1.2, and it
      --  has no other way to reach it.
      Legacy_Session : SSL.Sessions.Session;
      Has_Legacy_Session : Boolean := False;

      Watcher   : SSL.Diagnostics.Sink_Reference := null;
      Level     : SSL.Diagnostics.Detail_Level := SSL.Diagnostics.Off;
      Redaction : SSL.Diagnostics.Redaction_Level := SSL.Diagnostics.Strict;

      --  The two machines. Only one is ever started; both are declared because
      --  a variant record would make the whole engine discriminated, and an
      --  engine whose discriminant is fixed at declaration could not be
      --  declared before its role is known.
      Running : Running_Protocol := TLS13_Protocol;

      Client : aliased SSL.TLS13.Client.Machine;
      Server : aliased SSL.TLS13.Server.Machine;

      --  The TLS 1.2 machines. Both are declared even though at most one runs,
      --  for the same reason the TLS 1.3 pair is: a variant record would make
      --  the whole engine discriminated, and the discriminant is not known when
      --  the engine is declared.
      Legacy_Client : aliased SSL.TLS12.Client.Machine;
      Legacy_Server : aliased SSL.TLS12.Server.Machine;

      Legacy_Read  : SSL.TLS12.Records.Traffic_State;
      Legacy_Write : SSL.TLS12.Records.Traffic_State;

      --  The ClientHello this endpoint sent, kept only until the ServerHello
      --  settles the version. A TLS 1.2 machine adopting it needs the exact
      --  octets, because they are already in the peer's transcript.
      Hello_Length : Byte_Index := 0;
      Hello_Bytes  : Byte_Array (1 .. 4096) := [others => 0];
      Hello_Random : Byte_Array (1 .. 32) := [others => 0];
      Hello_Session : Byte_Array (1 .. 32) := [others => 0];
      Hello_Session_Length : Byte_Index := 0;

      --  The versions the configuration offered, and the configuration itself
      --  for the role this engine is. Kept because the version routing happens
      --  after the machines have started and needs both.
      Offered_Versions : SSL.Versions.Version_Set := SSL.Versions.No_Versions;
      Client_Policy : access constant SSL.Configurations.Client_Configuration;
      Server_Policy : access constant SSL.Configurations.Server_Configuration;

      Read_State  : SSL.Records.Traffic_State;
      Write_State : SSL.Records.Traffic_State;

      --  True once the corresponding direction is on application keys, so that
      --  a record arriving under the wrong epoch is a failure rather than a
      --  decryption that happens not to work.
      Read_Application  : Boolean := False;
      Write_Application : Boolean := False;

      Input     : SSL.Buffers.Queue;
      Output    : SSL.Buffers.Queue;
      Plaintext : SSL.Buffers.Queue;

      --  Handshake messages arrive cut into records at arbitrary boundaries: a
      --  message may span several records and a record may hold several
      --  messages. Reassembly happens here, bounded, before anything is parsed.
      Handshake : SSL.Buffers.Queue;

      Flight    : SSL.Buffers.Store;

      --  How much padding to add to each outgoing record, from the
      --  configuration. Kept here because the configuration is behind a
      --  reference this record does not hold once the machines have it.
      Padding : Byte_Index := 0;

      Metadata : SSL.Connection_Metadata.Metadata :=
        SSL.Connection_Metadata.No_Metadata;

      Failure       : SSL.Errors.Failure_Record;
      Stream_Ended  : Boolean := False;
      Peer_Notified : Boolean := False;
      Truncated     : Boolean := False;
      Shutdown_Sent : Boolean := False;
      Alert_Sent    : Boolean := False;
      Alert_Value   : SSL.Alerts.Alert_Description := SSL.Alerts.Close_Notify;

      --  How many ChangeCipherSpec records the peer has sent. Bounded, because
      --  a peer that sends an unbounded run of them would otherwise be free
      --  work for it and unbounded work for this endpoint.
      Compatibility_CCS : Natural := 0;

      --  Consecutive records that carried no content. Also bounded, and for the
      --  same reason.
      Empty_Records : Natural := 0;

      --  KeyUpdates the peer has asked for. Bounded for the same reason: each
      --  one obliges an answer, and answering an unbounded run of them is
      --  unbounded work here and almost none there.
      Peer_Updates : Natural := 0;
   end record;

   function State_Of (Item : Engine) return Lifecycle is (Item.State);
   function Is_Established (Item : Engine) return Boolean is (Item.State = Established);
   function Metadata_Of (Item : Engine) return SSL.Connection_Metadata.Metadata is
     (Item.Metadata);
   function Peer_Closed (Item : Engine) return Boolean is (Item.Peer_Notified);
   function Was_Truncated (Item : Engine) return Boolean is (Item.Truncated);
   function Has_Sent_Alert (Item : Engine) return Boolean is (Item.Alert_Sent);
   function Sent_Alert (Item : Engine) return SSL.Alerts.Alert_Description is
     (Item.Alert_Value);
   function Peer_Key_Updates (Item : Engine) return Natural is (Item.Peer_Updates);
   function Tickets_Issued (Item : Engine) return Natural is (Item.Tickets_Issued);
   function Write_Generation (Item : Engine) return Natural is
     (SSL.Records.Generation_Of (Item.Write_State));
   function Read_Generation (Item : Engine) return Natural is
     (SSL.Records.Generation_Of (Item.Read_State));

end SSL.Engines;
