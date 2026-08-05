# ssl-engines

Generated from `src/ssl-engines.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

The protocol driver: encrypted octets in, encrypted octets out,
application data in between. No transport, no tasking, no waiting.

An engine is the whole of TLS with the I/O taken out. It is fed the octets a
transport read, and it produces the octets a transport should write; it is
given plaintext to send, and it hands back plaintext that arrived. It never
calls a socket, never blocks, and never starts a task. `SSL.Blocking` puts a
transport and a loop around one for callers who want that, and an
application with its own event loop can drive one directly.

**Everything is partial.** Every operation reports how much it actually
consumed or produced, and every one of them may report zero without that
being a failure. A transport that delivered half a record, an application
that offered more plaintext than the output queue can hold, an output queue
that a transport accepted only part of -- all of these are ordinary, and an
engine that treated any of them as an error would be unusable with
non-blocking I/O.

**Nothing here waits, so nothing here can time out on its own.** Deadlines
are the caller's: `Advance` is given the current monotonic time and reports
a deadline as reached, and the caller decides what that means. The wall
clock is a separate thing and is used only for certificate validity, because
the two answer different questions and a system whose wall clock moves must
not thereby change when a read gives up.

-------------------------------------------------------------------------
Lifecycle
-------------------------------------------------------------------------

Where a connection is. The specification's lifecycle, exactly.

These are one-way. A connection that has failed does not return to
handshaking, and a closed one does not reopen: an engine is single-use,
and reuse is a new engine. That is what stops a connection from carrying
state across a failure it was supposed to have ended.

```ada
type Lifecycle is
  (Uninitialized,
   Ready,
   Handshaking,
   Established,
   Closing,
   Closed,
   Failed);
```

```ada
function Image (Item : Lifecycle) return String;
```

Is this a state from which nothing more will happen?

```ada
function Is_Terminal (Item : Lifecycle) return Boolean is (Item in Closed | Failed);
```

-------------------------------------------------------------------------
The engine
-------------------------------------------------------------------------

Limited and single-use. It holds traffic keys and a key schedule, so it
cannot be copied; it scrubs them, so it is controlled.

```ada
type Engine is limited private;
```

```ada
function State_Of (Item : Engine) return Lifecycle;
```

```ada
function Is_Established (Item : Engine) return Boolean;
```

What was negotiated. Meaningful once the handshake has completed; before
that it reports itself as not established.

```ada
function Metadata_Of (Item : Engine) return SSL.Connection_Metadata.Metadata;
```

The first failure this connection suffered, preserved. Later failures are
counted but never displace it, because the first one is the cause and the
rest are usually consequences.

```ada
function Failure_Of (Item : Engine) return SSL.Errors.Error_Information;
```

-------------------------------------------------------------------------
Starting one
-------------------------------------------------------------------------

Prepare a client engine.

The configuration must outlive the engine. It is referenced rather than
copied: a configuration is immutable after Build and shareable between
connections, and copying it per connection would be a copy to keep in
step with the original for no gain.
@param Item     out: the engine, in Ready
@param Config   the client policy
@param Identity this connection's stable identifier, for correlating logs
@param Now      the wall clock, for certificate validity
@param Error    out: No_Error, or why it could not start

```ada
procedure Start_Client
  (Item     : in out Engine;
   Config   : not null access constant SSL.Configurations.Client_Configuration;
   Identity : Connection_ID;
   Now      : SSL.Clocks.Wall_Time;
   Error    : out SSL.Errors.Error_Information)
  with Pre => State_Of (Item) = Uninitialized;
```

Prepare a server engine.

```ada
procedure Start_Server
  (Item     : in out Engine;
   Config   : not null access constant SSL.Configurations.Server_Configuration;
   Identity : Connection_ID;
   Now      : SSL.Clocks.Wall_Time;
   Error    : out SSL.Errors.Error_Information)
  with Pre => State_Of (Item) = Uninitialized;
```

-------------------------------------------------------------------------
Encrypted input
-------------------------------------------------------------------------

Supply octets a transport read.

Consumed may be fewer than Data'Length: the input buffer is bounded, and
a caller that read more than fits should keep the rest and offer it after
the next Advance. It may be zero when the buffer is already full, which
is backpressure and not a failure.
@param Item     the engine
@param Data     the octets read from the transport
@param Consumed out: how many were taken
@param Error    out: No_Error, or a terminal failure

```ada
procedure Supply_Encrypted
  (Item     : in out Engine;
   Data     : Byte_Array;
   Consumed : out Byte_Index;
   Error    : out SSL.Errors.Error_Information);
```

Tell the engine the transport reached end of stream.

Whether that is orderly is this library's judgement and not the
transport's: a stream that ended after a close_notify closed properly,
and one that ended before it was truncated -- which is an attack when the
application protocol has no length of its own.

```ada
procedure Report_End_Of_Stream
  (Item  : in out Engine;
   Error : out SSL.Errors.Error_Information);
```

Tell the engine the transport failed. The connection ends; the
description is recorded and never interpreted.

```ada
procedure Report_Transport_Failure
  (Item   : in out Engine;
   Reason : String);
```

-------------------------------------------------------------------------
Encrypted output
-------------------------------------------------------------------------

How many encrypted octets are waiting to be sent.

```ada
function Pending_Encrypted (Item : Engine) return Byte_Index;
```

Look at the queued encrypted output without consuming it.

Peek and consume are separate because a transport that accepted only part
of a write must be able to say so, and a design where peeking consumed
would lose the remainder.
@param Item  the engine
@param Into  out: receives up to Into'Length octets
@param Count out: how many were copied

```ada
procedure Peek_Encrypted
  (Item  : Engine;
   Into  : out Byte_Array;
   Count : out Byte_Index);
```

Drop octets a transport has accepted.
@param Item  the engine
@param Count how many the transport took; must not exceed what is pending

```ada
procedure Consume_Encrypted (Item : in out Engine; Count : Byte_Index)
  with Pre => Count <= Pending_Encrypted (Item);
```

-------------------------------------------------------------------------
Application data
-------------------------------------------------------------------------

Offer plaintext to send.

Accepted may be fewer than Data'Length, or zero, when the output queue is
full. Nothing is sent until the caller drains the encrypted output, so an
application that never drains will find this returning zero rather than
growing a buffer without limit.
@param Item     the engine, which must be Established
@param Data     the plaintext
@param Accepted out: how much was taken
@param Error    out: No_Error, or a terminal failure

```ada
procedure Write_Plaintext
  (Item     : in out Engine;
   Data     : Byte_Array;
   Accepted : out Byte_Index;
   Error    : out SSL.Errors.Error_Information);
```

How much authenticated application data is waiting to be read.

```ada
function Pending_Plaintext (Item : Engine) return Byte_Index;
```

Look at received application data without consuming it.

```ada
procedure Peek_Plaintext
  (Item  : Engine;
   Into  : out Byte_Array;
   Count : out Byte_Index);
```

Drop application data the caller has taken.

```ada
procedure Consume_Plaintext (Item : in out Engine; Count : Byte_Index)
  with Pre => Count <= Pending_Plaintext (Item);
```

-------------------------------------------------------------------------
Driving it
-------------------------------------------------------------------------

Do whatever can be done with what is already here.

This is where records are parsed, handshake messages are processed,
alerts are acted on and output is produced. It never waits: given nothing
to work with it does nothing and says so.
@param Item  the engine
@param Now   the current monotonic time, for deadlines
@param Error out: No_Error, or the failure that ended the connection

```ada
procedure Advance
  (Item  : in out Engine;
   Now   : SSL.Clocks.Monotonic_Time;
   Error : out SSL.Errors.Error_Information);
```

-------------------------------------------------------------------------
Sessions
-------------------------------------------------------------------------

Issue a session ticket, if this endpoint is a server that may.

Called by the engine itself when a handshake completes; exposed so that
an application with a reason to issue another one can. A server with no
active ticket key, or with ticket issuance disabled, does nothing and
reports no failure: not issuing is a state, not an error.

```ada
procedure Issue_Ticket
  (Item  : in out Engine;
   Error : out SSL.Errors.Error_Information);
```

How many tickets this connection has issued.

```ada
function Tickets_Issued (Item : Engine) return Natural;
```

Ask the peer to update its keys, and update this endpoint's own write key.

RFC 8446 section 7.2. The KeyUpdate message itself goes out under the
*old* key -- installing the new one first would produce a message the
peer cannot read -- so the message is queued and the key is installed
immediately afterwards, in that order and in one operation, because a
caller who could do one without the other could desynchronize the
connection.

A caller need not do this: the engine schedules its own updates as usage
approaches the configured thresholds. This exists for an application with
a policy of its own -- a long-lived connection that updates on a timer,
say.
@param Item          the engine, which must be Established
@param Ask_Peer      True to require an answering KeyUpdate from the peer
@param Error         out: No_Error, or the failure

```ada
procedure Request_Key_Update
  (Item     : in out Engine;
   Ask_Peer : Boolean;
   Error    : out SSL.Errors.Error_Information);
```

How many times each direction's key has been replaced. Part of the
no-nonce-reuse argument, and something an operator watching a long-lived
connection wants to see.

```ada
function Write_Generation (Item : Engine) return Natural;
```

```ada
function Read_Generation (Item : Engine) return Natural;
```

How many KeyUpdates the peer has asked for. Bounded: answering an
unbounded run of them is unbounded work for this endpoint and almost
none for the peer.

```ada
function Peer_Key_Updates (Item : Engine) return Natural;
```

-------------------------------------------------------------------------
Exported key material
-------------------------------------------------------------------------

Derive exported key material from this connection (RFC 8446 section 7.5).

Available only after the handshake has completed, because before that
there is no exporter master secret and anything this produced would not
be bound to a connection either end had authenticated.

There is no getter for the exporter master secret itself, here or
anywhere: a caller can ask for material derived under a label, and cannot
ask for the thing it is derived from.
@param Item        the engine, which must be Established
@param Label       the exporter label
@param Context     the context octets
@param Has_Context whether a context was supplied at all. Under TLS 1.3
this makes no difference to the output: RFC 8446
section 7.5 defines an absent context as the empty
string. It is a parameter because TLS 1.2's exporter
(RFC 5705) does distinguish them
@param Into        out: the exported material
@param Error       out: No_Error, or the failure

```ada
procedure Export_Keying_Material
  (Item        : Engine;
   Label       : String;
   Context     : Byte_Array;
   Has_Context : Boolean;
   Into        : out Byte_Array;
   Error       : out SSL.Errors.Error_Information);
```

Begin an orderly shutdown: queue a close_notify.

The connection is not closed until the queued alert has actually been
sent, which is why this is a request and not an action.

```ada
procedure Begin_Shutdown
  (Item  : in out Engine;
   Error : out SSL.Errors.Error_Information);
```

Give up on this connection now.

Not the same as a shutdown: nothing is queued and nothing is waited for.
For a caller whose own deadline has passed or whose user has cancelled.

```ada
procedure Cancel (Item : in out Engine; Reason : SSL.Cancellation.Token);
```

Set a deadline. Advance reports it as reached once the monotonic clock
passes it; nothing here enforces it, because nothing here waits.

```ada
procedure Set_Deadline (Item : in out Engine; Value : SSL.Clocks.Deadline);
```

-------------------------------------------------------------------------
Readiness
-------------------------------------------------------------------------

What the caller should do next. Several may be true at once, which is why
this is a set of questions rather than one answer.

```ada
type Readiness is record
   Wants_Transport_Read  : Boolean := False;
```

```ada
function Ready (Item : Engine) return Readiness;
```

-------------------------------------------------------------------------
Scrubbing
-------------------------------------------------------------------------

Scrub every key and buffer now rather than at end of scope.

```ada
procedure Wipe (Item : in out Engine);
```

Did the peer send a close_notify?

```ada
function Peer_Closed (Item : Engine) return Boolean;
```

Did the transport end without one? The truncation this library detects
when the configuration asks it to.

```ada
function Was_Truncated (Item : Engine) return Boolean;
```

The alert this endpoint sent, when it sent one. For diagnostics: an
operator correlating two ends of a failed connection needs to know which
alert travelled.

```ada
function Sent_Alert (Item : Engine) return SSL.Alerts.Alert_Description;
```

```ada
function Has_Sent_Alert (Item : Engine) return Boolean;
```


