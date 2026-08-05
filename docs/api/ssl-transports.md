# ssl-transports

Generated from `src/ssl-transports.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

The interface between this library and whatever actually moves
octets: the transport.

`ssllib` never opens a socket, never resolves a name and never waits. It
hands an application a buffer of encrypted octets and asks for them to be
sent, and asks for encrypted octets back. What happens in between -- a TCP
socket, a Unix socket, an in-memory pipe between two tasks, a test harness
that reorders and truncates -- is entirely the application's.

That is a deliberate boundary and not an omission. A TLS library that owned
its sockets would have to own its polling, its timeouts, its name
resolution and its address families, and would then be wrong for every
application whose event loop already owns those things. Here the protocol is
a pure function of the octets it is given, which is also what makes a
handshake reproducible in a test with no network at all.

**A transport is application code, so it may raise.** Every call this
library makes into one is made inside a handler that converts an exception
into a structured failure attributed to the transport, because an exception
propagating out of a read would unwind a connection that has traffic keys
installed and buffers to scrub.

-------------------------------------------------------------------------
What a transport operation can report
-------------------------------------------------------------------------

The outcomes of a read or a write.

Every one of these is a distinct thing to do next, which is why they are
separate values rather than a Boolean and an error. `Would_Block` and
`Interrupted` both mean "try again", but only one of them means the
caller should wait first; `End_Of_Stream` and `Failed` both end the
connection, but only one of them may be an orderly close.

```ada
type Transport_Status is
  (Ok,
   --  Some octets moved. How many is reported separately, and it may be
   --  fewer than were asked for: partial transfers are normal and are not a
   --  failure.

   Would_Block,
   --  Nothing moved and nothing is wrong. A non-blocking transport with an
   --  empty receive buffer or a full send buffer says this.

   End_Of_Stream,
   --  The peer closed the underlying connection. Whether that is orderly
   --  depends on whether a close_notify arrived first, which is this
   --  library's question and not the transport's.

   Interrupted,
   --  A signal or equivalent interrupted the operation before anything
   --  moved. Retrying immediately is correct.

   Timed_Out,
   --  A deadline the transport itself was enforcing expired.

   Failed);
```

Anything else. The transport may describe it; this library will not
interpret the description.


```ada
function Image (Item : Transport_Status) return String;
```

Is this a status a caller can make progress after by simply retrying?

```ada
function Is_Retryable (Item : Transport_Status) return Boolean is
  (Item in Would_Block | Interrupted);
```

Is this a status that ends the connection?

```ada
function Is_Terminal (Item : Transport_Status) return Boolean is
  (Item in End_Of_Stream | Failed);
```

-------------------------------------------------------------------------
The interface an application implements
-------------------------------------------------------------------------

A transport this library reads encrypted octets from and writes
encrypted octets to.

Both operations are permitted to move fewer octets than asked. Neither is
permitted to move more, and a transport that reported more than it was
given room for is refused rather than believed.

```ada
type Transport is limited interface;
```

```ada
type Transport_Reference is access all Transport'Class;
```

Read up to Into'Length octets.
@param Item   the transport
@param Into   out: where to put them; only 1 .. Count is written
@param Count  out: how many octets were read, zero unless Status is Ok
@param Status out: what happened

```ada
procedure Receive
  (Item   : in out Transport;
   Into   : out Byte_Array;
   Count  : out Byte_Index;
   Status : out Transport_Status) is abstract;
```

Write up to Data'Length octets.
@param Item   the transport
@param Data   the octets to send
@param Count  out: how many were accepted, zero unless Status is Ok
@param Status out: what happened

```ada
procedure Send
  (Item   : in out Transport;
   Data   : Byte_Array;
   Count  : out Byte_Index;
   Status : out Transport_Status) is abstract;
```

Short text naming this transport, for diagnostics. Never a secret and
never a credential: something an operator can match against their own
inventory.

Abstract rather than defaulted, because a language rule forbids a
concrete operation on an interface -- and because a default of
"transport" would put that word in every diagnostic an application never
got round to naming, which is worse than being asked for one line.

```ada
function Description (Item : Transport) return String is abstract;
```

-------------------------------------------------------------------------
Calling one
-------------------------------------------------------------------------

Read from a transport, converting every failure mode into a structured
result.

This is the boundary. A transport that raises fails one connection with a
named cause rather than unwinding through a protocol driver.
@param Item   the transport
@param Into   out: the octets read
@param Count  out: how many
@param Status out: what the transport reported, or Failed when it raised
@param Error  out: No_Error, or a structured transport failure

```ada
procedure Receive_Safely
  (Item   : in out Transport'Class;
   Into   : out Byte_Array;
   Count  : out Byte_Index;
   Status : out Transport_Status;
   Error  : out SSL.Errors.Error_Information);
```

Write to a transport, with the same protection.

```ada
procedure Send_Safely
  (Item   : in out Transport'Class;
   Data   : Byte_Array;
   Count  : out Byte_Index;
   Status : out Transport_Status;
   Error  : out SSL.Errors.Error_Information);
```


