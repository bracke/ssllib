# ssl-blocking

Generated from `src/ssl-blocking.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

Blocking operations over a connection, for callers who do not have
an event loop of their own.

Every operation here is the same loop: do what can be done, and if that was
nothing, wait a little and try again, until the work is finished or the
deadline passes. That loop is small enough that an application could write
it -- and this package exists because every application would write it
slightly differently, and the differences are exactly the short-read and
partial-write cases that are easy to get wrong and hard to test.

**Nothing here is more capable than the non-blocking API.** It is the same
operations with a wait in front of them, and the wait is a plain delay
rather than a poll on a file descriptor, because this library does not know
what a transport is made of. An application whose transport can be selected
on should use `SSL.Connections` with its own event loop and will get better
latency; this is for the straightforward case where that is not worth it.

Every operation takes a deadline. A blocking call with no deadline is a
program that can stop responding because a peer stopped talking, and there
is no default this library could pick that would be right.

Run the handshake to completion.

@param Item     the connection, which must have been started
@param Until_At the deadline; the call fails with Code_Deadline_Reached
rather than waiting past it
@param Error    out: No_Error once established, or the failure

```ada
procedure Handshake
  (Item     : in out SSL.Connections.Connection;
   Until_At : SSL.Clocks.Deadline;
   Error    : out SSL.Errors.Error_Information);
```

Read at least one octet, up to Into'Length.

Returns as soon as anything is available, which is what a stream read
should do: waiting for a full buffer would add latency no application
asked for. A peer that closed cleanly gives a zero count and no failure,
which is how end of stream is reported.

```ada
procedure Read_Some
  (Item     : in out SSL.Connections.Connection;
   Into     : out Byte_Array;
   Count    : out Byte_Index;
   Until_At : SSL.Clocks.Deadline;
   Error    : out SSL.Errors.Error_Information);
```

Read exactly Into'Length octets.

A peer that closes before they all arrive is a failure here, unlike in
Read_Some: a caller that asked for a fixed number of octets and got fewer
has an incomplete structure, and treating that as success is how a
truncation becomes a parse of half a message.

```ada
procedure Read_Exactly
  (Item     : in out SSL.Connections.Connection;
   Into     : out Byte_Array;
   Until_At : SSL.Clocks.Deadline;
   Error    : out SSL.Errors.Error_Information);
```

Write at least one octet, up to Data'Length.

```ada
procedure Write_Some
  (Item     : in out SSL.Connections.Connection;
   Data     : Byte_Array;
   Count    : out Byte_Index;
   Until_At : SSL.Clocks.Deadline;
   Error    : out SSL.Errors.Error_Information);
```

Write all of Data, and get it onto the transport.

Returning before the octets have actually been sent would leave them in a
queue an application has no reason to know about, so this drains the
output as well as accepting the plaintext.

```ada
procedure Write_All
  (Item     : in out SSL.Connections.Connection;
   Data     : Byte_Array;
   Until_At : SSL.Clocks.Deadline;
   Error    : out SSL.Errors.Error_Information);
```

Close down in an orderly way: send close_notify, and wait for the peer's.

Waiting for the peer's is what makes the close orderly in both
directions. A caller that does not care can stop after the send by
passing Await_Peer => False, which is correct when the application
protocol has its own framing and truncation cannot be mistaken for
completion.

```ada
procedure Shutdown
  (Item       : in out SSL.Connections.Connection;
   Until_At   : SSL.Clocks.Deadline;
   Error      : out SSL.Errors.Error_Information;
   Await_Peer : Boolean := True);
```


