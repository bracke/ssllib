# ssl-synchronized_connections

Generated from `src/ssl-synchronized_connections.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

One connection used from several tasks: a reader, a writer, and a
controller that can shut it down or cancel it.

`SSL.Connections.Connection` is one-task-at-a-time, deliberately. It holds a
protocol driver with sequence numbers, a transcript and traffic keys, and
two tasks stepping it at once would interleave records under one sequence
number space -- which is not a race that shows up as a wrong answer, it is a
race that shows up as a connection the peer terminates. So the base type
makes no attempt to be task-safe and says so.

This wrapper is the specification's optional synchronized form: **one reader
task, one writer task, and a shutdown or cancellation controller, over a
serialized driver**. Nothing here makes a connection faster or lets two
tasks read; it makes the three roles above safe, and it refuses to pretend
to more than that.

**How it serializes.** Every operation that touches the driver holds an
exclusive lock for the duration of one step, and releases it before waiting.
The lock is a protected object; the *work* happens outside any protected
body, because the work calls a transport, a transport is the application's
own code, and calling application code from inside a protected body is a
bounded error in Ada whatever the code does.

**Why the reader polls.** `Read` waits for data by taking the lock, doing
one step, releasing it, and -- if nothing arrived -- sleeping briefly before
trying again. It cannot sleep on the transport instead, because
`SSL.Transports` reports "nothing available" and offers no way to wait for
that to change; a wrapper that wanted to block until readable would need a
facility the transport interface does not have. The sleep is short and the
cost is a wakeup per millisecond on an idle connection. An application that
cannot pay it should use the event-loop API and its own selector, which is
what that API is for.

**What it does not do.** No second reader, no second writer, no queueing of
writes behind one another beyond the lock's own ordering, and no attempt to
make `Metadata_Of` and `Read` atomic with respect to each other. Two readers
will not corrupt the driver -- the lock prevents that -- but they will take
each other's data, which is not something a lock can fix and not something
this wrapper claims to.

```ada
type Synchronized_Connection is limited private;
```

-------------------------------------------------------------------------
Starting one
-------------------------------------------------------------------------

Both of these are called from one task, before the reader and the writer
start. A connection being set up is not yet shared.


```ada
procedure Connect
  (Item     : in out Synchronized_Connection;
   Config   : not null access constant SSL.Configurations.Client_Configuration;
   Medium   : not null SSL.Transports.Transport_Reference;
   Identity : Connection_ID;
   Now      : SSL.Clocks.Wall_Time;
   Error    : out SSL.Errors.Error_Information);
```

```ada
procedure Accept_Connection
  (Item     : in out Synchronized_Connection;
   Config   : not null access constant SSL.Configurations.Server_Configuration;
   Medium   : not null SSL.Transports.Transport_Reference;
   Identity : Connection_ID;
   Now      : SSL.Clocks.Wall_Time;
   Error    : out SSL.Errors.Error_Information);
```

Drive the handshake to completion, or to the deadline.

Also called before the reader and the writer start, for the same reason:
until the handshake finishes there is no application data for either of
them to move.
@param Item     the connection
@param Expires  when to give up
@param Error    out: No_Error, or the failure, or a timeout

```ada
procedure Handshake
  (Item  : in out Synchronized_Connection;
   Expires : SSL.Clocks.Deadline;
   Error : out SSL.Errors.Error_Information);
```

-------------------------------------------------------------------------
The reader task
-------------------------------------------------------------------------

Wait for application data and take it.

Returns as soon as anything arrives, when the peer closes, when the
connection fails, when the controller cancels, or at the deadline --
whichever comes first. `Count = 0` with no error means the deadline
passed with nothing to report, which is an ordinary answer and not a
failure.
@param Item  the connection
@param Into  out: the data
@param Count out: how much, possibly zero
@param Expires when to give up waiting
@param Error out: No_Error, or the failure that ended the connection

```ada
procedure Read
  (Item  : in out Synchronized_Connection;
   Into  : out Byte_Array;
   Count : out Byte_Index;
   Expires : SSL.Clocks.Deadline;
   Error : out SSL.Errors.Error_Information);
```

-------------------------------------------------------------------------
The writer task
-------------------------------------------------------------------------

Offer application data and push it out.

Keeps offering and pumping until everything is accepted, the connection
ends, the controller intervenes, or the deadline passes. A partial write
is reported rather than hidden: `Written` says how much reached the
connection, and the caller decides what to do about the rest.

```ada
procedure Write
  (Item    : in out Synchronized_Connection;
   Data    : Byte_Array;
   Written : out Byte_Index;
   Expires : SSL.Clocks.Deadline;
   Error   : out SSL.Errors.Error_Information);
```

-------------------------------------------------------------------------
The controller
-------------------------------------------------------------------------

Ask for an orderly shutdown.

Requested rather than performed: the reader or the writer may be holding
the driver, and a controller that waited for the lock would be a
controller that cannot interrupt a busy connection -- which is the one
thing it exists to do. The request is honoured by whichever task next
reaches a step boundary, and by `Close` if no other task is running.

Safe to call from any task, including while the reader is waiting.

```ada
procedure Request_Shutdown (Item : in out Synchronized_Connection);
```

Cancel, for the same reasons and with the same immediacy.

A cancelled connection stops at the next step boundary and reports
cancellation to whichever task was waiting.

There is no token parameter. `SSL.Cancellation.Token` is limited, which
is deliberate -- a token that could be copied could be copied
half-cancelled -- and it means a wrapper cannot hold the caller's. So
this holds one of its own and cancels that. An application that wants one
token across several connections cancels each of them.

```ada
procedure Cancel (Item : in out Synchronized_Connection);
```

Whether a shutdown or a cancellation has been asked for. Readable from
any task; it answers about the request, not about what has happened yet.

```ada
function Shutdown_Requested (Item : Synchronized_Connection) return Boolean;
```

```ada
function Cancel_Requested (Item : Synchronized_Connection) return Boolean;
```

Carry out a requested shutdown and wait for the peer's, or the deadline.

Called from one task once the reader and writer have stopped. Doing it
while they run would be a third task on the driver, which is exactly what
the lock serializes but not what the three-role design describes.

```ada
procedure Close
  (Item  : in out Synchronized_Connection;
   Expires : SSL.Clocks.Deadline;
   Error : out SSL.Errors.Error_Information);
```

-------------------------------------------------------------------------
Asking about it
-------------------------------------------------------------------------

Each of these takes the lock, copies out, and releases it, so what a
caller receives is a consistent snapshot of one instant rather than a
view that could change under it.

```ada
function State_Of (Item : in out Synchronized_Connection)
  return SSL.Engines.Lifecycle;
```

```ada
function Is_Established (Item : in out Synchronized_Connection) return Boolean;
```

```ada
function Is_Terminal (Item : in out Synchronized_Connection) return Boolean;
```

```ada
function Metadata_Of (Item : in out Synchronized_Connection)
  return SSL.Connection_Metadata.Metadata;
```

```ada
function Failure_Of (Item : in out Synchronized_Connection)
  return SSL.Errors.Error_Information;
```

Forget everything, from one task, once nothing else is using it.

```ada
procedure Wipe (Item : in out Synchronized_Connection);
```


