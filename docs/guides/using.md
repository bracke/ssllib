# Using ssllib

Covers the quickstart, configuration, the client and server APIs, the blocking
API, the engine, and transports. One document rather than six, because the six
would say the same things about the same four types and a reader following a
connection from `Build` to `Shutdown` would be reading them in order anyway.

The reference for every declaration named here is under `docs/api/`, generated
from the specifications themselves.

## The shortest client that is not wrong

```ada
declare
   Anchors : aliased SSL.Trust.Snapshot;
   Setup   : aliased SSL.Configurations.Client_Configuration;
   Builder : SSL.Configurations.Client_Builder;
   Item    : SSL.Connections.Connection;
   Error   : SSL.Errors.Error_Information;
   Ok      : Boolean;
begin
   SSL.Trust.Load_Native_Anchors (Anchors, Now, SSL.Limits.Default_Limits, Error);

   SSL.Configurations.Secure_Client_Defaults (Builder);
   SSL.Configurations.Set_Expected_Name
     (Builder, SSL.Server_Names.Name ("example.com"), Ok);
   SSL.Configurations.Set_Anchors (Builder, Anchors'Access, Ok);
   SSL.Configurations.Build (Builder, Setup, Error);

   SSL.Clients.Connect (Item, Setup'Access, Medium, SSL.No_Connection, Now, Error);
   SSL.Blocking.Handshake (Item, SSL.Clocks.In_Milliseconds (10_000), Error);
end;
```

Four things in that fragment are load-bearing.

**`Set_Expected_Name` is not optional.** A client configuration without an
expected identity is refused at `Build`, because a client that does not say what
it expects cannot have its expectation checked, and a library that filled one in
from the address would be verifying the attacker's answer.

**The anchors and the configuration must outlive the connection.** They are
referenced, not copied: a configuration is immutable after `Build` and a trust
snapshot is a shared, immutable set. Ada's accessibility rules enforce this, and
a program that declares either inside a subprogram meets that enforcement at
compile time rather than at run time.

**`Now` is a parameter.** The wall clock enters the library from the caller, so
that certificate validity is checked against a time the application chose and a
test can hand over a fixed one.

**There is no flag that turns verification off.** Not disabled by default —
absent. Nothing in `SSL.Configurations` accepts a value that would skip path
validation or identity checking.

## Servers

The same shape, with `Secure_Server_Defaults`, `Add_Credential` and
`SSL.Servers.Accept_Connection`. A server says nothing until a ClientHello
arrives, which is why `Accept_Connection` produces no output of its own.

Ticket issuance is refused at `Build` unless a ticket-key ring is attached. That
is the specified "tickets disabled until valid ticket keys are configured",
enforced rather than documented: a server that issued tickets under a key it
invented would issue tickets that survive nothing, including its own restart.

## The three ways to drive a connection

**Blocking** — `SSL.Blocking`. Every operation takes a deadline. Suits a
thread-per-connection program.

**Event loop** — `SSL.Connections.Step`, `Pump_Input`, `Pump_Output`,
`Read_Available`, `Write_Available`, with `Ready` and `Events` to decide what to
wait for. Nothing blocks. Suits a program with its own selector, and it is the
only API that lets one task drive many connections.

**Streams** — `SSL.Streams`, an `Ada.Streams.Root_Stream_Type` over a
connection, for code that already speaks streams. It raises, because the
inherited interface has no other way to report failure; that is the single
exception to this library's "failures are results" rule and it is inherited
rather than chosen.

`SSL.Synchronized_Connections` adds one reader task, one writer task and a
controller over a serialized driver. It is not a fourth way to drive a
connection so much as a way to share one of the first three.

## Transports

A transport is twenty lines. Implement `SSL.Transports.Transport` with
`Receive`, `Send` and `Description`; report `Ok`, `Would_Block`,
`End_Of_Stream` or `Failed`; never raise. The library catches exceptions at that
boundary anyway and turns them into structured failures, but a transport that
returns a status keeps its own contract true rather than nearly true.

The library does no input or output of any kind. `tests/src/tools/ssllib_peer.adb`
is a complete worked example over `GNAT.Sockets`, and it is the only place in the
repository that opens a socket.

## Shutting down

`SSL.Blocking.Shutdown`, or `SSL.Connections.Begin_Shutdown` plus pumping. It
sends a `close_notify`, and it matters: a peer that sees the connection end
without one reports a truncation attack, correctly. Every stack this library is
tested against does.
