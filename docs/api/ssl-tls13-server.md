# ssl-tls13-server

Generated from `src/ssl-tls13-server.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

The TLS 1.3 server handshake, as an explicit state machine.

The states are RFC 8446 appendix A.2's. Like the client machine, this one
does no input and no output: it is handed one complete handshake message and
answers with an ordered plan.

A server's position is the opposite of a client's. It **chooses** -- the
version, the suite, the group, the credential, the protocol -- and every
choice is made from the intersection of what the client offered and what
this configuration permits, with the configuration deciding whose preference
order wins. What a server has to refuse is different too: it is the first
thing an unauthenticated peer talks to, and the ClientHello is the largest
attacker-chosen structure it will ever parse.

The one thing a server must be careful about that a client need not: it
writes its own certificate, and it signs a transcript. Both happen after the
suite is settled and before the client has said anything else, so the
ordering here is fixed by construction rather than by a flag.

Not itself marked `private`: its parent already is, so nothing outside
SSL's own subtree can name it, and marking it private as well would put it
out of reach of the in-tree test unit that drives the two machines against
each other.

-------------------------------------------------------------------------
States
-------------------------------------------------------------------------

RFC 8446 appendix A.2, minus the early-data states, which do not exist
here because this library does not implement 0-RTT.

```ada
type Server_State is
  (Start,
   Received_Client_Hello,
   Wait_Second_Client_Hello,
   Wait_Client_Flight,
   Wait_Client_Certificate_Verify,
   Wait_Client_Finished,
   Connected,
   Failed);
```

```ada
function Image (Item : Server_State) return String;
```

-------------------------------------------------------------------------
The machine
-------------------------------------------------------------------------


```ada
type Machine is limited private;
```

```ada
function State_Of (Item : Machine) return Server_State;
```

```ada
function Is_Complete (Item : Machine) return Boolean;
```

```ada
function Outcome (Item : Machine) return Negotiated;
```

Did the client authenticate, and with what?

```ada
function Client_Authenticated (Item : Machine) return Boolean;
```

```ada
function Client_Certificate (Item : Machine)
  return SSL.Certificate_Validation.Validation_Result
  with Pre => Client_Authenticated (Item);
```

```ada
function Context_Of (Item : aliased Machine) return access constant Handshake_Context;
```

The key schedule, for the operations that outlive the handshake:
KeyUpdate, exporters, and resumption material. Mutable, because
advancing a traffic secret changes it -- which is the only thing the
engine is allowed to do to a finished handshake's state.

```ada
function Schedule_Of (Item : aliased in out Machine) return access SSL.Key_Schedule.Schedule;
```

-------------------------------------------------------------------------
Driving it
-------------------------------------------------------------------------

Prepare the machine. No message is produced: a server says nothing until
it has heard a ClientHello.
@param Item   out: the machine, moved to Received_Client_Hello
@param Config the server policy
@param Now    the wall clock, for certificate validity

```ada
procedure Begin_Handshake
  (Item   : in out Machine;
   Config : not null access constant SSL.Configurations.Server_Configuration;
   Now    : SSL.Clocks.Wall_Time;
   Error  : out SSL.Errors.Error_Information)
  with Pre => State_Of (Item) = Start;
```

Attach the ticket keys this server may open a client's offer with.

Called before the first message and nowhere else. Without a ring a server
never resumes, which is a state rather than a failure: every handshake is
a full one.

```ada
procedure Set_Ticket_Keys
  (Item  : in out Machine;
   Value : SSL.Ticket_Keys.Ring_Reference)
  with Pre => State_Of (Item) = Received_Client_Hello;
```

Did this handshake resume?

```ada
function Resumed (Item : Machine) return Boolean;
```

Handle one complete handshake message.

The first call carries the ClientHello and produces the whole server
flight -- ServerHello, then everything from EncryptedExtensions to
Finished under handshake keys -- as a sequence of steps with the key
installations in their right places between them.
@param Item    in out: the machine
@param Message one complete handshake message, header included
@param Source  in out: the random source
@param Into    in out: the output buffer
@param Result  out: what the driver must do, in order
@param Error   out: No_Error, or the failure that ends the connection

```ada
procedure Handle_Message
  (Item    : in out Machine;
   Message : Byte_Array;
   Source  : in out SSL.Crypto.Random_Source;
   Into    : in out Byte_Array;
   Result  : out Plan;
   Error   : out SSL.Errors.Error_Information)
  with Pre => State_Of (Item) not in Start | Failed;
```

```ada
procedure Wipe (Item : in out Machine);
```


