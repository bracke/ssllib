# ssl-tls13-client

Generated from `src/ssl-tls13-client.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

The TLS 1.3 client handshake, as an explicit state machine.

The states are RFC 8446 appendix A.1's, named the same way, because a reader
holding the specification open should be able to find each one. The machine
does no input and no output: it is handed one complete handshake message at
a time and answers with a plan -- send these octets, install these keys, the
handshake is finished.

A client's obligations here are almost entirely about **refusing**. A server
chooses everything: the version, the suite, the group, the protocol, the
certificate. Every one of those choices has to be checked against what this
client actually offered, because a server that selects something unoffered is
either broken or is an attacker who has rewritten the ClientHello. So each
transition below is mostly a list of things that end the connection, and the
handshake succeeding is what is left when none of them fired.

The order of the checks is fixed and it matters. The peer's certificate is
validated -- path, purpose, key usage, identity -- before its
CertificateVerify is checked, so that a signature is never verified under a
key from a certificate this client has not accepted. The peer's Finished is
checked after both, so that a transcript is never accepted from a peer that
has not proved who it is.

-------------------------------------------------------------------------
States
-------------------------------------------------------------------------

RFC 8446 appendix A.1. `Wait_Certificate_Or_Request` is the appendix's
WAIT_CERT_CR: at that point the server may send either, and which arrives
decides whether this client will be asked for a certificate.

```ada
type Client_State is
  (Start,
   Wait_Server_Hello,
   Wait_Encrypted_Extensions,
   Wait_Certificate_Or_Request,
   Wait_Certificate,
   Wait_Certificate_Verify,
   Wait_Finished,
   Connected,
   Failed);
```

```ada
function Image (Item : Client_State) return String;
```

-------------------------------------------------------------------------
The machine
-------------------------------------------------------------------------


```ada
type Machine is limited private;
```

```ada
function State_Of (Item : Machine) return Client_State;
```

```ada
function Is_Complete (Item : Machine) return Boolean;
```

What was negotiated. Meaningful once the handshake has completed.

```ada
function Outcome (Item : Machine) return Negotiated;
```

The validated peer certificate chain's outcome, for the connection
metadata: fingerprints, path length, key type.

```ada
function Peer_Certificate (Item : Machine)
  return SSL.Certificate_Validation.Validation_Result
  with Pre => Is_Complete (Item);
```

Was this client asked for a certificate, and did it send one?

```ada
function Was_Asked_For_Certificate (Item : Machine) return Boolean;
```

```ada
function Sent_Certificate (Item : Machine) return Boolean;
```

The handshake context, for the engine to derive exporters and resumption
material from after the handshake. Read-only from outside.

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

Begin the handshake: generate the ephemeral shares and produce the
ClientHello.

The configuration must outlive the machine. It is referenced rather than
copied because it is limited and because copying a policy at connection
time would be a second copy to keep in step with the first.
@param Item    out: the machine, moved to Wait_Server_Hello
@param Config  the client policy
@param Now     the wall clock, for certificate validity; may be absent,
in which case validation will refuse rather than guess
@param Source  in out: the random source
@param Into    in out: the output buffer
@param Result  out: the plan -- one Send_Handshake
@param Error   out: No_Error, or why the handshake could not start

```ada
procedure Begin_Handshake
  (Item   : in out Machine;
   Config : not null access constant SSL.Configurations.Client_Configuration;
   Now    : SSL.Clocks.Wall_Time;
   Source : in out SSL.Crypto.Random_Source;
   Into   : in out Byte_Array;
   Result : out Plan;
   Error  : out SSL.Errors.Error_Information)
  with Pre => State_Of (Item) = Start;
```

Handle one complete handshake message.

The message octets must stay valid for the duration of the call: the
certificate parser reports spans into them rather than copies, and the
transcript absorbs them as they arrived.
@param Item    in out: the machine
@param Message one complete handshake message, header included
@param Source  in out: the random source, for a retry's new key share
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

Offer a session for resumption on the next ClientHello.

Called before Begin_Handshake and nowhere else: the offer has to be in
the first message, and a session supplied later would be a session
offered in a handshake that had already committed to not resuming.
A session belongs to the version it was established under, and is
offered in that version's way: a TLS 1.3 one becomes a `pre_shared_key`
with a binder, a TLS 1.2 one becomes RFC 5077's `session_ticket`. This
routes on the session rather than making the caller choose, because the
caller has one cache and the two mechanisms are not interchangeable --
offering a TLS 1.2 master secret as a resumption PSK would be deriving
keys from a secret neither end agreed to derive them from.

```ada
procedure Offer_Session (Item : in out Machine; Value : SSL.Sessions.Session)
  with Pre => State_Of (Item) = Start;
```

Ask for a TLS 1.2 ticket without offering one.

Only meaningful when the policy offers TLS 1.2 at all; the extension is
omitted otherwise, since a server that cannot select TLS 1.2 has nothing
to issue.

```ada
procedure Request_Legacy_Tickets (Item : in out Machine; Value : Boolean)
  with Pre => State_Of (Item) = Start;
```

Did this handshake actually resume?

```ada
function Resumed (Item : Machine) return Boolean;
```

Scrub everything the machine holds.

```ada
procedure Wipe (Item : in out Machine);
```


