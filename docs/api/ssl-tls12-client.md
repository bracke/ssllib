# ssl-tls12-client

Generated from `src/ssl-tls12-client.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

The restricted TLS 1.2 client handshake, as an explicit state
machine.

Separate from the TLS 1.3 client and not a mode of it. The two protocols
differ in almost everything that matters here: TLS 1.2 negotiates its key
exchange in dedicated messages rather than in hello extensions, its server
signs the ephemeral parameters rather than the transcript, its epoch changes
on a ChangeCipherSpec rather than at a fixed point, and its key derivation
is one function applied five times rather than a labelled chain. A single
machine covering both would be two machines sharing a name.

**What this client refuses is the point.** Restricted TLS 1.2 means
ECDHE-only, AEAD-only, extended-master-secret-mandatory, and nothing else.
Every one of those refusals is a class of attack that does not apply:

* no static RSA, so no Bleichenbacher variant and no missing forward
secrecy;
* no CBC, so no MAC-then-encrypt and none of the padding oracles;
* extended master secret required, so no triple handshake;
* no renegotiation at all, so no renegotiation attack;
* no compression, so no CRIME.

A peer that cannot meet those terms gets a failed handshake with a named
reason, which is the right outcome: this library would rather not connect
than connect weakly.

Not itself marked `private`: its parent already is, so nothing outside SSL's
own subtree can name it, and marking it private as well would put it out of
reach of the in-tree test unit that drives the two machines against each
other.

-------------------------------------------------------------------------
States
-------------------------------------------------------------------------

RFC 5246 appendix F's flow, named for what is being waited for.

```ada
type Client_State is
  (Start,
   Wait_Server_Hello,
   Wait_Certificate,
   Wait_Key_Exchange,
   Wait_Request_Or_Done,
   Wait_Session_Ticket,
   --  Only on the abbreviated handshake, and only when the server promised
   --  a new ticket. The full handshake's NewSessionTicket arrives while a
   --  ChangeCipherSpec is due and needs no state of its own; this one
   --  arrives immediately after the ServerHello, before anything else, and
   --  a machine that could not name that point would have to accept the
   --  message wherever it liked.

   Wait_Change_Cipher_Spec,
   Wait_Finished,
   Connected,
   Failed);
```

```ada
function Image (Item : Client_State) return String;
```

```ada
type Machine is limited private;
```

```ada
function State_Of (Item : Machine) return Client_State;
```

```ada
function Is_Complete (Item : Machine) return Boolean;
```

```ada
function Cipher_Suite (Item : Machine) return SSL.Cipher_Suites.Cipher_Suite;
```

```ada
function Group (Item : Machine) return SSL.Supported_Groups.Named_Group;
```

```ada
function Server_Name (Item : Machine) return SSL.Server_Names.DNS_Name;
```

The application protocol that was negotiated, if any. Reported so that a
finished TLS 1.2 connection can say what it agreed to rather than saying
nothing, which is what it used to say.

```ada
function Has_Protocol (Item : Machine) return Boolean;
```

```ada
function Protocol (Item : Machine) return SSL.ALPN.Protocol_Name
  with Pre => Has_Protocol (Item);
```

```ada
function Peer_Scheme (Item : Machine) return SSL.Signature_Schemes.Signature_Scheme;
```

```ada
function Peer_Certificate (Item : Machine)
  return SSL.Certificate_Validation.Validation_Result;
```

The keys this handshake derived, for the driver to install. Read-only
from outside; there is no way to reach the master secret.

```ada
function Client_Keys (Item : aliased Machine) return access constant Direction_Keys;
```

```ada
function Server_Keys (Item : aliased Machine) return access constant Direction_Keys;
```

Did this handshake resume a session rather than establish one?

```ada
function Resumed (Item : Machine) return Boolean;
```

-------------------------------------------------------------------------
Tickets (RFC 5077)
-------------------------------------------------------------------------

Ask for a ticket in the hello, whether or not one is being offered.

A client with nowhere to put a ticket should not ask for one: the server
would seal its own state, send it, and have it dropped.

```ada
procedure Request_Tickets (Item : in out Machine; Value : Boolean)
  with Pre => State_Of (Item) = Start;
```

Offer a cached session for resumption.

The session is copied, because it holds a secret and this machine must
not depend on a cache entry surviving the handshake that is using it.
Offering also implies asking: a client that offers a ticket has somewhere
to put the next one.

```ada
procedure Offer_Session (Item : in out Machine; Value : SSL.Sessions.Session)
  with Pre => State_Of (Item) = Start;
```

What this machine will put in the `session_ticket` extension, for a
driver that encodes the hello itself.

The engine's client sends one hello for both versions, encoded by the
TLS 1.3 machine, so the octets have to be reachable from here before this
machine has seen anything.
`Offers_Ticket` says whether to send the extension at all;
`Offered_Ticket` says what to put in it, and an empty answer is the
request form rather than an absent one. There is deliberately no
precondition tying the two: an empty ticket is a legal thing to send, so
a caller that asked for the octets without asking whether to send them
has made no mistake to detect.

```ada
function Offers_Ticket (Item : Machine) return Boolean;
```

```ada
function Offered_Ticket (Item : Machine) return Byte_Array;
```

Take the session a NewSessionTicket established, if one arrived.

The machine assembles it rather than handing out the master secret: the
three bindings it cannot know are passed in, and the secret never leaves.
@param Item    the machine; its held session is wiped by this call
@param Context the security context in force
@param Setup   the configuration's fingerprint
@param Anchors the trust snapshot's fingerprint
@param Into    in out: receives the session
@param Present out: whether there was one

```ada
procedure Take_New_Session
  (Item    : in out Machine;
   Context : Security_Context_ID;
   Setup   : Configuration_Fingerprint;
   Anchors : Trust_Fingerprint;
   Into    : in out SSL.Sessions.Session;
   Present : out Boolean);
```

-------------------------------------------------------------------------
Driving it
-------------------------------------------------------------------------

Begin the handshake: generate the ephemeral keypair and produce the
ClientHello.

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

Adopt a ClientHello that has already been sent.

For a connection that offered both versions in one hello and found the
server wanted TLS 1.2. The hello is already on the wire and already in
the peer's transcript, so this machine takes it as given rather than
producing another: sending a second hello would be a second handshake,
and the extra round trip is what a downgrade attacker wants to provoke.
@param Item          out: the machine, at Wait_Server_Hello
@param Config        the client policy
@param Now           the wall clock
@param Hello         the ClientHello exactly as it was sent
@param Random_Value  the random inside it
@param Session_Id    the legacy session identifier inside it
@param Error         out: No_Error, or why it could not be adopted

```ada
procedure Adopt_Hello
  (Item         : in out Machine;
   Config       : not null access constant SSL.Configurations.Client_Configuration;
   Now          : SSL.Clocks.Wall_Time;
   Hello        : Byte_Array;
   Random_Value : SSL.Handshake_Messages.Random_Bytes;
   Session_Id   : Byte_Array;
   Error        : out SSL.Errors.Error_Information)
  with Pre => State_Of (Item) = Start and then Session_Id'Length <= 32;
```

Handle one complete handshake message.

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

Handle the peer's ChangeCipherSpec, which is the epoch switch.

A separate operation because it is not a handshake message: it has its
own record type, it is not in the transcript, and it changes what the
next record is protected under. Treating it as a handshake message would
put it in the transcript and every Finished would fail.

```ada
procedure Handle_Change_Cipher_Spec
  (Item   : in out Machine;
   Result : out Plan;
   Error  : out SSL.Errors.Error_Information);
```

```ada
procedure Wipe (Item : in out Machine);
```


