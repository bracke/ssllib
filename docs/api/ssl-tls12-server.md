# ssl-tls12-server

Generated from `src/ssl-tls12-server.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

The restricted TLS 1.2 server handshake, as an explicit state
machine.

The mirror of `SSL.TLS12.Client`, and separate from the TLS 1.3 server for
the same reasons. What it insists on is the same list: ECDHE, AEAD,
extended master secret, null compression, no renegotiation. A client that
cannot meet those terms gets a failed handshake with a named reason.

One thing worth stating that is easy to miss: this server **signs the
ephemeral parameters**, not the transcript. That is the TLS 1.2 design, and
it is why the signed content is assembled from the two randoms and the exact
parameter octets rather than from a hash of everything so far. A server that
signed something else would produce a handshake no client completes; a
client that verified something else would accept a substituted share.

```ada
type Server_State is
  (Start,
   Received_Client_Hello,
   Wait_Client_Key_Exchange,
   Wait_Client_Change_Cipher_Spec,
   Wait_Client_Finished,
   Connected,
   Failed);
```

```ada
function Image (Item : Server_State) return String;
```

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

The keys tickets are sealed under.

Without a ring this server issues nothing and accepts nothing, which is
the specified "tickets disabled until valid ticket keys are configured":
a server that issued tickets under a key it invented would be a server
whose tickets survive nothing, including its own restart.

```ada
procedure Set_Ticket_Keys
  (Item  : in out Machine;
   Value : SSL.Ticket_Keys.Ring_Reference)
  with Pre => State_Of (Item) = Start;
```

Whether to issue tickets at all. Separate from having a ring, because a
server may need to open the tickets it has already issued while it stops
issuing new ones.

```ada
procedure Set_Issues_Tickets (Item : in out Machine; Value : Boolean)
  with Pre => State_Of (Item) = Start;
```

Prepare the machine. A server says nothing until it hears a ClientHello.

```ada
procedure Begin_Handshake
  (Item   : in out Machine;
   Config : not null access constant SSL.Configurations.Server_Configuration;
   Now    : SSL.Clocks.Wall_Time;
   Error  : out SSL.Errors.Error_Information)
  with Pre => State_Of (Item) = Start;
```

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
procedure Handle_Change_Cipher_Spec
  (Item   : in out Machine;
   Result : out Plan;
   Error  : out SSL.Errors.Error_Information);
```

```ada
procedure Wipe (Item : in out Machine);
```


