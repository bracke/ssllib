# ssl-ticket_keys

Generated from `src/ssl-ticket_keys.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

The keys a server protects its session tickets with, and the
rotation of them.

A session ticket is the server's own state, encrypted under a key only the
server holds. That key is the most valuable thing a TLS server has after its
private key: anyone holding it can decrypt every ticket issued under it, and
therefore recover the resumption secret of every session those tickets
represent.

Which is why this is a separate, explicit object rather than something a
configuration conjures for itself:

* **Rotation is the application's decision.** How often, and on what
schedule, depends on how long the deployment wants a compromised key to
be useful for. This library will not pick a period.
* **Nothing is persisted and nothing is distributed.** A deployment
running several servers that must accept each other's tickets installs
the same key on each, by whatever means it already trusts. This library
writes no file and opens no socket to share one.
* **Rotation does not invalidate outstanding tickets.** The previous key
keeps opening what it issued, until it in turn retires. A rotation that
cut off every ticket at once would turn a routine operation into a
thundering herd of full handshakes.

A ring of ticket keys. Limited: it holds key material and scrubs it.

```ada
type Ring is limited private;
```

Is there a key that may issue? A server whose ring has none does not
issue tickets; that is a state, not a failure.

```ada
function Has_Active_Key (Item : Ring) return Boolean;
```

```ada
function Key_Count (Item : Ring) return Natural;
```

Generate a fresh key and make it the one that issues.

Whatever was issuing becomes decrypt-only, so tickets already in clients'
hands keep working.
@param Item     the ring
@param Lifetime how long tickets under this key may live, in seconds
@param Now      the wall clock
@param Error    out: No_Error, or a randomness failure

```ada
procedure Rotate
  (Item     : in out Ring;
   Lifetime : Natural := Default_Lifetime;
   Now      : SSL.Clocks.Wall_Time := SSL.Clocks.Current_UTC;
   Error    : out SSL.Errors.Error_Information)
  with Pre => Lifetime in 1 .. 604_800;
```

Install a key the application manages itself.

For a deployment where several servers must accept each other's tickets.
The identifier names the key inside every ticket issued under it, so it
must be the same on every server and must differ between keys.
@param Item       the ring
@param Identifier sixteen octets naming the key; not secret
@param Material   thirty-two octets of key; entirely secret
@param Lifetime   how long tickets under it may live, in seconds
@param Now        the wall clock
@param Error      out: No_Error, or why it was refused

```ada
procedure Install
  (Item       : in out Ring;
   Identifier : Byte_Array;
   Material   : Byte_Array;
   Lifetime   : Natural := Default_Lifetime;
   Now        : SSL.Clocks.Wall_Time := SSL.Clocks.Current_UTC;
   Error      : out SSL.Errors.Error_Information)
  with Pre => Identifier'Length = 16
              and then Material'Length = 32
              and then Lifetime in 1 .. 604_800;
```

Scrub every key now rather than at end of scope.

```ada
procedure Wipe (Item : in out Ring);
```

A reference to a ring, for a configuration to hold.

```ada
type Ring_Reference is access constant Ring;
```

Seal a session into a ticket, under the ring's active key.
@param Item    the ring
@param Value   the session to put inside; its own ticket field is ignored
@param Into    out: the sealed ticket
@param Written out: how many octets hold it
@param Error   out: No_Error, or why it could not be sealed

```ada
procedure Seal
  (Item    : Ring;
   Value   : SSL.Sessions.Session;
   Into    : out Byte_Array;
   Written : out Byte_Index;
   Error   : out SSL.Errors.Error_Information)
  with Pre => Into'Length >= Maximum_Ticket;
```

Open a ticket, if this ring can.

Everything that can go wrong produces `Usable => False` and one
undifferentiated refusal.
@param Item   the ring
@param Ticket the octets as they arrived
@param Now    the wall clock, for the expiry check
@param Into   in out: the recovered session
@param Usable out: True only when everything held
@param Error  out: No_Error, or one undifferentiated refusal

```ada
procedure Open
  (Item   : Ring;
   Ticket : Byte_Array;
   Now    : SSL.Clocks.Wall_Time;
   Into   : in out SSL.Sessions.Session;
   Usable : out Boolean;
   Error  : out SSL.Errors.Error_Information);
```


