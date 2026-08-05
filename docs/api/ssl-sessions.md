# ssl-sessions

Generated from `src/ssl-sessions.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

A session a client holds so that a later connection can resume
rather than handshake from nothing.

A resumed handshake skips the certificate, the signature and the path
validation. That is the point of it -- it is a round trip and a signature
cheaper -- and it is also the reason every one of the bindings below exists.
A resumed connection inherits the authentication of the one that issued the
ticket, so resuming across any difference that would have changed that
authentication is resuming into a connection the application never asked
for.

So a session records what it was established under, and offering it anywhere
else is refused:

* **the server name**, because a ticket issued for one host is not a claim
about another;
* **the application protocol**, because a session established under `h2`
must not resume under `http/1.1` -- an application that dispatched on
the protocol would be dispatching wrongly;
* **the cipher suite's hash**, because the PSK is derived under it;
* **the trust snapshot and the configuration**, by fingerprint, because a
deployment that narrowed its trust or changed its policy must not have
the old policy resurface through a cached session;
* **the security context**, because that is the application's own
statement that two connections belong to different domains.

A session is a value, not a handle. It holds a secret, so it is limited and
it scrubs itself.

```ada
type Session is limited private;
```

Has this session anything in it?

```ada
function Is_Present (Item : Session) return Boolean;
```

Is it still within its lifetime at this instant?

Separate from `Is_Present` because an expired session is a real session
that has run out, and the difference matters to a cache deciding what to
evict.

```ada
function Is_Live (Item : Session; At_Time : SSL.Clocks.Wall_Time) return Boolean;
```

-------------------------------------------------------------------------
What it was established under
-------------------------------------------------------------------------


```ada
function Version (Item : Session) return SSL.Versions.Protocol_Version
  with Pre => Is_Present (Item);
```

```ada
function Cipher_Suite (Item : Session) return SSL.Cipher_Suites.Cipher_Suite
  with Pre => Is_Present (Item);
```

```ada
function Server_Name (Item : Session) return SSL.Server_Names.DNS_Name;
```

```ada
function Has_Protocol (Item : Session) return Boolean;
```

```ada
function Protocol (Item : Session) return SSL.ALPN.Protocol_Name
  with Pre => Has_Protocol (Item);
```

```ada
function Issued (Item : Session) return SSL.Clocks.Wall_Time;
```

```ada
function Expires (Item : Session) return SSL.Clocks.Wall_Time;
```

```ada
function Security_Context (Item : Session) return Security_Context_ID;
```

```ada
function Configuration (Item : Session) return Configuration_Fingerprint;
```

```ada
function Trust (Item : Session) return Trust_Fingerprint;
```

Was the peer authenticated with a certificate in the handshake that
issued this? Reported so that a resumed connection can say it inherited
an authentication rather than performed one.

```ada
function Peer_Authenticated (Item : Session) return Boolean;
```

One line for a log. Never the ticket and never the secret.

```ada
function Image (Item : Session) return String;
```

-------------------------------------------------------------------------
Whether it may be offered here
-------------------------------------------------------------------------

Is this session usable for a connection with these properties?

Every binding is checked, and a mismatch in any of them means a full
handshake. That is a normal outcome and not a failure: resumption is an
optimization, and declining it costs a round trip rather than security.
@param Item      the session
@param Name      the server name the new connection is for
@param Context   the security context in force
@param Setup     the configuration's fingerprint
@param Anchors   the trust snapshot's fingerprint
@param At_Time   the wall clock
@return True when every binding matches and the session is live

```ada
function Matches
  (Item    : Session;
   Name    : SSL.Server_Names.DNS_Name;
   Context : Security_Context_ID;
   Setup   : Configuration_Fingerprint;
   Anchors : Trust_Fingerprint;
   At_Time : SSL.Clocks.Wall_Time) return Boolean;
```

-------------------------------------------------------------------------
Handling one
-------------------------------------------------------------------------

Forget everything this session holds, now.

```ada
procedure Wipe (Item : in out Session);
```

Copy a session. Explicit because the type is limited: a session holds a
secret, and a copy that happened implicitly would be a second copy of it
that nobody had decided to make.

```ada
procedure Copy (Target : in out Session; Source : Session);
```

The ticket octets, for offering the session back to the server. Bounded
and not secret in itself -- a ticket is opaque to everyone but the server
that issued it -- but treated carefully anyway, because possession of one
plus the secret is what resumption needs.

```ada
function Ticket (Item : Session) return Byte_Array
  with Pre => Is_Present (Item);
```

The obfuscation offset the server told the client to add when reporting
the ticket's age.

```ada
function Age_Add (Item : Session) return Interfaces.Unsigned_32;
```

The nonce the resumption secret was derived under.

```ada
function Nonce (Item : Session) return Byte_Array;
```

-------------------------------------------------------------------------
Building one
-------------------------------------------------------------------------

Assemble a session from a NewSessionTicket and the connection that
carried it.

Only the engine calls this. There is no way for an application to
fabricate a session, which is what stops one being offered that no
handshake ever established.
@param Item          out: the session
@param Version       the protocol it was established under
@param Suite         the cipher suite, whose hash the PSK is derived under
@param Name          the server name
@param Protocol      the agreed application protocol
@param Has_Protocol  whether one was agreed at all
@param Issued        when the ticket was issued
@param Lifetime      how many seconds the server said it may live
@param Context       the security context in force
@param Setup         the configuration's fingerprint
@param Anchors       the trust snapshot's fingerprint
@param Authenticated whether the peer presented a certificate
@param Ticket_Bytes  the ticket as it arrived
@param Age_Add       the obfuscation offset
@param Nonce_Bytes   the ticket nonce
@param Secret        the resumption PSK for this ticket
@param Error         out: No_Error, or why it could not be built

```ada
procedure Store
  (Item          : in out Session;
   Version       : SSL.Versions.Protocol_Version;
   Suite         : SSL.Cipher_Suites.Cipher_Suite;
   Name          : SSL.Server_Names.DNS_Name;
   Protocol      : SSL.ALPN.Protocol_Name;
   Has_Protocol  : Boolean;
   Issued        : SSL.Clocks.Wall_Time;
   Lifetime      : Natural;
   Context       : Security_Context_ID;
   Setup         : Configuration_Fingerprint;
   Anchors       : Trust_Fingerprint;
   Authenticated : Boolean;
   Ticket_Bytes  : Byte_Array;
   Age_Add       : Interfaces.Unsigned_32;
   Nonce_Bytes   : Byte_Array;
   Secret        : Byte_Array;
   Error         : out SSL.Errors.Error_Information);
```

The resumption PSK, for computing a binder.

Reachable only from inside this library's own subtree: the function is
here because the client machine needs it, and a `Secret` cannot be handed
out. The caller receives a copy it must scrub.

```ada
procedure Get_Secret (Item : Session; Into : out Byte_Array; Length : out Byte_Index)
  with Pre => Into'Length >= 64;
```


