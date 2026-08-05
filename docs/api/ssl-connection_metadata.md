# ssl-connection_metadata

Generated from `src/ssl-connection_metadata.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

What a finished connection can be asked about.

One immutable value, produced when the handshake completes and unchanged
afterwards. Immutable rather than a set of accessors on the live connection
because it is the natural thing to log, to pass to an authorization
decision, and to keep after the connection is gone -- and because a
connection being read from another task while it is being written to is not
a hazard this type should have.

Everything here is an answer to "what actually happened", never "what was
configured". A configuration lists the suites that were acceptable; this
says which one was used. The difference matters at exactly the moment
someone is trying to work out why a connection behaved unexpectedly.

```ada
type Metadata is private;
```

Nothing yet: what a connection reports before its handshake completes.

```ada
function No_Metadata return Metadata;
```

```ada
function Is_Established (Item : Metadata) return Boolean;
```

-------------------------------------------------------------------------
What was negotiated
-------------------------------------------------------------------------


```ada
function Version (Item : Metadata) return SSL.Versions.Protocol_Version
  with Pre => Is_Established (Item);
```

```ada
function Cipher_Suite (Item : Metadata) return SSL.Cipher_Suites.Cipher_Suite
  with Pre => Is_Established (Item);
```

The group the ephemeral key exchange used. Always present in TLS 1.3:
there is no key exchange in this library without one.

```ada
function Group (Item : Metadata) return SSL.Supported_Groups.Named_Group
  with Pre => Is_Established (Item);
```

The application protocol, when one was agreed.

```ada
function Has_Protocol (Item : Metadata) return Boolean;
```

```ada
function Protocol (Item : Metadata) return SSL.ALPN.Protocol_Name
  with Pre => Has_Protocol (Item);
```

The server name this connection was for: what a client sent, or what a
server was asked for.

```ada
function Server_Name (Item : Metadata) return SSL.Server_Names.DNS_Name;
```

-------------------------------------------------------------------------
What was proved
-------------------------------------------------------------------------

Did the peer authenticate with a certificate this endpoint accepted?

For a client this is always True on an established connection: an
unauthenticated server is not a connection this library completes. For a
server it is True only when a client certificate was requested, sent, and
validated.

```ada
function Peer_Authenticated (Item : Metadata) return Boolean;
```

The scheme the peer signed its CertificateVerify with.

```ada
function Peer_Signature_Scheme (Item : Metadata)
  return SSL.Signature_Schemes.Signature_Scheme
  with Pre => Peer_Authenticated (Item);
```

The peer's leaf certificate and its public key, as fingerprints. What
goes in a log, and what a pin is compared against.

```ada
function Peer_Certificate_Fingerprint (Item : Metadata) return Certificate_Fingerprint
  with Pre => Peer_Authenticated (Item);
```

```ada
function Peer_Public_Key_Fingerprint (Item : Metadata) return Certificate_Fingerprint
  with Pre => Peer_Authenticated (Item);
```

How many certificates the accepted path had, leaf included.

```ada
function Path_Length (Item : Metadata) return Natural;
```

Was this connection resumed from a ticket rather than authenticated
afresh? A resumed connection has no CertificateVerify, so the peer proved
only that it holds a key from an earlier handshake.

```ada
function Resumed (Item : Metadata) return Boolean;
```

-------------------------------------------------------------------------
Identity
-------------------------------------------------------------------------

This connection's own stable identifier, for correlating log lines.

```ada
function Identifier (Item : Metadata) return Connection_ID;
```

The security context the configuration declared. Two connections with
different contexts never share a session, whatever else they have in
common.

```ada
function Security_Context (Item : Metadata) return Security_Context_ID;
```

One line naming what was negotiated, for a log. Never a secret: version,
suite, group, protocol and whether the peer authenticated.

```ada
function Image (Item : Metadata) return String;
```

-------------------------------------------------------------------------
Construction
-------------------------------------------------------------------------

Assemble the metadata for an established connection. Called by the engine
when a handshake completes; there is no other way to produce an
established value, which is what keeps this type from ever describing a
connection that has not actually completed one.

```ada
procedure Establish
  (Item        : out Metadata;
   Identity    : Connection_ID;
   Context     : Security_Context_ID;
   Version     : SSL.Versions.Protocol_Version;
   Suite       : SSL.Cipher_Suites.Cipher_Suite;
   Group       : SSL.Supported_Groups.Named_Group;
   Protocol    : SSL.ALPN.Protocol_Name;
   Has_Protocol : Boolean;
   Name        : SSL.Server_Names.DNS_Name;
   Authenticated : Boolean;
   Scheme      : SSL.Signature_Schemes.Signature_Scheme;
   Leaf        : Certificate_Fingerprint;
   Public_Key  : Certificate_Fingerprint;
   Depth       : Natural;
   Was_Resumed : Boolean);
```


