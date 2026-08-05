# ssl

Generated from `src/ssl.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

Root of ssllib: the byte view every other package speaks, and the
typed stable identifiers that name things across the API.

ssllib provides TLS 1.3 and a deliberately restricted modern TLS 1.2 for
authenticated, confidential, integrity-protected bidirectional byte streams
over a transport the caller owns. It opens no sockets, reads no clocks,
looks at no environment variables and starts no tasks of its own.

The name is historical. SSL 2.0 and SSL 3.0 are not implemented, and
neither are TLS 1.0 and TLS 1.1.

Ownership boundaries, which the rest of the library holds to:

* every hash, MAC, KDF, AEAD, key agreement, signature, ASN.1, X.509,
PKIX, OCSP and CRL operation is CryptoLib's;
* every native trust-anchor source is Truststores';
* the remaining genuine host differences are Hostkit's;
* what is left -- the protocol -- is this library's.

Bytes are Ada.Streams.Stream_Element_Array throughout, because that is
what CryptoLib speaks and what Ada streams speak, so no conversion layer
sits between the caller, this library and the cryptography.

One octet on the wire or in a buffer.

```ada
subtype Byte is Ada.Streams.Stream_Element;
```

A run of octets. Every wire encoding, every plaintext buffer and every
secret in this library is one of these or a bounded record holding one.

```ada
subtype Byte_Array is Ada.Streams.Stream_Element_Array;
```

An index into a Byte_Array. Lengths and counts of octets use this so
that arithmetic on them cannot silently overflow a Natural on a
32-bit target.

```ada
subtype Byte_Index is Ada.Streams.Stream_Element_Offset;
```

-------------------------------------------------------------------------
Stable identifiers

Each of these names one thing for the life of a process. They are
immutable, comparable and hashable, and they carry no payload a caller
could mistake for the thing itself: a Credential_ID does not let anyone
reach the private key, and a Session_ID does not let anyone reach the
resumption secret.
-------------------------------------------------------------------------

Names one connection. Assigned when the connection object is
initialized and never reused within a process run, so a diagnostic
event can be attributed to a connection that has already been
finalized.

```ada
type Connection_ID is private;
```

Names one loaded credential -- a certificate chain and the signing
capability that goes with it -- within one configuration.

```ada
type Credential_ID is private;
```

Names one resumable session in a cache. Distinct from the TLS 1.2
legacy session_id field on the wire, which this library does not use
for resumption.

```ada
type Session_ID is private;
```

Names an application security context. A session is only offered for
resumption to a connection whose context matches the one it was
established under, which is how an application keeps sessions
belonging to different users or tenants from being crossed.

```ada
type Security_Context_ID is private;
```

A configuration's identity as a value: two configurations with the same
fingerprint negotiate the same way. Sessions are bound to it, so a
configuration change invalidates resumption rather than silently
resuming under policy the session was not established under.

```ada
type Configuration_Fingerprint is private;
```

A trust snapshot's identity as a value. Bound into sessions for the
same reason.

```ada
type Trust_Fingerprint is private;
```

A certificate's identity as a value: SHA-256 over the DER, or over the
SubjectPublicKeyInfo, according to how it was taken.

```ada
type Certificate_Fingerprint is private;
```

The two things a Certificate_Fingerprint can be over.

```ada
type Fingerprint_Subject is (Whole_Certificate, Public_Key_Info);
```

-------------------------------------------------------------------------
Identifier operations
-------------------------------------------------------------------------

The unset value of each identifier kind. Distinguishable from every
assigned value, so "no credential selected" is not the same as "the
first credential".

```ada
function No_Connection return Connection_ID;
```

```ada
function No_Credential return Credential_ID;
```

```ada
function No_Session return Session_ID;
```

```ada
function Default_Security_Context return Security_Context_ID;
```

Is this an assigned identifier rather than the unset one?
@param Item the identifier to test
@return True when Item names something

```ada
function Is_Present (Item : Connection_ID) return Boolean;
```

```ada
function Is_Present (Item : Credential_ID) return Boolean;
```

```ada
function Is_Present (Item : Session_ID) return Boolean;
```

Every identifier type above is a non-limited private type, so the
predefined "=" is visible to callers and is the right comparison: each
is a scalar or a fixed-size record with no padding a caller can set.
There is deliberately no ordering, because none of these has a
meaningful order and an accidental one invites sorting by it.

Build an application security context from a caller-chosen label. The
label is not secret and is not sent on the wire; it separates cache
domains. An empty label is the default context.
@param Label the caller's name for the context, up to 64 characters
@return the context identifier

```ada
function Security_Context (Label : String) return Security_Context_ID
  with Pre => Label'Length <= 64;
```

Lower-case hexadecimal image of a fingerprint, for logs and for
comparison against a pin an operator wrote down. Never a secret.
@param Item the fingerprint to render
@return 64 hexadecimal characters

```ada
function Image (Item : Certificate_Fingerprint) return String
  with Post => Image'Result'Length = 64;
```

```ada
function Image (Item : Configuration_Fingerprint) return String
  with Post => Image'Result'Length = 64;
```

```ada
function Image (Item : Trust_Fingerprint) return String
  with Post => Image'Result'Length = 64;
```

A decimal image of a connection identifier, for correlating diagnostic
events. Not stable across process runs.
@param Item the connection identifier to render
@return the decimal image, or "-" for No_Connection

```ada
function Image (Item : Connection_ID) return String;
```

The digest itself, as octets.

Not a secret: `Image` already renders the same value as hexadecimal, and
a fingerprint is meant to be written down and compared. The octets are
exposed because a channel binding needs them as octets rather than as
text, and hexadecimal round-tripping to get at them would be a second
place for the encoding to be wrong.
@param Item the fingerprint
@return the 32 digest octets

```ada
function Digest_Of (Item : Certificate_Fingerprint) return Byte_Array
  with Post => Digest_Of'Result'Length = 32;
```

Was this fingerprint ever taken, or is it the absent one a connection
with no peer certificate reports?

```ada
function Is_Present (Item : Certificate_Fingerprint) return Boolean;
```

The digest octets of the other two fingerprint kinds, and the way back.

These exist because a session ticket has to carry them across a process
boundary: a resumed session must be refused when the configuration or the
trust snapshot it was established under is not the one now in force, and
checking that means writing the fingerprints down and reading them back.
None of them is secret; each is already renderable as hexadecimal.

```ada
function Digest_Of (Item : Configuration_Fingerprint) return Byte_Array
  with Post => Digest_Of'Result'Length = 32;
```

```ada
function Digest_Of (Item : Trust_Fingerprint) return Byte_Array
  with Post => Digest_Of'Result'Length = 32;
```

```ada
function Configuration_From_Digest (Digest : Byte_Array) return Configuration_Fingerprint
  with Pre => Digest'Length = 32;
```

```ada
function Trust_From_Digest (Digest : Byte_Array) return Trust_Fingerprint
  with Pre => Digest'Length = 32;
```

The label an application gave a security context, so that it can be
written into a ticket and compared when the ticket comes back. Not
secret: it is the application's own name for a cache domain and is never
sent on the wire.

```ada
function Label_Of (Item : Security_Context_ID) return String
  with Post => Label_Of'Result'Length <= 64;
```

What a fingerprint was taken over.
@param Item the fingerprint to inspect
@return Whole_Certificate or Public_Key_Info

```ada
function Subject_Of (Item : Certificate_Fingerprint) return Fingerprint_Subject;
```

Parse a certificate or SPKI fingerprint from its hexadecimal image, for
reading a pin out of application configuration.
@param Text    64 hexadecimal characters, either case
@param Subject what the digest is over
@param Item    out: the parsed fingerprint, unchanged on failure
@return True when Text was 64 valid hexadecimal characters

```ada
function Parse_Fingerprint
  (Text    : String;
   Subject : Fingerprint_Subject;
   Item    : out Certificate_Fingerprint) return Boolean;
```


