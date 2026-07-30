# Security model and reporting

## Status

`ssllib` is incomplete and must not be used to protect anything. The handshake
state machines and the public connection API do not exist; see `docs/status.md`.
What follows describes the security properties of the parts that are built, and
the properties the rest is being built to hold.

## Reporting

Report a suspected vulnerability to bent@bracke.dk. Please do not open a public
issue for anything that would let someone read or forge traffic.

## What is defended

**No unauthenticated plaintext is ever exposed.** `SSL.Records.Open` verifies
the AEAD tag before any plaintext is produced — CryptoLib's `Open_AEAD` computes
the tag first and never writes plaintext on a mismatch — and on any failure the
output buffer is zeroed and the recovered-length is zero. Padding is removed only
after the tag has verified, so scanning back for the inner content type cannot be
a padding oracle: an attacker who could influence that scan would have had to
forge the tag first.

The test suite checks this directly: a record is sealed over a recognizable
plaintext, one bit of the tag is flipped, and the output buffer is then scanned
for any octet of the plaintext and for any non-zero octet at all.

**Nonce reuse is structurally impossible.** A record nonce is a function of the
static IV and the sequence number (RFC 8446 section 5.3). The sequence number is
incremented only after a successful protect or open. It returns to zero only
inside `Install`, which always installs a new key at the same time. There is no
operation on a traffic state that sets a sequence number, none that reuses a key
with a sequence number already used, and none that retries an open with a
different sequence number after a failure. The absence of those operations is the
guarantee; a runtime check would only be a second opinion.

At `Unsigned_64'Last` the record layer refuses to protect rather than wrapping.
The configured record and octet limits are many orders of magnitude below that,
so the refusal is a backstop and not a working path.

**The record header is authenticated.** The five header octets are the AEAD's
associated data. The suite flips each of them in turn and requires the open to
fail, which is what catches a header quietly excluded from the associated data —
a mistake that leaves a working handshake and a forgeable length field.

**Secrets are scrubbed through volatile stores.** `SSL.Secrets.Secret` is limited
and controlled; it wipes on finalization and on overwrite, over its whole buffer
rather than the used prefix, so a shorter secret set over a longer one leaves no
tail. Every local `Byte_Array` that holds secret material is scrubbed through
`SSL.Crypto.Scrub`, which calls `CryptoLib.Secure_Wipe`. A plain
`Buffer := [others => 0]` before a return is a dead store and is deleted at -O2;
it zeroes nothing.

Forward secrecy within a connection: the early secret and the binder key are
scrubbed the moment the handshake stage is reached, and a KeyUpdate scrubs the
traffic secret it retires.

**The alert surface is one table.** No failure site chooses its own alert.
`SSL.Errors` maps a code to a category, a fatality, an alert, a retry class and a
disclosure class in one `case` statement, so what a peer can distinguish is a
property of a table a reviewer can read rather than an emergent property of a
hundred call sites. Failures whose detail would be an oracle — a bad tag, bad
padding, a Finished that did not verify, a ticket that could not be used — are
classified `Restricted` and render as their code and category only, with their
parameters withheld even from a local log, because logs are shipped.

**Ticket failures are not fatal and send no alert.** An unusable ticket means a
full handshake. A peer therefore cannot tell a forged ticket from an expired one
from a ticket encrypted under a retired key.

**A peer's alert level is not trusted.** Terminality is decided on the alert
description, never on the level octet: a peer claiming that `handshake_failure`
was only a warning does not make it survivable. An alert description this library
does not recognize is treated as terminal and its number is preserved verbatim.

**Every declared length is bounded before it is used.** `SSL.Wire`'s vector
openers check the declared length against the caller's limit before a single body
octet is touched, and against the octets actually present before advancing.
Failure is a sticky flag rather than an exception, so a parser checks once at the
end and a partly-parsed structure never carries a value read from beyond its
bounds. The suite exercises a nested structure at every truncation from zero
octets to one short of complete.

**Buffers do not grow under load.** `SSL.Buffers.Queue` has a capacity fixed at
reservation. Full means full: the append is refused, all-or-nothing, and the
queue is unchanged. That is the backpressure boundary, and it is a boundary
precisely because a hostile peer can fill it but cannot move it.

**Names are compared as octets, or as normalized ASCII.** ALPN protocol names are
opaque byte strings: no case folding, no UTF-8 assumption. DNS names are folded
to lower case over the ASCII range only, never through a locale-sensitive
routine, because a Turkish locale folds "I" differently and a hostname comparison
must not depend on the process locale. An IP literal is refused as a DNS name.
Internationalized names must arrive as A-labels; this library does not implement
IDNA, because doing it wrong is a security bug and guessing is doing it wrong.

**Wildcards match one label, leftmost only.** `*.example.com` matches
`www.example.com`; it does not match `example.com`, does not match
`a.b.example.com`, and `a*.example.com` and `*.com` are refused outright. An
exact match always outranks a wildcard, and a narrower wildcard outranks a
broader one.

## What is not defended

**Timing side channels outside CryptoLib.** Tag and MAC comparison goes through
`CryptoLib.Constant_Time.Equal`, and CryptoLib's primitives are written for
constant time on secret paths. `ssllib`'s own control flow is not audited for
timing: the padding scan in `SSL.Records.Open` runs over authenticated plaintext
and its length is already public in the record length, but no systematic timing
audit has been done and none is claimed.

**Traffic analysis.** Record padding is available and defaults to none, because a
caller who wants it should say how much. Nothing here hides message sizes or
timing by default.

**Memory disclosure by the application.** `SSL.Secrets.Value` returns a copy, and
the copy is an ordinary array that scrubs nothing. Callers within the library
pass it straight into a CryptoLib call rather than binding it to a named object.
An application cannot reach it at all: the package is a private child.

**Compromise of the process.** Nothing here defends against an attacker who can
read the process's memory while a connection is open.

## Cryptographic provenance

The TLS 1.3 key schedule is checked against RFC 8448 section 3: the derived
secrets, the handshake secret, and both handshake traffic secrets through the
keys and IVs they expand to. Those values were independently recomputed from the
RFC 8446 section 7.1 definitions with a separate HKDF implementation before being
committed, and the two agreed. The cross-check is retained in the suite: the
published traffic secrets are re-expanded and required to produce the published
keys, so an inconsistent vector set fails rather than passing quietly.

The record-layer nonce is checked against RFC 8446 section 5.3 at sequence 0, 1
and 0x0102, and the high four octets of the IV are checked to be untouched at
`Unsigned_64'Last`.

Every primitive underneath — SHA-2, HMAC, HKDF, AES-GCM, ChaCha20-Poly1305,
X25519, NIST ECDH, ECDSA, EdDSA, RSA — is CryptoLib's, with CryptoLib's own
known-answer tests and its own cross-checks against independent implementations.

## Deliberate absences

Every construction in the list below is absent from the type system, not
disabled by a default. There is no configuration path to one because there is no
value to configure.

SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, TLS compression, export suites, RC4, DES,
3DES, CBC-with-HMAC suites, NULL encryption, static RSA key exchange, static and
anonymous DH/ECDH, renegotiation, heartbeat, 0-RTT, external PSKs, post-handshake
client authentication, DTLS, QUIC TLS, Encrypted ClientHello, delegated
credentials, certificate compression, raw public-key authentication, TLS 1.2
session-ID resumption, trust on first use, MD2, MD5, SHA-1 signatures, DSA.

Key logging, when it is implemented, will live in `SSL.Unsafe.Key_Logging`: off
by default, enabled only by an explicit call on a configuration, writing to an
application-supplied sink, never opening a file, and never reading an environment
variable to decide whether to turn itself on.
