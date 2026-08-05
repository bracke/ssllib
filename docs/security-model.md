# Security model

`SECURITY.md` is the summary an evaluator reads first. This document is the
reasoning behind the choices, which is the part that has to survive a
maintainer who was not present when they were made.

## The threat this library is built against

A network attacker who can read, drop, reorder, replay and inject arbitrary
octets on the transport, and who can be the peer. That attacker must not be able
to read application data, alter it undetectably, learn a key, cause an unbounded
allocation, cause an unbounded amount of work, cause an unhandled exception, or
make the library disclose which of several checks a forged input failed.

Explicitly out of scope: an attacker who can read the process's memory, an
attacker who can influence the machine's clock in a way the caller does not
notice, and traffic analysis of message sizes and timing beyond what padding the
caller asks for.

## Why the refusals are absences

Every construction in the "not implemented" list is missing from the type system
rather than switched off. This is the single most consequential design decision in
the project, so the reasoning is worth setting out.

A disabled-by-default weakness has three failure modes a nonexistent one does not.
It can be re-enabled by a configuration a reviewer does not read. It can be
re-enabled by a bug in the code that reads that configuration. And it must be kept
working, because code that is compiled but never exercised rots — which means the
weak path is also the least-tested path.

So there is no `Enable_TLS_1_0`. There is no `Cipher_Suite` value naming a CBC
suite. `SSL.Versions.Protocol_Version` has two values. `SSL.Cipher_Suites.Suite_For`
returns `False` for 0x002F, and the test suite asserts that it does, by code point,
for a CBC suite, a 3DES suite, an RC4 suite, a NULL suite and an anonymous suite.
Renegotiation is not a state the state machine can enter.

The cost is real: a peer that speaks only TLS 1.0 cannot be reached, and the answer
is that it should not be. The cost is also visible, which is the point — a peer that
cannot connect is a support conversation, whereas a peer that connects over TLS 1.0
because a flag was set three years ago is a breach nobody noticed.

## Why one alert table

An attacker learns about an implementation through the differences between its
responses. The alert descriptions a peer can distinguish are therefore an
interface, and interfaces should be designed rather than accumulated.

`SSL.Errors.Classify` is that design, in one place. Its important content is where
it deliberately loses information:

- A bad AEAD tag, malformed padding, an invalid inner content type and a missing
  inner content type all map to `bad_record_mac`, and all classify as
  `Restricted`. A peer cannot tell which happened, and neither can a log.
- A Finished that did not verify, a CertificateVerify that did not verify and a
  PSK binder that did not verify all map to `decrypt_error`, all `Restricted`.
- Every reason a ticket could not be used — malformed, unknown key, expired, bad
  tag, mismatched binding, unsupported version, wrong security context — is
  non-fatal, sends no alert at all, and classifies as `Restricted`. The peer
  observes a full handshake and nothing more, so ticket handling is not a forgery
  oracle.

And where it deliberately keeps information: a negotiation failure is
`Safe_For_Peer`, because telling a peer that its offer did not overlap is the
entire purpose of `handshake_failure`, `protocol_version` and
`no_application_protocol`, and withholding it would only make the failure harder
to diagnose without making it harder to cause.

## Why restricted errors are withheld from local logs too

`Image` on a `Restricted` failure prints the category and the code and stops. The
parameters — which check, how far it got — are dropped.

The reason is that logs travel. They are shipped to aggregators, attached to
support tickets, and pasted into issue trackers. A field that is safe on the
machine that produced it is not necessarily safe where it ends up, and the value
of "which of these four indistinguishable failures was it" to a person debugging is
smaller than its value to someone probing. The category and code still say what
subsystem refused, which is what a real diagnosis starts from.

## Why time is a parameter

Certificate validity is a question about the world, so it needs a wall clock.
Deadlines are questions about elapsed duration, so they need monotonic time. The
two are not interchangeable: a deadline on a wall clock moves when NTP steps the
clock, and a validity check on a monotonic clock has no idea what year it is.

Both enter as parameters rather than being read inside the engine. That is what
makes an expired-certificate test possible without touching the machine's clock,
and it is what makes the engine's behaviour a function of its inputs — which is
what "deterministic" means and what makes a byte-boundary or mutation test
reproducible.

## Why trust must be explicit

Native system trust is the default client trust domain, and it is the only default.
NSS and Java stores are opt-in and are never merged into the default domain
silently, because an operator who trusts the system store has not thereby agreed to
trust whatever a browser profile on the same machine has accumulated.

A required trust source that is unavailable or empty fails closed. The alternative —
proceeding with no anchors — turns a misconfiguration into an unauthenticated
connection, which is the worst possible ordering of those two outcomes.

A peer's self-signed certificate is never an implicit anchor. Trust on first use is
not implemented at all in V1, because a TOFU implementation that is not also a
persistence and revocation implementation is a promise it cannot keep.

## Why pinning does not replace identity matching

A pin says "this specific key, please". It does not say "and never mind which name
this certificate is for". Those are separate questions and this library keeps them
separate: `Require_Valid_Path_And_Pin` requires both, and even `Pin_Only` does not
silently disable identity matching.

The failure this prevents is a pinned certificate legitimately issued for a
different name being accepted for this one — which is exactly what happens when an
implementation treats a pin match as a full substitute for verification.

## Why SAN only

Identity matching uses subjectAltName and nothing else. There is no Common Name
fallback.

CN-as-hostname has been deprecated since RFC 2818 in 2000 and prohibited since
RFC 6125 in 2011. Every certificate authority has issued SANs for over a decade. A
CN fallback in 2026 buys compatibility with certificates that should not exist, and
costs the ambiguity that made CN matching exploitable: a CN is a free-text display
field, and parsing it as a hostname means an attacker who controls any part of a
subject name may control what the certificate appears to be for.

## Why names are compared as octets or as normalized ASCII

ALPN protocol names are opaque byte strings by RFC 7301, and this library treats
them as such: no case folding, no UTF-8 assumption. `h2` and `H2` are different
protocols. Folding them would negotiate a protocol the peer did not offer, and the
application above has already dispatched on the answer.

DNS names are folded, but only over the ASCII range, and never through
`Ada.Characters.Handling.To_Lower`, which is defined over the whole `Character`
range. The specific hazard is locale-sensitive folding: in a Turkish locale, "I"
folds to a dotless "ı", so a hostname comparison that used the locale's folding
would produce different answers on different machines. A hostname comparison must
not depend on the process locale.

IDNA is not implemented. An internationalized name must arrive as an A-label. Doing
IDNA needs Unicode tables and careful handling of confusables and of the mapping
rules; doing it approximately produces a hostname comparison that can be tricked,
which is worse than refusing. A resolver has already produced A-labels for the
caller, so the refusal costs little.

## Why a server must opt in to finite-field groups separately

Accepting a large finite-field group as a server is a denial-of-service
amplifier, and the asymmetry is worth setting out because it is the one place
where the right default differs between the two roles.

An attacker sends a ClientHello carrying a random in-range `key_share` for the
group. The endpoint checks 1 < Y < p-1, which is a comparison and costs
nothing, and must then perform key generation and agreement to derive handshake
keys. There is no way to defer that work: it is what produces the keys the rest
of the handshake needs. The attacker has spent the cost of generating random
octets and never has to complete the handshake, or even read the reply.

Measured on one development-profile build, so the ratios matter and the
absolute figures do not:

| group | our CPU per connection | est. strength | connections/sec/core |
|---|---|---|---|
| x25519 | 2.3 ms | ~128 bits | ~900 |
| secp384r1 | 9.4 ms | ~192 bits | ~210 |
| ffdhe2048 | 10.3 ms | ~103 bits | ~190 |
| ffdhe4096 | 62.5 ms | ~150 bits | ~16 |
| ffdhe8192 | 294 ms | ~192 bits | ~3 |

Two things follow. `ffdhe2048` is weaker than X25519 while costing four times
as much, so it is never the better choice on merit -- only on compliance. And
`ffdhe8192` buys exactly the strength of `secp384r1` at thirty-one times the
cost, which is why it is not offered at all.

The consequence for the API, when `SSL.Configurations` is written: a server
must not acquire finite-field groups through the same call a client uses.
Enabling them server-side is a separate, explicitly named operation, so that the
amplification is something an operator chose rather than something they
inherited from a list they copied. RFC 7919 section 5.2's optional subgroup
check would not help here; the cost is the exponentiation itself, which is
unavoidable once the group is accepted.

## Why buffers cannot grow

A queue that grows under load is a queue whose size an attacker chooses. Every
buffer here has a capacity fixed at reservation, and a full queue refuses — all or
nothing, leaving the queue unchanged — rather than allocating.

All-or-nothing matters for records and handshake messages: a partial append would
split a message across a backpressure boundary, and the code that reassembled it
would need to know that had happened. Only the application-write path accepts a
partial append, where partial acceptance is the documented contract and the caller
retries with the remainder.

## Why the padding scan is safe

`SSL.Records.Open` finds the inner content type by scanning back from the end for
the last non-zero octet. That is a data-dependent loop, which in another context
would be a padding oracle.

It is not one here, for a reason that is structural rather than incidental: the
scan runs only on plaintext whose AEAD tag has already verified. An attacker who
could influence what that scan sees would have had to forge a tag first. The
ordering is the defence, and it is the ordering RFC 8446 section 5.2 specifies.

The scan's duration does leak the amount of padding, which is already public in the
record's length.

## What the tests establish, and what they cannot

The suite establishes, by construction rather than by sampling:

- that the key schedule agrees with RFC 8448 section 3, and that the vector set is
  internally consistent (the published traffic secrets are re-expanded and must
  produce the published keys);
- that no single-bit change anywhere in a protected record or its header is
  accepted;
- that no octet of plaintext survives an authentication failure, and that the
  output buffer is cleared rather than left holding what it held before;
- that a failed open does not advance the sequence number, so injected garbage
  cannot desynchronize the two ends;
- that the same plaintext under the same key produces different ciphertext,
  which is what proves the sequence number reaches the nonce;
- that a nested wire structure truncated at any length fails cleanly and yields
  nothing;
- that a full queue refuses rather than grows.

The suite cannot establish constant time — there is no automated timing gate, and
none is claimed. It cannot establish interoperability, because no external stack has
been tested against. And it cannot establish anything about the handshake, because
there is no handshake yet.
