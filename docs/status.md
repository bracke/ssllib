# Implementation status

This document is the honest account of what `ssllib` currently is, measured
against the V1 specification in `ssllib_complete_implementation_prompt.txt`.

**`ssllib` completes a TLS 1.3 handshake and carries application data.** A
client and a server hand-shake, authenticate, exchange data in both directions
and shut down cleanly, over a transport that refuses half its reads and accepts
ninety-seven octets per write -- all of it exercised in the test suite with no
network involved.

**It interoperates with three other TLS stacks, in both protocol profiles.**
`ssllib_tools test-interop` drives real external implementations on the loopback
address and requires that each handshake *completes and negotiates what it was
told to* — version, suite, group, and whether the peer authenticated — rather
than merely connecting. On the development host that is OpenSSL 3.0.13,
GnuTLS 3.8.3 and the JSSE stack in OpenJDK 21, under TLS 1.3 and under
restricted TLS 1.2, in both directions: twelve runs, all passing. Every
certificate is passed to the external tool explicitly; the host's trust store is
never touched.

That matrix earned its place immediately. Four defects that the whole in-process
test suite had passed over came out of the first runs against real peers: RSA
signing had never worked at all (the signature was sized from the modulus's
encoded length, which is one octet too long for every RSA key); the TLS 1.2
server picked a cipher suite without regard to whether its credential could
authenticate it; a TLS 1.2 connection never sent a `close_notify`, so every peer
reported a truncation attack; and the TLS 1.2 server echoed the client's session
identifier on a full handshake, which under RFC 5077 means "your ticket was
accepted".

**One thing is missing**: the platform matrix, which has run on Linux x86_64
only. `ssllib_tools release` runs every gate and then refuses while it is
outstanding, naming it.

**Documentation.** The hand-written documents are the README, `SECURITY.md`,
the changelog, and under `docs/`: `architecture.md`, `package-map.md`,
`security-model.md`, `known-limitations.md`, `attribution.md`, this file, four
topic guides under `docs/guides/` (using, protocols, operating, developing) and
four machine-readable documents under `docs/machine/` (contracts,
state-machines, error-registry, workflows). `ssllib_tools docs` generates the
rest: one API page per public specification, and four specification tables —
algorithms, extension contexts, alerts and ticket formats — produced by asking
the registries rather than by transcribing them, so they cannot drift.

Section 25 of the specification lists its documentation as twenty-odd separate
topics. They are covered in four guides rather than twenty-odd files, and that
is a deliberate departure: six documents about the same four types would repeat
each other, and a reader following a connection from `Build` to `Shutdown` reads
them in order anyway. Every topic on the list is covered; the file count is not
the same. `ssllib_tools verify` requires each of these documents to exist and to
say something, so none of them can quietly disappear.

The specification's section 28 says not to declare V1 complete merely because
the project compiles. It is not complete, and this document says exactly where
the line is rather than leaving a reader to infer it.

## What is implemented and tested

| Subsystem | Package | State |
|---|---|---|
| Byte view, stable identifiers, fingerprints | `SSL` | complete |
| Crate identity and provenance | `SSL.Version` | complete |
| Resource limits with consistency checking | `SSL.Limits` | complete |
| Structured errors, central alert mapping, failure accumulation | `SSL.Errors` | complete |
| Alerts, including unknown peer alerts | `SSL.Alerts` | complete |
| Protocol versions and version sets | `SSL.Versions` | complete |
| Cipher suites: all nine, composition, ordered lists | `SSL.Cipher_Suites` | complete |
| Named groups: X25519, P-256, P-384, P-521, ffdhe2048/3072/4096 | `SSL.Supported_Groups` | complete |
| Signature schemes, version rules, curve binding | `SSL.Signature_Schemes` | complete |
| ALPN names and selection policy | `SSL.ALPN` | complete |
| Validated DNS names, wildcards, IP identities | `SSL.Server_Names` | complete |
| Wall and monotonic clocks, deadlines | `SSL.Clocks` | complete |
| Cancellation token | `SSL.Cancellation` | complete |
| Authentication outcomes, fresh versus resumed | `SSL.Authentication` | complete |
| Immutable configurations, builders, defaults, validation, fingerprints | `SSL.Configurations` | complete |
| Fixed-capacity stores and octet FIFOs | `SSL.Buffers` (private) | complete |
| Controlled secrets with non-elidable wiping | `SSL.Secrets` (private) | complete |
| Explicit wire codecs with bounded cursors | `SSL.Wire` (private) | complete |
| The single CryptoLib seam, incl. key agreement over every group | `SSL.Crypto` (private) | complete |
| Handshake transcript, dual-hash, HRR transform | `SSL.Transcripts` (private) | complete |
| TLS 1.3 key schedule, all secrets and products | `SSL.Key_Schedule` (private) | complete |
| Record layer: header, traffic state, AEAD, nonces | `SSL.Records` (private) | complete |
| Closed extension registry: identifiers, contexts, duplicates | `SSL.Extensions` (private) | complete |
| Every TLS 1.3 handshake message: framing, parsers and encoders | `SSL.Handshake_Messages` (private) | complete |
| Local credentials: loading, capability, signing, SNI ranking | `SSL.Credentials` | complete |
| Client authentication: certificate, CertificateVerify, both ends | `SSL.TLS13.Client`, `SSL.TLS13.Server` | complete |
| External signers and the provider boundary | `SSL.Credentials.Signers` | complete |
| Trust snapshots over truststores, explicit anchors | `SSL.Trust` | complete |
| Certificate and SPKI pins, scopes, activation periods | `SSL.Trust.Pinning` | complete |
| Revocation policy and evidence evaluation | `SSL.Trust.Revocation` | complete |
| The X.509 validation pipeline over CryptoLib | `SSL.Certificate_Validation` (private) | complete |
| TLS 1.3 handshake state machines, client and server | `SSL.TLS13.Client`, `SSL.TLS13.Server` (private) | complete for the full handshake |
| Transport interface and its exception boundary | `SSL.Transports` | complete |
| The protocol driver: records in, records out, no I/O | `SSL.Engines` | complete for TLS 1.3 |
| Engine events and readiness | `SSL.Engines.Events` | complete |
| Connections over a transport, partial I/O throughout | `SSL.Connections` | complete |
| Role constructors | `SSL.Clients`, `SSL.Servers` | complete |
| Blocking operations with deadlines | `SSL.Blocking` | complete |
| Ada stream over a connection | `SSL.Streams` | complete |
| What a finished connection reports | `SSL.Connection_Metadata` | complete |
| KeyUpdate: scheduling, flood bounds, both directions | `SSL.Engines` | complete |
| Exported keying material | `SSL.Exporters` | complete |
| Channel bindings: tls-exporter, tls-server-end-point | `SSL.Channel_Bindings` | complete |
| Structured diagnostics: levels, redaction, sinks | `SSL.Diagnostics` | complete |
| Unsafe key logging in the NSS format | `SSL.Unsafe.Key_Logging` | complete |
| Ticket keys: rotation, states, versioned sealed format | `SSL.Ticket_Keys` | complete |
| Sessions and their bindings | `SSL.Sessions` | complete |
| Client session cache: interface and bounded memory one | `SSL.Sessions.Client_Caches`, `.Memory` | complete |
| Ticket issue and client-side caching | `SSL.Engines` | complete |
| Resumption: offer, binder, acceptance, both ends | `SSL.TLS13.Client`, `SSL.TLS13.Server` | complete |
| Restricted TLS 1.2: PRF, EMS, key block, record layer | `SSL.TLS12`, `SSL.TLS12.Records` | complete |
| Restricted TLS 1.2 message codecs | `SSL.TLS12.Messages` | complete |
| Restricted TLS 1.2 state machines | `SSL.TLS12.Client`, `SSL.TLS12.Server` | complete |
| Stateless TLS 1.2 tickets and the abbreviated handshake | `SSL.TLS12.Client`, `SSL.TLS12.Server` | complete |
| Version negotiation and fallback in the engine | `SSL.Engines` | complete |
| One connection from a reader, a writer and a controller | `SSL.Synchronized_Connections` | complete |
| Test-only wipe observer on every secret | `SSL.Secrets` | complete |
| Deterministic mutation runner and corpus | `Tests_Mutation` | complete |
| Limit-boundary and concurrency checks | `ssllib_tests` | complete |
| AUnit suite: 87 cases | `ssllib_tests` | passing |
| Interoperability controller and external peer | `SSLLib_Interop`, `ssllib_peer` | complete |
| GNATprove profiles, development and release | `ssllib_tools prove` | complete |
| Ada tooling: every command, including docs, package and release | `ssllib_tools` | complete |
| Generated API pages and specification tables | `ssllib_tools docs` | complete |

The key schedule is checked against **RFC 8448 section 3** — the published
handshake secret, both handshake traffic secrets (through the keys and IVs they
expand to), and the derived-secret chain. Those values were also recomputed from
the RFC 8446 section 7.1 definitions with an independent HKDF implementation
before being committed; the two agreed.

Secret cleanup is checked through a **test-only wipe observer** in
`SSL.Secrets`: a hook that fires on every scrub and is handed the number of
octets wiped and nothing else — not the octets, not a reference to the secret,
because an observer that could see what it was observing would be a hole in the
property it exists to check. It is null by default and nothing in the library
ever installs one. The check runs a live connection with it installed, requires
that tearing the connection down scrubs what it held, and requires that one
hand-made wipe is reported exactly once with the length that actually held the
secret.

The same check scans **every diagnostic that live connection produced**, at the
most detailed level and the least redacting one, for that connection's own
exported key material — in both spellings a leak could take, the raw octets and
their hexadecimal — and for an eight-octet prefix of it, because a leak of part
of a secret is a leak. A scan at a level that hid everything would only prove
that the level hides everything, which is why the check turns the redaction off.

The record layer is checked for round-trip under all padding lengths from 0 to
64, for rejection of every single-bit flip across the ciphertext and the tag,
for rejection of every single-bit flip in the five header octets (which proves
the header really is the AEAD's associated data), for refusal of an out-of-order
record, for producing no plaintext whatsoever on an authentication failure, and
for refusing a record whose authenticated plaintext has no inner content type.

The wire codecs are checked at every truncation of a nested length-prefixed
structure, from zero octets to one short of complete.

Key agreement is exercised over **every group the registry offers** — X25519, the
three NIST curves and the three RFC 7919 finite-field groups — in both
directions, checking that the two ends agree, that the share and secret widths
are exactly what the registry states, and that a wrong-length or all-zero peer
share is refused before any arithmetic runs.

The certificate machinery is driven end to end against a **committed self-signed
Ed25519 fixture** that serves as both leaf and anchor: the credential's key type,
its capability set, both subjectAltName entries and their specificity ranking,
Ed25519 signing, refusal of a scheme the key cannot produce, and then the
pipeline itself — a valid chain, the wildcard name, a name the certificate is not
for (refused *after* the path validated), a time outside the validity window, no
clock at all, and an empty trust base. The fixture is embedded as text and its
validity runs to 2126, so the suite depends on no file, no clock and no
randomness.

Two of my own bugs surfaced there: the credential loader called a public
accessor whose precondition requires a loaded credential, while still loading
one; and the validation pipeline built the X.509 validity moment in a declarative
part, before the check that a wall clock had been supplied at all — so the "no
clock" case raised instead of refusing.

The external-signer boundary is checked against a signer that raises from `Sign`,
one that raises from `Supports`, one that refuses, and one that claims to have
written more than its buffer holds. Each becomes a structured provider failure
naming the signer; none propagates.

RSASSA-PSS verification is checked against a known signature, including that the
signature scheme really selects the hash (the same signature must fail under
`rsa_pss_rsae_sha384`) and that a tampered signature is refused.

The hello parsers are checked against a hand-built ClientHello carrying seven
extensions, and against their **refusals**: offered compression, an oversized
legacy session identifier, a key share whose length does not match the group it
claims, an `early_data` extension, a zero-length ALPN name, a cookie in an
ordinary ServerHello, and a server selecting a CBC suite. The ClientHello is also
truncated at **every length** from the header to one octet short of complete, and
every truncation must fail cleanly.

That last check found a real gap: a prefix stopping just before the extension
block is a well-formed extensionless ClientHello, and the parser accepted it,
because nothing compared the header's declared body length against the octets
supplied. Both hello parsers now make that comparison first.

Every message this library encodes is also **parsed back through the parser a
peer would use**, and the octets the specification fixes are asserted directly
alongside -- a round trip on its own cannot catch an encoding that both sides get
wrong the same way. That pairing found a real bug in the ClientHello encoder: the
deferred length prefix for the extension block and the one for a nested vector
inside `server_name` shared a variable, so closing the inner vector lost the
outer position and the block's length was back-patched over the wrong octets. The
encoders now give each nesting level its own mark.

The message-level refusals each carry their own check: a ServerHello built with
the HelloRetryRequest random (refused locally, because every peer would read it
as a retry), a `record_size_limit` below 64, a zero-length certificate entry, a
chain longer than the configured count, a CertificateRequest without
`signature_algorithms`, an empty CertificateVerify signature, a KeyUpdate request
octet of 2, a ticket lifetime past seven days, a zero-length ticket, and an
extension emitted after `pre_shared_key`.

The configuration layer is checked mostly through its **refusals**, because a
policy that cannot work must be rejected at `Build` rather than at the first
handshake: a client with no expected identity, a version enabled with no suite
for it, a key share for a group that is not offered, ALPN required with no
protocols, limits that cannot hold one record, a wildcard as an expected
identity, ticket issuance with no ticket key, and a TLS 1.2 suite ordered ahead
of a TLS 1.3 one. Invariant CERT-8 -- that a server cannot acquire finite-field
groups except through the explicitly named acceptor -- is checked in both roles,
including with a group list copied from elsewhere.

## What is not implemented

Nothing below is stubbed, faked, or partially present. Each is absent.

### Protocol

- ~~The remaining TLS 1.3 handshake messages.~~ Done. `SSL.Handshake_Messages`
  now carries every TLS 1.3 message in both directions: ClientHello, ServerHello,
  HelloRetryRequest, EncryptedExtensions, Certificate, CertificateRequest,
  CertificateVerify, Finished, NewSessionTicket and KeyUpdate, plus the
  `pre_shared_key` offer with the offset its binders stop covering. What is still
  missing is the code that *decides* what to put in them.
- ~~TLS 1.3 state machines, client or server.~~ Done for the full handshake.
  `SSL.TLS13.Client` and `SSL.TLS13.Server` are explicit machines with the
  RFC 8446 appendix A state names. They do no input and no output: each is handed
  one complete handshake message and answers with an ordered plan -- send these
  octets, install these keys, the handshake is complete -- which is what lets a
  whole handshake be run and asserted without a socket. Client authentication is
  requested and validated on the server side; a client asked for a certificate
  declines with an empty Certificate, because signing one needs an ECDSA
  encoder CryptoLib does not yet have. Resumption through `pre_shared_key` is
  parsed but not yet offered or accepted.
- ~~Restricted TLS 1.2~~ — the protocol is done: the PRF, the extended master
  secret, the key block, the TLS 1.2 record construction, the three messages
  TLS 1.3 does not have, and both state machines. A client and a server complete
  a handshake and exchange protected records in both directions, and the engine
  routes to it: one ClientHello serves both versions, a client falls back when
  the ServerHello does not select TLS 1.3, and a server routes on what the
  ClientHello offered. ~~Stateless TLS 1.2 tickets are absent~~ — done:
  RFC 5077's `session_ticket` travels in the hello that serves both versions, a
  server with a ticket-key ring issues a NewSessionTicket after the client's
  Finished, and a client that offers one back gets the abbreviated handshake,
  where the server goes first with its ChangeCipherSpec and Finished. The
  session's name, suite and application protocol are all checked before a ticket
  is taken up, and a ticket the server cannot open costs a resumption rather
  than a connection. This server does not renew a ticket it has just accepted,
  so a session lives exactly as long as the ticket that carried it.
- ~~Sessions, tickets and resumption.~~ Done. A server with a ticket-key ring
  issues NewSessionTickets in the flight that completes the handshake; a client
  with a cache derives each ticket's pre-shared key and keeps a session bound to
  the connection it came from; the next connection offers it with a binder over
  the truncated ClientHello, and the server opens the ticket, verifies the
  binder in constant time and resumes. Checked with three connections in a row,
  the second and third resuming. Always with a fresh key exchange: `psk_ke`
  alone is neither offered nor accepted, so a resumed connection has the same
  forward secrecy as a full one.
- ~~Exporters and channel bindings as public API.~~ Done. `SSL.Exporters` and
  `SSL.Channel_Bindings` exist, and both ends of a live connection are checked
  to derive the same material. `tls-unique` is deliberately absent: RFC 8446
  appendix C.5 says it does not apply to TLS 1.3, and this library implements no
  TLS 1.2 resumption that would qualify for it.
- ~~KeyUpdate scheduling.~~ Done. An engine queues an update when a direction's
  usage reaches the advisory threshold, sends the message under the key it
  replaces, installs the new key afterwards, answers a requested update exactly
  once, and bounds the run of updates a peer can drive.

### API

- ~~`SSL.Synchronized_Connections` does not exist.~~ Done. One reader task, one
  writer task and a controller share one connection over a serialized driver,
  which is the shape the specification's concurrency section describes. The
  lock is a protected object and the work happens outside it, because the work
  calls a transport and a transport is the application's own code. The reader
  polls at a millisecond interval while waiting, and the reason is written down
  rather than hidden: `SSL.Transports` reports "nothing available" and offers no
  way to wait for that to change, so a wrapper that wanted to sleep until
  readable would need a facility the transport interface does not have.
- Diagnostic events are emitted at the connection's start, its end, its
  handshake completion, each KeyUpdate and each peer alert. The per-message
  `Detailed_Protocol` events are declared and not yet emitted from every site
  that could emit one.
- Ticket issuance is still refused at `Build` with
  `Code_Ticket_Issuance_Without_Key` unless a ticket-key ring is attached, which
  is the specified "tickets disabled until valid ticket keys are configured" --
  enforced rather than documented.
- Six examples exist and run: a full handshake with an orderly shutdown, ALPN
  negotiation including the no-overlap refusal, an event-loop client over a
  transport that refuses half its reads, exporters and channel bindings, a
  diagnostic sink at two redaction levels, and mutual TLS with the server
  requiring a client certificate and asserting that it got one.

### The gap that had a named owner, now closed

**ECDSA signing is implemented.** A TLS ECDSA signature is a DER `SEQUENCE` of
two `INTEGER`s. CryptoLib's signers return `r` and `s` as fixed-width blocks --
which is what SSH puts on the wire -- and it now provides
`CryptoLib.ECDSA.Encode_DER_Signature`, which turns the pair into the encoding
X.509 and TLS want. Both halves are CryptoLib's; this library encodes no ASN.1
of its own, which is the same boundary that removed the RSASSA-PSS parameter
blobs once CryptoLib grew an entry point taking them as arguments.

The curve fixes the digest and RFC 8446 section 4.2.3 fixes the same pairing, so
there is no combination to get wrong: P-256 with SHA-256, P-384 with SHA-384,
P-521 with SHA-512. Verified against OpenSSL with `-verify_return_error` for a
server credential on both protocol versions, and against `openssl s_server
-Verify 1` -- which fails the handshake without a valid client certificate --
for a client one.

With it, **client authentication is complete**. A client that is asked for a
certificate and holds one the server would accept a signature from now sends the
chain and a CertificateVerify over the client context string. A client with no
credential, or none matching the request's `signature_algorithms`, still
declines with an empty Certificate: sending a chain this endpoint could not then
sign for would leave the server waiting for a CertificateVerify that never came,
and the handshake would fail with the shape of a protocol error rather than the
shape of a client that has no certificate.

### Verification and release

- ~~No mutation runner~~ — done. `Tests_Mutation` is deterministic: six kinds of
  mutation over every position of each seed, replayed identically on every run.
  It found a real defect on its first seed. `SSL.Handshake_Messages.Parse_Header`
  carried a precondition that the input be at least as long as a header, which
  turned a hostile short input into a raised exception at whichever caller had
  forgotten to check. Short input is now a structured failure.
- ~~No interoperability controller~~ — done, and passing against OpenSSL,
  GnuTLS and JSSE in both directions. Two stacks are declared and not driven:
  LibreSSL shares OpenSSL's command line and would run if the binary were
  present, and **BoringSSL has no driver at all** — its `bssl` has a command
  line of its own that nobody here has been able to exercise, and a driver
  written from documentation and never run would claim coverage it does not
  have. Both report a stable skip with the reason.
- ~~No GNATprove profiles~~ — done. `ssllib_tools prove` runs at two profiles,
  `development` and `release`, and both are clean.
- No platform matrix. Only Linux x86_64 has been built. `hostkit` carries the
  macOS and Windows implementations of what the tooling needs, and neither has
  been run.
- `ssllib_tools` implements every command: `build`, `test`, `test-vectors`,
  `test-corpus`, `test-interop`, `prove`, `verify`, `docs`, `package` and
  `release`.
  - `docs` generates one Markdown page per public specification from the
    specifications themselves — the `@summary` block, each declaration in full,
    and the comment that precedes it. Private packages are skipped, because
    publishing them as API pages would invite an application to depend on names
    it cannot legally reference.
  - `package` writes a sorted manifest of every source file with its SHA-256
    through CryptoLib, and one digest over the manifest. A manifest rather than
    an archive: what a release needs is something a second person can recompute
    and compare, and there is no timestamp, host name or build identifier
    anywhere in it. Two runs produce the same two files, octet for octet, and
    generated documentation is deliberately excluded so that the answer does not
    depend on whether `docs` had been run.
  - `release` runs every gate in the specification's order — verify, build,
    test, release-profile proof, the interoperability matrix, docs, package —
    and then **still refuses**, naming what is missing. Section 28 says not to
    declare V1 complete merely because the project builds; the outstanding gaps
    are a list in one place, and the gate passes only when that list is empty.

## Deviations from the specification, and why

One adaptation remains. Two earlier ones have been removed by changes in
CryptoLib.

**Resolved: finite-field Diffie-Hellman.** CryptoLib now provides
`CryptoLib.FFDHE`, the RFC 7919 named groups, distinct from the SSH MODP primes
in `CryptoLib.Diffie_Hellman`. `ffdhe2048`, `ffdhe3072` and `ffdhe4096` are
implemented and tested. They are offered but deliberately not in the default
group set: an ffdhe4096 exponentiation is thousands of times the work of an
X25519 multiplication for comparable strength, and its key share is 512 octets
against 32, so a caller that does not need them should not pay for them because
a default said so. `SSL.Supported_Groups.Finite_Field_Groups` is there for a
caller whose policy requires them. `ffdhe6144` and `ffdhe8192` are implemented
by CryptoLib and not offered here, since the specification's optional set stops
at `ffdhe4096`; their code points are recognized only so a diagnostic can name
them.

**Resolved: RSASSA-PSS parameters.** CryptoLib now provides
`CryptoLib.X509.Signatures.Verify_PSS_With_Key`, which takes the hash and salt
length as arguments rather than reading them out of a DER
`RSASSA-PSS-params`. That is exactly what a TLS CertificateVerify needs, since
RFC 8446 section 4.2.3 fixes the parameters per scheme and the signature carries
no AlgorithmIdentifier at all. `SSL.Crypto` previously encoded three constant DER
blobs purely so that CryptoLib could parse them straight back out; those are
gone, and the salt length now comes from
`CryptoLib.X509.Signatures.Digest_Length` rather than from a literal.

**The monotonic clock will not come from Hostkit.** The specification assigns
monotonic clocks to `hostkit`. Hostkit provides no monotonic clock, and does not
need to: `Ada.Real_Time.Clock` is monotonic by definition in every conforming
Ada implementation and involves no platform-specific code. When `SSL.Clocks` is
written it will use `Ada.Real_Time`, and `Hostkit` will keep the host
differences that are genuinely host differences — process execution and
temporary directories for the interoperability controller.

One deliberate design choice worth naming: **`SSL.Secrets.Secret` carries a
capacity discriminant** rather than one flat maximum. Everything in the key
schedule is at most 48 octets and an AEAD key at most 32, but an ffdhe4096 shared
secret is 512. A single 512-octet bound would have made a `Schedule` — which
holds ten secrets — five kilobytes, and would have made every wipe of a 32-octet
traffic key a 512-octet memset. There is no default discriminant, so each
declaration must name its capacity, and the wrong choice is a compile-time
failure rather than a silently oversized object.

## The order the rest should be built in

The specification's section 27 phase plan still applies. Phases 1 through 5 are
done. The next work, in dependency order:

1. ~~`SSL.Configurations`, `SSL.Authentication`, `SSL.Clocks`,
   `SSL.Cancellation`~~ — done.
2. ~~The extension registry~~ — done. The remaining handshake message codecs,
   and the encoding side of all of them.
3. ~~`SSL.Credentials`, the trust snapshot, pinning, revocation, the X.509
   pipeline, external signers, SNI selection, and attaching credentials and
   trust to `SSL.Configurations`~~ — done, except ECDSA signing (above).
   ~~Remaining here: plumbing CryptoLib's OCSP and CRL results into
   `SSL.Trust.Revocation.Status_Answer`~~ — done. A stapled OCSP response now
   reaches CryptoLib through `SSL.Certificate_Validation.Check_Stapled_Status`
   and its answer is evaluated against the configured policy, after the path has
   validated and before pinning. Nothing is fetched: a response that was not
   stapled does not exist.
4. ~~The TLS 1.3 state machines~~ — done, and with them the first end-to-end
   handshake between two in-process engines.
5. ~~`SSL.Engines` and the public API built on it: blocking, streams,
   transports~~ — done.
6. ~~Tickets, resumption and the client cache~~ — done, and `Ticket_Keys` in the
   server policy is now a real setting rather than permanently False.
7. ~~Restricted TLS 1.2~~ — done, except its stateless tickets.
8. ~~Diagnostics, metrics and unsafe key logging~~ — done.
9. ~~Mutation corpus, interoperability, proof profiles~~ — done. The platform
   matrix is not: only Linux x86_64 has been built.

What is left, in dependency order:

1. The `docs`, `package` and `release` commands, `release` last because it is
   the gate that runs every other one.
2. ECDSA client-certificate signing, whenever CryptoLib grows the encoder.
3. The platform matrix, which needs hosts this one is not.
