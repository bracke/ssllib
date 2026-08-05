# Changelog

All notable changes to `ssllib` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
semantic versioning once it reaches 1.0.0.

## [Unreleased] — 0.1.0-dev

Foundations only. `ssllib` cannot open a TLS connection in this state; see
`docs/status.md` for the subsystem-by-subsystem account.

### Added

- `SSL` — the octet view the whole library speaks, and the typed stable
  identifiers: `Connection_ID`, `Credential_ID`, `Session_ID`,
  `Security_Context_ID`, `Configuration_Fingerprint`, `Trust_Fingerprint`,
  `Certificate_Fingerprint`.
- `SSL.Version` — crate identity, protocol scope, and the list of deliberate
  absences, so a program recording provenance records the absences too.
- `SSL.Limits` — every peer-influenced count and length, with a consistency
  check that refuses a configuration which would deadlock rather than refuse.
- `SSL.Errors` — structured failure information with a stable category, an
  explicit numeric code, an origin, a fatality, an optional alert, a lifecycle
  stage, bounded parameters, a retry classification and a disclosure
  classification; plus the one central table that maps a code to an alert, and
  first-terminal-failure preservation with a bounded secondary count.
- `SSL.Alerts` — the closed alert set with wire values written out rather than
  derived from enumeration positions, terminality decided on the description
  rather than on the peer's level octet, and unknown peer descriptions preserved
  verbatim.
- `SSL.Versions` — TLS 1.2 and TLS 1.3, immutable version sets, and named
  recognition of the four obsolete versions so that a diagnostic can say which
  one a peer offered.
- `SSL.Cipher_Suites` — all nine suites, their composition, and ordered
  preference lists that refuse duplicates.
- `SSL.Supported_Groups` — X25519, secp256r1, secp384r1, secp521r1 and the
  RFC 7919 finite-field groups ffdhe2048, ffdhe3072 and ffdhe4096, with the
  share and secret lengths that bound a peer's `key_share` before any curve or
  modular arithmetic sees it. The finite-field groups are offered but never
  default; `Finite_Field_Groups` is there for a policy that requires them.
- `SSL.Signature_Schemes` — the fourteen schemes, the TLS 1.3 rule that PKCS#1
  v1.5 never signs a CertificateVerify, and the binding of each ECDSA scheme to
  one curve.
- `SSL.ALPN` — opaque protocol names, server-order and client-order selection,
  and policy validation that refuses "required" with an empty list.
- `SSL.Server_Names` — validated DNS names with ASCII-only folding, leftmost
  single-label wildcards with specificity ranking, and binary IP identities.
- `SSL.Buffers` (private) — heap-backed fixed-capacity stores and octet FIFOs
  that scrub on release and refuse rather than grow.
- `SSL.Secrets` (private) — bounded controlled secrets that wipe through
  volatile stores on overwrite and on finalization, with a capacity
  discriminant so that a 32-octet traffic key and a 512-octet ffdhe4096 shared
  secret do not share one bound. No default discriminant: a declaration must
  name its capacity, so the wrong choice is a compile-time failure.
- `SSL.Wire` (private) — explicit big-endian codecs and bounded cursors with a
  sticky failure flag; no unchecked conversion of wire octets anywhere.
- `SSL.Crypto` (private) — the single CryptoLib seam: hashing, HMAC, HKDF,
  Expand-Label, Derive-Secret, AEAD seal and open, key agreement over X25519,
  the NIST curves and the RFC 7919 finite-field groups, signature verification
  including the TLS RSASSA-PSS profile, randomness, secure wiping.
- `SSL.Transcripts` (private) — exact handshake-message absorption,
  non-finalizing snapshots, both candidate hashes run in parallel until the
  suite is chosen, and the RFC 8446 section 4.4.1 `message_hash` transformation.
- `SSL.Key_Schedule` (private) — the whole RFC 8446 section 7.1 schedule with
  stage ordering enforced, traffic keys, Finished keys, PSK binders, KeyUpdate
  advance, RFC 8446 section 7.5 exporters, and per-nonce resumption PSKs.
- `SSL.Records` (private) — the explicit five-octet header codec, per-direction
  traffic state, RFC 8446 section 5.3 nonce construction, protection and opening
  with padding removed only after authentication, and usage counters with soft
  and hard thresholds.
- `SSL.Clocks` — a wall clock for certificate validity and a monotonic clock for
  deadlines, kept apart, both entering the engine as parameters rather than
  being read inside it. An absent wall time sorts before every present one, so a
  validity check against an unset clock refuses.
- `SSL.Cancellation` — a one-way latch a caller sets from another task. Not
  resettable: a token that could be un-cancelled has a race with no correct
  resolution.
- `SSL.Authentication` — what authenticated a peer, distinguishing a chain
  validated during this handshake from an identity inherited through resumption.
  A resumption keeps the original authentication time and the fingerprints, and
  deliberately drops the signature scheme and path length, because no signature
  was made and no path was built.
- `SSL.Configurations` — immutable client and server configurations, limited
  builders, `Secure_Client_Defaults`, `Secure_Server_Defaults`,
  `Modern_Compatibility_Client`, `Modern_Compatibility_Server`, validation at
  `Build`, and configuration fingerprints that separate any two policies a peer
  could tell apart. There is no flag that disables path validation or identity
  checking. Finite-field groups cannot be set through `Set_Groups` in either
  role; a server acquires them only through
  `Accept_Finite_Field_Groups_With_Amplification_Risk` (invariant CERT-8).
- `SSL.Extensions` (private) — the closed extension registry: wire identifiers
  written out, the RFC 8446 section 4.2 context table as an explicit case so
  that adding an extension without deciding its contexts does not compile,
  duplicate refusal before a second body is opened, and unknown identifiers kept
  bounded for diagnostics. No registration call and no plugin seam.
- `SSL.Handshake_Messages` (private) — the four-octet framing every message and
  the transcript share, and the ClientHello and ServerHello/HelloRetryRequest
  parsers. A HelloRetryRequest is recognized by the RFC 8446 section 4.1.3
  random alone, which is the only signal there is, and it changes which
  extensions are permitted. Key shares and cookies are reported as spans into
  the message rather than copies, so nothing is duplicated and the transcript
  still hashes the octets that arrived.
- Every remaining TLS 1.3 handshake message, in both directions:
  EncryptedExtensions, Certificate, CertificateRequest, CertificateVerify,
  Finished, NewSessionTicket and KeyUpdate, plus encoders for ClientHello,
  ServerHello and HelloRetryRequest. Each parser checks that the header names the
  message it is parsing and that the declared body length equals the octets
  supplied, before reading a field; each encoder emits nothing at all when the
  buffer is too small, because a truncated message is one the transcript would
  hash and the peer could not parse. Extension order in an encoded ClientHello is
  fixed and deterministic, with `pre_shared_key` reserved for last.
- The `pre_shared_key` offer of a ClientHello: identities with their reported
  ages, binders matched to them by position, and the offset at which the binders
  stop covering the message -- the one thing a parser must hand back as a
  position rather than a value, because recomputing it would mean re-encoding a
  message a hostile peer wrote.
- `SSL.Handshake_Messages.Certificate_Verify_Content` — the exact octets an
  RFC 8446 section 4.4.3 signature covers, with the two role context strings
  written out rather than composed.
- `SSL.TLS13`, `SSL.TLS13.Client` and `SSL.TLS13.Server` — the TLS 1.3
  handshake as two explicit state machines with the RFC 8446 appendix A state
  names. Neither does any input or output: each is handed one complete handshake
  message and answers with an ordered plan of steps -- send this span, install
  these keys, the handshake is complete. Key installation is a step rather than
  something a driver infers, because the two directions change keys at
  asymmetric moments and a driver working that out for itself would be a second
  place for it to be wrong. A whole handshake now runs in the test suite with no
  transport at all, and the check that it worked is that a record the client
  seals opens on the server.
- `SSL.Versions.Has_Downgrade_Sentinel` — the RFC 8446 section 4.1.3 downgrade
  markers, checked by the client against every ServerHello random.
- `SSL.Transports` — the interface between this library and whatever moves
  octets, with the six transport statuses the specification names and an
  exception boundary that converts a transport that raises, or that claims to
  have moved more than it was given, into a structured failure.
- `SSL.Engines` and `SSL.Engines.Events` — the protocol driver. Encrypted octets
  in, encrypted octets out, application data in between; no socket, no task, no
  wait. Every operation is partial and reports what it actually moved, because a
  driver that treated a short transfer as a failure would be unusable with
  non-blocking I/O.
- `SSL.Connections`, `SSL.Clients` and `SSL.Servers` — a connection with a
  transport bound to it. Role is a package rather than a parameter: a client and
  a server run different machines and have different obligations, and an API
  where the role is an argument invites code that passes it through from
  somewhere else.
- `SSL.Blocking` — handshake, read, write and shutdown with deadlines, for
  callers with no event loop of their own. Every operation takes a deadline,
  because a blocking call without one is a program that can stop responding
  because a peer stopped talking.
- `SSL.Streams` — an `Ada.Streams.Root_Stream_Type` over a connection. The one
  place in the library where a failure is an exception, and only because the
  inherited signature has nowhere to put a structured one; the package says so.
- `SSL.Connection_Metadata` — what a finished connection reports: what was
  negotiated and what was proved, as one immutable value.
- `SSL.Certificate_Validation.No_Result` and `SSL.Key_Schedule.Has_Resumption`.
- KeyUpdate, in full: scheduled when a direction's usage reaches the advisory
  threshold, sent under the key it replaces, the new key installed only
  afterwards, an `update_requested` answered exactly once with
  `update_not_requested`, and the run of peer updates bounded.
- `SSL.Exporters` — exported keying material bound to the connection, with no
  getter for the secret it comes from.
- `SSL.Channel_Bindings` — `tls-exporter` and `tls-server-end-point`.
  `tls-unique` is deliberately absent and the package says why.
- `SSL.Digest_Of` and `SSL.Is_Present` for a `Certificate_Fingerprint`, so a
  channel binding can have the digest as octets without round-tripping through
  hexadecimal.
- `SSL.Diagnostics` — structured events with the five levels and three
  redaction classes the specification names, and a sink an application supplies.
  The library opens no file, writes nowhere on its own, reads no environment
  variable, and never logs key material or plaintext. A sink that raises loses
  its event and nothing else.
- `SSL.Unsafe` and `SSL.Unsafe.Key_Logging` — key logging in the NSS format, for
  decrypting one's own captures. Off unless a configuration attaches a sink,
  reachable only by writing the word `Unsafe` in a `with` clause, and
  deliberately not enabled by `SSLKEYLOGFILE`: a facility an environment
  variable enables is a facility anyone who can set environment variables
  enables. The formatting buffer is wiped on every path out, including the one
  where the sink raised.
- `SSL.Configurations.Set_Diagnostics` and `Set_Unsafe_Key_Logging`.
- `SSL.Ticket_Keys` — the keys a server seals its session tickets with, their
  four-state rotation, and the versioned sealed format. A ticket is
  authenticated before it is parsed; its version, family, purpose and key
  identifier are part of what is authenticated; every reason it might be
  unusable produces one undifferentiated refusal, so that a peer probing a
  server's key rotation learns nothing from which refusal it got.
- `SSL.Sessions`, `SSL.Sessions.Client_Caches` and
  `SSL.Sessions.Client_Caches.Memory` — a session and its bindings, the cache
  interface, and a bounded task-safe in-memory implementation with
  least-recently-used eviction. A session handed out is removed: a TLS 1.3
  ticket is single-use, and offering one twice is what makes two connections
  linkable to an observer.
- Session resumption, end to end. A server with a ticket-key ring issues
  NewSessionTickets in the flight that completes the handshake; a client with a
  cache derives each ticket's pre-shared key and keeps a session bound to the
  connection it came from; the next connection offers it with a binder computed
  over the ClientHello truncated immediately before the binders list, and the
  server opens the ticket, verifies the binder in constant time and resumes
  without sending a Certificate or a CertificateVerify. A ticket that opens but
  whose binder does not verify ends the connection rather than falling back --
  falling back would make a server a free oracle for testing stolen tickets.
  Resumption always comes with a fresh key exchange: `psk_ke` alone is neither
  offered nor accepted.
- `SSL.Clocks.Seconds_Since_Epoch`, `From_Seconds_Since_Epoch` and `Advanced`,
  because a ticket has to carry an instant across a process boundary and a
  lifetime has to be added to one.
- `SSL.Digest_Of` and the fingerprint constructors for the configuration and
  trust fingerprints, for the same reason.
- `SSL.Configurations.Set_Ticket_Keys` and `Set_Session_Cache`.
- Restricted TLS 1.2, as its own implementation rather than a mode of the
  TLS 1.3 one: `SSL.TLS12` (the PRF, the extended master secret, the key block,
  the Finished verify data), `SSL.TLS12.Records` (the TLS 1.2 AEAD
  construction, which differs from TLS 1.3's in the outer content type, the
  additional data and the nonce -- except for ChaCha20-Poly1305, which RFC 7905
  gave the TLS 1.3 construction), `SSL.TLS12.Messages` (ServerKeyExchange,
  ServerHelloDone, ClientKeyExchange, the TLS 1.2 hellos and the TLS 1.2
  Certificate), and `SSL.TLS12.Client` and `SSL.TLS12.Server`. ECDHE only, AEAD
  only, extended master secret mandatory, no renegotiation, no compression, no
  static key exchange of any kind.
- A deterministic mutation runner, `Tests_Mutation`: every single-bit flip,
  truncation, insertion, deletion, corrupted length and zeroed length of four
  seed messages, each handed to every parser. Deterministic in every argument,
  so a failure is reproducible from three numbers and a corpus entry needs no
  stored blob. Over ten thousand mutations per run.
- Limit-boundary checks at limit-1, at the limit and at limit+1, plus a
  sixteen-megabyte declared length behind a four-octet message -- the shape that
  distinguishes "bounded before allocation" from "bounded after".
- A whole connection delivered one octet at a time -- so that every record
  header, length prefix and epoch transition is split at every internal
  boundary -- and then several records supplied in one call, which is the
  opposite hazard.
- Concurrency: eight tasks doing every operation the session cache has, on
  overlapping keys. And a diagnostic sink that calls back into the library from
  inside its own `Emit`, with the observed nesting depth asserted to be one.
- Version negotiation in `SSL.Engines`: one ClientHello serves both versions, a
  client that finds the ServerHello did not select TLS 1.3 hands the connection
  to the TLS 1.2 machine and *adopts the hello it already sent* rather than
  encoding a second one, and a server routes on what the ClientHello offered. A
  server never chooses TLS 1.2 when the client offered TLS 1.3.
- `SSL.Extensions.In_Legacy_Server_Hello` — a TLS 1.2 ServerHello permits the
  server-name acknowledgement and the selected application protocol, which
  TLS 1.3 moved into EncryptedExtensions so that they are encrypted. One context
  for both would refuse a conforming hello from one version.
- Stapled OCSP responses are plumbed through: a client hands what the peer
  attached to CryptoLib, translates the answer into
  `SSL.Trust.Revocation.Status_Answer`, and evaluates it against the configured
  policy -- after the path has validated and before pinning, which is the order
  the pipeline fixes. Nothing is fetched, in any mode: a handshake that reached
  out to a responder would leak who was connecting to whom.
- Five runnable examples under `examples/`, each supplying its own in-memory
  transport so that it runs anywhere with no network: a full handshake, ALPN
  with the no-overlap refusal, an event-loop client over a transport that
  refuses half its reads, exporters and channel bindings, and diagnostics at two
  redaction levels.
- `SSL.Credentials` — a local chain and its signing capability as a limited
  controlled type that scrubs itself. Everything expensive happens at load:
  decoding, decryption, the key-matches-leaf and chain-order checks (CryptoLib's),
  the subjectAltName names the credential may be presented for, and which
  signature schemes the key can actually produce. No entry point reads a file, so
  a handshake can never block on a disk or a password prompt. Ed25519, Ed448 and
  both RSA paddings sign; ECDSA is refused with a named reason pending a
  CryptoLib DER signature encoder.
- `SSL.Trust` — immutable anchor snapshots from `truststores`, from explicitly
  selected NSS and Java stores, or from application-supplied PEM. A required
  source that is unavailable or empty fails closed rather than producing an empty
  snapshot. The fingerprint binds sessions to the trust base they were
  established under.
- `SSL.Trust.Pinning` — certificate and SPKI pins with name and ALPN scopes and
  mandatory activation periods. A pin set that covers nothing is a scope
  mismatch, not a pass; `Pin_Only` still requires identity matching.
- `SSL.Trust.Revocation` — the four policies, with evidence and its source kept
  distinct. Nothing here opens a network connection in any mode. An explicit
  revocation fails in every mode, including the disabled one.
- `SSL.Certificate_Validation` (private) — the pipeline in one fixed order over
  CryptoLib's path builder and validator, with a candidate pool that decides
  anchor-ness by provenance rather than by self-signature.
- `SSL.Credentials.Signers` — the external-signer interface, for a key in an HSM,
  a TPM or a remote service. A signer declares what it can do without touching
  the device, says whether it needs serialized access rather than being guessed
  at, and receives the exact octets to sign rather than a digest. Every call goes
  through a boundary that converts an exception into a structured provider
  failure.
- `SSL.Configurations` — credentials and trust snapshots attach, which turns on
  the last three validation rules: a client with no anchors, a server with no
  credential, and a server requesting client certificates with nothing to check
  them against are all refused at `Build`. `Select_Credential` ranks by
  subjectAltName specificity, then capability under the negotiated version, then
  insertion order.
- `ssllib_tests` — an AUnit suite of 63 cases, including the RFC 8448 section 3
  key-schedule vectors, byte-boundary truncation of nested wire structures,
  exhaustive single-bit tamper rejection across a protected record and its
  header, and a check that no plaintext octet survives an authentication
  failure, key agreement over every offered group in both directions with
  wrong-length and degenerate peer shares refused, and RSASSA-PSS verification
  including that the scheme really selects the hash, and the configuration
  layer's refusals -- a missing expected identity, a version with no suite, an
  unoffered key share, an unsatisfiable ALPN or revocation policy, ticket
  issuance with no key, and a TLS 1.2 suite ordered ahead of a TLS 1.3 one; and
  the hello parsers against a seven-extension ClientHello, their refusals, and
  truncation at every length from the header to one octet short of complete.
- `ssllib_tools` — the Ada driver. `build`, `test`, `test-vectors`,
  `test-corpus`, `test-interop`, `prove` and `verify` work; `verify` audits the
  dependency boundary, test registration, version consistency, document presence
  and invariant coverage. `docs`, `package` and `release` exit 3 and say why.
  `release` refuses rather than producing artifacts that would imply the V1
  gates had passed.
- `SSL.Synchronized_Connections` — one connection from a reader task, a writer
  task and a controller, over a serialized driver. The lock is a protected
  object and every operation on the connection happens outside it, because the
  operation calls a transport and calling application code from inside a
  protected body is a bounded error whatever the code does. The controller's
  `Request_Shutdown` and `Cancel` do not take the lock at all: a controller that
  waited for a busy reader could not interrupt it, which is the one thing it
  exists to do.
- Stateless TLS 1.2 tickets: RFC 5077's `session_ticket` in the hello that
  serves both versions, NewSessionTicket after the client's Finished, and the
  abbreviated handshake in which the server sends its ChangeCipherSpec and
  Finished first. The session's name, cipher suite and application protocol are
  all checked before a ticket is taken up; a ticket the server cannot open costs
  a resumption and not a connection; and a resumed handshake is not renewed, so
  a session lives exactly as long as the ticket that carried it.
- `SSLLib_Interop` and `ssllib_peer` — the interoperability controller and the
  external peer it drives. Every check asserts the *negotiated outcome* —
  version, suite, group, protocol, whether the peer authenticated — rather than
  that a socket connected, because a stack that fell back to TLS 1.2 or skipped
  verification would look like success to a connection check. Loopback only,
  credentials in a directory per stack that is removed afterwards, the host's
  trust store never consulted, and a stable named skip for an absent tool.
  Passing against OpenSSL, GnuTLS and JSSE in both directions.
- `tests/src/tools/java/SSLLibJavaPeer.java` — a driver for Java's own TLS
  stack, run from source. It is a driver for an external stack in the same sense
  that `openssl s_client` is: nothing in this repository is built with Java, and
  no part of the build, the test run or the release depends on it.

### Changed

- `SSL.Configurations.Revocation_Policy` is now a subtype of
  `SSL.Trust.Revocation.Revocation_Policy` rather than a second enumeration with
  the same values. Two declarations of one policy were two places for them to
  drift apart. The names are re-exported, so no caller changes.

- `SSL.Key_Schedule.Derive_Master` no longer derives the resumption master
  secret; `Derive_Resumption` does, from the client-Finished transcript. The two
  are bound to different milestones, and deriving both from one call meant a
  server could not have its application traffic secrets until the client's
  Finished arrived -- which would have made half-RTT server data impossible.
  Found by the first end-to-end engine test, as a failed precondition.
- `SSL.Key_Schedule.Export`'s documentation said an absent context and an empty
  one were different inputs. Under TLS 1.3 they are not: RFC 8446 section 7.5
  defines the absent case as the empty string, so both hash the empty string and
  both give the same output. The flag is still a parameter, because TLS 1.2's
  exporter (RFC 5705) does distinguish them. Found by a check written to assert
  the claim, which failed.
- `SSL.Credentials.Sign` takes the credential as `in` rather than `in out`.
  Signing reads the private key and records nothing, and the previous mode meant
  a server could not sign through the read-only reference its own configuration
  hands out.

- Finite-field Diffie-Hellman is implemented, over the `CryptoLib.FFDHE` groups
  that CryptoLib now provides. It was previously listed as a deviation from the
  specification, because the SSH MODP primes in `CryptoLib.Diffie_Hellman` are
  not the RFC 7919 ones and implementing them here would have crossed the
  ownership boundary.
- RSASSA-PSS verification now passes the hash and salt length to
  `CryptoLib.X509.Signatures.Verify_PSS_With_Key` as arguments. `SSL.Crypto`
  previously carried three constant DER `RSASSA-PSS-params` blobs purely so that
  CryptoLib could parse them straight back out; they are gone, and the salt
  length comes from `Digest_Length` rather than from a literal.

### Fixed

- `SSL.Handshake_Messages.Parse_Header` had a precondition requiring at least
  four octets. It is the first thing every message from a peer reaches, so the
  contract put the burden of checking on every caller and turned a hostile input
  into a raised exception at whichever one forgot. The precondition is gone and
  a short buffer is a structured failure. Found by the mutation runner, on the
  first seed it tried.

- The ClientHello encoder shared one deferred-length variable between the
  extension block and a vector nested inside `server_name`, so closing the inner
  vector lost the outer position and the block's length was back-patched over the
  wrong octets: the message went out with an extension block of length zero.
  Every nesting level now owns its own mark. Found by parsing an encoded
  ClientHello back through the parser a peer would use.
- Both hello parsers now check the handshake header's declared body length
  against the octets supplied before reading any field. Without it, a prefix
  stopping just before the extension block parsed as a well-formed
  extensionless ClientHello. Found by the truncate-at-every-length check.

### Fixed

- `SSL.Credentials`' loader called `Certificate_At`, whose precondition requires
  a loaded credential, while still loading one. The loader now indexes the span
  directly; the precondition is right for callers and was wrong for the loader.
- `SSL.Certificate_Validation` built the X.509 validity moment in a declarative
  part, before checking that a wall clock had been supplied. Every `Wall_Time`
  field accessor requires a present value, so the no-clock case raised instead of
  refusing. The check now precedes the construction.

- The interoperability controller ran its external server inside a task's
  *declarative* part. A block does not execute its own first statement until
  every task it activates has finished elaborating its declarations, so the
  server ran to completion — bind, readiness marker, timeout, kill — before the
  controller reached the line that drove the client against it. The symptom was
  perfect camouflage: the marker was there, the peer's own log said it had been
  listening, and the connection was refused. The run now happens in the task's
  statements.

- **RSA signing never worked.** `SSL.Credentials.Sign` sized an RSA signature
  from the modulus's *encoded* length. A DER INTEGER whose top bit is set
  carries a leading zero octet and every RSA modulus has its top bit set, so
  every signature buffer was one octet too long and CryptoLib refused each one
  — RFC 8017 fixes the length at exactly k. The width now comes from
  `Modulus_Bits`. No test had ever exercised RSA signing; the whole RSA
  credential path was dead. Found by pointing OpenSSL at a server holding an
  RSA credential.
- **The TLS 1.2 server chose a cipher suite without regard to its credential.**
  `ECDHE_RSA` and `ECDHE_ECDSA` differ in nothing but the authentication
  algorithm, so a server holding an RSA key could select `ECDHE_ECDSA` and then
  send an RSA certificate under it. Every client that checks reports "wrong
  certificate type". The credential is now selected first and the suite chosen
  to match it.
- **A TLS 1.2 connection never sent `close_notify`.** `Begin_Shutdown` and the
  alert path knew only the TLS 1.3 record layer, so a TLS 1.2 connection marked
  itself closed and let the socket drop — which every correct peer reports as a
  truncation attack, and which OpenSSL and GnuTLS both did. Alerts now go out
  under whichever record layer is running.
- **The TLS 1.2 server echoed the client's session identifier on a full
  handshake.** Under RFC 5077 section 3.4 that echo *is* the statement that a
  ticket was accepted, so a client offering one read every full handshake as a
  resumption and then met a Certificate it was not expecting. The identifier is
  now echoed only when a ticket really was taken up.

- `ssllib_tools docs`, `package` and `release`. `docs` extracts one Markdown
  page per public specification from the specifications themselves. `package`
  writes a sorted source manifest with a SHA-256 per file through CryptoLib and
  one digest over the manifest — reproducible by construction, with no
  timestamp, host name or build identifier in it. `release` runs every gate in
  order and refuses while anything is on the outstanding-gaps list, naming what
  it is.

- `SSL.Secrets.Observe_Wipes` — a test-only hook that fires whenever a secret
  is scrubbed. It is handed the number of octets wiped and nothing else, it is
  null by default, and nothing in this library ever installs one. The
  specification asks for secret cleanup to be tested through wipe observers, and
  there is no other way to tell "this was scrubbed" from "this went out of scope
  and the storage happened to be reused".

- Documentation: four topic guides under `docs/guides/` and four
  machine-readable documents under `docs/machine/`, plus generated API pages and
  four specification tables. The tables are produced by asking the registries —
  cipher suites, groups, schemes, extension contexts, alerts — rather than by
  transcribing them, so a table cannot disagree with the library: it *is* the
  library answering. `ssllib_tools verify` requires every one of these documents
  to exist and to say something.

- ECDSA signing, over P-256, P-384 and P-521, now that CryptoLib provides
  `Encode_DER_Signature`. The signers return `r` and `s` as fixed-width blocks
  and CryptoLib encodes the DER `SEQUENCE`; this library still encodes no ASN.1
  of its own. The curve fixes the digest and RFC 8446 section 4.2.3 fixes the
  same pairing, so there is no combination to get wrong.
- A mutual-TLS example, which was previously absent because it could not have
  worked.
- Client authentication, completed by the above. A client asked for a
  certificate sends the chain and a CertificateVerify over the client context
  string when it holds a credential the request would accept a signature from,
  and declines with an empty Certificate when it does not. Checked end to end in
  the suite, and against `openssl s_server -Verify 1`, which fails the handshake
  without a valid client certificate.

### Not yet present

The platform matrix. See `docs/status.md`.
