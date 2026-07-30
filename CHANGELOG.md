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
- `SSL.Supported_Groups` — X25519, secp256r1, secp384r1, secp521r1, with the
  share and secret lengths that bound a peer's `key_share` before any curve
  arithmetic sees it.
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
  volatile stores on overwrite and on finalization.
- `SSL.Wire` (private) — explicit big-endian codecs and bounded cursors with a
  sticky failure flag; no unchecked conversion of wire octets anywhere.
- `SSL.Crypto` (private) — the single CryptoLib seam: hashing, HMAC, HKDF,
  Expand-Label, Derive-Secret, AEAD seal and open, X25519 and NIST ECDH,
  signature verification, randomness, secure wiping.
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
- `ssllib_tests` — an AUnit suite of 36 cases, including the RFC 8448 section 3
  key-schedule vectors, byte-boundary truncation of nested wire structures,
  exhaustive single-bit tamper rejection across a protected record and its
  header, and a check that no plaintext octet survives an authentication
  failure.
- `ssllib_tools` — the Ada driver. `build`, `test`, `test-vectors` and `verify`
  work; `verify` audits the dependency boundary, test registration, version
  consistency, document presence and invariant coverage. `test-corpus`,
  `test-interop`, `prove`, `docs`, `package` and `release` exit 3 and say why.
  `release` refuses rather than producing artifacts that would imply the V1
  gates had passed.

### Not yet present

The TLS 1.3 and TLS 1.2 handshake state machines, the public engine and the API
built on it, credentials and trust, sessions and tickets, diagnostics, the
mutation corpus, the interoperability matrix, the proof profiles and the platform
matrix. See `docs/status.md`.
