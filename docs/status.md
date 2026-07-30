# Implementation status

This document is the honest account of what `ssllib` currently is, measured
against the V1 specification in `ssllib_complete_implementation_prompt.txt`.

**`ssllib` is not usable as a TLS library today.** It cannot open a connection,
because the handshake state machines and the public engine are not implemented.
What exists is the foundation those need, built and tested: the wire codecs, the
record layer, the transcript, the TLS 1.3 key schedule, the algorithm
registries, the structured error and alert model, and the bounded-buffer and
secret-handling machinery.

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
| Named groups: X25519, P-256, P-384, P-521 | `SSL.Supported_Groups` | complete |
| Signature schemes, version rules, curve binding | `SSL.Signature_Schemes` | complete |
| ALPN names and selection policy | `SSL.ALPN` | complete |
| Validated DNS names, wildcards, IP identities | `SSL.Server_Names` | complete |
| Fixed-capacity stores and octet FIFOs | `SSL.Buffers` (private) | complete |
| Controlled secrets with non-elidable wiping | `SSL.Secrets` (private) | complete |
| Explicit wire codecs with bounded cursors | `SSL.Wire` (private) | complete |
| The single CryptoLib seam | `SSL.Crypto` (private) | complete |
| Handshake transcript, dual-hash, HRR transform | `SSL.Transcripts` (private) | complete |
| TLS 1.3 key schedule, all secrets and products | `SSL.Key_Schedule` (private) | complete |
| Record layer: header, traffic state, AEAD, nonces | `SSL.Records` (private) | complete |
| AUnit suite: 36 cases | `ssllib_tests` | passing |
| Ada tooling: build, test, verify | `ssllib_tools` | partial |

The key schedule is checked against **RFC 8448 section 3** — the published
handshake secret, both handshake traffic secrets (through the keys and IVs they
expand to), and the derived-secret chain. Those values were also recomputed from
the RFC 8446 section 7.1 definitions with an independent HKDF implementation
before being committed; the two agreed.

The record layer is checked for round-trip under all padding lengths from 0 to
64, for rejection of every single-bit flip across the ciphertext and the tag,
for rejection of every single-bit flip in the five header octets (which proves
the header really is the AEAD's associated data), for refusal of an out-of-order
record, for producing no plaintext whatsoever on an authentication failure, and
for refusing a record whose authenticated plaintext has no inner content type.

The wire codecs are checked at every truncation of a nested length-prefixed
structure, from zero octets to one short of complete.

## What is not implemented

Nothing below is stubbed, faked, or partially present. Each is absent.

### Protocol

- **TLS 1.3 handshake messages and extensions.** No ClientHello, ServerHello,
  HelloRetryRequest, EncryptedExtensions, Certificate, CertificateVerify,
  Finished, NewSessionTicket or KeyUpdate codec; no extension registry.
- **TLS 1.3 state machines**, client or server.
- **Restricted TLS 1.2** in its entirety: PRF, EMS, ServerKeyExchange, CCS epoch
  switch, state machines, stateless tickets, downgrade markers.
- **Sessions, tickets and resumption.** The key schedule produces resumption
  PSKs and the per-ticket nonce separation is tested, but there is no ticket
  format, no ticket-key state machine, and no client cache.
- **Exporters and channel bindings** as public API. `SSL.Key_Schedule.Export`
  implements RFC 8446 section 7.5 and is tested; `SSL.Exporters` and
  `SSL.Channel_Bindings` do not exist.
- **KeyUpdate scheduling.** `SSL.Key_Schedule.Advance_Traffic_Secret` and the
  usage counters and thresholds in `SSL.Records` exist and are tested; the
  scheduling logic that drives them does not.

### API

- `SSL.Engines`, `SSL.Engines.Events`, `SSL.Connections`, `SSL.Blocking`,
  `SSL.Streams`, `SSL.Transports`, `SSL.Clients`, `SSL.Servers`,
  `SSL.Configurations`, `SSL.Credentials`, `SSL.Trust`, `SSL.Sessions`,
  `SSL.Diagnostics`, `SSL.Authentication`, `SSL.Clocks`, `SSL.Cancellation`,
  `SSL.Connection_Metadata`, `SSL.Exporters`, `SSL.Channel_Bindings`,
  `SSL.Unsafe.Key_Logging` — none of these exist.
- Consequently there are **no examples**: an example that used secure defaults,
  verified identity and shut down cleanly would need all of the above.

### Verification and release

- No mutation or fuzz corpus, and no deterministic Ada mutation runner.
- No interoperability controller and no external-stack matrix.
- No GNATprove profiles. Several units carry contracts written with proof in
  mind (`SSL.Wire`, `SSL.Records`, `SSL.Limits`), but no proof has been run.
- No platform matrix. Only Linux x86_64 has been built.
- `ssllib_tools` implements `build`, `test`, `test-vectors` and `verify`.
  `test-corpus`, `test-interop`, `prove`, `docs`, `package` and `release` exit 3
  and say why. In particular **`release` refuses**, rather than producing
  artifacts that would imply the V1 gates had passed.

## Deviations from the specification, and why

Two adaptations were forced by what the dependencies provide. Both are
documented rather than worked around.

**Finite-field Diffie-Hellman groups are absent.** The specification lists
`ffdhe2048`, `ffdhe3072` and `ffdhe4096` as "optional only when fully supported
and tested". CryptoLib provides the SSH MODP groups (group14/16/18), not the
RFC 7919 FFDHE groups, so ssllib cannot implement them without either
duplicating cryptography — which the ownership boundary forbids — or shipping an
untested group. `SSL.Supported_Groups` recognizes the three code points so a
diagnostic can name them, and refuses them.

**The monotonic clock will not come from Hostkit.** The specification assigns
monotonic clocks to `hostkit`. Hostkit provides no monotonic clock, and does not
need to: `Ada.Real_Time.Clock` is monotonic by definition in every conforming
Ada implementation and involves no platform-specific code. When `SSL.Clocks` is
written it will use `Ada.Real_Time`, and `Hostkit` will keep the host
differences that are genuinely host differences — process execution and
temporary directories for the interoperability controller.

One deliberate design choice worth naming: **RSASSA-PSS parameters are embedded
as three constant DER blobs** in `SSL.Crypto`. CryptoLib's X.509 signature layer
reads the PSS hash and salt length out of an AlgorithmIdentifier, which is where
a certificate keeps them; a TLS CertificateVerify has no such field because
RFC 8446 section 4.2.3 fixes MGF1-with-the-same-hash and a salt length equal to
the digest length. Those are constants, one per hash, so they are committed as
data. No ASN.1 is encoded in ssllib, because there is nothing variable to encode.

## The order the rest should be built in

The specification's section 27 phase plan still applies. Phases 1 through 5 are
done. The next work, in dependency order:

1. `SSL.Configurations` with builders, secure defaults and validation, plus
   `SSL.Authentication` and `SSL.Clocks` — everything above needs a
   configuration to read policy from.
2. The extension registry and the TLS 1.3 handshake message codecs.
3. `SSL.Credentials`, the `truststores` adapter, and the X.509 authentication
   pipeline over CryptoLib.
4. The TLS 1.3 state machines, and with them the first end-to-end handshake
   between two in-process engines.
5. `SSL.Engines` and the public API built on it: blocking, streams, transports.
6. Tickets, resumption and the client cache.
7. Restricted TLS 1.2.
8. Diagnostics, metrics and unsafe key logging.
9. Mutation corpus, interoperability, proof profiles, platform matrix.
