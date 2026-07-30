# ssllib

A pure Ada 2022 implementation of TLS 1.3 and a deliberately restricted modern
TLS 1.2, for authenticated, confidential, integrity-protected bidirectional byte
streams over a transport the caller owns.

> **Status: incomplete.** The cryptographic foundation is built and tested; the
> handshake state machines and the public connection API are not. `ssllib`
> cannot open a TLS connection today. **Read [`docs/status.md`](docs/status.md)
> before using or evaluating this crate** — it lists, subsystem by subsystem,
> what exists and what does not.

The name is historical. SSL 2.0 and SSL 3.0 are not implemented, and neither are
TLS 1.0 and TLS 1.1. There is no configuration that reaches them, because there
are no values to configure.

## What it is for

An Ada program that needs TLS for HTTP, SMTP, IMAP, a database protocol, or any
other secure stream, and that wants:

- **one deterministic protocol engine** that never opens a socket, never blocks,
  never reads a global clock, never looks at an environment variable and never
  starts a task, with the blocking API, the stream adapter and the event-loop
  integration all built on that same engine rather than beside it;
- **structured results instead of exceptions** for every ordinary failure —
  transport trouble, malformed peer input, a certificate that does not validate,
  a deadline, a cancellation, a limit;
- **bounded everything**, with the bound checked before the storage is reserved,
  so that a hostile peer meets a refusal of a stated size;
- **no cryptography of its own.** Every hash, MAC, KDF, AEAD, key agreement,
  signature, ASN.1, X.509, PKIX, OCSP and CRL operation belongs to
  [`cryptolib`](https://github.com/bracke/cryptolib), reached through one
  auditable seam.

## Dependencies and ownership

| Crate | Owns |
|---|---|
| [`cryptolib`](https://github.com/bracke/cryptolib) | All cryptography and PKI |
| [`truststores`](https://github.com/bracke/truststores) | Native system trust anchors; opt-in NSS and Java stores |
| [`hostkit`](https://github.com/bracke/hostkit) | The remaining genuine host differences |

`ssllib` owns the protocol and nothing else. That boundary is checked, not
asserted: `ssllib_tools verify` refuses a build in which any runtime source
outside `SSL.Crypto` (and the two units that reach only for secure wipe and
constant-time comparison) names `CryptoLib`, or in which any runtime source
names AUnit or `project_tools`.

There is no C ABI, no C bindings, no exported C symbols, no OpenSSL
compatibility layer, and no architecture arranged around future foreign-language
bindings. The project is Ada-only, tooling included: no shell, Python, Make,
Perl, Ruby or Node anywhere in the repository.

## Protocol scope

**TLS 1.3** (RFC 8446), client and server: full certificate-authenticated
handshake, optional and required client authentication, HelloRetryRequest, SNI,
ALPN, OCSP stapling, `record_size_limit`, session tickets, PSK resumption with
`psk_dhe_ke` only, KeyUpdate, exporters, channel binding, close_notify,
truncation detection.

**Restricted TLS 1.2**, client and server: ECDHE and AEAD only, Extended Master
Secret mandatory, stateless tickets, downgrade protection, secure-renegotiation
signalling parsed for the initial handshake and all actual renegotiation
refused.

**Cipher suites.** TLS 1.3: `TLS_AES_128_GCM_SHA256`,
`TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_256_GCM_SHA384` — in that preference
order. TLS 1.2: the six ECDHE-with-AEAD suites over ECDSA and RSA.

**Groups.** X25519, secp256r1, secp384r1, and secp521r1. The RFC 7919
finite-field groups are not implemented; see `docs/status.md` for why.

**Signature schemes.** Ed25519, Ed448, ECDSA over P-256/P-384/P-521, RSA-PSS in
both the RSAE and PSS key forms, and — for TLS 1.2 only — RSA PKCS#1 v1.5.
MD2, MD5, SHA-1 and DSA are absent rather than disabled.

## Not implemented, on purpose

TLS compression, export suites, RC4, DES, 3DES, CBC suites, NULL encryption,
static RSA key exchange, static or anonymous DH/ECDH, renegotiation, heartbeat,
0-RTT, external PSKs, post-handshake client authentication, DTLS, QUIC TLS,
Encrypted ClientHello, delegated credentials, certificate compression, raw
public-key authentication, TLS 1.2 session-ID resumption, trust on first use.

None of these is behind a flag. Each is absent from the type system, which is
why no configuration can reach one.

## Building

Requires Alire and GNAT 15.2.1.

```
alr build                 # the runtime library
alr -C tests build        # the AUnit suite and the Ada tooling
tests/bin/ssllib_tests    # run the suite
tests/bin/ssllib_tools verify
```

`ssllib_tools` is the Ada driver for build, test, verification, documentation,
packaging and release. CI invokes it rather than reimplementing any of it. Every
subcommand takes `--json` for a versioned machine-readable report and returns a
stable exit status: 0 success, 1 a check failed, 2 usage, 3 unavailable.

## Documentation

- [`docs/status.md`](docs/status.md) — what is implemented, what is not, and in
  what order the rest should be built
- [`docs/architecture.md`](docs/architecture.md) — the engine, the layering, and
  why the blocking API is a wrapper rather than a second stack
- [`docs/package-map.md`](docs/package-map.md) — every package and what it owns
- [`docs/security-model.md`](docs/security-model.md) — what is defended, what is
  not, and the reasoning behind the refusals
- [`docs/known-limitations.md`](docs/known-limitations.md)
- [`invariant-registry/registry.md`](invariant-registry/registry.md) — the
  invariants, their owners, and their verification coverage
- [`SECURITY.md`](SECURITY.md)

## Licence

MIT for project-owned code, tests, tooling, examples and documentation.
Imported test vectors and fixtures keep the licence and attribution of their
source; RFC 8448's code components are used under the IETF Trust's Simplified
BSD terms.
