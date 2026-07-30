# Third-party attribution

`ssllib`'s own code, tests, tooling, examples and documentation are MIT
licensed; see `LICENSE`.

## Runtime dependencies

| Crate | Licence | Used for |
|---|---|---|
| [cryptolib](https://github.com/bracke/cryptolib) | MIT | All cryptography and PKI |
| [truststores](https://github.com/bracke/truststores) | MIT | Native trust anchors |
| [hostkit](https://github.com/bracke/hostkit) | MIT | Host differences |

## Test-only dependencies

| Crate | Licence | Used for |
|---|---|---|
| [AUnit](https://github.com/AdaCore/aunit) | GPL-3.0-or-later WITH GCC-exception-3.1 | The test runner |
| [project_tools](https://github.com/bracke/project_tools) | MIT | The Ada release tooling |

AUnit is linked only into `tests/bin/ssllib_tests`. The runtime library does not
depend on it and `ssllib_tools verify` fails a build in which a runtime source
names it.

## Test vectors

### RFC 8448 — Example Handshake Traces for TLS 1.3

Source: RFC 8448, IETF Trust. Code components are used under the Simplified BSD
Licence set out in the IETF Trust's Legal Provisions Relating to IETF Documents.

Used in `tests/src/ssl-internal_tests.adb` (`Check_Key_Schedule_Vectors`), from
section 3, "Simple 1-RTT Handshake": the ECDHE shared secret, the
ClientHello..ServerHello transcript hash, both handshake traffic secrets, and
both handshake traffic keys and IVs.

Each value was independently recomputed from the RFC 8446 section 7.1
definitions with a separate HKDF implementation before being committed, and the
two agreed. The suite retains a consistency cross-check: the published traffic
secrets are re-expanded and required to produce the published keys, so an
inconsistent vector set fails rather than passing quietly.

### RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3

Source: RFC 8448's parent specification, IETF Trust, same terms. Section 5.3's
nonce construction and section 4.4.1's `message_hash` transformation are
implemented from the specification text and checked against values computed from
it, not copied from a published trace.

### Not yet imported

The specification requires authoritative vectors for the TLS 1.2 PRF, exporters,
channel bindings and X.509/PKIX. None is imported yet, because none of those
subsystems exists. `tests/vectors/` holds the note explaining what belongs there.
