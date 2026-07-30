# Package map

`(exists)` marks a package present in this release; everything else is specified
and not yet written. See `docs/status.md`.

## Public

| Package | Owns |
|---|---|
| `SSL` *(exists)* | The octet view; the stable identifiers and fingerprints |
| `SSL.Version` *(exists)* | Crate identity, protocol scope, deliberate absences |
| `SSL.Versions` *(exists)* | TLS 1.2 and TLS 1.3, wire values, version sets |
| `SSL.Cipher_Suites` *(exists)* | The nine suites, their composition, preference lists |
| `SSL.Supported_Groups` *(exists)* | Named groups, share and secret lengths |
| `SSL.Signature_Schemes` *(exists)* | Schemes, version rules, curve binding |
| `SSL.ALPN` *(exists)* | Opaque protocol names, selection policy |
| `SSL.Server_Names` *(exists)* | Validated DNS names, wildcards, IP identities |
| `SSL.Alerts` *(exists)* | The closed alert set; unknown peer alerts preserved |
| `SSL.Errors` *(exists)* | Structured failures; the one alert-mapping table |
| `SSL.Limits` *(exists)* | Every peer-influenced bound, with a consistency check |
| `SSL.Authentication` | What authenticated a peer, and how strongly |
| `SSL.Configurations` | Immutable client and server configurations and their builders |
| `SSL.Credentials` | Local certificate chains and signing capability |
| `SSL.Credentials.Signers` | External signers and their declared capabilities |
| `SSL.Trust` | Trust snapshots and their sources |
| `SSL.Trust.Pinning` | Certificate and SPKI pins, scopes, activation periods |
| `SSL.Trust.Revocation` | Revocation policy and caller-supplied status |
| `SSL.Clocks` | Wall time for validity, monotonic time for deadlines |
| `SSL.Cancellation` | A cancellation token the caller owns |
| `SSL.Engines` | The one deterministic protocol engine |
| `SSL.Engines.Events` | The semantic events the engine returns |
| `SSL.Connections` | Connection objects, lifecycle, single use |
| `SSL.Connection_Metadata` | What was negotiated, as a value |
| `SSL.Blocking` | Handshake, Read_Some, Read_Exactly, Write_Some, Write_All, Shutdown |
| `SSL.Streams` | The Ada stream adapter |
| `SSL.Transports` | The transport interface and its status values |
| `SSL.Transports.GNAT_Sockets` | An optional GNAT.Sockets transport |
| `SSL.Clients` | Client connection construction |
| `SSL.Servers` | Server connection construction and credential routing |
| `SSL.Sessions` | Sessions, their bindings, and their metadata |
| `SSL.Sessions.Client_Caches` | The client cache interface |
| `SSL.Sessions.Client_Caches.Memory` | A bounded task-safe in-memory cache |
| `SSL.Exporters` | RFC 8446 section 7.5 exported key material |
| `SSL.Channel_Bindings` | tls-exporter, tls-server-end-point, tls-unique |
| `SSL.Diagnostics` | Structured events, levels, redaction, metric sinks |
| `SSL.Synchronized_Connections` | One reader, one writer, one controller |
| `SSL.Unsafe` | The namespace for things that are unsafe by construction |
| `SSL.Unsafe.Key_Logging` | Key logging: off by default, explicit, sink-based |

## Private children

Named only from inside the `SSL` hierarchy. Not API, and not able to become API
by accident.

| Package | Owns |
|---|---|
| `SSL.Buffers` *(exists)* | Fixed-capacity stores and octet FIFOs; the backpressure boundary |
| `SSL.Secrets` *(exists)* | Bounded controlled secrets with non-elidable wiping |
| `SSL.Wire` *(exists)* | Explicit codecs and bounded cursors with a sticky failure flag |
| `SSL.Crypto` *(exists)* | The single CryptoLib seam |
| `SSL.Transcripts` *(exists)* | The handshake transcript and the HelloRetryRequest transform |
| `SSL.Key_Schedule` *(exists)* | The whole RFC 8446 section 7.1 schedule |
| `SSL.Records` *(exists)* | Header codec, traffic state, AEAD, nonces, usage counters |
| `SSL.Extensions` | The closed extension registry with wire IDs and context rules |
| `SSL.Handshake_Messages` | The handshake message codecs |
| `SSL.State_13` | The TLS 1.3 state machines, both roles |
| `SSL.State_12` | The restricted TLS 1.2 state machines, both roles |
| `SSL.PRF_12` | The TLS 1.2 PRF and P_hash |
| `SSL.Certificate_Validation` | The X.509 pipeline over CryptoLib |
| `SSL.Trust_Sources` | The truststores adapter |
| `SSL.Ticket_Format` | The versioned authenticated ticket encoding |

## Test and tooling crate

| Unit | Owns |
|---|---|
| `SSL.Internal_Tests` *(exists)* | Checks over the private children; a child of `SSL`, in the test crate |
| `Tests_Support` *(exists)* | The one assertion seam and the hexadecimal helpers |
| `Tests_Public` *(exists)* | AUnit cases over the public API |
| `Tests_Internals` *(exists)* | AUnit cases delegating to `SSL.Internal_Tests` |
| `Tests_Suite` *(exists)* | The suite |
| `Ssllib_Tests` *(exists)* | The AUnit runner |
| `Ssllib_Tools` *(exists)* | The Ada driver for build, test, verify, and the release gates |

## Naming

Nothing here imitates OpenSSL. There is no `SSL_CTX`, no `SSL_METHOD`, no `BIO`,
no `SSL_connect` and no `X509_STORE`, and no concept that maps to one. A
configuration is a `Client_Configuration`; a transport is a `Transport`; a
connection is a `Connection`. The reason is not aesthetic: a name borrowed from
another library carries that library's semantics with it, and a caller who reads
`SSL_CTX` will expect the reference counting, the mutability and the inheritance
that name implies here too.
