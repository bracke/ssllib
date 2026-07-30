# Invariant registry

Each entry states a property, names the code that owns it, and names the
verification that establishes it. `ssllib_tools verify` fails a build in which an
entry declares `verification: none`, so an invariant cannot be added without
coverage and cannot lose its coverage silently.

Families: `REC-*` record layer, `TLS13-*` TLS 1.3, `TLS12-*` TLS 1.2, `CERT-*`
certificates and trust, `SES-*` sessions, `EXT-*` extensions, `ERR-*` errors and
alerts, `API-*` API rules, `CONC-*` concurrency, `REP-*` repository.

Coverage kinds: `test` an automated check in the suite; `structure` a property held
by the shape of the type or the absence of an operation, with a test that would
catch a regression; `audit` a check in `ssllib_tools verify`; `proof` a GNATprove
obligation; `interop` an external-stack check. `pending` means the invariant is
declared and its subject is not yet implemented — those are listed in the second
table so that the first table contains only invariants that hold today.

## Invariants established in this release

| ID | Statement | Owner | Verification | Impact if broken |
|---|---|---|---|---|
| REC-1 | No (key, nonce) pair is used twice on a connection. A nonce is a function of the static IV and the sequence number; the sequence advances only after success; it returns to zero only when a new key is installed. | `SSL.Records.Traffic_State` | structure + test: `records: sequence and nonce uniqueness` (identical plaintext under one key yields different ciphertext); `records: every bit flip refused` (a failed open does not advance the sequence) | Confidentiality of the affected records is lost outright |
| REC-2 | No plaintext is exposed before authentication. A record whose tag does not verify produces a zeroed buffer and a zero length. | `SSL.Records.Open`, `SSL.Crypto.Open` | test: `records: no unauthenticated plaintext` (the output is scanned for any plaintext octet and for any non-zero octet) | An attacker can inject data the application treats as authentic |
| REC-3 | The five-octet record header is the AEAD's associated data, so no header field can be altered undetectably. | `SSL.Records.Protect`, `SSL.Records.Open` | test: `records: header is associated data` (each of the five octets is flipped in turn) | The length and type fields become forgeable |
| REC-4 | Padding is removed only after the tag has verified, and a bad tag, bad padding, an invalid inner type and a missing inner type are indistinguishable. | `SSL.Records.Open`, `SSL.Errors.Classify` | test: `records: padding removed after auth`, `records: missing inner type refused`; structure: all four map to `Code_Record_*` with `Restricted` disclosure | A padding oracle |
| REC-5 | Wire octets are never converted into an Ada record by unchecked conversion or by overlay; the header is parsed field by field. | `SSL.Records.Parse_Header`, `SSL.Wire` | structure + test: `records: explicit header codec`; audit: no `Unchecked_Conversion` in `src/` | Representation-dependent parsing; undefined behaviour across targets |
| REC-6 | A record layer sequence number is never wrapped; at the ceiling the endpoint refuses to protect. | `SSL.Records.Protect` | structure: the refusal precedes any AEAD call; test: `records: sequence and nonce uniqueness` | Nonce reuse |
| TLS13-1 | The transcript is the exact octets of each handshake message — type, three-octet length, body — with no record framing and no re-encoding. | `SSL.Transcripts` | test: `transcript: non-finalizing snapshot` (the transcript equals the hash of the concatenated messages) | The two ends derive different keys; a tampered message may go undetected |
| TLS13-2 | A transcript snapshot does not finalize; secrets may be derived at several milestones and hashing continues. | `SSL.Transcripts.Hash`, `SSL.Crypto.Snapshot` | test: `transcript: non-finalizing snapshot` (two consecutive snapshots agree, and absorbing afterwards changes the hash) | Every derivation after the first is wrong |
| TLS13-3 | After a HelloRetryRequest the transcript is the synthetic `message_hash` form of RFC 8446 section 4.4.1, applied at most once. | `SSL.Transcripts.Apply_Hello_Retry_Transform` | test: `transcript: message_hash transform` (compared against the hash computed independently); structure: `Transformed` gates the precondition | Retry handshakes fail against every conforming peer |
| TLS13-4 | The key schedule agrees with RFC 8446 section 7.1, and each stage is derived once and in order. | `SSL.Key_Schedule` | test: `key schedule: RFC 8448 section 3` (authoritative vectors, plus an internal-consistency cross-check); `key schedule: stage ordering` | Handshakes fail, or succeed on keys the peer did not derive |
| TLS13-5 | There is no getter for a raw key-schedule stage secret; only sanctioned products are reachable. | `SSL.Key_Schedule` | structure: the package exports no stage-secret accessor; audit: the package is a private child, so no application can name it | A caller can derive material the schedule did not sanction |
| TLS13-6 | The early secret and the binder key are scrubbed the moment the handshake stage is reached. | `SSL.Key_Schedule.Derive_Handshake` | structure + test: `key schedule: stage ordering` (a wiped schedule reports the unstarted state) | Loss of intra-connection forward secrecy |
| TLS13-7 | A KeyUpdate advances a direction's traffic secret and scrubs the retired one; the two directions advance independently. | `SSL.Key_Schedule.Advance_Traffic_Secret` | test: `key schedule: KeyUpdate advance` (key and IV both change; the other direction's generation does not) | The update provides no forward secrecy, or desynchronizes the directions |
| TLS13-8 | Exporter output is bound to its label and to whether a context was supplied; the derivation is deterministic. | `SSL.Key_Schedule.Export` | test: `exporters: label and context binding` | Two callers asking for different keys receive the same key |
| TLS13-9 | Each ticket's PSK is bound to that ticket's nonce, so several tickets from one connection yield unrelated PSKs. | `SSL.Key_Schedule.Resumption_PSK` | test: `tickets: per-nonce PSK separation` | Using one ticket compromises the others |
| ERR-1 | Every alert a peer can observe is chosen by one table; no failure site chooses its own. | `SSL.Errors.Classify` | structure + test: `errors: mapping, disclosure, accumulation`; audit: `SSL.Alerts.Local_Alert` is called only from `SSL.Errors` | The alert surface becomes an oracle nobody can review |
| ERR-2 | The first terminal failure is preserved and never displaced; later failures are counted, bounded. | `SSL.Errors.Failure_Record` | test: `errors: mapping, disclosure, accumulation` | The reported cause is a consequence rather than the cause |
| ERR-3 | A `Restricted` failure renders as its category and code only, with parameters withheld even from a local log. | `SSL.Errors.Image` | test: `errors: mapping, disclosure, accumulation` (the rendering is scanned for the parameter's text) | Shipped logs disclose which check a forgery failed |
| ERR-4 | Terminality is decided on the alert description, never on the peer's level octet; an unrecognized description is terminal and its number is preserved. | `SSL.Alerts.Is_Terminal`, `SSL.Alerts.Peer_Alert` | test: `alerts: values, terminality, unknown peer alerts` | A peer talks the endpoint into continuing after a fatal condition |
| ERR-5 | Numeric error codes and alert values are written out, never derived from enumeration positions. | `SSL.Errors`, `SSL.Alerts` | structure + test: `alerts: values, terminality, unknown peer alerts` (wire values asserted individually) | Reordering a declaration silently changes the wire or the logs |
| ERR-6 | An unusable ticket is non-fatal, sends no alert, and does not disclose why. | `SSL.Errors.Classify` | test: `errors: mapping, disclosure, accumulation` | Ticket handling becomes a forgery oracle |
| API-1 | Every declared length from a peer is checked against a configured bound before any storage is reserved. | `SSL.Wire.Open_Vector_*`, `SSL.Limits` | test: `wire: length-prefixed vectors`, `wire: every truncation refused`, `limits: defaults and consistency` | A declared length becomes an allocation |
| API-2 | A parse failure is a sticky flag, never an exception, and a failed cursor yields no values. | `SSL.Wire` | test: `wire: sticky failure flag`, `wire: every truncation refused` | An ordinary protocol error escapes as an unhandled exception |
| API-3 | Buffers never grow. A full queue refuses, all-or-nothing, and is unchanged. | `SSL.Buffers.Queue` | test: `buffers: bounded backpressure`, `buffers: partial append` | An attacker chooses the endpoint's memory use |
| API-4 | Secrets are scrubbed through volatile stores, on overwrite and on finalization, over the whole buffer. | `SSL.Secrets`, `SSL.Crypto.Scrub` | test: `secrets: wipe and overwrite` | Key material outlives the connection in freed memory |
| API-5 | MAC, tag and secret comparison is constant-time in the contents. | `SSL.Secrets.Equal`, `SSL.Crypto.Equal` | test: `secrets: constant-time equality`; structure: both delegate to `CryptoLib.Constant_Time.Equal` | A timing side channel on tag comparison |
| API-6 | Configured limits that would deadlock rather than refuse are rejected before use. | `SSL.Limits.Is_Valid` | test: `limits: defaults and consistency` (each inconsistency checked individually) | A configuration that reports backpressure forever |
| API-7 | ALPN protocol names are compared as octets, with no case folding and no UTF-8 assumption. | `SSL.ALPN` | test: `alpn: opaque names, selection, policy` | A protocol is negotiated that the peer did not offer |
| API-8 | DNS name folding is ASCII-only and locale-independent; IP literals are refused as DNS names; non-ASCII names are refused rather than guessed at. | `SSL.Server_Names` | test: `names: normalization, wildcards, addresses` | Hostname comparison depends on the process locale, or can be tricked |
| API-9 | A wildcard matches exactly one label, leftmost only; partial and registry-wide wildcards are refused; an exact match outranks any wildcard. | `SSL.Server_Names` | test: `names: normalization, wildcards, addresses` | A certificate is accepted for names the operator did not intend |
| REP-1 | No runtime source names CryptoLib outside `SSL.Crypto` and the two units that reach only for secure wipe and constant-time comparison. | whole of `src/` | audit: `ssllib_tools verify` | The ownership boundary becomes unreviewable |
| REP-2 | No runtime source names AUnit or `project_tools`. | whole of `src/` | audit: `ssllib_tools verify` | The runtime acquires a test-only dependency |
| REP-3 | Every declared internal check is called from a registered AUnit routine. | `tests/src` | audit: `ssllib_tools verify` | A check passes without testing anything |
| REP-4 | The crate version in `alire.toml` and `SSL.Version.Crate_Version` agree. | `alire.toml`, `SSL.Version` | audit: `ssllib_tools verify` | A release is labelled wrongly |
| REP-5 | Every document the project promises exists and is not empty. | `docs/`, root | audit: `ssllib_tools verify` | A promised document reads as covered when it is not |
| REP-6 | Every invariant in this registry declares verification coverage. | this file | audit: `ssllib_tools verify` | An invariant nobody checks |
| REP-7 | All tooling is Ada driven through `project_tools`; no shell, Python, Make, Perl, Ruby or Node. | `tests/src/tools`, `alire.toml` | audit: no such files in the repository; `ssllib_tools` is the only driver | Workflow logic leaves the language it is meant to be checkable in |

## Invariants declared, subject not yet implemented

These are recorded now so the coverage obligation is on the record before the code
exists. `ssllib_tools verify` does not yet gate on them, because gating on an
invariant whose subject is absent would report a pass for something untested.

| ID | Statement | Planned verification |
|---|---|---|
| TLS13-10 | CertificateVerify signs 64 spaces, the exact context string, a zero separator and the transcript hash. | test against RFC 8448; interop |
| TLS13-11 | A Finished message is appended to the transcript only after it has verified. | test; structure |
| TLS13-12 | An empty client Certificate is permitted only where policy allows, and is never followed by CertificateVerify. | test |
| TLS13-13 | Directional key installation timing matches RFC 8446 exactly. | test; interop |
| TLS13-14 | HelloRetryRequest occurs at most once, and never requests a group already supplied with a valid share. | test |
| TLS12-1 | Extended Master Secret is required; a peer that does not negotiate it is refused, and no non-EMS session is ever stored or resumed. | test; interop |
| TLS12-2 | ChangeCipherSpec is the real epoch switch; malformed, early, repeated or unexpected CCS is refused. | test |
| TLS12-3 | No renegotiation occurs, in either role. | test; interop |
| TLS12-4 | Downgrade sentinels are emitted and legacy downgrade is refused. | test; interop |
| CERT-1 | The validation pipeline runs in order: decode, parse, bounded path build, path validation, purpose, key usage, identity, revocation, pinning, CertificateVerify, Finished. | test |
| CERT-2 | Identity matching uses subjectAltName only; there is no Common Name fallback. | test |
| CERT-3 | A private key never leaves the credential object, and its bytes are never exposed. | structure; audit |
| CERT-4 | Trust is explicit; a required unavailable or empty source fails closed, and a peer's self-signed certificate is never an implicit anchor. | test |
| CERT-5 | Pinning never silently disables identity matching. | test |
| SES-1 | A session is bound to its expected identity, endpoint, SNI, ALPN, protocol, suite hash, trust fingerprint, configuration fingerprint, client authentication state and application security context, and is never resumed outside them. | test |
| SES-2 | A ticket is authenticated before it is parsed, and is never a raw Ada record. | test |
| SES-3 | Exactly one active ticket encryption key at a time; retired keys are decrypt-only and bounded. | test |
| EXT-1 | Duplicate extensions are refused; each extension is accepted only in its permitted contexts; an unsolicited response is refused. | test |
| EXT-2 | `pre_shared_key` is last in a ClientHello, and its binder covers the partial transcript exactly. | test against RFC 8448 |
| CONC-1 | A base connection is one-task-at-a-time; the synchronized wrapper serializes one reader, one writer and one controller through a single driver. | test |
| CONC-2 | A callback that raises is caught at the boundary and converted to a structured failure. | test |
