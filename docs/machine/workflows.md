# Allowed and prohibited workflows

Written for a reader — human or otherwise — that is about to change this
repository or write against it. Everything here is enforced somewhere: by the
type system, by a `Build` refusal, or by `ssllib_tools verify`. Where it is
enforced is named, because a rule with no enforcement is a wish.

## Allowed

- **Configure through a builder and `Build`.** Every policy decision is made
  before a connection exists, and an immutable configuration is shared by
  reference afterwards.
- **Attach a transport you wrote.** Implement `SSL.Transports.Transport`;
  return a status; never raise.
- **Drive a connection from one task**, or share one through
  `SSL.Synchronized_Connections` as one reader, one writer and a controller.
- **Share a session cache between tasks.** It is designed for it.
- **Ask for exported keying material under your own label.**
- **Read every failure as a value**, and act on its category, code, retry
  classification and disclosure classification.
- **Turn on diagnostics** at whatever detail and redaction the deployment
  allows.
- **Add a cipher suite, group, scheme, extension or alert** by extending the
  closed registry in its own package. The context table in `SSL.Extensions` is
  an explicit `case`, so adding an extension without deciding its contexts does
  not compile.

## Prohibited

- **Do not implement cryptography, ASN.1, X.509, PKIX, OCSP or CRL handling
  here.** CryptoLib is the sole provider. *Enforced by:*
  `ssllib_tools verify`, which fails when a source file under `src/` reaches for
  anything else.
- **Do not read the OS trust store directly.** `truststores` is the sole
  provider, and NSS and Java stores are opt-in.
- **Do not read entropy from the OS directly.** It comes through CryptoLib.
- **Do not add a C binding, or link OpenSSL, LibreSSL, BoringSSL, GnuTLS,
  mbedTLS or a platform TLS stack.** They appear in this repository only as
  external peers the interoperability matrix drives.
- **Do not add a shell script, Makefile, Python, Perl, Ruby or Node file.**
  Tooling is Ada, through `project_tools`.
- **Do not convert wire octets into an Ada record with an unchecked
  conversion**, and do not persist an Ada record. Every codec is explicit and
  octet by octet, because a record's layout is a compiler's decision.
- **Do not use an unbounded container on a path a peer can influence.**
- **Do not add a flag that disables verification**, and do not add a default
  that is weaker than the one above it.
- **Do not read an environment variable to decide a security policy**, and in
  particular do not let one enable key logging.
- **Do not log a secret.** Not at any detail level, not under any redaction
  setting. *Enforced by:* a test that scans a live connection's diagnostics for
  that connection's own key material.
- **Do not add a plugin or registration seam.** The registries are closed on
  purpose: a closed set is a set that can be reviewed.
- **Do not implement anything on the "not implemented" list** — SSL 2.0/3.0,
  TLS 1.0/1.1, compression, export suites, RC4, DES, 3DES, CBC, NULL ciphers,
  static RSA, static or anonymous DH, renegotiation, heartbeat, 0-RTT, external
  PSKs, post-handshake client auth, DTLS, QUIC, ECH, delegated credentials,
  certificate compression, raw public keys, TLS 1.2 session-identifier
  resumption, or trust on first use.
- **Do not declare V1 complete on partial work.** *Enforced by:*
  `ssllib_tools release`, which runs every gate and then refuses while the
  outstanding-gaps list is not empty.
