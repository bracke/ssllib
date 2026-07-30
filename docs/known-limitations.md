# Known limitations

Limitations that will persist past V1 are listed here. Work simply not yet done
is in `docs/status.md`; this document is for the things that are decisions.

## The library is incomplete

`ssllib` cannot open a TLS connection. This is the overriding limitation today and
it is documented separately, in detail, in `docs/status.md`. Everything below
assumes the rest is eventually built.

## Finite-field Diffie-Hellman is not supported

The RFC 7919 groups `ffdhe2048`, `ffdhe3072` and `ffdhe4096` are not implemented.
CryptoLib provides the SSH MODP groups (group14, group16, group18), which are
different primes; implementing FFDHE would mean adding cryptography to `ssllib`,
which the ownership boundary forbids, or shipping a group with no authoritative
test vectors, which the project's own rules forbid.

The three code points are recognized by `SSL.Supported_Groups` so a negotiation
failure can name them rather than reporting a bare number.

Consequence: a peer that offers only finite-field groups cannot be reached. In
practice every TLS 1.3 implementation offers X25519 or P-256, so this affects
essentially nothing on the open internet; it may matter in an environment whose
policy mandates FFDHE.

## IDNA conversion is the caller's

A non-ASCII domain name must be converted to A-label form (RFC 5890) before it
reaches `SSL.Server_Names`. This library refuses a name containing an octet above
127 rather than guessing.

Doing IDNA correctly requires Unicode tables, the IDNA2008 mapping rules, and care
about confusable and disallowed code points. Doing it approximately produces a
hostname comparison an attacker can trick, which is worse than refusing outright.
A resolver has already produced A-labels for the caller, so the conversion is
usually already done.

## Certificate policy handling is CryptoLib's

Certificate policies, name constraints and path-length constraints are validated by
`CryptoLib.X509.Validation` with the policy options that package provides.
`ssllib` chooses the options and the trust anchors and does not re-implement the
walk. A PKIX feature CryptoLib does not implement is therefore one `ssllib` does not
implement either, and the right place to add it is CryptoLib.

## No hidden network fetching, ever

Revocation checking uses stapled OCSP responses, or OCSP responses and CRLs the
caller or an application provider supplies. `ssllib` will never open a connection
to fetch one, in any policy mode.

The consequence is that `Require_Valid_Status` is only satisfiable when the
application arranges to supply status. That is deliberate: a TLS library that
opened its own HTTP connection during a handshake would be blocking on a third
party, leaking the identity of the site being visited to that third party, and
opening a socket the caller did not ask for.

## No renegotiation, in either version

`renegotiation_info` (RFC 5746) is parsed for an initial TLS 1.2 handshake, so that
a peer's support can be recorded and a downgrade recognized. Every actual
renegotiation attempt is refused. There is no configuration that permits one.

Consequence: a TLS 1.2 server that requires a client certificate only after seeing
the request — the classic renegotiation-based pattern — cannot be interoperated
with. The modern answer is to request the certificate in the initial handshake.

## No 0-RTT, and no external PSKs

0-RTT early data is not implemented and will not be. Its replay properties require
an application-level replay defence that a TLS library cannot provide and cannot
verify a caller has provided.

External PSKs are not implemented. A PSK here is always one this library derived
from a previous handshake's resumption master secret, which is what makes its
provenance and its lifetime knowable.

## No post-handshake client authentication

The TLS 1.3 `post_handshake_auth` extension is not implemented, and a peer's
CertificateRequest after the handshake is refused as an unexpected message.
Authentication that changes mid-connection means application data before and after
was sent under different identities, and no useful API expresses that.

## Ed448 is offered but rarely useful

Ed448 is implemented, because CryptoLib implements it. Almost nothing else does. It
is last in the default preference list and its presence is not expected to affect
any handshake.

## Concurrency is deliberately narrow

A base connection is one-task-at-a-time. The optional synchronized wrapper supports
one reader, one writer and one shutdown/cancellation controller, serialized through
a single protocol driver.

There is no support for several tasks reading, or several writing. TLS is a stream
with a sequence number per direction; two writers means two tasks competing for the
next sequence number, and any locking that made that safe would serialize them
anyway — while making the failure mode, if the locking were ever wrong, a nonce
reuse.

## No formal proof yet

Several units carry contracts written with GNATprove in mind — `SSL.Wire`,
`SSL.Records`, `SSL.Limits` in particular. No proof has been run and no proof
profile is configured. Until that changes, the contracts are runtime assertions
(the build keeps `-gnata` in every profile, deliberately) and not proofs.

## Platform claims are limited to what has been run

Only Linux x86_64 has been built and tested. The specification requires Linux
x86_64, Linux ARM64, Windows x86_64 and macOS ARM64 before V1, and requires that
support not be claimed from compilation alone. No support is claimed for any
platform but the one that has been run.
