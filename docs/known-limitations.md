# Known limitations

Limitations that will persist past V1 are listed here. Work simply not yet done
is in `docs/status.md`; this document is for the things that are decisions.

## The library is incomplete

`ssllib` cannot open a TLS connection. This is the overriding limitation today and
it is documented separately, in detail, in `docs/status.md`. Everything below
assumes the rest is eventually built.

## Finite-field Diffie-Hellman is offered but never default

`ffdhe2048`, `ffdhe3072` and `ffdhe4096` are implemented, over CryptoLib's
RFC 7919 groups. They are not in the default group set and never will be.

An ffdhe4096 exchange costs about 62 ms of CPU per connection against 2.3 ms for
X25519, and puts 512 octets on the wire in each direction against 32. A caller
whose policy requires finite-field key exchange adds
`SSL.Supported_Groups.Finite_Field_Groups`; a caller who does not need it should
not be paying for it because a default said so.

Enabling them on a **server** will be a separate, explicitly named operation
rather than the same call a client uses, because accepting a large finite-field
group server-side is a denial-of-service amplifier: an attacker forces a full
exponentiation with a random in-range key share and pays nothing. See the
measurements in `docs/security-model.md`.

`ffdhe6144` and `ffdhe8192` are implemented by CryptoLib and are not offered
here. The specification's optional set stops at `ffdhe4096`, and neither buys
anything on merit: `ffdhe8192` provides about the security of `secp384r1` --
~192 bits by RFC 7919 appendix A -- at roughly thirty-one times the cost, 294 ms
per connection against 9.4 ms. The only reason to add them would be a compliance
regime that names the group by name. Their values are recognized so a diagnostic
can say what a peer asked for.

No subgroup check is performed on a finite-field peer value, because CryptoLib
does not perform one: with a safe prime, a value passing the 1 < Y < p-1 check
leaks at most the parity of the private exponent through the Legendre symbol, and
closing that bit costs a second full exponentiation. CryptoLib documents the
choice; it is inherited here rather than re-litigated.

## Client authentication requires a credential the server will accept

A client that is asked for a certificate sends one only when it holds a
credential *and* the request's `signature_algorithms` names a scheme that
credential can produce. Otherwise it declines with an empty Certificate, which is
the conforming answer.

That is a limitation worth stating because the failure it avoids is confusing:
sending a chain this endpoint could not then sign for would leave the server
waiting for a CertificateVerify that never came, and the handshake would fail
with the shape of a protocol error rather than the shape of a client that has no
certificate the server would take.

The scheme sets are not negotiable from the outside. If a server asks only for
schemes a deployment's client key cannot produce, the answer is a different key,
not a flag.

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
