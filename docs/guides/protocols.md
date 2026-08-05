# What is on the wire

Covers TLS 1.3, restricted TLS 1.2, the record layer, certificates and trust,
sessions and resumption, ALPN and SNI, and exporters. The generated tables under
`docs/tables/` give the code points; this gives the shape and the reasoning.

## TLS 1.3

The whole handshake, both roles: HelloRetryRequest, client authentication,
KeyUpdate in both directions, NewSessionTicket, and resumption through
`pre_shared_key` with a binder.

Resumption is always with a fresh key exchange. `psk_ke` alone is neither
offered nor accepted, so a resumed connection has the same forward secrecy as a
full one. That costs a key exchange and buys the property that a stolen ticket
does not decrypt anything already recorded.

## Restricted TLS 1.2

ECDHE only, AEAD only, extended master secret mandatory. What that leaves out is
the point: no static RSA, so no Bleichenbacher variant and no missing forward
secrecy; no CBC, so no MAC-then-encrypt and none of the padding oracles; extended
master secret required, so no triple handshake; no renegotiation at all, so no
renegotiation attack; no compression, so no CRIME.

One ClientHello serves both versions. A client that sent a 1.3-only hello and
then found the server wanted 1.2 would have to start again, and the extra round
trip is exactly what a downgrade attacker wants to provoke. The downgrade
sentinel in a ServerHello random is checked in both directions.

Stateless tickets (RFC 5077) are implemented, including the abbreviated
handshake in which the server sends its ChangeCipherSpec and Finished first.
Session-identifier resumption is not, and will not be: it needs server-side
state, and the ticket does the same job without it.

## The record layer

Explicit five-octet header codec; no unchecked conversion of wire octets into
Ada records anywhere. Incremental parsing at every octet boundary, several
records per supply, and a record split across arbitrarily many supplies.

Padding is removed only after authentication. Nothing is handed upward from a
record whose tag did not verify — not a length, not a content type, not a
partial plaintext.

## Certificates and trust

A trust snapshot is immutable and is taken once. `truststores` is the only source
of native anchors; NSS and Java stores are opt-in and are never silently merged
into the default domain. Explicit anchors are a separate call, so a program that
wants only its own roots gets only its own roots.

Everything below the snapshot — path building, validation, purpose checks,
identity matching, revocation evidence — is CryptoLib's. This library decides
*policy*: which anchors, which pins, which revocation stance, and what to do
with the answer. It implements no ASN.1, no X.509 and no OCSP of its own, and
the dependency-boundary audit in `ssllib_tools verify` fails the build if any
appears.

## Sessions and resumption

A session records what it was established under and refuses to be offered
anywhere else: the server name, the application protocol, the cipher suite's
hash, the configuration and trust fingerprints, and the security context. A
resumed connection inherits the authentication of the one that issued the
ticket, so resuming across any difference that would have changed that
authentication would be resuming into a connection the application never asked
for.

A ticket is single use. Taking one out of the cache removes it, so that offering
the same one twice cannot make two connections linkable to an observer.

## ALPN and SNI

ALPN selection is server-order or client-order by policy, and "required with no
overlap" is a refusal rather than a silent no-protocol. SNI is a validated DNS
name; a wildcard is not a legal expected identity and is refused at `Build`.

## Exporters and channel bindings

`SSL.Exporters` gives keying material bound to the connection.
`SSL.Channel_Bindings` gives `tls-exporter` (RFC 9266) and
`tls-server-end-point` (RFC 5929). `tls-unique` is deliberately absent: RFC 8446
appendix C.5 says it does not apply to TLS 1.3, and this library implements no
TLS 1.2 resumption that would qualify for it.

There is no getter for the exporter master secret. A caller can ask for material
under a label; nothing can ask for the secret it came from.
