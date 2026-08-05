# Contracts

What the preconditions, postconditions and predicates in this library mean, and
why each of them is a contract rather than a check.

## The rule

A precondition states something the caller must establish. Violating one is a
programming error, and it raises — that is one of the three cases where this
library raises at all. Everything a *peer* can cause is a structured failure
instead, and the distinction is deliberate: a hostile input must never be able
to reach a precondition.

The clearest example is a defect this rule caught.
`SSL.Handshake_Messages.Parse_Header` once required its input to be at least as
long as a header. It is the first thing every message from a peer reaches, so
that contract put the burden of checking on every caller and turned a hostile
short input into a raised exception at whichever one forgot. The precondition is
gone; a short buffer is now a structured failure. The mutation runner found it
on its first seed.

## The kinds in use

**Stage ordering.** `SSL.Key_Schedule` requires each derivation to follow the
one before it. `Derive_Master` needs the server-Finished transcript;
`Derive_Resumption` needs the client's. Conflating the two meant a server could
not have its application traffic secrets until the client's Finished arrived,
which would have made half-RTT server data impossible. A failed precondition
found that, in the first end-to-end test.

**State.** `SSL.TLS13.Client.Handle_Message` requires a state that is not
`Start` or `Failed`. `SSL.Exporters.Export` requires an established connection:
before the handshake there is no exporter master secret, and anything derived
would not be bound to a connection either end had authenticated.

**Size and shape.** `Derive_Key_Block` requires two 32-octet randoms.
`SSL.Records.Protect` requires an active traffic state.
`SSL.Ticket_Keys.Seal` requires a buffer that can hold the largest ticket. Each
one is a fact the caller has and the callee cannot check cheaply.

**Capacity as a discriminant.** `SSL.Secrets.Secret` has no default
discriminant, so every declaration must name its capacity. Everything in the key
schedule is at most 48 octets and an AEAD key at most 32, but an ffdhe4096
shared secret is 512. One flat bound would have made a `Schedule` — ten secrets
— five kilobytes, and would have made every wipe of a 32-octet traffic key a
512-octet memset. The wrong choice is a compile-time failure.

**Postconditions that state the useful thing.** `Wipe` posts that the length is
zero. `Reader` posts that the cursor is valid. `Encoded_Parameters` posts its
own length, which is what a caller sizing a buffer needs.

## Proof

`ssllib_tools prove` runs GNATprove at two profiles, `development` and
`release`, and both are clean. `SSL.Wire`, `SSL.Records` and `SSL.Limits` carry
contracts written with proof in mind. What is proved is absence of run-time
errors and the contracts as written — not the protocol, and this document does
not claim otherwise.
