# Error registry

Every failure this library reports is a value with a stable numeric code. The
codes are grouped by leading digit, and the grouping is stable: a program may
switch on a code, and a code never changes meaning.

The authoritative list is `src/ssl-errors.ads`, and the generated page
`docs/api/ssl-errors.md` reproduces it with the comment attached to each code.
This document explains the shape.

## The bands

| Band | Category | Meaning |
|---|---|---|
| 1000 | configuration | A policy that cannot work, refused at `Build` |
| 2000 | credential | A local key or chain that cannot do what was asked |
| 3000 | trust | Anchors, pinning, revocation |
| 4000 | protocol | What a peer sent, and what this end refused |
| 4800 | cryptographic | A provider said no |
| 5000 | certificate | Path validation and identity |
| 6000 | limit | A bound in `SSL.Limits` was reached |
| 7000 | resource | Queues, buffers |
| 8000 | lifecycle | Deadlines, cancellation, state |

## The fields, and why each exists

**Category and code.** The category is for a switch; the code is for a log and a
bug report.

**Origin.** `Peer_Message`, `Peer_Alert`, `Local_Policy`, `Local_Implementation`,
`Caller_Request` or a provider. This is the field that answers "whose fault is
this", and it is the difference between an operator paging someone and an
operator blocking an address.

**Fatality and alert.** One central table maps a code to the alert it sends.
One table, so that two call sites cannot disagree about what a peer is told.

**Stage.** Which part of the lifecycle it happened in.

**Parameters.** Bounded, typed, and never secret. A parameter is a name and a
value, and the value is a number or a short piece of text.

**Retry classification.** Whether retrying could possibly help, and on what: the
same connection, a new connection, or never.

**Disclosure classification.** Whether this failure may be reported to a peer in
full. Some may not, because the difference between two of them is an oracle.
Deciding it once, in the registry, is what stops each call site from having to
remember.

## Accumulation

The first terminal failure is preserved and later ones increment a bounded
secondary count. The first is the one that explains the rest, and a structure
that let a late failure overwrite it would lose the only interesting one.
