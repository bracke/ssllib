# Architecture

## One engine

There is one protocol engine, and everything else is a wrapper on it.

The engine is deterministic and transport-independent. It never opens a socket,
never blocks or sleeps, never reads a global clock, never performs a hidden
environment lookup and never launches a task. It consumes encrypted octets the
caller supplies, produces encrypted octets the caller drains, accepts bounded
application plaintext, exposes authenticated application plaintext, returns
explicit semantic events, and reports exactly why progress is blocked.

The blocking API, the Ada stream adapter, the synchronized wrapper and the
event-loop integration are all built on that same engine. There is deliberately
no second protocol stack for blocking use. Two stacks means two state machines,
and two state machines means the bug that exists in one and not the other — which
is invariably the one nobody tests, because it is the one nobody notices is
separate.

The consequences of "never" are worth stating, because each removes a class of
surprise:

- **Never opens a socket.** The transport is the caller's, so a caller behind a
  proxy, on a Unix socket, on a shared-memory channel or in a test harness uses
  the same engine with no seam to work around.
- **Never blocks.** The engine returns a readiness answer; the caller decides
  whether to wait, and how. That is what makes one engine serve both a blocking
  call and an epoll loop.
- **Never reads a global clock.** Time enters through a parameter. Certificate
  validity uses a wall clock the caller supplies; deadlines use a monotonic time
  the caller supplies. A test can therefore make a certificate expire without
  touching the machine's clock.
- **Never launches a task.** Concurrency is the caller's, so there is no thread
  the caller did not ask for and no synchronization the caller cannot see.

## Layering

Each layer knows only the layer below. The arrows are dependencies.

```
   application
        |
   SSL.Clients / SSL.Servers / SSL.Blocking / SSL.Streams / SSL.Transports
        |
   SSL.Engines  (lifecycle, events, readiness, backpressure)
        |
   +----+----------------+---------------------+
   |                     |                     |
 SSL.State_13        SSL.State_12         SSL.Sessions
   |                     |                     |
   +----+----------------+---------------------+
        |
   SSL.Handshake_Messages / SSL.Extensions
        |
   SSL.Transcripts   SSL.Key_Schedule   SSL.Certificate_Validation
        |                  |                     |
   SSL.Records  (header codec, traffic state, AEAD, nonces)
        |
   SSL.Wire   SSL.Buffers   SSL.Secrets
        |
   SSL.Crypto  ---->  cryptolib
   SSL.Trust_Sources  ---->  truststores
```

`SSL.Crypto` is the only unit that names CryptoLib for a cryptographic operation.
`SSL.Buffers` and `SSL.Secrets` reach CryptoLib for `Secure_Wipe` and
`Constant_Time` only, which is what makes their scrubbing non-elidable and their
comparisons constant-time. Nothing else in the runtime names CryptoLib at all,
and `ssllib_tools verify` fails a build in which something does.

Everything from `SSL.Records` downwards is a private child. Private children can
be named only from inside the `SSL` hierarchy, so the wire codecs, the record
layer, the transcript and the key schedule are not API and cannot become API by
accident. Testing them is possible because a test unit can itself be a child of
`SSL`; `SSL.Internal_Tests` in the test crate is exactly that, and it lives in
the test crate so the runtime has no dependency on it.

## Why the record layer holds the nonce invariant

The property "no (key, nonce) pair is ever used twice" is the one whose failure
destroys confidentiality outright, so it is worth being precise about where it
lives.

It lives in `SSL.Records.Traffic_State`, and it is held by the shape of the type
rather than by a check:

- A nonce is computed only in one place, as a function of the static IV and the
  sequence number (RFC 8446 section 5.3).
- The sequence number is incremented only after a successful protect or open.
- The sequence number returns to zero only inside `Install`, which always
  installs a new key at the same moment.
- There is no operation that sets a sequence number, none that installs a key
  without resetting the sequence, and none that retries an open at a different
  sequence number after a failure.

The last of these is the one that is easy to get wrong. An implementation that
retried a failed open at the next sequence number — to "resynchronize" — would let
a peer that injects one garbage record cause every subsequent nonce to be used
twice. So `Open` does not advance on failure, and the caller's only correct
response to a failure is to fail the connection.

## Why errors are results

Ordinary failures are values, not exceptions. Transport trouble, malformed peer
input, a negotiation with no overlap, a certificate that does not validate, a
deadline, a cancellation, a limit, a session that cannot be used — all of these
are things a correct program must handle, and a correct program should not have
to write an exception handler to discover that they happened.

Exceptions are permitted for exactly three things: a programming-contract
violation (an invalid literal in program text, for instance), an internal state
that cannot occur, and the inherited Ada stream interface, which has no other way
to report failure. A callback that raises is caught at the boundary and converted
into a structured application-policy or provider error, so an application's bug
becomes a connection failure rather than an unwinding through the middle of a
state machine.

## Why the alert map is one table

`SSL.Errors.Classify` is a single `case` statement from an error code to a
category, a fatality, an alert, a retry class and a disclosure class. A failure
site names a code and nothing else.

The reason is not tidiness. The set of alerts a peer can distinguish is the
attack surface of the error-reporting machinery, and an implementation that
chooses an alert at each failure site has that surface spread across a hundred
places where nobody can see it whole. Here it is a table a reviewer reads in one
sitting — and it is where the deliberate coarseness lives: a bad tag, bad
padding, an invalid inner content type and a missing inner content type all map
to `bad_record_mac`, and are all classified `Restricted` so that even a local log
does not record which of them it was.

## Two state machines, not one

TLS 1.2 and TLS 1.3 get separate explicit state machines. They share the record
layer, the transcript machinery, the algorithm registries and the error model,
and share nothing about their message sequences.

They are different protocols wearing similar names. TLS 1.2 has a
ChangeCipherSpec that really switches epochs, a ServerKeyExchange, a PRF, and a
master secret derived from a premaster; TLS 1.3 has none of those, has a
HelloRetryRequest, and has a key schedule with three Extract stages. Encoding
both in one machine means a set of Boolean fields whose legal combinations nobody
can enumerate — which is the shape of code where a TLS 1.2 message is accepted in
a TLS 1.3 handshake.

## Connections are single-use

A connection is a limited, controlled object that cannot be reset or reused after
close or failure. Its lifecycle is linear: Uninitialized, Ready, Handshaking,
Established, Closing, Closed, Failed, with no path back.

Finalization performs no I/O and no blocking work. It scrubs secrets and releases
storage. A graceful close is an explicit operation, because a close_notify that
happened in a finalizer would be a network write at an arbitrary moment during
stack unwinding.

## Where time enters

Two clocks, kept separate because they answer different questions:

- **Wall clock**, caller-supplied, for certificate validity. A certificate is
  valid between two dates in the world, and only a wall clock knows those.
- **Monotonic time**, caller-supplied, for deadlines. A deadline must not move
  because the system clock was stepped, which is precisely what a wall clock
  does.

`SSL.Clocks` will source monotonic time from `Ada.Real_Time`, which is monotonic
by definition and needs no platform-specific code. See `docs/status.md` for why
this deviates from the specification's assignment of monotonic clocks to
`hostkit`.
