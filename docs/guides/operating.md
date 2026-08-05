# Running it in production

Covers errors, diagnostics, limits and concurrency.

## Errors

Ordinary failures are values. `SSL.Errors.Error_Information` carries a stable
category, an explicit numeric code, an origin, whether it is fatal, the alert it
maps to, the lifecycle stage it happened in, bounded parameters, a retry
classification and a disclosure classification.

Exceptions are for three things only: a violated precondition, an impossible
internal state, and the inherited `Ada.Streams` interface. A peer sending
nonsense is none of those.

The **disclosure classification** is the field most worth knowing about. Some
failures may be reported to a peer in full; others must not be, because the
difference between two of them is an oracle. `SSL.Errors` decides that once, in
one table, rather than leaving each call site to remember.

The first terminal failure is preserved. Later failures increment a bounded
secondary count and do not overwrite it, because the first one is the one that
explains the rest.

## Diagnostics

Two settings, not one. **Detail level** is how much to say; **redaction level**
is how much of what is said may leave the machine. A deployment shipping logs to
a third party wants `Detailed_Protocol` with `Strict` redaction, and there is no
way to express that with a single knob.

A sink that raises has its exception caught and the event dropped. Losing a
diagnostic is better than unwinding a connection that has keys installed, and an
application must not be able to break its own connections by writing a bad
logger.

**No secret is ever logged.** Not at any level, not under any redaction setting.
The test suite runs a live connection with the most detailed level and the least
redacting setting, then scans every event it produced for that connection's own
exported key material, in both the raw and hexadecimal spellings, including an
eight-octet prefix.

Key logging is a separate thing: `SSL.Unsafe.Key_Logging`, in a child package
called `Unsafe` so that a code review can grep for it. It is disabled by
default, enabled only explicitly in a configuration, writes to an application
sink and never to a file, and never reads an environment variable to decide
whether to turn itself on.

## Limits

Every peer-influenced count and length has a bound in `SSL.Limits`, and the set
is checked for consistency at `Build`: a configuration whose limits could not
hold a single record is refused rather than deadlocking later. The bounds are
the answer to hostile input on every path, which is why there are no unbounded
containers on those paths.

## Concurrency

A `SSL.Connections.Connection` is one task at a time. It holds sequence numbers,
a transcript and traffic keys; two tasks stepping it would interleave records
under one sequence-number space, which shows up as a peer terminating the
connection rather than as a wrong answer.

`SSL.Synchronized_Connections` is the supported way to share one: a reader task,
a writer task and a controller, over a serialized driver. The lock is a
protected object and the work happens outside it, because the work calls a
transport and a transport is the application's own code.

A session cache is a different matter: `SSL.Sessions.Client_Caches` is designed
to be shared, and the test suite drives eight tasks against one.
