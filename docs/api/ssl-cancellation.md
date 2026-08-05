# ssl-cancellation

Generated from `src/ssl-cancellation.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

A cancellation token the caller owns and the engine only reads.

Cancellation has to cross tasks: the point of it is that one task can stop a
blocking read another task is sitting in. That is the only concurrency this
library has, and it is deliberately the narrowest shape that works -- a
one-way latch, set once, read anywhere.

A one-way latch rather than a resettable flag, because a token that can be
un-cancelled has a race with no correct resolution: a reader that has already
observed the cancellation and begun unwinding cannot be told to carry on. Once
set, a token stays set, and a caller who wants to reconnect uses a new
connection and a new token -- which is what connections being single-use
already requires.

The engine never blocks on this and never waits for it. It reads the flag at
the points where it would otherwise make progress, and reports
Code_Cancelled as an ordinary structured failure.

Limited: a token is shared by reference between the task that cancels and
the task that observes, and copying one would give them separate flags.

```ada
type Token is limited private;
```

Prepare a token for use. Only before the connection it belongs to has
started; a token is not reusable once a connection has observed it.

```ada
procedure Initialize (Item : out Token)
  with Post => not Is_Cancelled (Item);
```

Request cancellation. Safe to call from a task other than the one using
the connection, and safe to call more than once.

```ada
procedure Cancel (Item : in out Token)
  with Post => Is_Cancelled (Item);
```

Has cancellation been requested? Safe to call from any task.

```ada
function Is_Cancelled (Item : Token) return Boolean;
```


