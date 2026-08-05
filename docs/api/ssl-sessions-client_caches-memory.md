# ssl-sessions-client_caches-memory

Generated from `src/ssl-sessions-client_caches-memory.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

A bounded, task-safe session cache that lives in memory and goes
away with the process.

What most applications should use. It holds a fixed number of sessions,
evicts the least recently used when it is full, and never allocates after
it is created.

**Task-safe, by a protected object.** A client cache is exactly the thing
several worker tasks reach at once -- each opening its own outbound
connection to the same handful of hosts -- so serializing it here rather
than asking every application to do it is the right place for the cost.
The operations are short: a bounded scan and a copy.

**Bounded, and eviction is by use rather than by age.** A cache that evicted
the oldest would keep discarding the session for the host it talks to most,
because that is the one whose entry was created first. Least-recently-used
keeps the working set.

**Nothing is written anywhere.** Sessions here do not survive the process.
Persisting them would need an explicit persistence key -- there is no
unencrypted mode and no hidden file I/O -- and that is a separate thing this
library does not yet provide.

How many sessions one cache holds. Fixed at declaration rather than
configurable at run time, so that the storage is reserved once and the
bound is visible where the cache is declared.

```ada
type Memory_Cache (Capacity : Positive) is
  limited new Cache with private;
```

How many live entries the cache holds. For diagnostics and for a test
that wants to assert eviction happened.

```ada
function Occupancy (Item : Memory_Cache) return Natural;
```

Forget everything, scrubbing as it goes.

```ada
procedure Clear (Item : in out Memory_Cache);
```


