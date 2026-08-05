# ssl-sessions-client_caches

Generated from `src/ssl-sessions-client_caches.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

Where a client keeps the sessions it may resume with.

An interface rather than an implementation, because where sessions live is
an application's decision and not this library's. A short-lived command-line
tool wants them in memory and gone at exit; a long-running server making
outbound connections wants them shared between its worker tasks; a browser
wants them on disk, encrypted, surviving a restart. None of those is a
default that suits the others.

`SSL.Sessions.Client_Caches.Memory` is the bounded, task-safe in-memory one,
and is what most applications should use.

**A cache that fails is not a connection failure.** Every operation here
reports what happened, and the engine's response to any failure is the same:
do a full handshake. A cache is an optimization, and an optimization that
breaks must not break the thing it was optimizing.

**A cache is application code, so it may raise.** Calls are made through the
boundary below, which converts an exception into a structured failure and
falls back to a full handshake.

```ada
type Cache is limited interface;
```

```ada
type Cache_Reference is access all Cache'Class;
```

Look for a session usable for this server name and context.

An implementation must not return one whose bindings do not match; the
engine checks again, but a cache that returned mismatched sessions would
be doing lookups that always fail.
@param Item    the cache
@param Name    the server name the connection is for
@param Context the security context in force
@param At_Time the wall clock, for expiry
@param Into    in out: the session, left absent when there is none
@param Found   out: True when one was supplied

```ada
procedure Look_Up
  (Item    : in out Cache;
   Name    : SSL.Server_Names.DNS_Name;
   Context : Security_Context_ID;
   At_Time : SSL.Clocks.Wall_Time;
   Into    : in out Session;
   Found   : out Boolean) is abstract;
```

Offer a session for storage.

An implementation may decline -- it is full, the session is too large, it
has a policy of its own -- and declining is not a failure. It must not
keep a reference to the argument: the session is copied or it is dropped.
@param Item  the cache
@param Value the session to keep
@param Kept  out: True when it was stored

```ada
procedure Store
  (Item  : in out Cache;
   Value : Session;
   Kept  : out Boolean) is abstract;
```

Forget a session that turned out not to work.

Called when a server refuses a ticket. Keeping one that has been refused
means offering it again and wasting the round trip again.

```ada
procedure Discard
  (Item    : in out Cache;
   Name    : SSL.Server_Names.DNS_Name;
   Context : Security_Context_ID) is abstract;
```

Short text naming this cache, for the failure recorded when it raises.

```ada
function Description (Item : Cache) return String is abstract;
```

-------------------------------------------------------------------------
Calling one
-------------------------------------------------------------------------

Look up through the exception boundary.

A cache that raises produces no session and a structured failure naming
it. The caller's response is a full handshake either way, which is why
the failure is reported rather than propagated.

```ada
procedure Look_Up_Safely
  (Item    : in out Cache'Class;
   Name    : SSL.Server_Names.DNS_Name;
   Context : Security_Context_ID;
   At_Time : SSL.Clocks.Wall_Time;
   Into    : in out Session;
   Found   : out Boolean;
   Error   : out SSL.Errors.Error_Information);
```

```ada
procedure Store_Safely
  (Item  : in out Cache'Class;
   Value : Session;
   Kept  : out Boolean;
   Error : out SSL.Errors.Error_Information);
```

```ada
procedure Discard_Safely
  (Item    : in out Cache'Class;
   Name    : SSL.Server_Names.DNS_Name;
   Context : Security_Context_ID);
```


