# ssl-streams

Generated from `src/ssl-streams.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

An Ada stream over a TLS connection, for code that is written
against `Ada.Streams.Root_Stream_Type`.

This is the one place in the library where a failure is an exception, and it
is not a choice: `Read` and `Write` are inherited from
`Ada.Streams.Root_Stream_Type` and have no way to report a structured
result. That is a real cost. A stream read that fails raises, and the
exception carries a rendering of the failure rather than the failure itself,
so a caller that needs to act on the failure -- to distinguish a certificate
problem from a transport one, say -- must ask the connection afterwards
rather than catching a type.

Because of that, this is a bridge rather than the recommended API. Code that
can use `SSL.Blocking` or `SSL.Connections` directly should: it gets the
structured failures the rest of this library is built around. This exists so
that `Type'Read` and `Type'Write` work over TLS, which is worth having and
cannot be had any other way.

A stream bound to a connection.

Limited and holding a reference: the connection is the application's and
outlives the stream. Two streams over one connection would be two things
reading one queue, which is the concurrency the base connection type
explicitly does not defend against.

```ada
type Connection_Stream
  (Target : not null access SSL.Connections.Connection)
is limited new Ada.Streams.Root_Stream_Type with private;
```

The deadline every Read and Write on this stream uses.

Set once, because the inherited operations have nowhere to take one. A
stream with no deadline is a program that can stop responding because a
peer stopped talking, so setting one is worth doing even though it is not
required.

```ada
procedure Set_Deadline (Item : in out Connection_Stream; Value : SSL.Clocks.Deadline);
```

The failure that ended this stream, when one did. For a caller that
caught Stream_Failure and needs to know what actually happened.

```ada
function Last_Failure (Item : Connection_Stream) return SSL.Errors.Error_Information;
```


