# ssl-clients

Generated from `src/ssl-clients.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

Starting a connection as the client.

A thin package, deliberately. Everything a client connection does is
`SSL.Connections`'; what is here is the one call that says *which role this
endpoint is playing*, and a name for it that reads as what it is.

It exists as a package of its own rather than as a `Connect` on
`SSL.Connections` for a reason worth stating: role is not a parameter. A
client and a server run different state machines, refuse different things
and have different obligations, and an API where the role is an argument
invites code that passes it through from somewhere else. Here the role is
in the name of the package, and choosing it is a decision at the call site.

Begin a connection to a server.

Returns as soon as the ClientHello is queued -- nothing here waits, and
the handshake has not happened yet. Drive it with `SSL.Blocking.Handshake`
or with `SSL.Connections.Step` from an event loop.

The configuration and the transport must both outlive the connection.
@param Item     out: the connection
@param Config   the client policy, already built
@param Medium   the transport
@param Identity a stable identifier for correlating this connection's
log lines; No_Connection when the caller has none
@param Now      the wall clock, for certificate validity. An absent clock
is not an error here; certificate validation refuses
later rather than guessing a date
@param Error    out: No_Error, or why the connection could not start

```ada
procedure Connect
  (Item     : in out SSL.Connections.Connection;
   Config   : not null access constant SSL.Configurations.Client_Configuration;
   Medium   : not null SSL.Transports.Transport_Reference;
   Identity : Connection_ID := No_Connection;
   Now      : SSL.Clocks.Wall_Time := SSL.Clocks.Current_UTC;
   Error    : out SSL.Errors.Error_Information);
```


