# ssl-servers

Generated from `src/ssl-servers.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

Starting a connection as the server.

The mirror of `SSL.Clients`, and a separate package for the same reason:
role is not a parameter, it is a decision made once at the call site.

A server says nothing until it has heard a ClientHello, so this call queues
no octets. It is not an accept in the socket sense either -- this library
does not listen, does not bind and does not know what a socket is. The
application has already accepted a connection by whatever means it uses, and
this wraps TLS around the transport that came out of it.

Begin serving a connection an application has already accepted.

@param Item     out: the connection, waiting for a ClientHello
@param Config   the server policy, already built
@param Medium   the transport
@param Identity a stable identifier for correlating log lines
@param Now      the wall clock, for certificate validity
@param Error    out: No_Error, or why the connection could not start

```ada
procedure Accept_Connection
  (Item     : in out SSL.Connections.Connection;
   Config   : not null access constant SSL.Configurations.Server_Configuration;
   Medium   : not null SSL.Transports.Transport_Reference;
   Identity : Connection_ID := No_Connection;
   Now      : SSL.Clocks.Wall_Time := SSL.Clocks.Current_UTC;
   Error    : out SSL.Errors.Error_Information);
```


