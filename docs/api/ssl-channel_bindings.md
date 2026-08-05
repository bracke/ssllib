# ssl-channel_bindings

Generated from `src/ssl-channel_bindings.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

Channel bindings: a value that ties an authentication exchange
running inside TLS to the particular TLS connection carrying it.

The problem they solve is a real one. An application that authenticates
inside a TLS tunnel -- SASL, HTTP authentication, a token exchange -- is
protected against an eavesdropper, and is *not* protected against a proxy
that terminates one TLS connection and opens another. The proxy can replay
the authentication onto its own connection, because nothing in the
authentication mentions which connection it was for. A channel binding is
the mention: both ends include a value derived from their own connection,
and a relayed exchange no longer matches.

Two kinds are produced here.

* **tls-exporter** (RFC 9266). Derived from the connection's exporter, so
it is bound to the key exchange itself. This is the one to use: it works
in TLS 1.3, it does not depend on the certificate, and it has no known
weakness.
* **tls-server-end-point** (RFC 5929). A hash of the server's certificate.
Weaker, because two connections to the same server share it -- it binds
to the *server*, not to the connection -- but it survives a proxy that
re-uses the server's certificate, and some deployed protocols require
it.

**tls-unique is not here and will not be.** RFC 5929 defines it from the
first Finished message, which TLS 1.3 does not expose in the same way, and
RFC 8446 appendix C.5 says so explicitly. It is also the binding the triple
handshake attack broke. This library implements no TLS 1.2 resumption that
would qualify for it either, so there is nothing it could correctly return.

**The values are sensitive.** A channel binding is not a secret in the way a
key is -- a peer knows it too -- but it is derived from key material and
disclosing one weakens the binding it exists to provide. Nothing here logs
one, and callers should treat them the same way.

The RFC 9266 tls-exporter binding.

`Exporter(EXPORTER-Channel-Binding, "", 32)` -- an empty context, and
*supplied* rather than absent, which is what the specification says and
is not the same thing.
@param Item  the connection, which must be established
@param Into  out: the binding; zeroed on failure
@param Error out: No_Error, or why it could not be produced

```ada
procedure Exporter_Binding
  (Item  : SSL.Connections.Connection;
   Into  : out Byte_Array;
   Error : out SSL.Errors.Error_Information)
  with Pre => Into'Length = Exporter_Binding_Length;
```

The RFC 5929 tls-server-end-point binding: a hash of the peer's leaf
certificate.

RFC 5929 says to use the hash from the certificate's own signature
algorithm, with SHA-256 as the floor. This library always uses SHA-256,
which is what every deployed implementation does and what every protocol
that asks for this binding expects; following the letter of the RFC would
produce a value no peer computes.

Requires a peer that actually presented a certificate. A resumed
connection has no fresh certificate and this refuses rather than
returning a binding to something that was not proved.
@param Item  the connection
@param Into  out: the binding; zeroed on failure
@param Error out: No_Error, or why it could not be produced

```ada
procedure End_Point_Binding
  (Item  : SSL.Connections.Connection;
   Into  : out Byte_Array;
   Error : out SSL.Errors.Error_Information)
  with Pre => Into'Length = End_Point_Binding_Length;
```


