# Examples

Each of these builds and runs. None of them opens a socket.

That last point is the important one and it is not a limitation of the
examples: `ssllib` does not do I/O at all. It is handed encrypted octets and
produces encrypted octets, and what carries them is the application's. Every
example here therefore supplies its own transport — an in-memory pipe, so that
the example runs anywhere with no network, no ports and no privileges — and an
application using a real socket writes a `SSL.Transports.Transport` around it
in the same twenty lines.

| Example | What it shows |
|---|---|
| `handshake_example` | A client and a server, secure defaults, identity verified, orderly shutdown |
| `alpn_example` | Negotiating an application protocol, and what happens when there is no overlap |
| `nonblocking_example` | Driving a connection from an event loop with `Ready`, over a transport that refuses half its reads |
| `exporter_example` | Exported keying material and a `tls-exporter` channel binding |
| `diagnostics_example` | A diagnostic sink, the level and redaction settings, and what a log line looks like |
| `mutual_example` | The server requires a client certificate, the client sends one and signs for it, and both ends report an authenticated peer |

Build and run them all:

```
cd examples && alr build && ./bin/handshake_example
```

## What is not here yet

A session-resumption example. Resumption *is* implemented — for TLS 1.3 through
`pre_shared_key` and for TLS 1.2 through RFC 5077 tickets, both checked end to
end in the test suite — but an example of it needs two connections in sequence
with a cache between them, and the interesting part is the cache's bindings
rather than anything in the handshake. `docs/guides/protocols.md` describes
those bindings and why each one refuses.

An example demonstrating an API that is not there would be documentation of
something untrue, which is why this section exists rather than a stub.
