# Examples

Empty, and deliberately so.

The specification asks for a basic client and server, a mutual-TLS pair, an ALPN
client, a nonblocking client, a session-resumption example, a custom-trust
example and an exporter example — each using secure defaults, verifying identity,
bounding its timeouts, handling structured errors and shutting down cleanly.

Every one of those needs `SSL.Configurations`, `SSL.Connections`,
`SSL.Blocking` and `SSL.Transports`, none of which exists yet. An example that
demonstrated an API that is not there would be documentation of something
untrue, so there is none.

See `docs/status.md` for what this release does contain, and for the order the
rest is to be built in.
