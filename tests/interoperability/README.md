# tests/interoperability

Empty in this release. See `docs/status.md`.

This directory is for the Ada interoperability controller and its fixtures: an
ssllib client against external servers and external clients against an ssllib
server, over loopback, in temporary directories, with controlled credentials,
bounded process execution through Hostkit, stable skip reasons and no
modification of any global trust store.

It is empty because there is no handshake to drive. When it exists it must verify
the negotiated version, suite, group, signature scheme, ALPN protocol, SNI,
authentication outcome, resumption, KeyUpdate and closure — not merely that a
socket connected.
