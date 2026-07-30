# tests/vectors

Empty in this release. See `docs/status.md`.

This directory is for imported authoritative vectors kept as data files, with
their source, version, licence and vector identifiers recorded alongside them.

The RFC 8448 TLS 1.3 key-schedule vectors that this release does use are
embedded in `tests/src/ssl-internal_tests.adb` rather than held here, because
there are eight of them and a data file would add a parser without adding
provenance — the provenance is recorded in `docs/attribution.md` and in a comment
at the point of use.

Still to import, when their subjects exist: the TLS 1.2 PRF vectors, exporter and
channel-binding vectors, and the X.509/PKIX path-validation suites.
