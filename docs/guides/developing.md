# Building, testing and releasing

Covers building, testing, interoperability and the release process. Everything
here goes through `ssllib_tools`, which is an Ada program. There is no shell
script, Makefile, Python, Perl, Ruby or Node in this repository, and CI runs
this program rather than reimplementing any part of it.

## Building

```
alr build                     # the library
cd tests && alr build         # the test crate and the tooling
./tests/bin/ssllib_tools build
```

GNAT 15.2.1 through Alire. The switches are `-gnat2022 -gnatyM120 -gnatX -gnata
-gnatwa`: assertions on, warnings on, and contracts checked.

## Testing

```
ssllib_tools test           # the AUnit suite, including the authoritative vectors
ssllib_tools test-vectors   # only the vector checks
ssllib_tools test-corpus    # the mutation corpus
ssllib_tools test-interop   # the external-stack matrix
ssllib_tools prove          # GNATprove, development profile
ssllib_tools prove release  # GNATprove, release profile
ssllib_tools verify         # the API, boundary and no-secret audits
```

The suite depends on no file, no network, no clock and no randomness. Fixtures
are embedded as text and the certificate fixture is valid to 2126, so a green
suite today is a green suite in ten years.

The **mutation runner** is deterministic: six kinds of mutation over every
position of each seed, replayed identically on every run. It found a real defect
on its first seed.

## Interoperability

`ssllib_tools test-interop` drives real external stacks on the loopback address,
under both protocol profiles, in both directions. Every check asserts the
*negotiated outcome* — version, suite, group, protocol, whether the peer
authenticated — because a stack that fell back to TLS 1.2 or skipped
verification would look like success to a connection check.

Loopback only; credentials in a directory per stack and profile, removed
afterwards; the host's trust store never consulted; and an absent tool produces
a named skip rather than a failure, with a stable name so a report can be
compared across machines and across time.

That matrix pays for itself. Four defects the in-process suite had passed over
came out of the first runs against real peers, and they are listed in the
changelog.

## Releasing

```
ssllib_tools docs      # API pages and the specification tables
ssllib_tools package   # the reproducible source manifest and its hashes
ssllib_tools release   # every gate in order
```

`docs` generates one page per public specification from the specifications
themselves, and four tables from the registries themselves — so neither can
drift away from the code.

`package` writes a sorted manifest of every source file with its SHA-256 through
CryptoLib, and one digest over the manifest. There is no timestamp, host name or
build identifier anywhere in it: two runs on two machines from the same source
produce the same two files, octet for octet.

`release` runs verify, build, test, release-profile proof, the interoperability
matrix, docs and package, in that order, and then **refuses** while anything is
on the outstanding-gaps list — naming what it is. The specification says not to
declare V1 complete merely because the project builds, and this is that rule
with an exit status attached.
