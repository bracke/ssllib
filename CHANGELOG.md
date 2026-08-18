# Changelog

Notable changes to ssllib. Format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`0.1.0-dev`, no tag: consumers pin this crate **by path**, so the commit is the
version, and a consumer's release records which commit it was verified against.

## [Unreleased]

### Fixed

- **The connection kept the octets the engine could not take yet.** Supplying
  the engine is a partial operation — its input queue is bounded, it takes what
  fits and reports how much — and `Pump_Input` ignored the report, dropping the
  rest of the socket read. A dropped octet is not a lost octet: the next record
  header lands mid-record and the AEAD rejects what follows, so it surfaced as
  `bad_record_mac` at a different offset every run, on the hosts whose socket
  reads are largest and never on macOS. An 82 MB download in a consumer's CI
  found it; the suite, whose largest transfer read what it sent as it sent it,
  could not.
- **A full plaintext queue makes the engine wait rather than fail.** A record
  whose plaintext would not fit was decrypted anyway and then failed the
  connection, so an application reading more slowly than its peer sends killed
  its own connection. The record now stays in the input queue, the input queue
  fills, and the peer's flow control does the rest.
- **`Maximum_Trust_Anchors` raised from 512 to 4096.** A stock Windows host's
  root store holds 563 certificates (Linux 121, macOS 159), and
  `Load_System_Anchors` refuses an over-large store rather than truncating it —
  correctly — so the whole system store was rejected and every TLS connection
  from that host failed. The bound is on a store somebody hands us, not on the
  one the operating system ships. `Constrained_Limits` keeps 256 deliberately.

### Added

- Tri-platform CI (ubuntu, macos-15-intel, windows-latest). This crate had
  none, which is why both defects above were found by a consumer three crates
  away rather than here.
- A regression test for the dropped octets: a sender running ahead of a reader
  that takes a kilobyte a round. It only became reachable once a full plaintext
  queue stopped ending the connection.

## Releasing

No procedure yet. The open question is the same one the sibling crates have:
what a version means while every consumer resolves this one by path.
