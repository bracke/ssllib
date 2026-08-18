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
- **The queues an endpoint configures are the ones it gets.**
  `Maximum_Input_Buffer`, `Maximum_Ciphertext_Queue` and
  `Maximum_Plaintext_Queue` decided nothing: `SSL.Engines` reserved three
  constants of its own whatever the configuration said, so raising a queue got
  the constant, lowering it got the constant, and `SSL.Limits.Is_Valid` checked
  relationships between numbers that never reached a buffer — including the
  rule that exists to keep a configuration from deadlocking. The engine
  reserves what it was configured with now. **The defaults have changed to what
  this library has always reserved** (64 KiB of plaintext, 130 KiB of
  ciphertext, 32 KiB of input) rather than the megabyte each that used to stand
  in the record and reach nothing: honouring the old numbers would have
  quadrupled the memory of every connection every consumer opens, which is not
  a change a corrected number should smuggle in. An endpoint that wants a
  megabyte can now ask for one and get it.
- **An endpoint no longer waits for an empty queue to drain.** Backpressure is
  measured against the record's ciphertext length, because the plaintext length
  is inside the ciphertext — an upper bound, and erring towards waiting is the
  safe direction. But a queue close to one record wide fails that comparison
  even when empty, so an endpoint configured with the smallest plaintext queue
  `Is_Valid` accepts stalled on the first full-size record it was sent: it
  waited for a drain that could not come, with nothing to drain and nobody
  behind. It was unreachable while the capacity was a constant four records
  wide; the fix above made it reachable, and a test names it.
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
