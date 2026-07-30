# tests/corpora

Empty in this release. See `docs/status.md`.

This directory is for the permanent mutation corpus: every input that ever caused
a failure, kept forever with the seed that produced it, so that a fixed bug
cannot come back unnoticed.

There is no corpus because there is no mutation runner, and there is no mutation
runner because the handshake parsers it would mutate do not exist. The runner is
specified to be deterministic Ada — bit flips, insertion, deletion, length
corruption, duplicate and reordered extensions, tag and signature corruption, and
certificate truncation — with recorded seeds.
