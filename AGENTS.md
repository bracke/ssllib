# Agent instructions — ssllib

Pure Ada 2022 TLS 1.3 and restricted modern TLS 1.2 library.

This crate pins its GNAT toolchain via Alire (`gnat_native = "=15.2.1"`). Build and test with `alr`, not
system GNAT / GPRBuild / GNATprove / GNATdoc tools on `PATH` — `alr exec -- gnatls --version` must report the pinned GNAT.

```sh
alr build
```
