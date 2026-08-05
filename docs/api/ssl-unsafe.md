# ssl-unsafe

Generated from `src/ssl-unsafe.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

The parent of everything in this library that weakens it.

There is exactly one child, `SSL.Unsafe.Key_Logging`, and there is a parent
package holding it for one reason: a `with` clause naming `SSL.Unsafe`
appears in a diff, in a grep, and in a review. A facility that can decrypt
every connection an application makes should be impossible to reach without
writing the word.

Nothing here is enabled by default. Nothing here reads an environment
variable. Nothing here opens a file. Each of those is a way that a
debugging facility becomes a production vulnerability, and each is closed
deliberately rather than by omission.


