--  @summary This library's own version and provenance, for release metadata
--  and for an application that wants to record what it was built against.
--
--  Distinct from SSL.Versions, which is about the protocol. The similarity of
--  the names is unfortunate and deliberate: the crate version belongs in a
--  package named after the crate's version, and the protocol versions belong in
--  the plural. Nothing here is about the wire.
package SSL.Version is
   pragma Preelaborate;

   --  The crate version, matching alire.toml. The release tooling checks that
   --  these agree and refuses a release when they do not, so this is the one
   --  place either has to be edited.
   Crate_Version : constant String := "0.1.0-dev";

   --  The protocol scope this release implements, as a single line for a
   --  report or a banner.
   Protocol_Scope : constant String :=
     "TLS 1.3 (RFC 8446) and restricted modern TLS 1.2 (ECDHE+AEAD, EMS required)";

   --  What this release deliberately does not implement, so that an
   --  application recording provenance records the absences too.
   Excluded_Features : constant String :=
     "SSL 2.0/3.0, TLS 1.0/1.1, compression, RC4/DES/3DES/CBC/NULL, static RSA, "
     & "static/anonymous DH, renegotiation, heartbeat, 0-RTT, external PSK, "
     & "post-handshake client auth, DTLS, QUIC, ECH, delegated credentials, "
     & "certificate compression, raw public keys, TLS 1.2 session-ID resumption";

   --  The crates this library's runtime depends on. Recorded here so a
   --  diagnostic bundle names the ownership boundaries the implementation
   --  holds to.
   Runtime_Dependencies : constant String := "cryptolib, truststores, hostkit";

end SSL.Version;
