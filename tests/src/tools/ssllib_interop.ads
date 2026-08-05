--  @summary The interoperability controller: driving `ssllib` against other
--  people's TLS implementations, and them against it.
--
--  Everything else in this repository proves that `ssllib` agrees with itself.
--  That is worth a great deal and it is not the same as agreeing with the
--  protocol: a library can be internally consistent and wrong, and the way that
--  shows is that nothing else will talk to it. So this drives real external
--  stacks -- OpenSSL, GnuTLS, and whatever else the host happens to have -- and
--  requires that a handshake with each one *completes and negotiates what it
--  was supposed to*.
--
--  That last point is the whole design. A socket that connected proves almost
--  nothing: a stack that fell back to TLS 1.2 when 1.3 was demanded, or agreed
--  no application protocol when one was required, or skipped certificate
--  verification, would all look like success. Every check here asserts the
--  *negotiated outcome* -- version, suite, group, protocol, whether the peer
--  authenticated -- and treats a connection that succeeded with the wrong
--  answers as a failure.
--
--  Four rules the controller holds to, each because the obvious alternative
--  causes trouble that is hard to attribute:
--
--    * **Loopback only.** No name resolution, no outside address, no
--      dependence on anything a firewall or a proxy might be doing.
--    * **Temporary directories, removed afterwards.** Credentials are written
--      where they can be found and cleaned up, never into a shared location.
--    * **The host's trust store is never touched.** Every certificate this
--      controller uses is passed to the external tool explicitly. A test that
--      installed a root would be a test that changed the machine it ran on.
--    * **Bounded execution, and a stable reason for every skip.** An absent
--      tool produces a named skip rather than a failure, and the name is stable
--      so that a report can be compared across machines and across time.
package SSLLib_Interop is

   --  An external stack the controller knows how to drive.
   --
   --  A closed set, because each one needs its own command line and its own
   --  reading of its output. A stack that is not here is not supported rather
   --  than silently attempted.
   type External_Stack is
     (OpenSSL,
      GnuTLS,
      LibreSSL,
      BoringSSL,
      Java_Keytool);

   function Image (Item : External_Stack) return String;

   --  Which direction is being tested.
   type Direction is
     (Ours_As_Client,
      --  `ssllib` connects to the external stack's server.

      Ours_As_Server);
      --  The external stack's client connects to `ssllib`.

   function Image (Item : Direction) return String;

   --  Which of this library's two protocol profiles is being exercised.
   --
   --  A dimension of its own rather than a second matrix, because the question
   --  "does TLS 1.2 interoperate" is not answered by a TLS 1.3 run that passed:
   --  the two share a hello and nothing else.
   type Profile is
     (Modern,
      --  TLS 1.3.

      Restricted_Legacy);
      --  Restricted TLS 1.2: ECDHE, AEAD, extended master secret.

   function Image (Item : Profile) return String;

   --  What happened.
   type Outcome is
     (Passed,
      --  The handshake completed and negotiated what it was told to.

      Skipped,
      --  The stack is not installed, or is too old to do what was asked. Not a
      --  failure: a report that turned an absent tool into a red mark would be
      --  a report nobody could read.

      Refused,
      --  The handshake failed.

      Mismatched);
      --  The handshake completed and negotiated something else. The most
      --  interesting outcome of the four, and the one a socket-success check
      --  would have missed.

   function Image (Item : Outcome) return String;

   --  Run the whole matrix and print a report.
   --
   --  Never fails the build on a skip, always fails it on a refusal or a
   --  mismatch. The distinction is the point: a machine without GnuTLS should
   --  not look the same as a machine where GnuTLS refused to talk to us.
   --  @param Root      the repository root
   --  @param Succeeded out: False when anything was refused or mismatched
   procedure Run_Matrix (Root : String; Succeeded : out Boolean);

end SSLLib_Interop;
