--  @summary Checks over ssllib's private children, reachable because this unit
--  is itself a child of SSL.
--
--  The wire codecs, the record layer, the transcript and the key schedule are
--  private children: nothing outside the SSL hierarchy can name them, which is
--  the point -- they are not API and must not become API by being tested. A
--  child of SSL, however, may name a private sibling from its body, and that is
--  what this unit is for. It lives in the test crate, not in the runtime
--  library, so the runtime has no dependency on it and cannot call into it.
--
--  Each check is a function returning a diagnostic: the empty string when the
--  check passed, and text naming what disagreed when it did not. The AUnit test
--  cases in ssllib_tests assert on that string, so a failure reports what was
--  expected and what was produced rather than only that something was wrong.
package SSL.Internal_Tests is

   --  Wire codecs: big-endian integers, length-prefixed vectors, the sticky
   --  failure flag, and refusal at every bound.
   function Check_Wire_Integers return String;
   function Check_Wire_Vectors return String;
   function Check_Wire_Sticky_Failure return String;
   function Check_Wire_Byte_Boundaries return String;
   function Check_Wire_Emitter_Backpatch return String;

   --  The TLS 1.3 key schedule against RFC 8448 section 3.
   function Check_Key_Schedule_Vectors return String;

   --  Stage ordering, generation advance, and that the products of the schedule
   --  are distinct from one another.
   function Check_Key_Schedule_Stages return String;
   function Check_Key_Schedule_Distinct return String;
   function Check_Key_Update_Advance return String;
   function Check_Exporter_Context_Distinction return String;
   function Check_Resumption_Nonce_Distinction return String;

   --  The transcript: exact absorption, non-finalizing snapshots, and the
   --  HelloRetryRequest message_hash transformation.
   function Check_Transcript_Snapshot return String;
   function Check_Transcript_Hello_Retry return String;

   --  The record layer.
   function Check_Record_Header_Codec return String;
   function Check_Record_Nonce return String;
   function Check_Record_Round_Trip return String;
   function Check_Record_Padding_Removed return String;
   function Check_Record_Tag_Tamper return String;
   function Check_Record_Header_Tamper return String;
   function Check_Record_Sequence_Advance return String;
   function Check_Record_No_Plaintext_On_Failure return String;
   function Check_Record_Inner_Type_All_Zero return String;

   --  Secret handling.
   function Check_Secret_Wipe return String;
   function Check_Secret_Constant_Time_Equality return String;

   --  Signature verification, which the certificate path and
   --  CertificateVerify share. RSASSA-PSS specifically: TLS fixes its
   --  parameters per scheme rather than carrying them, so this is the path
   --  that has no AlgorithmIdentifier to read.
   function Check_PSS_Signature_Verification return String;

   --  Key agreement over every group the registry offers, both elliptic-curve
   --  and finite-field, in both directions, with the degenerate and
   --  wrong-length peer shares refused.
   function Check_Key_Agreement_Groups return String;

   --  The closed extension registry: identifiers, context rules, duplicate
   --  refusal, and the unknown identifiers kept for diagnostics.
   function Check_Extension_Registry return String;
   function Check_Extension_Contexts return String;
   function Check_Extension_Block_Parsing return String;

   --  Handshake message framing and the two hello parsers, including what they
   --  refuse: a hostile ClientHello is the largest attacker-chosen structure in
   --  the protocol and is parsed before anything has been authenticated.
   function Check_Handshake_Framing return String;
   function Check_Client_Hello_Round_Trip return String;
   function Check_Client_Hello_Refusals return String;
   function Check_Client_Hello_Truncation return String;
   function Check_Server_Hello_And_Retry return String;

   --  The X.509 validation pipeline, driven end to end against a committed
   --  self-signed fixture that serves as both leaf and anchor.
   function Check_Validation_Pipeline return String;

   --  The ClientHello encoder, checked by parsing back what it produced. A
   --  round trip cannot catch an encoding both sides get wrong the same way,
   --  so it is paired with assertions on the octets the specification fixes.
   function Check_Client_Hello_Encoding return String;

   --  The CertificateVerify signed-data construction, RFC 8446 section 4.4.3.
   function Check_Certificate_Verify_Content return String;

   --  The remaining TLS 1.3 message codecs: each encoded, then parsed back
   --  through the parser a peer would use, plus the refusals each one owns.
   function Check_Server_Hello_Encoding return String;
   function Check_Encrypted_Extensions_Codec return String;
   function Check_Certificate_Codec return String;
   function Check_Certificate_Request_Codec return String;
   function Check_Small_Message_Codecs return String;

   --  A ClientHello's pre_shared_key offer: the two lists, their
   --  correspondence, the binders offset, and the last-extension rule.
   function Check_PSK_Offer_Parsing return String;

   --  The TLS 1.3 client machine driven against the TLS 1.3 server machine, in
   --  process and with no transport: both must reach Connected, agree on what
   --  was negotiated, and derive keys that actually decrypt each other's
   --  records.
   function Check_Handshake_End_To_End return String;

   --  Two engines driven against each other with no transport at all: the
   --  handshake, application data both ways, partial consumption, and an
   --  orderly shutdown.
   function Check_Engine_Round_Trip return String;

   --  The connection layer over a transport that refuses half its reads and
   --  accepts ninety-seven octets per write: handshake, a message spanning
   --  several records, and an orderly shutdown.
   function Check_Connection_Over_Pipes return String;

   --  An endpoint whose plaintext queue is exactly one record long still
   --  moves a full-size record through it.
   --
   --  Backpressure is measured against the *ciphertext* length, because the
   --  plaintext length is inside the ciphertext -- so an empty queue that is
   --  one plaintext record wide looks too small for a full record and would
   --  wait for itself to drain. This drives that configuration and fails if
   --  nothing arrives, rather than hanging where a suite cannot say why.
   function Check_A_Queue_Of_One_Record_Still_Moves return String;

   --  The plaintext queue an endpoint configured is the one it gets.
   --
   --  The queues were reserved at constants in SSL.Engines whatever an
   --  endpoint had configured, so Maximum_Plaintext_Queue decided nothing and
   --  the limits validator checked relationships between numbers that never
   --  reached a buffer. This fills a reader that never reads and asks how much
   --  it took.
   function Check_A_Configured_Queue_Is_The_Boundary return String;

   --  A stream that ends without a close_notify must be distinguishable from
   --  one that closed properly.
   function Check_Truncation_Detected return String;

   --  Everything that happens after the handshake: exporters, channel
   --  bindings, and a KeyUpdate in both directions with data flowing across it.
   function Check_Post_Handshake return String;

   --  Tickets: the key ring's states, a server issuing, a client's cache
   --  keeping what it was issued, and the bindings that stop a session being
   --  offered where it does not belong.
   function Check_Ticket_Issue return String;

   --  Three connections in a row: the first cannot resume, the second resumes
   --  from the first one's ticket, and the third from the second's.
   function Check_Resumption return String;

   --  Restricted TLS 1.2, end to end: the client machine against the server
   --  machine, with the key block proved by records crossing in both
   --  directions and a flipped tag bit refused.
   function Check_TLS12_Handshake return String;

   --  A full TLS 1.2 handshake that issues a ticket, an abbreviated one that
   --  takes it up, and a damaged ticket that costs a resumption rather than a
   --  connection.
   function Check_TLS12_Resumption return String;

   --  The same thing over a transport rather than machine-to-machine: two
   --  TLS 1.2 connections through the engine, the second resuming from the
   --  ticket the first was issued.
   function Check_TLS12_Connection_Resumption return String;

   --  A reader task, a writer task and a controller on one connection through
   --  `SSL.Synchronized_Connections`, all at once.
   function Check_Synchronized return String;

   --  Wiping watched through a test-only observer, and every diagnostic a live
   --  connection produced scanned for that connection's own key material.
   function Check_Secret_Hygiene return String;

   --  A handshake where the server requires a client certificate and the
   --  client sends one, signs for it, and is believed.
   function Check_Mutual_TLS return String;

   --  A trust store allocates for what it holds rather than for its ceiling,
   --  and growing it keeps every anchor already in it.
   function Check_Trust_Store_Sizing return String;

   --  Trust anchors and a credential loaded from a task with a 256 KB stack.
   --  A loader whose temporary is sized to the whole store rather than to one
   --  certificate raises Storage_Error here and nowhere in the tooling.
   function Check_Small_Stack_Loading return String;

   ---------------------------------------------------------------------------
   --  A table only this subtree can produce
   ---------------------------------------------------------------------------

   --  Which extensions are permitted in which message, as Markdown.
   --
   --  Here rather than in the tooling because `SSL.Extensions` is a private
   --  child: nothing outside SSL's own subtree can name it, which is the
   --  boundary working. This unit is inside the subtree and already exists to
   --  reach in from the test crate, so it is the one place that can ask the
   --  registry and hand the answer out.
   function Extension_Context_Table return String;

   --  A TLS 1.2-only client against a server that speaks both: the connection
   --  layer must negotiate down and carry data over the TLS 1.2 record
   --  construction.
   function Check_Version_Negotiation return String;

   --  Every single-bit flip, truncation, insertion, deletion and corrupted
   --  length of three seed messages, handed to every parser. The only thing a
   --  parser may not do is raise.
   function Check_Mutated_Messages return String;

   --  Every configured limit at limit-1, at the limit and at limit+1, plus a
   --  huge declared length with no payload behind it.
   function Check_Limit_Boundaries return String;

   --  Eight tasks on one session cache, doing every operation it has on
   --  overlapping keys.
   function Check_Cache_Concurrency return String;

   --  A diagnostic sink that calls back into the library from inside its own
   --  Emit: the library must never call a sink from inside a sink.
   function Check_Callback_Reentrancy return String;

   --  A whole connection delivered one octet at a time, so that every record
   --  header, length prefix and epoch transition is split at every internal
   --  boundary; and then several records supplied in one call.
   function Check_Byte_At_A_Time return String;

   --  Buffers and queues.
   function Check_Queue_Backpressure return String;
   function Check_Queue_Partial_Append return String;

end SSL.Internal_Tests;
