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

   --  Buffers and queues.
   function Check_Queue_Backpressure return String;
   function Check_Queue_Partial_Append return String;

end SSL.Internal_Tests;
