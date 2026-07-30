with AUnit.Test_Cases;

with SSL.Internal_Tests;

with Tests_Support;

package body Tests_Internals is

   package Internals renames SSL.Internal_Tests;

   ----------
   -- Name --
   ----------

   overriding function Name (T : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (T);
   begin
      return Tests_Support.Message ("ssllib internals: wire, transcript, key schedule, records");
   end Name;

   ---------------------------------------------------------------------------
   --  Wrappers
   --
   --  One per check, so that AUnit reports the checks separately and a failure
   --  names the subsystem rather than the whole suite.
   ---------------------------------------------------------------------------

   procedure Run_Wire_Integers (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Wire_Vectors (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Wire_Sticky_Failure (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Wire_Byte_Boundaries (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Wire_Emitter_Backpatch (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Key_Schedule_Vectors (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Key_Schedule_Stages (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Key_Schedule_Distinct (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Key_Update_Advance (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Exporter_Context (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Resumption_Nonce (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Transcript_Snapshot (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Transcript_Hello_Retry (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Record_Header_Codec (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Record_Nonce (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Record_Round_Trip (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Record_Padding (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Record_Tag_Tamper (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Record_Header_Tamper (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Record_Sequence (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Record_No_Plaintext (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Record_Inner_All_Zero (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Secret_Wipe (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Secret_Equality (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Queue_Backpressure (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Queue_Partial_Append (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Wire_Integers (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Wire_Integers, "wire integers");
   end Run_Wire_Integers;

   procedure Run_Wire_Vectors (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Wire_Vectors, "wire vectors");
   end Run_Wire_Vectors;

   procedure Run_Wire_Sticky_Failure (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Wire_Sticky_Failure, "wire sticky failure");
   end Run_Wire_Sticky_Failure;

   procedure Run_Wire_Byte_Boundaries (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Wire_Byte_Boundaries, "wire byte boundaries");
   end Run_Wire_Byte_Boundaries;

   procedure Run_Wire_Emitter_Backpatch (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Wire_Emitter_Backpatch, "wire emitter backpatch");
   end Run_Wire_Emitter_Backpatch;

   procedure Run_Key_Schedule_Vectors (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Key_Schedule_Vectors, "key schedule against RFC 8448");
   end Run_Key_Schedule_Vectors;

   procedure Run_Key_Schedule_Stages (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Key_Schedule_Stages, "key schedule stages");
   end Run_Key_Schedule_Stages;

   procedure Run_Key_Schedule_Distinct (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Key_Schedule_Distinct, "key schedule distinctness");
   end Run_Key_Schedule_Distinct;

   procedure Run_Key_Update_Advance (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Key_Update_Advance, "key update advance");
   end Run_Key_Update_Advance;

   procedure Run_Exporter_Context (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Exporter_Context_Distinction, "exporter context distinction");
   end Run_Exporter_Context;

   procedure Run_Resumption_Nonce (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Resumption_Nonce_Distinction, "resumption nonce distinction");
   end Run_Resumption_Nonce;

   procedure Run_Transcript_Snapshot (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Transcript_Snapshot, "transcript snapshot");
   end Run_Transcript_Snapshot;

   procedure Run_Transcript_Hello_Retry (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Transcript_Hello_Retry, "hello-retry transcript transform");
   end Run_Transcript_Hello_Retry;

   procedure Run_Record_Header_Codec (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Record_Header_Codec, "record header codec");
   end Run_Record_Header_Codec;

   procedure Run_Record_Nonce (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Record_Nonce, "record nonce construction");
   end Run_Record_Nonce;

   procedure Run_Record_Round_Trip (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Record_Round_Trip, "record round trip");
   end Run_Record_Round_Trip;

   procedure Run_Record_Padding (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Record_Padding_Removed, "record padding removal");
   end Run_Record_Padding;

   procedure Run_Record_Tag_Tamper (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Record_Tag_Tamper, "record bit-flip rejection");
   end Run_Record_Tag_Tamper;

   procedure Run_Record_Header_Tamper (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Record_Header_Tamper, "record header is authenticated");
   end Run_Record_Header_Tamper;

   procedure Run_Record_Sequence (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Record_Sequence_Advance, "record sequence advance");
   end Run_Record_Sequence;

   procedure Run_Record_No_Plaintext (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Record_No_Plaintext_On_Failure,
         "no plaintext exposed on authentication failure");
   end Run_Record_No_Plaintext;

   procedure Run_Record_Inner_All_Zero (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Record_Inner_Type_All_Zero, "all-zero inner plaintext refused");
   end Run_Record_Inner_All_Zero;

   procedure Run_Secret_Wipe (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Secret_Wipe, "secret wipe");
   end Run_Secret_Wipe;

   procedure Run_Secret_Equality (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Secret_Constant_Time_Equality, "secret constant-time equality");
   end Run_Secret_Equality;

   procedure Run_Queue_Backpressure (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Queue_Backpressure, "queue backpressure");
   end Run_Queue_Backpressure;

   procedure Run_Queue_Partial_Append (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Queue_Partial_Append, "queue partial append");
   end Run_Queue_Partial_Append;

   ---------------------
   -- Register_Tests --
   ---------------------

   overriding procedure Register_Tests (T : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Run_Wire_Integers'Access, "wire: big-endian integers");
      Register_Routine (T, Run_Wire_Vectors'Access, "wire: length-prefixed vectors");
      Register_Routine (T, Run_Wire_Sticky_Failure'Access, "wire: sticky failure flag");
      Register_Routine (T, Run_Wire_Byte_Boundaries'Access, "wire: every truncation refused");
      Register_Routine (T, Run_Wire_Emitter_Backpatch'Access, "wire: deferred length prefixes");

      Register_Routine (T, Run_Key_Schedule_Vectors'Access, "key schedule: RFC 8448 section 3");
      Register_Routine (T, Run_Key_Schedule_Stages'Access, "key schedule: stage ordering");
      Register_Routine (T, Run_Key_Schedule_Distinct'Access, "key schedule: products differ");
      Register_Routine (T, Run_Key_Update_Advance'Access, "key schedule: KeyUpdate advance");
      Register_Routine (T, Run_Exporter_Context'Access, "exporters: label and context binding");
      Register_Routine (T, Run_Resumption_Nonce'Access, "tickets: per-nonce PSK separation");

      Register_Routine (T, Run_Transcript_Snapshot'Access, "transcript: non-finalizing snapshot");
      Register_Routine (T, Run_Transcript_Hello_Retry'Access, "transcript: message_hash transform");

      Register_Routine (T, Run_Record_Header_Codec'Access, "records: explicit header codec");
      Register_Routine (T, Run_Record_Nonce'Access, "records: nonce per RFC 8446 5.3");
      Register_Routine (T, Run_Record_Round_Trip'Access, "records: protect and open");
      Register_Routine (T, Run_Record_Padding'Access, "records: padding removed after auth");
      Register_Routine (T, Run_Record_Tag_Tamper'Access, "records: every bit flip refused");
      Register_Routine (T, Run_Record_Header_Tamper'Access, "records: header is associated data");
      Register_Routine (T, Run_Record_Sequence'Access, "records: sequence and nonce uniqueness");
      Register_Routine (T, Run_Record_No_Plaintext'Access, "records: no unauthenticated plaintext");
      Register_Routine (T, Run_Record_Inner_All_Zero'Access, "records: missing inner type refused");

      Register_Routine (T, Run_Secret_Wipe'Access, "secrets: wipe and overwrite");
      Register_Routine (T, Run_Secret_Equality'Access, "secrets: constant-time equality");

      Register_Routine (T, Run_Queue_Backpressure'Access, "buffers: bounded backpressure");
      Register_Routine (T, Run_Queue_Partial_Append'Access, "buffers: partial append");
   end Register_Tests;

end Tests_Internals;
