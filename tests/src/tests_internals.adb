
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
   procedure Run_Extension_Registry (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Extension_Contexts (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Extension_Block (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Handshake_Framing (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Client_Hello (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Client_Hello_Refusals (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Client_Hello_Truncation (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Server_Hello (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Key_Agreement_Groups (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Client_Hello_Encoding (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Certificate_Verify_Content (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Server_Hello_Encoding (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Encrypted_Extensions (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Certificate_Codec (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Certificate_Request (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Small_Messages (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_PSK_Offer (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Handshake (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Engine (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Pipes (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Truncation (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Post_Handshake (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Tickets (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Resumption (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_TLS12 (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Negotiation (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Mutation (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Limits (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Concurrency (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Reentrancy (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Splitting (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Validation_Pipeline (T : in out AUnit.Test_Cases.Test_Case'Class);
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

   procedure Run_PSS_Verification (T : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_PSS_Verification (T : in out AUnit.Test_Cases.Test_Case'Class)
   is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_PSS_Signature_Verification, "pss verification");
   end Run_PSS_Verification;

   procedure Run_Secret_Equality (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Secret_Constant_Time_Equality, "secret constant-time equality");
   end Run_Secret_Equality;

   procedure Run_Extension_Registry (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Extension_Registry, "extension registry");
   end Run_Extension_Registry;

   procedure Run_Extension_Contexts (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Extension_Contexts, "extension contexts");
   end Run_Extension_Contexts;

   procedure Run_Extension_Block (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Extension_Block_Parsing, "extension block");
   end Run_Extension_Block;

   procedure Run_Handshake_Framing (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Handshake_Framing, "handshake framing");
   end Run_Handshake_Framing;

   procedure Run_Client_Hello (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Client_Hello_Round_Trip, "client hello parse");
   end Run_Client_Hello;

   procedure Run_Client_Hello_Refusals (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Client_Hello_Refusals, "client hello refusals");
   end Run_Client_Hello_Refusals;

   procedure Run_Client_Hello_Truncation (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Client_Hello_Truncation, "client hello truncation");
   end Run_Client_Hello_Truncation;

   procedure Run_Server_Hello (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Server_Hello_And_Retry, "server hello and retry");
   end Run_Server_Hello;

   procedure Run_Key_Agreement_Groups (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Key_Agreement_Groups, "key agreement groups");
   end Run_Key_Agreement_Groups;

   procedure Run_Client_Hello_Encoding (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Client_Hello_Encoding, "client hello encoding");
   end Run_Client_Hello_Encoding;

   procedure Run_Certificate_Verify_Content (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Certificate_Verify_Content, "certificate verify content");
   end Run_Certificate_Verify_Content;

   procedure Run_Server_Hello_Encoding (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Server_Hello_Encoding, "server hello encoding");
   end Run_Server_Hello_Encoding;

   procedure Run_Encrypted_Extensions (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Encrypted_Extensions_Codec, "encrypted extensions");
   end Run_Encrypted_Extensions;

   procedure Run_Certificate_Codec (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Certificate_Codec, "certificate codec");
   end Run_Certificate_Codec;

   procedure Run_Certificate_Request (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok
        (Internals.Check_Certificate_Request_Codec, "certificate request codec");
   end Run_Certificate_Request;

   procedure Run_Small_Messages (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Small_Message_Codecs, "small message codecs");
   end Run_Small_Messages;

   procedure Run_PSK_Offer (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_PSK_Offer_Parsing, "psk offer parsing");
   end Run_PSK_Offer;

   procedure Run_Handshake (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Handshake_End_To_End, "handshake end to end");
   end Run_Handshake;

   procedure Run_Engine (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Engine_Round_Trip, "engine round trip");
   end Run_Engine;

   procedure Run_Pipes (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Connection_Over_Pipes, "connection over pipes");
   end Run_Pipes;

   procedure Run_Truncation (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Truncation_Detected, "truncation detected");
   end Run_Truncation;

   procedure Run_Post_Handshake (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Post_Handshake, "post handshake");
   end Run_Post_Handshake;

   procedure Run_Tickets (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Ticket_Issue, "ticket issue");
   end Run_Tickets;

   procedure Run_Resumption (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Resumption, "resumption");
   end Run_Resumption;

   procedure Run_TLS12 (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_TLS12_Handshake, "tls 1.2 handshake");
      Tests_Support.Expect_Ok (Internals.Check_TLS12_Resumption, "tls 1.2 resumption");
      Tests_Support.Expect_Ok
        (Internals.Check_TLS12_Connection_Resumption, "tls 1.2 resumption over a transport");
   end Run_TLS12;

   procedure Run_Negotiation (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Version_Negotiation, "version negotiation");
   end Run_Negotiation;

   procedure Run_Mutation (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Mutated_Messages, "mutated messages");
   end Run_Mutation;

   procedure Run_Limits (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Limit_Boundaries, "limit boundaries");
   end Run_Limits;

   procedure Run_Concurrency (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Cache_Concurrency, "cache concurrency");
      Tests_Support.Expect_Ok (Internals.Check_Synchronized, "one connection, three tasks");
      Tests_Support.Expect_Ok
        (Internals.Check_Secret_Hygiene, "secrets wiped, diagnostics clean");
      Tests_Support.Expect_Ok (Internals.Check_Mutual_TLS, "mutual TLS");
      Tests_Support.Expect_Ok
        (Internals.Check_Trust_Store_Sizing, "a trust store costs what it holds");
      Tests_Support.Expect_Ok
        (Internals.Check_Small_Stack_Loading, "loading on a worker-sized stack");
   end Run_Concurrency;

   procedure Run_Reentrancy (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Callback_Reentrancy, "callback reentrancy");
   end Run_Reentrancy;

   procedure Run_Splitting (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Byte_At_A_Time, "byte at a time");
   end Run_Splitting;

   procedure Run_Validation_Pipeline (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
   begin
      Tests_Support.Expect_Ok (Internals.Check_Validation_Pipeline, "validation pipeline");
   end Run_Validation_Pipeline;

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
      Register_Routine (T, Run_PSS_Verification'Access,
                        "crypto: RSASSA-PSS verification");
      Register_Routine (T, Run_Secret_Equality'Access, "secrets: constant-time equality");

      Register_Routine (T, Run_Extension_Registry'Access, "extensions: identifiers");
      Register_Routine (T, Run_Extension_Contexts'Access, "extensions: RFC 8446 4.2 contexts");
      Register_Routine (T, Run_Extension_Block'Access, "extensions: duplicates and contexts");
      Register_Routine (T, Run_Handshake_Framing'Access, "handshake: message framing");
      Register_Routine (T, Run_Client_Hello'Access, "handshake: ClientHello parse");
      Register_Routine (T, Run_Client_Hello_Refusals'Access, "handshake: ClientHello refusals");
      Register_Routine (T, Run_Client_Hello_Truncation'Access,
                        "handshake: ClientHello truncated at every length");
      Register_Routine (T, Run_Server_Hello'Access, "handshake: ServerHello and HelloRetry");
      Register_Routine (T, Run_Key_Agreement_Groups'Access,
                        "agreement: every offered group, both directions");
      Register_Routine (T, Run_Client_Hello_Encoding'Access,
                        "handshake: ClientHello encode then parse back");
      Register_Routine (T, Run_Certificate_Verify_Content'Access,
                        "handshake: CertificateVerify content per RFC 8446 4.4.3");
      Register_Routine (T, Run_Server_Hello_Encoding'Access,
                        "handshake: ServerHello and retry encode then parse back");
      Register_Routine (T, Run_Encrypted_Extensions'Access,
                        "handshake: EncryptedExtensions round trip and refusals");
      Register_Routine (T, Run_Certificate_Codec'Access,
                        "handshake: Certificate round trip, staples and bounds");
      Register_Routine (T, Run_Certificate_Request'Access,
                        "handshake: CertificateRequest round trip and refusals");
      Register_Routine (T, Run_Small_Messages'Access,
                        "handshake: CertificateVerify, Finished, KeyUpdate, tickets");
      Register_Routine (T, Run_PSK_Offer'Access,
                        "handshake: pre_shared_key offer and the last-extension rule");
      Register_Routine (T, Run_Handshake'Access,
                        "handshake: TLS 1.3 client against TLS 1.3 server, end to end");
      Register_Routine (T, Run_Engine'Access,
                        "engines: two engines, handshake, data both ways, shutdown");
      Register_Routine (T, Run_Pipes'Access,
                        "connections: handshake and bulk data over partial I/O");
      Register_Routine (T, Run_Truncation'Access,
                        "connections: a stream ending without close_notify");
      Register_Routine (T, Run_Post_Handshake'Access,
                        "post-handshake: exporters, channel bindings, KeyUpdate");
      Register_Routine (T, Run_Tickets'Access,
                        "sessions: key ring states, ticket issue, cache bindings");
      Register_Routine (T, Run_Resumption'Access,
                        "sessions: a second connection resumes from the first one's ticket");
      Register_Routine (T, Run_TLS12'Access,
                        "handshake: restricted TLS 1.2, tickets, and resumption");
      Register_Routine (T, Run_Negotiation'Access,
                        "connections: a TLS 1.2-only client negotiates down");
      Register_Routine (T, Run_Mutation'Access,
                        "mutation: every damaged message answers rather than raises");
      Register_Routine (T, Run_Limits'Access,
                        "limits: each bound at limit-1, limit and limit+1");
      Register_Routine (T, Run_Concurrency'Access,
                        "concurrency: a shared cache, three tasks on one connection, "
                        & "and secret hygiene");
      Register_Routine (T, Run_Reentrancy'Access,
                        "callbacks: a sink that calls back into the library");
      Register_Routine (T, Run_Splitting'Access,
                        "records: one octet at a time, and several per supply");
      Register_Routine (T, Run_Validation_Pipeline'Access,
                        "certificates: the pipeline end to end");
      Register_Routine (T, Run_Queue_Backpressure'Access, "buffers: bounded backpressure");
      Register_Routine (T, Run_Queue_Partial_Append'Access, "buffers: partial append");
   end Register_Tests;

end Tests_Internals;
