with Ada.Streams;
with Interfaces;

with SSL.Buffers;
with SSL.Cipher_Suites;
with SSL.Crypto;
with SSL.Errors;
with SSL.Extensions;
with SSL.Handshake_Messages;
with SSL.Limits;
with SSL.ALPN;
with SSL.Authentication;
with SSL.Server_Names;
with SSL.Key_Schedule;
with SSL.Records;
with SSL.Secrets;
with SSL.Signature_Schemes;
with SSL.Supported_Groups;
with SSL.Certificate_Validation;
with SSL.Clocks;
with SSL.Configurations;
with SSL.Credentials;
with SSL.Trust;
with SSL.Transcripts;
with SSL.Versions;
with SSL.Wire;
with SSL.Channel_Bindings;
with SSL.Clients;
with SSL.Connection_Metadata;
with SSL.Connections;
with SSL.Servers;
with SSL.Sessions;
with SSL.Sessions.Client_Caches;
with SSL.Sessions.Client_Caches.Memory;
with SSL.Ticket_Keys;
with SSL.Diagnostics;
with SSL.Engines;
with SSL.Exporters;
with SSL.Synchronized_Connections;
with SSL.TLS12;
with SSL.TLS12.Messages;
with SSL.TLS12.Client;
with SSL.TLS12.Records;
with SSL.TLS12.Server;
with SSL.TLS13;
with SSL.TLS13.Client;
with SSL.TLS13.Server;

with Tests_Fixtures;
with Tests_Mutation;
with Tests_Support;
with Tests_Pipes;

package body SSL.Internal_Tests is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;
   use type SSL.Cipher_Suites.Hash_Algorithm;
   use type SSL.Errors.Error_Code;
   use type SSL.Key_Schedule.Stage;
   use type SSL.Records.Content_Type;
   use type SSL.Versions.Version_Value;
   use type SSL.Credentials.Key_Kind;
   use type SSL.Extensions.Extension_Kind;
   use type SSL.Extensions.Extension_Value;
   use type SSL.Extensions.Message_Context;
   use type SSL.Handshake_Messages.Message_Type;
   use type SSL.Supported_Groups.Named_Group;
   use type SSL.Cipher_Suites.Cipher_Suite;
   use type SSL.Signature_Schemes.Signature_Scheme;
   use type SSL.Signature_Schemes.Scheme_Value;
   use type SSL.Handshake_Messages.Key_Update_Request;

   ---------------------------------------------------------------------------
   --  Helpers
   ---------------------------------------------------------------------------

   Hex_Digits : constant String := "0123456789abcdef";

   function Hex (Data : Byte_Array) return String;
   function From_Hex (Text : String) return Byte_Array;
   function Report (Label : String; Expected : String; Actual : String) return String;

   ---------
   -- Hex --
   ---------

   function Hex (Data : Byte_Array) return String is
      Result : String (1 .. 2 * Natural (Data'Length));
      Cursor : Positive := 1;
   begin
      for Index in Data'Range loop
         declare
            Value : constant Natural := Natural (Data (Index));
         begin
            Result (Cursor) := Hex_Digits (1 + Value / 16);
            Result (Cursor + 1) := Hex_Digits (1 + Value mod 16);
         end;
         Cursor := Cursor + 2;
      end loop;
      return Result;
   end Hex;

   --------------
   -- From_Hex --
   --------------

   function From_Hex (Text : String) return Byte_Array is
      Result : Byte_Array (1 .. Byte_Index (Text'Length / 2));
      Cursor : Natural := Text'First;

      function Digit_Value (Item : Character) return Natural
      is (if Item in '0' .. '9' then Character'Pos (Item) - Character'Pos ('0')
          elsif Item in 'a' .. 'f' then 10 + Character'Pos (Item) - Character'Pos ('a')
          else 10 + Character'Pos (Item) - Character'Pos ('A'));

   begin
      for Index in Result'Range loop
         Result (Index) :=
           Byte (16 * Digit_Value (Text (Cursor)) + Digit_Value (Text (Cursor + 1)));
         Cursor := Cursor + 2;
      end loop;
      return Result;
   end From_Hex;

   ------------
   -- Report --
   ------------

   function Report (Label : String; Expected : String; Actual : String) return String is
   begin
      return Label & ": expected " & Expected & ", got " & Actual;
   end Report;

   ---------------------------------------------------------------------------
   --  Wire codecs
   ---------------------------------------------------------------------------

   ---------------------------
   -- Check_Wire_Integers --
   ---------------------------

   function Check_Wire_Integers return String is
      Data : constant Byte_Array :=
        From_Hex ("01" & "0203" & "040506" & "0708090a" & "0b0c0d0e0f101112");
      Cursor : SSL.Wire.Cursor := SSL.Wire.Reader (Data);
      V8  : Natural;
      V16 : Natural;
      V24 : Byte_Index;
      V32 : Interfaces.Unsigned_32;
      V64 : Interfaces.Unsigned_64;
   begin
      SSL.Wire.Get_UInt8 (Data, Cursor, V8);
      if V8 /= 1 then
         return Report ("uint8", "1", V8'Image);
      end if;

      SSL.Wire.Get_UInt16 (Data, Cursor, V16);
      if V16 /= 16#0203# then
         return Report ("uint16", "515", V16'Image);
      end if;

      SSL.Wire.Get_UInt24 (Data, Cursor, V24);
      if V24 /= 16#040506# then
         return Report ("uint24", "263430", V24'Image);
      end if;

      SSL.Wire.Get_UInt32 (Data, Cursor, V32);
      if V32 /= 16#0708090A# then
         return Report ("uint32", "0708090a", Hex (From_Hex ("0708090a")));
      end if;

      SSL.Wire.Get_UInt64 (Data, Cursor, V64);
      if V64 /= 16#0B0C0D0E0F101112# then
         return "uint64 mismatch";
      end if;

      if not SSL.Wire.At_End (Cursor) then
         return "cursor not at end after reading every field";
      end if;

      --  One octet past the end must fail rather than raise.
      SSL.Wire.Get_UInt8 (Data, Cursor, V8);
      if SSL.Wire.Is_Valid (Cursor) then
         return "reading past the end left the cursor valid";
      end if;
      if V8 /= 0 then
         return "a failed read yielded a nonzero value";
      end if;

      return "";
   end Check_Wire_Integers;

   --------------------------
   -- Check_Wire_Vectors --
   --------------------------

   function Check_Wire_Vectors return String is
      --  A two-octet-prefixed vector holding 0xaabb, followed by one more octet.
      Data : constant Byte_Array := From_Hex ("0002aabbcc");
      Cursor : SSL.Wire.Cursor := SSL.Wire.Reader (Data);
      Body_Cursor : SSL.Wire.Cursor;
      Value : Natural;
   begin
      SSL.Wire.Open_Vector_16 (Data, Cursor, Limit => 16, Body_Cursor => Body_Cursor);
      if not SSL.Wire.Is_Valid (Body_Cursor) then
         return "a well-formed vector was refused";
      end if;
      if SSL.Wire.Remaining (Body_Cursor) /= 2 then
         return Report ("vector body length", "2", SSL.Wire.Remaining (Body_Cursor)'Image);
      end if;

      SSL.Wire.Get_UInt16 (Data, Body_Cursor, Value);
      if Value /= 16#AABB# then
         return "vector body content mismatch";
      end if;
      if not SSL.Wire.At_End (Body_Cursor) then
         return "vector body cursor should be exhausted";
      end if;

      --  The outer cursor must have advanced past the whole vector and be
      --  positioned on the trailing octet.
      SSL.Wire.Get_UInt8 (Data, Cursor, Value);
      if Value /= 16#CC# then
         return "outer cursor did not skip the vector body exactly";
      end if;

      --  A declared length above the caller's bound must be refused on the
      --  number alone, before any body octet is touched.
      declare
         Second : SSL.Wire.Cursor := SSL.Wire.Reader (Data);
         Sub    : SSL.Wire.Cursor;
      begin
         SSL.Wire.Open_Vector_16 (Data, Second, Limit => 1, Body_Cursor => Sub);
         if SSL.Wire.Is_Valid (Second) then
            return "an over-long vector was accepted";
         end if;
      end;

      --  A declared length longer than the octets actually present must fail,
      --  not read past the end.
      declare
         Short  : constant Byte_Array := From_Hex ("0004aabb");
         Third  : SSL.Wire.Cursor := SSL.Wire.Reader (Short);
         Sub    : SSL.Wire.Cursor;
      begin
         SSL.Wire.Open_Vector_16 (Short, Third, Limit => 64, Body_Cursor => Sub);
         if SSL.Wire.Is_Valid (Third) then
            return "a truncated vector was accepted";
         end if;
      end;

      return "";
   end Check_Wire_Vectors;

   ---------------------------------
   -- Check_Wire_Sticky_Failure --
   ---------------------------------

   function Check_Wire_Sticky_Failure return String is
      Data   : constant Byte_Array := From_Hex ("aa");
      Cursor : SSL.Wire.Cursor := SSL.Wire.Reader (Data);
      V16    : Natural;
      V8     : Natural;
   begin
      --  Two octets from a one-octet buffer: fails.
      SSL.Wire.Get_UInt16 (Data, Cursor, V16);
      if SSL.Wire.Is_Valid (Cursor) then
         return "a short read left the cursor valid";
      end if;

      --  A subsequent read that would have succeeded must not: the flag is
      --  sticky, so a parser can check once at the end.
      SSL.Wire.Get_UInt8 (Data, Cursor, V8);
      if V8 /= 0 then
         return "a read after failure produced a value";
      end if;
      if SSL.Wire.Remaining (Cursor) /= 0 then
         return "a failed cursor reported octets remaining";
      end if;

      return "";
   end Check_Wire_Sticky_Failure;

   ----------------------------------
   -- Check_Wire_Byte_Boundaries --
   ----------------------------------

   function Check_Wire_Byte_Boundaries return String is
      --  A representative nested structure: a 16-bit vector containing two
      --  8-bit vectors. Truncated at every length from zero to one short of
      --  complete, every parse must fail cleanly rather than raise or succeed.
      Full : constant Byte_Array := From_Hex ("0006" & "02" & "1122" & "02" & "3344");
   begin
      for Cut in 0 .. Natural (Full'Length) - 1 loop
         declare
            Partial : constant Byte_Array := Full (1 .. Byte_Index (Cut));
            Cursor  : SSL.Wire.Cursor := SSL.Wire.Reader (Partial);
            Outer   : SSL.Wire.Cursor;
            Inner   : SSL.Wire.Cursor;
            Value   : Natural;
         begin
            SSL.Wire.Open_Vector_16 (Partial, Cursor, 64, Outer);
            if SSL.Wire.Is_Valid (Cursor) then
               return "a truncated structure parsed as complete at cut" & Cut'Image;
            end if;

            --  Continuing to parse a failed structure must stay bounded and
            --  produce nothing.
            SSL.Wire.Open_Vector_8 (Partial, Outer, 64, Inner);
            SSL.Wire.Get_UInt8 (Partial, Inner, Value);
            if Value /= 0 then
               return "a truncated structure yielded a value at cut" & Cut'Image;
            end if;
         end;
      end loop;

      --  The complete structure must parse, so the loop above was testing
      --  something.
      declare
         Cursor : SSL.Wire.Cursor := SSL.Wire.Reader (Full);
         Outer  : SSL.Wire.Cursor;
         First  : SSL.Wire.Cursor;
         Second : SSL.Wire.Cursor;
         Value  : Natural;
      begin
         SSL.Wire.Open_Vector_16 (Full, Cursor, 64, Outer);
         SSL.Wire.Open_Vector_8 (Full, Outer, 64, First);
         SSL.Wire.Get_UInt16 (Full, First, Value);
         if Value /= 16#1122# then
            return "complete structure: first inner vector mismatch";
         end if;
         SSL.Wire.Open_Vector_8 (Full, Outer, 64, Second);
         SSL.Wire.Get_UInt16 (Full, Second, Value);
         if Value /= 16#3344# then
            return "complete structure: second inner vector mismatch";
         end if;
         if not SSL.Wire.At_End (Outer) or else not SSL.Wire.Is_Valid (Cursor) then
            return "complete structure did not consume exactly";
         end if;
      end;

      return "";
   end Check_Wire_Byte_Boundaries;

   -------------------------------------
   -- Check_Wire_Emitter_Backpatch --
   -------------------------------------

   function Check_Wire_Emitter_Backpatch return String is
      Buffer  : Byte_Array (1 .. 32) := [others => 0];
      Emitter : SSL.Wire.Emitter := SSL.Wire.Writer (Buffer);
      Outer   : Byte_Index;
      Inner   : Byte_Index;
   begin
      SSL.Wire.Open_Vector_16 (Buffer, Emitter, Outer);
      SSL.Wire.Open_Vector_8 (Buffer, Emitter, Inner);
      SSL.Wire.Put_UInt16 (Buffer, Emitter, 16#1122#);
      SSL.Wire.Close_Vector_8 (Buffer, Emitter, Inner);
      SSL.Wire.Put_UInt8 (Buffer, Emitter, 16#FF#);
      SSL.Wire.Close_Vector_16 (Buffer, Emitter, Outer);

      if not SSL.Wire.Is_Valid (Emitter) then
         return "emitter failed on a structure that fits";
      end if;

      declare
         Written  : constant Byte_Index := SSL.Wire.Written (Emitter);
         Expected : constant Byte_Array := From_Hex ("0004" & "02" & "1122" & "ff");
      begin
         if Written /= Expected'Length then
            return Report ("emitted length", Expected'Length'Image, Written'Image);
         end if;
         if Buffer (1 .. Written) /= Expected then
            return Report ("emitted octets", Hex (Expected), Hex (Buffer (1 .. Written)));
         end if;
      end;

      --  An emitter with no room must fail rather than overrun.
      declare
         Tight   : Byte_Array (1 .. 2) := [others => 0];
         Cramped : SSL.Wire.Emitter := SSL.Wire.Writer (Tight);
      begin
         SSL.Wire.Put_UInt32 (Tight, Cramped, 1);
         if SSL.Wire.Is_Valid (Cramped) then
            return "an emitter accepted more than it had room for";
         end if;
      end;

      return "";
   end Check_Wire_Emitter_Backpatch;

   ---------------------------------------------------------------------------
   --  Key schedule
   ---------------------------------------------------------------------------

   --  RFC 8448 section 3, "Simple 1-RTT Handshake", TLS_AES_128_GCM_SHA256.
   --
   --  Source: RFC 8448 (IETF Trust, BSD-style Simplified licence for code
   --  components). Every value below is quoted from that document and was
   --  independently recomputed from the RFC 8446 section 7.1 definitions with a
   --  separate HKDF implementation before being written here; the two agreed.
   Vector_Shared_Secret : constant String :=
     "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";
   Vector_Hello_Hash : constant String :=
     "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";
   Vector_Client_Handshake_Traffic : constant String :=
     "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
   Vector_Server_Handshake_Traffic : constant String :=
     "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
   Vector_Client_Handshake_Key : constant String := "dbfaa693d1762c5b666af5d950258d01";
   Vector_Client_Handshake_IV  : constant String := "5bd3c71b836e0b76bb73265f";
   Vector_Server_Handshake_Key : constant String := "3fce516009c21727d0f2e4e86ee403bc";
   Vector_Server_Handshake_IV  : constant String := "5d313eb2671276ee13000b30";

   --------------------------------
   -- Check_Key_Schedule_Vectors --
   --------------------------------

   function Check_Key_Schedule_Vectors return String is
      use SSL.Key_Schedule;

      Item   : Schedule;
      Error  : SSL.Errors.Error_Information;
      Shared : constant Byte_Array := From_Hex (Vector_Shared_Secret);
      Hello  : constant Byte_Array := From_Hex (Vector_Hello_Hash);

      Key : Byte_Array (1 .. 16);
      IV  : Byte_Array (1 .. 12);
   begin
      Start (Item, SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256);

      Derive_Early_Without_PSK (Item, Error);
      if SSL.Errors.Is_Error (Error) then
         return "early secret: " & SSL.Errors.Image (Error);
      end if;

      Derive_Handshake (Item, Shared, Hello, Error);
      if SSL.Errors.Is_Error (Error) then
         return "handshake secret: " & SSL.Errors.Image (Error);
      end if;

      --  The handshake traffic secrets are not exposed directly -- by design --
      --  so they are checked through the two things derived from them that are:
      --  the traffic key and IV, and the Finished key. RFC 8448 publishes the
      --  key and IV, so a wrong traffic secret cannot survive this.
      Traffic_Key (Item, Client_Side, Handshake_Epoch, Key, IV, Error);
      if SSL.Errors.Is_Error (Error) then
         return "client handshake key: " & SSL.Errors.Image (Error);
      end if;
      if Hex (Key) /= Vector_Client_Handshake_Key then
         return Report ("client handshake key", Vector_Client_Handshake_Key, Hex (Key));
      end if;
      if Hex (IV) /= Vector_Client_Handshake_IV then
         return Report ("client handshake iv", Vector_Client_Handshake_IV, Hex (IV));
      end if;

      Traffic_Key (Item, Server_Side, Handshake_Epoch, Key, IV, Error);
      if SSL.Errors.Is_Error (Error) then
         return "server handshake key: " & SSL.Errors.Image (Error);
      end if;
      if Hex (Key) /= Vector_Server_Handshake_Key then
         return Report ("server handshake key", Vector_Server_Handshake_Key, Hex (Key));
      end if;
      if Hex (IV) /= Vector_Server_Handshake_IV then
         return Report ("server handshake iv", Vector_Server_Handshake_IV, Hex (IV));
      end if;

      --  Cross-check the traffic secrets themselves by re-deriving the key from
      --  the published secret through the same primitive: if the schedule's
      --  secret matched the RFC's, this must reproduce the same key.
      declare
         Published : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
         Direct    : Byte_Array (1 .. 16) := [others => 0];
         Ignored   : Byte_Array (1 .. 12) := [others => 0];
      begin
         SSL.Secrets.Set (Published, From_Hex (Vector_Client_Handshake_Traffic));
         SSL.Crypto.Expand_Label_Into
           (Algorithm => SSL.Cipher_Suites.SHA_256,
            Secret    => Published,
            Label     => "key",
            Context   => Empty_Bytes,
            Into      => Direct,
            Error     => Error);
         if SSL.Errors.Is_Error (Error) then
            return "cross-check expand: " & SSL.Errors.Image (Error);
         end if;
         if Hex (Direct) /= Vector_Client_Handshake_Key then
            return "the published client handshake traffic secret does not expand to the "
              & "published key; the vector set is inconsistent";
         end if;

         SSL.Secrets.Set (Published, From_Hex (Vector_Server_Handshake_Traffic));
         SSL.Crypto.Expand_Label_Into
           (Algorithm => SSL.Cipher_Suites.SHA_256,
            Secret    => Published,
            Label     => "iv",
            Context   => Empty_Bytes,
            Into      => Ignored,
            Error     => Error);
         if Hex (Ignored) /= Vector_Server_Handshake_IV then
            return "the published server handshake traffic secret does not expand to the "
              & "published iv";
         end if;
      end;

      Wipe (Item);
      return "";
   end Check_Key_Schedule_Vectors;

   -------------------------------
   -- Check_Key_Schedule_Stages --
   -------------------------------

   function Check_Key_Schedule_Stages return String is
      use SSL.Key_Schedule;
      Item  : Schedule;
      Error : SSL.Errors.Error_Information;
   begin
      Start (Item, SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256);
      if Current_Stage (Item) /= Unstarted then
         return "a fresh schedule was not at the unstarted stage";
      end if;

      Derive_Early_Without_PSK (Item, Error);
      if SSL.Errors.Is_Error (Error) or else Current_Stage (Item) /= Early_Stage then
         return "the early stage was not reached";
      end if;
      if Used_PSK (Item) then
         return "a schedule with no PSK reported one";
      end if;

      Derive_Handshake (Item, From_Hex (Vector_Shared_Secret), From_Hex (Vector_Hello_Hash), Error);
      if SSL.Errors.Is_Error (Error) or else Current_Stage (Item) /= Handshake_Stage then
         return "the handshake stage was not reached";
      end if;

      declare
         Server_Hash : constant Byte_Array (1 .. 32) := [others => 16#11#];
         Client_Hash : constant Byte_Array (1 .. 32) := [others => 16#22#];
      begin
         Derive_Master (Item, Server_Hash, Error);
         if not SSL.Errors.Is_Error (Error) then
            Derive_Resumption (Item, Client_Hash, Error);
         end if;
         if SSL.Errors.Is_Error (Error) or else Current_Stage (Item) /= Master_Stage then
            return "the master stage was not reached";
         end if;
      end;

      if Generation (Item, Client_Side) /= 0
        or else Generation (Item, Server_Side) /= 0
      then
         return "generations did not start at zero";
      end if;

      --  A PSK schedule reports that it used one, which is what distinguishes
      --  resumed authentication from fresh authentication in the metadata.
      declare
         Resumed : Schedule;
         PSK     : constant Byte_Array (1 .. 32) := [others => 16#AB#];
      begin
         Start (Resumed, SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256);
         Derive_Early_From_PSK (Resumed, PSK, Error);
         if SSL.Errors.Is_Error (Error) then
            return "a PSK early secret was refused";
         end if;
         if not Used_PSK (Resumed) then
            return "a schedule built on a PSK did not report one";
         end if;
         Wipe (Resumed);
      end;

      Wipe (Item);
      if Current_Stage (Item) /= Unstarted or else Is_Started (Item) then
         return "wiping a schedule did not return it to the unstarted state";
      end if;

      return "";
   end Check_Key_Schedule_Stages;

   ---------------------------------
   -- Check_Key_Schedule_Distinct --
   ---------------------------------

   function Check_Key_Schedule_Distinct return String is
      use SSL.Key_Schedule;
      Item  : Schedule;
      Error : SSL.Errors.Error_Information;

      Client_Key, Server_Key : Byte_Array (1 .. 16) := [others => 0];
      Client_IV, Server_IV   : Byte_Array (1 .. 12) := [others => 0];
      Client_Finished        : Byte_Array (1 .. 32) := [others => 0];
      Server_Finished        : Byte_Array (1 .. 32) := [others => 0];
      Handshake_Key          : Byte_Array (1 .. 16) := [others => 0];
      Handshake_IV           : Byte_Array (1 .. 12) := [others => 0];
   begin
      Start (Item, SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256);
      Derive_Early_Without_PSK (Item, Error);
      Derive_Handshake (Item, From_Hex (Vector_Shared_Secret), From_Hex (Vector_Hello_Hash), Error);

      Traffic_Key (Item, Client_Side, Handshake_Epoch, Handshake_Key, Handshake_IV, Error);
      Finished_Key (Item, Client_Side, Client_Finished, Error);
      Finished_Key (Item, Server_Side, Server_Finished, Error);
      if SSL.Errors.Is_Error (Error) then
         return "finished keys: " & SSL.Errors.Image (Error);
      end if;
      if Client_Finished = Server_Finished then
         return "the two Finished keys are identical";
      end if;

      declare
         Hash_A : constant Byte_Array (1 .. 32) := [others => 16#11#];
         Hash_B : constant Byte_Array (1 .. 32) := [others => 16#22#];
      begin
         Derive_Master (Item, Hash_A, Error);
         if not SSL.Errors.Is_Error (Error) then
            Derive_Resumption (Item, Hash_B, Error);
         end if;
      end;

      Traffic_Key (Item, Client_Side, Application_Epoch, Client_Key, Client_IV, Error);
      Traffic_Key (Item, Server_Side, Application_Epoch, Server_Key, Server_IV, Error);
      if SSL.Errors.Is_Error (Error) then
         return "application keys: " & SSL.Errors.Image (Error);
      end if;

      if Client_Key = Server_Key then
         return "the two application traffic keys are identical";
      end if;
      if Client_IV = Server_IV then
         return "the two application traffic IVs are identical";
      end if;
      if Client_Key = Handshake_Key then
         return "the handshake and application keys for one direction are identical";
      end if;

      Wipe (Item);
      return "";
   end Check_Key_Schedule_Distinct;

   ------------------------------
   -- Check_Key_Update_Advance --
   ------------------------------

   function Check_Key_Update_Advance return String is
      use SSL.Key_Schedule;
      Item   : Schedule;
      Error  : SSL.Errors.Error_Information;
      Before : Byte_Array (1 .. 16) := [others => 0];
      After  : Byte_Array (1 .. 16) := [others => 0];
      IV_One : Byte_Array (1 .. 12) := [others => 0];
      IV_Two : Byte_Array (1 .. 12) := [others => 0];
      Hash_A : constant Byte_Array (1 .. 32) := [others => 16#33#];
      Hash_B : constant Byte_Array (1 .. 32) := [others => 16#44#];
   begin
      Start (Item, SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256);
      Derive_Early_Without_PSK (Item, Error);
      Derive_Handshake (Item, From_Hex (Vector_Shared_Secret), From_Hex (Vector_Hello_Hash), Error);
      Derive_Master (Item, Hash_A, Error);
      if not SSL.Errors.Is_Error (Error) then
         Derive_Resumption (Item, Hash_B, Error);
      end if;

      Traffic_Key (Item, Client_Side, Application_Epoch, Before, IV_One, Error);
      Advance_Traffic_Secret (Item, Client_Side, Error);
      if SSL.Errors.Is_Error (Error) then
         return "advancing the client traffic secret: " & SSL.Errors.Image (Error);
      end if;
      Traffic_Key (Item, Client_Side, Application_Epoch, After, IV_Two, Error);

      if Before = After then
         return "a key update did not change the traffic key";
      end if;
      if IV_One = IV_Two then
         return "a key update did not change the static IV";
      end if;
      if Generation (Item, Client_Side) /= 1 then
         return Report ("client generation", "1", Generation (Item, Client_Side)'Image);
      end if;
      if Generation (Item, Server_Side) /= 0 then
         return "advancing one direction changed the other direction's generation";
      end if;

      Wipe (Item);
      return "";
   end Check_Key_Update_Advance;

   ------------------------------------------
   -- Check_Exporter_Context_Distinction --
   ------------------------------------------

   function Check_Exporter_Context_Distinction return String is
      use SSL.Key_Schedule;
      Item   : Schedule;
      Error  : SSL.Errors.Error_Information;
      Hash_A : constant Byte_Array (1 .. 32) := [others => 16#55#];
      Hash_B : constant Byte_Array (1 .. 32) := [others => 16#66#];

      No_Context    : Byte_Array (1 .. 32) := [others => 0];
      Empty_Context : Byte_Array (1 .. 32) := [others => 0];
      Some_Context  : Byte_Array (1 .. 32) := [others => 0];
      Other_Label   : Byte_Array (1 .. 32) := [others => 0];
      Repeat        : Byte_Array (1 .. 32) := [others => 0];
   begin
      Start (Item, SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256);
      Derive_Early_Without_PSK (Item, Error);
      Derive_Handshake (Item, From_Hex (Vector_Shared_Secret), From_Hex (Vector_Hello_Hash), Error);
      Derive_Master (Item, Hash_A, Error);
      if not SSL.Errors.Is_Error (Error) then
         Derive_Resumption (Item, Hash_B, Error);
      end if;

      Export (Item, "EXPORTER-test", Empty_Bytes, False, No_Context, Error);
      Export (Item, "EXPORTER-test", Empty_Bytes, True, Empty_Context, Error);
      Export (Item, "EXPORTER-test", From_Hex ("00"), True, Some_Context, Error);
      Export (Item, "EXPORTER-other", Empty_Bytes, False, Other_Label, Error);
      Export (Item, "EXPORTER-test", Empty_Bytes, False, Repeat, Error);
      if SSL.Errors.Is_Error (Error) then
         return "exporter: " & SSL.Errors.Image (Error);
      end if;

      --  RFC 8446 section 7.5 hashes the context, and the hash of the empty
      --  string is what an absent context uses too, so those two agree by
      --  construction. What must differ is a present, non-empty context and a
      --  different label.
      if No_Context /= Empty_Context then
         return "an absent context and an empty context gave different output, "
           & "which contradicts RFC 8446 section 7.5";
      end if;
      if No_Context = Some_Context then
         return "a non-empty context gave the same output as no context";
      end if;
      if No_Context = Other_Label then
         return "two different exporter labels gave the same output";
      end if;
      if No_Context /= Repeat then
         return "the exporter is not deterministic";
      end if;

      Wipe (Item);
      return "";
   end Check_Exporter_Context_Distinction;

   -------------------------------------------
   -- Check_Resumption_Nonce_Distinction --
   -------------------------------------------

   function Check_Resumption_Nonce_Distinction return String is
      use SSL.Key_Schedule;
      Item   : Schedule;
      Error  : SSL.Errors.Error_Information;
      Hash_A : constant Byte_Array (1 .. 32) := [others => 16#77#];
      Hash_B : constant Byte_Array (1 .. 32) := [others => 16#88#];
      PSK_One, PSK_Two : Byte_Array (1 .. 32) := [others => 0];
   begin
      Start (Item, SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256);
      Derive_Early_Without_PSK (Item, Error);
      Derive_Handshake (Item, From_Hex (Vector_Shared_Secret), From_Hex (Vector_Hello_Hash), Error);
      Derive_Master (Item, Hash_A, Error);
      if not SSL.Errors.Is_Error (Error) then
         Derive_Resumption (Item, Hash_B, Error);
      end if;

      Resumption_PSK (Item, From_Hex ("0000"), PSK_One, Error);
      Resumption_PSK (Item, From_Hex ("0001"), PSK_Two, Error);
      if SSL.Errors.Is_Error (Error) then
         return "resumption PSK: " & SSL.Errors.Image (Error);
      end if;

      if PSK_One = PSK_Two then
         return "two tickets with different nonces yielded the same PSK";
      end if;

      Wipe (Item);
      return "";
   end Check_Resumption_Nonce_Distinction;

   ---------------------------------------------------------------------------
   --  Transcript
   ---------------------------------------------------------------------------

   -------------------------------
   -- Check_Transcript_Snapshot --
   -------------------------------

   function Check_Transcript_Snapshot return String is
      Item : SSL.Transcripts.Transcript;

      --  A minimal well-formed handshake message: type 1, length 2, body.
      First  : constant Byte_Array := From_Hex ("01000002" & "aabb");
      Second : constant Byte_Array := From_Hex ("02000001" & "cc");
   begin
      SSL.Transcripts.Start (Item);
      SSL.Transcripts.Select_Algorithm (Item, SSL.Cipher_Suites.SHA_256);

      --  An empty transcript hashes to the hash of the empty string, which is
      --  the value RFC 8446 uses as the transcript for the first derivations.
      if Hex (SSL.Transcripts.Hash (Item))
        /= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      then
         return "the empty transcript is not SHA-256 of the empty string";
      end if;

      SSL.Transcripts.Absorb (Item, First);
      declare
         After_First : constant Byte_Array := SSL.Transcripts.Hash (Item);
         Repeat      : constant Byte_Array := SSL.Transcripts.Hash (Item);
      begin
         if After_First /= Repeat then
            return "a snapshot finalized the transcript: the second snapshot differs";
         end if;

         SSL.Transcripts.Absorb (Item, Second);
         if SSL.Transcripts.Hash (Item) = After_First then
            return "absorbing a message did not change the transcript hash";
         end if;

         --  The transcript must be a hash of the concatenated message octets
         --  with no framing of its own.
         if SSL.Transcripts.Hash (Item) /= SSL.Crypto.SHA_256 (First & Second) then
            return "the transcript is not the hash of the concatenated messages";
         end if;
      end;

      if SSL.Transcripts.Absorbed (Item) /= First'Length + Second'Length then
         return "the absorbed octet count is wrong";
      end if;

      --  Selecting the algorithm after absorbing must give the same answer as
      --  selecting it first, which is what running both hashes buys.
      declare
         Late : SSL.Transcripts.Transcript;
      begin
         SSL.Transcripts.Start (Late);
         SSL.Transcripts.Absorb (Late, First);
         SSL.Transcripts.Absorb (Late, Second);
         SSL.Transcripts.Select_Algorithm (Late, SSL.Cipher_Suites.SHA_256);
         if SSL.Transcripts.Hash (Late) /= SSL.Transcripts.Hash (Item) then
            return "selecting the hash late gave a different transcript";
         end if;

         SSL.Transcripts.Select_Algorithm (Late, SSL.Cipher_Suites.SHA_384);
         if SSL.Transcripts.Hash (Late) /= SSL.Crypto.SHA_384 (First & Second) then
            return "the SHA-384 transcript is wrong";
         end if;
      end;

      return "";
   end Check_Transcript_Snapshot;

   ----------------------------------
   -- Check_Transcript_Hello_Retry --
   ----------------------------------

   function Check_Transcript_Hello_Retry return String is
      Item  : SSL.Transcripts.Transcript;
      Hello : constant Byte_Array := From_Hex ("01000004" & "01020304");
      Retry : constant Byte_Array := From_Hex ("02000002" & "0506");
   begin
      SSL.Transcripts.Start (Item);
      SSL.Transcripts.Select_Algorithm (Item, SSL.Cipher_Suites.SHA_256);
      SSL.Transcripts.Absorb (Item, Hello);

      if SSL.Transcripts.Transformed (Item) then
         return "a fresh transcript reported the retry transform as applied";
      end if;

      SSL.Transcripts.Apply_Hello_Retry_Transform (Item);
      if not SSL.Transcripts.Transformed (Item) then
         return "the retry transform was not recorded";
      end if;

      SSL.Transcripts.Absorb (Item, Retry);

      --  RFC 8446 section 4.4.1: the transcript becomes
      --      Hash(message_hash || 00 00 Hash.length || Hash(ClientHello1)
      --           || HelloRetryRequest || ...)
      declare
         Digest   : constant Byte_Array := SSL.Crypto.SHA_256 (Hello);
         Synthetic : constant Byte_Array :=
           From_Hex ("fe000020") & Digest & Retry;
         Expected : constant Byte_Array := SSL.Crypto.SHA_256 (Synthetic);
      begin
         if SSL.Transcripts.Hash (Item) /= Expected then
            return Report ("hello-retry transcript",
                           Hex (Expected),
                           Hex (SSL.Transcripts.Hash (Item)));
         end if;
      end;

      return "";
   end Check_Transcript_Hello_Retry;

   ---------------------------------------------------------------------------
   --  Record layer
   ---------------------------------------------------------------------------

   --------------------------------
   -- Check_Record_Header_Codec --
   --------------------------------

   function Check_Record_Header_Codec return String is
      Item  : SSL.Records.Record_Header;
      Error : SSL.Errors.Error_Information;
   begin
      SSL.Records.Parse_Header (From_Hex ("1703030014"), Item, Error);
      if SSL.Errors.Is_Error (Error) then
         return "a well-formed header was refused: " & SSL.Errors.Image (Error);
      end if;
      if Item.Content /= SSL.Records.Application_Content then
         return "content type mis-parsed";
      end if;
      if Item.Version /= SSL.Versions.Legacy_Record_Value then
         return "version mis-parsed";
      end if;
      if Item.Length /= 20 then
         return Report ("header length", "20", Item.Length'Image);
      end if;

      if SSL.Records.Encode_Header (Item) /= From_Hex ("1703030014") then
         return "encoding a parsed header did not reproduce the octets";
      end if;

      --  An unrecognized content type is refused rather than carried.
      SSL.Records.Parse_Header (From_Hex ("FF03030014"), Item, Error);
      if not SSL.Errors.Is_Error (Error) then
         return "an unknown content type was accepted";
      end if;
      if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_Record_Header_Malformed then
         return "an unknown content type produced the wrong failure code";
      end if;

      --  The maximum expressible length parses; policy limits are a separate
      --  question answered elsewhere.
      SSL.Records.Parse_Header (From_Hex ("1603030000"), Item, Error);
      if SSL.Errors.Is_Error (Error) or else Item.Length /= 0 then
         return "a zero-length handshake record header was mis-handled";
      end if;

      return "";
   end Check_Record_Header_Codec;

   -------------------------
   -- Check_Record_Nonce --
   -------------------------

   function Check_Record_Nonce return String is
      --  RFC 8446 section 5.3, with the client handshake IV from RFC 8448.
      Static : constant Byte_Array := From_Hex (Vector_Client_Handshake_IV);
   begin
      --  Sequence zero leaves the static IV unchanged.
      if SSL.Records.Nonce (Static, 0) /= Static then
         return "sequence zero did not leave the static IV unchanged";
      end if;

      --  Sequence one flips the low octet.
      if Hex (SSL.Records.Nonce (Static, 1)) /= "5bd3c71b836e0b76bb73265e" then
         return Report ("nonce at sequence 1",
                        "5bd3c71b836e0b76bb73265e",
                        Hex (SSL.Records.Nonce (Static, 1)));
      end if;

      --  A sequence number spanning two octets exclusive-ors both.
      if Hex (SSL.Records.Nonce (Static, 16#0102#)) /= "5bd3c71b836e0b76bb73275d" then
         return Report ("nonce at sequence 0x0102",
                        "5bd3c71b836e0b76bb73275d",
                        Hex (SSL.Records.Nonce (Static, 16#0102#)));
      end if;

      --  The sequence number occupies the low eight octets, so the high four
      --  octets of a twelve-octet IV are never touched by it.
      declare
         High : constant Byte_Array := SSL.Records.Nonce (Static, Interfaces.Unsigned_64'Last);
      begin
         if High (1 .. 4) /= Static (1 .. 4) then
            return "the sequence number reached into the IV's high octets";
         end if;
      end;

      return "";
   end Check_Record_Nonce;

   --  A pair of traffic states sharing one key, for round-trip checks: one
   --  protects, the other opens, exactly as two endpoints would.
   procedure Make_Pair
     (Writer : in out SSL.Records.Traffic_State;
      Reader : in out SSL.Records.Traffic_State);

   procedure Make_Pair
     (Writer : in out SSL.Records.Traffic_State;
      Reader : in out SSL.Records.Traffic_State)
   is
      Suite : constant SSL.Cipher_Suites.Cipher_Suite :=
        SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256;
      Key   : constant Byte_Array := From_Hex (Vector_Client_Handshake_Key);
      IV    : constant Byte_Array := From_Hex (Vector_Client_Handshake_IV);
   begin
      SSL.Records.Install (Writer, Suite, Key, IV, 0);
      SSL.Records.Install (Reader, Suite, Key, IV, 0);
   end Make_Pair;

   ------------------------------
   -- Check_Record_Round_Trip --
   ------------------------------

   function Check_Record_Round_Trip return String is
      Writer, Reader : SSL.Records.Traffic_State;
      Buffer  : Byte_Array (1 .. 512) := [others => 0];
      Output  : Byte_Array (1 .. 512) := [others => 0];
      Written : Byte_Index;
      Got     : Byte_Index;
      Inner   : SSL.Records.Content_Type;
      Error   : SSL.Errors.Error_Information;
      Message : constant Byte_Array := From_Hex ("14000020") & From_Hex ("aa") & [1 .. 31 => 16#bb#];
   begin
      Make_Pair (Writer, Reader);

      for Round in 1 .. 3 loop
         SSL.Records.Protect
           (Item      => Writer,
            Inner     => SSL.Records.Handshake_Content,
            Plaintext => Message,
            Padding   => 0,
            Into      => Buffer,
            Written   => Written,
            Error     => Error);
         if SSL.Errors.Is_Error (Error) then
            return "protect failed on round" & Round'Image & ": " & SSL.Errors.Image (Error);
         end if;

         --  The outer header is always application_data with the legacy version,
         --  whatever the inner content type.
         if Buffer (1) /= 23 then
            return "the outer content type was not application_data";
         end if;
         if Buffer (2) /= 16#03# or else Buffer (3) /= 16#03# then
            return "the outer version was not 0x0303";
         end if;

         SSL.Records.Open
           (Item       => Reader,
            Header     => Buffer (1 .. 5),
            Ciphertext => Buffer (6 .. Written),
            Into       => Output,
            Written    => Got,
            Inner      => Inner,
            Error      => Error);
         if SSL.Errors.Is_Error (Error) then
            return "open failed on round" & Round'Image & ": " & SSL.Errors.Image (Error);
         end if;
         if Inner /= SSL.Records.Handshake_Content then
            return "the inner content type was not recovered";
         end if;
         if Got /= Message'Length or else Output (1 .. Got) /= Message then
            return "the plaintext was not recovered";
         end if;
      end loop;

      --  Three records in each direction means three sequence numbers used.
      if SSL.Records.Sequence (Writer) /= 3 or else SSL.Records.Sequence (Reader) /= 3 then
         return "sequence numbers did not track the records processed";
      end if;

      --  An empty record round-trips: RFC 8446 permits a record whose content is
      --  empty, and the inner content type still has to survive.
      SSL.Records.Protect
        (Writer, SSL.Records.Application_Content, Empty_Bytes, 0, Buffer, Written, Error);
      if SSL.Errors.Is_Error (Error) then
         return "protecting an empty record failed";
      end if;
      SSL.Records.Open (Reader, Buffer (1 .. 5), Buffer (6 .. Written), Output, Got, Inner, Error);
      if SSL.Errors.Is_Error (Error) or else Got /= 0
        or else Inner /= SSL.Records.Application_Content
      then
         return "an empty record did not round-trip";
      end if;

      SSL.Records.Wipe (Writer);
      SSL.Records.Wipe (Reader);
      return "";
   end Check_Record_Round_Trip;

   -----------------------------------
   -- Check_Record_Padding_Removed --
   -----------------------------------

   function Check_Record_Padding_Removed return String is
      Writer, Reader : SSL.Records.Traffic_State;
      Buffer  : Byte_Array (1 .. 1024) := [others => 0];
      Output  : Byte_Array (1 .. 1024) := [others => 0];
      Written : Byte_Index;
      Got     : Byte_Index;
      Inner   : SSL.Records.Content_Type;
      Error   : SSL.Errors.Error_Information;
      Message : constant Byte_Array := From_Hex ("48656c6c6f");   --  "Hello"
   begin
      Make_Pair (Writer, Reader);

      for Padding in Byte_Index range 0 .. 64 loop
         SSL.Records.Protect
           (Writer, SSL.Records.Application_Content, Message, Padding,
            Buffer, Written, Error);
         if SSL.Errors.Is_Error (Error) then
            return "protect with padding" & Padding'Image & " failed";
         end if;

         --  Padding is inside the protected plaintext, so it shows up in the
         --  record's length and nowhere else.
         if Written /= 5 + Message'Length + 1 + Padding + 16 then
            return "the padded record length is wrong at padding" & Padding'Image;
         end if;

         SSL.Records.Open
           (Reader, Buffer (1 .. 5), Buffer (6 .. Written), Output, Got, Inner, Error);
         if SSL.Errors.Is_Error (Error) then
            return "open with padding" & Padding'Image & " failed";
         end if;
         if Got /= Message'Length or else Output (1 .. Got) /= Message then
            return "padding was not removed correctly at padding" & Padding'Image;
         end if;
         if Inner /= SSL.Records.Application_Content then
            return "the inner type was lost behind padding";
         end if;
      end loop;

      --  Content ending in a zero octet still works: the scan back for the
      --  inner type stops at the type octet, which is never zero, so a
      --  plaintext of zeroes is not mistaken for padding.
      declare
         Zeroed : constant Byte_Array (1 .. 8) := [others => 0];
      begin
         SSL.Records.Protect
           (Writer, SSL.Records.Application_Content, Zeroed, 4, Buffer, Written, Error);
         SSL.Records.Open
           (Reader, Buffer (1 .. 5), Buffer (6 .. Written), Output, Got, Inner, Error);
         if SSL.Errors.Is_Error (Error) then
            return "an all-zero plaintext with padding failed to open";
         end if;
         if Got /= Zeroed'Length then
            return Report ("all-zero plaintext length", Zeroed'Length'Image, Got'Image);
         end if;
      end;

      SSL.Records.Wipe (Writer);
      SSL.Records.Wipe (Reader);
      return "";
   end Check_Record_Padding_Removed;

   ------------------------------
   -- Check_Record_Tag_Tamper --
   ------------------------------

   function Check_Record_Tag_Tamper return String is
      Writer, Reader : SSL.Records.Traffic_State;
      Buffer  : Byte_Array (1 .. 512) := [others => 0];
      Output  : Byte_Array (1 .. 512) := [others => 0];
      Written : Byte_Index;
      Got     : Byte_Index;
      Inner   : SSL.Records.Content_Type;
      Error   : SSL.Errors.Error_Information;
      Message : constant Byte_Array := From_Hex ("0102030405060708");
   begin
      --  Every single-bit flip anywhere in a protected record must be refused.
      for Position in Byte_Index range 6 .. 40 loop
         declare
            Fresh_Writer, Fresh_Reader : SSL.Records.Traffic_State;
         begin
            Make_Pair (Fresh_Writer, Fresh_Reader);
            SSL.Records.Protect
              (Fresh_Writer, SSL.Records.Application_Content, Message, 0,
               Buffer, Written, Error);
            if SSL.Errors.Is_Error (Error) then
               return "protect failed while preparing a tamper case";
            end if;

            exit when Position > Written;

            Buffer (Position) := Buffer (Position) xor 1;

            SSL.Records.Open
              (Fresh_Reader, Buffer (1 .. 5), Buffer (6 .. Written),
               Output, Got, Inner, Error);

            if not SSL.Errors.Is_Error (Error) then
               return "a flipped bit at octet" & Position'Image & " was accepted";
            end if;
            if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_Record_Authentication_Failed then
               return "a flipped bit produced the wrong failure code at octet"
                 & Position'Image;
            end if;
            if Got /= 0 then
               return "a rejected record produced plaintext";
            end if;
            if Inner /= SSL.Records.Invalid_Content then
               return "a rejected record reported an inner content type";
            end if;

            --  A failed open must not advance the sequence number: doing so
            --  would let a peer desynchronize the two ends by injecting
            --  garbage, and would eventually reuse a nonce.
            if SSL.Records.Sequence (Fresh_Reader) /= 0 then
               return "a failed open advanced the sequence number";
            end if;

            SSL.Records.Wipe (Fresh_Writer);
            SSL.Records.Wipe (Fresh_Reader);
         end;
      end loop;

      SSL.Records.Wipe (Writer);
      SSL.Records.Wipe (Reader);
      return "";
   end Check_Record_Tag_Tamper;

   ---------------------------------
   -- Check_Record_Header_Tamper --
   ---------------------------------

   function Check_Record_Header_Tamper return String is
      Writer, Reader : SSL.Records.Traffic_State;
      Buffer  : Byte_Array (1 .. 512) := [others => 0];
      Output  : Byte_Array (1 .. 512) := [others => 0];
      Written : Byte_Index;
      Got     : Byte_Index;
      Inner   : SSL.Records.Content_Type;
      Error   : SSL.Errors.Error_Information;
      Message : constant Byte_Array := From_Hex ("cafebabe");
   begin
      --  The header is the AEAD's additional data, so changing any of its five
      --  octets must break authentication even though none of the ciphertext
      --  changed. This is the check that catches a header being excluded from
      --  the associated data.
      for Position in Byte_Index range 1 .. 5 loop
         Make_Pair (Writer, Reader);
         SSL.Records.Protect
           (Writer, SSL.Records.Application_Content, Message, 0, Buffer, Written, Error);
         if SSL.Errors.Is_Error (Error) then
            return "protect failed while preparing a header tamper case";
         end if;

         Buffer (Position) := Buffer (Position) xor 1;

         SSL.Records.Open
           (Reader, Buffer (1 .. 5), Buffer (6 .. Written), Output, Got, Inner, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a flipped header octet at position" & Position'Image & " was accepted";
         end if;
         if Got /= 0 then
            return "a record with a tampered header produced plaintext";
         end if;

         SSL.Records.Wipe (Writer);
         SSL.Records.Wipe (Reader);
      end loop;

      return "";
   end Check_Record_Header_Tamper;

   ------------------------------------
   -- Check_Record_Sequence_Advance --
   ------------------------------------

   function Check_Record_Sequence_Advance return String is
      Writer, Reader : SSL.Records.Traffic_State;
      First   : Byte_Array (1 .. 512) := [others => 0];
      Second  : Byte_Array (1 .. 512) := [others => 0];
      Output  : Byte_Array (1 .. 512) := [others => 0];
      Length_One, Length_Two : Byte_Index;
      Got     : Byte_Index;
      Inner   : SSL.Records.Content_Type;
      Error   : SSL.Errors.Error_Information;
      Message : constant Byte_Array := From_Hex ("00112233");
   begin
      Make_Pair (Writer, Reader);

      SSL.Records.Protect
        (Writer, SSL.Records.Application_Content, Message, 0, First, Length_One, Error);
      SSL.Records.Protect
        (Writer, SSL.Records.Application_Content, Message, 0, Second, Length_Two, Error);
      if SSL.Errors.Is_Error (Error) then
         return "protecting two records failed";
      end if;

      --  The same plaintext under the same key must produce different
      --  ciphertext, because the nonce differs. Identical output would mean the
      --  sequence number was not feeding the nonce.
      if First (1 .. Length_One) = Second (1 .. Length_Two) then
         return "two records with the same plaintext produced identical ciphertext";
      end if;

      --  Records must open in order. Presenting the second record first fails,
      --  because its nonce belongs to sequence one and the reader is at zero.
      SSL.Records.Open
        (Reader, Second (1 .. 5), Second (6 .. Length_Two), Output, Got, Inner, Error);
      if not SSL.Errors.Is_Error (Error) then
         return "a record was accepted out of order";
      end if;

      --  And after that failure the reader is still at sequence zero, so the
      --  first record still opens.
      SSL.Records.Open
        (Reader, First (1 .. 5), First (6 .. Length_One), Output, Got, Inner, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the in-order record failed after an out-of-order attempt";
      end if;

      SSL.Records.Wipe (Writer);
      SSL.Records.Wipe (Reader);
      return "";
   end Check_Record_Sequence_Advance;

   --------------------------------------------
   -- Check_Record_No_Plaintext_On_Failure --
   --------------------------------------------

   function Check_Record_No_Plaintext_On_Failure return String is
      Writer, Reader : SSL.Records.Traffic_State;
      Buffer  : Byte_Array (1 .. 512) := [others => 0];
      Output  : Byte_Array (1 .. 512) := [others => 16#5A#];
      Written : Byte_Index;
      Got     : Byte_Index;
      Inner   : SSL.Records.Content_Type;
      Error   : SSL.Errors.Error_Information;

      --  A recognizable plaintext, so that finding any of it in the output
      --  buffer after a rejected open is unambiguous.
      Message : constant Byte_Array (1 .. 32) := [others => 16#A5#];
   begin
      Make_Pair (Writer, Reader);
      SSL.Records.Protect
        (Writer, SSL.Records.Application_Content, Message, 0, Buffer, Written, Error);

      --  Break the tag.
      Buffer (Written) := Buffer (Written) xor 16#FF#;

      SSL.Records.Open
        (Reader, Buffer (1 .. 5), Buffer (6 .. Written), Output, Got, Inner, Error);
      if not SSL.Errors.Is_Error (Error) then
         return "a record with a broken tag was accepted";
      end if;

      --  Not one octet of the plaintext may be visible, and the buffer must have
      --  been cleared rather than left holding whatever it held before.
      for Index in Output'Range loop
         if Output (Index) = 16#A5# then
            return "plaintext octets were exposed after an authentication failure";
         end if;
         if Output (Index) /= 0 then
            return "the output buffer was not cleared on failure";
         end if;
      end loop;

      SSL.Records.Wipe (Writer);
      SSL.Records.Wipe (Reader);
      return "";
   end Check_Record_No_Plaintext_On_Failure;

   ---------------------------------------
   -- Check_Record_Inner_Type_All_Zero --
   ---------------------------------------

   function Check_Record_Inner_Type_All_Zero return String is
      --  A record whose authenticated plaintext is all zeroes has no inner
      --  content type at all. It has to be refused, and refused as an
      --  authentication-class failure so that it is indistinguishable from a
      --  bad tag: RFC 8446 section 5.4.
      Writer, Reader : SSL.Records.Traffic_State;
      Suite   : constant SSL.Cipher_Suites.Cipher_Suite :=
        SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256;
      Key     : constant Byte_Array := From_Hex (Vector_Client_Handshake_Key);
      IV      : constant Byte_Array := From_Hex (Vector_Client_Handshake_IV);
      Header  : constant Byte_Array := From_Hex ("1703030024");
      Zeroes  : constant Byte_Array (1 .. 20) := [others => 0];
      Sealed  : Byte_Array (1 .. 36) := [others => 0];
      Output  : Byte_Array (1 .. 64) := [others => 0];
      Got     : Byte_Index;
      Inner   : SSL.Records.Content_Type;
      Error   : SSL.Errors.Error_Information;
      Secret_Key : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
   begin
      SSL.Records.Install (Writer, Suite, Key, IV, 0);
      SSL.Records.Install (Reader, Suite, Key, IV, 0);

      --  Seal an all-zero inner plaintext directly, bypassing Protect, which
      --  would always append a valid inner type. This is the record a malicious
      --  peer with the key would send.
      SSL.Secrets.Set (Secret_Key, Key);
      SSL.Crypto.Seal
        (Algorithm  => SSL.Cipher_Suites.AES_128_GCM,
         Key        => Secret_Key,
         Nonce      => SSL.Records.Nonce (IV, 0),
         Additional => Header,
         Plaintext  => Zeroes,
         Wire       => Sealed,
         Error      => Error);
      if SSL.Errors.Is_Error (Error) then
         return "sealing the all-zero case failed: " & SSL.Errors.Image (Error);
      end if;

      SSL.Records.Open (Reader, Header, Sealed, Output, Got, Inner, Error);
      if not SSL.Errors.Is_Error (Error) then
         return "a record with no inner content type was accepted";
      end if;
      if Got /= 0 or else Inner /= SSL.Records.Invalid_Content then
         return "a record with no inner content type produced output";
      end if;

      SSL.Secrets.Wipe (Secret_Key);
      SSL.Records.Wipe (Writer);
      SSL.Records.Wipe (Reader);
      return "";
   end Check_Record_Inner_Type_All_Zero;

   ---------------------------------------------------------------------------
   --  Secrets
   ---------------------------------------------------------------------------

   ------------------------
   -- Check_Secret_Wipe --
   ------------------------

   function Check_Secret_Wipe return String is
      Item    : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
      Pattern : constant Byte_Array (1 .. 32) := [others => 16#3C#];
   begin
      SSL.Secrets.Set (Item, Pattern);
      if SSL.Secrets.Length (Item) /= 32 or else not SSL.Secrets.Is_Present (Item) then
         return "a secret did not record what was set";
      end if;
      if SSL.Secrets.Value (Item) /= Pattern then
         return "a secret did not return what was set";
      end if;

      SSL.Secrets.Wipe (Item);
      if SSL.Secrets.Length (Item) /= 0 or else SSL.Secrets.Is_Present (Item) then
         return "a wiped secret still reported content";
      end if;
      if SSL.Secrets.Value (Item)'Length /= 0 then
         return "a wiped secret returned octets";
      end if;

      --  Setting a shorter secret over a longer one must not leave the longer
      --  one's tail behind. Checked by setting, wiping, setting shorter, and
      --  asking for the full width through a copy.
      declare
         Long_Value  : constant Byte_Array (1 .. 48) := [others => 16#7E#];
         Short_Value : constant Byte_Array (1 .. 16) := [others => 16#01#];
      begin
         SSL.Secrets.Set (Item, Long_Value);
         SSL.Secrets.Set (Item, Short_Value);
         if SSL.Secrets.Length (Item) /= 16 then
            return "overwriting a secret left the old length";
         end if;
         if SSL.Secrets.Value (Item) /= Short_Value then
            return "overwriting a secret left the old value";
         end if;
      end;

      return "";
   end Check_Secret_Wipe;

   ------------------------------------------
   -- Check_Secret_Constant_Time_Equality --
   ------------------------------------------

   function Check_Secret_Constant_Time_Equality return String is
      Left, Right : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
      Value  : constant Byte_Array (1 .. 32) := [others => 16#42#];
      Other  : Byte_Array (1 .. 32) := [others => 16#42#];
   begin
      SSL.Secrets.Set (Left, Value);
      SSL.Secrets.Set (Right, Value);
      if not SSL.Secrets.Equal (Left, Right) then
         return "two identical secrets compared unequal";
      end if;
      if not SSL.Secrets.Equal (Left, Value) then
         return "a secret did not compare equal to its own octets";
      end if;

      Other (Other'Last) := 16#43#;
      SSL.Secrets.Set (Right, Other);
      if SSL.Secrets.Equal (Left, Right) then
         return "secrets differing in the last octet compared equal";
      end if;

      Other := [others => 16#42#];
      Other (Other'First) := 16#43#;
      SSL.Secrets.Set (Right, Other);
      if SSL.Secrets.Equal (Left, Right) then
         return "secrets differing in the first octet compared equal";
      end if;

      --  Different lengths are unequal, and the length is not secret.
      SSL.Secrets.Set (Right, Value (1 .. 16));
      if SSL.Secrets.Equal (Left, Right) then
         return "secrets of different lengths compared equal";
      end if;

      return "";
   end Check_Secret_Constant_Time_Equality;

   ---------------------------------------------------------------------------
   --  Extensions
   ---------------------------------------------------------------------------

   package Ext renames SSL.Extensions;
   package Messages renames SSL.Handshake_Messages;

   Bounds : constant SSL.Limits.Resource_Limits := SSL.Limits.Default_Limits;

   ---------------------------------
   -- Check_Extension_Registry --
   ---------------------------------

   function Check_Extension_Registry return String is
   begin
      --  Wire identifiers, against RFC 8446 section 4.2 and the RFCs that
      --  allocated the others.
      if Ext.Value_Of (Ext.Server_Name) /= 0 then
         return "server_name is code point 0";
      end if;
      if Ext.Value_Of (Ext.Supported_Groups) /= 10 then
         return "supported_groups is code point 10";
      end if;
      if Ext.Value_Of (Ext.Signature_Algorithms) /= 13 then
         return "signature_algorithms is code point 13";
      end if;
      if Ext.Value_Of (Ext.Application_Layer_Protocol_Negotiation) /= 16 then
         return "alpn is code point 16";
      end if;
      if Ext.Value_Of (Ext.Record_Size_Limit) /= 28 then
         return "record_size_limit is code point 28 (RFC 8449)";
      end if;
      if Ext.Value_Of (Ext.Supported_Versions) /= 43 then
         return "supported_versions is code point 43";
      end if;
      if Ext.Value_Of (Ext.Key_Share) /= 51 then
         return "key_share is code point 51";
      end if;
      if Ext.Value_Of (Ext.Extended_Master_Secret) /= 23 then
         return "extended_master_secret is code point 23 (RFC 7627)";
      end if;
      if Ext.Value_Of (Ext.Renegotiation_Info) /= 16#FF01# then
         return "renegotiation_info is code point 0xff01 (RFC 5746)";
      end if;

      --  Round trip.
      for Kind in Ext.Extension_Kind loop
         if Kind /= Ext.Unknown_Extension then
            if Ext.Kind_For (Ext.Value_Of (Kind)) /= Kind then
               return "the identifier for " & Ext.Image (Kind) & " does not round-trip";
            end if;
         end if;
      end loop;

      --  An identifier nobody has allocated maps to Unknown and keeps its
      --  number in the rendering.
      if Ext.Kind_For (16#7A7A#) /= Ext.Unknown_Extension then
         return "an unallocated identifier was recognized";
      end if;
      if Ext.Image (Ext.Extension_Value'(16#7A7A#)) /= "extension_31354" then
         return Report ("unknown identifier image", "extension_31354",
                        Ext.Image (Ext.Extension_Value'(16#7A7A#)));
      end if;

      --  The two features this library declines are recognized as declined,
      --  which is what lets a diagnostic say "we will not" rather than "we have
      --  not heard of that".
      if not Ext.Is_Refused (Ext.Early_Data) then
         return "early_data is not marked as refused";
      end if;
      if not Ext.Is_Refused (Ext.Post_Handshake_Auth) then
         return "post_handshake_auth is not marked as refused";
      end if;
      if Ext.Is_Refused (Ext.Key_Share) then
         return "key_share is marked as refused";
      end if;

      return "";
   end Check_Extension_Registry;

   ---------------------------------
   -- Check_Extension_Contexts --
   ---------------------------------

   function Check_Extension_Contexts return String is
   begin
      --  RFC 8446 section 4.2's table, spot-checked where getting it wrong
      --  would matter.
      if not Ext.Permitted (Ext.Key_Share, Ext.In_Client_Hello) then
         return "key_share belongs in a ClientHello";
      end if;
      if not Ext.Permitted (Ext.Key_Share, Ext.In_Server_Hello) then
         return "key_share belongs in a ServerHello";
      end if;
      if Ext.Permitted (Ext.Key_Share, Ext.In_Encrypted_Extensions) then
         return "key_share does not belong in EncryptedExtensions";
      end if;

      if not Ext.Permitted (Ext.Server_Name, Ext.In_Encrypted_Extensions) then
         return "server_name is acknowledged in EncryptedExtensions";
      end if;
      if Ext.Permitted (Ext.Server_Name, Ext.In_Server_Hello) then
         return "server_name does not belong in a ServerHello";
      end if;

      if not Ext.Permitted (Ext.Cookie, Ext.In_Hello_Retry_Request) then
         return "cookie belongs in a HelloRetryRequest";
      end if;
      if Ext.Permitted (Ext.Cookie, Ext.In_Server_Hello) then
         return "cookie does not belong in a ServerHello";
      end if;

      if not Ext.Permitted (Ext.Pre_Shared_Key, Ext.In_Server_Hello) then
         return "pre_shared_key belongs in a ServerHello";
      end if;
      if Ext.Permitted (Ext.PSK_Key_Exchange_Modes, Ext.In_Server_Hello) then
         return "psk_key_exchange_modes is client-only";
      end if;

      --  The refused features are permitted nowhere at all.
      for Context in Ext.Message_Context loop
         if Ext.Permitted (Ext.Early_Data, Context) then
            return "early_data was permitted in " & Ext.Image (Context);
         end if;
         if Ext.Permitted (Ext.Post_Handshake_Auth, Context) then
            return "post_handshake_auth was permitted in " & Ext.Image (Context);
         end if;
      end loop;

      --  An unrecognized extension is tolerated in a ClientHello, which RFC 8446
      --  section 4.2 requires a server to ignore, and nowhere else -- because
      --  this endpoint cannot have solicited something it does not know.
      if not Ext.Permitted (Ext.Unknown_Extension, Ext.In_Client_Hello) then
         return "an unknown extension must be tolerated in a ClientHello";
      end if;
      for Context in Ext.Message_Context loop
         if Context /= Ext.In_Client_Hello
           and then Ext.Permitted (Ext.Unknown_Extension, Context)
         then
            return "an unknown extension was tolerated in " & Ext.Image (Context);
         end if;
      end loop;

      return "";
   end Check_Extension_Contexts;

   -------------------------------------
   -- Check_Extension_Block_Parsing --
   -------------------------------------

   function Check_Extension_Block_Parsing return String is

      --  A block holding supported_versions then an unallocated extension.
      Block : constant Byte_Array :=
        From_Hex ("000d")                        --  block length 13
        & From_Hex ("002b") & From_Hex ("0003") & From_Hex ("020304")
        & From_Hex ("7a7a") & From_Hex ("0002") & From_Hex ("beef");

      Cursor : SSL.Wire.Cursor := SSL.Wire.Reader (Block);
      Inner  : SSL.Wire.Cursor;
      Seen   : Ext.Seen_Set := Ext.Empty_Set;
      Error  : SSL.Errors.Error_Information;
   begin
      Ext.Open_Block (Block, Cursor, Bounds, Inner, Error);
      if SSL.Errors.Is_Error (Error) then
         return "a well-formed block was refused: " & SSL.Errors.Image (Error);
      end if;

      declare
         Kind    : Ext.Extension_Kind;
         Value   : Ext.Extension_Value;
         Body_Part : SSL.Wire.Cursor;
         Present : Boolean;
      begin
         Ext.Next (Block, Inner, Ext.In_Client_Hello, Bounds, Seen,
                   Kind, Value, Body_Part, Present, Error);
         if SSL.Errors.Is_Error (Error) or else not Present then
            return "the first extension did not parse";
         end if;
         if Kind /= Ext.Supported_Versions then
            return "the first extension should be supported_versions";
         end if;
         if SSL.Wire.Remaining (Body_Part) /= 3 then
            return "the body cursor is confined to the extension's own length";
         end if;

         Ext.Next (Block, Inner, Ext.In_Client_Hello, Bounds, Seen,
                   Kind, Value, Body_Part, Present, Error);
         if SSL.Errors.Is_Error (Error) or else not Present then
            return "the unknown extension did not parse";
         end if;
         if Kind /= Ext.Unknown_Extension or else Value /= 16#7A7A# then
            return "the unknown extension lost its identifier";
         end if;

         Ext.Next (Block, Inner, Ext.In_Client_Hello, Bounds, Seen,
                   Kind, Value, Body_Part, Present, Error);
         if Present then
            return "the block should be exhausted";
         end if;
      end;

      --  The unknown identifier is kept for diagnostics, and the recognized one
      --  is in the set.
      if not Ext.Contains (Seen, Ext.Supported_Versions) then
         return "supported_versions was not recorded";
      end if;
      if Ext.Unknown_Count (Seen) /= 1
        or else Ext.Unknown_At (Seen, 1) /= 16#7A7A#
      then
         return "the unknown identifier was not kept for diagnostics";
      end if;
      if not Ext.Contains (Seen, Ext.Extension_Value'(16#7A7A#)) then
         return "the unknown identifier is not reported as seen";
      end if;

      --  A duplicate is refused, and refused before its body is opened.
      declare
         Repeated : constant Byte_Array :=
           From_Hex ("000e")
           & From_Hex ("002b") & From_Hex ("0003") & From_Hex ("020304")
           & From_Hex ("002b") & From_Hex ("0003") & From_Hex ("020304");
         Outer : SSL.Wire.Cursor := SSL.Wire.Reader (Repeated);
         List  : SSL.Wire.Cursor;
         Fresh : Ext.Seen_Set := Ext.Empty_Set;
         Kind    : Ext.Extension_Kind;
         Value   : Ext.Extension_Value;
         Body_Part : SSL.Wire.Cursor;
         Present : Boolean;
      begin
         Ext.Open_Block (Repeated, Outer, Bounds, List, Error);
         Ext.Next (Repeated, List, Ext.In_Client_Hello, Bounds, Fresh,
                   Kind, Value, Body_Part, Present, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the first occurrence should parse";
         end if;

         Ext.Next (Repeated, List, Ext.In_Client_Hello, Bounds, Fresh,
                   Kind, Value, Body_Part, Present, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a duplicate extension was accepted";
         end if;
         if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_Duplicate_Extension then
            return "a duplicate produced the wrong failure code";
         end if;
      end;

      --  An extension in a message it may not appear in is refused, whatever
      --  its body would have said.
      declare
         Misplaced : constant Byte_Array :=
           From_Hex ("0007") & From_Hex ("0000") & From_Hex ("0003") & From_Hex ("000000");
         Outer : SSL.Wire.Cursor := SSL.Wire.Reader (Misplaced);
         List  : SSL.Wire.Cursor;
         Fresh : Ext.Seen_Set := Ext.Empty_Set;
         Kind    : Ext.Extension_Kind;
         Value   : Ext.Extension_Value;
         Body_Part : SSL.Wire.Cursor;
         Present : Boolean;
      begin
         Ext.Open_Block (Misplaced, Outer, Bounds, List, Error);
         Ext.Next (Misplaced, List, Ext.In_Server_Hello, Bounds, Fresh,
                   Kind, Value, Body_Part, Present, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "server_name was accepted in a ServerHello";
         end if;
         if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_Extension_In_Wrong_Context then
            return "a misplaced extension produced the wrong failure code";
         end if;
      end;

      return "";
   end Check_Extension_Block_Parsing;

   ---------------------------------------------------------------------------
   --  Handshake messages
   ---------------------------------------------------------------------------

   ------------------------------
   -- Check_Handshake_Framing --
   ------------------------------

   function Check_Handshake_Framing return String is
      Kind   : Messages.Message_Type;
      Value  : Messages.Type_Value;
      Length : Byte_Index;
      Error  : SSL.Errors.Error_Information;
   begin
      Messages.Parse_Header (From_Hex ("01000123"), Kind, Value, Length, Error);
      if SSL.Errors.Is_Error (Error) then
         return "a ClientHello header was refused";
      end if;
      if Kind /= Messages.Client_Hello then
         return "the message type was mis-parsed";
      end if;
      if Length /= 16#0123# then
         return Report ("declared length", "291", Length'Image);
      end if;

      if Messages.Encode_Header (Messages.Client_Hello, 16#0123#)
        /= From_Hex ("01000123")
      then
         return "encoding a header did not reproduce the octets";
      end if;

      --  message_hash is synthetic and never travels; a peer sending one is
      --  trying to inject a transcript transformation.
      Messages.Parse_Header (From_Hex ("fe000020"), Kind, Value, Length, Error);
      if not SSL.Errors.Is_Error (Error) then
         return "a message_hash on the wire was accepted";
      end if;

      Messages.Parse_Header (From_Hex ("7f000000"), Kind, Value, Length, Error);
      if not SSL.Errors.Is_Error (Error) then
         return "an unknown message type was accepted";
      end if;

      --  Certificate gets its own, larger bound; everything else would let a
      --  peer send a four-megabyte Finished under it.
      if not Messages.Length_Permitted (Messages.Certificate, 2_000_000, Bounds) then
         return "a two-megabyte Certificate should be permitted";
      end if;
      if Messages.Length_Permitted (Messages.Finished, 2_000_000, Bounds) then
         return "a two-megabyte Finished should not be permitted";
      end if;
      if not Messages.Length_Permitted (Messages.Finished, 48, Bounds) then
         return "an ordinary Finished should be permitted";
      end if;

      return "";
   end Check_Handshake_Framing;

   --  A ClientHello carrying supported_versions, supported_groups,
   --  signature_algorithms, ALPN, server_name, a key share and
   --  record_size_limit. Built here octet by octet so the test knows exactly
   --  what the parser is being given.
   function Sample_Client_Hello return Byte_Array;

   function Sample_Client_Hello return Byte_Array is
      Body_Octets : constant Byte_Array :=
        From_Hex ("0303")                              --  legacy_version
        & [1 .. 32 => 16#AB#]                          --  random
        & From_Hex ("20") & [1 .. 32 => 16#CD#]        --  legacy_session_id
        & From_Hex ("0004") & From_Hex ("13011303")    --  two suites
        & From_Hex ("01") & From_Hex ("00")            --  null compression only
        & From_Hex ("0071")                            --  extension block, 113 octets
          --  supported_versions: tls1.3
          & From_Hex ("002b") & From_Hex ("0003") & From_Hex ("020304")
          --  supported_groups: x25519, secp256r1
          & From_Hex ("000a") & From_Hex ("0006") & From_Hex ("0004") & From_Hex ("001d0017")
          --  signature_algorithms: ed25519, ecdsa_secp256r1_sha256
          & From_Hex ("000d") & From_Hex ("0006") & From_Hex ("0004") & From_Hex ("08070403")
          --  alpn: h2, http/1.1
          & From_Hex ("0010") & From_Hex ("000e") & From_Hex ("000c")
            & From_Hex ("02") & From_Hex ("6832")
            & From_Hex ("08") & From_Hex ("687474702f312e31")
          --  server_name: example.com
          & From_Hex ("0000") & From_Hex ("0010") & From_Hex ("000e")
            & From_Hex ("00") & From_Hex ("000b") & From_Hex ("6578616d706c652e636f6d")
          --  record_size_limit: 16384
          & From_Hex ("001c") & From_Hex ("0002") & From_Hex ("4000")
          --  key_share: x25519
          & From_Hex ("0033") & From_Hex ("0026") & From_Hex ("0024")
            & From_Hex ("001d") & From_Hex ("0020") & [1 .. 32 => 16#11#];
   begin
      return Messages.Encode_Header (Messages.Client_Hello, Body_Octets'Length) & Body_Octets;
   end Sample_Client_Hello;

   -------------------------------------
   -- Check_Client_Hello_Round_Trip --
   -------------------------------------

   function Check_Client_Hello_Round_Trip return String is
      Data  : constant Byte_Array := Sample_Client_Hello;
      Item  : Messages.Client_Hello_Message;
      Error : SSL.Errors.Error_Information;
      First : Byte_Index;
      Last  : Byte_Index;
   begin
      Messages.Parse_Client_Hello (Data, Bounds, Item, Error);
      if SSL.Errors.Is_Error (Error) then
         return "a well-formed ClientHello was refused: " & SSL.Errors.Image (Error);
      end if;

      if Messages.Legacy_Version (Item) /= 16#0303# then
         return "the legacy version is 0x0303 in every TLS 1.3 ClientHello";
      end if;
      if Messages.Random (Item) /= Byte_Array'[1 .. 32 => 16#AB#] then
         return "the random was mis-parsed";
      end if;

      --  The legacy session identifier is kept verbatim, because a TLS 1.3
      --  server must echo it exactly.
      if Messages.Session_Id (Item)'Length /= 32
        or else Messages.Session_Id (Item) /= Byte_Array'[1 .. 32 => 16#CD#]
      then
         return "the legacy session identifier was not kept verbatim";
      end if;

      if SSL.Cipher_Suites.Length (Messages.Offered_Suites (Item)) /= 2 then
         return "two suites were offered";
      end if;
      if SSL.Cipher_Suites.Element (Messages.Offered_Suites (Item), 1)
        /= SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256
      then
         return "the first offered suite is TLS_AES_128_GCM_SHA256";
      end if;

      if not SSL.Versions.Contains
               (Messages.Offered_Versions (Item), SSL.Versions.TLS_1_3)
      then
         return "supported_versions offered TLS 1.3";
      end if;

      if SSL.Supported_Groups.Length (Messages.Offered_Groups (Item)) /= 2 then
         return "two groups were offered";
      end if;
      if SSL.Signature_Schemes.Length (Messages.Offered_Schemes (Item)) /= 2 then
         return "two signature schemes were offered";
      end if;

      if SSL.ALPN.Length (Messages.Offered_Protocols (Item)) /= 2 then
         return "two application protocols were offered";
      end if;
      if SSL.ALPN.Image (SSL.ALPN.Element (Messages.Offered_Protocols (Item), 1)) /= "h2" then
         return "the first protocol is h2";
      end if;

      if SSL.Server_Names.Image (Messages.Offered_Name (Item)) /= "example.com" then
         return Report ("server name", "example.com",
                        SSL.Server_Names.Image (Messages.Offered_Name (Item)));
      end if;

      if Messages.Requested_Record_Limit (Item) /= 16_384 then
         return "the record size limit was mis-parsed";
      end if;

      --  The key share is reported as a span into the message, so nothing was
      --  copied and the transcript still hashes the octets that arrived.
      if not Messages.Key_Share_For (Item, SSL.Supported_Groups.X25519, First, Last) then
         return "the x25519 key share was not found";
      end if;
      if Last - First + 1 /= 32 then
         return "the key share span is the wrong width";
      end if;
      if Data (First .. Last) /= Byte_Array'[1 .. 32 => 16#11#] then
         return "the key share span points at the wrong octets";
      end if;

      if Messages.Key_Share_For (Item, SSL.Supported_Groups.Secp384r1, First, Last) then
         return "a key share was reported for a group that offered none";
      end if;

      return "";
   end Check_Client_Hello_Round_Trip;

   -----------------------------------
   -- Check_Client_Hello_Refusals --
   -----------------------------------

   function Check_Client_Hello_Refusals return String is
      Item  : Messages.Client_Hello_Message;
      Error : SSL.Errors.Error_Information;

      --  A ClientHello offering deflate compression. TLS compression is a CRIME
      --  vulnerability and this library refuses rather than negotiating it away.
      Compressed_Body : constant Byte_Array :=
        From_Hex ("0303") & [1 .. 32 => 16#AB#]
        & From_Hex ("00")
        & From_Hex ("0002") & From_Hex ("1301")
        & From_Hex ("02") & From_Hex ("0001")     --  null and deflate
        & From_Hex ("0000");
      Compressed : constant Byte_Array :=
        Messages.Encode_Header (Messages.Client_Hello, Compressed_Body'Length)
        & Compressed_Body;
   begin
      Messages.Parse_Client_Hello (Compressed, Bounds, Item, Error);
      if not SSL.Errors.Is_Error (Error) then
         return "a ClientHello offering compression was accepted";
      end if;
      if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_Legacy_Compression_Offered then
         return "offering compression produced the wrong failure code";
      end if;

      --  An oversized legacy session identifier.
      declare
         Oversized_Body : constant Byte_Array :=
           From_Hex ("0303") & [1 .. 32 => 16#AB#]
           & From_Hex ("21") & [1 .. 33 => 16#CD#]
           & From_Hex ("0002") & From_Hex ("1301")
           & From_Hex ("01") & From_Hex ("00")
           & From_Hex ("0000");
         Oversized : constant Byte_Array :=
           Messages.Encode_Header (Messages.Client_Hello, Oversized_Body'Length)
           & Oversized_Body;
      begin
         Messages.Parse_Client_Hello (Oversized, Bounds, Item, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a 33-octet legacy session identifier was accepted";
         end if;
      end;

      --  A key share whose length does not match the group it claims. This must
      --  never reach key agreement, and it does not: the share is dropped at
      --  parse time on the length alone.
      declare
         Wrong_Width_Body : constant Byte_Array :=
           From_Hex ("0303") & [1 .. 32 => 16#AB#]
           & From_Hex ("00")
           & From_Hex ("0002") & From_Hex ("1301")
           & From_Hex ("01") & From_Hex ("00")
           & From_Hex ("000e")
             & From_Hex ("0033") & From_Hex ("000a") & From_Hex ("0008")
               & From_Hex ("001d") & From_Hex ("0004") & From_Hex ("11223344");
         Wrong_Width : constant Byte_Array :=
           Messages.Encode_Header (Messages.Client_Hello, Wrong_Width_Body'Length)
           & Wrong_Width_Body;
         First, Last : Byte_Index;
      begin
         Messages.Parse_Client_Hello (Wrong_Width, Bounds, Item, Error);
         if SSL.Errors.Is_Error (Error) then
            return "a short x25519 share should be dropped, not fail the parse";
         end if;
         if Messages.Key_Share_For (Item, SSL.Supported_Groups.X25519, First, Last) then
            return "a four-octet share was accepted as an x25519 key share";
         end if;
      end;

      --  An early_data extension: a feature this library does not implement, so
      --  it is permitted in no context and refused by name.
      declare
         With_Early_Body : constant Byte_Array :=
           From_Hex ("0303") & [1 .. 32 => 16#AB#]
           & From_Hex ("00")
           & From_Hex ("0002") & From_Hex ("1301")
           & From_Hex ("01") & From_Hex ("00")
           & From_Hex ("0004") & From_Hex ("002a") & From_Hex ("0000");
         With_Early : constant Byte_Array :=
           Messages.Encode_Header (Messages.Client_Hello, With_Early_Body'Length)
           & With_Early_Body;
      begin
         Messages.Parse_Client_Hello (With_Early, Bounds, Item, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "an early_data extension was accepted";
         end if;
         if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_Extension_In_Wrong_Context then
            return "early_data produced the wrong failure code";
         end if;
      end;

      --  A zero-length ALPN protocol name, which RFC 7301 forbids.
      declare
         Empty_Name_Body : constant Byte_Array :=
           From_Hex ("0303") & [1 .. 32 => 16#AB#]
           & From_Hex ("00")
           & From_Hex ("0002") & From_Hex ("1301")
           & From_Hex ("01") & From_Hex ("00")
           & From_Hex ("0007")
             & From_Hex ("0010") & From_Hex ("0003") & From_Hex ("0001") & From_Hex ("00");
         Empty_Name : constant Byte_Array :=
           Messages.Encode_Header (Messages.Client_Hello, Empty_Name_Body'Length)
           & Empty_Name_Body;
      begin
         Messages.Parse_Client_Hello (Empty_Name, Bounds, Item, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a zero-length ALPN protocol name was accepted";
         end if;
      end;

      return "";
   end Check_Client_Hello_Refusals;

   -------------------------------------
   -- Check_Client_Hello_Truncation --
   -------------------------------------

   function Check_Client_Hello_Truncation return String is
      Full : constant Byte_Array := Sample_Client_Hello;
   begin
      --  Truncated at every length short of complete, the parse must fail
      --  cleanly: no exception, no partly-filled message acted on, and no read
      --  past the end. This is the check that a hostile peer's short message
      --  cannot get anywhere.
      --
      --  It found a real gap. A prefix that stops just before the extension
      --  block is a well-formed extensionless ClientHello, and the parser
      --  accepted it, because nothing compared the header's declared body
      --  length against the octets actually supplied. Both hello parsers now
      --  make that comparison first.
      for Cut in 4 .. Natural (Full'Length) - 1 loop
         declare
            Partial : constant Byte_Array := Full (Full'First .. Full'First + Byte_Index (Cut) - 1);
            Item    : Messages.Client_Hello_Message;
            Error   : SSL.Errors.Error_Information;
         begin
            Messages.Parse_Client_Hello (Partial, Bounds, Item, Error);
            if not SSL.Errors.Is_Error (Error) then
               return "a ClientHello truncated to" & Cut'Image & " octets was accepted";
            end if;
         end;
      end loop;

      --  And the complete one still parses, so the loop above was testing
      --  something.
      declare
         Item  : Messages.Client_Hello_Message;
         Error : SSL.Errors.Error_Information;
      begin
         Messages.Parse_Client_Hello (Full, Bounds, Item, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the complete ClientHello no longer parses";
         end if;
      end;

      return "";
   end Check_Client_Hello_Truncation;

   -------------------------------------
   -- Check_Server_Hello_And_Retry --
   -------------------------------------

   function Check_Server_Hello_And_Retry return String is

      function Build (Random_Part : Byte_Array; Extensions : Byte_Array) return Byte_Array is
         Body_Octets : constant Byte_Array :=
           From_Hex ("0303") & Random_Part
           & From_Hex ("20") & [1 .. 32 => 16#CD#]
           & From_Hex ("1301")
           & From_Hex ("00")
           & Extensions;
      begin
         return Messages.Encode_Header (Messages.Server_Hello, Body_Octets'Length)
           & Body_Octets;
      end Build;

      Item  : Messages.Server_Hello_Message;
      Error : SSL.Errors.Error_Information;
      Group : SSL.Supported_Groups.Named_Group;
      First : Byte_Index;
      Last  : Byte_Index;
   begin
      --  An ordinary ServerHello: supported_versions and a key share.
      declare
         Data : constant Byte_Array :=
           Build ([1 .. 32 => 16#5A#],
                  From_Hex ("002e")
                  & From_Hex ("002b") & From_Hex ("0002") & From_Hex ("0304")
                  & From_Hex ("0033") & From_Hex ("0024")
                    & From_Hex ("001d") & From_Hex ("0020") & [1 .. 32 => 16#22#]);
      begin
         Messages.Parse_Server_Hello (Data, Bounds, Item, Error);
         if SSL.Errors.Is_Error (Error) then
            return "a well-formed ServerHello was refused: " & SSL.Errors.Image (Error);
         end if;
         if Messages.Is_Hello_Retry_Request (Item) then
            return "an ordinary ServerHello was read as a HelloRetryRequest";
         end if;
         if Messages.Selected_Version (Item) /= 16#0304# then
            return "the negotiated version was mis-parsed";
         end if;
         if Messages.Selected_Suite (Item) /= SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256 then
            return "the selected suite was mis-parsed";
         end if;
         if not Messages.Server_Key_Share (Item, Group, First, Last) then
            return "the server key share was not found";
         end if;
         if Group /= SSL.Supported_Groups.X25519 or else Last - First + 1 /= 32 then
            return "the server key share is the wrong group or width";
         end if;
         if Data (First .. Last) /= Byte_Array'[1 .. 32 => 16#22#] then
            return "the server key share span points at the wrong octets";
         end if;
      end;

      --  A HelloRetryRequest, which is a ServerHello whose random is exactly
      --  the RFC 8446 section 4.1.3 constant. It carries a bare group and a
      --  cookie, and no share.
      declare
         Data : constant Byte_Array :=
           Build (Messages.Hello_Retry_Random,
                  From_Hex ("0015")
                  & From_Hex ("002b") & From_Hex ("0002") & From_Hex ("0304")
                  & From_Hex ("0033") & From_Hex ("0002") & From_Hex ("0017")
                  & From_Hex ("002c") & From_Hex ("0005") & From_Hex ("0003")
                    & From_Hex ("abcdef"));
      begin
         Messages.Parse_Server_Hello (Data, Bounds, Item, Error);
         if SSL.Errors.Is_Error (Error) then
            return "a well-formed HelloRetryRequest was refused: " & SSL.Errors.Image (Error);
         end if;
         if not Messages.Is_Hello_Retry_Request (Item) then
            return "the special random was not recognized";
         end if;
         if not Messages.Retry_Group (Item, Group)
           or else Group /= SSL.Supported_Groups.Secp256r1
         then
            return "the requested group was not read";
         end if;
         if Messages.Server_Key_Share (Item, Group, First, Last) then
            return "a HelloRetryRequest must carry no key share";
         end if;
         if not Messages.Cookie_Span (Item, First, Last)
           or else Data (First .. Last) /= From_Hex ("abcdef")
         then
            return "the cookie was not read exactly";
         end if;
      end;

      --  A cookie in an ordinary ServerHello is a context violation: RFC 8446
      --  permits it only in a ClientHello or a HelloRetryRequest.
      declare
         Data : constant Byte_Array :=
           Build ([1 .. 32 => 16#5A#],
                  From_Hex ("0009")
                  & From_Hex ("002c") & From_Hex ("0005") & From_Hex ("0003")
                    & From_Hex ("abcdef"));
      begin
         Messages.Parse_Server_Hello (Data, Bounds, Item, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a cookie was accepted in an ordinary ServerHello";
         end if;
         if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_Extension_In_Wrong_Context then
            return "a misplaced cookie produced the wrong failure code";
         end if;
      end;

      --  A server selecting a suite this library does not implement cannot have
      --  selected one that was offered.
      declare
         Body_Octets : constant Byte_Array :=
           From_Hex ("0303") & [1 .. 32 => 16#5A#]
           & From_Hex ("00")
           & From_Hex ("002f")                        --  TLS_RSA_WITH_AES_128_CBC_SHA
           & From_Hex ("00");
         Data : constant Byte_Array :=
           Messages.Encode_Header (Messages.Server_Hello, Body_Octets'Length) & Body_Octets;
      begin
         Messages.Parse_Server_Hello (Data, Bounds, Item, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a CBC suite selection was accepted";
         end if;
         if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_Selected_Suite_Not_Offered then
            return "an unimplemented suite produced the wrong failure code";
         end if;
      end;

      return "";
   end Check_Server_Hello_And_Retry;

   ---------------------------------------------------------------------------
   --  ClientHello encoding
   ---------------------------------------------------------------------------

   -----------------------------------
   -- Check_Client_Hello_Encoding --
   -----------------------------------

   --  Library level, not local to the check.
   --
   --  A configuration holds a reference to its trust snapshot, so the snapshot
   --  must outlive it. That is the lifetime obligation SSL.Configurations
   --  documents, and Ada's accessibility rules enforce it rather than leaving it
   --  to the caller's care: a snapshot declared inside the check below fails an
   --  accessibility check at run time, which is the language doing its job.
   Encoder_Anchors : aliased SSL.Trust.Snapshot;

   function Check_Client_Hello_Encoding return String is
      package Config renames SSL.Configurations;

      Anchors : SSL.Trust.Snapshot renames Encoder_Anchors;
      Builder : Config.Client_Builder;
      Setup   : Config.Client_Configuration;
      Error   : SSL.Errors.Error_Information;
      Ok      : Boolean;

      Random_Value : constant Messages.Random_Bytes := [others => 16#3C#];
      Session      : constant Byte_Array (1 .. 32) := [others => 16#7E#];
      Shares       : Messages.Key_Share_List;

      Buffer  : Byte_Array (1 .. 4096) := [others => 0];
      Written : Byte_Index;
      Binders : Byte_Index;
   begin
      SSL.Trust.Load_Explicit_Anchors
        (Anchors, Tests_Fixtures.Anchor_PEM, SSL.Clocks.UTC (2026, 8, 1), Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load";
      end if;

      Config.Secure_Client_Defaults (Builder);
      Config.Set_Expected_Name (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
      Config.Set_Anchors (Builder, Encoder_Anchors'Access, Ok);
      declare
         Protocols : SSL.ALPN.Protocol_List := SSL.ALPN.No_Protocols;
      begin
         SSL.ALPN.Append (Protocols, SSL.ALPN.Protocol ("h2"), Ok);
         SSL.ALPN.Append (Protocols, SSL.ALPN.Protocol ("http/1.1"), Ok);
         Config.Set_Application_Protocols (Builder, Protocols, SSL.ALPN.Required, Ok);
      end;
      Config.Build (Builder, Setup, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the configuration did not build: " & SSL.Errors.Image (Error);
      end if;

      --  One X25519 share, of the right width for its group.
      Shares (1).Group := SSL.Supported_Groups.X25519;
      Shares (1).Length := 32;
      Shares (1).Value (1 .. 32) := [others => 16#99#];

      Messages.Encode_Client_Hello
        (Config       => Setup,
         Random_Value => Random_Value,
         Session_Id   => Session,
         Shares       => Shares,
         Share_Count  => 1,
         Cookie       => Empty_Bytes,
         Identity     => Empty_Bytes,
         Obfuscated_Age => 0,
         Binder_Length  => 0,
         Into         => Buffer,
         Written      => Written,
         Binders_At   => Binders,
         Error        => Error);
      if SSL.Errors.Is_Error (Error) then
         return "encoding failed: " & SSL.Errors.Image (Error);
      end if;

      --  The octets the specification fixes, checked directly rather than only
      --  through the round trip: a round trip cannot catch an encoding that
      --  both sides get wrong the same way.
      if Buffer (1) /= 1 then
         return "a ClientHello begins with message type 1";
      end if;
      if Buffer (5) /= 16#03# or else Buffer (6) /= 16#03# then
         return "legacy_version is 0x0303 in every TLS 1.3 ClientHello";
      end if;

      --  The declared body length must equal what follows it.
      declare
         Declared : constant Byte_Index :=
           65_536 * Byte_Index (Buffer (2))
           + 256 * Byte_Index (Buffer (3))
           + Byte_Index (Buffer (4));
      begin
         if Declared /= Written - 4 then
            return Report ("declared body length", Byte_Index'Image (Written - 4),
                           Declared'Image);
         end if;
      end;

      --  And now the round trip, through the parser that a peer would use.
      declare
         Parsed : Messages.Client_Hello_Message;
         First  : Byte_Index;
         Last   : Byte_Index;
      begin
         Messages.Parse_Client_Hello (Buffer (1 .. Written), Bounds, Parsed, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the encoder produced something the parser rejects: "
              & SSL.Errors.Image (Error);
         end if;

         if Messages.Random (Parsed) /= Random_Value then
            return "the random did not survive the round trip";
         end if;
         if Messages.Session_Id (Parsed) /= Session then
            return "the legacy session identifier did not survive";
         end if;
         if not SSL.Versions.Contains
                  (Messages.Offered_Versions (Parsed), SSL.Versions.TLS_1_3)
         then
            return "supported_versions did not survive";
         end if;
         if SSL.Server_Names.Image (Messages.Offered_Name (Parsed)) /= "www.example.com" then
            return "the server name did not survive";
         end if;
         if SSL.ALPN.Length (Messages.Offered_Protocols (Parsed)) /= 2 then
            return "the ALPN list did not survive";
         end if;
         if SSL.Cipher_Suites.Length (Messages.Offered_Suites (Parsed)) /= 3 then
            return "the three default suites did not survive";
         end if;
         if SSL.Supported_Groups.Length (Messages.Offered_Groups (Parsed)) /= 3 then
            return "the three default groups did not survive";
         end if;
         if not Messages.Key_Share_For
                  (Parsed, SSL.Supported_Groups.X25519, First, Last)
         then
            return "the key share did not survive";
         end if;
         if Buffer (First .. Last) /= Byte_Array'[1 .. 32 => 16#99#] then
            return "the key share octets are wrong";
         end if;

         --  The secure defaults request a stapled status, so the extension is
         --  there; and no finite-field group is offered.
         if not Messages.Requests_Status (Parsed) then
            return "status_request should be sent under the default revocation policy";
         end if;
         if SSL.Supported_Groups.Contains
              (Messages.Offered_Groups (Parsed), SSL.Supported_Groups.FFDHE2048)
         then
            return "no finite-field group should be offered by default";
         end if;
      end;

      --  A buffer too small produces nothing at all rather than a truncated
      --  message: a half-written ClientHello is one the transcript has hashed
      --  and the peer cannot parse.
      declare
         Tiny : Byte_Array (1 .. 32) := [others => 16#FF#];
         Got  : Byte_Index;
      begin
         Messages.Encode_Client_Hello
           (Config         => Setup,
            Random_Value   => Random_Value,
            Session_Id     => Session,
            Shares         => Shares,
            Share_Count    => 1,
            Cookie         => Empty_Bytes,
            Identity       => Empty_Bytes,
            Obfuscated_Age => 0,
            Binder_Length  => 0,
            Into           => Tiny,
            Written        => Got,
            Binders_At     => Binders,
            Error          => Error);
         if not SSL.Errors.Is_Error (Error) then
            return "encoding into a buffer that cannot hold the message succeeded";
         end if;
         if Got /= 0 then
            return "a failed encode reported a length";
         end if;
         for Octet of Tiny loop
            if Octet /= 0 then
               return "a failed encode left octets behind";
            end if;
         end loop;
      end;

      return "";
   end Check_Client_Hello_Encoding;

   ---------------------------------------------
   -- Check_Certificate_Verify_Content --
   ---------------------------------------------

   function Check_Certificate_Verify_Content return String is
      Hash : constant Byte_Array (1 .. 32) := [others => 16#AA#];

      Server : constant Byte_Array :=
        Messages.Certificate_Verify_Content (Messages.Server_Signing, Hash);
      Client : constant Byte_Array :=
        Messages.Certificate_Verify_Content (Messages.Client_Signing, Hash);
   begin
      --  RFC 8446 section 4.4.3: 64 octets of 0x20, the context string, a
      --  single zero octet, then the transcript hash.
      if Server'Length /= 64 + 33 + 1 + 32 then
         return Report ("server content length", "130", Server'Length'Image);
      end if;

      for Index in 1 .. 64 loop
         if Server (Server'First + Byte_Index (Index) - 1) /= 16#20# then
            return "the first 64 octets must all be 0x20";
         end if;
      end loop;

      declare
         Context : String (1 .. 33);
      begin
         for Index in Context'Range loop
            Context (Index) :=
              Character'Val (Natural (Server (Server'First + 64 + Byte_Index (Index) - 1)));
         end loop;
         if Context /= "TLS 1.3, server CertificateVerify" then
            return Report ("server context", "TLS 1.3, server CertificateVerify", Context);
         end if;
      end;

      if Server (Server'First + 64 + 33) /= 0 then
         return "the context string must be followed by a single zero octet";
      end if;

      if Server (Server'First + 64 + 33 + 1 .. Server'Last) /= Hash then
         return "the transcript hash must follow the separator";
      end if;

      --  The two roles must differ, or a server's signature could be replayed
      --  as a client's.
      if Server = Client then
         return "the server and client contexts must differ";
      end if;

      declare
         Context : String (1 .. 33);
      begin
         for Index in Context'Range loop
            Context (Index) :=
              Character'Val (Natural (Client (Client'First + 64 + Byte_Index (Index) - 1)));
         end loop;
         if Context /= "TLS 1.3, client CertificateVerify" then
            return Report ("client context", "TLS 1.3, client CertificateVerify", Context);
         end if;
      end;

      --  A SHA-384 transcript gives a longer structure, and the prefix is
      --  unchanged.
      declare
         Long : constant Byte_Array (1 .. 48) := [others => 16#BB#];
         Wide : constant Byte_Array :=
           Messages.Certificate_Verify_Content (Messages.Server_Signing, Long);
      begin
         if Wide'Length /= 64 + 33 + 1 + 48 then
            return "a SHA-384 transcript gives a 146-octet structure";
         end if;
         if Wide (Wide'First .. Wide'First + 97) /= Server (Server'First .. Server'First + 97)
         then
            return "the fixed prefix must not depend on the hash width";
         end if;
      end;

      return "";
   end Check_Certificate_Verify_Content;


   ---------------------------------------------------------------------------
   --  The remaining TLS 1.3 message codecs
   ---------------------------------------------------------------------------

   ------------------------------------------
   -- Check_Server_Hello_Encoding --
   ------------------------------------------

   function Check_Server_Hello_Encoding return String is
      Random_Value : constant Messages.Random_Bytes := [others => 16#5A#];
      Session      : constant Byte_Array (1 .. 32) := [others => 16#7E#];
      Share        : constant Byte_Array (1 .. 32) := [others => 16#42#];

      Buffer  : Byte_Array (1 .. 512);
      Written : Byte_Index;
      Error   : SSL.Errors.Error_Information;
   begin
      Messages.Encode_Server_Hello
        (Random_Value => Random_Value,
         Session_Id   => Session,
         Suite        => SSL.Cipher_Suites.TLS_AES_256_GCM_SHA384,
         Share_Group  => SSL.Supported_Groups.X25519,
         Share_Value  => Share,
         Has_Identity => True,
         Identity     => 0,
         Into         => Buffer,
         Written      => Written,
         Error        => Error);
      if SSL.Errors.Is_Error (Error) then
         return "encoding a ServerHello failed: " & SSL.Errors.Image (Error);
      end if;

      declare
         Parsed : Messages.Server_Hello_Message;
         Group  : SSL.Supported_Groups.Named_Group;
         First  : Byte_Index;
         Last   : Byte_Index;
         Index  : Natural;
      begin
         Messages.Parse_Server_Hello (Buffer (1 .. Written), Bounds, Parsed, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the encoder produced a ServerHello the parser rejects: "
              & SSL.Errors.Image (Error);
         end if;

         if Messages.Is_Hello_Retry_Request (Parsed) then
            return "an ordinary ServerHello must not read as a retry";
         end if;
         if Messages.Random (Parsed) /= Random_Value then
            return "the random did not survive";
         end if;
         if Messages.Session_Id (Parsed) /= Session then
            return "the echoed session identifier did not survive";
         end if;
         if Messages.Selected_Suite (Parsed) /= SSL.Cipher_Suites.TLS_AES_256_GCM_SHA384 then
            return "the selected suite did not survive";
         end if;
         if Messages.Selected_Version (Parsed) /= SSL.Versions.TLS_1_3_Value then
            return "supported_versions must select 1.3";
         end if;
         if not Messages.Server_Key_Share (Parsed, Group, First, Last) then
            return "the key share did not survive";
         end if;
         if Group /= SSL.Supported_Groups.X25519
           or else Buffer (First .. Last) /= Share
         then
            return "the key share came back changed";
         end if;
         if not Messages.Selected_Identity (Parsed, Index) or else Index /= 0 then
            return "the selected PSK identity did not survive";
         end if;
      end;

      --  A HelloRetryRequest is the same shape with the specified random, and
      --  the parser has to tell them apart on that alone.
      Messages.Encode_Hello_Retry_Request
        (Session_Id => Session,
         Suite      => SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256,
         Group      => SSL.Supported_Groups.Secp384r1,
         Cookie     => [1 .. 16 => 16#C0#],
         Into       => Buffer,
         Written    => Written,
         Error      => Error);
      if SSL.Errors.Is_Error (Error) then
         return "encoding a HelloRetryRequest failed: " & SSL.Errors.Image (Error);
      end if;

      declare
         Parsed : Messages.Server_Hello_Message;
         Group  : SSL.Supported_Groups.Named_Group;
         First  : Byte_Index;
         Last   : Byte_Index;
      begin
         Messages.Parse_Server_Hello (Buffer (1 .. Written), Bounds, Parsed, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the encoder produced a retry the parser rejects: "
              & SSL.Errors.Image (Error);
         end if;
         if not Messages.Is_Hello_Retry_Request (Parsed) then
            return "a retry must be recognized by its random alone";
         end if;
         if not Messages.Retry_Group (Parsed, Group)
           or else Group /= SSL.Supported_Groups.Secp384r1
         then
            return "the requested group did not survive";
         end if;
         if not Messages.Cookie_Span (Parsed, First, Last)
           or else Buffer (First .. Last) /= [1 .. 16 => 16#C0#]
         then
            return "the cookie did not survive";
         end if;
      end;

      --  Sending the retry constant through the ordinary encoder would produce
      --  a message every peer reads as a retry. It is refused locally instead.
      Messages.Encode_Server_Hello
        (Random_Value => Messages.Hello_Retry_Random,
         Session_Id   => Session,
         Suite        => SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256,
         Share_Group  => SSL.Supported_Groups.X25519,
         Share_Value  => Share,
         Has_Identity => False,
         Identity     => 0,
         Into         => Buffer,
         Written      => Written,
         Error        => Error);
      if not SSL.Errors.Is_Error (Error) then
         return "a ServerHello carrying the retry random must be refused";
      end if;

      return "";
   end Check_Server_Hello_Encoding;

   -------------------------------------------
   -- Check_Encrypted_Extensions_Codec --
   -------------------------------------------

   function Check_Encrypted_Extensions_Codec return String is
      Buffer  : Byte_Array (1 .. 512);
      Written : Byte_Index;
      Error   : SSL.Errors.Error_Information;
      Chosen  : constant SSL.ALPN.Protocol_Name := SSL.ALPN.Protocol ("h2");
   begin
      Messages.Encode_Encrypted_Extensions
        (Protocol         => Chosen,
         Has_Protocol     => True,
         Record_Limit     => 4096,
         Acknowledge_Name => True,
         Into             => Buffer,
         Written          => Written,
         Error            => Error);
      if SSL.Errors.Is_Error (Error) then
         return "encoding EncryptedExtensions failed: " & SSL.Errors.Image (Error);
      end if;

      declare
         Parsed   : Messages.Encrypted_Extensions_Message;
         Protocol : SSL.ALPN.Protocol_Name;
      begin
         Messages.Parse_Encrypted_Extensions (Buffer (1 .. Written), Bounds, Parsed, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the encoder produced something the parser rejects: "
              & SSL.Errors.Image (Error);
         end if;
         if not Messages.Selected_Protocol (Parsed, Protocol)
           or else SSL.ALPN.Image (Protocol) /= "h2"
         then
            return "the selected protocol did not survive";
         end if;
         if Messages.Requested_Record_Limit (Parsed) /= 4096 then
            return "the record size limit did not survive";
         end if;
         if not Messages.Acknowledged_Server_Name (Parsed) then
            return "an empty server_name is the acknowledgement and must be seen";
         end if;
      end;

      --  A record_size_limit below 64 is malformed, not a small limit
      --  (RFC 8449 section 4).
      declare
         Small : constant Byte_Array :=
           Messages.Encode_Header (Messages.Encrypted_Extensions, 8)
           & From_Hex ("0006") & From_Hex ("001c") & From_Hex ("0002") & From_Hex ("0020");
         Parsed : Messages.Encrypted_Extensions_Message;
      begin
         Messages.Parse_Encrypted_Extensions (Small, Bounds, Parsed, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a record size limit of 32 must be refused";
         end if;
      end;

      --  A message of another type must not parse here even if its body would
      --  fit: each parser checks the type it was given.
      declare
         Wrong : constant Byte_Array :=
           Messages.Encode_Header (Messages.Finished, 2) & From_Hex ("0000");
         Parsed : Messages.Encrypted_Extensions_Message;
      begin
         Messages.Parse_Encrypted_Extensions (Wrong, Bounds, Parsed, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a Finished must not parse as EncryptedExtensions";
         end if;
      end;

      return "";
   end Check_Encrypted_Extensions_Codec;

   -----------------------------------
   -- Check_Certificate_Codec --
   -----------------------------------

   function Check_Certificate_Codec return String is
      Leaf   : constant Byte_Array := [1 .. 40 => 16#11#];
      Issuer : constant Byte_Array := [1 .. 24 => 16#22#];
      Staple : constant Byte_Array := [1 .. 12 => 16#33#];

      Chain : constant Byte_Array := Leaf & Issuer;
      Spans : Messages.Certificate_Span_List :=
        [others => (First => 1, Last => 0)];

      Buffer  : Byte_Array (1 .. 512);
      Written : Byte_Index;
      Error   : SSL.Errors.Error_Information;
   begin
      Spans (1) := (First => Chain'First, Last => Chain'First + Leaf'Length - 1);
      Spans (2) := (First => Chain'First + Leaf'Length, Last => Chain'Last);

      Messages.Encode_Certificate
        (Chain   => Chain,
         Spans   => Spans,
         Count   => 2,
         Context => Empty_Bytes,
         Staple  => Staple,
         Into    => Buffer,
         Written => Written,
         Error   => Error);
      if SSL.Errors.Is_Error (Error) then
         return "encoding a Certificate failed: " & SSL.Errors.Image (Error);
      end if;

      declare
         Parsed : Messages.Certificate_Message;
         First  : Byte_Index;
         Last   : Byte_Index;
      begin
         Messages.Parse_Certificate (Buffer (1 .. Written), Bounds, Parsed, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the encoder produced a Certificate the parser rejects: "
              & SSL.Errors.Image (Error);
         end if;
         if Messages.Entry_Count (Parsed) /= 2 then
            return Report ("certificate entries", "2",
                           Natural'Image (Messages.Entry_Count (Parsed)));
         end if;

         Messages.Entry_Span (Parsed, 1, First, Last);
         if Buffer (First .. Last) /= Leaf then
            return "the leaf did not survive the round trip";
         end if;
         Messages.Entry_Span (Parsed, 2, First, Last);
         if Buffer (First .. Last) /= Issuer then
            return "the issuer did not survive the round trip";
         end if;

         if not Messages.Entry_Status_Span (Parsed, 1, First, Last)
           or else Buffer (First .. Last) /= Staple
         then
            return "the stapled response did not survive on the leaf";
         end if;
         if Messages.Entry_Status_Span (Parsed, 2, First, Last) then
            return "a staple belongs to the leaf and to no other entry";
         end if;

         if not Messages.Request_Context_Span (Parsed, First, Last)
           or else Last >= First
         then
            return "a server's certificate_request_context is present and empty";
         end if;
      end;

      --  An empty chain is a message, not an absence: it is how a client
      --  declines a request.
      Messages.Encode_Certificate
        (Chain   => Chain,
         Spans   => Spans,
         Count   => 0,
         Context => [1 .. 4 => 16#AB#],
         Staple  => Empty_Bytes,
         Into    => Buffer,
         Written => Written,
         Error   => Error);
      if SSL.Errors.Is_Error (Error) then
         return "encoding an empty Certificate failed: " & SSL.Errors.Image (Error);
      end if;

      declare
         Parsed : Messages.Certificate_Message;
         First  : Byte_Index;
         Last   : Byte_Index;
      begin
         Messages.Parse_Certificate (Buffer (1 .. Written), Bounds, Parsed, Error);
         if SSL.Errors.Is_Error (Error) then
            return "an empty chain must parse: " & SSL.Errors.Image (Error);
         end if;
         if Messages.Entry_Count (Parsed) /= 0 then
            return "an empty chain has no entries";
         end if;
         if not Messages.Request_Context_Span (Parsed, First, Last)
           or else Buffer (First .. Last) /= [1 .. 4 => 16#AB#]
         then
            return "the request context did not survive";
         end if;
      end;

      --  A zero-length certificate never reaches a DER parser.
      declare
         Message : constant Byte_Array :=
           Messages.Encode_Header (Messages.Certificate, 9)
           & From_Hex ("00")                --  empty context
           & From_Hex ("000005")            --  certificate_list length
           & From_Hex ("000000")            --  a zero-length entry
           & From_Hex ("0000");             --  its extensions
         Parsed : Messages.Certificate_Message;
      begin
         Messages.Parse_Certificate (Message, Bounds, Parsed, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a zero-length certificate entry must be refused";
         end if;
      end;

      --  More certificates than the configured count, refused at the bound.
      declare
         Tight : SSL.Limits.Resource_Limits := Bounds;
         Parsed : Messages.Certificate_Message;
      begin
         Tight.Maximum_Certificate_Count := 1;
         Messages.Encode_Certificate
           (Chain, Spans, 2, Empty_Bytes, Empty_Bytes, Buffer, Written, Error);
         if SSL.Errors.Is_Error (Error) then
            return "re-encoding the two-entry chain failed";
         end if;
         Messages.Parse_Certificate (Buffer (1 .. Written), Tight, Parsed, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a chain past the configured count must be refused";
         end if;
      end;

      return "";
   end Check_Certificate_Codec;

   -------------------------------------------
   -- Check_Certificate_Request_Codec --
   -------------------------------------------

   function Check_Certificate_Request_Codec return String is
      Buffer  : Byte_Array (1 .. 512);
      Written : Byte_Index;
      Error   : SSL.Errors.Error_Information;
      Wanted  : SSL.Signature_Schemes.Scheme_List := SSL.Signature_Schemes.No_Schemes;
      Ok      : Boolean;
   begin
      SSL.Signature_Schemes.Append (Wanted, SSL.Signature_Schemes.Ed25519, Ok);
      SSL.Signature_Schemes.Append
        (Wanted, SSL.Signature_Schemes.ECDSA_Secp256r1_SHA256, Ok);

      Messages.Encode_Certificate_Request
        (Context             => Empty_Bytes,
         Schemes             => Wanted,
         Certificate_Schemes => SSL.Signature_Schemes.No_Schemes,
         Into                => Buffer,
         Written             => Written,
         Error               => Error);
      if SSL.Errors.Is_Error (Error) then
         return "encoding a CertificateRequest failed: " & SSL.Errors.Image (Error);
      end if;

      declare
         Parsed : Messages.Certificate_Request_Message;
         First  : Byte_Index;
         Last   : Byte_Index;
      begin
         Messages.Parse_Certificate_Request (Buffer (1 .. Written), Bounds, Parsed, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the encoder produced a request the parser rejects: "
              & SSL.Errors.Image (Error);
         end if;
         if not SSL.Signature_Schemes.Contains
                  (Messages.Offered_Schemes (Parsed), SSL.Signature_Schemes.Ed25519)
         then
            return "the offered schemes did not survive";
         end if;
         if Messages.Has_Certificate_Authorities (Parsed) then
            return "no certificate_authorities was sent";
         end if;
         if not Messages.Request_Context_Span (Parsed, First, Last)
           or else Last >= First
         then
            return "the context is present and empty";
         end if;
      end;

      --  RFC 8446 section 4.3.2 makes signature_algorithms mandatory: a request
      --  without it names nothing a client could sign with.
      declare
         Bare : constant Byte_Array :=
           Messages.Encode_Header (Messages.Certificate_Request, 3)
           & From_Hex ("00") & From_Hex ("0000");
         Parsed : Messages.Certificate_Request_Message;
      begin
         Messages.Parse_Certificate_Request (Bare, Bounds, Parsed, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a CertificateRequest without signature_algorithms must be refused";
         end if;
         if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_Missing_Required_Extension then
            return Report ("refusal", "missing required extension",
                           SSL.Errors.Image (Error));
         end if;
      end;

      return "";
   end Check_Certificate_Request_Codec;

   -------------------------------------------
   -- Check_Small_Message_Codecs --
   -------------------------------------------

   function Check_Small_Message_Codecs return String is
      Buffer  : Byte_Array (1 .. 1024);
      Written : Byte_Index;
      Error   : SSL.Errors.Error_Information;
   begin
      --  CertificateVerify.
      declare
         Signature : constant Byte_Array := [1 .. 64 => 16#5E#];
         Parsed    : Messages.Certificate_Verify_Message;
         First     : Byte_Index;
         Last      : Byte_Index;
      begin
         Messages.Encode_Certificate_Verify
           (SSL.Signature_Schemes.Ed25519, Signature, Buffer, Written, Error);
         if SSL.Errors.Is_Error (Error) then
            return "encoding a CertificateVerify failed";
         end if;
         Messages.Parse_Certificate_Verify (Buffer (1 .. Written), Bounds, Parsed, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the encoder produced a CertificateVerify the parser rejects: "
              & SSL.Errors.Image (Error);
         end if;
         if not Messages.Scheme_Recognized (Parsed)
           or else Messages.Scheme (Parsed) /= SSL.Signature_Schemes.Ed25519
         then
            return "the signature scheme did not survive";
         end if;
         Messages.Signature_Span (Parsed, First, Last);
         if Buffer (First .. Last) /= Signature then
            return "the signature did not survive";
         end if;
      end;

      --  An unknown scheme keeps its number rather than losing it, so the
      --  refusal the state machine reports can name what the peer sent.
      declare
         Message : constant Byte_Array :=
           Messages.Encode_Header (Messages.Certificate_Verify, 6)
           & From_Hex ("0A0B") & From_Hex ("0002") & From_Hex ("FFFF");
         Parsed  : Messages.Certificate_Verify_Message;
      begin
         Messages.Parse_Certificate_Verify (Message, Bounds, Parsed, Error);
         if SSL.Errors.Is_Error (Error) then
            return "an unknown scheme is parsed, not refused here";
         end if;
         if Messages.Scheme_Recognized (Parsed) then
            return "0x0A0B is not a scheme this library implements";
         end if;
         if Messages.Scheme_Value (Parsed) /= 16#0A0B# then
            return "the unknown scheme's number must be preserved";
         end if;
      end;

      --  An empty signature is refused: there is nothing to verify.
      declare
         Message : constant Byte_Array :=
           Messages.Encode_Header (Messages.Certificate_Verify, 4)
           & From_Hex ("0807") & From_Hex ("0000");
         Parsed  : Messages.Certificate_Verify_Message;
      begin
         Messages.Parse_Certificate_Verify (Message, Bounds, Parsed, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "an empty signature must be refused";
         end if;
      end;

      --  Finished.
      declare
         Verify : constant Byte_Array := [1 .. 48 => 16#F1#];
         First  : Byte_Index;
         Last   : Byte_Index;
      begin
         Messages.Encode_Finished (Verify, Buffer, Written, Error);
         if SSL.Errors.Is_Error (Error) then
            return "encoding a Finished failed";
         end if;
         Messages.Parse_Finished (Buffer (1 .. Written), Bounds, First, Last, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the encoder produced a Finished the parser rejects";
         end if;
         if Buffer (First .. Last) /= Verify then
            return "the verify data did not survive";
         end if;
      end;

      --  KeyUpdate, both values, and a third that has no meaning.
      for Request in Messages.Key_Update_Request loop
         declare
            Back : Messages.Key_Update_Request;
         begin
            Messages.Encode_Key_Update (Request, Buffer, Written, Error);
            if SSL.Errors.Is_Error (Error) then
               return "encoding a KeyUpdate failed";
            end if;
            if Written /= 5 then
               return Report ("KeyUpdate length", " 5", Byte_Index'Image (Written));
            end if;
            Messages.Parse_Key_Update (Buffer (1 .. Written), Back, Error);
            if SSL.Errors.Is_Error (Error) or else Back /= Request then
               return "a KeyUpdate did not survive the round trip";
            end if;
         end;
      end loop;

      declare
         Message : constant Byte_Array :=
           Messages.Encode_Header (Messages.Key_Update, 1) & From_Hex ("02");
         Back    : Messages.Key_Update_Request;
      begin
         Messages.Parse_Key_Update (Message, Back, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a KeyUpdate request octet of 2 has no meaning and must be refused";
         end if;
      end;

      --  NewSessionTicket.
      declare
         Nonce  : constant Byte_Array := [1 .. 8 => 16#01#];
         Ticket : constant Byte_Array := [1 .. 96 => 16#7C#];
         Parsed : Messages.New_Session_Ticket_Message;
         First  : Byte_Index;
         Last   : Byte_Index;
      begin
         Messages.Encode_New_Session_Ticket
           (Lifetime => 7200,
            Age_Add  => 16#DEADBEEF#,
            Nonce    => Nonce,
            Ticket   => Ticket,
            Into     => Buffer,
            Written  => Written,
            Error    => Error);
         if SSL.Errors.Is_Error (Error) then
            return "encoding a NewSessionTicket failed: " & SSL.Errors.Image (Error);
         end if;
         Messages.Parse_New_Session_Ticket (Buffer (1 .. Written), Bounds, Parsed, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the encoder produced a ticket the parser rejects: "
              & SSL.Errors.Image (Error);
         end if;
         if Messages.Lifetime (Parsed) /= 7200 then
            return "the lifetime did not survive";
         end if;
         if Messages.Age_Add (Parsed) /= 16#DEADBEEF# then
            return "the age offset did not survive";
         end if;
         Messages.Nonce_Span (Parsed, First, Last);
         if Buffer (First .. Last) /= Nonce then
            return "the ticket nonce did not survive";
         end if;
         Messages.Ticket_Span (Parsed, First, Last);
         if Buffer (First .. Last) /= Ticket then
            return "the ticket did not survive";
         end if;
      end;

      --  A lifetime past the seven days RFC 8446 section 4.6.1 permits is
      --  refused rather than clamped: clamping would leave the two ends
      --  disagreeing about when the ticket died.
      declare
         Message : constant Byte_Array :=
           Messages.Encode_Header (Messages.New_Session_Ticket, 15)
           & From_Hex ("00093A81")          --  604801 seconds, one past the cap
           & From_Hex ("00000000")
           & From_Hex ("00")
           & From_Hex ("0002") & From_Hex ("ABCD")
           & From_Hex ("0000");
         Parsed : Messages.New_Session_Ticket_Message;
      begin
         Messages.Parse_New_Session_Ticket (Message, Bounds, Parsed, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a ticket lifetime past seven days must be refused";
         end if;
      end;

      --  A ticket of no octets identifies nothing.
      declare
         Message : constant Byte_Array :=
           Messages.Encode_Header (Messages.New_Session_Ticket, 13)
           & From_Hex ("00000E10")
           & From_Hex ("00000000")
           & From_Hex ("00")
           & From_Hex ("0000")
           & From_Hex ("0000");
         Parsed : Messages.New_Session_Ticket_Message;
      begin
         Messages.Parse_New_Session_Ticket (Message, Bounds, Parsed, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "an empty ticket must be refused";
         end if;
      end;

      return "";
   end Check_Small_Message_Codecs;

   ----------------------------------
   -- Check_PSK_Offer_Parsing --
   ----------------------------------

   function Check_PSK_Offer_Parsing return String is
      --  A ClientHello carrying psk_key_exchange_modes and a pre_shared_key
      --  offer of two identities. Built by hand, because the point is to read
      --  what a peer would send rather than what this library would encode.
      Identity_A : constant Byte_Array := [1 .. 8 => 16#A1#];
      Identity_B : constant Byte_Array := [1 .. 4 => 16#B2#];
      Binder_A   : constant Byte_Array := [1 .. 32 => 16#C3#];
      Binder_B   : constant Byte_Array := [1 .. 32 => 16#D4#];

      --  identities: (2 + 8 + 4) + (2 + 4 + 4) = 24 octets
      Identity_List : constant Byte_Array :=
        From_Hex ("0008") & Identity_A & From_Hex ("00000064")
        & From_Hex ("0004") & Identity_B & From_Hex ("000000C8");

      --  binders: (1 + 32) * 2 = 66 octets
      Binder_List : constant Byte_Array :=
        From_Hex ("20") & Binder_A & From_Hex ("20") & Binder_B;

      PSK_Body : constant Byte_Array :=
        From_Hex ("0018") & Identity_List & From_Hex ("0042") & Binder_List;

      function Hello (With_Trailing : Boolean) return Byte_Array;

      function Hello (With_Trailing : Boolean) return Byte_Array is
         Head : constant Byte_Array :=
           From_Hex ("0303")
           & [1 .. 32 => 16#3C#]
           & From_Hex ("00")                            --  no session id
           & From_Hex ("0002") & From_Hex ("1301")      --  one suite
           & From_Hex ("0100");                         --  null compression
         Fixed : constant Byte_Array :=
           --  supported_versions
           From_Hex ("002b") & From_Hex ("0003") & From_Hex ("02") & From_Hex ("0304")
           --  psk_key_exchange_modes: psk_dhe_ke only
           & From_Hex ("002d") & From_Hex ("0002") & From_Hex ("01") & From_Hex ("01");
         Offer : constant Byte_Array :=
           From_Hex ("0029") & SSL.Wire.Encode_UInt16 (Natural (PSK_Body'Length)) & PSK_Body;
         Tail  : constant Byte_Array :=
           (if With_Trailing
            then From_Hex ("001c") & From_Hex ("0002") & From_Hex ("4000")
            else Empty_Bytes);
         Block : constant Byte_Array := Fixed & Offer & Tail;
         Body_Octets : constant Byte_Array :=
           Head & SSL.Wire.Encode_UInt16 (Natural (Block'Length)) & Block;
      begin
         return Messages.Encode_Header (Messages.Client_Hello, Body_Octets'Length)
           & Body_Octets;
      end Hello;

      Message : constant Byte_Array := Hello (With_Trailing => False);
      Parsed  : Messages.Client_Hello_Message;
      Error   : SSL.Errors.Error_Information;
      First   : Byte_Index;
      Last    : Byte_Index;
   begin
      Messages.Parse_Client_Hello (Message, Bounds, Parsed, Error);
      if SSL.Errors.Is_Error (Error) then
         return "a ClientHello with a PSK offer did not parse: " & SSL.Errors.Image (Error);
      end if;

      if not Messages.Offers_PSK (Parsed) then
         return "the offer was not recorded";
      end if;
      if Messages.PSK_Identity_Count (Parsed) /= 2 then
         return Report ("identities", "2",
                        Natural'Image (Messages.PSK_Identity_Count (Parsed)));
      end if;

      Messages.PSK_Identity_Span (Parsed, 1, First, Last);
      if Message (First .. Last) /= Identity_A then
         return "the first identity did not survive";
      end if;
      Messages.PSK_Identity_Span (Parsed, 2, First, Last);
      if Message (First .. Last) /= Identity_B then
         return "the second identity did not survive";
      end if;

      if Messages.PSK_Obfuscated_Age (Parsed, 1) /= 100
        or else Messages.PSK_Obfuscated_Age (Parsed, 2) /= 200
      then
         return "the reported ages did not survive";
      end if;

      Messages.PSK_Binder_Span (Parsed, 1, First, Last);
      if Message (First .. Last) /= Binder_A then
         return "the first binder did not survive";
      end if;
      Messages.PSK_Binder_Span (Parsed, 2, First, Last);
      if Message (First .. Last) /= Binder_B then
         return "the second binder did not survive";
      end if;

      if not Messages.Allows_PSK_With_DHE (Parsed)
        or else Messages.Allows_PSK_Alone (Parsed)
      then
         return "psk_dhe_ke alone was offered";
      end if;

      --  The binders offset is where the message stops being covered by them.
      --  The octets from there to the end are exactly the binders list with its
      --  own two-octet prefix.
      declare
         Offset : constant Byte_Index := Messages.PSK_Binders_Offset (Parsed);
      begin
         if Message (Offset .. Message'Last)
              /= From_Hex ("0042") & Binder_List
         then
            return "the binders offset does not point at the binders list";
         end if;
      end;

      --  An extension after pre_shared_key is refused: the binders would not
      --  cover it, so a peer could change it undetected.
      declare
         Trailing : constant Byte_Array := Hello (With_Trailing => True);
         Late     : Messages.Client_Hello_Message;
      begin
         Messages.Parse_Client_Hello (Trailing, Bounds, Late, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "an extension after pre_shared_key must be refused";
         end if;
         if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_PSK_Not_Last_Extension then
            return Report ("refusal", "pre_shared_key not last",
                           SSL.Errors.Image (Error));
         end if;
      end;

      return "";
   end Check_PSK_Offer_Parsing;


   ---------------------------------------------------------------------------
   --  The TLS 1.3 handshake, client machine against server machine
   ---------------------------------------------------------------------------

   --  Library level for the same reason the encoder fixture is: a configuration
   --  holds a reference to its trust snapshot and to its credentials, so both
   --  must outlive it, and Ada's accessibility rules enforce that rather than
   --  leaving it to be remembered.
   --  A credential for the mutation runner's deepest seed. Library level for
   --  the lifetime reason recorded throughout this file.
   Mutation_Credential : SSL.Credentials.Credential;

   Handshake_Anchors    : aliased SSL.Trust.Snapshot;
   Handshake_Credential : aliased SSL.Credentials.Credential;

   --  The configurations too: a machine keeps a reference to the policy it is
   --  running under, so the policy must outlive the machine for exactly the
   --  same reason the snapshot must outlive the configuration.
   Handshake_Client_Setup : aliased SSL.Configurations.Client_Configuration;
   Handshake_Server_Setup : aliased SSL.Configurations.Server_Configuration;

   ----------------------------------
   -- Check_Handshake_End_To_End --
   ----------------------------------

   function Check_Handshake_End_To_End return String is
      package Config renames SSL.Configurations;
      package Machines_Client renames SSL.TLS13.Client;
      package Machines_Server renames SSL.TLS13.Server;

      use type SSL.TLS13.Step_Kind;
      use type SSL.TLS13.Client.Client_State;
      use type SSL.TLS13.Server.Server_State;

      --  Inside the fixture's validity window and fixed, so the outcome does
      --  not depend on today's date.
      Now : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);

      Client_Setup : Config.Client_Configuration renames Handshake_Client_Setup;
      Server_Setup : Config.Server_Configuration renames Handshake_Server_Setup;
      Error        : SSL.Errors.Error_Information;
      Ok           : Boolean;

      --  Two deterministic sources with different patterns. One source for both
      --  ends would hand the two machines the same scalars, which is the bug a
      --  previous check in this file was written to remember.
      Client_Random : SSL.Crypto.Random_Source;
      Server_Random : SSL.Crypto.Random_Source;

      Client_Machine : aliased Machines_Client.Machine;
      Server_Machine : aliased Machines_Server.Machine;

      Client_Out : Byte_Array (1 .. 16_384) := [others => 0];
      Server_Out : Byte_Array (1 .. 16_384) := [others => 0];

      --  A queue of complete handshake messages waiting to be delivered. Each
      --  is copied out of the producing side's buffer, because the next call
      --  into that side will overwrite it.
      Maximum_Queued : constant := 16;
      type Queued_Message is record
         Length : Byte_Index := 0;
         Octets : Byte_Array (1 .. 8_192) := [others => 0];
      end record;
      type Message_Queue is array (1 .. Maximum_Queued) of Queued_Message;

      Queue : Message_Queue;
      Count : Natural := 0;

      Client_Complete : Boolean := False;
      Server_Complete : Boolean := False;

      --  What each side was told to install, in the order it was told. Recorded
      --  rather than acted on, so that the ordering itself can be asserted.
      Maximum_Recorded : constant := 32;
      type Step_Log is array (1 .. Maximum_Recorded) of SSL.TLS13.Step_Kind;
      Client_Log : Step_Log := [others => SSL.TLS13.Handshake_Complete];
      Client_Steps : Natural := 0;
      Server_Log : Step_Log := [others => SSL.TLS13.Handshake_Complete];
      Server_Steps : Natural := 0;

      procedure Collect
        (Result : SSL.TLS13.Plan;
         Buffer : Byte_Array;
         Log    : in out Step_Log;
         Logged : in out Natural;
         Done   : in out Boolean;
         Failed : out Boolean);

      procedure Collect
        (Result : SSL.TLS13.Plan;
         Buffer : Byte_Array;
         Log    : in out Step_Log;
         Logged : in out Natural;
         Done   : in out Boolean;
         Failed : out Boolean)
      is
      begin
         Failed := False;
         for Index in 1 .. Result.Count loop
            if Logged < Maximum_Recorded then
               Logged := Logged + 1;
               Log (Logged) := Result.Steps (Index).Kind;
            end if;

            case Result.Steps (Index).Kind is
               when SSL.TLS13.Send_Handshake =>
                  if Count = Maximum_Queued then
                     Failed := True;
                     return;
                  end if;
                  Count := Count + 1;
                  Queue (Count).Length :=
                    Result.Steps (Index).Last - Result.Steps (Index).First + 1;
                  Queue (Count).Octets (1 .. Queue (Count).Length) :=
                    Buffer (Result.Steps (Index).First .. Result.Steps (Index).Last);

               when SSL.TLS13.Handshake_Complete =>
                  Done := True;

               when others =>
                  null;
            end case;
         end loop;
      end Collect;

      Overflow : Boolean;
   begin
      --  Deliberately distinct patterns; see the comment above.
      SSL.Crypto.Use_Fixed_Pattern (Client_Random, [16#11#, 16#22#, 16#33#, 16#45#, 16#57#]);
      SSL.Crypto.Use_Fixed_Pattern (Server_Random, [16#A1#, 16#B2#, 16#C3#, 16#D4#, 16#E5#,
                                                    16#F6#, 16#07#]);

      SSL.Trust.Load_Explicit_Anchors
        (Handshake_Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load: " & SSL.Errors.Image (Error);
      end if;

      SSL.Credentials.Load_PEM
        (Handshake_Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the credential fixture did not load: " & SSL.Errors.Image (Error);
      end if;

      declare
         Builder : Config.Client_Builder;
      begin
         Config.Secure_Client_Defaults (Builder);
         Config.Set_Expected_Name
           (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
         Config.Set_Anchors (Builder, Handshake_Anchors'Access, Ok);
         Config.Build (Builder, Client_Setup, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      declare
         Builder : Config.Server_Builder;
      begin
         Config.Secure_Server_Defaults (Builder);
         Config.Add_Credential (Builder, Handshake_Credential'Access, Ok);
         if not Ok then
            return "the fixture credential was not accepted";
         end if;
         Config.Build (Builder, Server_Setup, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      Machines_Server.Begin_Handshake
        (Server_Machine, Handshake_Server_Setup'Access, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the server machine did not start: " & SSL.Errors.Image (Error);
      end if;

      declare
         Result : SSL.TLS13.Plan;
      begin
         Machines_Client.Begin_Handshake
           (Item   => Client_Machine,
            Config => Handshake_Client_Setup'Access,
            Now    => Now,
            Source => Client_Random,
            Into   => Client_Out,
            Result => Result,
            Error  => Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client machine did not start: " & SSL.Errors.Image (Error);
         end if;
         Collect (Result, Client_Out, Client_Log, Client_Steps, Client_Complete, Overflow);
         if Overflow then
            return "the message queue overflowed";
         end if;
      end;

      if Count /= 1 then
         return "Begin_Handshake produces exactly one ClientHello";
      end if;

      --  Deliver messages alternately until both machines are finished. The
      --  loop is bounded: a handshake that does not converge is a failure, not
      --  something to wait for.
      declare
         To_Server : Boolean := True;
         Rounds    : Natural := 0;
      begin
         while Count > 0 loop
            Rounds := Rounds + 1;
            if Rounds > 12 then
               return "the handshake did not converge";
            end if;

            declare
               Pending : constant Natural := Count;
               Batch   : Message_Queue := Queue;
            begin
               Count := 0;
               for Index in 1 .. Pending loop
                  declare
                     Result : SSL.TLS13.Plan;
                  begin
                     if To_Server then
                        Machines_Server.Handle_Message
                          (Item    => Server_Machine,
                           Message => Batch (Index).Octets (1 .. Batch (Index).Length),
                           Source  => Server_Random,
                           Into    => Server_Out,
                           Result  => Result,
                           Error   => Error);
                        if SSL.Errors.Is_Error (Error) then
                           return "the server refused a message: " & SSL.Errors.Image (Error);
                        end if;
                        Collect (Result, Server_Out, Server_Log, Server_Steps,
                                 Server_Complete, Overflow);
                     else
                        Machines_Client.Handle_Message
                          (Item    => Client_Machine,
                           Message => Batch (Index).Octets (1 .. Batch (Index).Length),
                           Source  => Client_Random,
                           Into    => Client_Out,
                           Result  => Result,
                           Error   => Error);
                        if SSL.Errors.Is_Error (Error) then
                           return "the client refused a message: " & SSL.Errors.Image (Error);
                        end if;
                        Collect (Result, Client_Out, Client_Log, Client_Steps,
                                 Client_Complete, Overflow);
                     end if;
                     if Overflow then
                        return "the message queue overflowed";
                     end if;
                  end;
               end loop;
            end;

            To_Server := not To_Server;
         end loop;
      end;

      if Machines_Client.State_Of (Client_Machine) /= Machines_Client.Connected then
         return "the client did not reach Connected: "
           & Machines_Client.Image (Machines_Client.State_Of (Client_Machine));
      end if;
      if Machines_Server.State_Of (Server_Machine) /= Machines_Server.Connected then
         return "the server did not reach Connected: "
           & Machines_Server.Image (Machines_Server.State_Of (Server_Machine));
      end if;
      if not Client_Complete or else not Server_Complete then
         return "both machines must report the handshake complete";
      end if;

      --  The two ends must agree about what was negotiated.
      declare
         From_Client : constant SSL.TLS13.Negotiated :=
           Machines_Client.Outcome (Client_Machine);
         From_Server : constant SSL.TLS13.Negotiated :=
           Machines_Server.Outcome (Server_Machine);
      begin
         if From_Client.Suite /= From_Server.Suite then
            return "the two ends disagree about the cipher suite";
         end if;
         if From_Client.Group /= From_Server.Group then
            return "the two ends disagree about the group";
         end if;
         if not From_Client.Peer_Authenticated then
            return "a client that validated a server certificate has an authenticated peer";
         end if;
      end;

      --  The real proof: a record the client seals must open on the server.
      --  Agreeing about names proves nothing if the key schedules diverged.
      declare
         Client_Write : SSL.Records.Traffic_State;
         Server_Read  : SSL.Records.Traffic_State;
         Plaintext    : constant Byte_Array := [1 .. 24 => 16#5A#];
         Sealed       : Byte_Array (1 .. 256) := [others => 0];
         Opened       : Byte_Array (1 .. 256) := [others => 0];
         Sealed_Last  : Byte_Index;
         Opened_Last  : Byte_Index;
         Kind         : SSL.Records.Content_Type;
      begin
         SSL.TLS13.Install_Traffic_Keys
           (Item    => Machines_Client.Context_Of (Client_Machine).all,
            Role    => SSL.TLS13.Client_Endpoint,
            Reading => False,
            Epoch   => SSL.Key_Schedule.Application_Epoch,
            State   => Client_Write,
            Error   => Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client could not install its application write keys";
         end if;

         SSL.TLS13.Install_Traffic_Keys
           (Item    => Machines_Server.Context_Of (Server_Machine).all,
            Role    => SSL.TLS13.Server_Endpoint,
            Reading => True,
            Epoch   => SSL.Key_Schedule.Application_Epoch,
            State   => Server_Read,
            Error   => Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server could not install its application read keys";
         end if;

         SSL.Records.Protect
           (Item      => Client_Write,
            Inner     => SSL.Records.Application_Content,
            Plaintext => Plaintext,
            Padding   => 0,
            Into      => Sealed,
            Written   => Sealed_Last,
            Error     => Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client could not protect a record: " & SSL.Errors.Image (Error);
         end if;

         SSL.Records.Open
           (Item       => Server_Read,
            Header     => Sealed (1 .. SSL.Records.Header_Length),
            Ciphertext => Sealed (SSL.Records.Header_Length + 1 .. Sealed_Last),
            Into       => Opened,
            Written    => Opened_Last,
            Inner      => Kind,
            Error      => Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server could not open the client's record -- the key "
              & "schedules diverged: " & SSL.Errors.Image (Error);
         end if;
         if Opened (1 .. Opened_Last) /= Plaintext then
            return "the record opened to something else";
         end if;
         if Kind /= SSL.Records.Application_Content then
            return "the inner content type did not survive";
         end if;
      end;

      --  The ordering of key installation, which is the part of TLS 1.3 most
      --  easily got subtly wrong. A client installs both handshake directions
      --  at once after ServerHello, and its application keys only once the
      --  server's Finished has verified.
      declare
         Read_Handshake  : Natural := 0;
         Read_Application : Natural := 0;
      begin
         for Index in 1 .. Client_Steps loop
            if Client_Log (Index) = SSL.TLS13.Install_Read_Handshake_Keys then
               Read_Handshake := Index;
            elsif Client_Log (Index) = SSL.TLS13.Install_Read_Application_Keys then
               Read_Application := Index;
            end if;
         end loop;
         if Read_Handshake = 0 or else Read_Application = 0 then
            return "a client installs handshake and then application read keys";
         end if;
         if Read_Handshake >= Read_Application then
            return "handshake read keys must be installed before application ones";
         end if;
      end;

      Machines_Client.Wipe (Client_Machine);
      Machines_Server.Wipe (Server_Machine);
      return "";
   end Check_Handshake_End_To_End;


   ---------------------------------------------------------------------------
   --  Two engines driving each other
   ---------------------------------------------------------------------------

   --  Library level, for the lifetime reason recorded above.
   Engine_Anchors    : aliased SSL.Trust.Snapshot;
   Engine_Credential : aliased SSL.Credentials.Credential;
   Engine_Client_Setup : aliased SSL.Configurations.Client_Configuration;
   Engine_Server_Setup : aliased SSL.Configurations.Server_Configuration;

   -------------------------------
   -- Check_Engine_Round_Trip --
   -------------------------------

   function Check_Engine_Round_Trip return String is
      package Config renames SSL.Configurations;
      package Engines renames SSL.Engines;

      use type Engines.Lifecycle;

      Now  : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);
      Tick : constant SSL.Clocks.Monotonic_Time := SSL.Clocks.Current_Monotonic;

      Client : Engines.Engine;
      Server : Engines.Engine;
      Error  : SSL.Errors.Error_Information;
      Ok     : Boolean;

      --  Move everything one engine has queued into the other, then let the
      --  receiver work through it. Returns how many octets crossed, so the
      --  driving loop can tell when nothing more is happening.
      function Pump
        (From : in out Engines.Engine;
         To   : in out Engines.Engine) return Byte_Index;

      function Pump
        (From : in out Engines.Engine;
         To   : in out Engines.Engine) return Byte_Index
      is
         Moved : Byte_Index := 0;
      begin
         while Engines.Pending_Encrypted (From) > 0 loop
            declare
               Chunk    : Byte_Array (1 .. 4_096) := [others => 0];
               Copied   : Byte_Index;
               Consumed : Byte_Index;
            begin
               Engines.Peek_Encrypted (From, Chunk, Copied);
               exit when Copied = 0;

               Engines.Supply_Encrypted (To, Chunk (1 .. Copied), Consumed, Error);
               exit when SSL.Errors.Is_Error (Error) or else Consumed = 0;

               Engines.Consume_Encrypted (From, Consumed);
               Moved := Moved + Consumed;

               Engines.Advance (To, Tick, Error);
               exit when SSL.Errors.Is_Error (Error);
            end;
         end loop;
         return Moved;
      end Pump;

      Rounds : Natural := 0;
   begin
      SSL.Trust.Load_Explicit_Anchors
        (Engine_Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load";
      end if;

      SSL.Credentials.Load_PEM
        (Engine_Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the credential fixture did not load";
      end if;

      declare
         Builder : Config.Client_Builder;
      begin
         Config.Secure_Client_Defaults (Builder);
         Config.Set_Expected_Name
           (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
         Config.Set_Anchors (Builder, Engine_Anchors'Access, Ok);
         Config.Build (Builder, Engine_Client_Setup, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      declare
         Builder : Config.Server_Builder;
      begin
         Config.Secure_Server_Defaults (Builder);
         Config.Add_Credential (Builder, Engine_Credential'Access, Ok);
         Config.Build (Builder, Engine_Server_Setup, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      Engines.Start_Server
        (Server, Engine_Server_Setup'Access, SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the server engine did not start: " & SSL.Errors.Image (Error);
      end if;

      Engines.Start_Client
        (Client, Engine_Client_Setup'Access, SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the client engine did not start: " & SSL.Errors.Image (Error);
      end if;

      if Engines.Pending_Encrypted (Client) = 0 then
         return "a client engine has a ClientHello queued the moment it starts";
      end if;

      --  Drive until neither side has anything more to say. The loop is
      --  bounded: a handshake that does not converge is a failure rather than
      --  something to keep waiting for.
      loop
         Rounds := Rounds + 1;
         if Rounds > 16 then
            return "the engines did not converge";
         end if;

         declare
            Forward : constant Byte_Index := Pump (Client, Server);
            Back    : constant Byte_Index := Pump (Server, Client);
         begin
            if SSL.Errors.Is_Error (Error) then
               return "an engine refused during the handshake: " & SSL.Errors.Image (Error);
            end if;
            exit when Forward = 0 and then Back = 0;
         end;
      end loop;

      if Engines.State_Of (Client) /= Engines.Established then
         return "the client engine did not establish: "
           & Engines.Image (Engines.State_Of (Client))
           & " -- " & SSL.Errors.Image (Engines.Failure_Of (Client));
      end if;
      if Engines.State_Of (Server) /= Engines.Established then
         return "the server engine did not establish: "
           & Engines.Image (Engines.State_Of (Server))
           & " -- " & SSL.Errors.Image (Engines.Failure_Of (Server));
      end if;

      --  The metadata both ends report must describe the same connection.
      declare
         package Meta renames SSL.Connection_Metadata;
         From_Client : constant Meta.Metadata := Engines.Metadata_Of (Client);
         From_Server : constant Meta.Metadata := Engines.Metadata_Of (Server);
      begin
         if not Meta.Is_Established (From_Client)
           or else not Meta.Is_Established (From_Server)
         then
            return "an established engine reports established metadata";
         end if;
         if Meta.Cipher_Suite (From_Client) /= Meta.Cipher_Suite (From_Server) then
            return "the two ends disagree about the cipher suite";
         end if;
         if not Meta.Peer_Authenticated (From_Client) then
            return "a client that validated a server certificate has an authenticated peer";
         end if;
         if Meta.Peer_Authenticated (From_Server) then
            return "no client certificate was requested, so the server's peer is anonymous";
         end if;
      end;

      --  Application data, both directions.
      declare
         Greeting : constant Byte_Array := [1 .. 100 => 16#41#];
         Reply    : constant Byte_Array := [1 .. 37 => 16#5A#];
         Accepted : Byte_Index;
         Received : Byte_Array (1 .. 256) := [others => 0];
         Copied   : Byte_Index;
         Ignored  : Byte_Index;
      begin
         Engines.Write_Plaintext (Client, Greeting, Accepted, Error);
         if SSL.Errors.Is_Error (Error) or else Accepted /= Greeting'Length then
            return "the client could not send application data";
         end if;
         Ignored := Pump (Client, Server);

         Engines.Peek_Plaintext (Server, Received, Copied);
         if Received (1 .. Copied) /= Greeting then
            return "the server did not receive what the client sent";
         end if;
         Engines.Consume_Plaintext (Server, Copied);
         if Engines.Pending_Plaintext (Server) /= 0 then
            return "consuming everything leaves nothing";
         end if;

         Engines.Write_Plaintext (Server, Reply, Accepted, Error);
         if SSL.Errors.Is_Error (Error) or else Accepted /= Reply'Length then
            return "the server could not send application data";
         end if;
         Ignored := Pump (Server, Client);

         Engines.Peek_Plaintext (Client, Received, Copied);
         if Received (1 .. Copied) /= Reply then
            return "the client did not receive what the server sent";
         end if;
         Engines.Consume_Plaintext (Client, Copied);
      end;

      --  Partial consumption: peeking twice must give the same octets, and
      --  consuming half must leave the other half.
      declare
         Payload  : constant Byte_Array := [1 .. 64 => 16#7F#];
         Accepted : Byte_Index;
         First    : Byte_Array (1 .. 256) := [others => 0];
         Second   : Byte_Array (1 .. 256) := [others => 0];
         Copied   : Byte_Index;
         Again    : Byte_Index;
         Ignored  : Byte_Index;
      begin
         Engines.Write_Plaintext (Client, Payload, Accepted, Error);
         Ignored := Pump (Client, Server);

         Engines.Peek_Plaintext (Server, First, Copied);
         Engines.Peek_Plaintext (Server, Second, Again);
         if Copied /= Again or else First (1 .. Copied) /= Second (1 .. Again) then
            return "peeking must not consume";
         end if;

         Engines.Consume_Plaintext (Server, Copied / 2);
         Engines.Peek_Plaintext (Server, Second, Again);
         if Again /= Copied - Copied / 2 then
            return "consuming half must leave the other half";
         end if;
         if Second (1 .. Again) /= First (Copied / 2 + 1 .. Copied) then
            return "the half that remains must be the second half";
         end if;
         Engines.Consume_Plaintext (Server, Again);
      end;

      --  An orderly shutdown. The client's close_notify has to reach the server
      --  and be recognized as a clean close rather than a truncation.
      declare
         Ignored : Byte_Index;
      begin
         Engines.Begin_Shutdown (Client, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client could not begin a shutdown";
         end if;
         if Engines.State_Of (Client) /= Engines.Closing then
            return "a queued close_notify leaves the connection Closing, not Closed";
         end if;

         Ignored := Pump (Client, Server);

         if not Engines.Peer_Closed (Server) then
            return "the server must see the peer's close_notify";
         end if;
         if Engines.State_Of (Client) /= Engines.Closed then
            return "once the close_notify has left, the connection is Closed";
         end if;
         if Engines.Was_Truncated (Server) then
            return "a close_notify is not a truncation";
         end if;
      end;

      --  Writing after close_notify is refused rather than silently dropped.
      declare
         Accepted : Byte_Index;
      begin
         Engines.Write_Plaintext (Client, [1 .. 4 => 0], Accepted, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "writing after close_notify must be refused";
         end if;
         if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_Write_After_Close_Notify then
            return Report ("refusal", "write after close_notify", SSL.Errors.Image (Error));
         end if;
      end;

      Engines.Wipe (Client);
      Engines.Wipe (Server);
      return "";
   end Check_Engine_Round_Trip;


   ---------------------------------------------------------------------------
   --  The connection layer over a deliberately awkward transport
   ---------------------------------------------------------------------------

   Pipe_Anchors      : aliased SSL.Trust.Snapshot;
   Pipe_Credential   : aliased SSL.Credentials.Credential;
   Pipe_Client_Setup : aliased SSL.Configurations.Client_Configuration;
   Pipe_Server_Setup : aliased SSL.Configurations.Server_Configuration;

   Pipe_To_Server : aliased Tests_Pipes.Pipe;
   Pipe_To_Client : aliased Tests_Pipes.Pipe;
   Client_Medium  : aliased Tests_Pipes.Pipe_Transport;
   Server_Medium  : aliased Tests_Pipes.Pipe_Transport;

   ------------------------------------
   -- Check_Connection_Over_Pipes --
   ------------------------------------

   function Check_Connection_Over_Pipes return String is
      package Config renames SSL.Configurations;
      package Conn renames SSL.Connections;

      use type SSL.Engines.Lifecycle;

      Now : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);

      Client : Conn.Connection;
      Server : Conn.Connection;
      Error  : SSL.Errors.Error_Information;
      Ok     : Boolean;
      Moved  : Boolean;
      Rounds : Natural := 0;
   begin
      Tests_Pipes.Reset (Pipe_To_Server);
      Tests_Pipes.Reset (Pipe_To_Client);
      Tests_Pipes.Attach (Client_Medium, Pipe_To_Server'Access, Pipe_To_Client'Access, 'c');
      Tests_Pipes.Attach (Server_Medium, Pipe_To_Client'Access, Pipe_To_Server'Access, 's');

      SSL.Trust.Load_Explicit_Anchors
        (Pipe_Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load";
      end if;
      SSL.Credentials.Load_PEM
        (Pipe_Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the credential fixture did not load";
      end if;

      declare
         Builder : Config.Client_Builder;
      begin
         Config.Secure_Client_Defaults (Builder);
         Config.Set_Expected_Name
           (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
         Config.Set_Anchors (Builder, Pipe_Anchors'Access, Ok);
         Config.Build (Builder, Pipe_Client_Setup, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client configuration did not build";
         end if;
      end;

      declare
         Builder : Config.Server_Builder;
      begin
         Config.Secure_Server_Defaults (Builder);
         Config.Add_Credential (Builder, Pipe_Credential'Access, Ok);
         Config.Build (Builder, Pipe_Server_Setup, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server configuration did not build";
         end if;
      end;

      SSL.Servers.Accept_Connection
        (Item     => Server,
         Config   => Pipe_Server_Setup'Access,
         Medium   => Server_Medium'Unchecked_Access,
         Identity => SSL.No_Connection,
         Now      => Now,
         Error    => Error);
      if SSL.Errors.Is_Error (Error) then
         return "the server connection did not start: " & SSL.Errors.Image (Error);
      end if;

      SSL.Clients.Connect
        (Item     => Client,
         Config   => Pipe_Client_Setup'Access,
         Medium   => Client_Medium'Unchecked_Access,
         Identity => SSL.No_Connection,
         Now      => Now,
         Error    => Error);
      if SSL.Errors.Is_Error (Error) then
         return "the client connection did not start: " & SSL.Errors.Image (Error);
      end if;

      --  Step both ends until they settle. The transport refuses half the reads
      --  and takes only ninety-seven octets per write, so this takes many more
      --  rounds than a friendly transport would -- which is the point.
      loop
         Rounds := Rounds + 1;
         if Rounds > 2_000 then
            return "the connections did not converge over an awkward transport";
         end if;

         Conn.Step (Client, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client failed: " & SSL.Errors.Image (Error);
         end if;

         Conn.Step (Server, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server failed: " & SSL.Errors.Image (Error);
         end if;

         exit when Conn.Is_Established (Client) and then Conn.Is_Established (Server);
      end loop;

      if not SSL.Connection_Metadata.Peer_Authenticated (Conn.Metadata_Of (Client)) then
         return "the client must have authenticated the server";
      end if;

      --  A message larger than one record, so the fragmenting and reassembly
      --  both run: at 40_000 octets it is three records.
      declare
         Payload  : Byte_Array (1 .. 40_000);
         Accepted : Byte_Index;
         Sent     : Byte_Index := 0;
         Received : Byte_Index := 0;
         Landed   : Byte_Array (1 .. 40_000) := [others => 0];
      begin
         for Index in Payload'Range loop
            --  A varying pattern, so that a reassembly that dropped or
            --  duplicated a fragment shows up rather than matching by accident.
            Payload (Index) := Byte ((Natural (Index) * 7 + 13) mod 256);
         end loop;

         Rounds := 0;
         while Received < Payload'Length loop
            Rounds := Rounds + 1;
            if Rounds > 20_000 then
               return "a large message did not get through";
            end if;

            if Sent < Payload'Length then
               Conn.Write_Available
                 (Client, Payload (Sent + 1 .. Payload'Last), Accepted, Error);
               if SSL.Errors.Is_Error (Error) then
                  return "writing failed: " & SSL.Errors.Image (Error);
               end if;
               Sent := Sent + Accepted;
            end if;

            Conn.Step (Client, Moved, Error);
            if SSL.Errors.Is_Error (Error) then
               return "the client failed while sending: " & SSL.Errors.Image (Error);
            end if;
            Conn.Step (Server, Moved, Error);
            if SSL.Errors.Is_Error (Error) then
               return "the server failed while receiving: " & SSL.Errors.Image (Error);
            end if;

            declare
               Chunk : Byte_Array (1 .. 8_192) := [others => 0];
               Count : Byte_Index;
            begin
               Conn.Read_Available (Server, Chunk, Count, Error);
               if Count > 0 then
                  Landed (Received + 1 .. Received + Count) := Chunk (1 .. Count);
                  Received := Received + Count;
               end if;
            end;
         end loop;

         if Landed /= Payload then
            return "a large message did not arrive intact";
         end if;
      end;

      --  And now with a reader slower than its peer, which is where the
      --  octets went.
      --
      --  Supplying the engine is a *partial* operation: its input queue is
      --  bounded, it takes what fits and says how much. The connection dropped
      --  the rest -- and a dropped octet is not a lost octet, it is a stream
      --  that no longer parses. The next record header lands mid-record and
      --  what reaches the AEAD authenticates as a forgery: bad_record_mac,
      --  from this endpoint, at whatever offset the queue first filled.
      --
      --  Reaching that state needs a reader that falls behind: the input queue
      --  only backs up while records cannot be moved into the plaintext queue,
      --  and the plaintext queue only fills while nobody is draining it. This
      --  reads one small sip per round against a sender running flat out,
      --  which is an ordinary client on a fast link and was not something any
      --  test here did -- every one of them read what it sent as it sent it.
      declare
         Payload  : Byte_Array (1 .. 400_000);
         Landed   : Byte_Array (1 .. 400_000) := [others => 0];
         Accepted : Byte_Index;
         Sent     : Byte_Index := 0;
         Received : Byte_Index := 0;
      begin
         for Index in Payload'Range loop
            Payload (Index) := Byte ((Natural (Index) * 31 + 7) mod 256);
         end loop;

         Rounds := 0;
         while Received < Payload'Length loop
            Rounds := Rounds + 1;
            if Rounds > 400_000 then
               return "a stream did not get through to a reader behind it:"
                      & " sent" & Byte_Index'Image (Sent)
                      & " of" & Natural'Image (Payload'Length)
                      & ", received" & Byte_Index'Image (Received);
            end if;

            --  The sender runs ahead: several turns of writing and stepping
            --  for every turn the receiver takes, so the transport always has
            --  a full read waiting and the receiver's queues stay full.
            for Feeding in 1 .. 20 loop
               if Sent < Payload'Length then
                  Conn.Write_Available
                    (Client, Payload (Sent + 1 .. Payload'Last), Accepted, Error);
                  if SSL.Errors.Is_Error (Error) then
                     return "writing ahead of the reader failed: "
                            & SSL.Errors.Image (Error);
                  end if;
                  Sent := Sent + Accepted;
               end if;

               Conn.Step (Client, Moved, Error);
               if SSL.Errors.Is_Error (Error) then
                  return "the client failed while sending ahead: "
                         & SSL.Errors.Image (Error);
               end if;
            end loop;

            Conn.Step (Server, Moved, Error);
            if SSL.Errors.Is_Error (Error) then
               return "the server failed while behind: "
                      & SSL.Errors.Image (Error);
            end if;

            --  One sip while the sender is still going, and everything once
            --  it has stopped -- which is what a client busy with something
            --  else does, and then what it does when it is not.
            --
            --  The sips are the point: a full queue is a reason to wait, not
            --  a reason to fail, and it is only while the reader is behind
            --  that the input queue backs up far enough for the engine to
            --  take less than it is offered.
            loop
               declare
                  Sip : Byte_Array (1 .. 1_024) := [others => 0];
                  Got : Byte_Index;
               begin
                  Conn.Read_Available (Server, Sip, Got, Error);
                  if SSL.Errors.Is_Error (Error) then
                     return "reading behind the sender failed: "
                            & SSL.Errors.Image (Error);
                  end if;

                  exit when Got = 0;

                  Landed (Received + 1 .. Received + Got) := Sip (1 .. Got);
                  Received := Received + Got;

                  exit when Sent < Payload'Length;
               end;
            end loop;
         end loop;

         if Landed /= Payload then
            return "octets went missing while the reader was behind";
         end if;
      end;

      --  An orderly shutdown across the same transport.
      Conn.Begin_Shutdown (Client, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the client could not begin a shutdown";
      end if;

      Rounds := 0;
      loop
         Rounds := Rounds + 1;
         if Rounds > 2_000 then
            return "the shutdown did not complete";
         end if;

         Conn.Step (Client, Moved, Error);
         Conn.Step (Server, Moved, Error);
         exit when Conn.Peer_Closed (Server);
      end loop;

      if Conn.Was_Truncated (Server) then
         return "a close_notify is not a truncation";
      end if;
      if Conn.State_Of (Client) /= SSL.Engines.Closed then
         return "the client is Closed once its close_notify has left";
      end if;

      Conn.Wipe (Client);
      Conn.Wipe (Server);
      return "";
   end Check_Connection_Over_Pipes;

   ----------------------------------------------------
   -- Check_A_Configured_Queue_Is_The_Boundary --
   ----------------------------------------------------

   Boundary_Anchors      : aliased SSL.Trust.Snapshot;
   Boundary_Credential   : aliased SSL.Credentials.Credential;
   Boundary_Client_Setup : aliased SSL.Configurations.Client_Configuration;
   Boundary_Server_Setup : aliased SSL.Configurations.Server_Configuration;

   function Check_A_Configured_Queue_Is_The_Boundary return String is
      package Config renames SSL.Configurations;
      package Engines renames SSL.Engines;

      use type Engines.Lifecycle;

      Now  : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);
      Tick : constant SSL.Clocks.Monotonic_Time := SSL.Clocks.Current_Monotonic;

      --  Two plaintext records: a number that is neither the default this
      --  library reserves nor the smallest it accepts, so a queue that came
      --  from anywhere but the configuration is a queue of the wrong size.
      Room : constant := 2 * SSL.Limits.Protocol_Plaintext_Record_Limit;

      Narrow : SSL.Limits.Resource_Limits := SSL.Limits.Default_Limits;

      Client : Engines.Engine;
      Server : Engines.Engine;
      Error  : SSL.Errors.Error_Information;
      Ok     : Boolean;

      function Pump
        (From : in out Engines.Engine;
         To   : in out Engines.Engine) return Byte_Index;

      function Pump
        (From : in out Engines.Engine;
         To   : in out Engines.Engine) return Byte_Index
      is
         Moved : Byte_Index := 0;
      begin
         while Engines.Pending_Encrypted (From) > 0 loop
            declare
               Chunk    : Byte_Array (1 .. 4_096) := [others => 0];
               Copied   : Byte_Index;
               Consumed : Byte_Index;
            begin
               Engines.Peek_Encrypted (From, Chunk, Copied);
               exit when Copied = 0;

               Engines.Supply_Encrypted (To, Chunk (1 .. Copied), Consumed, Error);
               exit when SSL.Errors.Is_Error (Error) or else Consumed = 0;

               Engines.Consume_Encrypted (From, Consumed);
               Moved := Moved + Consumed;

               Engines.Advance (To, Tick, Error);
               exit when SSL.Errors.Is_Error (Error);
            end;
         end loop;
         return Moved;
      end Pump;

      Rounds : Natural := 0;
   begin
      Narrow.Maximum_Plaintext_Queue := Room;

      SSL.Trust.Load_Explicit_Anchors
        (Boundary_Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load";
      end if;

      SSL.Credentials.Load_PEM
        (Boundary_Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the credential fixture did not load";
      end if;

      declare
         Builder : Config.Client_Builder;
      begin
         Config.Secure_Client_Defaults (Builder);
         Config.Set_Expected_Name
           (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
         Config.Set_Anchors (Builder, Boundary_Anchors'Access, Ok);
         Config.Build (Builder, Boundary_Client_Setup, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client configuration did not build";
         end if;
      end;

      declare
         Builder : Config.Server_Builder;
      begin
         Config.Secure_Server_Defaults (Builder);
         Config.Add_Credential (Builder, Boundary_Credential'Access, Ok);
         Config.Set_Limits (Builder, Narrow, Ok);
         if not Ok then
            return "the server would not take a two-record plaintext queue";
         end if;

         Config.Build (Builder, Boundary_Server_Setup, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server configuration did not build";
         end if;
      end;

      Engines.Start_Server
        (Server, Boundary_Server_Setup'Access, SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the server engine did not start: " & SSL.Errors.Image (Error);
      end if;

      Engines.Start_Client
        (Client, Boundary_Client_Setup'Access, SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the client engine did not start: " & SSL.Errors.Image (Error);
      end if;

      loop
         Rounds := Rounds + 1;
         if Rounds > 16 then
            return "the engines did not converge";
         end if;

         declare
            Forward : constant Byte_Index := Pump (Client, Server);
            Back    : constant Byte_Index := Pump (Server, Client);
         begin
            if SSL.Errors.Is_Error (Error) then
               return "an engine refused during the handshake: "
                      & SSL.Errors.Image (Error);
            end if;
            exit when Forward = 0 and then Back = 0;
         end;
      end loop;

      if Engines.State_Of (Server) /= Engines.Established then
         return "the server engine did not establish";
      end if;

      --  Far more than the queue is wide, written by a sender that is not
      --  narrow, into a reader that never reads. What the reader holds
      --  afterwards is its queue.
      declare
         Payload  : constant Byte_Array (1 .. 8 * Room) := [others => 16#3C#];
         Accepted : Byte_Index;
         Sent     : Byte_Index := 0;
         Ignored  : Byte_Index;
      begin
         for Turn in 1 .. 64 loop
            exit when Sent >= Payload'Length;

            Engines.Write_Plaintext
              (Client, Payload (Sent + 1 .. Payload'Last), Accepted, Error);
            if SSL.Errors.Is_Error (Error) then
               return "writing failed: " & SSL.Errors.Image (Error);
            end if;
            Sent := Sent + Accepted;

            Ignored := Pump (Client, Server);
            if SSL.Errors.Is_Error (Error) then
               return "the server failed while filling: "
                      & SSL.Errors.Image (Error);
            end if;
         end loop;

         if Engines.Pending_Plaintext (Server) = 0 then
            return "a reader that was sent eight queues' worth holds some of it";
         end if;

         if Engines.Pending_Plaintext (Server) > Byte_Index (Room) then
            return "a reader holds no more plaintext than its configured"
                   & " queue: it holds"
                   & Byte_Index'Image (Engines.Pending_Plaintext (Server))
                   & " with a queue of" & Natural'Image (Room);
         end if;
      end;

      Engines.Wipe (Client);
      Engines.Wipe (Server);
      return "";
   end Check_A_Configured_Queue_Is_The_Boundary;

   ------------------------------------------------
   -- Check_A_Queue_Of_One_Record_Still_Moves --
   ------------------------------------------------

   Narrow_To_Server : aliased Tests_Pipes.Pipe;
   Narrow_To_Client : aliased Tests_Pipes.Pipe;
   Narrow_Client    : aliased Tests_Pipes.Pipe_Transport;
   Narrow_Server    : aliased Tests_Pipes.Pipe_Transport;

   Narrow_Anchors      : aliased SSL.Trust.Snapshot;
   Narrow_Credential   : aliased SSL.Credentials.Credential;
   Narrow_Client_Setup : aliased SSL.Configurations.Client_Configuration;
   Narrow_Server_Setup : aliased SSL.Configurations.Server_Configuration;

   function Check_A_Queue_Of_One_Record_Still_Moves return String is
      package Config renames SSL.Configurations;
      package Conn renames SSL.Connections;

      Now : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);

      --  The smallest plaintext queue SSL.Limits.Is_Valid accepts: exactly one
      --  plaintext record. A protected record carrying one is longer than that
      --  -- the tag, the inner content type and any padding are inside it --
      --  so an endpoint measuring room by the ciphertext length finds an empty
      --  queue too small and waits for it to drain.
      Narrow : SSL.Limits.Resource_Limits := SSL.Limits.Default_Limits;

      Client : Conn.Connection;
      Server : Conn.Connection;
      Error  : SSL.Errors.Error_Information;
      Ok     : Boolean;
      Moved  : Boolean;
      Rounds : Natural := 0;
   begin
      Narrow.Maximum_Plaintext_Queue := SSL.Limits.Protocol_Plaintext_Record_Limit;

      if not SSL.Limits.Is_Valid (Narrow) then
         return "a queue of one plaintext record is a configuration this"
                & " library accepts, and this one was refused";
      end if;

      Tests_Pipes.Reset (Narrow_To_Server);
      Tests_Pipes.Reset (Narrow_To_Client);
      Tests_Pipes.Attach
        (Narrow_Client, Narrow_To_Server'Access, Narrow_To_Client'Access, 'c');
      Tests_Pipes.Attach
        (Narrow_Server, Narrow_To_Client'Access, Narrow_To_Server'Access, 's');

      SSL.Trust.Load_Explicit_Anchors
        (Narrow_Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load";
      end if;

      SSL.Credentials.Load_PEM
        (Narrow_Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the credential fixture did not load";
      end if;

      declare
         Builder : Config.Client_Builder;
      begin
         Config.Secure_Client_Defaults (Builder);
         Config.Set_Expected_Name
           (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
         Config.Set_Anchors (Builder, Narrow_Anchors'Access, Ok);
         Config.Build (Builder, Narrow_Client_Setup, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client configuration did not build";
         end if;
      end;

      declare
         Builder : Config.Server_Builder;
      begin
         Config.Secure_Server_Defaults (Builder);
         Config.Add_Credential (Builder, Narrow_Credential'Access, Ok);

         --  Only the reader is narrow. The sender keeps the defaults, so what
         --  arrives is a full-size record rather than one the sender happened
         --  to cut small.
         Config.Set_Limits (Builder, Narrow, Ok);
         if not Ok then
            return "the server would not take a queue of one record";
         end if;

         Config.Build (Builder, Narrow_Server_Setup, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server configuration did not build";
         end if;
      end;

      SSL.Servers.Accept_Connection
        (Item     => Server,
         Config   => Narrow_Server_Setup'Access,
         Medium   => Narrow_Server'Unchecked_Access,
         Identity => SSL.No_Connection,
         Now      => Now,
         Error    => Error);
      if SSL.Errors.Is_Error (Error) then
         return "the server connection did not start: " & SSL.Errors.Image (Error);
      end if;

      SSL.Clients.Connect
        (Item     => Client,
         Config   => Narrow_Client_Setup'Access,
         Medium   => Narrow_Client'Unchecked_Access,
         Identity => SSL.No_Connection,
         Now      => Now,
         Error    => Error);
      if SSL.Errors.Is_Error (Error) then
         return "the client connection did not start: " & SSL.Errors.Image (Error);
      end if;

      loop
         Rounds := Rounds + 1;
         if Rounds > 4_000 then
            return "the connections did not converge with a narrow queue";
         end if;

         Conn.Step (Client, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client failed: " & SSL.Errors.Image (Error);
         end if;

         Conn.Step (Server, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server failed: " & SSL.Errors.Image (Error);
         end if;

         exit when Conn.Is_Established (Client) and then Conn.Is_Established (Server);
      end loop;

      --  A full record's worth, so the ciphertext is longer than the reader's
      --  whole queue. Anything smaller fits either way and proves nothing.
      declare
         Payload  : Byte_Array (1 .. SSL.Limits.Protocol_Plaintext_Record_Limit);
         Landed   : Byte_Array (1 .. Payload'Length) := [others => 0];
         Accepted : Byte_Index;
         Sent     : Byte_Index := 0;
         Received : Byte_Index := 0;
      begin
         for Index in Payload'Range loop
            Payload (Index) := Byte ((Natural (Index) * 11 + 5) mod 256);
         end loop;

         Rounds := 0;
         while Received < Payload'Length loop
            Rounds := Rounds + 1;

            --  Bounded, because the failure this guards against is a stall:
            --  an endpoint that will not open a record until a queue it is
            --  not draining has drained. A test that waited for it would hang
            --  a suite instead of naming it.
            if Rounds > 20_000 then
               return "a full-size record did not reach a reader whose queue"
                      & " is one record wide: sent" & Byte_Index'Image (Sent)
                      & ", received" & Byte_Index'Image (Received);
            end if;

            if Sent < Payload'Length then
               Conn.Write_Available
                 (Client, Payload (Sent + 1 .. Payload'Last), Accepted, Error);
               if SSL.Errors.Is_Error (Error) then
                  return "writing failed: " & SSL.Errors.Image (Error);
               end if;
               Sent := Sent + Accepted;
            end if;

            Conn.Step (Client, Moved, Error);
            if SSL.Errors.Is_Error (Error) then
               return "the client failed while sending: " & SSL.Errors.Image (Error);
            end if;

            Conn.Step (Server, Moved, Error);
            if SSL.Errors.Is_Error (Error) then
               return "the server failed while receiving: " & SSL.Errors.Image (Error);
            end if;

            declare
               Chunk : Byte_Array (1 .. 4_096) := [others => 0];
               Count : Byte_Index;
            begin
               Conn.Read_Available (Server, Chunk, Count, Error);
               if SSL.Errors.Is_Error (Error) then
                  return "the server failed while reading: " & SSL.Errors.Image (Error);
               end if;

               if Count > 0 then
                  Landed (Received + 1 .. Received + Count) := Chunk (1 .. Count);
                  Received := Received + Count;
               end if;
            end;
         end loop;

         if Landed /= Payload then
            return "a full-size record did not arrive intact through a narrow queue";
         end if;
      end;

      Conn.Wipe (Client);
      Conn.Wipe (Server);
      return "";
   end Check_A_Queue_Of_One_Record_Still_Moves;

   -------------------------------------
   -- Check_Truncation_Detected --
   -------------------------------------

   Truncation_To_Server : aliased Tests_Pipes.Pipe;
   Truncation_To_Client : aliased Tests_Pipes.Pipe;
   Truncation_Client    : aliased Tests_Pipes.Pipe_Transport;
   Truncation_Server    : aliased Tests_Pipes.Pipe_Transport;

   function Check_Truncation_Detected return String is
      package Conn renames SSL.Connections;

      Now    : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);
      Client : Conn.Connection;
      Server : Conn.Connection;
      Error  : SSL.Errors.Error_Information;
      Moved  : Boolean;
      Rounds : Natural := 0;
   begin
      --  The configurations and fixtures the previous check built are reused:
      --  they are immutable after Build, which is the property that makes
      --  sharing them between connections correct.
      Tests_Pipes.Reset (Truncation_To_Server);
      Tests_Pipes.Reset (Truncation_To_Client);
      Tests_Pipes.Attach
        (Truncation_Client, Truncation_To_Server'Access, Truncation_To_Client'Access, 'C');
      Tests_Pipes.Attach
        (Truncation_Server, Truncation_To_Client'Access, Truncation_To_Server'Access, 'S');

      SSL.Servers.Accept_Connection
        (Server, Pipe_Server_Setup'Access, Truncation_Server'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the server connection did not start";
      end if;
      SSL.Clients.Connect
        (Client, Pipe_Client_Setup'Access, Truncation_Client'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the client connection did not start";
      end if;

      loop
         Rounds := Rounds + 1;
         if Rounds > 2_000 then
            return "the connections did not converge";
         end if;
         Conn.Step (Client, Moved, Error);
         Conn.Step (Server, Moved, Error);
         exit when Conn.Is_Established (Client) and then Conn.Is_Established (Server);
      end loop;

      --  The transport ends without a close_notify, which is what an attacker
      --  who can cut a connection produces. It has to be distinguishable from
      --  an orderly close, because in an application protocol with no length of
      --  its own the two would otherwise look the same.
      Tests_Pipes.Close_Incoming (Truncation_Client);

      Rounds := 0;
      loop
         Rounds := Rounds + 1;
         if Rounds > 100 then
            return "the truncation was never noticed";
         end if;
         Conn.Step (Client, Moved, Error);
         exit when Conn.Is_Terminal (Client);
      end loop;

      if not Conn.Was_Truncated (Client) then
         return "a stream that ended without close_notify is a truncation";
      end if;
      if SSL.Errors.Code_Of (Conn.Failure_Of (Client))
         /= SSL.Errors.Code_Transport_Truncated
      then
         return Report ("failure", "transport truncated",
                        SSL.Errors.Image (Conn.Failure_Of (Client)));
      end if;

      Conn.Wipe (Client);
      Conn.Wipe (Server);
      return "";
   end Check_Truncation_Detected;


   ---------------------------------------------------------------------------
   --  KeyUpdate, exporters and channel bindings on a live connection
   ---------------------------------------------------------------------------

   Post_To_Server : aliased Tests_Pipes.Pipe;
   Post_To_Client : aliased Tests_Pipes.Pipe;
   Post_Client    : aliased Tests_Pipes.Pipe_Transport;
   Post_Server    : aliased Tests_Pipes.Pipe_Transport;

   ------------------------------------
   -- Check_Post_Handshake --
   ------------------------------------

   function Check_Post_Handshake return String is
      package Conn renames SSL.Connections;

      Now    : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);
      Client : Conn.Connection;
      Server : Conn.Connection;
      Error  : SSL.Errors.Error_Information;
      Moved  : Boolean;
      Rounds : Natural;

      --  Settle both ends: step until neither has anything queued.
      function Settle (Limit : Natural) return Boolean;

      function Settle (Limit : Natural) return Boolean is
         Count : Natural := 0;
      begin
         loop
            Count := Count + 1;
            if Count > Limit then
               return False;
            end if;
            Conn.Step (Client, Moved, Error);
            if SSL.Errors.Is_Error (Error) then
               return False;
            end if;
            Conn.Step (Server, Moved, Error);
            if SSL.Errors.Is_Error (Error) then
               return False;
            end if;
            exit when not Conn.Ready (Client).Wants_Transport_Write
              and then not Conn.Ready (Server).Wants_Transport_Write
              and then Count > 4;
         end loop;
         return True;
      end Settle;
   begin
      Tests_Pipes.Reset (Post_To_Server);
      Tests_Pipes.Reset (Post_To_Client);
      Tests_Pipes.Attach (Post_Client, Post_To_Server'Access, Post_To_Client'Access, 'k');
      Tests_Pipes.Attach (Post_Server, Post_To_Client'Access, Post_To_Server'Access, 'K');

      SSL.Servers.Accept_Connection
        (Server, Pipe_Server_Setup'Access, Post_Server'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the server connection did not start";
      end if;
      SSL.Clients.Connect
        (Client, Pipe_Client_Setup'Access, Post_Client'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the client connection did not start";
      end if;

      Rounds := 0;
      loop
         Rounds := Rounds + 1;
         if Rounds > 2_000 then
            return "the connections did not converge";
         end if;
         Conn.Step (Client, Moved, Error);
         Conn.Step (Server, Moved, Error);
         exit when Conn.Is_Established (Client) and then Conn.Is_Established (Server);
      end loop;

      --  Exporters. The two ends must agree, and different labels and different
      --  context-presence must give different material.
      declare
         Client_Side : Byte_Array (1 .. 48) := [others => 0];
         Server_Side : Byte_Array (1 .. 48) := [others => 0];
         Other_Label : Byte_Array (1 .. 48) := [others => 0];
         No_Context  : Byte_Array (1 .. 48) := [others => 0];
         With_Empty  : Byte_Array (1 .. 48) := [others => 0];
      begin
         SSL.Exporters.Export (Client, "ssllib test label", Client_Side, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client could not export: " & SSL.Errors.Image (Error);
         end if;
         SSL.Exporters.Export (Server, "ssllib test label", Server_Side, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server could not export: " & SSL.Errors.Image (Error);
         end if;
         if Client_Side /= Server_Side then
            return "the two ends must export the same material under one label";
         end if;

         SSL.Exporters.Export (Client, "ssllib other label", Other_Label, Error);
         if Other_Label = Client_Side then
            return "a different label must give different material";
         end if;

         --  Under TLS 1.3 an absent context and an empty one give the same
         --  output, because RFC 8446 section 7.5 defines the absent case as the
         --  empty string. Asserted rather than assumed: the flag exists for
         --  TLS 1.2's exporter, where RFC 5705 does distinguish them, and a
         --  reader could reasonably expect it to matter here too.
         SSL.Exporters.Export (Client, "ssllib test label", No_Context, Error);
         SSL.Exporters.Export
           (Client, "ssllib test label", Empty_Bytes, True, With_Empty, Error);
         if No_Context /= With_Empty then
            return "under TLS 1.3 an absent context is the empty one";
         end if;

         --  A context that is not empty does change the output, which is what
         --  makes the parameter worth having at all.
         declare
            Real_Context : Byte_Array (1 .. 48) := [others => 0];
         begin
            SSL.Exporters.Export
              (Client, "ssllib test label", [1 .. 4 => 16#AB#], True, Real_Context, Error);
            if Real_Context = No_Context then
               return "a non-empty context must change the output";
            end if;
         end;
      end;

      --  Channel bindings. The exporter binding must agree across the
      --  connection; the end-point binding must be the peer's certificate.
      declare
         Client_Bind : Byte_Array (1 .. SSL.Channel_Bindings.Exporter_Binding_Length) :=
           [others => 0];
         Server_Bind : Byte_Array (1 .. SSL.Channel_Bindings.Exporter_Binding_Length) :=
           [others => 0];
         End_Point   : Byte_Array (1 .. SSL.Channel_Bindings.End_Point_Binding_Length) :=
           [others => 0];
      begin
         SSL.Channel_Bindings.Exporter_Binding (Client, Client_Bind, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client could not produce a tls-exporter binding";
         end if;
         SSL.Channel_Bindings.Exporter_Binding (Server, Server_Bind, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server could not produce a tls-exporter binding";
         end if;
         if Client_Bind /= Server_Bind then
            return "a channel binding that differed between the ends would bind nothing";
         end if;

         SSL.Channel_Bindings.End_Point_Binding (Client, End_Point, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client could not produce a tls-server-end-point binding";
         end if;
         if End_Point
            /= SSL.Digest_Of
                 (SSL.Connection_Metadata.Peer_Certificate_Fingerprint
                    (Conn.Metadata_Of (Client)))
         then
            return "the end-point binding is the peer certificate's digest";
         end if;

         --  A server that asked for no client certificate has no peer
         --  certificate to bind to, and must say so rather than invent one.
         SSL.Channel_Bindings.End_Point_Binding (Server, End_Point, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "an anonymous peer has no end-point binding";
         end if;
      end;

      --  KeyUpdate. The client asks, the server must answer, and data must
      --  keep flowing across the change in both directions.
      declare
         Before_Write : constant Natural := Conn.Write_Generation (Client);
         Before_Read  : constant Natural := Conn.Read_Generation (Server);
         Payload      : constant Byte_Array := [1 .. 300 => 16#3C#];
         Accepted     : Byte_Index;
         Chunk        : Byte_Array (1 .. 1_024) := [others => 0];
         Count        : Byte_Index;
      begin
         Conn.Request_Key_Update (Client, Ask_Peer => True, Error => Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client could not request a key update: " & SSL.Errors.Image (Error);
         end if;

         if Conn.Write_Generation (Client) /= Before_Write + 1 then
            return "a KeyUpdate replaces the sender's own write key";
         end if;

         if not Settle (500) then
            return "the key update did not settle: " & SSL.Errors.Image (Error);
         end if;

         if Conn.Read_Generation (Server) /= Before_Read + 1 then
            return "the receiver's read key must follow the sender's write key";
         end if;
         if Conn.Peer_Key_Updates (Server) /= 1 then
            return "the server saw one KeyUpdate";
         end if;

         --  The server was asked to update, so it must have sent one back and
         --  the client must have followed it.
         if Conn.Peer_Key_Updates (Client) /= 1 then
            return "an update_requested must be answered";
         end if;

         --  And the connection still works, in both directions, under the new
         --  keys. This is the check that would catch installing the new key
         --  before sending the message rather than after.
         --
         --  Each direction is driven until the octets actually arrive rather
         --  than until the connections look idle: an idle-looking pair can
         --  still have a record sitting in the pipe that nobody has read.
         Conn.Write_Available (Client, Payload, Accepted, Error);
         if SSL.Errors.Is_Error (Error) or else Accepted /= Payload'Length then
            return "the client could not write after a key update";
         end if;

         Count := 0;
         Rounds := 0;
         while Count = 0 loop
            Rounds := Rounds + 1;
            if Rounds > 500 then
               return "data after the key update did not arrive";
            end if;
            Conn.Step (Client, Moved, Error);
            Conn.Step (Server, Moved, Error);
            if SSL.Errors.Is_Error (Error) then
               return "a connection failed after the key update: "
                 & SSL.Errors.Image (Error);
            end if;
            Conn.Read_Available (Server, Chunk, Count, Error);
         end loop;
         if Chunk (1 .. Count) /= Payload then
            return "data written after a key update must arrive intact";
         end if;

         Conn.Write_Available (Server, Payload, Accepted, Error);
         if SSL.Errors.Is_Error (Error) or else Accepted /= Payload'Length then
            return "the server could not write after a key update";
         end if;

         Count := 0;
         Rounds := 0;
         while Count = 0 loop
            Rounds := Rounds + 1;
            if Rounds > 500 then
               return "the reply after the key update did not arrive";
            end if;
            Conn.Step (Server, Moved, Error);
            Conn.Step (Client, Moved, Error);
            if SSL.Errors.Is_Error (Error) then
               return "a connection failed after the reply: " & SSL.Errors.Image (Error);
            end if;
            Conn.Read_Available (Client, Chunk, Count, Error);
         end loop;
         if Chunk (1 .. Count) /= Payload then
            return "the reply after a key update must arrive intact";
         end if;
      end;

      Conn.Wipe (Client);
      Conn.Wipe (Server);
      return "";
   end Check_Post_Handshake;


   ---------------------------------------------------------------------------
   --  Tickets: a server issues, a client keeps
   ---------------------------------------------------------------------------

   Ticket_Ring   : aliased SSL.Ticket_Keys.Ring;
   Ticket_Cache  : aliased SSL.Sessions.Client_Caches.Memory.Memory_Cache (Capacity => 4);
   Ticket_Client : aliased SSL.Configurations.Client_Configuration;
   Ticket_Server : aliased SSL.Configurations.Server_Configuration;

   Ticket_To_Server : aliased Tests_Pipes.Pipe;
   Ticket_To_Client : aliased Tests_Pipes.Pipe;
   Ticket_Client_Medium : aliased Tests_Pipes.Pipe_Transport;
   Ticket_Server_Medium : aliased Tests_Pipes.Pipe_Transport;

   ---------------------------
   -- Check_Ticket_Issue --
   ---------------------------

   function Check_Ticket_Issue return String is
      package Conn renames SSL.Connections;
      package Config renames SSL.Configurations;
      package Sessions renames SSL.Sessions;

      Now    : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);
      Client : Conn.Connection;
      Server : Conn.Connection;
      Error  : SSL.Errors.Error_Information;
      Ok     : Boolean;
      Moved  : Boolean;
      Rounds : Natural := 0;
   begin
      --  A ring with no key issues nothing, and a configuration that asks for
      --  tickets without one is refused at Build. Both are checked before the
      --  key is generated, because both are the states a deployment actually
      --  reaches.
      if SSL.Ticket_Keys.Has_Active_Key (Ticket_Ring) then
         return "a fresh ring has no active key";
      end if;

      declare
         Builder : Config.Server_Builder;
         Attempt : SSL.Configurations.Server_Configuration;
      begin
         Config.Secure_Server_Defaults (Builder);
         Config.Add_Credential (Builder, Pipe_Credential'Access, Ok);
         Config.Set_Ticket_Issuance (Builder, True);
         Config.Build (Builder, Attempt, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "ticket issuance without keys must be refused at Build";
         end if;
         if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_Ticket_Issuance_Without_Key then
            return Report ("refusal", "ticket issuance without key",
                           SSL.Errors.Image (Error));
         end if;
      end;

      SSL.Ticket_Keys.Rotate (Ticket_Ring, 86_400, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the ring could not rotate: " & SSL.Errors.Image (Error);
      end if;
      if not SSL.Ticket_Keys.Has_Active_Key (Ticket_Ring) then
         return "a rotated ring has an active key";
      end if;
      if SSL.Ticket_Keys.Key_Count (Ticket_Ring) /= 1 then
         return "one rotation gives one key";
      end if;

      --  Rotating again keeps the old key so that tickets already issued still
      --  open. A rotation that cut them all off would turn a routine operation
      --  into a thundering herd of full handshakes.
      SSL.Ticket_Keys.Rotate (Ticket_Ring, 86_400, Now, Error);
      if SSL.Ticket_Keys.Key_Count (Ticket_Ring) /= 2 then
         return "rotating keeps the previous key for decryption";
      end if;

      declare
         Builder : Config.Server_Builder;
      begin
         Config.Secure_Server_Defaults (Builder);
         Config.Add_Credential (Builder, Pipe_Credential'Access, Ok);
         Config.Set_Ticket_Keys (Builder, Ticket_Ring'Access);
         Config.Set_Ticket_Issuance (Builder, True);
         Config.Build (Builder, Ticket_Server, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      declare
         Builder : Config.Client_Builder;
      begin
         Config.Secure_Client_Defaults (Builder);
         Config.Set_Expected_Name
           (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
         Config.Set_Anchors (Builder, Pipe_Anchors'Access, Ok);
         Config.Set_Session_Cache (Builder, Ticket_Cache'Unchecked_Access);
         Config.Build (Builder, Ticket_Client, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      Tests_Pipes.Reset (Ticket_To_Server);
      Tests_Pipes.Reset (Ticket_To_Client);
      Tests_Pipes.Attach
        (Ticket_Client_Medium, Ticket_To_Server'Access, Ticket_To_Client'Access, 't');
      Tests_Pipes.Attach
        (Ticket_Server_Medium, Ticket_To_Client'Access, Ticket_To_Server'Access, 'T');

      SSL.Servers.Accept_Connection
        (Server, Ticket_Server'Access, Ticket_Server_Medium'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      SSL.Clients.Connect
        (Client, Ticket_Client'Access, Ticket_Client_Medium'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the connections did not start";
      end if;

      loop
         Rounds := Rounds + 1;
         if Rounds > 2_000 then
            return "the connections did not converge";
         end if;
         Conn.Step (Client, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client failed: " & SSL.Errors.Image (Error);
         end if;
         Conn.Step (Server, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server failed: " & SSL.Errors.Image (Error);
         end if;
         exit when Conn.Is_Established (Client) and then Conn.Is_Established (Server);
      end loop;

      --  The tickets go out with the flight that completes the handshake, so
      --  the client has them without having sent anything. Driving a little
      --  further lets them arrive.
      Rounds := 0;
      while SSL.Sessions.Client_Caches.Memory.Occupancy (Ticket_Cache) = 0 loop
         Rounds := Rounds + 1;
         if Rounds > 500 then
            return "no ticket reached the client's cache";
         end if;
         Conn.Step (Server, Moved, Error);
         Conn.Step (Client, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return "a connection failed while the tickets travelled: "
              & SSL.Errors.Image (Error);
         end if;
      end loop;

      --  Two tickets are issued, and the cache keeps one entry per name and
      --  context -- so the second replaces the first rather than accumulating.
      if SSL.Sessions.Client_Caches.Memory.Occupancy (Ticket_Cache) /= 1 then
         return Report ("cached sessions", "1",
                        Natural'Image
                          (SSL.Sessions.Client_Caches.Memory.Occupancy (Ticket_Cache)));
      end if;

      --  What the cache holds must be bound to this connection.
      declare
         Held  : Sessions.Session;
         Found : Boolean;
      begin
         SSL.Sessions.Client_Caches.Memory.Look_Up
           (Item    => Ticket_Cache,
            Name    => SSL.Server_Names.Name ("www.example.com"),
            Context => SSL.Default_Security_Context,
            At_Time => Now,
            Into    => Held,
            Found   => Found);
         if not Found then
            return "the cached session is found under the name it was issued for";
         end if;

         if not Sessions.Is_Live (Held, Now) then
            return "a session issued now is live now";
         end if;
         if Sessions.Cipher_Suite (Held)
            /= SSL.Connection_Metadata.Cipher_Suite (Conn.Metadata_Of (Client))
         then
            return "the session records the suite the connection negotiated";
         end if;
         if not Sessions.Peer_Authenticated (Held) then
            return "the session records that the server authenticated";
         end if;

         --  A ticket is single-use: taking it out of the cache removes it, so
         --  that offering the same one twice cannot make two connections
         --  linkable to an observer.
         if SSL.Sessions.Client_Caches.Memory.Occupancy (Ticket_Cache) /= 0 then
            return "a session handed out is a session removed";
         end if;

         --  It must not be offered where a binding differs. A different
         --  security context is the sharpest of these: it is the application's
         --  own statement that two connections belong to different domains.
         if Sessions.Matches
              (Item    => Held,
               Name    => SSL.Server_Names.Name ("www.example.com"),
               Context => SSL.Security_Context ("another domain"),
               Setup   => Sessions.Configuration (Held),
               Anchors => Sessions.Trust (Held),
               At_Time => Now)
         then
            return "a session must not match a different security context";
         end if;

         if Sessions.Matches
              (Item    => Held,
               Name    => SSL.Server_Names.Name ("other.example.com"),
               Context => Sessions.Security_Context (Held),
               Setup   => Sessions.Configuration (Held),
               Anchors => Sessions.Trust (Held),
               At_Time => Now)
         then
            return "a session must not match a different server name";
         end if;

         if not Sessions.Matches
                  (Item    => Held,
                   Name    => SSL.Server_Names.Name ("www.example.com"),
                   Context => Sessions.Security_Context (Held),
                   Setup   => Sessions.Configuration (Held),
                   Anchors => Sessions.Trust (Held),
                   At_Time => Now)
         then
            return "a session must match the connection it was issued for";
         end if;

         --  And it must not match after it has run out.
         if Sessions.Matches
              (Item    => Held,
               Name    => SSL.Server_Names.Name ("www.example.com"),
               Context => Sessions.Security_Context (Held),
               Setup   => Sessions.Configuration (Held),
               Anchors => Sessions.Trust (Held),
               At_Time => SSL.Clocks.UTC (2027, 1, 1))
         then
            return "an expired session must not match";
         end if;

         Sessions.Wipe (Held);
      end;

      Conn.Wipe (Client);
      Conn.Wipe (Server);
      return "";
   end Check_Ticket_Issue;


   -------------------------------
   -- Check_Resumption --
   -------------------------------

   Resume_To_Server : aliased Tests_Pipes.Pipe;
   Resume_To_Client : aliased Tests_Pipes.Pipe;
   Resume_Client_Medium : aliased Tests_Pipes.Pipe_Transport;
   Resume_Server_Medium : aliased Tests_Pipes.Pipe_Transport;

   function Check_Resumption return String is
      package Conn renames SSL.Connections;
      package Meta renames SSL.Connection_Metadata;

      Now : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);

      Error  : SSL.Errors.Error_Information;
      Moved  : Boolean;
      Rounds : Natural;

      --  Run one whole connection over a fresh pair of pipes, driving until the
      --  tickets have had a chance to arrive.
      procedure Connect_Once (Resumed : out Boolean; Diagnostic : out Boolean);

      procedure Connect_Once (Resumed : out Boolean; Diagnostic : out Boolean) is
         Client : Conn.Connection;
         Server : Conn.Connection;
      begin
         Resumed := False;
         Diagnostic := False;

         Tests_Pipes.Reset (Resume_To_Server);
         Tests_Pipes.Reset (Resume_To_Client);
         Tests_Pipes.Attach
           (Resume_Client_Medium, Resume_To_Server'Access, Resume_To_Client'Access, 'r');
         Tests_Pipes.Attach
           (Resume_Server_Medium, Resume_To_Client'Access, Resume_To_Server'Access, 'R');

         SSL.Servers.Accept_Connection
           (Server, Ticket_Server'Access, Resume_Server_Medium'Unchecked_Access,
            SSL.No_Connection, Now, Error);
         SSL.Clients.Connect
           (Client, Ticket_Client'Access, Resume_Client_Medium'Unchecked_Access,
            SSL.No_Connection, Now, Error);
         if SSL.Errors.Is_Error (Error) then
            Diagnostic := True;
            return;
         end if;

         Rounds := 0;
         loop
            Rounds := Rounds + 1;
            if Rounds > 2_000 then
               Diagnostic := True;
               return;
            end if;
            Conn.Step (Client, Moved, Error);
            if SSL.Errors.Is_Error (Error) then
               Diagnostic := True;
               return;
            end if;
            Conn.Step (Server, Moved, Error);
            if SSL.Errors.Is_Error (Error) then
               Diagnostic := True;
               return;
            end if;
            exit when Conn.Is_Established (Client) and then Conn.Is_Established (Server);
         end loop;

         Resumed := Meta.Resumed (Conn.Metadata_Of (Client));

         --  Let the tickets travel, so the next connection has one to offer.
         for Extra in 1 .. 200 loop
            Conn.Step (Server, Moved, Error);
            Conn.Step (Client, Moved, Error);
         end loop;

         Conn.Wipe (Client);
         Conn.Wipe (Server);
      end Connect_Once;

      Resumed : Boolean;
      Broken  : Boolean;
   begin
      --  The first connection cannot resume: the cache is empty because the
      --  previous check took its one session out.
      Connect_Once (Resumed, Broken);
      if Broken then
         return "the first connection failed: " & SSL.Errors.Image (Error);
      end if;
      if Resumed then
         return "the first connection has nothing to resume from";
      end if;

      --  The second one has a ticket and must use it.
      Connect_Once (Resumed, Broken);
      if Broken then
         return "the second connection failed: " & SSL.Errors.Image (Error);
      end if;
      if not Resumed then
         return "the second connection must resume from the first one's ticket";
      end if;

      --  And a third, from the second's ticket, so that resumption is not a
      --  one-off that happens to work once.
      Connect_Once (Resumed, Broken);
      if Broken then
         return "the third connection failed: " & SSL.Errors.Image (Error);
      end if;
      if not Resumed then
         return "a resumed connection issues tickets of its own";
      end if;

      return "";
   end Check_Resumption;


   ---------------------------------------------------------------------------
   --  Restricted TLS 1.2, client machine against server machine
   ---------------------------------------------------------------------------

   Legacy_Anchors    : aliased SSL.Trust.Snapshot;
   Legacy_Credential : aliased SSL.Credentials.Credential;
   Legacy_Client_Setup : aliased SSL.Configurations.Client_Configuration;
   Legacy_Server_Setup : aliased SSL.Configurations.Server_Configuration;

   --------------------------------
   -- Check_TLS12_Handshake --
   --------------------------------

   function Check_TLS12_Handshake return String is
      package Config renames SSL.Configurations;
      package Legacy_Client renames SSL.TLS12.Client;
      package Legacy_Server renames SSL.TLS12.Server;

      use type SSL.TLS12.Step_Kind;
      use type SSL.TLS12.Client.Client_State;
      use type SSL.TLS12.Server.Server_State;
      use type SSL.Cipher_Suites.Cipher_Suite;
      use type SSL.Supported_Groups.Named_Group;

      Now : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);

      Error : SSL.Errors.Error_Information;
      Ok    : Boolean;

      Client_Random : SSL.Crypto.Random_Source;
      Server_Random : SSL.Crypto.Random_Source;

      Client_Machine : aliased Legacy_Client.Machine;
      Server_Machine : aliased Legacy_Server.Machine;

      Client_Out : Byte_Array (1 .. 16_384) := [others => 0];
      Server_Out : Byte_Array (1 .. 16_384) := [others => 0];

      Maximum_Queued : constant := 16;
      type Queued_Message is record
         Length : Byte_Index := 0;
         Octets : Byte_Array (1 .. 8_192) := [others => 0];
      end record;
      type Message_Queue is array (1 .. Maximum_Queued) of Queued_Message;

      Queue : Message_Queue;
      Count : Natural := 0;

      --  A ChangeCipherSpec is not a handshake message, so it is not queued
      --  with them: it is a marker in the stream that says "everything after
      --  this is under the new keys". Recorded as a position, with a separate
      --  flag because position zero is a real position -- a flight can begin
      --  with the epoch switch, and a Natural alone cannot say the difference
      --  between "before the first message" and "not in this batch".
      CCS_Present : Boolean := False;
      CCS_After   : Natural := 0;

      Client_Done : Boolean := False;
      Server_Done : Boolean := False;

      Client_Write : SSL.TLS12.Records.Traffic_State;
      Client_Read  : SSL.TLS12.Records.Traffic_State;
      Server_Write : SSL.TLS12.Records.Traffic_State;
      Server_Read  : SSL.TLS12.Records.Traffic_State;

      Failed : Boolean := False;

      procedure Collect
        (Result : SSL.TLS12.Plan;
         Buffer : Byte_Array;
         Done   : in out Boolean;
         Client : Boolean);

      procedure Collect
        (Result : SSL.TLS12.Plan;
         Buffer : Byte_Array;
         Done   : in out Boolean;
         Client : Boolean)
      is
      begin
         for Index in 1 .. Result.Count loop
            case Result.Steps (Index).Kind is
               when SSL.TLS12.Send_Handshake =>
                  if Count = Maximum_Queued then
                     Failed := True;
                     return;
                  end if;
                  Count := Count + 1;
                  Queue (Count).Length :=
                    Result.Steps (Index).Last - Result.Steps (Index).First + 1;
                  Queue (Count).Octets (1 .. Queue (Count).Length) :=
                    Buffer (Result.Steps (Index).First .. Result.Steps (Index).Last);

               when SSL.TLS12.Send_Change_Cipher_Spec =>
                  --  Everything queued after this point is under the new keys.
                  CCS_Present := True;
                  CCS_After := Count;

               when SSL.TLS12.Install_Write_Keys =>
                  if Client then
                     SSL.TLS12.Records.Install
                       (Client_Write, Legacy_Client.Cipher_Suite (Client_Machine),
                        Legacy_Client.Client_Keys (Client_Machine).all);
                  else
                     SSL.TLS12.Records.Install
                       (Server_Write, Legacy_Server.Cipher_Suite (Server_Machine),
                        Legacy_Server.Server_Keys (Server_Machine).all);
                  end if;

               when SSL.TLS12.Install_Read_Keys =>
                  if Client then
                     SSL.TLS12.Records.Install
                       (Client_Read, Legacy_Client.Cipher_Suite (Client_Machine),
                        Legacy_Client.Server_Keys (Client_Machine).all);
                  else
                     SSL.TLS12.Records.Install
                       (Server_Read, Legacy_Server.Cipher_Suite (Server_Machine),
                        Legacy_Server.Client_Keys (Server_Machine).all);
                  end if;

               when SSL.TLS12.Handshake_Complete =>
                  Done := True;
            end case;
         end loop;
      end Collect;

      Rounds : Natural := 0;
   begin
      SSL.Crypto.Use_Fixed_Pattern (Client_Random, [16#21#, 16#43#, 16#65#, 16#87#, 16#A9#]);
      SSL.Crypto.Use_Fixed_Pattern
        (Server_Random, [16#B1#, 16#C2#, 16#D3#, 16#E4#, 16#F5#, 16#16#, 16#27#]);

      SSL.Trust.Load_Explicit_Anchors
        (Legacy_Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load";
      end if;
      SSL.Credentials.Load_PEM
        (Legacy_Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the credential fixture did not load";
      end if;

      --  Modern compatibility: TLS 1.3 and restricted TLS 1.2. The TLS 1.2
      --  suites are only present in a configuration that asked for them.
      declare
         Builder : Config.Client_Builder;
      begin
         Config.Modern_Compatibility_Client (Builder);
         Config.Set_Expected_Name
           (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
         Config.Set_Anchors (Builder, Legacy_Anchors'Access, Ok);
         Config.Build (Builder, Legacy_Client_Setup, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      declare
         Builder : Config.Server_Builder;
      begin
         Config.Modern_Compatibility_Server (Builder);
         Config.Add_Credential (Builder, Legacy_Credential'Access, Ok);
         Config.Build (Builder, Legacy_Server_Setup, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      Legacy_Server.Begin_Handshake
        (Server_Machine, Legacy_Server_Setup'Access, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the server machine did not start: " & SSL.Errors.Image (Error);
      end if;

      declare
         Result : SSL.TLS12.Plan;
      begin
         Legacy_Client.Begin_Handshake
           (Item   => Client_Machine,
            Config => Legacy_Client_Setup'Access,
            Now    => Now,
            Source => Client_Random,
            Into   => Client_Out,
            Result => Result,
            Error  => Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client machine did not start: " & SSL.Errors.Image (Error);
         end if;
         Collect (Result, Client_Out, Client_Done, Client => True);
      end;

      if Count /= 1 then
         return "Begin_Handshake produces exactly one ClientHello";
      end if;

      --  Deliver alternately, honouring the ChangeCipherSpec marker: a batch
      --  that carried one is split, and the peer is told about it in the right
      --  place.
      declare
         To_Server : Boolean := True;
      begin
         while Count > 0 loop
            Rounds := Rounds + 1;
            if Rounds > 12 then
               return "the TLS 1.2 handshake did not converge";
            end if;

            declare
               Pending : constant Natural := Count;
               Batch   : Message_Queue := Queue;
               Switch  : constant Natural := CCS_After;
               Switched : constant Boolean := CCS_Present;
            begin
               Count := 0;
               CCS_After := 0;
               CCS_Present := False;

               for Index in 1 .. Pending loop
                  --  The epoch switch arrives before the message that follows
                  --  it, which is what the record layer sees on the wire.
                  if Switched and then Index = Switch + 1 then
                     declare
                        Result : SSL.TLS12.Plan;
                     begin
                        if To_Server then
                           Legacy_Server.Handle_Change_Cipher_Spec
                             (Server_Machine, Result, Error);
                           Collect (Result, Server_Out, Server_Done, Client => False);
                        else
                           Legacy_Client.Handle_Change_Cipher_Spec
                             (Client_Machine, Result, Error);
                           Collect (Result, Client_Out, Client_Done, Client => True);
                        end if;
                        if SSL.Errors.Is_Error (Error) then
                           return "a ChangeCipherSpec was refused: " & SSL.Errors.Image (Error);
                        end if;
                     end;
                  end if;

                  declare
                     Result : SSL.TLS12.Plan;
                  begin
                     if To_Server then
                        Legacy_Server.Handle_Message
                          (Item    => Server_Machine,
                           Message => Batch (Index).Octets (1 .. Batch (Index).Length),
                           Source  => Server_Random,
                           Into    => Server_Out,
                           Result  => Result,
                           Error   => Error);
                        if SSL.Errors.Is_Error (Error) then
                           return "the server refused a message: " & SSL.Errors.Image (Error);
                        end if;
                        Collect (Result, Server_Out, Server_Done, Client => False);
                     else
                        Legacy_Client.Handle_Message
                          (Item    => Client_Machine,
                           Message => Batch (Index).Octets (1 .. Batch (Index).Length),
                           Source  => Client_Random,
                           Into    => Client_Out,
                           Result  => Result,
                           Error   => Error);
                        if SSL.Errors.Is_Error (Error) then
                           return "the client refused a message: " & SSL.Errors.Image (Error);
                        end if;
                        Collect (Result, Client_Out, Client_Done, Client => True);
                     end if;
                     if Failed then
                        return "the message queue overflowed";
                     end if;
                  end;
               end loop;
            end;

            To_Server := not To_Server;
         end loop;
      end;

      if Legacy_Client.State_Of (Client_Machine) /= Legacy_Client.Connected then
         return "the TLS 1.2 client did not connect: "
           & Legacy_Client.Image (Legacy_Client.State_Of (Client_Machine));
      end if;
      if Legacy_Server.State_Of (Server_Machine) /= Legacy_Server.Connected then
         return "the TLS 1.2 server did not connect: "
           & Legacy_Server.Image (Legacy_Server.State_Of (Server_Machine));
      end if;

      if Legacy_Client.Cipher_Suite (Client_Machine)
         /= Legacy_Server.Cipher_Suite (Server_Machine)
      then
         return "the two ends disagree about the cipher suite";
      end if;
      if Legacy_Client.Group (Client_Machine) /= Legacy_Server.Group (Server_Machine) then
         return "the two ends disagree about the group";
      end if;

      --  The real proof, as in TLS 1.3: a record the client seals must open on
      --  the server. Agreeing about names proves nothing if the key blocks
      --  diverged, and TLS 1.2's key block has an order that is easy to get
      --  backwards.
      declare
         Plaintext   : constant Byte_Array := [1 .. 40 => 16#7B#];
         Sealed      : Byte_Array (1 .. 256) := [others => 0];
         Opened      : Byte_Array (1 .. 256) := [others => 0];
         Sealed_Last : Byte_Index;
         Opened_Last : Byte_Index;
      begin
         SSL.TLS12.Records.Protect
           (Item      => Client_Write,
            Content   => SSL.Records.Application_Content,
            Plaintext => Plaintext,
            Into      => Sealed,
            Written   => Sealed_Last,
            Error     => Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client could not protect a TLS 1.2 record: "
              & SSL.Errors.Image (Error);
         end if;

         SSL.TLS12.Records.Open
           (Item     => Server_Read,
            Header   => Sealed (1 .. SSL.Records.Header_Length),
            Fragment => Sealed (SSL.Records.Header_Length + 1 .. Sealed_Last),
            Into     => Opened,
            Written  => Opened_Last,
            Error    => Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server could not open the client's TLS 1.2 record -- the key "
              & "blocks diverged: " & SSL.Errors.Image (Error);
         end if;
         if Opened (1 .. Opened_Last) /= Plaintext then
            return "the TLS 1.2 record opened to something else";
         end if;

         --  And the other direction, which uses the other half of the key
         --  block: getting the split backwards fails exactly here.
         SSL.TLS12.Records.Protect
           (Item      => Server_Write,
            Content   => SSL.Records.Application_Content,
            Plaintext => Plaintext,
            Into      => Sealed,
            Written   => Sealed_Last,
            Error     => Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server could not protect a TLS 1.2 record";
         end if;

         SSL.TLS12.Records.Open
           (Item     => Client_Read,
            Header   => Sealed (1 .. SSL.Records.Header_Length),
            Fragment => Sealed (SSL.Records.Header_Length + 1 .. Sealed_Last),
            Into     => Opened,
            Written  => Opened_Last,
            Error    => Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client could not open the server's TLS 1.2 record: "
              & SSL.Errors.Image (Error);
         end if;
         if Opened (1 .. Opened_Last) /= Plaintext then
            return "the reply record opened to something else";
         end if;

         --  A flipped bit in the tag must be refused, and must produce no
         --  plaintext at all.
         SSL.TLS12.Records.Protect
           (Item      => Server_Write,
            Content   => SSL.Records.Application_Content,
            Plaintext => Plaintext,
            Into      => Sealed,
            Written   => Sealed_Last,
            Error     => Error);
         Sealed (Sealed_Last) := Sealed (Sealed_Last) xor 1;
         SSL.TLS12.Records.Open
           (Item     => Client_Read,
            Header   => Sealed (1 .. SSL.Records.Header_Length),
            Fragment => Sealed (SSL.Records.Header_Length + 1 .. Sealed_Last),
            Into     => Opened,
            Written  => Opened_Last,
            Error    => Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a flipped tag bit must be refused";
         end if;
         if Opened_Last /= 0 then
            return "a refused record produces no plaintext";
         end if;
      end;

      Legacy_Client.Wipe (Client_Machine);
      Legacy_Server.Wipe (Server_Machine);
      return "";
   end Check_TLS12_Handshake;

   ---------------------------------------------------------------------------
   --  Restricted TLS 1.2 resumption, over stateless tickets
   ---------------------------------------------------------------------------

   Resume_Anchors      : aliased SSL.Trust.Snapshot;
   Resume_Credential   : aliased SSL.Credentials.Credential;
   Resume_Client_Setup : aliased SSL.Configurations.Client_Configuration;
   Resume_Server_Setup : aliased SSL.Configurations.Server_Configuration;
   Resume_Ring         : aliased SSL.Ticket_Keys.Ring;

   ---------------------------------
   -- Check_TLS12_Resumption --
   ---------------------------------

   function Check_TLS12_Resumption return String is
      package Config renames SSL.Configurations;
      package Legacy_Client renames SSL.TLS12.Client;
      package Legacy_Server renames SSL.TLS12.Server;

      use type SSL.TLS12.Step_Kind;
      use type SSL.TLS12.Client.Client_State;
      use type SSL.TLS12.Server.Server_State;
      use type SSL.Cipher_Suites.Cipher_Suite;
      use type SSL.Versions.Protocol_Version;

      Now : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);

      Error : SSL.Errors.Error_Information;
      Ok    : Boolean;

      --  The session the first handshake establishes and the second offers.
      --  Declared out here because it has to outlive both of them, which is the
      --  whole point of a session.
      Kept    : SSL.Sessions.Session;
      Present : Boolean;

      --  One handshake, from the ClientHello to the two Finisheds.
      --
      --  Parameterised by whether to offer the session, so that the full
      --  handshake and the abbreviated one are driven by the same code: a
      --  second copy would be a second place for the delivery order to be
      --  wrong, and the delivery order is what an abbreviated handshake
      --  changes.
      function Run (Offer : Boolean; Resumed : out Boolean) return String;

      function Run (Offer : Boolean; Resumed : out Boolean) return String is
         Client_Random : SSL.Crypto.Random_Source;
         Server_Random : SSL.Crypto.Random_Source;

         Client_Machine : aliased Legacy_Client.Machine;
         Server_Machine : aliased Legacy_Server.Machine;

         Client_Out : Byte_Array (1 .. 16_384) := [others => 0];
         Server_Out : Byte_Array (1 .. 16_384) := [others => 0];

         Maximum_Queued : constant := 16;
         type Queued_Message is record
            Length : Byte_Index := 0;
            Octets : Byte_Array (1 .. 8_192) := [others => 0];
         end record;
         type Message_Queue is array (1 .. Maximum_Queued) of Queued_Message;

         Queue : Message_Queue;
         Count : Natural := 0;

         CCS_Present : Boolean := False;
         CCS_After   : Natural := 0;

         Client_Done : Boolean := False;
         Server_Done : Boolean := False;

         Client_Write : SSL.TLS12.Records.Traffic_State;
         Client_Read  : SSL.TLS12.Records.Traffic_State;
         Server_Write : SSL.TLS12.Records.Traffic_State;
         Server_Read  : SSL.TLS12.Records.Traffic_State;

         Overflowed : Boolean := False;
         Rounds     : Natural := 0;

         procedure Collect
           (Result : SSL.TLS12.Plan;
            Buffer : Byte_Array;
            Done   : in out Boolean;
            Client : Boolean);

         procedure Collect
           (Result : SSL.TLS12.Plan;
            Buffer : Byte_Array;
            Done   : in out Boolean;
            Client : Boolean)
         is
         begin
            for Index in 1 .. Result.Count loop
               case Result.Steps (Index).Kind is
                  when SSL.TLS12.Send_Handshake =>
                     if Count = Maximum_Queued then
                        Overflowed := True;
                        return;
                     end if;
                     Count := Count + 1;
                     Queue (Count).Length :=
                       Result.Steps (Index).Last - Result.Steps (Index).First + 1;
                     Queue (Count).Octets (1 .. Queue (Count).Length) :=
                       Buffer (Result.Steps (Index).First .. Result.Steps (Index).Last);

                  when SSL.TLS12.Send_Change_Cipher_Spec =>
                     CCS_Present := True;
                     CCS_After := Count;

                  when SSL.TLS12.Install_Write_Keys =>
                     if Client then
                        SSL.TLS12.Records.Install
                          (Client_Write, Legacy_Client.Cipher_Suite (Client_Machine),
                           Legacy_Client.Client_Keys (Client_Machine).all);
                     else
                        SSL.TLS12.Records.Install
                          (Server_Write, Legacy_Server.Cipher_Suite (Server_Machine),
                           Legacy_Server.Server_Keys (Server_Machine).all);
                     end if;

                  when SSL.TLS12.Install_Read_Keys =>
                     if Client then
                        SSL.TLS12.Records.Install
                          (Client_Read, Legacy_Client.Cipher_Suite (Client_Machine),
                           Legacy_Client.Server_Keys (Client_Machine).all);
                     else
                        SSL.TLS12.Records.Install
                          (Server_Read, Legacy_Server.Cipher_Suite (Server_Machine),
                           Legacy_Server.Client_Keys (Server_Machine).all);
                     end if;

                  when SSL.TLS12.Handshake_Complete =>
                     Done := True;
               end case;
            end loop;
         end Collect;

      begin
         Resumed := False;

         --  Different randomness in the second handshake, so that a resumption
         --  which only worked because the two randoms happened to repeat would
         --  fail here rather than pass.
         SSL.Crypto.Use_Fixed_Pattern
           (Client_Random,
            (if Offer then [16#31#, 16#53#, 16#75#, 16#97#, 16#B9#]
             else [16#21#, 16#43#, 16#65#, 16#87#, 16#A9#]));
         SSL.Crypto.Use_Fixed_Pattern
           (Server_Random,
            (if Offer then [16#C1#, 16#D2#, 16#E3#, 16#F4#, 16#05#, 16#26#, 16#37#]
             else [16#B1#, 16#C2#, 16#D3#, 16#E4#, 16#F5#, 16#16#, 16#27#]));

         Legacy_Server.Set_Ticket_Keys (Server_Machine, Resume_Ring'Access);
         Legacy_Server.Set_Issues_Tickets (Server_Machine, True);
         Legacy_Server.Begin_Handshake
           (Server_Machine, Resume_Server_Setup'Access, Now, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server machine did not start: " & SSL.Errors.Image (Error);
         end if;

         Legacy_Client.Request_Tickets (Client_Machine, True);
         if Offer then
            Legacy_Client.Offer_Session (Client_Machine, Kept);
            if not Legacy_Client.Offers_Ticket (Client_Machine) then
               return "a client given a session offers a ticket";
            end if;
         end if;

         declare
            Result : SSL.TLS12.Plan;
         begin
            Legacy_Client.Begin_Handshake
              (Item   => Client_Machine,
               Config => Resume_Client_Setup'Access,
               Now    => Now,
               Source => Client_Random,
               Into   => Client_Out,
               Result => Result,
               Error  => Error);
            if SSL.Errors.Is_Error (Error) then
               return "the client machine did not start: " & SSL.Errors.Image (Error);
            end if;
            Collect (Result, Client_Out, Client_Done, Client => True);
         end;

         declare
            To_Server : Boolean := True;
         begin
            while Count > 0 loop
               Rounds := Rounds + 1;
               if Rounds > 12 then
                  return "the handshake did not converge";
               end if;

               declare
                  Pending  : constant Natural := Count;
                  Batch    : Message_Queue := Queue;
                  Switch   : constant Natural := CCS_After;
                  Switched : constant Boolean := CCS_Present;
               begin
                  Count := 0;
                  CCS_After := 0;
                  CCS_Present := False;

                  for Index in 1 .. Pending loop
                     if Switched and then Index = Switch + 1 then
                        declare
                           Result : SSL.TLS12.Plan;
                        begin
                           if To_Server then
                              Legacy_Server.Handle_Change_Cipher_Spec
                                (Server_Machine, Result, Error);
                              Collect (Result, Server_Out, Server_Done, Client => False);
                           else
                              Legacy_Client.Handle_Change_Cipher_Spec
                                (Client_Machine, Result, Error);
                              Collect (Result, Client_Out, Client_Done, Client => True);
                           end if;
                           if SSL.Errors.Is_Error (Error) then
                              return "a ChangeCipherSpec was refused: "
                                & SSL.Errors.Image (Error);
                           end if;
                        end;
                     end if;

                     declare
                        Result : SSL.TLS12.Plan;
                     begin
                        if To_Server then
                           Legacy_Server.Handle_Message
                             (Item    => Server_Machine,
                              Message => Batch (Index).Octets (1 .. Batch (Index).Length),
                              Source  => Server_Random,
                              Into    => Server_Out,
                              Result  => Result,
                              Error   => Error);
                           if SSL.Errors.Is_Error (Error) then
                              return "the server refused a message: "
                                & SSL.Errors.Image (Error);
                           end if;
                           Collect (Result, Server_Out, Server_Done, Client => False);
                        else
                           Legacy_Client.Handle_Message
                             (Item    => Client_Machine,
                              Message => Batch (Index).Octets (1 .. Batch (Index).Length),
                              Source  => Client_Random,
                              Into    => Client_Out,
                              Result  => Result,
                              Error   => Error);
                           if SSL.Errors.Is_Error (Error) then
                              return "the client refused a message: "
                                & SSL.Errors.Image (Error);
                           end if;
                           Collect (Result, Client_Out, Client_Done, Client => True);
                        end if;
                        if Overflowed then
                           return "the message queue overflowed";
                        end if;
                     end;
                  end loop;
               end;

               --  The last flight of an abbreviated handshake is the client's,
               --  and it leaves the queue empty with both ends connected. The
               --  loop stops on an empty queue either way.
               To_Server := not To_Server;
            end loop;
         end;

         if Legacy_Client.State_Of (Client_Machine) /= Legacy_Client.Connected then
            return "the client did not connect: "
              & Legacy_Client.Image (Legacy_Client.State_Of (Client_Machine));
         end if;
         if Legacy_Server.State_Of (Server_Machine) /= Legacy_Server.Connected then
            return "the server did not connect: "
              & Legacy_Server.Image (Legacy_Server.State_Of (Server_Machine));
         end if;

         if Legacy_Client.Resumed (Client_Machine)
            /= Legacy_Server.Resumed (Server_Machine)
         then
            return "the two ends disagree about whether this was a resumption";
         end if;
         Resumed := Legacy_Client.Resumed (Client_Machine);

         --  The proof that the key blocks agree, which is the only thing that
         --  distinguishes a resumption that worked from one that merely said it
         --  did: on the abbreviated handshake the keys come from a master
         --  secret that travelled inside a ticket.
         declare
            Plaintext   : constant Byte_Array := [1 .. 40 => 16#5C#];
            Sealed      : Byte_Array (1 .. 256) := [others => 0];
            Opened      : Byte_Array (1 .. 256) := [others => 0];
            Sealed_Last : Byte_Index;
            Opened_Last : Byte_Index;
         begin
            SSL.TLS12.Records.Protect
              (Item      => Client_Write,
               Content   => SSL.Records.Application_Content,
               Plaintext => Plaintext,
               Into      => Sealed,
               Written   => Sealed_Last,
               Error     => Error);
            if SSL.Errors.Is_Error (Error) then
               return "the client could not protect a record";
            end if;

            SSL.TLS12.Records.Open
              (Item     => Server_Read,
               Header   => Sealed (1 .. SSL.Records.Header_Length),
               Fragment => Sealed (SSL.Records.Header_Length + 1 .. Sealed_Last),
               Into     => Opened,
               Written  => Opened_Last,
               Error    => Error);
            if SSL.Errors.Is_Error (Error) then
               return "the server could not open the client's record -- the key "
                 & "blocks diverged: " & SSL.Errors.Image (Error);
            end if;
            if Opened (1 .. Opened_Last) /= Plaintext then
               return "the record opened to something else";
            end if;

            SSL.TLS12.Records.Protect
              (Item      => Server_Write,
               Content   => SSL.Records.Application_Content,
               Plaintext => Plaintext,
               Into      => Sealed,
               Written   => Sealed_Last,
               Error     => Error);
            SSL.TLS12.Records.Open
              (Item     => Client_Read,
               Header   => Sealed (1 .. SSL.Records.Header_Length),
               Fragment => Sealed (SSL.Records.Header_Length + 1 .. Sealed_Last),
               Into     => Opened,
               Written  => Opened_Last,
               Error    => Error);
            if SSL.Errors.Is_Error (Error) then
               return "the client could not open the server's record: "
                 & SSL.Errors.Image (Error);
            end if;
         end;

         --  The session, taken from the machine that established it. Only the
         --  full handshake issues one here: this server does not renew a ticket
         --  it has just accepted.
         if not Offer then
            Legacy_Client.Take_New_Session
              (Item    => Client_Machine,
               Context => SSL.Default_Security_Context,
               Setup   => SSL.Configurations.Fingerprint (Resume_Client_Setup),
               Anchors => SSL.Trust.Fingerprint (Resume_Anchors),
               Into    => Kept,
               Present => Present);
            if not Present then
               return "a full handshake with tickets enabled establishes a session";
            end if;
         end if;

         Legacy_Client.Wipe (Client_Machine);
         Legacy_Server.Wipe (Server_Machine);
         return "";
      end Run;

      First_Resumed  : Boolean;
      Second_Resumed : Boolean;
   begin
      SSL.Trust.Load_Explicit_Anchors
        (Resume_Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load";
      end if;
      SSL.Credentials.Load_PEM
        (Resume_Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the credential fixture did not load";
      end if;

      SSL.Ticket_Keys.Rotate (Resume_Ring, Now => Now, Error => Error);
      if SSL.Errors.Is_Error (Error) then
         return "the ticket key ring could not rotate: " & SSL.Errors.Image (Error);
      end if;

      declare
         Builder : Config.Client_Builder;
      begin
         Config.Modern_Compatibility_Client (Builder);
         Config.Set_Expected_Name
           (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
         Config.Set_Anchors (Builder, Resume_Anchors'Access, Ok);
         Config.Build (Builder, Resume_Client_Setup, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      declare
         Builder : Config.Server_Builder;
      begin
         Config.Modern_Compatibility_Server (Builder);
         Config.Add_Credential (Builder, Resume_Credential'Access, Ok);
         Config.Set_Ticket_Keys (Builder, Resume_Ring'Access);
         Config.Build (Builder, Resume_Server_Setup, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      declare
         Report : constant String := Run (Offer => False, Resumed => First_Resumed);
      begin
         if Report /= "" then
            return "the first handshake: " & Report;
         end if;
      end;

      if First_Resumed then
         return "a handshake with no ticket to offer cannot be a resumption";
      end if;

      if not SSL.Sessions.Is_Present (Kept) then
         return "the first handshake left no session";
      end if;
      if SSL.Sessions.Version (Kept) /= SSL.Versions.TLS_1_2 then
         return "the session records the version it was established under";
      end if;
      if SSL.Sessions.Ticket (Kept)'Length = 0 then
         return "the session carries the ticket it came in";
      end if;

      declare
         Report : constant String := Run (Offer => True, Resumed => Second_Resumed);
      begin
         if Report /= "" then
            return "the second handshake: " & Report;
         end if;
      end;

      if not Second_Resumed then
         return "a ticket this server issued must be accepted by it";
      end if;

      --  And a ticket the server cannot open is declined rather than refused:
      --  a full handshake follows and the connection is unaffected. Every
      --  octet of the ticket is flipped, so nothing about it survives.
      declare
         Broken  : SSL.Sessions.Session;
         Ticket  : Byte_Array := SSL.Sessions.Ticket (Kept);
         Secret  : Byte_Array (1 .. 64) := [others => 0];
         Length  : Byte_Index;
         Third   : Boolean;
      begin
         for Octet of Ticket loop
            Octet := Octet xor 16#FF#;
         end loop;

         SSL.Sessions.Get_Secret (Kept, Secret, Length);
         SSL.Sessions.Store
           (Item          => Broken,
            Version       => SSL.Versions.TLS_1_2,
            Suite         => SSL.Sessions.Cipher_Suite (Kept),
            Name          => SSL.Sessions.Server_Name (Kept),
            Protocol      => SSL.ALPN.No_Protocol,
            Has_Protocol  => False,
            Issued        => Now,
            Lifetime      => 86_400,
            Context       => SSL.Default_Security_Context,
            Setup         => SSL.Configurations.Fingerprint (Resume_Client_Setup),
            Anchors       => SSL.Trust.Fingerprint (Resume_Anchors),
            Authenticated => True,
            Ticket_Bytes  => Ticket,
            Age_Add       => 0,
            Nonce_Bytes   => [1 .. 0 => 0],
            Secret        => Secret (1 .. Length),
            Error         => Error);
         SSL.Crypto.Scrub (Secret);
         if SSL.Errors.Is_Error (Error) then
            return "the damaged session could not be assembled";
         end if;

         SSL.Sessions.Wipe (Kept);
         SSL.Sessions.Copy (Kept, Broken);
         SSL.Sessions.Wipe (Broken);

         declare
            Report : constant String := Run (Offer => True, Resumed => Third);
         begin
            if Report /= "" then
               return "a damaged ticket must cost a resumption and not a "
                 & "connection: " & Report;
            end if;
         end;

         if Third then
            return "a damaged ticket must not be accepted";
         end if;
      end;

      SSL.Sessions.Wipe (Kept);
      SSL.Ticket_Keys.Wipe (Resume_Ring);
      return "";
   end Check_TLS12_Resumption;

   ---------------------------------------------------------------------------
   --  A TLS 1.2 connection that resumes, over a transport
   ---------------------------------------------------------------------------

   Legacy_Resume_Anchors    : aliased SSL.Trust.Snapshot;
   Legacy_Resume_Credential : aliased SSL.Credentials.Credential;
   Legacy_Resume_Client     : aliased SSL.Configurations.Client_Configuration;
   Legacy_Resume_Server     : aliased SSL.Configurations.Server_Configuration;
   Legacy_Resume_Ring       : aliased SSL.Ticket_Keys.Ring;
   Legacy_Resume_Cache      : aliased SSL.Sessions.Client_Caches.Memory.Memory_Cache
                                (Capacity => 4);

   Legacy_Resume_To_Server : aliased Tests_Pipes.Pipe;
   Legacy_Resume_To_Client : aliased Tests_Pipes.Pipe;
   Legacy_Resume_Client_Medium : aliased Tests_Pipes.Pipe_Transport;
   Legacy_Resume_Server_Medium : aliased Tests_Pipes.Pipe_Transport;

   ------------------------------------------
   -- Check_TLS12_Connection_Resumption --
   ------------------------------------------

   function Check_TLS12_Connection_Resumption return String is
      package Config renames SSL.Configurations;
      package Conn renames SSL.Connections;
      package Meta renames SSL.Connection_Metadata;

      use type SSL.Versions.Protocol_Version;

      Now : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);

      Error  : SSL.Errors.Error_Information;
      Ok     : Boolean;
      Moved  : Boolean;
      Rounds : Natural;

      --  One whole connection over a fresh pair of pipes, driven far enough
      --  past the handshake that a ticket has time to arrive.
      procedure Connect_Once
        (Resumed    : out Boolean;
         Version    : out SSL.Versions.Protocol_Version;
         Diagnostic : out Boolean);

      procedure Connect_Once
        (Resumed    : out Boolean;
         Version    : out SSL.Versions.Protocol_Version;
         Diagnostic : out Boolean)
      is
         Client : Conn.Connection;
         Server : Conn.Connection;
      begin
         Resumed := False;
         Version := SSL.Versions.TLS_1_3;
         Diagnostic := False;

         Tests_Pipes.Reset (Legacy_Resume_To_Server);
         Tests_Pipes.Reset (Legacy_Resume_To_Client);
         Tests_Pipes.Attach
           (Legacy_Resume_Client_Medium, Legacy_Resume_To_Server'Access,
            Legacy_Resume_To_Client'Access, 'l');
         Tests_Pipes.Attach
           (Legacy_Resume_Server_Medium, Legacy_Resume_To_Client'Access,
            Legacy_Resume_To_Server'Access, 'L');

         SSL.Servers.Accept_Connection
           (Server, Legacy_Resume_Server'Access,
            Legacy_Resume_Server_Medium'Unchecked_Access, SSL.No_Connection, Now, Error);
         SSL.Clients.Connect
           (Client, Legacy_Resume_Client'Access,
            Legacy_Resume_Client_Medium'Unchecked_Access, SSL.No_Connection, Now, Error);
         if SSL.Errors.Is_Error (Error) then
            Diagnostic := True;
            return;
         end if;

         Rounds := 0;
         loop
            Rounds := Rounds + 1;
            if Rounds > 2_000 then
               Diagnostic := True;
               return;
            end if;
            Conn.Step (Client, Moved, Error);
            if SSL.Errors.Is_Error (Error) then
               Diagnostic := True;
               return;
            end if;
            Conn.Step (Server, Moved, Error);
            if SSL.Errors.Is_Error (Error) then
               Diagnostic := True;
               return;
            end if;
            exit when Conn.Is_Established (Client) and then Conn.Is_Established (Server);
         end loop;

         Resumed := Meta.Resumed (Conn.Metadata_Of (Client));
         Version := Meta.Version (Conn.Metadata_Of (Client));

         --  The two ends must agree. A client that thought it had resumed
         --  against a server that had not would be a client using keys the
         --  server never derived, and the record layer would say so -- but it
         --  would say so as a decryption failure with no cause attached.
         if Meta.Resumed (Conn.Metadata_Of (Server)) /= Resumed then
            Diagnostic := True;
            return;
         end if;

         --  Application data both ways, which is the only proof that the two
         --  key blocks agree.
         declare
            Sent    : constant Byte_Array := [1 .. 24 => 16#3E#];
            Got     : Byte_Array (1 .. 64) := [others => 0];
            Written : Byte_Index;
            Taken   : Byte_Index;
         begin
            Conn.Write_Available (Client, Sent, Written, Error);
            if SSL.Errors.Is_Error (Error) or else Written /= Sent'Length then
               Diagnostic := True;
               return;
            end if;

            for Extra in 1 .. 200 loop
               Conn.Step (Client, Moved, Error);
               Conn.Step (Server, Moved, Error);
            end loop;

            Conn.Read_Available (Server, Got, Taken, Error);
            if SSL.Errors.Is_Error (Error)
              or else Taken /= Sent'Length
              or else Got (1 .. Taken) /= Sent
            then
               Diagnostic := True;
               return;
            end if;
         end;

         --  And let the ticket travel, so the next connection has one.
         for Extra in 1 .. 200 loop
            Conn.Step (Server, Moved, Error);
            Conn.Step (Client, Moved, Error);
         end loop;

         Conn.Wipe (Client);
         Conn.Wipe (Server);
      end Connect_Once;

      Resumed : Boolean;
      Version : SSL.Versions.Protocol_Version;
      Broken  : Boolean;
   begin
      SSL.Trust.Load_Explicit_Anchors
        (Legacy_Resume_Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load";
      end if;
      SSL.Credentials.Load_PEM
        (Legacy_Resume_Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the credential fixture did not load";
      end if;

      SSL.Ticket_Keys.Rotate (Legacy_Resume_Ring, 86_400, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the ticket key ring could not rotate";
      end if;

      --  A client that speaks only TLS 1.2, so that what is being tested is
      --  the TLS 1.2 path and not the TLS 1.3 one arriving at the same answer.
      declare
         Builder : Config.Client_Builder;
      begin
         Config.Modern_Compatibility_Client (Builder);
         Config.Set_Versions (Builder, SSL.Versions.Only (SSL.Versions.TLS_1_2), Ok);
         Config.Set_Expected_Name
           (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
         Config.Set_Anchors (Builder, Legacy_Resume_Anchors'Access, Ok);
         Config.Set_Session_Cache (Builder, Legacy_Resume_Cache'Unchecked_Access);
         Config.Build (Builder, Legacy_Resume_Client, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      declare
         Builder : Config.Server_Builder;
      begin
         Config.Modern_Compatibility_Server (Builder);
         Config.Add_Credential (Builder, Legacy_Resume_Credential'Access, Ok);
         Config.Set_Ticket_Keys (Builder, Legacy_Resume_Ring'Access);
         Config.Set_Ticket_Issuance (Builder, True);
         Config.Build (Builder, Legacy_Resume_Server, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      Connect_Once (Resumed, Version, Broken);
      if Broken then
         return "the first connection failed: " & SSL.Errors.Image (Error);
      end if;
      if Version /= SSL.Versions.TLS_1_2 then
         return "a TLS 1.2-only client must negotiate TLS 1.2";
      end if;
      if Resumed then
         return "the first connection has nothing to resume from";
      end if;

      Connect_Once (Resumed, Version, Broken);
      if Broken then
         return "the second connection failed: " & SSL.Errors.Image (Error);
      end if;
      if Version /= SSL.Versions.TLS_1_2 then
         return "a resumed TLS 1.2 connection is still TLS 1.2";
      end if;
      if not Resumed then
         return "the second connection must resume from the first one's ticket";
      end if;

      SSL.Ticket_Keys.Wipe (Legacy_Resume_Ring);
      return "";
   end Check_TLS12_Connection_Resumption;

   ---------------------------------------------------------------------------
   --  One connection, three tasks
   ---------------------------------------------------------------------------

   Sync_Anchors    : aliased SSL.Trust.Snapshot;
   Sync_Credential : aliased SSL.Credentials.Credential;
   Sync_Client     : aliased SSL.Configurations.Client_Configuration;
   Sync_Server     : aliased SSL.Configurations.Server_Configuration;

   Sync_To_Server : aliased Tests_Pipes.Pipe;
   Sync_To_Client : aliased Tests_Pipes.Pipe;
   Sync_Client_Medium : aliased Tests_Pipes.Pipe_Transport;
   Sync_Server_Medium : aliased Tests_Pipes.Pipe_Transport;

   --  Library level, because the reader and the writer tasks take a reference
   --  to it and Ada's accessibility rules will not let a task outlive what it
   --  points at. Which is the rule doing its job: a synchronized connection
   --  shared with tasks must outlive them.
   Sync_Connection : aliased SSL.Synchronized_Connections.Synchronized_Connection;

   --  The plain connection on the other end. Driven by the test's own task,
   --  because what is being checked is the wrapper and not the pipe.
   Sync_Peer : SSL.Connections.Connection;

   -------------------------------
   -- Check_Synchronized --
   -------------------------------

   function Check_Synchronized return String is
      package Config renames SSL.Configurations;
      package Sync renames SSL.Synchronized_Connections;
      package Conn renames SSL.Connections;

      Now : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);

      Error : SSL.Errors.Error_Information;
      Ok    : Boolean;
      Moved : Boolean;

      --  What each side sends. Different lengths and different contents, so
      --  that a wrapper which crossed the two directions over would produce a
      --  mismatch rather than a coincidence.
      Client_Says : constant Byte_Array (1 .. 300) := [others => 16#A5#];
      Server_Says : constant Byte_Array (1 .. 120) := [others => 16#5A#];

      --  Filled by the reader task, read by the main task after it has ended.
      --  No lock: a task's termination is a synchronization point, and reading
      --  these before it ends would be the bug the wrapper exists to prevent.
      Read_Count  : Byte_Index := 0;
      Read_Octets : Byte_Array (1 .. 512) := [others => 0];
      Read_Report : SSL.Errors.Error_Information;

      Write_Count  : Byte_Index := 0;
      Write_Report : SSL.Errors.Error_Information;
   begin
      SSL.Trust.Load_Explicit_Anchors
        (Sync_Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load";
      end if;
      SSL.Credentials.Load_PEM
        (Sync_Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the credential fixture did not load";
      end if;

      declare
         Builder : Config.Client_Builder;
      begin
         Config.Secure_Client_Defaults (Builder);
         Config.Set_Expected_Name
           (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
         Config.Set_Anchors (Builder, Sync_Anchors'Access, Ok);
         Config.Build (Builder, Sync_Client, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      declare
         Builder : Config.Server_Builder;
      begin
         Config.Secure_Server_Defaults (Builder);
         Config.Add_Credential (Builder, Sync_Credential'Access, Ok);
         Config.Build (Builder, Sync_Server, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      Tests_Pipes.Reset (Sync_To_Server);
      Tests_Pipes.Reset (Sync_To_Client);
      Tests_Pipes.Attach
        (Sync_Client_Medium, Sync_To_Server'Access, Sync_To_Client'Access, 's');
      Tests_Pipes.Attach
        (Sync_Server_Medium, Sync_To_Client'Access, Sync_To_Server'Access, 'S');

      Conn.Accept_Connection
        (Sync_Peer, Sync_Server'Access, Sync_Server_Medium'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the peer did not start";
      end if;

      Sync.Connect
        (Sync_Connection, Sync_Client'Access, Sync_Client_Medium'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the synchronized connection did not start: " & SSL.Errors.Image (Error);
      end if;

      --  The handshake first, from one task on each side. `Handshake` blocks
      --  until it is done, so the peer has to be driven at the same time --
      --  which is the situation this whole wrapper is about, arriving before
      --  the application data does.
      declare
         task Drive_Peer;

         task body Drive_Peer is
            Rounds : Natural := 0;
            Local  : SSL.Errors.Error_Information;
            Went   : Boolean;
         begin
            loop
               Rounds := Rounds + 1;
               exit when Rounds > 200_000;
               Conn.Step (Sync_Peer, Went, Local);
               exit when SSL.Errors.Is_Error (Local);
               exit when Conn.Is_Established (Sync_Peer);
               delay 0.0002;
            end loop;
         end Drive_Peer;
      begin
         Sync.Handshake
           (Sync_Connection, SSL.Clocks.In_Milliseconds (10_000), Error);

         --  And then keep stepping, inside this block rather than after it.
         --  A TLS 1.3 client is established the moment it has queued its
         --  Finished; the server is established only once that Finished has
         --  arrived, and over a transport that accepts ninety-seven octets at
         --  a time it has not all gone out yet. Waiting for the peer's task
         --  outside this block would be waiting for a flight this task is the
         --  only one that can send.
         if not SSL.Errors.Is_Error (Error) then
            declare
               Spare  : Byte_Array (1 .. 64) := [others => 0];
               Taken  : Byte_Index;
               Local  : SSL.Errors.Error_Information;
               Rounds : Natural := 0;
            begin
               while not Conn.Is_Established (Sync_Peer) loop
                  Rounds := Rounds + 1;
                  exit when Rounds > 4_000;
                  Sync.Read
                    (Item    => Sync_Connection,
                     Into    => Spare,
                     Count   => Taken,
                     Expires => SSL.Clocks.In_Milliseconds (2),
                     Error   => Local);
                  exit when SSL.Errors.Is_Error (Local);
               end loop;
            end;
         end if;
      end;

      if SSL.Errors.Is_Error (Error) then
         return "the handshake failed: " & SSL.Errors.Image (Error);
      end if;
      if not Sync.Is_Established (Sync_Connection) then
         return "the handshake did not establish the connection";
      end if;
      if not Conn.Is_Established (Sync_Peer) then
         return "the peer did not finish the handshake";
      end if;

      --  Now the three roles, at once. The reader and the writer touch the same
      --  driver from two tasks for as long as this block lasts; without the
      --  wrapper's lock that is two tasks interleaving records under one
      --  sequence number space, and the peer would refuse the first one it
      --  could not authenticate.
      declare
         task Reader;
         task Writer;

         task body Reader is
         begin
            Sync.Read
              (Item    => Sync_Connection,
               Into    => Read_Octets,
               Count   => Read_Count,
               Expires => SSL.Clocks.In_Milliseconds (10_000),
               Error   => Read_Report);
         end Reader;

         task body Writer is
         begin
            Sync.Write
              (Item    => Sync_Connection,
               Data    => Client_Says,
               Written => Write_Count,
               Expires => SSL.Clocks.In_Milliseconds (10_000),
               Error   => Write_Report);
         end Writer;
      begin
         --  The peer, driven here: it takes what the writer sends and answers,
         --  which is what gives the reader something to find.
         declare
            Rounds  : Natural := 0;
            Got     : Byte_Array (1 .. 512) := [others => 0];
            Taken   : Byte_Index;
            Sent    : Byte_Index;
            Total   : Byte_Index := 0;
            Answered : Boolean := False;
         begin
            loop
               Rounds := Rounds + 1;
               exit when Rounds > 20_000;

               Conn.Step (Sync_Peer, Moved, Error);
               exit when SSL.Errors.Is_Error (Error);

               Conn.Read_Available (Sync_Peer, Got, Taken, Error);
               exit when SSL.Errors.Is_Error (Error);
               Total := Total + Taken;

               if Total >= Client_Says'Length and then not Answered then
                  Conn.Write_Available (Sync_Peer, Server_Says, Sent, Error);
                  exit when SSL.Errors.Is_Error (Error);
                  Answered := Sent = Server_Says'Length;
               end if;

               exit when Answered and then Read_Count > 0;
               delay 0.0005;
            end loop;
         end;
      end;

      if SSL.Errors.Is_Error (Write_Report) then
         return "the writer task failed: " & SSL.Errors.Image (Write_Report);
      end if;
      if Write_Count /= Client_Says'Length then
         return "the writer must place every octet it was given";
      end if;

      if SSL.Errors.Is_Error (Read_Report) then
         return "the reader task failed: " & SSL.Errors.Image (Read_Report);
      end if;
      if Read_Count = 0 then
         return "the reader must find the data the peer sent";
      end if;
      if Read_Octets (1 .. Read_Count) /= Server_Says (1 .. Read_Count) then
         return "the reader must find what the peer actually sent";
      end if;

      --  The controller. Asking is not doing: the request is recorded now and
      --  acted on by whichever task next holds the driver, which here is
      --  `Close`.
      Sync.Request_Shutdown (Sync_Connection);
      if not Sync.Shutdown_Requested (Sync_Connection) then
         return "a shutdown that was asked for must be reported as asked for";
      end if;
      if Sync.Cancel_Requested (Sync_Connection) then
         return "asking for a shutdown is not asking for a cancellation";
      end if;

      Sync.Close (Sync_Connection, SSL.Clocks.In_Milliseconds (200), Error);

      --  And cancellation, which must be observable from the controller
      --  without touching the driver at all.
      Sync.Cancel (Sync_Connection);
      if not Sync.Cancel_Requested (Sync_Connection) then
         return "a cancellation that was asked for must be reported as asked for";
      end if;

      Sync.Wipe (Sync_Connection);
      Conn.Wipe (Sync_Peer);
      return "";
   end Check_Synchronized;

   ---------------------------------------------------------------------------
   --  Secret hygiene: wiping observed, diagnostics scanned
   ---------------------------------------------------------------------------

   Hygiene_Anchors    : aliased SSL.Trust.Snapshot;
   Hygiene_Credential : aliased SSL.Credentials.Credential;
   Hygiene_Client     : aliased SSL.Configurations.Client_Configuration;
   Hygiene_Server     : aliased SSL.Configurations.Server_Configuration;

   Hygiene_To_Server : aliased Tests_Pipes.Pipe;
   Hygiene_To_Client : aliased Tests_Pipes.Pipe;
   Hygiene_Client_Medium : aliased Tests_Pipes.Pipe_Transport;
   Hygiene_Server_Medium : aliased Tests_Pipes.Pipe_Transport;

   --  How many wipes were observed, and how many octets they covered. Package
   --  level because the observer is a plain access-to-procedure and has nowhere
   --  else to put its answer.
   Hygiene_Wipes  : Natural := 0;
   Hygiene_Octets : Natural := 0;

   procedure Hygiene_Observer (Wiped : Byte_Index);

   procedure Hygiene_Observer (Wiped : Byte_Index) is
   begin
      Hygiene_Wipes := Hygiene_Wipes + 1;
      Hygiene_Octets := Hygiene_Octets + Natural (Wiped);
   end Hygiene_Observer;

   --  Everything the diagnostics said, kept verbatim so it can be searched.
   Hygiene_Log_Limit : constant := 64 * 1024;

   type Hygiene_Sink is limited new SSL.Diagnostics.Sink with record
      Text  : String (1 .. Hygiene_Log_Limit) := [others => ' '];
      Used  : Natural := 0;
      Count : Natural := 0;
      Full  : Boolean := False;
   end record;

   overriding procedure Emit
     (Item : in out Hygiene_Sink; What : SSL.Diagnostics.Event);

   overriding function Description (Item : Hygiene_Sink) return String;

   overriding procedure Emit
     (Item : in out Hygiene_Sink; What : SSL.Diagnostics.Event)
   is
      --  At the level that redacts least. A scan against the most talkative
      --  setting is the only one that proves anything: passing at a level that
      --  hides everything would prove that the level hides everything.
      Line : constant String :=
        SSL.Diagnostics.Image (What, SSL.Diagnostics.Explicit_Debug);
   begin
      Item.Count := Item.Count + 1;
      if Item.Used + Line'Length + 1 > Item.Text'Last then
         Item.Full := True;
         return;
      end if;
      Item.Text (Item.Used + 1 .. Item.Used + Line'Length) := Line;
      Item.Used := Item.Used + Line'Length + 1;
   end Emit;

   overriding function Description (Item : Hygiene_Sink) return String is
     ("the secret-hygiene recorder");

   Hygiene_Recorder : aliased Hygiene_Sink;

   ---------------------------
   -- Check_Secret_Hygiene --
   ---------------------------

   function Check_Secret_Hygiene return String is
      package Config renames SSL.Configurations;
      package Conn renames SSL.Connections;

      Now : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);

      Error  : SSL.Errors.Error_Information;
      Ok     : Boolean;
      Moved  : Boolean;
      Rounds : Natural := 0;

      Client : Conn.Connection;
      Server : Conn.Connection;

      --  Real key material from the finished connection, used as the needle.
      --  Exported material is derived from the same schedule the traffic keys
      --  come from, so if the diagnostics were leaking secrets this is the
      --  shape of the thing that would be in them.
      Material : Byte_Array (1 .. 32) := [others => 0];

      --  Whether a run of octets appears anywhere in the recorded text.
      --
      --  The text is hexadecimal where it is anything, so the needle is
      --  searched for in both of the two spellings a leak could take: the raw
      --  octets, and their hexadecimal. A scan for only one of them would pass
      --  against a leak written the other way.
      function Leaked (Needle : Byte_Array) return Boolean;

      function Leaked (Needle : Byte_Array) return Boolean is
         Digits_Set : constant String := "0123456789abcdef";
         Raw        : String (1 .. Natural (Needle'Length));
         Hex        : String (1 .. 2 * Natural (Needle'Length));
         At_Now     : Positive := 1;
      begin
         for Index in Needle'Range loop
            Raw (Natural (Index - Needle'First) + 1) :=
              Character'Val (Natural (Needle (Index)));
            Hex (At_Now) := Digits_Set (Natural (Needle (Index)) / 16 + 1);
            Hex (At_Now + 1) := Digits_Set (Natural (Needle (Index)) mod 16 + 1);
            At_Now := At_Now + 2;
         end loop;

         return Tests_Support.Index_Of
                  (Hygiene_Recorder.Text (1 .. Hygiene_Recorder.Used), Raw) > 0
           or else Tests_Support.Index_Of
                     (Hygiene_Recorder.Text (1 .. Hygiene_Recorder.Used), Hex) > 0;
      end Leaked;
   begin
      Hygiene_Wipes := 0;
      Hygiene_Octets := 0;
      Hygiene_Recorder.Used := 0;
      Hygiene_Recorder.Count := 0;
      Hygiene_Recorder.Full := False;

      SSL.Trust.Load_Explicit_Anchors
        (Hygiene_Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load";
      end if;
      SSL.Credentials.Load_PEM
        (Hygiene_Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the credential fixture did not load";
      end if;

      declare
         Builder : Config.Client_Builder;
      begin
         Config.Secure_Client_Defaults (Builder);
         Config.Set_Expected_Name
           (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
         Config.Set_Anchors (Builder, Hygiene_Anchors'Access, Ok);
         Config.Set_Diagnostics
           (Builder,
            Value     => Hygiene_Recorder'Unchecked_Access,
            Level     => SSL.Diagnostics.Detailed_Protocol,
            Redaction => SSL.Diagnostics.Explicit_Debug);
         Config.Build (Builder, Hygiene_Client, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      declare
         Builder : Config.Server_Builder;
      begin
         Config.Secure_Server_Defaults (Builder);
         Config.Add_Credential (Builder, Hygiene_Credential'Access, Ok);
         Config.Build (Builder, Hygiene_Server, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      Tests_Pipes.Reset (Hygiene_To_Server);
      Tests_Pipes.Reset (Hygiene_To_Client);
      Tests_Pipes.Attach
        (Hygiene_Client_Medium, Hygiene_To_Server'Access, Hygiene_To_Client'Access, 'h');
      Tests_Pipes.Attach
        (Hygiene_Server_Medium, Hygiene_To_Client'Access, Hygiene_To_Server'Access, 'H');

      --  The observer goes on for the connection and comes off afterwards, so
      --  that nothing else in the suite is counted.
      SSL.Secrets.Observe_Wipes (Hygiene_Observer'Access);

      Conn.Accept_Connection
        (Server, Hygiene_Server'Access, Hygiene_Server_Medium'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      Conn.Connect
        (Client, Hygiene_Client'Access, Hygiene_Client_Medium'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         SSL.Secrets.Observe_Wipes (null);
         return "the connection did not start: " & SSL.Errors.Image (Error);
      end if;

      loop
         Rounds := Rounds + 1;
         if Rounds > 2_000 then
            SSL.Secrets.Observe_Wipes (null);
            return "the handshake did not converge";
         end if;
         Conn.Step (Client, Moved, Error);
         exit when SSL.Errors.Is_Error (Error);
         Conn.Step (Server, Moved, Error);
         exit when SSL.Errors.Is_Error (Error);
         exit when Conn.Is_Established (Client) and then Conn.Is_Established (Server);
      end loop;

      if SSL.Errors.Is_Error (Error) then
         SSL.Secrets.Observe_Wipes (null);
         return "the handshake failed: " & SSL.Errors.Image (Error);
      end if;

      SSL.Exporters.Export
        (Item  => Client,
         Label => "ssllib secret hygiene",
         Into  => Material,
         Error => Error);
      if SSL.Errors.Is_Error (Error) then
         SSL.Secrets.Observe_Wipes (null);
         return "the exporter refused: " & SSL.Errors.Image (Error);
      end if;

      --  Some data both ways, so that the traffic keys are used and the
      --  diagnostics have as much to say as they ever will.
      declare
         Sent    : constant Byte_Array := [1 .. 64 => 16#C3#];
         Got     : Byte_Array (1 .. 128) := [others => 0];
         Taken   : Byte_Index;
         Written : Byte_Index;
      begin
         Conn.Write_Available (Client, Sent, Written, Error);
         for Extra in 1 .. 200 loop
            Conn.Step (Client, Moved, Error);
            Conn.Step (Server, Moved, Error);
         end loop;
         Conn.Read_Available (Server, Got, Taken, Error);
      end;

      --  Every diagnostic the connection produced, searched for the connection's
      --  own key material. This is the check the specification asks for: a
      --  recognizable secret, seeded by the handshake itself, must not appear
      --  anywhere in what was logged.
      if Hygiene_Recorder.Count = 0 then
         SSL.Secrets.Observe_Wipes (null);
         return "a connection with a sink attached must produce diagnostics";
      end if;
      if Hygiene_Recorder.Full then
         SSL.Secrets.Observe_Wipes (null);
         return "the recorder overflowed, so the scan would not have covered "
           & "everything";
      end if;

      if Leaked (Material) then
         SSL.Secrets.Observe_Wipes (null);
         return "exported key material appeared in the diagnostics";
      end if;

      --  And a prefix of it, because a leak of part of a secret is a leak.
      if Leaked (Material (1 .. 8)) then
         SSL.Secrets.Observe_Wipes (null);
         return "eight octets of exported key material appeared in the diagnostics";
      end if;

      --  Now the wiping. Tearing the two connections down must scrub what they
      --  hold, and the observer is the only way to see that happen.
      declare
         Before : constant Natural := Hygiene_Wipes;
      begin
         Conn.Wipe (Client);
         Conn.Wipe (Server);

         if Hygiene_Wipes <= Before then
            SSL.Secrets.Observe_Wipes (null);
            return "wiping a connection must scrub the secrets it holds";
         end if;
      end;

      --  A secret of this library's own, wiped by hand, to check that the
      --  observer reports the length that was actually scrubbed rather than a
      --  capacity or a zero.
      declare
         Value  : SSL.Secrets.Secret (SSL.Secrets.Traffic_Capacity);
         Before : Natural;
         Octets : Natural;
      begin
         SSL.Secrets.Set (Value, [1 .. 16 => 16#7E#]);
         Before := Hygiene_Wipes;
         Octets := Hygiene_Octets;
         SSL.Secrets.Wipe (Value);

         if Hygiene_Wipes /= Before + 1 then
            SSL.Secrets.Observe_Wipes (null);
            return "one wipe must be observed exactly once";
         end if;
         if Hygiene_Octets - Octets /= 16 then
            SSL.Secrets.Observe_Wipes (null);
            return "the observer must be told how many octets held the secret";
         end if;
         if SSL.Secrets.Length (Value) /= 0 then
            SSL.Secrets.Observe_Wipes (null);
            return "a wiped secret has no length";
         end if;
      end;

      SSL.Secrets.Observe_Wipes (null);
      return "";
   end Check_Secret_Hygiene;

   ---------------------------------------------------------------------------
   --  Mutual TLS: the client proves it holds a key too
   ---------------------------------------------------------------------------

   Mutual_Anchors    : aliased SSL.Trust.Snapshot;
   Mutual_Credential : aliased SSL.Credentials.Credential;
   Mutual_Client     : aliased SSL.Configurations.Client_Configuration;
   Mutual_Server     : aliased SSL.Configurations.Server_Configuration;

   Mutual_To_Server : aliased Tests_Pipes.Pipe;
   Mutual_To_Client : aliased Tests_Pipes.Pipe;
   Mutual_Client_Medium : aliased Tests_Pipes.Pipe_Transport;
   Mutual_Server_Medium : aliased Tests_Pipes.Pipe_Transport;

   -------------------------
   -- Check_Mutual_TLS --
   -------------------------

   function Check_Mutual_TLS return String is
      package Config renames SSL.Configurations;
      package Conn renames SSL.Connections;
      package Meta renames SSL.Connection_Metadata;

      Now : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);

      Error  : SSL.Errors.Error_Information;
      Ok     : Boolean;
      Moved  : Boolean;
      Rounds : Natural := 0;

      Client : Conn.Connection;
      Server : Conn.Connection;
   begin
      SSL.Trust.Load_Explicit_Anchors
        (Mutual_Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load";
      end if;
      SSL.Credentials.Load_PEM
        (Mutual_Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the credential fixture did not load";
      end if;

      --  The same credential on both ends. One fixture rather than two,
      --  because what is being checked is that a client can prove it holds a
      --  key -- not that two different certificates exist.
      declare
         Builder : Config.Client_Builder;
      begin
         Config.Secure_Client_Defaults (Builder);
         Config.Set_Expected_Name
           (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
         Config.Set_Anchors (Builder, Mutual_Anchors'Access, Ok);
         Config.Set_Client_Credential (Builder, Mutual_Credential'Access, Ok);
         if not Ok then
            return "a client credential must be accepted";
         end if;
         Config.Build (Builder, Mutual_Client, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      declare
         Builder : Config.Server_Builder;
      begin
         Config.Secure_Server_Defaults (Builder);
         Config.Add_Credential (Builder, Mutual_Credential'Access, Ok);
         Config.Set_Anchors (Builder, Mutual_Anchors'Access, Ok);
         Config.Set_Client_Authentication
           (Builder, SSL.Authentication.Required);
         Config.Build (Builder, Mutual_Server, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      Tests_Pipes.Reset (Mutual_To_Server);
      Tests_Pipes.Reset (Mutual_To_Client);
      Tests_Pipes.Attach
        (Mutual_Client_Medium, Mutual_To_Server'Access, Mutual_To_Client'Access, 'm');
      Tests_Pipes.Attach
        (Mutual_Server_Medium, Mutual_To_Client'Access, Mutual_To_Server'Access, 'M');

      Conn.Accept_Connection
        (Server, Mutual_Server'Access, Mutual_Server_Medium'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      Conn.Connect
        (Client, Mutual_Client'Access, Mutual_Client_Medium'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the connection did not start: " & SSL.Errors.Image (Error);
      end if;

      loop
         Rounds := Rounds + 1;
         if Rounds > 2_000 then
            return "the mutual handshake did not converge";
         end if;
         Conn.Step (Client, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client failed: " & SSL.Errors.Image (Error);
         end if;
         Conn.Step (Server, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server failed: " & SSL.Errors.Image (Error);
         end if;
         exit when Conn.Is_Established (Client) and then Conn.Is_Established (Server);
      end loop;

      --  A server that required a certificate and got one says so. This is the
      --  assertion the whole check is for: a handshake that completed while the
      --  server still considered its peer anonymous would mean the requirement
      --  was not enforced.
      if not Meta.Peer_Authenticated (Conn.Metadata_Of (Server)) then
         return "a server that required a client certificate must report an "
           & "authenticated peer";
      end if;
      if not Meta.Peer_Authenticated (Conn.Metadata_Of (Client)) then
         return "a client authenticates its server as it always does";
      end if;

      --  And the record layer agrees, which is the proof that the transcript
      --  the two ends signed and verified was the same one. A CertificateVerify
      --  over the wrong transcript hash would have failed before here, but a
      --  Certificate absorbed at the wrong moment would not: it would leave two
      --  ends with different transcripts and the same belief that all was well.
      declare
         Plaintext : constant Byte_Array := [1 .. 48 => 16#2D#];
         Got       : Byte_Array (1 .. 128) := [others => 0];
         Written   : Byte_Index;
         Taken     : Byte_Index;
      begin
         Conn.Write_Available (Client, Plaintext, Written, Error);
         if SSL.Errors.Is_Error (Error) or else Written /= Plaintext'Length then
            return "the client could not send after a mutual handshake";
         end if;

         for Extra in 1 .. 200 loop
            Conn.Step (Client, Moved, Error);
            Conn.Step (Server, Moved, Error);
         end loop;

         Conn.Read_Available (Server, Got, Taken, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server could not read after a mutual handshake: "
              & SSL.Errors.Image (Error);
         end if;
         if Taken /= Plaintext'Length or else Got (1 .. Taken) /= Plaintext then
            return "the record opened to something else";
         end if;
      end;

      Conn.Wipe (Client);
      Conn.Wipe (Server);
      return "";
   end Check_Mutual_TLS;

   ---------------------------------------------------------------------------
   --  A trust store costs what it holds
   ---------------------------------------------------------------------------

   Sized_Anchors : aliased SSL.Trust.Snapshot;
   Sized_Second  : aliased SSL.Trust.Snapshot;

   -------------------------------
   -- Check_Trust_Store_Sizing --
   -------------------------------

   function Check_Trust_Store_Sizing return String is
      use type SSL.Byte_Index;

      Now   : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);
      Error : SSL.Errors.Error_Information;

      Before : SSL.Trust_Fingerprint;
   begin
      SSL.Trust.Load_Explicit_Anchors
        (Sized_Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load: " & SSL.Errors.Image (Error);
      end if;

      if SSL.Trust.Anchor_Count (Sized_Anchors) = 0 then
         return "the fixture holds at least one anchor";
      end if;
      if SSL.Trust.Held_Octets (Sized_Anchors) = 0 then
         return "an anchor occupies octets";
      end if;

      --  The store is sized to what it holds, not to the ceiling.
      --
      --  It used to allocate four megabytes before seeing a certificate,
      --  whatever it turned out to hold. This is the assertion that stops that
      --  coming back: a handful of anchors must not cost more than a handful
      --  of anchors, and the slack allowed here is generous enough that a
      --  reasonable growth policy passes and a flat pre-allocation cannot.
      if SSL.Trust.Allocated_Octets (Sized_Anchors)
         > 4 * SSL.Trust.Held_Octets (Sized_Anchors) + 4096
      then
         return "the store allocated far more than it holds: held"
           & SSL.Byte_Index'Image (SSL.Trust.Held_Octets (Sized_Anchors))
           & ", allocated"
           & SSL.Byte_Index'Image (SSL.Trust.Allocated_Octets (Sized_Anchors));
      end if;

      --  And growing it keeps what was there. A snapshot absorbs one source
      --  per call -- system, then NSS, then explicit -- so the storage is
      --  reallocated between them, and a copy that lost the earlier anchors
      --  would leave a trust base quietly smaller than the operator built.
      Before := SSL.Trust.Fingerprint (Sized_Anchors);

      SSL.Trust.Load_Explicit_Anchors
        (Sized_Second, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the second snapshot did not load";
      end if;

      if SSL.Trust.Fingerprint (Sized_Second) /= Before then
         return "two snapshots over the same anchors must have one fingerprint";
      end if;

      --  The anchors themselves still read back, which a resize that copied
      --  the wrong span would break in a way a count alone would not show.
      for Index in 1 .. SSL.Trust.Anchor_Count (Sized_Anchors) loop
         if SSL.Trust.Anchor_At (Sized_Anchors, Index)'Length = 0 then
            return "every anchor still reads back after sizing";
         end if;
         if SSL.Trust.Anchor_At (Sized_Anchors, Index)
            /= SSL.Trust.Anchor_At (Sized_Second, Index)
         then
            return "an anchor differs between two identically loaded stores";
         end if;
      end loop;

      return "";
   end Check_Trust_Store_Sizing;


   ---------------------------------------------------------------------------
   --  Loading anchors and credentials on a small stack
   ---------------------------------------------------------------------------

   --  What a worker task actually gets.
   --
   --  256 KB is generous for a connection handler and far below what a
   --  multi-megabyte frame needs. The number is here rather than left to the
   --  default because the default is large enough to hide the bug this checks
   --  for: a loader that sized a temporary to the whole store rather than to
   --  one certificate ran fine on an environment task and raised
   --  Storage_Error everywhere else.
   Small_Stack : constant := 256 * 1024;

   Stack_Report : String (1 .. 200) := [others => ' '];
   Stack_Length : Natural := 0;

   procedure Say_Stack (Text : String);

   procedure Say_Stack (Text : String) is
   begin
      if Stack_Length = 0 and then Text'Length <= Stack_Report'Length then
         Stack_Report (1 .. Text'Length) := Text;
         Stack_Length := Text'Length;
      end if;
   end Say_Stack;

   ---------------------------------
   -- Check_Small_Stack_Loading --
   ---------------------------------

   function Check_Small_Stack_Loading return String is
      Now : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);

      task Loader is
         pragma Storage_Size (Small_Stack);

         --  Both stacks, because GNAT puts a dynamically sized local on the
         --  secondary stack and Storage_Size does not bound that one. A check
         --  that constrained only the primary stack would pass with the bug it
         --  exists to catch still present -- which is exactly what happened
         --  the first time this was written.
         pragma Secondary_Stack_Size (Small_Stack);
      end Loader;

      task body Loader is
         --  A nested procedure, because a task body cannot return early and
         --  every step here wants to stop at the first thing that went wrong.
         procedure Attempt;

         procedure Attempt is
            Anchors    : SSL.Trust.Snapshot;
            Credential : SSL.Credentials.Credential;
            Error      : SSL.Errors.Error_Information;
         begin
            --  Explicit anchors rather than the system store, so the check
            --  does not depend on what this host happens to trust.
            SSL.Trust.Load_Explicit_Anchors
              (Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
            if SSL.Errors.Is_Error (Error) then
               Say_Stack ("anchors did not load: " & SSL.Errors.Image (Error));
               return;
            end if;
            if SSL.Trust.Anchor_Count (Anchors) = 0 then
               Say_Stack ("anchors loaded but the snapshot is empty");
               return;
            end if;

            SSL.Credentials.Load_PEM
              (Credential, Tests_Fixtures.Leaf_Certificate_PEM,
               Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
            if SSL.Errors.Is_Error (Error) then
               Say_Stack ("credential did not load: " & SSL.Errors.Image (Error));
               return;
            end if;
            if SSL.Credentials.Chain_Length (Credential) = 0 then
               Say_Stack ("credential loaded but holds no certificate");
               return;
            end if;
         end Attempt;
      begin
         Attempt;
      exception
         when Storage_Error =>
            --  The failure this check exists for. A loader whose temporary is
            --  proportional to the store rather than to one certificate lands
            --  here on any ordinary task stack.
            Say_Stack ("Storage_Error: loading needs more stack than a worker "
                       & "task has");
         when others =>
            Say_Stack ("loading raised on a small stack");
      end Loader;

   begin
      --  The task is awaited by leaving this block, so its verdict is complete
      --  by the time it is read.
      null;
      return Stack_Report (1 .. Stack_Length);
   end Check_Small_Stack_Loading;



   -----------------------------------
   -- Extension_Context_Table --
   -----------------------------------

   function Extension_Context_Table return String is
      package Ext renames SSL.Extensions;

      --  A plain buffer rather than an unbounded string: this unit does not
      --  otherwise reach for Ada.Strings.Unbounded, and a table of a few dozen
      --  rows has a size anyone can bound by looking at it.
      Page : String (1 .. 32_768) := [others => ' '];
      Used : Natural := 0;

      procedure Put (Text : String);

      procedure Put (Text : String) is
      begin
         if Used + Text'Length <= Page'Last then
            Page (Used + 1 .. Used + Text'Length) := Text;
            Used := Used + Text'Length;
         end if;
      end Put;

      New_Line : constant String := [1 => ASCII.LF];
   begin
      Put ("# Extension contexts" & New_Line & New_Line);
      Put ("Which extensions this library permits in which message, generated"
           & " by `ssllib_tools docs` from `SSL.Extensions` itself. A `no`"
           & " here is a refusal the parser makes before it opens the"
           & " extension's body, and the table is the registry answering"
           & " rather than a second copy of it."
           & New_Line & New_Line);

      Put ("| Extension | Code point |");
      for Context in Ext.Message_Context'Range loop
         Put (" " & Ext.Image (Context) & " |");
      end loop;
      Put (New_Line & "|---|---|");
      for Context in Ext.Message_Context'Range loop
         pragma Unreferenced (Context);
         Put ("---|");
      end loop;
      Put (New_Line);

      for Kind in Ext.Extension_Kind'Range loop
         Put ("| `" & Ext.Image (Kind) & "` | ");
         if Kind = Ext.Unknown_Extension then
            Put ("-- |");
         else
            declare
               Text : constant String := Natural (Ext.Value_Of (Kind))'Image;
            begin
               Put (Text (Text'First + 1 .. Text'Last) & " |");
            end;
         end if;

         for Context in Ext.Message_Context'Range loop
            Put ((if Ext.Permitted (Kind, Context) then " yes |" else " no |"));
         end loop;
         Put (New_Line);
      end loop;

      Put (New_Line);
      Put ("`unknown_extension` is not a code point: it is what the parser"
           & " calls anything it does not recognize, and it is tolerated only"
           & " in a ClientHello -- which RFC 8446 section 4.2 requires a"
           & " server to ignore. Anywhere else it is unsolicited by"
           & " construction, because this endpoint cannot have asked for"
           & " something it does not know." & New_Line);

      return Page (1 .. Used);
   end Extension_Context_Table;









   ---------------------------------------------------------------------------
   --  Version negotiation over a connection
   ---------------------------------------------------------------------------

   Negotiate_Anchors    : aliased SSL.Trust.Snapshot;
   Negotiate_Credential : aliased SSL.Credentials.Credential;
   Negotiate_Client     : aliased SSL.Configurations.Client_Configuration;
   Negotiate_Server     : aliased SSL.Configurations.Server_Configuration;

   Negotiate_To_Server : aliased Tests_Pipes.Pipe;
   Negotiate_To_Client : aliased Tests_Pipes.Pipe;
   Negotiate_Client_Medium : aliased Tests_Pipes.Pipe_Transport;
   Negotiate_Server_Medium : aliased Tests_Pipes.Pipe_Transport;

   -------------------------------------
   -- Check_Version_Negotiation --
   -------------------------------------

   function Check_Version_Negotiation return String is
      package Conn renames SSL.Connections;
      package Config renames SSL.Configurations;
      package Meta renames SSL.Connection_Metadata;

      use type SSL.Versions.Protocol_Version;

      Now    : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);
      Error  : SSL.Errors.Error_Information;
      Ok     : Boolean;
      Moved  : Boolean;
      Rounds : Natural;

      Client : Conn.Connection;
      Server : Conn.Connection;
   begin
      SSL.Trust.Load_Explicit_Anchors
        (Negotiate_Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load";
      end if;
      SSL.Credentials.Load_PEM
        (Negotiate_Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the credential fixture did not load";
      end if;

      --  A client that speaks only TLS 1.2, against a server that speaks both.
      --  This is the case the fallback exists for, and it is the one a
      --  deployment actually meets.
      declare
         Builder : Config.Client_Builder;
      begin
         Config.Modern_Compatibility_Client (Builder);
         Config.Set_Versions (Builder, SSL.Versions.Only (SSL.Versions.TLS_1_2), Ok);
         if not Ok then
            return "a TLS 1.2-only version set must be accepted";
         end if;
         Config.Set_Expected_Name
           (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
         Config.Set_Anchors (Builder, Negotiate_Anchors'Access, Ok);
         Config.Build (Builder, Negotiate_Client, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      declare
         Builder : Config.Server_Builder;
      begin
         Config.Modern_Compatibility_Server (Builder);
         Config.Add_Credential (Builder, Negotiate_Credential'Access, Ok);
         Config.Build (Builder, Negotiate_Server, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server configuration did not build: " & SSL.Errors.Image (Error);
         end if;
      end;

      Tests_Pipes.Reset (Negotiate_To_Server);
      Tests_Pipes.Reset (Negotiate_To_Client);
      Tests_Pipes.Attach
        (Negotiate_Client_Medium, Negotiate_To_Server'Access,
         Negotiate_To_Client'Access, 'v');
      Tests_Pipes.Attach
        (Negotiate_Server_Medium, Negotiate_To_Client'Access,
         Negotiate_To_Server'Access, 'V');

      SSL.Servers.Accept_Connection
        (Server, Negotiate_Server'Access, Negotiate_Server_Medium'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      SSL.Clients.Connect
        (Client, Negotiate_Client'Access, Negotiate_Client_Medium'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the connections did not start: " & SSL.Errors.Image (Error);
      end if;

      Rounds := 0;
      loop
         Rounds := Rounds + 1;
         if Rounds > 4_000 then
            return "the TLS 1.2 connection did not converge";
         end if;
         Conn.Step (Client, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client failed: " & SSL.Errors.Image (Error);
         end if;
         Conn.Step (Server, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the server failed: " & SSL.Errors.Image (Error);
         end if;
         exit when Conn.Is_Established (Client) and then Conn.Is_Established (Server);
      end loop;

      if Meta.Version (Conn.Metadata_Of (Client)) /= SSL.Versions.TLS_1_2 then
         return "a TLS 1.2-only client negotiates TLS 1.2";
      end if;
      if Meta.Version (Conn.Metadata_Of (Server)) /= SSL.Versions.TLS_1_2 then
         return "the server agrees it is TLS 1.2";
      end if;
      if not Meta.Peer_Authenticated (Conn.Metadata_Of (Client)) then
         return "the client authenticated the server over TLS 1.2 too";
      end if;

      --  Application data across the TLS 1.2 record layer, which is a different
      --  construction from TLS 1.3's and is where a mistake in the additional
      --  data or the nonce would show.
      declare
         Payload  : constant Byte_Array := [1 .. 200 => 16#6C#];
         Accepted : Byte_Index;
         Chunk    : Byte_Array (1 .. 1_024) := [others => 0];
         Count    : Byte_Index := 0;
      begin
         Conn.Write_Available (Client, Payload, Accepted, Error);
         if SSL.Errors.Is_Error (Error) or else Accepted /= Payload'Length then
            return "the client could not send over TLS 1.2";
         end if;

         Rounds := 0;
         while Count = 0 loop
            Rounds := Rounds + 1;
            if Rounds > 1_000 then
               return "TLS 1.2 application data did not arrive";
            end if;
            Conn.Step (Client, Moved, Error);
            Conn.Step (Server, Moved, Error);
            if SSL.Errors.Is_Error (Error) then
               return "a TLS 1.2 connection failed while sending: "
                 & SSL.Errors.Image (Error);
            end if;
            Conn.Read_Available (Server, Chunk, Count, Error);
         end loop;

         if Chunk (1 .. Count) /= Payload then
            return "TLS 1.2 application data did not arrive intact";
         end if;
      end;

      Conn.Wipe (Client);
      Conn.Wipe (Server);
      return "";
   end Check_Version_Negotiation;


   ---------------------------------------------------------------------------
   --  Mutation
   ---------------------------------------------------------------------------

   -----------------------------------
   -- Check_Mutated_Messages --
   -----------------------------------

   function Check_Mutated_Messages return String is
      package Mutation renames Tests_Mutation;

      --  Every message this runner damages must survive every mutation with a
      --  structured answer. The seeds are messages this library itself
      --  produces, so a mutation is exactly "what a peer could have sent
      --  instead".
      Buffer  : Byte_Array (1 .. 4_096) := [others => 0];
      Damaged : Byte_Array (1 .. 4_200) := [others => 0];
      Written : Byte_Index;
      Length  : Byte_Index;
      Error   : SSL.Errors.Error_Information;

      Examined : Natural := 0;

      Load : SSL.Errors.Error_Information;

      --  Drive one seed through every mutation of every kind, handing each
      --  result to a parser. The parser's only obligation is to return: any
      --  answer is acceptable, and an exception is not.
      function Sweep (Seed : Byte_Array; Label : String) return String;

      function Sweep (Seed : Byte_Array; Label : String) return String is
      begin
         for Kind in Mutation.Mutation_Kind loop
            for Index in 1 .. Mutation.Case_Count (Kind, Seed'Length) loop
               Mutation.Mutate (Seed, Kind, Index, Damaged, Length);
               Examined := Examined + 1;

               --  Every parser, on every mutation. Which one the seed was built
               --  for does not matter: a peer can send any message at any time,
               --  and a parser handed the wrong one must refuse rather than
               --  misread it.
               declare
                  Hello   : Messages.Client_Hello_Message;
                  Server  : Messages.Server_Hello_Message;
                  Encrypt : Messages.Encrypted_Extensions_Message;
                  Chain   : Messages.Certificate_Message;
                  Request : Messages.Certificate_Request_Message;
                  Verify  : Messages.Certificate_Verify_Message;
                  Ticket  : Messages.New_Session_Ticket_Message;
                  Update  : Messages.Key_Update_Request;
                  First   : Byte_Index;
                  Last    : Byte_Index;
               begin
                  Messages.Parse_Client_Hello (Damaged (1 .. Length), Bounds, Hello, Error);
                  Messages.Parse_Server_Hello (Damaged (1 .. Length), Bounds, Server, Error);
                  Messages.Parse_Encrypted_Extensions
                    (Damaged (1 .. Length), Bounds, Encrypt, Error);
                  Messages.Parse_Certificate (Damaged (1 .. Length), Bounds, Chain, Error);
                  Messages.Parse_Certificate_Request
                    (Damaged (1 .. Length), Bounds, Request, Error);
                  Messages.Parse_Certificate_Verify
                    (Damaged (1 .. Length), Bounds, Verify, Error);
                  Messages.Parse_New_Session_Ticket
                    (Damaged (1 .. Length), Bounds, Ticket, Error);
                  Messages.Parse_Finished
                    (Damaged (1 .. Length), Bounds, First, Last, Error);
                  Messages.Parse_Key_Update (Damaged (1 .. Length), Update, Error);
               exception
                  when others =>
                     --  The one thing a parser may not do. An exception here is
                     --  a bug however the message got that way, because every
                     --  one of these messages arrives from a peer.
                     return "a parser raised on " & Label & " under "
                       & Mutation.Image (Kind) & Integer'Image (Index);
               end;
            end loop;
         end loop;
         return "";
      end Sweep;

   begin
      SSL.Credentials.Load_PEM
        (Mutation_Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Load);
      if SSL.Errors.Is_Error (Load) then
         return "the certificate fixture did not load";
      end if;

      --  Seed one: a ClientHello this library encodes.
      declare
         Shares : Messages.Key_Share_List;
         Binders : Byte_Index;
      begin
         Shares (1).Group := SSL.Supported_Groups.X25519;
         Shares (1).Length := 32;
         Shares (1).Value (1 .. 32) := [others => 16#42#];

         Messages.Encode_Client_Hello
           (Config         => Handshake_Client_Setup,
            Random_Value   => [others => 16#11#],
            Session_Id     => [1 .. 32 => 16#22#],
            Shares         => Shares,
            Share_Count    => 1,
            Cookie         => Empty_Bytes,
            Identity       => Empty_Bytes,
            Obfuscated_Age => 0,
            Binder_Length  => 0,
            Into           => Buffer,
            Written        => Written,
            Binders_At     => Binders,
            Error          => Error);
         if SSL.Errors.Is_Error (Error) then
            return "the ClientHello seed did not encode";
         end if;

         declare
            Report_Text : constant String :=
              Sweep (Buffer (1 .. Written), "a ClientHello");
         begin
            if Report_Text /= "" then
               return Report_Text;
            end if;
         end;
      end;

      --  Seed two: a ServerHello.
      Messages.Encode_Server_Hello
        (Random_Value => [others => 16#33#],
         Session_Id   => [1 .. 32 => 16#22#],
         Suite        => SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256,
         Share_Group  => SSL.Supported_Groups.X25519,
         Share_Value  => [1 .. 32 => 16#44#],
         Has_Identity => False,
         Identity     => 0,
         Into         => Buffer,
         Written      => Written,
         Error        => Error);
      if SSL.Errors.Is_Error (Error) then
         return "the ServerHello seed did not encode";
      end if;
      declare
         Report_Text : constant String := Sweep (Buffer (1 .. Written), "a ServerHello");
      begin
         if Report_Text /= "" then
            return Report_Text;
         end if;
      end;

      --  Seed three: a NewSessionTicket, whose lengths nest three deep.
      Messages.Encode_New_Session_Ticket
        (Lifetime => 3_600,
         Age_Add  => 16#01020304#,
         Nonce    => [1 .. 8 => 16#55#],
         Ticket   => [1 .. 64 => 16#66#],
         Into     => Buffer,
         Written  => Written,
         Error    => Error);
      if SSL.Errors.Is_Error (Error) then
         return "the ticket seed did not encode";
      end if;
      declare
         Report_Text : constant String := Sweep (Buffer (1 .. Written), "a ticket");
      begin
         if Report_Text /= "" then
            return Report_Text;
         end if;
      end;

      --  Seed four: a Certificate carrying the real fixture chain. The deepest
      --  nesting in the protocol -- a message length, a list length, a
      --  certificate length and a per-entry extension block -- and therefore
      --  the seed most likely to find a length treated as trusted.
      declare
         Leaf  : constant Byte_Array := SSL.Credentials.Certificate_At (Mutation_Credential, 1);
         Spans : Messages.Certificate_Span_List := [others => <>];
      begin
         Spans (1) := (First => Leaf'First, Last => Leaf'Last);
         Messages.Encode_Certificate
           (Chain   => Leaf,
            Spans   => Spans,
            Count   => 1,
            Context => Empty_Bytes,
            Staple  => Empty_Bytes,
            Into    => Buffer,
            Written => Written,
            Error   => Error);
         if SSL.Errors.Is_Error (Error) then
            return "the certificate seed did not encode";
         end if;

         declare
            Report_Text : constant String :=
              Sweep (Buffer (1 .. Written), "a Certificate");
         begin
            if Report_Text /= "" then
               return Report_Text;
            end if;
         end;
      end;

      --  A sanity check on the runner itself: a sweep that examined nothing
      --  would pass silently and prove nothing. The figure is thirteen
      --  mutations per octet of seed -- eight bit flips and one each of the
      --  other five kinds -- so it is a statement about how much seed was
      --  covered rather than an arbitrary threshold.
      if Examined < 10_000 then
         return Report ("mutations examined", "at least 10000",
                        Natural'Image (Examined));
      end if;

      return "";
   end Check_Mutated_Messages;

   ---------------------------------------------------------------------------
   --  Limit boundaries
   ---------------------------------------------------------------------------

   ---------------------------------
   -- Check_Limit_Boundaries --
   ---------------------------------

   function Check_Limit_Boundaries return String is
      --  A limit is only meaningful if it is checked at exactly the right
      --  place. Testing at the limit alone would pass for a check that is off
      --  by one in either direction, so each is tested at limit-1, at the
      --  limit, and at limit+1.
      Tight : SSL.Limits.Resource_Limits := Bounds;

      Buffer : Byte_Array (1 .. 8_192) := [others => 0];
      Error  : SSL.Errors.Error_Information;
   begin
      --  Certificate count. A chain of exactly the permitted number must be
      --  accepted and one more refused.
      Tight.Maximum_Certificate_Count := 3;

      for Count in 2 .. 4 loop
         declare
            One    : constant Byte_Array := [1 .. 20 => 16#AA#];
            Chain  : Byte_Array (1 .. 4 * One'Length) := [others => 0];
            Spans  : Messages.Certificate_Span_List := [others => <>];
            Parsed : Messages.Certificate_Message;
            Written : Byte_Index;
         begin
            for Index in 1 .. Count loop
               Chain (Byte_Index (Index - 1) * One'Length + 1
                      .. Byte_Index (Index) * One'Length) := One;
               Spans (Index) :=
                 (First => Byte_Index (Index - 1) * One'Length + 1,
                  Last  => Byte_Index (Index) * One'Length);
            end loop;

            Messages.Encode_Certificate
              (Chain   => Chain,
               Spans   => Spans,
               Count   => Count,
               Context => Empty_Bytes,
               Staple  => Empty_Bytes,
               Into    => Buffer,
               Written => Written,
               Error   => Error);
            if SSL.Errors.Is_Error (Error) then
               return "a certificate seed did not encode";
            end if;

            Messages.Parse_Certificate (Buffer (1 .. Written), Tight, Parsed, Error);

            if Count <= 3 then
               if SSL.Errors.Is_Error (Error) then
                  return Report ("chain of" & Integer'Image (Count), "accepted",
                                 SSL.Errors.Image (Error));
               end if;
               if Messages.Entry_Count (Parsed) /= Count then
                  return "an accepted chain reports its own length";
               end if;
            else
               if not SSL.Errors.Is_Error (Error) then
                  return "a chain past the configured count must be refused";
               end if;
            end if;
         end;
      end loop;

      --  A declared length far beyond the limit, with no payload at all. This
      --  is the shape that distinguishes "bounded before allocation" from
      --  "bounded after": a parser that reserved storage from the declared
      --  length would do so here, for a message four octets long.
      declare
         Parsed : Messages.Certificate_Message;
         Huge   : constant Byte_Array :=
           Messages.Encode_Header (Messages.Certificate, 4)
           & From_Hex ("00")            --  empty context
           & From_Hex ("FFFFFF");       --  a sixteen-megabyte certificate list
      begin
         Messages.Parse_Certificate (Huge, Tight, Parsed, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a huge declared length with no payload must be refused";
         end if;
         if Messages.Entry_Count (Parsed) /= 0 then
            return "a refused message reports nothing";
         end if;
      end;

      --  The extension block, at its own three boundaries. The limit is
      --  expressed in octets of block, so the seeds are built to land exactly
      --  on it.
      for Offset in -1 .. 1 loop
         declare
            Block_Limit : constant Byte_Index := 64;
            Body_Size   : constant Byte_Index :=
              Block_Limit + Byte_Index (Offset);
            Padded      : Byte_Array (1 .. Body_Size) := [others => 0];
            Message     : Byte_Array
              (1 .. Messages.Header_Length + 2 + Body_Size) := [others => 0];
            Parsed      : Messages.Encrypted_Extensions_Message;
            Narrow      : SSL.Limits.Resource_Limits := Bounds;
         begin
            Narrow.Maximum_Extension_Block := Positive (Block_Limit);

            --  A block of unknown extensions, which an EncryptedExtensions
            --  parser records and acts on nowhere -- so the only thing under
            --  test is the bound.
            declare
               Cursor : Byte_Index := 1;
            begin
               while Cursor + 3 <= Body_Size loop
                  Padded (Cursor) := 16#7F#;
                  Padded (Cursor + 1) := Byte (Cursor mod 256);
                  Padded (Cursor + 2) := 0;
                  Padded (Cursor + 3) := 0;
                  Cursor := Cursor + 4;
               end loop;
            end;

            Message (1 .. Messages.Header_Length) :=
              Messages.Encode_Header
                (Messages.Encrypted_Extensions, 2 + Body_Size);
            Message (Messages.Header_Length + 1) := Byte (Body_Size / 256);
            Message (Messages.Header_Length + 2) := Byte (Body_Size mod 256);
            Message (Messages.Header_Length + 3 .. Message'Last) := Padded;

            Messages.Parse_Encrypted_Extensions (Message, Narrow, Parsed, Error);

            --  An unknown extension in EncryptedExtensions is unsolicited and
            --  is refused whatever its size, so what is under test here is the
            --  *bound* rather than acceptance: at the limit and below, the
            --  refusal must not be the block-limit one; above it, it must be.
            declare
               Block_Refusal : constant Boolean :=
                 SSL.Errors.Is_Error (Error)
                 and then Tests_Support.Index_Of (SSL.Errors.Image (Error), "block_limit") > 0;
            begin
               if Offset <= 0 then
                  if Block_Refusal then
                     return Report ("extension block at limit" & Integer'Image (Offset),
                                    "not a block-limit refusal",
                                    SSL.Errors.Image (Error));
                  end if;
               else
                  if not Block_Refusal then
                     return Report ("extension block past the limit",
                                    "a block-limit refusal",
                                    SSL.Errors.Image (Error));
                  end if;
               end if;
            end;
         end;
      end loop;

      return "";
   end Check_Limit_Boundaries;


   ---------------------------------------------------------------------------
   --  Concurrency and callback re-entrancy
   ---------------------------------------------------------------------------

   Shared_Cache : aliased SSL.Sessions.Client_Caches.Memory.Memory_Cache
                            (Capacity => 8);

   ------------------------------------
   -- Check_Cache_Concurrency --
   ------------------------------------

   function Check_Cache_Concurrency return String is
      package Sessions renames SSL.Sessions;
      package Caches renames SSL.Sessions.Client_Caches;

      Now : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);

      --  Eight tasks hammering one cache. A client cache is exactly the thing
      --  several workers reach at once -- each opening its own outbound
      --  connection to the same handful of hosts -- so this is the shape the
      --  protected object exists for rather than an artificial stress.
      Workers    : constant := 8;
      Iterations : constant := 250;

      Names : constant array (1 .. 4) of SSL.Server_Names.DNS_Name :=
        [SSL.Server_Names.Name ("one.example.com"),
         SSL.Server_Names.Name ("two.example.com"),
         SSL.Server_Names.Name ("three.example.com"),
         SSL.Server_Names.Name ("four.example.com")];

      Trouble : Boolean := False;
      pragma Atomic (Trouble);

      task type Worker is
         entry Start (Seed : Positive);
      end Worker;

      task body Worker is
         Mine : Positive;
      begin
         accept Start (Seed : Positive) do
            Mine := Seed;
         end Start;

         for Round in 1 .. Iterations loop
            declare
               Which : constant Positive := ((Mine + Round) mod Names'Length) + 1;
               Value : Sessions.Session;
               Found : Boolean;
               Kept  : Boolean;
               Error : SSL.Errors.Error_Information;
            begin
               --  Store, look up, discard: every operation the cache has, from
               --  every task, on overlapping keys. What is under test is that
               --  none of them corrupts another -- an unprotected cache would
               --  produce a torn session or an index out of range.
               Sessions.Store
                 (Item          => Value,
                  Version       => SSL.Versions.TLS_1_3,
                  Suite         => SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256,
                  Name          => Names (Which),
                  Protocol      => SSL.ALPN.No_Protocol,
                  Has_Protocol  => False,
                  Issued        => Now,
                  Lifetime      => 3_600,
                  Context       => SSL.Default_Security_Context,
                  Setup         => SSL.Configuration_From_Digest ([1 .. 32 => 0]),
                  Anchors       => SSL.Trust_From_Digest ([1 .. 32 => 0]),
                  Authenticated => True,
                  Ticket_Bytes  => [1 .. 32 => Byte (Round mod 256)],
                  Age_Add       => 0,
                  Nonce_Bytes   => [1 .. 8 => 0],
                  Secret        => [1 .. 32 => Byte (Mine mod 256)],
                  Error         => Error);

               if SSL.Errors.Is_Error (Error) then
                  Trouble := True;
                  exit;
               end if;

               Caches.Store_Safely (Shared_Cache, Value, Kept, Error);
               Sessions.Wipe (Value);

               Caches.Look_Up_Safely
                 (Item    => Shared_Cache,
                  Name    => Names (((Mine + Round + 1) mod Names'Length) + 1),
                  Context => SSL.Default_Security_Context,
                  At_Time => Now,
                  Into    => Value,
                  Found   => Found,
                  Error   => Error);

               if Found and then not Sessions.Is_Present (Value) then
                  --  A cache that said it found something and supplied nothing.
                  Trouble := True;
                  exit;
               end if;
               Sessions.Wipe (Value);

               Caches.Discard_Safely
                 (Shared_Cache,
                  Names (((Mine + Round + 2) mod Names'Length) + 1),
                  SSL.Default_Security_Context);
            end;
         end loop;
      exception
         when others =>
            --  Any exception at all from a protected operation is a failure.
            Trouble := True;
      end Worker;

      Crew : array (1 .. Workers) of Worker;
   begin
      SSL.Sessions.Client_Caches.Memory.Clear (Shared_Cache);

      for Index in Crew'Range loop
         Crew (Index).Start (Index);
      end loop;

      --  Ada's own rule finishes the job: the declaring block does not complete
      --  until every task in it has. Nothing here needs a join.
      declare
         Held : constant Natural :=
           SSL.Sessions.Client_Caches.Memory.Occupancy (Shared_Cache);
      begin
         if Trouble then
            return "a worker task saw the cache misbehave";
         end if;

         --  The capacity is a real bound and not an aspiration: eight tasks
         --  storing two thousand sessions between them must leave at most the
         --  eight the cache holds.
         if Held > 8 then
            return Report ("cached sessions", "at most 8", Natural'Image (Held));
         end if;
      end;

      SSL.Sessions.Client_Caches.Memory.Clear (Shared_Cache);
      return "";
   end Check_Cache_Concurrency;

   --------------------------------------
   -- Check_Callback_Reentrancy --
   --------------------------------------

   --  A diagnostic sink that calls back into the library from inside its own
   --  Emit, and one that raises. Both are things an application will
   --  eventually do, and neither may take a connection down.
   type Reentrant_Sink is limited new SSL.Diagnostics.Sink with record
      Depth   : Natural := 0;
      Deepest : Natural := 0;
      Seen    : Natural := 0;
   end record;

   overriding procedure Emit
     (Item : in out Reentrant_Sink; What : SSL.Diagnostics.Event);
   overriding function Description (Item : Reentrant_Sink) return String;

   overriding procedure Emit
     (Item : in out Reentrant_Sink; What : SSL.Diagnostics.Event)
   is
   begin
      Item.Seen := Item.Seen + 1;
      Item.Depth := Item.Depth + 1;
      Item.Deepest := Natural'Max (Item.Deepest, Item.Depth);

      --  Reach back into the library from inside the callback. Rendering an
      --  event is the most likely thing an application does here, and it must
      --  not need the library to be re-entrant in any deeper sense.
      declare
         Line : constant String :=
           SSL.Diagnostics.Image (What, SSL.Diagnostics.Operational);
         pragma Unreferenced (Line);
      begin
         null;
      end;

      Item.Depth := Item.Depth - 1;
   end Emit;

   overriding function Description (Item : Reentrant_Sink) return String is
     ("reentrant sink" & (if Item.Seen = 0 then "" else ""));

   Reentrant_Watcher : aliased Reentrant_Sink;

   Reentrant_Client : aliased SSL.Configurations.Client_Configuration;
   Reentrant_To_Server : aliased Tests_Pipes.Pipe;
   Reentrant_To_Client : aliased Tests_Pipes.Pipe;
   Reentrant_Client_Medium : aliased Tests_Pipes.Pipe_Transport;
   Reentrant_Server_Medium : aliased Tests_Pipes.Pipe_Transport;

   function Check_Callback_Reentrancy return String is
      package Conn renames SSL.Connections;
      package Config renames SSL.Configurations;

      Now    : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);
      Client : Conn.Connection;
      Server : Conn.Connection;
      Error  : SSL.Errors.Error_Information;
      Ok     : Boolean;
      Moved  : Boolean;
      Rounds : Natural := 0;
   begin
      declare
         Builder : Config.Client_Builder;
      begin
         Config.Secure_Client_Defaults (Builder);
         Config.Set_Expected_Name
           (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
         Config.Set_Anchors (Builder, Pipe_Anchors'Access, Ok);
         Config.Set_Diagnostics
           (Item      => Builder,
            Value     => Reentrant_Watcher'Unchecked_Access,
            Level     => SSL.Diagnostics.Detailed_Protocol,
            Redaction => SSL.Diagnostics.Operational);
         Config.Build (Builder, Reentrant_Client, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client configuration did not build";
         end if;
      end;

      Tests_Pipes.Reset (Reentrant_To_Server);
      Tests_Pipes.Reset (Reentrant_To_Client);
      Tests_Pipes.Attach
        (Reentrant_Client_Medium, Reentrant_To_Server'Access,
         Reentrant_To_Client'Access, 'x');
      Tests_Pipes.Attach
        (Reentrant_Server_Medium, Reentrant_To_Client'Access,
         Reentrant_To_Server'Access, 'X');

      SSL.Servers.Accept_Connection
        (Server, Pipe_Server_Setup'Access, Reentrant_Server_Medium'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      SSL.Clients.Connect
        (Client, Reentrant_Client'Access, Reentrant_Client_Medium'Unchecked_Access,
         SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the connections did not start";
      end if;

      loop
         Rounds := Rounds + 1;
         if Rounds > 2_000 then
            return "the connection did not converge with a re-entrant sink";
         end if;
         Conn.Step (Client, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return "a re-entrant sink broke the connection: " & SSL.Errors.Image (Error);
         end if;
         Conn.Step (Server, Moved, Error);
         exit when Conn.Is_Established (Client) and then Conn.Is_Established (Server);
      end loop;

      if Reentrant_Watcher.Seen = 0 then
         return "the sink was never called, so nothing was proved";
      end if;
      if Reentrant_Watcher.Deepest /= 1 then
         --  The library must not call a sink from inside a sink. If it did, an
         --  application doing anything stateful in one would see its own state
         --  half-updated.
         return Report ("deepest sink nesting", " 1",
                        Natural'Image (Reentrant_Watcher.Deepest));
      end if;

      Conn.Wipe (Client);
      Conn.Wipe (Server);
      return "";
   end Check_Callback_Reentrancy;


   ---------------------------------------------------------------------------
   --  Delivering a connection's octets at every boundary
   ---------------------------------------------------------------------------

   Split_Client_Setup : aliased SSL.Configurations.Client_Configuration;
   Split_Server_Setup : aliased SSL.Configurations.Server_Configuration;
   Split_To_Server : aliased Tests_Pipes.Pipe;
   Split_To_Client : aliased Tests_Pipes.Pipe;
   Split_Client_Medium : aliased Tests_Pipes.Pipe_Transport;
   Split_Server_Medium : aliased Tests_Pipes.Pipe_Transport;

   -----------------------------------
   -- Check_Byte_At_A_Time --
   -----------------------------------

   function Check_Byte_At_A_Time return String is
      package Engines renames SSL.Engines;

      use type SSL.Engines.Lifecycle;

      Now : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);

      Client : Engines.Engine;
      Server : Engines.Engine;
      Error  : SSL.Errors.Error_Information;
      Rounds : Natural := 0;

      --  Move one octet at a time, in both directions.
      --
      --  This is the strongest form of the incremental-parsing requirement:
      --  every record header, every handshake message, every length prefix and
      --  every epoch transition is split at every internal boundary, because a
      --  single octet cannot straddle anything. A parser that assumed a whole
      --  record had arrived, or that a handshake message did not span records,
      --  fails somewhere in here.
      function Trickle
        (From : in out Engines.Engine;
         To   : in out Engines.Engine) return Byte_Index;

      function Trickle
        (From : in out Engines.Engine;
         To   : in out Engines.Engine) return Byte_Index
      is
         Moved : Byte_Index := 0;
      begin
         while Engines.Pending_Encrypted (From) > 0 loop
            declare
               One      : Byte_Array (1 .. 1) := [others => 0];
               Copied   : Byte_Index;
               Consumed : Byte_Index;
            begin
               Engines.Peek_Encrypted (From, One, Copied);
               exit when Copied = 0;

               Engines.Supply_Encrypted (To, One (1 .. 1), Consumed, Error);
               exit when SSL.Errors.Is_Error (Error) or else Consumed = 0;

               Engines.Consume_Encrypted (From, Consumed);
               Moved := Moved + Consumed;

               --  Advance after every single octet, so the engine is asked to
               --  make progress at every boundary rather than only at the ones
               --  a friendly chunking would have produced.
               Engines.Advance (To, SSL.Clocks.Current_Monotonic, Error);
               exit when SSL.Errors.Is_Error (Error);
            end;
         end loop;
         return Moved;
      end Trickle;
   begin
      Engines.Start_Server
        (Server, Pipe_Server_Setup'Access, SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the server engine did not start";
      end if;
      Engines.Start_Client
        (Client, Pipe_Client_Setup'Access, SSL.No_Connection, Now, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the client engine did not start";
      end if;

      loop
         Rounds := Rounds + 1;
         if Rounds > 64 then
            return "the octet-at-a-time handshake did not converge";
         end if;

         declare
            Forward : constant Byte_Index := Trickle (Client, Server);
            Back    : constant Byte_Index := Trickle (Server, Client);
         begin
            if SSL.Errors.Is_Error (Error) then
               return "an engine refused an octet-at-a-time handshake: "
                 & SSL.Errors.Image (Error);
            end if;
            exit when Forward = 0 and then Back = 0;
         end;
      end loop;

      if Engines.State_Of (Client) /= Engines.Established
        or else Engines.State_Of (Server) /= Engines.Established
      then
         return "an octet-at-a-time handshake must still establish: "
           & Engines.Image (Engines.State_Of (Client)) & " / "
           & Engines.Image (Engines.State_Of (Server));
      end if;

      --  And application data, also one octet at a time, across the epoch that
      --  has already changed.
      declare
         Payload  : constant Byte_Array := [1 .. 500 => 16#2D#];
         Accepted : Byte_Index;
         Landed   : Byte_Array (1 .. 512) := [others => 0];
         Copied   : Byte_Index;
         Ignored  : Byte_Index;
      begin
         Engines.Write_Plaintext (Client, Payload, Accepted, Error);
         if SSL.Errors.Is_Error (Error) or else Accepted /= Payload'Length then
            return "the client could not write";
         end if;

         Ignored := Trickle (Client, Server);
         Engines.Peek_Plaintext (Server, Landed, Copied);
         if Landed (1 .. Copied) /= Payload then
            return "data delivered one octet at a time must arrive intact";
         end if;
         Engines.Consume_Plaintext (Server, Copied);
      end;

      --  Several records in one supply, which is the opposite hazard: a driver
      --  that handled one record per call would leave the rest sitting in the
      --  buffer for ever.
      declare
         Payload  : constant Byte_Array := [1 .. 40_000 => 16#3E#];
         Accepted : Byte_Index;
         Chunk    : Byte_Array (1 .. 65_536) := [others => 0];
         Copied   : Byte_Index;
         Consumed : Byte_Index;
         Received : Byte_Index := 0;
         Landed   : Byte_Array (1 .. 40_000) := [others => 0];
      begin
         Engines.Write_Plaintext (Client, Payload, Accepted, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the client could not write a large payload";
         end if;

         --  Everything the client has queued, handed over in one call. At
         --  16 kB per record that is three records at once.
         while Engines.Pending_Encrypted (Client) > 0 loop
            Engines.Peek_Encrypted (Client, Chunk, Copied);
            exit when Copied = 0;
            Engines.Supply_Encrypted (Server, Chunk (1 .. Copied), Consumed, Error);
            exit when SSL.Errors.Is_Error (Error) or else Consumed = 0;
            Engines.Consume_Encrypted (Client, Consumed);
            Engines.Advance (Server, SSL.Clocks.Current_Monotonic, Error);
            exit when SSL.Errors.Is_Error (Error);

            declare
               Piece : Byte_Array (1 .. 65_536) := [others => 0];
               Taken : Byte_Index;
            begin
               Engines.Peek_Plaintext (Server, Piece, Taken);
               if Taken > 0 then
                  Landed (Received + 1 .. Received + Taken) := Piece (1 .. Taken);
                  Received := Received + Taken;
                  Engines.Consume_Plaintext (Server, Taken);
               end if;
            end;
         end loop;

         if SSL.Errors.Is_Error (Error) then
            return "several records in one supply failed: " & SSL.Errors.Image (Error);
         end if;
         if Received /= Accepted then
            return Report ("octets received", Byte_Index'Image (Accepted),
                           Byte_Index'Image (Received));
         end if;
         if Landed (1 .. Received) /= Payload (1 .. Received) then
            return "several records in one supply must arrive intact";
         end if;
      end;

      Engines.Wipe (Client);
      Engines.Wipe (Server);
      return "";
   end Check_Byte_At_A_Time;

   ---------------------------------------------------------------------------
   --  The validation pipeline
   ---------------------------------------------------------------------------

   ---------------------------------
   -- Check_Validation_Pipeline --
   ---------------------------------

   function Check_Validation_Pipeline return String is
      package Validation renames SSL.Certificate_Validation;
      use type Validation.Leaf_Key_Kind;

      Anchors    : aliased SSL.Trust.Snapshot;
      Credential : SSL.Credentials.Credential;
      Error      : SSL.Errors.Error_Information;

      --  Inside the fixture's validity window, and fixed, so the test does not
      --  depend on today's date.
      Now : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 8, 1);
   begin
      SSL.Trust.Load_Explicit_Anchors
        (Anchors, Tests_Fixtures.Anchor_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the anchor fixture did not load: " & SSL.Errors.Image (Error);
      end if;
      if SSL.Trust.Anchor_Count (Anchors) /= 1 then
         return "one anchor was expected";
      end if;

      SSL.Credentials.Load_PEM
        (Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return "the credential fixture did not load: " & SSL.Errors.Image (Error);
      end if;

      --  The credential reports what the leaf actually says.
      if SSL.Credentials.Key_Type (Credential) /= SSL.Credentials.Ed25519_Key then
         return "the fixture holds an Ed25519 key";
      end if;
      if not SSL.Credentials.Supports
               (Credential, SSL.Signature_Schemes.Ed25519)
      then
         return "an Ed25519 credential must support the ed25519 scheme";
      end if;
      if SSL.Credentials.Supports
           (Credential, SSL.Signature_Schemes.RSA_PSS_RSAE_SHA256)
      then
         return "an Ed25519 credential must not claim an RSA scheme";
      end if;

      --  Both subjectAltName entries were read, and the specificity ranking
      --  prefers the exact name over the wildcard.
      if SSL.Credentials.Identity_Count (Credential) /= 2 then
         return Report ("subjectAltName entries", "2",
                        SSL.Credentials.Identity_Count (Credential)'Image);
      end if;
      if SSL.Credentials.Covers
           (Credential, SSL.Server_Names.Name ("www.example.com")) = 0
      then
         return "the credential must cover its own exact name";
      end if;
      if SSL.Credentials.Covers
           (Credential, SSL.Server_Names.Name ("other.example.com")) = 0
      then
         return "the credential must cover its wildcard";
      end if;
      if SSL.Credentials.Covers
           (Credential, SSL.Server_Names.Name ("www.elsewhere.test")) /= 0
      then
         return "the credential must not cover an unrelated name";
      end if;
      if SSL.Credentials.Covers (Credential, SSL.Server_Names.Name ("www.example.com"))
        <= SSL.Credentials.Covers (Credential, SSL.Server_Names.Name ("other.example.com"))
      then
         return "an exact subjectAltName must outrank the wildcard";
      end if;

      --  Signing works, and the signature verifies against the leaf's own key.
      declare
         Message   : constant Byte_Array := From_Hex ("48656c6c6f20544c53");
         Signature : Byte_Array (1 .. SSL.Credentials.Maximum_Signature_Length) :=
           [others => 0];
         Length    : Byte_Index;
      begin
         SSL.Credentials.Sign
           (Credential, SSL.Signature_Schemes.Ed25519, Message, Signature, Length, Error);
         if SSL.Errors.Is_Error (Error) then
            return "Ed25519 signing failed: " & SSL.Errors.Image (Error);
         end if;
         if Length /= 64 then
            return Report ("ed25519 signature length", "64", Length'Image);
         end if;

         --  An ECDSA scheme this credential cannot produce is refused by name
         --  rather than attempted.
         SSL.Credentials.Sign
           (Credential, SSL.Signature_Schemes.ECDSA_Secp256r1_SHA256,
            Message, Signature, Length, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "an Ed25519 credential signed an ECDSA scheme";
         end if;
         if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_Signer_Capability_Missing then
            return "an unsupported scheme produced the wrong failure code";
         end if;
      end;

      --  The pipeline itself: a one-certificate chain that is its own anchor.
      declare
         Leaf  : constant Byte_Array := SSL.Credentials.Certificate_At (Credential, 1);
         Chain : aliased Validation.Chain_Storage (Leaf'Length);
         Result : Validation.Validation_Result;
      begin
         Chain.Octets := Leaf;
         Chain.Spans (1) := (First => 1, Last => Leaf'Length);

         Validation.Validate
           (Chain    => Chain,
            Count    => 1,
            Anchors  => Anchors,
            Identity => Validation.For_Name (SSL.Server_Names.Name ("www.example.com")),
            Role     => Validation.Server_Certificate,
            At_Time  => Now,
            Bounds   => Bounds,
            Result   => Result,
            Error    => Error);
         if SSL.Errors.Is_Error (Error) then
            return "a valid chain was refused: " & SSL.Errors.Image (Error);
         end if;
         if Validation.Leaf_Key_Type (Result) /= Validation.Ed25519_Key then
            return "the pipeline mis-read the leaf key type";
         end if;
         if Validation.Leaf_Fingerprint (Result)
           /= SSL.Credentials.Leaf_Fingerprint (Credential)
         then
            return "the pipeline and the credential disagree on the leaf fingerprint";
         end if;

         --  The wildcard name is covered too.
         Validation.Validate
           (Chain, 1, Anchors,
            Validation.For_Name (SSL.Server_Names.Name ("other.example.com")),
            Validation.Server_Certificate, Now, Bounds, Result, Error);
         if SSL.Errors.Is_Error (Error) then
            return "the wildcard name was refused: " & SSL.Errors.Image (Error);
         end if;

         --  A name the certificate is not for is refused *after* the path has
         --  validated. Identity is an additional condition, never a substitute.
         Validation.Validate
           (Chain, 1, Anchors,
            Validation.For_Name (SSL.Server_Names.Name ("www.elsewhere.test")),
            Validation.Server_Certificate, Now, Bounds, Result, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a certificate was accepted for a name it is not for";
         end if;
         if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_Identity_No_Match then
            return "an identity mismatch produced the wrong failure code";
         end if;

         --  Outside the validity window.
         Validation.Validate
           (Chain, 1, Anchors,
            Validation.For_Name (SSL.Server_Names.Name ("www.example.com")),
            Validation.Server_Certificate, SSL.Clocks.UTC (2020, 1, 1),
            Bounds, Result, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a certificate was accepted before it was valid";
         end if;

         --  With no wall clock at all, validity cannot be judged, so the
         --  pipeline refuses rather than assuming.
         Validation.Validate
           (Chain, 1, Anchors,
            Validation.For_Name (SSL.Server_Names.Name ("www.example.com")),
            Validation.Server_Certificate, SSL.Clocks.No_Wall_Time,
            Bounds, Result, Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a certificate was accepted with no clock to judge validity";
         end if;

         --  An empty trust snapshot means nothing can validate, and it is
         --  reported as the configuration failure it is.
         declare
            Empty : aliased SSL.Trust.Snapshot;
         begin
            Validation.Validate
              (Chain, 1, Empty,
               Validation.For_Name (SSL.Server_Names.Name ("www.example.com")),
               Validation.Server_Certificate, Now, Bounds, Result, Error);
            if not SSL.Errors.Is_Error (Error) then
               return "a chain validated against no anchors at all";
            end if;
            if SSL.Errors.Code_Of (Error) /= SSL.Errors.Code_Trust_Required_But_Absent then
               return "an empty trust base produced the wrong failure code";
            end if;
         end;

         --  A chain the anchor does not cover: the same leaf, but validated
         --  against a snapshot built from nothing related to it. There is no
         --  second fixture, so this is covered by the empty-anchor case above
         --  and by the path-building tests in cryptolib.
         null;
      end;

      return "";
   end Check_Validation_Pipeline;

   ---------------------------------------------------------------------------
   --  Buffers
   ---------------------------------------------------------------------------

   -------------------------------
   -- Check_Queue_Backpressure --
   -------------------------------

   function Check_Queue_Backpressure return String is
      Item : SSL.Buffers.Queue;
      Ok   : Boolean;
      Data : constant Byte_Array (1 .. 8) := [others => 16#11#];
      Out_Buffer : Byte_Array (1 .. 8);
      Copied : Byte_Index;
   begin
      SSL.Buffers.Reserve (Item, 16, Ok);
      if not Ok then
         return "reserving a queue failed";
      end if;
      if SSL.Buffers.Capacity (Item) /= 16 or else SSL.Buffers.Space (Item) /= 16 then
         return "a fresh queue reported the wrong capacity";
      end if;

      SSL.Buffers.Append (Item, Data, Ok);
      if not Ok or else SSL.Buffers.Length (Item) /= 8 then
         return "appending to an empty queue failed";
      end if;

      SSL.Buffers.Append (Item, Data, Ok);
      if not Ok or else SSL.Buffers.Space (Item) /= 0 then
         return "filling a queue exactly failed";
      end if;

      --  Full means full: no growth, and an all-or-nothing refusal.
      SSL.Buffers.Append (Item, Data (1 .. 1), Ok);
      if Ok then
         return "a full queue accepted more";
      end if;
      if SSL.Buffers.Length (Item) /= 16 then
         return "a refused append changed the queue";
      end if;

      --  Draining makes room again, and the octets come back in order.
      SSL.Buffers.Peek (Item, Out_Buffer, Copied);
      if Copied /= 8 or else Out_Buffer /= Data then
         return "peeking returned the wrong octets";
      end if;
      SSL.Buffers.Consume (Item, 8);
      if SSL.Buffers.Space (Item) /= 8 then
         return "consuming did not free space";
      end if;

      SSL.Buffers.Append (Item, Data, Ok);
      if not Ok then
         return "a drained queue refused an append that fits";
      end if;

      SSL.Buffers.Release (Item);
      return "";
   end Check_Queue_Backpressure;

   ---------------------------------
   -- Check_Queue_Partial_Append --
   ---------------------------------

   function Check_Queue_Partial_Append return String is
      Item : SSL.Buffers.Queue;
      Ok   : Boolean;
      Data : constant Byte_Array (1 .. 10) := [others => 16#22#];
      Accepted : Byte_Index;
   begin
      SSL.Buffers.Reserve (Item, 4, Ok);
      SSL.Buffers.Append_Partial (Item, Data, Accepted);
      if Accepted /= 4 then
         return Report ("partial append", "4", Accepted'Image);
      end if;
      if SSL.Buffers.Length (Item) /= 4 then
         return "a partial append did not queue what it reported";
      end if;

      SSL.Buffers.Append_Partial (Item, Data, Accepted);
      if Accepted /= 0 then
         return "a full queue accepted octets in a partial append";
      end if;

      SSL.Buffers.Release (Item);
      return "";
   end Check_Queue_Partial_Append;

   ---------------------------------------
   -- Check_PSS_Signature_Verification --
   ---------------------------------------

   function Check_PSS_Signature_Verification return String is
      Modulus_Hex : constant String :=
        "eda66e8e74fd6e04e99282f52f13153b856a59cf6be7b5bddd5473b54eacac4c43e60b2d5bd98e0aa8559439"
        & "fea7d24389e4cb59a782909127d5661b4ceca2b51ee802688ad9bbaf77871706c55ec8b09343768f6eb6240d"
        & "b6474e6dcf4f639559455b94010ed58244a5eccc9066ef4daaac62cbcf3af938a20e8da458a18e8d78edf75f"
        & "f4d65f3eb3bade68f4a0e80848ac60edec51199ecb3490b662e04e692dac129919af92e83bd88f658bd7e48c"
        & "610845aed7c86b68827de33e31be15cc13ccdda683c64d015919d47da0e552860295101086c547e2a6aaeaba"
        & "65d844ddaf5658dc61b0a97187fb0fa2b1a7176d1028f70739d67a5ae9ae410c4b60befb";

      Signature_Hex : constant String :=
        "604e628b09500e7271e6c38a37959ff5f868a4854d199ee9f7479b2933673a744b08cfd01364701899b36cad"
        & "8c414d568c31a2b8ec2259c8a5b83c29d69153ee52435becb74352ee6e6fb36ac352ca6eef9ebe07888901f0"
        & "2293cf536a12f8ba2398417c9d3ea1d418c51444b602758559e9f064db94a9ebb21fb49eee88a8071a77ce36"
        & "25b32c1c6c516ae590b51f71c6a81d40836362c5c9249462d6ec6b907e51c27f3a3edf52b42b42fb3b6c01f9"
        & "9976d739bd5ba56a09fc7ad3835961ac9439d8cd678c2b0b5245c493fef468b5c926163000f6df15cd35c17f"
        & "c2e290e2d3377f7ff6f7cf875423e5ea74d7dc9e448ee5fea36d0507ac93e4ea4dc6c8f9";

      --  RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }, which is the
      --  encoding Verify_Signature documents for RSA. The modulus has its top
      --  bit set, so its INTEGER carries a leading zero octet.
      Key : constant Byte_Array :=
        [16#30#, 16#82#, 16#01#, 16#0A#,
         16#02#, 16#82#, 16#01#, 16#01#, 16#00#]
        & From_Hex (Modulus_Hex)
        & [16#02#, 16#03#, 16#01#, 16#00#, 16#01#];

      Signed : constant Byte_Array := From_Hex ("63727970746f6c6962207073732"
                                                & "06b6e6f776e20616e73776572");
      Signature : constant Byte_Array := From_Hex (Signature_Hex);
      Error     : SSL.Errors.Error_Information;
   begin
      --  A signature OpenSSL made with SHA-256 and a 32-octet salt, which is
      --  the rsa_pss_rsae_sha256 profile exactly: RFC 8446 section 4.2.3 fixes
      --  MGF1 with the same hash and a salt equal to the digest length.
      SSL.Crypto.Verify_Signature
        (Scheme      => SSL.Signature_Schemes.RSA_PSS_RSAE_SHA256,
         Public_Key  => Key,
         Signed_Data => Signed,
         Signature   => Signature,
         Error       => Error);
      if SSL.Errors.Is_Error (Error) then
         return "a valid PSS signature was refused: " & SSL.Errors.Image (Error);
      end if;

      --  The scheme selects the hash. Verifying the same signature as
      --  SHA-384 must fail, or the scheme is decoration.
      SSL.Crypto.Verify_Signature
        (Scheme      => SSL.Signature_Schemes.RSA_PSS_RSAE_SHA384,
         Public_Key  => Key,
         Signed_Data => Signed,
         Signature   => Signature,
         Error       => Error);
      if not SSL.Errors.Is_Error (Error) then
         return "a PSS signature verified under the wrong hash";
      end if;

      declare
         Tampered : Byte_Array := Signature;
      begin
         Tampered (Tampered'Last) := Tampered (Tampered'Last) xor 1;
         SSL.Crypto.Verify_Signature
           (Scheme      => SSL.Signature_Schemes.RSA_PSS_RSAE_SHA256,
            Public_Key  => Key,
            Signed_Data => Signed,
            Signature   => Tampered,
            Error       => Error);
         if not SSL.Errors.Is_Error (Error) then
            return "a tampered PSS signature verified";
         end if;
      end;

      return "";
   end Check_PSS_Signature_Verification;

   ---------------------------------
   -- Check_Key_Agreement_Groups --
   ---------------------------------

   function Check_Key_Agreement_Groups return String is
      use SSL.Supported_Groups;

      --  Two deterministic sources with different patterns, one per party, so
      --  the test depends on no system entropy and on no property of how a
      --  single source advances.
      --
      --  Drawing both parties from one patterned source does not work and the
      --  reason is worth recording: the deterministic source cycles its
      --  pattern, so when the draw length is a multiple of the pattern length
      --  the second draw starts at the same phase and returns the same octets.
      --  A 24-octet pattern and a 48-octet P-384 scalar is exactly that case,
      --  and it produced two identical key shares.
      Ours_Source   : SSL.Crypto.Random_Source;
      Theirs_Source : SSL.Crypto.Random_Source;
      Error         : SSL.Errors.Error_Information;
   begin
      SSL.Crypto.Use_Fixed_Pattern
        (Ours_Source, From_Hex ("a3f1029c5e7b46d80f2a91cc37e5b8140d6693fa2c518e07"));
      SSL.Crypto.Use_Fixed_Pattern
        (Theirs_Source, From_Hex ("5c0e7b1449a2f36d8e05c73b120fa96d47e8815300bd2ca6f1"));

      for Group in Named_Group loop
         declare
            Ours, Theirs   : SSL.Crypto.Key_Exchange_Pair;
            Our_Secret     : SSL.Secrets.Secret (SSL.Secrets.Agreement_Capacity);
            Their_Secret   : SSL.Secrets.Secret (SSL.Secrets.Agreement_Capacity);
            Expected_Share : constant Byte_Index := Share_Length (Group);
            Expected_Width : constant Byte_Index := Secret_Length (Group);
         begin
            SSL.Crypto.Generate (Ours, Group, Ours_Source, Error);
            if SSL.Errors.Is_Error (Error) then
               return "generating " & Image (Group) & ": " & SSL.Errors.Image (Error);
            end if;
            SSL.Crypto.Generate (Theirs, Group, Theirs_Source, Error);
            if SSL.Errors.Is_Error (Error) then
               return "generating a second " & Image (Group) & " pair: "
                 & SSL.Errors.Image (Error);
            end if;

            --  The share is exactly the width the registry states, which is
            --  what bounds a peer key_share before any arithmetic sees it.
            if SSL.Crypto.Public_Share (Ours)'Length /= Expected_Share then
               return Report (Image (Group) & " share length",
                              Expected_Share'Image,
                              SSL.Crypto.Public_Share (Ours)'Length'Image);
            end if;

            --  Two independently generated pairs must not collide.
            if SSL.Crypto.Public_Share (Ours) = SSL.Crypto.Public_Share (Theirs) then
               return "two " & Image (Group) & " key shares were identical";
            end if;

            SSL.Crypto.Agree (Ours, SSL.Crypto.Public_Share (Theirs), Our_Secret, Error);
            if SSL.Errors.Is_Error (Error) then
               return "agreeing over " & Image (Group) & ": " & SSL.Errors.Image (Error);
            end if;
            SSL.Crypto.Agree (Theirs, SSL.Crypto.Public_Share (Ours), Their_Secret, Error);
            if SSL.Errors.Is_Error (Error) then
               return "agreeing back over " & Image (Group) & ": " & SSL.Errors.Image (Error);
            end if;

            if not SSL.Secrets.Equal (Our_Secret, Their_Secret) then
               return "the two ends disagreed on the " & Image (Group) & " shared secret";
            end if;
            if SSL.Secrets.Length (Our_Secret) /= Expected_Width then
               return Report (Image (Group) & " secret length",
                              Expected_Width'Image,
                              SSL.Secrets.Length (Our_Secret)'Image);
            end if;

            --  A share of the wrong length for its group is refused on the
            --  length alone, before any exponentiation or point arithmetic.
            declare
               Short : constant Byte_Array (1 .. Expected_Share - 1) := [others => 0];
            begin
               SSL.Crypto.Agree (Ours, Short, Our_Secret, Error);
               if not SSL.Errors.Is_Error (Error) then
                  return "a short " & Image (Group) & " peer share was accepted";
               end if;
               if SSL.Secrets.Is_Present (Our_Secret) then
                  return "a refused " & Image (Group) & " share produced a secret";
               end if;
            end;

            --  An all-zero share is the degenerate element in every family
            --  here: the identity for the curves, and Y = 0 for finite fields.
            declare
               Zeroes : constant Byte_Array (1 .. Expected_Share) := [others => 0];
            begin
               SSL.Crypto.Agree (Ours, Zeroes, Our_Secret, Error);
               if not SSL.Errors.Is_Error (Error) then
                  return "an all-zero " & Image (Group) & " peer share was accepted";
               end if;
            end;

            SSL.Crypto.Wipe (Ours);
            SSL.Crypto.Wipe (Theirs);
         end;
      end loop;

      return "";
   end Check_Key_Agreement_Groups;

end SSL.Internal_Tests;
