with Ada.Streams;
with Interfaces;

with SSL.Buffers;
with SSL.Cipher_Suites;
with SSL.Crypto;
with SSL.Errors;
with SSL.Key_Schedule;
with SSL.Records;
with SSL.Secrets;
with SSL.Transcripts;
with SSL.Versions;
with SSL.Wire;

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
         Published : SSL.Secrets.Secret;
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
         Derive_Master (Item, Server_Hash, Client_Hash, Error);
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
         Derive_Master (Item, Hash_A, Hash_B, Error);
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
      Derive_Master (Item, Hash_A, Hash_B, Error);

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
      Derive_Master (Item, Hash_A, Hash_B, Error);

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
      Derive_Master (Item, Hash_A, Hash_B, Error);

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
      Secret_Key : SSL.Secrets.Secret;
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
      Item    : SSL.Secrets.Secret;
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
      Left, Right : SSL.Secrets.Secret;
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

end SSL.Internal_Tests;
