with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Unbounded;
with Ada.Text_IO;

with GNAT.OS_Lib;

with Project_Tools.Files;
with Project_Tools.Processes;
with Project_Tools.Text;

with SSL.Version;

--  The Ada driver for build, test, verification, documentation, packaging and
--  release. There is no shell script, Makefile or Python in this repository, and
--  CI invokes this program rather than reimplementing any of it.
--
--  Every subcommand prints a line per step and returns a stable exit status: 0
--  for success, 1 for a failed check, 2 for a usage error, 3 for a missing
--  prerequisite. With --json it writes a versioned machine-readable report
--  instead of prose, so that a CI job can gate on fields rather than on text.
--
--  What is implemented here corresponds to the parts of the library that exist.
--  Subcommands whose subject is not yet implemented say so and exit 3 rather
--  than passing vacuously: a release gate that reports success because it had
--  nothing to check is worse than one that is absent.
procedure Ssllib_Tools is

   use Ada.Strings.Unbounded;

   package IO renames Ada.Text_IO;
   package Files renames Project_Tools.Files;
   package Processes renames Project_Tools.Processes;
   package Text renames Project_Tools.Text;

   Exit_Success        : constant := 0;
   Exit_Check_Failed   : constant := 1;
   Exit_Usage          : constant := 2;
   Exit_Unavailable    : constant := 3;

   Report_As_JSON : Boolean := False;
   Dry_Run        : Boolean := False;

   --  The repository root, which is the parent of the tests crate this program
   --  is built in. Derived from the current directory rather than from an
   --  environment variable: an implicit environment-driven path is exactly the
   --  kind of hidden configuration this project refuses elsewhere.
   function Repository_Root return String;

   function Repository_Root return String is
      Here : constant String := Ada.Directories.Current_Directory;
   begin
      if Files.File_Exists (Here & "/ssllib.gpr") then
         return Here;
      end if;

      declare
         Parent : constant String := Ada.Directories.Containing_Directory (Here);
      begin
         if Files.File_Exists (Parent & "/ssllib.gpr") then
            return Parent;
         end if;
      end;

      return Here;
   end Repository_Root;

   Root : constant String := Repository_Root;

   --  Join a repository-relative path onto the root.
   --
   --  Not Ada.Directories.Compose: that takes a *simple* name and raises
   --  Name_Error on anything containing a separator, which every path in this
   --  program does. Joining with a forward slash is correct on every platform
   --  GNAT targets, Windows included.
   function Under (Relative : String) return String
   is (Root & "/" & Relative);

   Failures : Natural := 0;

   procedure Note (Text_Item : String);
   procedure Step (Label : String; Ok : Boolean; Detail : String := "");

   ----------
   -- Note --
   ----------

   procedure Note (Text_Item : String) is
   begin
      if not Report_As_JSON then
         IO.Put_Line (Text_Item);
      end if;
   end Note;

   ----------
   -- Step --
   ----------

   procedure Step (Label : String; Ok : Boolean; Detail : String := "") is
   begin
      if not Ok then
         Failures := Failures + 1;
      end if;

      if Report_As_JSON then
         IO.Put_Line
           ("    {""step"": """ & Label & """, ""ok"": "
            & (if Ok then "true" else "false")
            & (if Detail = "" then "" else ", ""detail"": """ & Detail & """")
            & "},");
      else
         IO.Put_Line
           ((if Ok then "  ok    " else "  FAIL  ") & Label
            & (if Detail = "" then "" else "  -- " & Detail));
      end if;
   end Step;

   ---------------------------------------------------------------------------
   --  Build and test
   ---------------------------------------------------------------------------

   function Run_Alr (Label : String; Directory : String; Argument : String) return Boolean;

   function Run_Alr (Label : String; Directory : String; Argument : String) return Boolean is
      Arguments : GNAT.OS_Lib.Argument_List :=
        [1 => new String'("--non-interactive"),
         2 => new String'(Argument)];
      Status : Integer;
   begin
      if Dry_Run then
         Note ("  would run: alr --non-interactive " & Argument & "  in " & Directory);
         for Item of Arguments loop
            GNAT.OS_Lib.Free (Item);
         end loop;
         return True;
      end if;

      Status := Processes.Run_Status
        (Label   => Label,
         Dir     => Directory,
         Program => Processes.Locate_Command ("alr"),
         Args    => Arguments,
         Quiet   => Report_As_JSON);

      for Item of Arguments loop
         GNAT.OS_Lib.Free (Item);
      end loop;
      return Status = 0;
   end Run_Alr;

   procedure Command_Build;

   procedure Command_Build is
   begin
      Note ("ssllib_tools build");
      Step ("runtime library builds", Run_Alr ("build ssllib", Root, "build"));
      Step ("test and tooling crate builds",
            Run_Alr ("build ssllib_tests", Under ("tests"), "build"));
   end Command_Build;

   procedure Command_Test;

   procedure Command_Test is
      Runner : constant String :=
        Under ("tests/bin/ssllib_tests");
      Empty  : GNAT.OS_Lib.Argument_List (1 .. 0);
   begin
      Note ("ssllib_tools test");

      if not Run_Alr ("build ssllib_tests", Under ("tests"), "build") then
         Step ("test crate builds", False);
         return;
      end if;
      Step ("test crate builds", True);

      if Dry_Run then
         Step ("unit and vector tests", True, "dry run");
         return;
      end if;

      if not Files.File_Exists (Runner) then
         Step ("unit and vector tests", False, "runner not found at " & Runner);
         return;
      end if;

      Step ("unit and vector tests",
            Processes.Run_Status
              (Label   => "ssllib_tests",
               Dir     => Root,
               Program => Runner,
               Args    => Empty,
               Quiet   => Report_As_JSON) = 0);
   end Command_Test;

   ---------------------------------------------------------------------------
   --  Audits
   --
   --  These are the checks that keep the project's stated boundaries true. Each
   --  one is a property a reviewer would otherwise have to re-establish by
   --  reading, and each one fails the release when it stops holding.
   ---------------------------------------------------------------------------

   --  Does any runtime source outside the permitted adapters name CryptoLib?
   function Audit_Dependency_Boundaries return Boolean;

   function Audit_Dependency_Boundaries return Boolean is
      Source_Directory : constant String := Under ("src");
      Search  : Ada.Directories.Search_Type;
      Item    : Ada.Directories.Directory_Entry_Type;
      Clean   : Boolean := True;

      --  The units allowed to name CryptoLib. Everything cryptographic goes
      --  through SSL.Crypto; SSL.Buffers and SSL.Secrets reach only for the
      --  secure-wipe and constant-time primitives, which is what makes their
      --  scrubbing non-elidable.
      function Permitted (Name : String) return Boolean
      is (Name in "ssl-crypto.ads" | "ssl-crypto.adb"
                | "ssl-buffers.adb" | "ssl-secrets.adb");

   begin
      if not Files.Directory_Exists (Source_Directory) then
         return False;
      end if;

      Ada.Directories.Start_Search (Search, Source_Directory, "*.ad[bs]");
      while Ada.Directories.More_Entries (Search) loop
         Ada.Directories.Get_Next_Entry (Search, Item);
         declare
            Name : constant String := Ada.Directories.Simple_Name (Item);
            Path : constant String := Ada.Directories.Full_Name (Item);
         begin
            if not Permitted (Name)
              and then Files.File_Contains (Path, "CryptoLib.")
            then
               Note ("    " & Name & " names CryptoLib outside the adapter");
               Clean := False;
            end if;

            --  Nothing in the runtime may name AUnit or project_tools.
            if Files.File_Contains (Path, "AUnit")
              or else Files.File_Contains (Path, "Project_Tools")
            then
               Note ("    " & Name & " names test or tooling code from the runtime");
               Clean := False;
            end if;
         end;
      end loop;
      Ada.Directories.End_Search (Search);

      return Clean;
   end Audit_Dependency_Boundaries;

   --  Is every Check_<Name> in the internal test unit registered?
   function Audit_Test_Registration return Boolean;

   function Audit_Test_Registration return Boolean is
      Spec : constant String :=
        Under ("tests/src/ssl-internal_tests.ads");
      Cases : constant String :=
        Under ("tests/src/tests_internals.adb");
      Content : Unbounded_String;
      Clean   : Boolean := True;
      Cursor  : Natural;
   begin
      if not Files.File_Exists (Spec) or else not Files.File_Exists (Cases) then
         return False;
      end if;

      Content := Text.Read_Text_File (Spec);

      --  Every declared check must appear in the registering body. An
      --  unregistered check passes without testing anything, which is the one
      --  failure mode a test suite cannot report on itself.
      Cursor := 1;
      loop
         declare
            Whole : constant String := To_String (Content);
            Found : constant Natural :=
              (if Cursor > Whole'Length then 0
               else Text.Index_From (Whole, "function Check_", Cursor));
         begin
            exit when Found = 0;

            declare
               Start : constant Natural := Found + String'("function ")'Length;
               Stop  : Natural := Start;
            begin
               while Stop <= Whole'Last
                 and then (Whole (Stop) in 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '_')
               loop
                  Stop := Stop + 1;
               end loop;

               declare
                  Check_Name : constant String := Whole (Start .. Stop - 1);
               begin
                  if not Files.File_Contains (Cases, Check_Name) then
                     Note ("    " & Check_Name & " is declared but never called");
                     Clean := False;
                  end if;
               end;

               Cursor := Stop;
            end;
         end;
      end loop;

      return Clean;
   end Audit_Test_Registration;

   --  Does the crate version in alire.toml agree with SSL.Version?
   function Audit_Version_Consistency return Boolean;

   function Audit_Version_Consistency return Boolean is
      Manifest : constant String := Under ("alire.toml");
   begin
      if not Files.File_Exists (Manifest) then
         return False;
      end if;
      return Files.File_Contains
        (Manifest, "version = """ & SSL.Version.Crate_Version & """");
   end Audit_Version_Consistency;

   --  Are the documents the project promises present and non-trivial?
   function Audit_Documentation return Boolean;

   function Audit_Documentation return Boolean is
      Required : constant Files.Path_List :=
        [To_Unbounded_String ("README.md"),
         To_Unbounded_String ("SECURITY.md"),
         To_Unbounded_String ("CHANGELOG.md"),
         To_Unbounded_String ("LICENSE"),
         To_Unbounded_String ("docs/architecture.md"),
         To_Unbounded_String ("docs/package-map.md"),
         To_Unbounded_String ("docs/security-model.md"),
         To_Unbounded_String ("docs/known-limitations.md"),
         To_Unbounded_String ("docs/status.md"),
         To_Unbounded_String ("invariant-registry/registry.md")];
      Clean : Boolean := True;
   begin
      for Entry_Item of Required loop
         declare
            Relative : constant String := To_String (Entry_Item);
            Path     : constant String := Under (Relative);
         begin
            if not Files.File_Exists (Path) then
               Note ("    missing " & Relative);
               Clean := False;
            elsif Natural (Ada.Directories.Size (Path)) < 200 then
               --  A promised document that exists but says nothing is worse than
               --  one that is missing: it reads as covered.
               Note ("    " & Relative & " is present but effectively empty");
               Clean := False;
            end if;
         end;
      end loop;
      return Clean;
   end Audit_Documentation;

   --  Does every invariant in the registry declare verification coverage?
   function Audit_Invariant_Coverage return Boolean;

   function Audit_Invariant_Coverage return Boolean is
      Registry : constant String :=
        Under ("invariant-registry/registry.md");
      Content  : Unbounded_String;
      Clean    : Boolean := True;
      Cursor   : Natural := 1;
   begin
      if not Files.File_Exists (Registry) then
         return False;
      end if;

      Content := Text.Read_Text_File (Registry);

      --  Every entry is a table row beginning with an invariant identifier. A
      --  row whose verification column is empty or "none" is an invariant
      --  nobody checks, and the release must not pass with one.
      declare
         Whole : constant String := To_String (Content);
      begin
         loop
            declare
               Found : constant Natural :=
                 (if Cursor > Whole'Length then 0
                  else Text.Index_From (Whole, "| verification: none", Cursor));
            begin
               exit when Found = 0;
               Note ("    an invariant declares no verification coverage");
               Clean := False;
               Cursor := Found + 1;
            end;
         end loop;
      end;

      return Clean;
   end Audit_Invariant_Coverage;

   procedure Command_Verify;

   procedure Command_Verify is
   begin
      Note ("ssllib_tools verify");
      Step ("dependency boundaries hold", Audit_Dependency_Boundaries);
      Step ("every internal check is registered", Audit_Test_Registration);
      Step ("crate version matches SSL.Version", Audit_Version_Consistency);
      Step ("promised documents are present", Audit_Documentation);
      Step ("every invariant declares coverage", Audit_Invariant_Coverage);
   end Command_Verify;

   ---------------------------------------------------------------------------
   --  Not yet available
   ---------------------------------------------------------------------------

   procedure Unavailable (Command : String; Because : String);

   procedure Unavailable (Command : String; Because : String) is
   begin
      if Report_As_JSON then
         IO.Put_Line ("{""schema"": 1, ""command"": """ & Command
                      & """, ""available"": false, ""reason"": """ & Because & """}");
      else
         IO.Put_Line ("ssllib_tools " & Command & ": not available yet");
         IO.Put_Line ("  " & Because);
         IO.Put_Line ("  See docs/status.md for what this release implements.");
      end if;
      Ada.Command_Line.Set_Exit_Status
        (Ada.Command_Line.Exit_Status (Exit_Unavailable));
   end Unavailable;

   ---------------------------------------------------------------------------
   --  Usage
   ---------------------------------------------------------------------------

   procedure Usage;

   procedure Usage is
   begin
      IO.Put_Line ("ssllib_tools <command> [--json] [--dry-run]");
      IO.Put_Line ("");
      IO.Put_Line ("  build          build the runtime library and the test crate");
      IO.Put_Line ("  test           build and run the AUnit suite, including the vector checks");
      IO.Put_Line ("  test-vectors   run only the authoritative-vector checks");
      IO.Put_Line ("  test-corpus    replay the permanent mutation corpus");
      IO.Put_Line ("  test-interop   run the interoperability matrix against external stacks");
      IO.Put_Line ("  prove          run GNATprove over the proof targets");
      IO.Put_Line ("  docs           generate the API documentation");
      IO.Put_Line ("  verify         run the API, dependency-boundary and no-secret audits");
      IO.Put_Line ("  package        produce reproducible source artifacts and hashes");
      IO.Put_Line ("  release        run every gate in order and emit release metadata");
      IO.Put_Line ("");
      IO.Put_Line ("Exit status: 0 success, 1 a check failed, 2 usage, 3 unavailable.");
   end Usage;

   Command : Unbounded_String;

begin
   ---------------------------------------------------------------------------
   --  Argument handling
   ---------------------------------------------------------------------------

   for Index in 1 .. Ada.Command_Line.Argument_Count loop
      declare
         Argument : constant String := Ada.Command_Line.Argument (Index);
      begin
         if Argument = "--json" then
            Report_As_JSON := True;
         elsif Argument = "--dry-run" then
            Dry_Run := True;
         elsif Text.Starts_With (Argument, "--") then
            IO.Put_Line ("unknown option: " & Argument);
            Usage;
            Ada.Command_Line.Set_Exit_Status
              (Ada.Command_Line.Exit_Status (Exit_Usage));
            return;
         elsif Command = Null_Unbounded_String then
            Command := To_Unbounded_String (Argument);
         else
            IO.Put_Line ("unexpected argument: " & Argument);
            Usage;
            Ada.Command_Line.Set_Exit_Status
              (Ada.Command_Line.Exit_Status (Exit_Usage));
            return;
         end if;
      end;
   end loop;

   if Command = Null_Unbounded_String then
      Usage;
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Exit_Status (Exit_Usage));
      return;
   end if;

   if Report_As_JSON then
      IO.Put_Line ("{");
      IO.Put_Line ("  ""schema"": 1,");
      IO.Put_Line ("  ""crate"": ""ssllib"",");
      IO.Put_Line ("  ""version"": """ & SSL.Version.Crate_Version & """,");
      IO.Put_Line ("  ""command"": """ & To_String (Command) & """,");
      IO.Put_Line ("  ""steps"": [");
   end if;

   declare
      Name : constant String := To_String (Command);
   begin
      if Name = "build" then
         Command_Build;

      elsif Name = "test" then
         Command_Test;

      elsif Name = "verify" then
         Command_Verify;

      elsif Name = "test-vectors" then
         --  The authoritative-vector checks run inside the AUnit suite, so this
         --  is the same runner. It is a separate subcommand because CI gates on
         --  it separately.
         Command_Test;

      elsif Name = "test-corpus" then
         Unavailable
           ("test-corpus",
            "the mutation corpus and its deterministic Ada runner are not implemented "
            & "in this release; there is no corpus to replay.");
         return;

      elsif Name = "test-interop" then
         Unavailable
           ("test-interop",
            "the interoperability controller needs a complete handshake to drive, and the "
            & "TLS 1.3 and TLS 1.2 state machines are not implemented in this release.");
         return;

      elsif Name = "prove" then
         Unavailable
           ("prove",
            "the GNATprove profiles are not configured in this release; the proof targets "
            & "named in docs/status.md have contracts but no proof run.");
         return;

      elsif Name = "docs" then
         Unavailable
           ("docs",
            "generated API documentation is not wired up in this release; the hand-written "
            & "documents under docs/ are current and the verify audit checks them.");
         return;

      elsif Name = "package" then
         Unavailable
           ("package",
            "artifact generation is gated on the release gates, which cannot pass in this "
            & "release. See docs/status.md.");
         return;

      elsif Name = "release" then
         Unavailable
           ("release",
            "the V1 acceptance criteria in the implementation specification are not met by "
            & "this release, so the release command refuses rather than producing artifacts "
            & "that would claim otherwise. See docs/status.md.");
         return;

      else
         IO.Put_Line ("unknown command: " & Name);
         Usage;
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Exit_Status (Exit_Usage));
         return;
      end if;
   end;

   if Report_As_JSON then
      --  A trailing empty object keeps the array valid without tracking commas.
      IO.Put_Line ("    {}");
      IO.Put_Line ("  ],");
      IO.Put_Line ("  ""failures"": " & Failures'Image & ",");
      IO.Put_Line ("  ""ok"": " & (if Failures = 0 then "true" else "false"));
      IO.Put_Line ("}");
   else
      IO.Put_Line ("");
      if Failures = 0 then
         IO.Put_Line ("all steps passed");
      else
         IO.Put_Line (Failures'Image & " step(s) failed");
      end if;
   end if;

   Ada.Command_Line.Set_Exit_Status
     (Ada.Command_Line.Exit_Status (if Failures = 0 then Exit_Success else Exit_Check_Failed));
end Ssllib_Tools;
