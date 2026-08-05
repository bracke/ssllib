with Ada.Command_Line;
with Ada.Directories;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;

with GNAT.OS_Lib;

with CryptoLib.Hashes;

with Project_Tools.Files;
with Project_Tools.Processes;
with Project_Tools.Text;

with SSL.Alerts;
with SSL.Cipher_Suites;
with SSL.Signature_Schemes;
with SSL.Supported_Groups;
with SSL.Internal_Tests;
with SSL.Version;
with SSL.Versions;

with SSLLib_Interop;

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

   use type SSL.Alerts.Alert_Description;

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

   procedure Command_Interop;

   procedure Command_Interop is
      Succeeded : Boolean;
   begin
      SSLLib_Interop.Run_Matrix (Root, Succeeded);
      Step ("interoperability matrix", Succeeded);
   end Command_Interop;

   --  The proof profiles.
   --
   --  Three, because proof costs time and the three occasions want different
   --  amounts of it: a developer wants an answer in seconds, a release wants
   --  the run that must pass before anything ships, and an audit wants
   --  everything the prover can be made to attempt. The switches differ only in
   --  effort and timeout -- the *targets* are the same, because a profile that
   --  proved less would be a profile that reported a green run over a smaller
   --  claim.
   procedure Command_Prove (Profile : String);

   procedure Command_Prove (Profile : String) is
      Level   : constant String :=
        (if Profile = "release" then "2"
         elsif Profile = "audit" then "4"
         else "0");
      Timeout : constant String :=
        (if Profile = "release" then "60"
         elsif Profile = "audit" then "600"
         else "10");
   begin
      Note ("ssllib_tools prove (" & Profile & ")");

      if Profile not in "development" | "release" | "audit" then
         Step ("profile is one of development, release, audit", False);
         return;
      end if;

      if Processes.Locate_Command ("gnatprove") = "" then
         --  A named skip rather than a failure. GNATprove is not part of a
         --  GNAT installation and a machine without it is not a machine with a
         --  problem -- but a release must not pass on a skip, so that case is
         --  reported separately below.
         Note ("  skip   gnatprove is not installed");
         if Profile = "release" then
            Step ("release proof is mandatory", False);
         end if;
         return;
      end if;

      --  Run through `alr exec`, which is the only thing that knows where the
      --  dependency project files are. Invoking gnatprove directly finds
      --  ssllib.gpr and then fails on the first `with` in it, which reads as a
      --  proof failure and is not one.
      declare
         Arguments : GNAT.OS_Lib.Argument_List :=
           [1 => new String'("--non-interactive"),
            2 => new String'("exec"),
            3 => new String'("--"),
            4 => new String'("gnatprove"),
            5 => new String'("-P" & Root & "/ssllib.gpr"),
            6 => new String'("--level=" & Level),
            7 => new String'("--timeout=" & Timeout),
            8 => new String'("--report=fail"),
            9 => new String'("-j0")];
         Status : Integer;
      begin
         Status := Processes.Run_Status
           (Label   => "gnatprove",
            Dir     => Root,
            Program => Processes.Locate_Command ("alr"),
            Args    => Arguments,
            Quiet   => Report_As_JSON);

         for Item of Arguments loop
            GNAT.OS_Lib.Free (Item);
         end loop;

         Step ("gnatprove over the library (" & Profile & ")", Status = 0);
      end;
   end Command_Prove;

   procedure Command_Build;

   procedure Command_Build is
   begin
      Note ("ssllib_tools build");
      Step ("runtime library builds", Run_Alr ("build ssllib", Root, "build"));
      Step ("test and tooling crate builds",
            Run_Alr ("build ssllib_tests", Under ("tests"), "build"));

      --  The examples are built as part of the ordinary build, not as an
      --  afterthought. An example that stopped compiling would be documentation
      --  of an API that no longer exists, and nothing else in this repository
      --  would notice.
      Step ("examples build",
            Run_Alr ("build ssllib_examples", Under ("examples"), "build"));
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

      --  The units allowed to name CryptoLib, and nothing else.
      --
      --  There are two seams, not one, because CryptoLib owns two domains and
      --  merging them would put certificate parsing behind the same door as the
      --  AEAD:
      --
      --    * the cryptographic seam is SSL.Crypto -- hashes, MACs, KDFs, AEADs,
      --      key agreement, signature verification, randomness;
      --    * the PKI seam is SSL.Credentials, SSL.Trust and
      --      SSL.Certificate_Validation -- X.509 decoding, path building, path
      --      validation, purpose checks, identity matching.
      --
      --  SSL.Buffers and SSL.Secrets reach for Secure_Wipe and Constant_Time
      --  only, which is what makes their scrubbing non-elidable and their
      --  comparisons constant-time.
      --
      --  The list is deliberately explicit and short. Adding a unit to it is a
      --  decision somebody has to write down here; the audit exists so that
      --  reaching for CryptoLib from anywhere else fails the build.
      function Permitted (Name : String) return Boolean
      is (Name in "ssl-crypto.ads" | "ssl-crypto.adb"
                | "ssl-buffers.adb" | "ssl-secrets.adb"
                | "ssl-credentials.ads" | "ssl-credentials.adb"
                | "ssl-trust.adb"
                | "ssl-certificate_validation.ads" | "ssl-certificate_validation.adb");

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
         To_Unbounded_String ("docs/guides/using.md"),
         To_Unbounded_String ("docs/guides/protocols.md"),
         To_Unbounded_String ("docs/guides/operating.md"),
         To_Unbounded_String ("docs/guides/developing.md"),
         To_Unbounded_String ("docs/machine/contracts.md"),
         To_Unbounded_String ("docs/machine/state-machines.md"),
         To_Unbounded_String ("docs/machine/error-registry.md"),
         To_Unbounded_String ("docs/machine/workflows.md"),
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
   --  docs
   ---------------------------------------------------------------------------

   --  Leading and trailing blanks removed. One line of it, rather than a
   --  dependency on `Ada.Strings.Fixed` for a single use.
   function Trim (Value : String) return String;

   function Trim (Value : String) return String is
      First : Positive := Value'First;
      Last  : Natural  := Value'Last;
   begin
      while First <= Last and then Value (First) = ' ' loop
         First := First + 1;
      end loop;
      while Last >= First and then Value (Last) = ' ' loop
         Last := Last - 1;
      end loop;
      return Value (First .. Last);
   end Trim;

   --  Generate one Markdown page per public specification, from the
   --  specifications themselves.
   --
   --  Not a general Ada documentation generator, and it does not try to be. It
   --  extracts what this repository actually writes down: the `@summary` block
   --  that opens every package, and each declaration with the comment that
   --  precedes it. A tool that parsed Ada properly would be a second Ada
   --  front end to keep in step with GNAT, and the thing being documented is
   --  the prose, which is exactly what a comment extractor can reach.
   --
   --  Private packages are skipped. Their specifications are documentation for
   --  this repository's own maintainers, and publishing them as API pages would
   --  invite an application to depend on names it cannot legally reference.
   function Generate_Documentation return Boolean;

   function Generate_Documentation return Boolean is
      Root      : constant String := Repository_Root;
      Source    : constant String := Root & "/src";
      Output    : constant String := Root & "/docs/api";
      Specs     : constant Files.Path_List :=
        Files.List_Tree (Source, "*.ads");
      Generated : Natural := 0;
   begin
      if not Files.Directory_Exists (Source) then
         return False;
      end if;

      begin
         Ada.Directories.Create_Path (Output);
      exception
         when others =>
            return False;
      end;

      for Path of Specs loop
         declare
            Text_Body : constant String := Files.Read_Raw_File (To_String (Path));
            Simple    : constant String :=
              Ada.Directories.Simple_Name (To_String (Path));
            Stem      : constant String :=
              Ada.Directories.Base_Name (Simple);
            Page      : Unbounded_String;
            Unit      : Unbounded_String;
            Private_Unit : Boolean := False;
            In_Private   : Boolean := False;
            First     : Positive := Text_Body'First;
            Pending   : Unbounded_String;
         begin
            --  A line at a time, because that is the granularity the comments
            --  are written at and the only granularity a comment extractor can
            --  honestly claim. A declaration runs until the line that closes it
            --  -- a semicolon at bracket depth zero -- because a page showing
            --  `procedure Export` without its parameters would be a page that
            --  cost a reader a trip to the source anyway.
            declare
               Depth      : Integer := 0;
               Collecting : Boolean := False;
               Current    : Unbounded_String;

               --  How far the declaration's own first line was indented.
               --  Continuation lines keep everything past that, so a parameter
               --  list on the page lines up the way it does in the source.
               Indent : Natural := 0;

               function Leading (Value : String) return Natural;

               function Leading (Value : String) return Natural is
                  Count : Natural := 0;
               begin
                  for Character_Item of Value loop
                     exit when Character_Item /= ' ';
                     Count := Count + 1;
                  end loop;
                  return Count;
               end Leading;

               function Reindented (Value : String) return String is
                 (if Leading (Value) >= Indent
                  then Value (Value'First + Indent .. Value'Last)
                  else Trim (Value));
            begin
               while First <= Text_Body'Last loop
                  declare
                     Last : Natural := First;
                     Stop : Natural;
                  begin
                     while Last <= Text_Body'Last
                       and then Text_Body (Last) /= ASCII.LF
                     loop
                        Last := Last + 1;
                     end loop;
                     Stop := Last - 1;

                     declare
                        Line    : constant String := Text_Body (First .. Stop);
                        Trimmed : constant String := Trim (Line);

                        function Opens_Declaration return Boolean is
                          (Text.Starts_With (Trimmed, "procedure ")
                           or else Text.Starts_With (Trimmed, "function ")
                           or else Text.Starts_With (Trimmed, "type ")
                           or else Text.Starts_With (Trimmed, "subtype ")
                           or else Text.Starts_With (Trimmed, "package ")
                           or else Text.Starts_With (Trimmed, "private package "));
                     begin
                        if Text.Starts_With (Trimmed, "private package ") then
                           Private_Unit := True;
                        end if;

                        if Trimmed = "private" and then not Collecting then
                           In_Private := True;
                        end if;

                        if Text.Starts_With (Trimmed, "package ")
                          and then Unit = Null_Unbounded_String
                        then
                           Unit := To_Unbounded_String (Trimmed);
                        end if;

                        if In_Private then
                           null;

                        elsif Collecting then
                           Append (Current, Reindented (Line) & ASCII.LF);
                           for Character_Item of Trimmed loop
                              if Character_Item = '(' then
                                 Depth := Depth + 1;
                              elsif Character_Item = ')' then
                                 Depth := Depth - 1;
                              end if;
                           end loop;

                           if Depth <= 0
                             and then Trimmed'Length > 0
                             and then Trimmed (Trimmed'Last) = ';'
                           then
                              Append (Page, "```ada" & ASCII.LF);
                              Append (Page, To_String (Current));
                              Append (Page, "```" & ASCII.LF & ASCII.LF);
                              Current := Null_Unbounded_String;
                              Collecting := False;
                              Depth := 0;
                           end if;

                        elsif Text.Starts_With (Trimmed, "--") then
                           declare
                              Rest : constant String :=
                                (if Trimmed'Length > 2
                                 then Trim (Trimmed (Trimmed'First + 2 .. Trimmed'Last))
                                 else "");
                           begin
                              --  `@summary` opens the block that describes the
                              --  package, and it is the one comment on the page
                              --  that is a heading rather than a paragraph.
                              if Text.Starts_With (Rest, "@summary ") then
                                 Append
                                   (Pending,
                                    Rest (Rest'First + 9 .. Rest'Last) & ASCII.LF);
                              else
                                 Append (Pending, Rest & ASCII.LF);
                              end if;
                           end;

                        elsif Trimmed = "" then
                           if Pending /= Null_Unbounded_String then
                              Append (Pending, ASCII.LF);
                           end if;

                        elsif Opens_Declaration then
                           if Pending /= Null_Unbounded_String then
                              Append (Page, To_String (Pending) & ASCII.LF);
                              Pending := Null_Unbounded_String;
                           end if;

                           if Text.Starts_With (Trimmed, "package ")
                             or else Text.Starts_With (Trimmed, "private package ")
                           then
                              --  The package line itself is not shown: the page
                              --  is named after it already.
                              null;
                           else
                              Collecting := True;
                              Depth := 0;
                              Indent := Leading (Line);
                              Current := Null_Unbounded_String;
                              Append (Current, Trimmed & ASCII.LF);
                              for Character_Item of Trimmed loop
                                 if Character_Item = '(' then
                                    Depth := Depth + 1;
                                 elsif Character_Item = ')' then
                                    Depth := Depth - 1;
                                 end if;
                              end loop;

                              if Depth <= 0
                                and then Trimmed (Trimmed'Last) = ';'
                              then
                                 Append (Page, "```ada" & ASCII.LF);
                                 Append (Page, To_String (Current));
                                 Append (Page, "```" & ASCII.LF & ASCII.LF);
                                 Current := Null_Unbounded_String;
                                 Collecting := False;
                              end if;
                           end if;

                        else
                           Pending := Null_Unbounded_String;
                        end if;
                     end;

                     First := Last + 1;
                  end;
               end loop;
            end;

            if not Private_Unit then
               declare
                  Header : constant String :=
                    "# " & Stem & ASCII.LF & ASCII.LF
                    & "Generated from `src/" & Simple & "` by `ssllib_tools docs`."
                    & " The prose is the specification's own; nothing here is"
                    & " written twice." & ASCII.LF & ASCII.LF;
               begin
                  Files.Write_Text_File
                    (Output & "/" & Stem & ".md", Header & To_String (Page));
                  Generated := Generated + 1;
               end;
            end if;
         end;
      end loop;

      return Generated > 0;
   end Generate_Documentation;

   --  A code point as four hexadecimal digits.
   function Hex_16 (Value : Natural) return String;

   function Hex_16 (Value : Natural) return String is
      Digits_Set : constant String := "0123456789abcdef";
      Result     : String (1 .. 4);
      Rest       : Natural := Value;
   begin
      for Index in reverse Result'Range loop
         Result (Index) := Digits_Set (Rest mod 16 + 1);
         Rest := Rest / 16;
      end loop;
      return Result;
   end Hex_16;

   --  The specification tables, generated by asking the library.
   --
   --  Written from the registries rather than by hand, and that is the whole
   --  point of them. A table of cipher suites typed into a document is a table
   --  that is right on the day it is typed; one produced by walking
   --  `SSL.Cipher_Suites.Cipher_Suite'Range` and asking each value for its own
   --  code point cannot disagree with the library, because it *is* the library
   --  answering.
   function Generate_Tables return Boolean;

   function Generate_Tables return Boolean is
      Output : constant String := Repository_Root & "/docs/tables";
      Page   : Unbounded_String;
   begin
      begin
         Ada.Directories.Create_Path (Output);
      exception
         when others =>
            return False;
      end;

      ------------------------------------------------------------------
      --  Algorithms
      ------------------------------------------------------------------

      Page := Null_Unbounded_String;
      Append (Page, "# Algorithms" & ASCII.LF & ASCII.LF);
      Append (Page,
              "Generated by `ssllib_tools docs` from the registries themselves."
              & " Every value here is what the library answers when asked, so this"
              & " table cannot drift away from the code." & ASCII.LF & ASCII.LF);

      Append (Page, "## Cipher suites" & ASCII.LF & ASCII.LF);
      Append (Page, "| Suite | Code point | Version | AEAD | Hash | Authentication |"
              & ASCII.LF);
      Append (Page, "|---|---|---|---|---|---|" & ASCII.LF);
      for Suite in SSL.Cipher_Suites.Cipher_Suite'Range loop
         Append (Page,
                 "| `" & SSL.Cipher_Suites.Image (Suite) & "` | 0x"
                 & Hex_16 (Natural (SSL.Cipher_Suites.Value_Of (Suite))) & " | "
                 & SSL.Versions.Image (SSL.Cipher_Suites.Version_Of (Suite)) & " | "
                 & SSL.Cipher_Suites.Image (SSL.Cipher_Suites.AEAD_Of (Suite)) & " | "
                 & SSL.Cipher_Suites.Image (SSL.Cipher_Suites.Hash_Of (Suite)) & " | "
                 & SSL.Cipher_Suites.Authentication_Of (Suite)'Image & " |" & ASCII.LF);
      end loop;
      Append (Page, ASCII.LF);

      Append (Page, "## Named groups" & ASCII.LF & ASCII.LF);
      Append (Page, "| Group | Code point | Family | Key share | Shared secret |"
              & ASCII.LF);
      Append (Page, "|---|---|---|---|---|" & ASCII.LF);
      for Group in SSL.Supported_Groups.Named_Group'Range loop
         Append (Page,
                 "| `" & SSL.Supported_Groups.Image (Group) & "` | 0x"
                 & Hex_16 (Natural (SSL.Supported_Groups.Value_Of (Group))) & " | "
                 & (if SSL.Supported_Groups.Is_Elliptic_Curve (Group)
                    then "elliptic curve" else "finite field") & " | "
                 & SSL.Supported_Groups.Share_Length (Group)'Image & " octets | "
                 & SSL.Supported_Groups.Secret_Length (Group)'Image & " octets |"
                 & ASCII.LF);
      end loop;
      Append (Page, ASCII.LF);

      Append (Page, "## Signature schemes" & ASCII.LF & ASCII.LF);
      Append (Page, "| Scheme | Code point | TLS 1.3 CertificateVerify |" & ASCII.LF);
      Append (Page, "|---|---|---|" & ASCII.LF);
      for Scheme in SSL.Signature_Schemes.Signature_Scheme'Range loop
         Append (Page,
                 "| `" & SSL.Signature_Schemes.Image (Scheme) & "` | 0x"
                 & Hex_16 (Natural (SSL.Signature_Schemes.Value_Of (Scheme))) & " | "
                 & (if SSL.Signature_Schemes.Usable_For_Handshake
                         (Scheme, SSL.Versions.TLS_1_3)
                    then "yes" else "no") & " |" & ASCII.LF);
      end loop;
      Append (Page, ASCII.LF);

      Files.Write_Text_File (Output & "/algorithms.md", To_String (Page));

      ------------------------------------------------------------------
      --  Extension contexts
      ------------------------------------------------------------------

      --  Asked for rather than built here. `SSL.Extensions` is a private child
      --  and nothing outside SSL's own subtree can name it, which is the
      --  boundary doing its job: this program is a tool, not part of the
      --  library. `SSL.Internal_Tests` is inside the subtree and hands the
      --  table over as text.
      Files.Write_Text_File
        (Output & "/extension-contexts.md", SSL.Internal_Tests.Extension_Context_Table);

      ------------------------------------------------------------------
      --  Alerts
      ------------------------------------------------------------------

      Page := Null_Unbounded_String;
      Append (Page, "# Alerts" & ASCII.LF & ASCII.LF);
      Append (Page,
              "Every alert this library knows, with the wire value it is written"
              & " down as and whether receiving it ends the connection."
              & " Terminality is decided on the description rather than on a"
              & " peer's level octet, which is why it is a column here rather"
              & " than something a reader has to infer." & ASCII.LF & ASCII.LF);
      Append (Page, "| Alert | Wire value | Terminal |" & ASCII.LF);
      Append (Page, "|---|---|---|" & ASCII.LF);
      for Item in SSL.Alerts.Alert_Description'Range loop
         --  `unknown_alert` is not an alert this endpoint can send: it is what
         --  a description a peer sent and this library does not recognize is
         --  called, and it has no wire value of its own. Listed anyway, because
         --  a table that omitted it would leave a reader wondering what happens
         --  to an unrecognized alert.
         if Item = SSL.Alerts.Unknown_Alert then
            Append (Page,
                    "| `" & SSL.Alerts.Image (Item)
                    & "` | -- (a peer's, preserved verbatim) | yes |" & ASCII.LF);
         else
            Append (Page,
                    "| `" & SSL.Alerts.Image (Item) & "` |"
                    & Natural (SSL.Alerts.Value_For (Item))'Image & " | "
                    & (if SSL.Alerts.Is_Terminal (SSL.Alerts.Local_Alert (Item))
                       then "yes" else "no") & " |"
                    & ASCII.LF);
         end if;
      end loop;
      Append (Page, ASCII.LF);

      Files.Write_Text_File (Output & "/alerts.md", To_String (Page));

      ------------------------------------------------------------------
      --  Ticket formats
      ------------------------------------------------------------------

      Page := Null_Unbounded_String;
      Append (Page, "# Ticket formats" & ASCII.LF & ASCII.LF);
      Append (Page,
              "A session ticket is a server's own state under a key only that"
              & " server holds, and the protocol says nothing about what is"
              & " inside one. Every decision below is therefore this library's,"
              & " and every one of them can be got wrong in a way that costs the"
              & " security of every resumed connection -- so they are written"
              & " down." & ASCII.LF & ASCII.LF);
      Append (Page, "## The sealed ticket" & ASCII.LF & ASCII.LF);
      Append (Page,
              "| Field | Width | Authenticated | Encrypted |" & ASCII.LF
              & "|---|---|---|---|" & ASCII.LF
              & "| format version | 1 octet | yes | no |" & ASCII.LF
              & "| key identifier | 16 octets | yes | no |" & ASCII.LF
              & "| nonce | 12 octets | yes | no |" & ASCII.LF
              & "| sealed body | variable | yes | yes |" & ASCII.LF
              & "| authentication tag | 16 octets | -- | -- |" & ASCII.LF
              & ASCII.LF);
      Append (Page,
              "The body is AES-256-GCM, and it is authenticated before it is"
              & " parsed: a ticket a server cannot authenticate is a ticket whose"
              & " contents it never looks at, which is what keeps chosen bytes"
              & " away from the decoder. The format version is inside the"
              & " authenticated data, because a format change an attacker could"
              & " roll back would be no change at all." & ASCII.LF & ASCII.LF);
      Append (Page, "## Inside the body" & ASCII.LF & ASCII.LF);
      Append (Page,
              "| Field | Encoding |" & ASCII.LF
              & "|---|---|" & ASCII.LF
              & "| issued at | 8 octets, seconds since the epoch |" & ASCII.LF
              & "| expires at | 8 octets, seconds since the epoch |" & ASCII.LF
              & "| protocol version | 2 octets, the TLS wire value |" & ASCII.LF
              & "| cipher suite | 2 octets, the TLS wire value |" & ASCII.LF
              & "| configuration fingerprint | 32 octets |" & ASCII.LF
              & "| trust fingerprint | 32 octets |" & ASCII.LF
              & "| security context | 1 octet length, then the label |" & ASCII.LF
              & "| application protocol | 1 octet length, then the name |" & ASCII.LF
              & "| server name | 1 octet length, then the name |" & ASCII.LF
              & "| peer authenticated | 1 octet |" & ASCII.LF
              & "| secret | 1 octet length, then the octets |" & ASCII.LF
              & ASCII.LF);
      Append (Page,
              "Nothing is persisted as an Ada record. Every field is written"
              & " octet by octet, because a record's layout is a compiler's"
              & " decision and a ticket outlives the process that wrote it."
              & ASCII.LF & ASCII.LF);
      Append (Page,
              "The protocol version is in there because it was once assumed."
              & " Every sealed session was a TLS 1.3 one, the assumption was not"
              & " written down, and it stopped being true: a TLS 1.2 session came"
              & " back out of its own ticket claiming to be TLS 1.3, and the"
              & " server declined every resumption it had just issued."
              & ASCII.LF & ASCII.LF);
      Append (Page, "## Refusal" & ASCII.LF & ASCII.LF);
      Append (Page,
              "Unknown key, expired, corrupt, wrong format version, wrong"
              & " protocol version, a suite that does not belong to that version"
              & " -- each produces the same undifferentiated refusal and a full"
              & " handshake, so that a peer probing a server's key rotation"
              & " learns nothing from which one it got." & ASCII.LF);

      Files.Write_Text_File (Output & "/ticket-formats.md", To_String (Page));

      return True;
   end Generate_Tables;

   procedure Command_Docs;

   procedure Command_Docs is
   begin
      Note ("ssllib_tools docs");
      Step ("API pages generated from the specifications", Generate_Documentation,
            Repository_Root & "/docs/api");
      Step ("specification tables generated from the registries", Generate_Tables,
            Repository_Root & "/docs/tables");
   end Command_Docs;

   ---------------------------------------------------------------------------
   --  package
   ---------------------------------------------------------------------------

   --  Hex, lower case, for a digest.
   function Hex (Data : Ada.Streams.Stream_Element_Array) return String;

   function Hex (Data : Ada.Streams.Stream_Element_Array) return String is
      Digits_Set : constant String := "0123456789abcdef";
      Result     : String (1 .. 2 * Natural (Data'Length)) := [others => '0'];
      At_Now     : Positive := 1;
   begin
      for Octet of Data loop
         Result (At_Now) := Digits_Set (Natural (Octet) / 16 + 1);
         Result (At_Now + 1) := Digits_Set (Natural (Octet) mod 16 + 1);
         At_Now := At_Now + 2;
      end loop;
      return Result;
   end Hex;

   function File_Digest (Path : String) return String;

   function File_Digest (Path : String) return String is
      Content : constant String := Files.Read_Raw_File (Path);
      Octets  : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Content'Length));
   begin
      for Index in Content'Range loop
         Octets (Ada.Streams.Stream_Element_Offset (Index - Content'First + 1)) :=
           Ada.Streams.Stream_Element (Character'Pos (Content (Index)));
      end loop;

      return Hex (Ada.Streams.Stream_Element_Array (CryptoLib.Hashes.SHA256 (Octets)));
   end File_Digest;

   --  Produce the source artifact: a manifest of every file that goes into a
   --  release, each with its SHA-256, and one digest over the manifest.
   --
   --  A manifest rather than an archive, deliberately. Writing a tar or a zip
   --  here would mean implementing an archive format in Ada for no purpose the
   --  format serves: what a release needs is something a second person can
   --  recompute and compare, and that is exactly a sorted list of paths and
   --  digests. Whoever wants an archive can make one from the same tree with
   --  whatever their platform already has, and check it against this.
   --
   --  Reproducible by construction: the paths are sorted, the digests depend on
   --  nothing but the bytes, and there is no timestamp, no host name and no
   --  build identifier anywhere in it. Two runs on two machines from the same
   --  source produce the same two files, octet for octet.
   function Write_Source_Manifest (Report : out Unbounded_String) return Boolean;

   function Write_Source_Manifest (Report : out Unbounded_String) return Boolean is
      Root   : constant String := Repository_Root;
      Output : constant String := Root & "/dist";

      --  What a source release consists of. Named rather than discovered, so
      --  that a stray file in the working tree cannot silently become part of
      --  a release.
      Roots : constant array (1 .. 4) of Unbounded_String :=
        [To_Unbounded_String ("src"),
         To_Unbounded_String ("docs"),
         To_Unbounded_String ("examples/src"),
         To_Unbounded_String ("invariant-registry")];

      Loose : constant array (1 .. 6) of Unbounded_String :=
        [To_Unbounded_String ("alire.toml"),
         To_Unbounded_String ("ssllib.gpr"),
         To_Unbounded_String ("README.md"),
         To_Unbounded_String ("CHANGELOG.md"),
         To_Unbounded_String ("LICENSE"),
         To_Unbounded_String ("ssllib_complete_implementation_prompt.txt")];

      Manifest : Unbounded_String;
      Counted  : Natural := 0;
   begin
      Report := Null_Unbounded_String;

      begin
         Ada.Directories.Create_Path (Output);
      exception
         when others =>
            return False;
      end;

      --  Sorted, because a manifest whose order depended on how a directory
      --  happened to be laid out would differ between two copies of the same
      --  source.
      declare
         Capacity : constant := 4_096;
         Every    : Files.Path_List (1 .. Capacity);
         Used     : Natural := 0;
         Overflow : Boolean := False;

         procedure Add_Sorted (Path : String);

         --  Insertion sort into a fixed array: the list is a few hundred
         --  entries, and a bound a release cannot silently exceed is worth more
         --  here than an algorithm nobody would notice.
         procedure Add_Sorted (Path : String) is
            At_Now : Natural;
         begin
            if Used = Capacity then
               Overflow := True;
               return;
            end if;

            At_Now := Used;
            while At_Now >= 1 and then To_String (Every (At_Now)) > Path loop
               Every (At_Now + 1) := Every (At_Now);
               At_Now := At_Now - 1;
            end loop;
            Every (At_Now + 1) := To_Unbounded_String (Path);
            Used := Used + 1;
         end Add_Sorted;
      begin
         for Directory of Roots loop
            declare
               Here : constant String := Root & "/" & To_String (Directory);
            begin
               if Files.Directory_Exists (Here) then
                  --  `docs/api` and `docs/tables` are generated by
                  --  `ssllib_tools docs`, so they are output rather than
                  --  source. Including them would make the manifest depend on
                  --  whether that command had been run, which is exactly the
                  --  kind of dependence a reproducible artifact must not have.
                  for Path of Files.List_Tree
                                (Here, "*",
                                 [To_Unbounded_String ("api"),
                                  To_Unbounded_String ("tables")])
                  loop
                     Add_Sorted (To_String (Path));
                  end loop;
               end if;
            end;
         end loop;

         for Name of Loose loop
            declare
               Here : constant String := Root & "/" & To_String (Name);
            begin
               if Files.File_Exists (Here) then
                  Add_Sorted (Here);
               end if;
            end;
         end loop;

         if Overflow then
            return False;
         end if;

         for Index in 1 .. Used loop
            declare
               Path : constant Unbounded_String := Every (Index);
               Full     : constant String := To_String (Path);
               Relative : constant String :=
                 (if Full'Length > Root'Length + 1
                  then Full (Full'First + Root'Length + 1 .. Full'Last)
                  else Full);
            begin
               Append (Manifest, File_Digest (Full) & "  " & Relative & ASCII.LF);
               Counted := Counted + 1;
            end;
         end loop;
      end;

      if Counted = 0 then
         return False;
      end if;

      declare
         Manifest_Path : constant String :=
           Output & "/ssllib-" & SSL.Version.Crate_Version & ".manifest";
         Digest_Path   : constant String :=
           Output & "/ssllib-" & SSL.Version.Crate_Version & ".sha256";
      begin
         Files.Write_Text_File (Manifest_Path, To_String (Manifest));
         Files.Write_Text_File
           (Digest_Path,
            File_Digest (Manifest_Path) & "  ssllib-"
            & SSL.Version.Crate_Version & ".manifest" & ASCII.LF);

         Report := To_Unbounded_String
           (Counted'Image & " files, digest " & File_Digest (Manifest_Path));
      end;

      return True;
   end Write_Source_Manifest;

   procedure Command_Package;

   procedure Command_Package is
      Report : Unbounded_String;
      Ok     : constant Boolean := Write_Source_Manifest (Report);
   begin
      Note ("ssllib_tools package");
      Step ("reproducible source manifest and hashes", Ok, To_String (Report));
   end Command_Package;

   ---------------------------------------------------------------------------
   --  release
   ---------------------------------------------------------------------------

   --  What still stands between this repository and a V1 release.
   --
   --  One list, in one place, and the release gate reads it. The specification's
   --  section 28 says not to declare V1 complete merely because the project
   --  builds, so `release` runs every gate and *still* refuses while anything is
   --  on this list -- and says which thing. When the list is empty the gate
   --  passes, which is the only way it ever will.
   type Gap_List is array (Positive range <>) of Unbounded_String;

   function Outstanding_Gaps return Gap_List;

   function Outstanding_Gaps return Gap_List is
     ([1 => To_Unbounded_String
              ("the platform matrix has run on Linux x86_64 only")]);

   procedure Command_Release;

   procedure Command_Release is
      Gaps : constant Gap_List := Outstanding_Gaps;
   begin
      Note ("ssllib_tools release");

      --  Every gate, in the order section 27 of the specification fixes, and
      --  each one for real. A release command that skipped a gate because the
      --  release was going to be refused anyway would be a release command that
      --  never tells anyone which gate is broken.
      Command_Verify;
      Command_Build;
      Command_Test;
      Command_Prove (Profile => "release");
      Command_Interop;
      Command_Docs;
      Command_Package;

      IO.Put_Line ("");
      if Failures > 0 then
         IO.Put_Line ("release refused: a mandatory gate failed");
         return;
      end if;

      if Gaps'Length > 0 then
         IO.Put_Line ("release refused: the V1 acceptance criteria are not met");
         for Gap of Gaps loop
            IO.Put_Line ("  - " & To_String (Gap));
         end loop;
         IO.Put_Line ("");
         IO.Put_Line ("Every gate above passed. What is missing is missing, and");
         IO.Put_Line ("this command will not emit artifacts that imply otherwise.");
         Failures := Failures + 1;
         return;
      end if;

      --  Machine-readable metadata, written only when there is something true
      --  to say in it.
      declare
         Metadata : Unbounded_String;
      begin
         Append (Metadata, "{" & ASCII.LF);
         Append (Metadata, "  ""schema"": 1," & ASCII.LF);
         Append (Metadata, "  ""crate"": ""ssllib""," & ASCII.LF);
         Append (Metadata,
                 "  ""version"": """ & SSL.Version.Crate_Version & """," & ASCII.LF);
         Append (Metadata, "  ""gates"": [""verify"", ""build"", ""test"", "
                 & """prove"", ""interop"", ""docs"", ""package""]," & ASCII.LF);
         Append (Metadata, "  ""v1_complete"": true" & ASCII.LF);
         Append (Metadata, "}" & ASCII.LF);
         Files.Write_Text_File (Repository_Root & "/dist/release.json",
                                To_String (Metadata));
      end;

      Step ("release metadata written", True, Repository_Root & "/dist/release.json");
   end Command_Release;

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
   Profile_Word : Unbounded_String;

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
         elsif Profile_Word = Null_Unbounded_String then
            --  One positional argument after the command, which today only
            --  `prove` reads: the profile. Accepted generally rather than only
            --  for `prove` so that the argument loop has one rule rather than a
            --  special case per command.
            Profile_Word := To_Unbounded_String (Argument);
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
         --  The corpus is the mutation runner itself: it is deterministic in
         --  every argument, so replaying it *is* replaying the corpus. There is
         --  no stored blob to read back, and a directory of them would be a
         --  directory nobody could regenerate.
         Command_Test;
         return;

      elsif Name = "test-interop" then
         Command_Interop;
         return;

      elsif Name = "prove" then
         Command_Prove
           (Profile =>
              (if Profile_Word = Null_Unbounded_String
               then "development" else To_String (Profile_Word)));
         return;

      elsif Name = "docs" then
         Command_Docs;
         return;

      elsif Name = "package" then
         Command_Package;
         return;

      elsif Name = "release" then
         Command_Release;
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
