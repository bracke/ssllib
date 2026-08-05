with SSL;
with SSL.ALPN;
with SSL.Authentication;
with SSL.Cancellation;
with SSL.Cipher_Suites;
with SSL.Clocks;
with SSL.Configurations;
with SSL.Credentials;
with SSL.Credentials.Signers;
with SSL.Trust;
with SSL.Trust.Pinning;
with SSL.Trust.Revocation;
with SSL.Errors;
with SSL.Limits;
with SSL.Server_Names;
with SSL.Signature_Schemes;
with SSL.Supported_Groups;
with SSL.Versions;

with Tests_Fixtures;
with Tests_Support;

package body Tests_Policy is

   use Tests_Support;

   use type SSL.Byte_Index;
   use type SSL.Configuration_Fingerprint;
   use type SSL.Authentication.Authentication_Basis;
   use type SSL.Cipher_Suites.Cipher_Suite;
   use type SSL.Configurations.Revocation_Policy;
   use type SSL.Configurations.Trust_Source;
   use type SSL.Errors.Error_Code;
   use type SSL.Errors.Error_Origin;
   use type SSL.Byte;
   use type SSL.Server_Names.Name_Status;
   use type SSL.Supported_Groups.Named_Group;
   use type SSL.Versions.Protocol_Version;
   use type SSL.Certificate_Fingerprint;
   use type SSL.Signature_Schemes.Signature_Scheme;
   use type SSL.Authentication.Client_Authentication_Policy;
   use type SSL.Configurations.Negotiation_Preference;
   use type SSL.Configurations.Unrecognized_Name_Policy;
   use type SSL.Trust.Revocation.Status_Answer;

   --  The negative checks below call a query for its answer and discard the
   --  out parameter, which is the whole subject of a negative check.
   pragma Warnings (Off, "*useless assignment*");

   package Config renames SSL.Configurations;

   Bounds : constant SSL.Limits.Resource_Limits := SSL.Limits.Default_Limits;

   --  The fixture, loaded once. Both are aliased because a configuration holds
   --  a reference rather than a copy, and both outlive every configuration
   --  built in this file.
   Fixture_Anchors    : aliased SSL.Trust.Snapshot;
   Fixture_Credential : aliased SSL.Credentials.Credential;
   Fixture_Ready      : Boolean := False;

   --  Load the fixture on first use. Not an elaboration-time action: a failure
   --  here should be a test failure with a message, not an exception during
   --  package elaboration that says nothing about which test needed it.
   procedure Ensure_Fixture;

   procedure Ensure_Fixture is
      Error : SSL.Errors.Error_Information;
   begin
      if Fixture_Ready then
         return;
      end if;

      SSL.Trust.Load_Explicit_Anchors
        (Fixture_Anchors, Tests_Fixtures.Anchor_PEM,
         SSL.Clocks.UTC (2026, 7, 30), Bounds, Error);
      Expect (not SSL.Errors.Is_Error (Error),
              "the fixture anchor loads: " & SSL.Errors.Image (Error));

      SSL.Credentials.Load_PEM
        (Fixture_Credential, Tests_Fixtures.Leaf_Certificate_PEM,
         Tests_Fixtures.Leaf_Key_PEM, Bounds, Error);
      Expect (not SSL.Errors.Is_Error (Error),
              "the fixture credential loads: " & SSL.Errors.Image (Error));

      Fixture_Ready := True;
   end Ensure_Fixture;

   --  Secure client defaults with the fixture attached, which is the least a
   --  buildable client configuration now needs.
   procedure Provisioned_Client (Item : out Config.Client_Builder);

   procedure Provisioned_Client (Item : out Config.Client_Builder) is
      Ok : Boolean;
   begin
      Ensure_Fixture;
      Config.Secure_Client_Defaults (Item);
      Config.Set_Expected_Name (Item, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
      Config.Set_Anchors (Item, Fixture_Anchors'Access, Ok);
      Expect (Ok, "the fixture anchors attach");
   end Provisioned_Client;

   procedure Provisioned_Server (Item : out Config.Server_Builder);

   procedure Provisioned_Server (Item : out Config.Server_Builder) is
      Ok : Boolean;
   begin
      Ensure_Fixture;
      Config.Secure_Server_Defaults (Item);
      Config.Add_Credential (Item, Fixture_Credential'Access, Ok);
      Expect (Ok, "the fixture credential attaches");
   end Provisioned_Server;
   package Groups renames SSL.Supported_Groups;
   package Suites renames SSL.Cipher_Suites;

   ----------
   -- Name --
   ----------

   overriding function Name (T : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (T);
   begin
      return Tests_Support.Message ("ssllib policy: clocks, cancellation, configurations");
   end Name;

   ---------------------------------------------------------------------------
   --  Clocks
   ---------------------------------------------------------------------------

   procedure Run_Clocks (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Clocks (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      use SSL.Clocks;
      Early : constant Wall_Time := UTC (2026, 1, 1);
      Late  : constant Wall_Time := UTC (2026, 7, 30, 13, 1, 0);
   begin
      Expect (not Is_Present (No_Wall_Time), "an unset wall time is absent");
      Expect (Is_Present (Early), "a constructed wall time is present");
      Expect_Equal (Image (Late), "2026-07-30T13:01:00Z", "ISO 8601 rendering");
      Expect_Equal (Image (No_Wall_Time), "none", "an absent time renders as none");

      Expect (Early < Late, "January precedes July");
      Expect (not (Late < Early), "July does not precede January");
      Expect (Early <= Early, "a time is not after itself");

      --  Ordering runs through every field, not just the year.
      Expect (UTC (2026, 7, 30, 13, 0, 59) < UTC (2026, 7, 30, 13, 1, 0),
              "seconds order correctly");
      Expect (UTC (2026, 7, 30, 12, 59, 59) < UTC (2026, 7, 30, 13, 0, 0),
              "hours order correctly");

      --  An absent time sorts before every present one, so that a "not yet
      --  valid" check against an unset clock refuses rather than passes.
      Expect (No_Wall_Time < Early, "an absent time precedes every present one");
      Expect (not (Early < No_Wall_Time), "no present time precedes an absent one");

      Expect (Year_Of (Late) = 2026 and then Month_Of (Late) = 7 and then Day_Of (Late) = 30,
              "date fields read back");
      Expect (Hour_Of (Late) = 13 and then Minute_Of (Late) = 1 and then Second_Of (Late) = 0,
              "time fields read back");

      --  Deadlines are computed from a supplied instant, so a test needs no
      --  real elapsed time.
      declare
         Base  : constant Monotonic_Time := Current_Monotonic;
         Later : constant Deadline := At_Offset (Base, 1000);
      begin
         Expect (not Is_Set (No_Deadline), "no deadline is unset");
         Expect (Is_Set (Later), "a computed deadline is set");
         Expect (not Has_Expired (No_Deadline, Base), "an unset deadline never expires");
         Expect (Remaining_Milliseconds (No_Deadline, Base) = Natural'Last,
                 "an unset deadline reports an unbounded wait");
         Expect (not Has_Expired (Later, Base), "a future deadline has not expired");
         Expect (Has_Expired (At_Offset (Base, 0), Base),
                 "a zero-offset deadline has expired at its instant");

         --  Elapsed time never goes backwards, whichever way the caller passed
         --  the arguments. Two readings of the real clock give a genuinely
         --  ordered pair without the test having to wait.
         Expect (Elapsed_Milliseconds (Base, Base) = 0,
                 "no time elapses between an instant and itself");

         declare
            Second_Reading : constant Monotonic_Time := Current_Monotonic;
         begin
            Expect (Elapsed_Milliseconds (Second_Reading, Base) = 0,
                    "a reversed interval reports zero rather than a huge number");
            Expect (Elapsed_Milliseconds (Base, Second_Reading) < 60_000,
                    "a forward interval between two immediate readings is small");
         end;
      end;
   end Run_Clocks;

   ---------------------------------------------------------------------------
   --  Cancellation
   ---------------------------------------------------------------------------

   procedure Run_Cancellation (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Cancellation (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Token : SSL.Cancellation.Token;
   begin
      SSL.Cancellation.Initialize (Token);
      Expect (not SSL.Cancellation.Is_Cancelled (Token), "a fresh token is not cancelled");

      SSL.Cancellation.Cancel (Token);
      Expect (SSL.Cancellation.Is_Cancelled (Token), "cancelling sets the token");

      --  A one-way latch: cancelling twice is not an error and does not undo.
      SSL.Cancellation.Cancel (Token);
      Expect (SSL.Cancellation.Is_Cancelled (Token), "cancelling twice keeps it cancelled");
   end Run_Cancellation;

   ---------------------------------------------------------------------------
   --  Authentication outcomes
   ---------------------------------------------------------------------------

   procedure Run_Authentication (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Authentication (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      use SSL.Authentication;

      Leaf, Key : SSL.Certificate_Fingerprint;
      Hex       : constant String (1 .. 64) := [others => 'a'];
      When_Made : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 7, 30, 9, 0, 0);
      Scheme    : SSL.Signature_Schemes.Signature_Scheme;
   begin
      Expect (SSL.Parse_Fingerprint (Hex, SSL.Whole_Certificate, Leaf), "leaf fingerprint");
      Expect (SSL.Parse_Fingerprint (Hex, SSL.Public_Key_Info, Key), "spki fingerprint");

      Expect (not Is_Authenticated (Unauthenticated_Peer), "an unauthenticated peer is not");

      declare
         Now : constant Peer_Authentication :=
           Fresh (At_Time     => When_Made,
                  Name        => SSL.Server_Names.Name ("www.example.com"),
                  Address     => SSL.Server_Names.No_Address,
                  Scheme      => SSL.Signature_Schemes.Ed25519,
                  Path_Length => 3,
                  Leaf        => Leaf,
                  Public_Key  => Key);
         Old : constant Peer_Authentication := Resumed (Now);
         Got : SSL.Certificate_Fingerprint;
      begin
         Expect (Is_Authenticated (Now), "a fresh outcome is authenticated");
         Expect (Is_Freshly_Authenticated (Now), "a fresh outcome is fresh");
         Expect (Path_Length (Now) = 3, "the path length is recorded");
         Expect (Signature_Used (Now, Scheme) and then Scheme = SSL.Signature_Schemes.Ed25519,
                 "the signature scheme is recorded");

         --  The distinction this type exists for: a resumption is authenticated
         --  but not freshly, and it must not claim a signature it never saw.
         Expect (Is_Authenticated (Old), "a resumption is authenticated");
         Expect (not Is_Freshly_Authenticated (Old), "a resumption is not fresh");
         Expect (not Signature_Used (Old, Scheme),
                 "a resumption reports no CertificateVerify, because there was none");
         Expect (Path_Length (Old) = 0, "a resumption reports no path, because none was built");

         --  The age of the evidence survives, which is the whole point.
         Expect (SSL.Clocks.Image (Authenticated_At (Old))
                 = SSL.Clocks.Image (When_Made),
                 "a resumption keeps the original authentication time");

         --  Fingerprints travel, so an application pinning on one can check a
         --  resumed connection that has no certificate present.
         Expect (Leaf_Fingerprint (Old, Got) and then Got = Leaf,
                 "the leaf fingerprint survives resumption");
         Expect (Public_Key_Fingerprint (Old, Got) and then Got = Key,
                 "the SPKI fingerprint survives resumption");

         Expect (Basis_Of (Old) = Resumed_Session, "the basis says resumed");
      end;
   end Run_Authentication;

   ---------------------------------------------------------------------------
   --  Secure defaults
   ---------------------------------------------------------------------------

   procedure Run_Secure_Defaults (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Secure_Defaults (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Builder : Config.Client_Builder;
      Result  : Config.Client_Configuration;
      Error   : SSL.Errors.Error_Information;
      Ok      : Boolean;
   begin
      Ensure_Fixture;
      Config.Secure_Client_Defaults (Builder);

      --  A client with no expected identity cannot be built, because there is
      --  no mode in which it does not verify one.
      Config.Build (Builder, Result, Error);
      Expect (SSL.Errors.Is_Error (Error), "a client with no expected identity is refused");
      Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Identity_Not_Specified,
              "and the reason names the missing identity");
      Expect (not Config.Is_Valid (Result), "the configuration is left invalid");

      Config.Set_Expected_Name (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
      Expect (Ok, "an expected name is accepted");

      --  And a client with an identity but no anchors still cannot be built: it
      --  always verifies, so it always needs something to verify against.
      Config.Build (Builder, Result, Error);
      Expect (SSL.Errors.Is_Error (Error), "a client with no trust anchors is refused");
      Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Trust_Required_But_Absent,
              "and the reason names the missing trust");

      Config.Set_Anchors (Builder, Fixture_Anchors'Access, Ok);
      Expect (Ok, "the anchors attach");
      Config.Build (Builder, Result, Error);
      Expect (not SSL.Errors.Is_Error (Error),
              "the secure defaults build: " & SSL.Errors.Image (Error));
      Expect (Config.Is_Valid (Result), "the configuration is valid");

      --  Specification section 9, item by item.
      Expect (SSL.Versions.Count (Config.Versions (Result)) = 1
              and then SSL.Versions.Contains (Config.Versions (Result), SSL.Versions.TLS_1_3),
              "TLS 1.3 only");
      Expect (Suites.Length (Config.Cipher_Suites (Result)) = 3, "all three TLS 1.3 suites");
      Expect (Suites.Element (Config.Cipher_Suites (Result), 1)
              = Suites.TLS_AES_128_GCM_SHA256, "AES-128-GCM preferred first");
      Expect (Groups.Length (Config.Groups (Result)) = 3, "three groups");
      Expect (Groups.Contains (Config.Groups (Result), Groups.X25519), "X25519 offered");
      Expect (Groups.Contains (Config.Groups (Result), Groups.Secp256r1), "P-256 offered");
      Expect (Groups.Contains (Config.Groups (Result), Groups.Secp384r1), "P-384 offered");
      Expect (Config.Trust_Source_Of (Result) = Config.Native_System,
              "native system trust is the default");
      Expect (not Config.Uses_NSS_Trust (Result), "NSS is not merged in silently");
      Expect (not Config.Uses_Java_Trust (Result), "Java is not merged in silently");
      Expect (Config.Resumption_Enabled (Result), "resumption is enabled");
      Expect (Config.Sends_Close_Notify (Result), "close_notify is attempted");
      Expect (Config.Detects_Truncation (Result), "truncation is detected");
      Expect (Config.Record_Padding (Result) = 0, "no padding by default");

      --  SNI follows the authenticated name unless deliberately separated.
      Expect (Config.Sends_Server_Name (Result), "SNI is sent for a DNS name");
      Expect (SSL.Server_Names.Image (Config.Server_Name_Indication (Result))
              = "www.example.com", "SNI carries the expected name");

      --  No finite-field group is in the default set.
      Expect (not Groups.Contains (Config.Groups (Result), Groups.FFDHE2048),
              "no finite-field group is default");
   end Run_Secure_Defaults;

   procedure Run_Server_Defaults (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Server_Defaults (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Builder : Config.Server_Builder;
      Result  : Config.Server_Configuration;
      Error   : SSL.Errors.Error_Information;
      Ok      : Boolean;
   begin
      Ensure_Fixture;
      Config.Secure_Server_Defaults (Builder);

      --  A server with nothing to present cannot complete a handshake, so it
      --  cannot be built either.
      Config.Build (Builder, Result, Error);
      Expect (SSL.Errors.Is_Error (Error), "a server with no credential is refused");
      Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_No_Credential_Configured,
              "and the reason names the missing credential");

      Config.Add_Credential (Builder, Fixture_Credential'Access, Ok);
      Expect (Ok, "the credential attaches");
      Config.Build (Builder, Result, Error);
      Expect (not SSL.Errors.Is_Error (Error),
              "the secure server defaults build: " & SSL.Errors.Image (Error));

      Expect (SSL.Versions.Count (Config.Versions (Result)) = 1, "TLS 1.3 only");
      Expect (Config.Preference (Result) = Config.Server_Preference,
              "server-preference negotiation");
      Expect (Config.Client_Authentication (Result) = SSL.Authentication.Not_Requested,
              "client certificates are not requested");
      Expect (not Config.Issues_Tickets (Result), "tickets are off by default");
      Expect (Config.Name_Policy (Result) = Config.Reject_Unrecognized,
              "an unrecognized SNI name is rejected by default");

      --  "Tickets disabled until valid ticket keys are configured", enforced
      --  rather than documented. No ticket-key API exists yet, so enabling
      --  issuance must fail -- and it must fail with the code that says why.
      Config.Set_Ticket_Issuance (Builder, True);
      Config.Build (Builder, Result, Error);
      Expect (SSL.Errors.Is_Error (Error), "ticket issuance without keys is refused");
      Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Ticket_Issuance_Without_Key,
              "and the reason names the missing key");
      Expect (not Config.Is_Valid (Result), "the configuration is left invalid");
   end Run_Server_Defaults;

   ---------------------------------------------------------------------------
   --  Modern compatibility must not weaken TLS 1.3
   ---------------------------------------------------------------------------

   procedure Run_Modern_Compatibility (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Modern_Compatibility (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Secure_Builder, Compat_Builder : Config.Client_Builder;
      Secure_Config, Compat_Config   : Config.Client_Configuration;
      Error : SSL.Errors.Error_Information;
      Ok    : Boolean;
      Name  : constant SSL.Server_Names.DNS_Name :=
        SSL.Server_Names.Name ("www.example.com");
   begin
      Provisioned_Client (Secure_Builder);
      Config.Build (Secure_Builder, Secure_Config, Error);
      Expect (not SSL.Errors.Is_Error (Error), "secure defaults build");

      Config.Modern_Compatibility_Client (Compat_Builder);
      Config.Set_Expected_Name (Compat_Builder, Name, Ok => Ok);
      Config.Set_Anchors (Compat_Builder, Fixture_Anchors'Access, Ok);
      Config.Build (Compat_Builder, Compat_Config, Error);
      Expect (not SSL.Errors.Is_Error (Error),
              "modern compatibility builds: " & SSL.Errors.Image (Error));

      --  It adds TLS 1.2 and nothing else.
      Expect (SSL.Versions.Contains (Config.Versions (Compat_Config), SSL.Versions.TLS_1_2),
              "TLS 1.2 is added");
      Expect (SSL.Versions.Contains (Config.Versions (Compat_Config), SSL.Versions.TLS_1_3),
              "TLS 1.3 is still enabled");

      --  The TLS 1.3 policy is untouched: same groups, and the same TLS 1.3
      --  suites in the same order at the front of the list.
      Expect (Groups.Image (Config.Groups (Compat_Config))
              = Groups.Image (Config.Groups (Secure_Config)),
              "the group policy is unchanged");

      declare
         Secure_Suites : constant Suites.Suite_List := Config.Cipher_Suites (Secure_Config);
         Compat_Suites : constant Suites.Suite_List := Config.Cipher_Suites (Compat_Config);
      begin
         Expect (Suites.Length (Compat_Suites) = Suites.Length (Secure_Suites) + 6,
                 "six TLS 1.2 suites are added");
         for Index in 1 .. Suites.Length (Secure_Suites) loop
            Expect (Suites.Element (Compat_Suites, Index) = Suites.Element (Secure_Suites, Index),
                    "the TLS 1.3 suites keep their order and position");
         end loop;
      end;

      --  And the two are different configurations, so a session established
      --  under one does not resume under the other.
      Expect (Config.Fingerprint (Secure_Config) /= Config.Fingerprint (Compat_Config),
              "adding TLS 1.2 changes the configuration fingerprint");
   end Run_Modern_Compatibility;

   --  A TLS 1.2 suite ahead of a TLS 1.3 one is a weakening by ordering, and is
   --  refused.
   procedure Run_Ordering_Refusal (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Ordering_Refusal (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Builder : Config.Client_Builder;
      Result  : Config.Client_Configuration;
      Error   : SSL.Errors.Error_Information;
      Ok      : Boolean;
      Bad     : Suites.Suite_List := Suites.No_Suites;
   begin
      Ensure_Fixture;
      Config.Modern_Compatibility_Client (Builder);
      Config.Set_Expected_Name (Builder, SSL.Server_Names.Name ("a.example.com"), Ok => Ok);
      Config.Set_Anchors (Builder, Fixture_Anchors'Access, Ok);

      --  A TLS 1.2 suite first, then a TLS 1.3 one. Both versions are enabled,
      --  so a peer speaking both could be steered onto the older protocol.
      Suites.Append (Bad, Suites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, Ok);
      Suites.Append (Bad, Suites.TLS_AES_128_GCM_SHA256, Ok);
      Config.Set_Cipher_Suites (Builder, Bad, Ok);
      Expect (Ok, "the list itself is accepted by the setter");

      Config.Build (Builder, Result, Error);
      Expect (SSL.Errors.Is_Error (Error), "a TLS 1.2 suite ahead of a TLS 1.3 one is refused");
      Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Compatibility_Weakens_TLS13,
              "and the reason names the weakening");

      --  The same two suites the other way round are fine.
      declare
         Good : Suites.Suite_List := Suites.No_Suites;
      begin
         Suites.Append (Good, Suites.TLS_AES_128_GCM_SHA256, Ok);
         Suites.Append (Good, Suites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, Ok);
         Config.Set_Cipher_Suites (Builder, Good, Ok);
         Config.Build (Builder, Result, Error);
         Expect (not SSL.Errors.Is_Error (Error),
                 "TLS 1.3 first is accepted: " & SSL.Errors.Image (Error));
      end;
   end Run_Ordering_Refusal;

   ---------------------------------------------------------------------------
   --  Invariant CERT-8: a server cannot pick up finite-field groups by accident
   ---------------------------------------------------------------------------

   procedure Run_Finite_Field_Opt_In (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Finite_Field_Opt_In (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Client  : Config.Client_Builder;
      Server  : Config.Server_Builder;
      Result  : Config.Server_Configuration;
      Error   : SSL.Errors.Error_Information;
      Ok      : Boolean;
      Mixed   : Groups.Group_List := Groups.Default_Groups;
   begin
      Groups.Append (Mixed, Groups.FFDHE2048, Ok);
      Expect (Ok, "the group list itself can hold a finite-field group");

      --  Neither role accepts one through Set_Groups, however the list was
      --  assembled -- including a list copied from somewhere else, which is the
      --  realistic way it would happen.
      Provisioned_Server (Server);
      Config.Set_Groups (Server, Mixed, Ok);
      Expect (not Ok, "a server refuses finite-field groups through Set_Groups");

      Config.Secure_Client_Defaults (Client);
      Config.Set_Groups (Client, Mixed, Ok);
      Expect (not Ok, "a client refuses finite-field groups through Set_Groups");

      --  A curve-only list is accepted by both.
      Config.Set_Groups (Server, Groups.Default_Groups, Ok);
      Expect (Ok, "a curve-only list is accepted");

      --  The server's opt-in is a differently named operation, and it works.
      Config.Build (Server, Result, Error);
      Expect (not SSL.Errors.Is_Error (Error), "the server builds before the opt-in");
      Expect (not Groups.Contains (Config.Groups (Result), Groups.FFDHE4096),
              "and holds no finite-field group");

      Config.Accept_Finite_Field_Groups_With_Amplification_Risk (Server, Ok);
      Expect (Ok, "the explicit server opt-in adds them");
      Config.Build (Server, Result, Error);
      Expect (not SSL.Errors.Is_Error (Error), "the server builds after the opt-in");
      Expect (Groups.Contains (Config.Groups (Result), Groups.FFDHE2048), "ffdhe2048 is offered");
      Expect (Groups.Contains (Config.Groups (Result), Groups.FFDHE4096), "ffdhe4096 is offered");

      --  They go after the curves, so a peer offering both gets a curve.
      Expect (Groups.Position (Config.Groups (Result), Groups.X25519)
              < Groups.Position (Config.Groups (Result), Groups.FFDHE2048),
              "the curves are still preferred");

      --  ffdhe6144 and ffdhe8192 are not reachable at all: they are not values
      --  of the type.
      Expect (Groups.Length (Config.Groups (Result)) = 6,
              "exactly three curves and three finite-field groups");
   end Run_Finite_Field_Opt_In;

   ---------------------------------------------------------------------------
   --  Validation refusals
   ---------------------------------------------------------------------------

   procedure Run_Validation (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Validation (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Builder : Config.Client_Builder;
      Result  : Config.Client_Configuration;
      Error   : SSL.Errors.Error_Information;
      Ok      : Boolean;

      procedure Reset;

      procedure Reset is
      begin
         Provisioned_Client (Builder);
      end Reset;

   begin
      --  Empty policy lists are refused by the setters, so an empty
      --  configuration is unreachable.
      Reset;
      Config.Set_Versions (Builder, SSL.Versions.No_Versions, Ok);
      Expect (not Ok, "an empty version set is refused");
      Config.Set_Cipher_Suites (Builder, Suites.No_Suites, Ok);
      Expect (not Ok, "an empty suite list is refused");
      Config.Set_Groups (Builder, Groups.No_Groups, Ok);
      Expect (not Ok, "an empty group list is refused");

      --  A version with no suite for it: TLS 1.2 enabled, only TLS 1.3 suites.
      Reset;
      Config.Set_Versions (Builder, SSL.Versions.Only (SSL.Versions.TLS_1_2), Ok);
      Expect (Ok, "TLS 1.2 only is a legal version set");
      Config.Build (Builder, Result, Error);
      Expect (SSL.Errors.Is_Error (Error), "TLS 1.2 with only TLS 1.3 suites is refused");
      Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Suite_Version_Mismatch,
              "and the reason names the mismatch");

      --  A key share for a group that is not offered.
      Reset;
      declare
         Shares : Groups.Group_List := Groups.No_Groups;
      begin
         Groups.Append (Shares, Groups.Secp521r1, Ok);
         Config.Set_Key_Share_Groups (Builder, Shares, Ok);
         Expect (Ok, "the setter accepts the list");
         Config.Build (Builder, Result, Error);
         Expect (SSL.Errors.Is_Error (Error),
                 "a key share for an unoffered group is refused");
         Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Key_Share_Not_Offered,
                 "and the reason names it, as RFC 8446 4.2.8 requires");
      end;

      --  ALPN required with no protocols.
      Reset;
      Config.Set_Application_Protocols
        (Builder, SSL.ALPN.No_Protocols, SSL.ALPN.Required, Ok);
      Expect (not Ok, "required ALPN with no protocols is refused by the setter");

      --  Inconsistent limits.
      Reset;
      declare
         Bad : SSL.Limits.Resource_Limits := SSL.Limits.Default_Limits;
      begin
         Bad.Maximum_Ciphertext_Queue := 100;
         Config.Set_Limits (Builder, Bad, Ok);
         Expect (not Ok, "limits that cannot hold one record are refused by the setter");
      end;

      --  A wildcard is never a name a client is trying to reach.
      Reset;
      declare
         Pattern : SSL.Server_Names.DNS_Name;
         Status  : SSL.Server_Names.Name_Status;
      begin
         SSL.Server_Names.Parse_Pattern ("*.example.com", Pattern, Status);
         Expect (Status = SSL.Server_Names.Ok, "the pattern itself parses");
         Config.Set_Expected_Name (Builder, Pattern, Ok => Ok);
         Expect (not Ok, "a wildcard is refused as an expected identity");
      end;

      --  Requiring a stapled response while not asking for one cannot succeed;
      --  asking for it turns the request on rather than failing later.
      Reset;
      Config.Set_Revocation_Policy (Builder, Config.Require_Stapled_OCSP, Ok);
      Expect (Ok, "the revocation policy is accepted");
      Config.Build (Builder, Result, Error);
      Expect (not SSL.Errors.Is_Error (Error),
              "requiring stapling turns the request on: " & SSL.Errors.Image (Error));
      Expect (Config.Requests_Stapled_Status (Result), "and the request is on");
      Expect (Config.Revocation (Result) = Config.Require_Stapled_OCSP,
              "and the policy is recorded");
   end Run_Validation;

   ---------------------------------------------------------------------------
   --  Fingerprints
   ---------------------------------------------------------------------------

   procedure Run_Fingerprints (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Fingerprints (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      First, Second : Config.Client_Builder;
      Left, Right   : Config.Client_Configuration;
      Error         : SSL.Errors.Error_Information;
      Ok            : Boolean;
   begin
      Provisioned_Client (First);
      Config.Build (First, Left, Error);

      Provisioned_Client (Second);
      Config.Build (Second, Right, Error);

      --  Two configurations that negotiate identically fingerprint identically.
      Expect (Config.Fingerprint (Left) = Config.Fingerprint (Right),
              "identical policy gives an identical fingerprint");
      Expect (SSL.Image (Config.Fingerprint (Left))'Length = 64,
              "a fingerprint renders as 64 hexadecimal characters");

      --  Anything a peer could observe changes it.
      Config.Set_Resumption (Second, False);
      Config.Build (Second, Right, Error);
      Expect (Config.Fingerprint (Left) /= Config.Fingerprint (Right),
              "turning resumption off changes the fingerprint");

      Provisioned_Client (Second);
      Config.Set_Expected_Name (Second, SSL.Server_Names.Name ("other.example.com"), Ok => Ok);
      Config.Build (Second, Right, Error);
      Expect (Config.Fingerprint (Left) /= Config.Fingerprint (Right),
              "a different expected identity changes the fingerprint, so a session "
              & "cannot be resumed against another name");

      --  The security context separates tenants that are otherwise identical.
      Provisioned_Client (Second);
      Config.Set_Security_Context (Second, SSL.Security_Context ("tenant-a"));
      Config.Build (Second, Right, Error);
      Expect (Config.Fingerprint (Left) /= Config.Fingerprint (Right),
              "a different security context changes the fingerprint");
   end Run_Fingerprints;

   ---------------------------------------------------------------------------
   --  Pinning
   ---------------------------------------------------------------------------

   procedure Run_Pinning (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Pinning (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      use SSL.Trust.Pinning;

      Leaf, Key, Other : SSL.Certificate_Fingerprint;
      Hex_A : constant String (1 .. 64) := [others => 'a'];
      Hex_B : constant String (1 .. 64) := [others => 'b'];

      Early : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 1, 1);
      Now   : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 7, 30);
      Late  : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2027, 1, 1);

      Name  : constant SSL.Server_Names.DNS_Name :=
        SSL.Server_Names.Name ("www.example.com");
      Other_Name : constant SSL.Server_Names.DNS_Name :=
        SSL.Server_Names.Name ("other.example.com");

      Item  : Pin;
      Pins  : Pin_Set := No_Pins;
      Error : SSL.Errors.Error_Information;
      Ok    : Boolean;
   begin
      Expect (SSL.Parse_Fingerprint (Hex_A, SSL.Whole_Certificate, Leaf), "leaf digest");
      Expect (SSL.Parse_Fingerprint (Hex_A, SSL.Public_Key_Info, Key), "spki digest");
      Expect (SSL.Parse_Fingerprint (Hex_B, SSL.Public_Key_Info, Other), "other digest");

      --  A pin needs both ends of its period. One with no end date outlives the
      --  key it names and eventually locks the application out of its own
      --  service, with no date anywhere for anyone to have noticed.
      Expect (not Make (Key, Name, SSL.ALPN.No_Protocol, Early, SSL.Clocks.No_Wall_Time, Item),
              "a pin with no expiry is refused");
      Expect (not Make (Key, Name, SSL.ALPN.No_Protocol, Late, Early, Item),
              "a pin whose period runs backwards is refused");
      Expect (Make (Key, Name, SSL.ALPN.No_Protocol, Early, Late, Item),
              "a pin with a sane period is accepted");

      Expect (Is_Active (Item, Now), "the pin is active inside its period");
      Expect (not Is_Active (Item, SSL.Clocks.UTC (2025, 1, 1)),
              "the pin is not active before it starts");
      Expect (not Is_Active (Item, SSL.Clocks.UTC (2028, 1, 1)),
              "the pin is not active after it ends");
      Expect (not Is_Active (Item, SSL.Clocks.No_Wall_Time),
              "a pin cannot be active when the time is unknown");

      Expect (Applies (Item, Name, SSL.ALPN.No_Protocol), "the pin applies to its own name");
      Expect (not Applies (Item, Other_Name, SSL.ALPN.No_Protocol),
              "the pin does not apply to a different name");

      Append (Pins, Item, Ok);
      Expect (Ok, "the pin was added");

      --  No pinning: nothing is consulted.
      Evaluate (No_Pinning, No_Pins, Leaf, Key, Name, SSL.ALPN.No_Protocol, Now, Error);
      Expect (not SSL.Errors.Is_Error (Error), "no pinning consults nothing");

      --  The SPKI pin matches the SPKI fingerprint.
      Evaluate (Require_Valid_Path_And_Pin, Pins, Leaf, Key, Name,
                SSL.ALPN.No_Protocol, Now, Error);
      Expect (not SSL.Errors.Is_Error (Error),
              "a matching pin satisfies the policy: " & SSL.Errors.Image (Error));

      --  A pin over a different key does not.
      declare
         Wrong : Pin_Set := No_Pins;
         Entry_Item : Pin;
      begin
         Expect (Make (Other, Name, SSL.ALPN.No_Protocol, Early, Late, Entry_Item), "other pin");
         Append (Wrong, Entry_Item, Ok);
         Evaluate (Require_Valid_Path_And_Pin, Wrong, Leaf, Key, Name,
                   SSL.ALPN.No_Protocol, Now, Error);
         Expect (SSL.Errors.Is_Error (Error), "a non-matching pin fails");
         Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Pin_Not_Met,
                 "and the reason says the pin was not met");
      end;

      --  A set whose pins do not cover this connection is a scope mismatch, not
      --  a pass. This is the case a naive implementation reads as "no pin
      --  applied, therefore satisfied".
      Evaluate (Require_Valid_Path_And_Pin, Pins, Leaf, Key, Other_Name,
                SSL.ALPN.No_Protocol, Now, Error);
      Expect (SSL.Errors.Is_Error (Error), "pins that do not cover the connection do not pass");
      Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Pin_Scope_Mismatch,
              "and the reason says the scope did not match");

      --  An expired pin is reported as expired rather than as a mismatch, so an
      --  operator is told to renew rather than to hunt for the wrong key.
      Evaluate (Require_Valid_Path_And_Pin, Pins, Leaf, Key, Name,
                SSL.ALPN.No_Protocol, SSL.Clocks.UTC (2028, 1, 1), Error);
      Expect (SSL.Errors.Is_Error (Error), "an expired pin does not satisfy the policy");
      Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Pin_Expired,
              "and the reason says it expired");

      --  A mode that consults pins with none configured can never succeed.
      Expect (not Is_Valid_Policy (Require_Valid_Path_And_Pin, No_Pins),
              "pinning with no pins is refused at configuration time");
      Expect (not Is_Valid_Policy (Pin_Only, No_Pins), "pin-only with no pins is refused");
      Expect (Is_Valid_Policy (No_Pinning, No_Pins), "no pinning needs no pins");
      Expect (Is_Valid_Policy (Require_Valid_Path_And_Pin, Pins), "pins make the policy valid");
   end Run_Pinning;

   ---------------------------------------------------------------------------
   --  Revocation
   ---------------------------------------------------------------------------

   procedure Run_Revocation (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Revocation (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      use SSL.Trust.Revocation;

      Now    : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 7, 30);
      Error  : SSL.Errors.Error_Information;
   begin
      --  A revocation always fails, in every mode -- including the disabled one.
      --  Disabling revocation checking means not going looking for status; it
      --  has never meant ignoring a revocation that arrived anyway.
      for Policy in Revocation_Policy loop
         Evaluate (Policy, Revoked, Stapled_By_Peer, True, Now, Bounds, Error);
         Expect (SSL.Errors.Is_Error (Error),
                 "a revocation fails under " & Image (Policy));
         Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Certificate_Revoked,
                 "and it is reported as a revocation under " & Image (Policy));
      end loop;

      --  Absent status is fine when nothing was demanded.
      Evaluate (Revocation_Disabled, Status_Unknown, Stapled_By_Peer, False, Now, Bounds, Error);
      Expect (not SSL.Errors.Is_Error (Error), "disabled tolerates absent status");
      Evaluate (Check_When_Available, Status_Unknown, Stapled_By_Peer, False, Now, Bounds, Error);
      Expect (not SSL.Errors.Is_Error (Error), "check-when-available tolerates absent status");

      --  And a failure when it was.
      Evaluate (Require_Valid_Status, Status_Unknown, Stapled_By_Peer, False, Now, Bounds, Error);
      Expect (SSL.Errors.Is_Error (Error), "requiring status fails when there is none");
      Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Revocation_Status_Absent,
              "and the reason says it was absent");

      Evaluate (Require_Valid_Status, Not_Revoked, Supplied_By_Application, True,
                Now, Bounds, Error);
      Expect (not SSL.Errors.Is_Error (Error),
              "an affirmative application-supplied answer satisfies require-valid");

      --  The stricter mode takes only the peer's own staple: an application
      --  response may come from a cache the peer knows nothing about.
      Evaluate (Require_Stapled_OCSP, Not_Revoked, Supplied_By_Application, True,
                Now, Bounds, Error);
      Expect (SSL.Errors.Is_Error (Error), "require-stapled declines an application response");
      Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Stapled_Status_Required,
              "and the reason says a staple was required");

      Evaluate (Require_Stapled_OCSP, Not_Revoked, Stapled_By_Peer, True, Now, Bounds, Error);
      Expect (not SSL.Errors.Is_Error (Error), "require-stapled accepts a staple");

      --  Stale is distinguished from unknown, because they call for different
      --  operator action.
      Evaluate (Require_Valid_Status, Status_Stale, Stapled_By_Peer, True, Now, Bounds, Error);
      Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Revocation_Status_Stale,
              "stale status is reported as stale");

      --  A response about a different certificate is worse than none: it is an
      --  answer to a question nobody asked.
      Evaluate (Require_Valid_Status, Wrong_Issuer, Stapled_By_Peer, True, Now, Bounds, Error);
      Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Stapled_Status_Wrong_Certificate,
              "a response for the wrong issuer is reported as such");

      --  Satisfiability, which the configuration checks before any handshake.
      Expect (Is_Satisfiable (Revocation_Disabled, False, False), "disabled is always satisfiable");
      Expect (Is_Satisfiable (Check_When_Available, False, False),
              "check-when-available is always satisfiable");
      Expect (not Is_Satisfiable (Require_Valid_Status, False, False),
              "requiring status with no source can never succeed");
      Expect (Is_Satisfiable (Require_Valid_Status, True, False),
              "requesting stapling makes it satisfiable");
      Expect (Is_Satisfiable (Require_Valid_Status, False, True),
              "an application provider makes it satisfiable");
      Expect (not Is_Satisfiable (Require_Stapled_OCSP, False, True),
              "require-stapled is not satisfied by a provider alone");
      Expect (Is_Satisfiable (Require_Stapled_OCSP, True, False),
              "require-stapled needs the request sent");

      Expect (Is_Affirmative (Not_Revoked), "not_revoked is affirmative");
      Expect (not Is_Affirmative (Status_Unknown), "unknown is not affirmative");
      Expect (Is_Revocation (Revoked), "revoked is a revocation");
      Expect (not Is_Revocation (Status_Stale), "stale is not a revocation");
   end Run_Revocation;

   ---------------------------------------------------------------------------
   --  Trust snapshots
   ---------------------------------------------------------------------------

   procedure Run_Trust (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Trust (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Item   : SSL.Trust.Snapshot;
      Now    : constant SSL.Clocks.Wall_Time := SSL.Clocks.UTC (2026, 7, 30);
      Error  : SSL.Errors.Error_Information;
   begin
      Expect (not SSL.Trust.Is_Built (Item), "a fresh snapshot is not built");

      --  Text with no certificate in it yields no snapshot, and fails closed
      --  rather than producing an empty one. An empty trust base would turn a
      --  misconfiguration into an unauthenticated connection.
      SSL.Trust.Load_Explicit_Anchors (Item, "not a certificate", Now, Bounds, Error);
      Expect (SSL.Errors.Is_Error (Error), "anchor material with no certificate is refused");
      Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Trust_Source_Empty,
              "and the reason says the source was empty");
      Expect (not SSL.Trust.Is_Built (Item), "and no snapshot was produced");

      SSL.Trust.Load_Explicit_Anchors (Item, "", Now, Bounds, Error);
      Expect (SSL.Errors.Is_Error (Error), "empty text is refused");
   end Run_Trust;

   ---------------------------------------------------------------------------
   --  Credentials
   ---------------------------------------------------------------------------

   procedure Run_Credentials (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Credentials (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Item   : SSL.Credentials.Credential;
      Error  : SSL.Errors.Error_Information;
   begin
      Expect (not SSL.Credentials.Is_Loaded (Item), "a fresh credential is not loaded");

      --  Material with no certificate in it is refused, and the credential is
      --  left unloaded rather than half-built.
      SSL.Credentials.Load_PEM (Item, "no certificate here", "no key here", Bounds, Error);
      Expect (SSL.Errors.Is_Error (Error), "material with no PEM block is refused");
      Expect (not SSL.Credentials.Is_Loaded (Item), "and the credential stays unloaded");

      SSL.Credentials.Load_PEM (Item, "", "", Bounds, Error);
      Expect (SSL.Errors.Is_Error (Error), "empty material is refused");
      Expect (not SSL.Credentials.Is_Loaded (Item), "and the credential stays unloaded");
   end Run_Credentials;

   ---------------------------------------------------------------------------
   --  SNI credential selection
   ---------------------------------------------------------------------------

   procedure Run_Credential_Selection (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Credential_Selection (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      Builder : Config.Server_Builder;
      Result  : Config.Server_Configuration;
      Error   : SSL.Errors.Error_Information;
      Index   : Natural;

      EdDSA_Only : SSL.Signature_Schemes.Scheme_List := SSL.Signature_Schemes.No_Schemes;
      RSA_Only   : SSL.Signature_Schemes.Scheme_List := SSL.Signature_Schemes.No_Schemes;
      Ok         : Boolean;
   begin
      Provisioned_Server (Builder);
      Config.Build (Builder, Result, Error);
      Expect (not SSL.Errors.Is_Error (Error),
              "the server builds: " & SSL.Errors.Image (Error));
      Expect (Config.Credential_Count (Result) = 1, "one credential is configured");

      SSL.Signature_Schemes.Append (EdDSA_Only, SSL.Signature_Schemes.Ed25519, Ok);
      SSL.Signature_Schemes.Append (RSA_Only, SSL.Signature_Schemes.RSA_PSS_RSAE_SHA256, Ok);

      --  The fixture is an Ed25519 credential covering www.example.com and
      --  *.example.com.
      Expect (Config.Select_Credential
                (Result, SSL.Server_Names.Name ("www.example.com"),
                 EdDSA_Only, SSL.Versions.TLS_1_3, Index),
              "the exact name selects the credential");
      Expect (Index = 1, "and it is the one configured");

      Expect (Config.Select_Credential
                (Result, SSL.Server_Names.Name ("api.example.com"),
                 EdDSA_Only, SSL.Versions.TLS_1_3, Index),
              "a name under the wildcard selects it too");

      --  A name it does not cover is refused, because the default
      --  unrecognized-name policy is to reject.
      Expect (not Config.Select_Credential
                    (Result, SSL.Server_Names.Name ("www.elsewhere.test"),
                     EdDSA_Only, SSL.Versions.TLS_1_3, Index),
              "a name the credential does not cover selects nothing");

      --  Capability is checked, not just the name: a peer that will only accept
      --  RSA cannot be served by an Ed25519 credential however well the name
      --  matches.
      Expect (not Config.Select_Credential
                    (Result, SSL.Server_Names.Name ("www.example.com"),
                     RSA_Only, SSL.Versions.TLS_1_3, Index),
              "a credential that cannot produce an offered scheme is not selected");

      --  And the version matters: PKCS#1 v1.5 is offered here but is not usable
      --  in a TLS 1.3 CertificateVerify, so it does not rescue the RSA case.
      declare
         Legacy_RSA : SSL.Signature_Schemes.Scheme_List := SSL.Signature_Schemes.No_Schemes;
      begin
         SSL.Signature_Schemes.Append (Legacy_RSA, SSL.Signature_Schemes.RSA_PKCS1_SHA256, Ok);
         Expect (not Config.Select_Credential
                       (Result, SSL.Server_Names.Name ("www.example.com"),
                        Legacy_RSA, SSL.Versions.TLS_1_3, Index),
                 "PKCS#1 v1.5 does not make an RSA-less credential selectable in TLS 1.3");
      end;

      --  With no name asked for at all, the first usable credential is the
      --  default, which is what insertion order as the last tie-break means.
      Expect (Config.Select_Credential
                (Result, SSL.Server_Names.No_Name,
                 EdDSA_Only, SSL.Versions.TLS_1_3, Index),
              "no SNI selects the default credential");
      Expect (Index = 1, "which is the first one added");
   end Run_Credential_Selection;

   ---------------------------------------------------------------------------
   --  External signers
   ---------------------------------------------------------------------------

   --  A signer that misbehaves in each of the ways the boundary is built to
   --  contain: raising from Sign, raising from Supports, refusing, and claiming
   --  to have written more than it was given room for.
   type Misbehaviour is (Behaves, Raises_On_Sign, Raises_On_Supports, Refuses, Overruns);

   type Test_Signer (Mode : Misbehaviour) is
     limited new SSL.Credentials.Signers.External_Signer with null record;

   overriding function Supports
     (Item   : Test_Signer;
      Scheme : SSL.Signature_Schemes.Signature_Scheme) return Boolean;
   overriding function Requires_Serialized_Access (Item : Test_Signer) return Boolean;
   overriding function Public_Key (Item : Test_Signer) return SSL.Byte_Array;
   overriding procedure Sign
     (Item        : in out Test_Signer;
      Scheme      : SSL.Signature_Schemes.Signature_Scheme;
      Signed_Data : SSL.Byte_Array;
      Signature   : out SSL.Byte_Array;
      Length      : out SSL.Byte_Index);
   overriding function Description (Item : Test_Signer) return String;

   overriding function Supports
     (Item   : Test_Signer;
      Scheme : SSL.Signature_Schemes.Signature_Scheme) return Boolean
   is
      pragma Unreferenced (Scheme);
   begin
      if Item.Mode = Raises_On_Supports then
         raise Program_Error with "a signer that answers questions badly";
      end if;
      return True;
   end Supports;

   overriding function Requires_Serialized_Access (Item : Test_Signer) return Boolean is
      pragma Unreferenced (Item);
   begin
      return True;
   end Requires_Serialized_Access;

   overriding function Public_Key (Item : Test_Signer) return SSL.Byte_Array is
      pragma Unreferenced (Item);
   begin
      return [1 .. 32 => 0];
   end Public_Key;

   overriding procedure Sign
     (Item        : in out Test_Signer;
      Scheme      : SSL.Signature_Schemes.Signature_Scheme;
      Signed_Data : SSL.Byte_Array;
      Signature   : out SSL.Byte_Array;
      Length      : out SSL.Byte_Index)
   is
      pragma Unreferenced (Scheme, Signed_Data);
   begin
      Signature := [others => 0];
      case Item.Mode is
         when Raises_On_Sign =>
            raise Constraint_Error with "a signer whose device fell over";
         when Refuses =>
            Length := 0;
         when Overruns =>
            Length := Signature'Length + 1;
         when others =>
            Signature (Signature'First .. Signature'First + 63) := [1 .. 64 => 16#5A#];
            Length := 64;
      end case;
   end Sign;

   overriding function Description (Item : Test_Signer) return String is
      pragma Unreferenced (Item);
   begin
      return "test-signer";
   end Description;

   procedure Run_External_Signer (T : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_External_Signer (T : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (T);
      use SSL.Credentials.Signers;

      Data      : constant SSL.Byte_Array (1 .. 8) := [others => 16#11#];
      Signature : SSL.Byte_Array (1 .. SSL.Credentials.Maximum_Signature_Length) :=
        [others => 0];
      Length    : SSL.Byte_Index;
      Error     : SSL.Errors.Error_Information;
   begin
      --  A signer that works.
      declare
         Good : Test_Signer (Behaves);
      begin
         Sign_Externally (Good, SSL.Signature_Schemes.Ed25519, Data,
                          Signature, Length, Error);
         Expect (not SSL.Errors.Is_Error (Error),
                 "a working signer succeeds: " & SSL.Errors.Image (Error));
         Expect (Length = 64, "and its signature is returned");
         Expect (Supports_Safely (Good, SSL.Signature_Schemes.Ed25519),
                 "and it answers its capability question");
      end;

      --  A signer that raises from Sign. The exception stops at the boundary
      --  and becomes a structured failure attributed to the provider, rather
      --  than unwinding through a handshake with keys installed.
      declare
         Bad : Test_Signer (Raises_On_Sign);
      begin
         Sign_Externally (Bad, SSL.Signature_Schemes.Ed25519, Data,
                          Signature, Length, Error);
         Expect (SSL.Errors.Is_Error (Error), "a raising signer produces a failure");
         Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Provider_Callback_Raised,
                 "and the reason says the callback raised");
         Expect (SSL.Errors.Origin_Of (Error) = SSL.Errors.External_Provider,
                 "and it is attributed to the provider");
         Expect (Length = 0, "and no signature is reported");
         Expect_Equal (SSL.Errors.Provider_Text (Error), "test-signer",
                       "and the signer is named");
      end;

      --  A signer that raises while being asked what it supports cannot be
      --  selected, and says so by answering no rather than by propagating.
      declare
         Awkward : Test_Signer (Raises_On_Supports);
      begin
         Expect (not Supports_Safely (Awkward, SSL.Signature_Schemes.Ed25519),
                 "a signer that raises on Supports is not selectable");
      end;

      --  A signer that declines.
      declare
         Declining : Test_Signer (Refuses);
      begin
         Sign_Externally (Declining, SSL.Signature_Schemes.Ed25519, Data,
                          Signature, Length, Error);
         Expect (SSL.Errors.Is_Error (Error), "a refusing signer produces a failure");
         Expect (SSL.Errors.Code_Of (Error) = SSL.Errors.Code_Provider_Refused,
                 "and the reason says it refused");
      end;

      --  A signer claiming to have written more than it was given room for.
      --  Nothing about the result can be trusted, including the part that fits.
      declare
         Liar : Test_Signer (Overruns);
      begin
         Sign_Externally (Liar, SSL.Signature_Schemes.Ed25519, Data,
                          Signature, Length, Error);
         Expect (SSL.Errors.Is_Error (Error), "an over-long claim is refused");
         Expect (Length = 0, "and no length is reported");
         for Octet of Signature loop
            Expect (Octet = 0, "and the buffer is cleared");
         end loop;
      end;
   end Run_External_Signer;

   ---------------------
   -- Register_Tests --
   ---------------------

   overriding procedure Register_Tests (T : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (T, Run_Clocks'Access, "clocks: wall order, deadlines");
      Register_Routine (T, Run_Cancellation'Access, "cancellation: one-way latch");
      Register_Routine (T, Run_Authentication'Access, "authentication: fresh versus resumed");
      Register_Routine (T, Run_Secure_Defaults'Access, "configuration: secure client defaults");
      Register_Routine (T, Run_Server_Defaults'Access, "configuration: secure server defaults");
      Register_Routine (T, Run_Modern_Compatibility'Access,
                        "configuration: compatibility does not weaken TLS 1.3");
      Register_Routine (T, Run_Ordering_Refusal'Access,
                        "configuration: TLS 1.2 suite ahead of TLS 1.3 refused");
      Register_Routine (T, Run_Finite_Field_Opt_In'Access,
                        "configuration: finite-field groups need an explicit opt-in (CERT-8)");
      Register_Routine (T, Run_Validation'Access, "configuration: validation refusals");
      Register_Routine (T, Run_Fingerprints'Access, "configuration: fingerprint separation");
      Register_Routine (T, Run_Pinning'Access, "pinning: scope, period, and what it refuses");
      Register_Routine (T, Run_Revocation'Access, "revocation: policy and evidence");
      Register_Routine (T, Run_Trust'Access, "trust: snapshots fail closed when empty");
      Register_Routine (T, Run_Credentials'Access, "credentials: unusable material refused");
      Register_Routine (T, Run_Credential_Selection'Access,
                        "credentials: SNI selection by specificity then capability");
      Register_Routine (T, Run_External_Signer'Access,
                        "signers: the provider boundary contains every misbehaviour");
   end Register_Tests;

end Tests_Policy;
