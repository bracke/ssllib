with SSL.ALPN;
with SSL.Authentication;
with SSL.Credentials;
with SSL.Diagnostics;
with SSL.Sessions.Client_Caches;
with SSL.Ticket_Keys;
with SSL.Unsafe.Key_Logging;
with SSL.Cipher_Suites;
with SSL.Errors;
with SSL.Limits;
with SSL.Server_Names;
with SSL.Signature_Schemes;
with SSL.Supported_Groups;
with SSL.Trust;
with SSL.Trust.Revocation;
with SSL.Trust.Pinning;
with SSL.Versions;

--  @summary Immutable client and server configurations, and the limited
--  builders that produce them.
--
--  A configuration is policy: which versions, suites, groups and signature
--  schemes this endpoint will use, what it expects to authenticate, what it will
--  negotiate about, and what bounds it holds a peer to. It is built once, checked
--  once, and then shared unchanged by as many connections as the caller likes,
--  from as many tasks as the caller likes. Nothing mutates it after Build.
--
--  The builder is separate and limited. That separation is what makes the
--  immutability worth having: there is no setter on a configuration, so a
--  connection cannot alter the policy it was handed, and two connections sharing
--  a configuration cannot interfere.
--
--  **Validation happens at Build, not at the first handshake.** A configuration
--  that cannot work -- no suite for an enabled version, a key share for a group
--  that is not offered, ALPN required with no protocols listed, ticket issuance
--  with no ticket key -- is refused with a structured error naming the problem.
--  The alternative is a configuration that looks fine until a connection fails
--  in production against one particular peer.
--
--  There is deliberately **no way to disable certificate path validation or
--  identity checking**. Not a flag defaulting to on: no flag. A library whose
--  verification can be turned off has its most dangerous state reachable from
--  ordinary configuration, and that state is invariably the one someone reaches
--  for to make a test pass. Pinning modes that alter *how* a peer is accepted
--  live in SSL.Trust.Pinning, and none of them removes identity matching.
package SSL.Configurations is

   ---------------------------------------------------------------------------
   --  Policy vocabulary
   ---------------------------------------------------------------------------

   --  Where a client's trust anchors come from.
   --
   --  Native system trust is the default and the only default. NSS and Java
   --  stores are opt-in and are never merged in silently: an operator who trusts
   --  the system store has not thereby agreed to trust whatever a browser
   --  profile on the same machine has accumulated.
   type Trust_Source is
     (Native_System,
      Explicit_Anchors_Only,
      Native_System_And_Explicit);

   function Image (Item : Trust_Source) return String;

   --  How hard this endpoint tries to establish revocation status.
   --
   --  A subtype rather than a second declaration: `SSL.Trust.Revocation` owns
   --  this policy and acts on it, and two enumerations with the same values in
   --  two packages would be two places for them to drift apart. The names are
   --  re-exported so that a caller configuring a policy need not name the
   --  package that evaluates it.
   --
   --  No mode fetches anything over the network, in any circumstance. Status
   --  comes from a stapled response or from the caller. See
   --  docs/known-limitations.md.
   subtype Revocation_Policy is SSL.Trust.Revocation.Revocation_Policy;

   Revocation_Disabled  : Revocation_Policy renames SSL.Trust.Revocation.Revocation_Disabled;
   Check_When_Available : Revocation_Policy renames SSL.Trust.Revocation.Check_When_Available;
   Require_Valid_Status : Revocation_Policy renames SSL.Trust.Revocation.Require_Valid_Status;
   Require_Stapled_OCSP : Revocation_Policy renames SSL.Trust.Revocation.Require_Stapled_OCSP;

   function Image (Item : Revocation_Policy) return String
     renames SSL.Trust.Revocation.Image;

   --  Whose preference order decides the cipher suite and group.
   type Negotiation_Preference is (Server_Preference, Client_Preference);

   function Image (Item : Negotiation_Preference) return String;

   --  What a server does with an SNI name it has no credential for.
   type Unrecognized_Name_Policy is
     (Reject_Unrecognized,
      Use_Default_Credential);

   function Image (Item : Unrecognized_Name_Policy) return String;

   ---------------------------------------------------------------------------
   --  Configurations
   ---------------------------------------------------------------------------

   --  Limited so that a configuration is shared by reference rather than copied.
   --  Copying one would be legal and harmless but wasteful -- it holds the ALPN
   --  list and the algorithm lists inline -- and passing it as an "in" parameter
   --  is already the shareable view.
   type Client_Configuration is limited private;
   type Server_Configuration is limited private;

   --  Has this configuration been through Build successfully? A configuration
   --  that has not is not usable and every entry point that takes one says so.
   function Is_Valid (Item : Client_Configuration) return Boolean;
   function Is_Valid (Item : Server_Configuration) return Boolean;

   --  The configuration's identity as a value. Two configurations that
   --  negotiate identically have the same fingerprint. Sessions are bound to it,
   --  so changing policy invalidates resumption rather than silently resuming
   --  under policy the session was not established under.
   function Fingerprint (Item : Client_Configuration) return Configuration_Fingerprint
     with Pre => Is_Valid (Item);
   function Fingerprint (Item : Server_Configuration) return Configuration_Fingerprint
     with Pre => Is_Valid (Item);

   --  Readers. Every one of these is a question a connection asks while
   --  negotiating; there are no setters.

   function Versions (Item : Client_Configuration) return SSL.Versions.Version_Set;
   function Cipher_Suites (Item : Client_Configuration) return SSL.Cipher_Suites.Suite_List;
   function Groups (Item : Client_Configuration) return SSL.Supported_Groups.Group_List;
   function Key_Share_Groups (Item : Client_Configuration) return SSL.Supported_Groups.Group_List;
   function Signature_Schemes (Item : Client_Configuration)
     return SSL.Signature_Schemes.Scheme_List;
   function Certificate_Signature_Schemes (Item : Client_Configuration)
     return SSL.Signature_Schemes.Scheme_List;
   function Application_Protocols (Item : Client_Configuration) return SSL.ALPN.Protocol_List;
   function ALPN_Requirement (Item : Client_Configuration) return SSL.ALPN.ALPN_Requirement;
   function Bounds (Item : Client_Configuration) return SSL.Limits.Resource_Limits;

   --  The three names that are commonly conflated and are separate here.
   --
   --  Expected_Name and Expected_Address are what the presented certificate must
   --  match -- the only one of the three that decides anything about trust.
   --  Server_Name_Indication is the routing hint sent in the extension, which is
   --  not authenticated. The transport destination is the caller's and this
   --  library never sees it.
   function Expected_Name (Item : Client_Configuration) return SSL.Server_Names.DNS_Name;
   function Expected_Address (Item : Client_Configuration) return SSL.Server_Names.IP_Address;
   function Server_Name_Indication (Item : Client_Configuration) return SSL.Server_Names.DNS_Name;
   function Sends_Server_Name (Item : Client_Configuration) return Boolean;

   function Trust_Source_Of (Item : Client_Configuration) return Trust_Source;

   --  The trust snapshot this configuration validates against.
   --
   --  A reference to the caller's snapshot, not a copy: a snapshot holds every
   --  anchor on the machine and copying it per configuration would be
   --  megabytes. **The caller must keep the snapshot alive for as long as the
   --  configuration is used**, which is the one lifetime obligation this API
   --  places on an application. Build validation refuses a configuration whose
   --  policy needs anchors and has none attached.
   function Anchors (Item : Client_Configuration) return access constant SSL.Trust.Snapshot;

   function Has_Anchors (Item : Client_Configuration) return Boolean;

   --  The client certificate, when one is configured. Absent means this client
   --  will send an empty Certificate if a server asks, which a server may
   --  accept or refuse according to its own policy.
   function Client_Credential (Item : Client_Configuration)
     return access constant SSL.Credentials.Credential;

   function Has_Client_Credential (Item : Client_Configuration) return Boolean;

   function Pinning_Mode_Of (Item : Client_Configuration)
     return SSL.Trust.Pinning.Pinning_Mode;
   function Pins (Item : Client_Configuration) return SSL.Trust.Pinning.Pin_Set;
   function Uses_NSS_Trust (Item : Client_Configuration) return Boolean;
   function Uses_Java_Trust (Item : Client_Configuration) return Boolean;
   function Revocation (Item : Client_Configuration) return Revocation_Policy;
   function Requests_Stapled_Status (Item : Client_Configuration) return Boolean;
   function Resumption_Enabled (Item : Client_Configuration) return Boolean;
   function Session_Cache_Of (Item : Client_Configuration)
     return SSL.Sessions.Client_Caches.Cache_Reference;
   function Security_Context_Of (Item : Client_Configuration) return Security_Context_ID;
   function Sends_Close_Notify (Item : Client_Configuration) return Boolean;
   function Detects_Truncation (Item : Client_Configuration) return Boolean;
   function Record_Padding (Item : Client_Configuration) return Byte_Index;

   --  The diagnostics an application attached, if any.
   function Diagnostic_Sink (Item : Client_Configuration)
     return SSL.Diagnostics.Sink_Reference;
   function Diagnostic_Level (Item : Client_Configuration)
     return SSL.Diagnostics.Detail_Level;
   function Diagnostic_Redaction (Item : Client_Configuration)
     return SSL.Diagnostics.Redaction_Level;

   --  The key-log sink an application attached, if any. Absent unless a
   --  configuration explicitly attached one.
   function Key_Log_Sink (Item : Client_Configuration)
     return SSL.Unsafe.Key_Logging.Sink_Reference;

   function Versions (Item : Server_Configuration) return SSL.Versions.Version_Set;
   function Cipher_Suites (Item : Server_Configuration) return SSL.Cipher_Suites.Suite_List;
   function Groups (Item : Server_Configuration) return SSL.Supported_Groups.Group_List;
   function Signature_Schemes (Item : Server_Configuration)
     return SSL.Signature_Schemes.Scheme_List;
   function Application_Protocols (Item : Server_Configuration) return SSL.ALPN.Protocol_List;
   function ALPN_Requirement (Item : Server_Configuration) return SSL.ALPN.ALPN_Requirement;
   function ALPN_Selection (Item : Server_Configuration) return SSL.ALPN.Selection_Policy;
   function Bounds (Item : Server_Configuration) return SSL.Limits.Resource_Limits;
   function Preference (Item : Server_Configuration) return Negotiation_Preference;
   function Client_Authentication (Item : Server_Configuration)
     return SSL.Authentication.Client_Authentication_Policy;
   function Issues_Tickets (Item : Server_Configuration) return Boolean;
   function Ticket_Keys_Of (Item : Server_Configuration)
     return access constant SSL.Ticket_Keys.Ring;
   function Name_Policy (Item : Server_Configuration) return Unrecognized_Name_Policy;

   --  The credentials this server may present, in the order they were added.
   function Credential_Count (Item : Server_Configuration) return Natural;
   function Credential_At (Item : Server_Configuration; Index : Positive)
     return access constant SSL.Credentials.Credential
     with Pre => Index <= Credential_Count (Item);

   --  The trust snapshot used to validate client certificates. Absent when
   --  client authentication is not requested.
   function Anchors (Item : Server_Configuration) return access constant SSL.Trust.Snapshot;
   function Has_Anchors (Item : Server_Configuration) return Boolean;

   --  Choose the credential to present for an SNI name.
   --
   --  Deterministic, and the ordering is the whole point. Candidates are ranked
   --  by, in order: whether the credential covers the name at all and how
   --  specifically (an exact subjectAltName ahead of any wildcard, a narrower
   --  wildcard ahead of a broader one), whether it can produce a signature
   --  scheme the peer offered, and finally the order it was added in. Insertion
   --  order is the last tie-break rather than the first, so adding a credential
   --  never changes which one an existing name resolves to unless the new one is
   --  genuinely more specific.
   --  @param Item      the configuration
   --  @param Name      the name the client asked for, or No_Name for none
   --  @param Offered   the signature schemes the client will accept
   --  @param Version   the protocol version being negotiated
   --  @param Index     out: which credential to present
   --  @return True when one was found
   function Select_Credential
     (Item    : Server_Configuration;
      Name    : SSL.Server_Names.DNS_Name;
      Offered : SSL.Signature_Schemes.Scheme_List;
      Version : SSL.Versions.Protocol_Version;
      Index   : out Natural) return Boolean;
   function Security_Context_Of (Item : Server_Configuration) return Security_Context_ID;
   function Sends_Close_Notify (Item : Server_Configuration) return Boolean;
   function Detects_Truncation (Item : Server_Configuration) return Boolean;
   function Record_Padding (Item : Server_Configuration) return Byte_Index;

   function Diagnostic_Sink (Item : Server_Configuration)
     return SSL.Diagnostics.Sink_Reference;
   function Diagnostic_Level (Item : Server_Configuration)
     return SSL.Diagnostics.Detail_Level;
   function Diagnostic_Redaction (Item : Server_Configuration)
     return SSL.Diagnostics.Redaction_Level;
   function Key_Log_Sink (Item : Server_Configuration)
     return SSL.Unsafe.Key_Logging.Sink_Reference;

   ---------------------------------------------------------------------------
   --  Builders
   ---------------------------------------------------------------------------

   type Client_Builder is limited private;
   type Server_Builder is limited private;

   --  TLS 1.3 only, all three required suites, X25519 with P-256 and P-384,
   --  native system trust, path and identity verification required, SNI sent for
   --  DNS names, resumption enabled, 0-RTT absent, truncation detected,
   --  close_notify attempted. Specification section 9.
   procedure Secure_Client_Defaults (Item : out Client_Builder);

   --  TLS 1.3 only, all three required suites, X25519 with P-256 and P-384,
   --  server-preference negotiation, client certificates not requested, tickets
   --  disabled until ticket keys exist, 0-RTT absent.
   procedure Secure_Server_Defaults (Item : out Server_Builder);

   --  The secure defaults plus the restricted TLS 1.2, and nothing else changed.
   --
   --  Adding TLS 1.2 does not weaken TLS 1.3: the same groups, the same TLS 1.3
   --  suites in the same order, the same verification. The TLS 1.2 suites are
   --  appended after the TLS 1.3 ones, and the PKCS#1 v1.5 signature schemes
   --  become reachable -- but only for TLS 1.2, which
   --  SSL.Signature_Schemes.Usable_For_Handshake enforces independently of this
   --  configuration.
   procedure Modern_Compatibility_Client (Item : out Client_Builder);
   procedure Modern_Compatibility_Server (Item : out Server_Builder);

   ---------------------------------------------------------------------------
   --  Client builder
   ---------------------------------------------------------------------------

   --  Each of these replaces a policy field. They report failure through Ok
   --  rather than raising, because a caller assembling policy from a
   --  configuration file has an ordinary failure to handle, not a bug.

   procedure Set_Versions
     (Item : in out Client_Builder; Value : SSL.Versions.Version_Set; Ok : out Boolean);

   procedure Set_Cipher_Suites
     (Item : in out Client_Builder; Value : SSL.Cipher_Suites.Suite_List; Ok : out Boolean);

   --  Set the supported groups. Refuses a list containing a finite-field group;
   --  those are added by Accept_Finite_Field_Groups, so that enabling them is
   --  always a deliberate separate act.
   procedure Set_Groups
     (Item : in out Client_Builder; Value : SSL.Supported_Groups.Group_List; Ok : out Boolean);

   --  Add ffdhe2048, ffdhe3072 and ffdhe4096 to the supported groups.
   --
   --  For a policy that requires finite-field key exchange. They are appended
   --  after the curves, so a peer that offers both gets a curve. No key share is
   --  sent for them, so selecting one costs a HelloRetryRequest -- which is the
   --  right trade when the group costs 62 ms of key exchange against 2.3 ms for
   --  X25519. See docs/security-model.md.
   procedure Accept_Finite_Field_Groups (Item : in out Client_Builder; Ok : out Boolean);

   --  The groups a ClientHello sends an actual key share for. Must be a subset
   --  of the supported groups, which RFC 8446 section 4.2.8 requires and which
   --  Build checks.
   procedure Set_Key_Share_Groups
     (Item : in out Client_Builder; Value : SSL.Supported_Groups.Group_List; Ok : out Boolean);

   procedure Set_Signature_Schemes
     (Item : in out Client_Builder; Value : SSL.Signature_Schemes.Scheme_List; Ok : out Boolean);

   procedure Set_Certificate_Signature_Schemes
     (Item : in out Client_Builder; Value : SSL.Signature_Schemes.Scheme_List; Ok : out Boolean);

   procedure Set_Application_Protocols
     (Item        : in out Client_Builder;
      Value       : SSL.ALPN.Protocol_List;
      Requirement : SSL.ALPN.ALPN_Requirement;
      Ok          : out Boolean);

   --  The DNS name the presented certificate must match, and -- unless
   --  Send_Indication is False -- the name sent in the server_name extension.
   --
   --  The two are the same string in nearly every case, which is why they are
   --  set together. They are separate fields because they are separate
   --  questions: a connection through a proxy, or to a staging host, may need to
   --  authenticate one name while routing on another or sending none.
   procedure Set_Expected_Name
     (Item            : in out Client_Builder;
      Value           : SSL.Server_Names.DNS_Name;
      Send_Indication : Boolean := True;
      Ok              : out Boolean);

   --  Send a different routing name from the one being authenticated. Rare, and
   --  deliberately awkward to reach: it is the shape of a mistake as often as it
   --  is the shape of a proxy.
   procedure Set_Server_Name_Indication
     (Item : in out Client_Builder; Value : SSL.Server_Names.DNS_Name; Ok : out Boolean);

   --  Authenticate an IP address through an iPAddress subjectAltName. No SNI is
   --  sent: RFC 6066 section 3 forbids an address there.
   procedure Set_Expected_Address
     (Item : in out Client_Builder; Value : SSL.Server_Names.IP_Address; Ok : out Boolean);

   procedure Set_Trust_Source
     (Item        : in out Client_Builder;
      Value       : Trust_Source;
      Include_NSS : Boolean := False;
      Include_Java : Boolean := False;
      Ok          : out Boolean);

   --  Attach the trust snapshot. The caller retains ownership and must keep it
   --  alive for as long as the configuration is used.
   --  @param Item    the builder
   --  @param Value   the snapshot, which must already be built
   --  @param Ok      out: False when the snapshot holds no anchors
   procedure Set_Anchors
     (Item  : in out Client_Builder;
      Value : not null access constant SSL.Trust.Snapshot;
      Ok    : out Boolean);

   --  Attach a client certificate, for mutual TLS. Same lifetime obligation.
   procedure Set_Client_Credential
     (Item  : in out Client_Builder;
      Value : not null access constant SSL.Credentials.Credential;
      Ok    : out Boolean);

   --  Set the pinning policy and its pins.
   procedure Set_Pinning
     (Item : in out Client_Builder;
      Mode : SSL.Trust.Pinning.Pinning_Mode;
      Pins : SSL.Trust.Pinning.Pin_Set;
      Ok   : out Boolean);

   procedure Set_Revocation_Policy
     (Item : in out Client_Builder; Value : Revocation_Policy; Ok : out Boolean);

   procedure Set_Resumption (Item : in out Client_Builder; Enabled : Boolean);
   procedure Set_Security_Context
     (Item : in out Client_Builder; Value : Security_Context_ID);
   procedure Set_Limits
     (Item : in out Client_Builder; Value : SSL.Limits.Resource_Limits; Ok : out Boolean);
   procedure Set_Record_Padding
     (Item : in out Client_Builder; Octets : Byte_Index; Ok : out Boolean);
   procedure Set_Close_Behaviour
     (Item              : in out Client_Builder;
      Send_Close_Notify : Boolean;
      Detect_Truncation : Boolean);

   --  Check the assembled policy and produce the configuration.
   --
   --  On failure Into is left invalid and Error names what is wrong. The builder
   --  is unchanged, so a caller can correct one field and build again.
   procedure Build
     (Item  : in out Client_Builder;
      Into  : out Client_Configuration;
      Error : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  Server builder
   ---------------------------------------------------------------------------

   procedure Set_Versions
     (Item : in out Server_Builder; Value : SSL.Versions.Version_Set; Ok : out Boolean);

   procedure Set_Cipher_Suites
     (Item : in out Server_Builder; Value : SSL.Cipher_Suites.Suite_List; Ok : out Boolean);

   --  Set the supported groups. **Refuses any list containing a finite-field
   --  group.** A server acquires those only through
   --  Accept_Finite_Field_Groups_With_Amplification_Risk, below.
   procedure Set_Groups
     (Item : in out Server_Builder; Value : SSL.Supported_Groups.Group_List; Ok : out Boolean);

   --  Accept finite-field groups as a server, knowingly.
   --
   --  The long name is the point. Accepting a large finite-field group
   --  server-side is a denial-of-service amplifier: an attacker sends a
   --  ClientHello carrying a random in-range key share, and this endpoint must
   --  perform key generation and agreement -- 62 ms of CPU at ffdhe4096, against
   --  2.3 ms for X25519 -- before it can derive handshake keys. The attacker
   --  spent the cost of generating random octets and never completes the
   --  handshake. Roughly sixteen connections per second per core saturates a
   --  server that accepts ffdhe4096, against about nine hundred for X25519.
   --
   --  There is no way to reach this through Set_Groups, and no server default
   --  includes it. A caller that needs finite-field key exchange server-side
   --  should also lower Maximum_Ciphertext_Queue and put a connection-rate limit
   --  in front of the endpoint. See docs/security-model.md.
   --  @param Item the builder
   --  @param Ok   out: False when the groups are already present
   procedure Accept_Finite_Field_Groups_With_Amplification_Risk
     (Item : in out Server_Builder; Ok : out Boolean);

   procedure Set_Signature_Schemes
     (Item : in out Server_Builder; Value : SSL.Signature_Schemes.Scheme_List; Ok : out Boolean);

   procedure Set_Application_Protocols
     (Item        : in out Server_Builder;
      Value       : SSL.ALPN.Protocol_List;
      Requirement : SSL.ALPN.ALPN_Requirement;
      Selection   : SSL.ALPN.Selection_Policy;
      Ok          : out Boolean);

   procedure Set_Preference
     (Item : in out Server_Builder; Value : Negotiation_Preference);

   ---------------------------------------------------------------------------
   --  Diagnostics and key logging
   ---------------------------------------------------------------------------

   --  Attach a diagnostic sink.
   --
   --  The sink must outlive every connection built from this configuration.
   --  Attaching none leaves diagnostics off, which is the default: a library
   --  that logged without being asked would be writing into an application's
   --  output uninvited.
   --  @param Item      the builder
   --  @param Value     the sink
   --  @param Level     how much to say
   --  @param Redaction how much of the non-secret detail may travel
   procedure Set_Diagnostics
     (Item      : in out Client_Builder;
      Value     : not null SSL.Diagnostics.Sink_Reference;
      Level     : SSL.Diagnostics.Detail_Level;
      Redaction : SSL.Diagnostics.Redaction_Level := SSL.Diagnostics.Operational);

   procedure Set_Diagnostics
     (Item      : in out Server_Builder;
      Value     : not null SSL.Diagnostics.Sink_Reference;
      Level     : SSL.Diagnostics.Detail_Level;
      Redaction : SSL.Diagnostics.Redaction_Level := SSL.Diagnostics.Operational);

   --  Attach a key-log sink, which defeats the encryption for every connection
   --  built from this configuration.
   --
   --  Named `Unsafe` in its own type, so that the `with` clause reaching it says
   --  what it is. There is no environment variable that does this and there
   --  will not be: a facility an environment variable enables is a facility
   --  anyone who can set environment variables enables.
   --  @param Item  the builder
   --  @param Value the sink, which must outlive every connection
   procedure Set_Unsafe_Key_Logging
     (Item  : in out Client_Builder;
      Value : not null SSL.Unsafe.Key_Logging.Sink_Reference);

   procedure Set_Unsafe_Key_Logging
     (Item  : in out Server_Builder;
      Value : not null SSL.Unsafe.Key_Logging.Sink_Reference);

   ---------------------------------------------------------------------------
   --  Sessions and tickets
   ---------------------------------------------------------------------------

   --  Attach the keys this server seals its tickets with.
   --
   --  Until one is attached, enabling ticket issuance fails at `Build` with
   --  `Code_Ticket_Issuance_Without_Key`. The ring must outlive every
   --  connection built from this configuration, and must have an active key by
   --  the time a handshake completes -- a ring whose keys have all retired
   --  simply stops issuing, which is a state and not a failure.
   --  @param Item  the builder
   --  @param Value the ring
   procedure Set_Ticket_Keys
     (Item  : in out Server_Builder;
      Value : not null access constant SSL.Ticket_Keys.Ring);

   --  Attach the cache this client keeps resumable sessions in.
   --
   --  Without one a client never resumes, which is the default. The cache must
   --  outlive every connection built from this configuration.
   procedure Set_Session_Cache
     (Item  : in out Client_Builder;
      Value : not null SSL.Sessions.Client_Caches.Cache_Reference);

   procedure Set_Client_Authentication
     (Item  : in out Server_Builder;
      Value : SSL.Authentication.Client_Authentication_Policy);

   --  Issue session tickets.
   --
   --  Enabling this without ticket keys fails at Build with
   --  Code_Ticket_Issuance_Without_Key. That is the specification's "tickets
   --  disabled until valid ticket keys are configured", enforced rather than
   --  documented: a server that issued tickets under a key it did not have would
   --  be issuing tickets nobody can decrypt.
   procedure Set_Ticket_Issuance (Item : in out Server_Builder; Enabled : Boolean);

   procedure Set_Name_Policy
     (Item : in out Server_Builder; Value : Unrecognized_Name_Policy);

   --  Add a credential this server may present. Order is the final tie-break in
   --  selection; specificity and capability come first. Same lifetime
   --  obligation as the client side.
   --  @param Item  the builder
   --  @param Value the credential, which must already be loaded
   --  @param Ok    out: False when the credential is unloaded or the list is full
   procedure Add_Credential
     (Item  : in out Server_Builder;
      Value : not null access constant SSL.Credentials.Credential;
      Ok    : out Boolean);

   --  Attach the trust snapshot used to validate client certificates. Required
   --  once client authentication is requested, and refused at Build otherwise.
   procedure Set_Anchors
     (Item  : in out Server_Builder;
      Value : not null access constant SSL.Trust.Snapshot;
      Ok    : out Boolean);

   procedure Set_Security_Context
     (Item : in out Server_Builder; Value : Security_Context_ID);
   procedure Set_Limits
     (Item : in out Server_Builder; Value : SSL.Limits.Resource_Limits; Ok : out Boolean);
   procedure Set_Record_Padding
     (Item : in out Server_Builder; Octets : Byte_Index; Ok : out Boolean);
   procedure Set_Close_Behaviour
     (Item              : in out Server_Builder;
      Send_Close_Notify : Boolean;
      Detect_Truncation : Boolean);

   procedure Build
     (Item  : in out Server_Builder;
      Into  : out Server_Configuration;
      Error : out SSL.Errors.Error_Information);

private

   --  The policy every endpoint has, whatever its role. Held once and shared by
   --  both configuration types so that a rule stated in one place applies to
   --  both -- the version/suite consistency check in particular, which is the
   --  same question for a client and a server.
   type Common_Policy is record
      Versions            : SSL.Versions.Version_Set := SSL.Versions.TLS_1_3_Only;
      Suites              : SSL.Cipher_Suites.Suite_List :=
        SSL.Cipher_Suites.Default_TLS_1_3_Suites;
      Groups              : SSL.Supported_Groups.Group_List :=
        SSL.Supported_Groups.Default_Groups;
      Schemes             : SSL.Signature_Schemes.Scheme_List :=
        SSL.Signature_Schemes.Default_Schemes;
      Protocols           : SSL.ALPN.Protocol_List := SSL.ALPN.No_Protocols;
      ALPN_Need           : SSL.ALPN.ALPN_Requirement := SSL.ALPN.Not_Offered;
      Bounds              : SSL.Limits.Resource_Limits := SSL.Limits.Default_Limits;
      Context             : Security_Context_ID := Default_Security_Context;
      Send_Close          : Boolean := True;
      Detect_Truncation   : Boolean := True;
      Padding             : Byte_Index := 0;

      --  Diagnostics. Off with no sink is the default and is the only default
      --  a library can defensibly have: anything else would be writing into an
      --  application's output uninvited.
      Diagnostic_Sink     : SSL.Diagnostics.Sink_Reference := null;
      Diagnostic_Level    : SSL.Diagnostics.Detail_Level := SSL.Diagnostics.Off;
      Diagnostic_Redaction : SSL.Diagnostics.Redaction_Level := SSL.Diagnostics.Strict;

      --  Key logging. Absent unless a configuration explicitly attaches a sink,
      --  and reachable only by naming SSL.Unsafe.
      Key_Log_Sink        : SSL.Unsafe.Key_Logging.Sink_Reference := null;
   end record;

   Maximum_Credentials : constant := 16;

   type Credential_Reference is access constant SSL.Credentials.Credential;
   type Credential_Array is array (1 .. Maximum_Credentials) of Credential_Reference;

   type Client_Policy is record
      Common            : Common_Policy;

      --  Where resumable sessions are kept. Absent by default: a client with no
      --  cache does full handshakes, which is correct and is what an
      --  application that has not thought about session lifetime should get.
      Session_Cache     : SSL.Sessions.Client_Caches.Cache_Reference := null;
      Trust_Snapshot    : access constant SSL.Trust.Snapshot := null;
      Own_Credential    : Credential_Reference := null;
      Pin_Mode          : SSL.Trust.Pinning.Pinning_Mode := SSL.Trust.Pinning.No_Pinning;
      Pin_Values        : SSL.Trust.Pinning.Pin_Set := SSL.Trust.Pinning.No_Pins;
      Key_Shares        : SSL.Supported_Groups.Group_List :=
        SSL.Supported_Groups.Default_Key_Share_Groups;
      Certificate_Schemes : SSL.Signature_Schemes.Scheme_List :=
        SSL.Signature_Schemes.Default_Certificate_Schemes;
      Expected_Name     : SSL.Server_Names.DNS_Name := SSL.Server_Names.No_Name;
      Expected_Address  : SSL.Server_Names.IP_Address := SSL.Server_Names.No_Address;
      Indication        : SSL.Server_Names.DNS_Name := SSL.Server_Names.No_Name;
      Send_Indication   : Boolean := True;
      Trust             : Trust_Source := Native_System;
      With_NSS          : Boolean := False;
      With_Java         : Boolean := False;
      Revocation        : Revocation_Policy := Check_When_Available;
      Request_Stapling  : Boolean := True;
      Resumption        : Boolean := True;
   end record;

   type Server_Policy is record
      Common          : Common_Policy;
      Trust_Snapshot  : access constant SSL.Trust.Snapshot := null;
      Credential_Total : Natural range 0 .. Maximum_Credentials := 0;
      Credential_List  : Credential_Array := [others => null];
      ALPN_Choice     : SSL.ALPN.Selection_Policy := SSL.ALPN.Server_Order;
      Prefer          : Negotiation_Preference := Server_Preference;
      Client_Auth     : SSL.Authentication.Client_Authentication_Policy :=
        SSL.Authentication.Not_Requested;
      Issue_Tickets   : Boolean := False;

      --  The keys tickets are sealed under. A reference, because the ring is
      --  the application's own object and rotation happens on it: a
      --  configuration is immutable after Build, and a key that rotated inside
      --  one would not be.
      Ticket_Ring     : access constant SSL.Ticket_Keys.Ring := null;

      Names           : Unrecognized_Name_Policy := Reject_Unrecognized;
   end record;

   type Client_Configuration is limited record
      Built  : Boolean := False;
      Policy : Client_Policy;
      Digest : Configuration_Fingerprint;
   end record;

   type Server_Configuration is limited record
      Built  : Boolean := False;
      Policy : Server_Policy;
      Digest : Configuration_Fingerprint;
   end record;

   type Client_Builder is limited record
      Policy : Client_Policy;
   end record;

   type Server_Builder is limited record
      Policy : Server_Policy;
   end record;

end SSL.Configurations;
