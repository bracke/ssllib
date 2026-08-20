with Ada.Streams;
with Interfaces;

with SSL.Crypto;
with SSL.Wire;

package body SSL.Configurations is

   use type SSL.Trust.Revocation.Revocation_Policy;

   use type Ada.Streams.Stream_Element_Array;
   use type SSL.Supported_Groups.Group_Family;
   use type SSL.Versions.Protocol_Version;
   use type SSL.Authentication.Client_Authentication_Policy;

   package Groups_Registry renames SSL.Supported_Groups;
   package Suites_Registry renames SSL.Cipher_Suites;
   package Schemes_Registry renames SSL.Signature_Schemes;

   ---------------------------------------------------------------------------
   --  Vocabulary
   ---------------------------------------------------------------------------

   function Image (Item : Trust_Source) return String is
   begin
      case Item is
         when Native_System              => return "native_system";
         when Explicit_Anchors_Only      => return "explicit_anchors_only";
         when Native_System_And_Explicit => return "native_system_and_explicit";
      end case;
   end Image;

   function Image (Item : Negotiation_Preference) return String is
   begin
      case Item is
         when Server_Preference => return "server_preference";
         when Client_Preference => return "client_preference";
      end case;
   end Image;

   function Image (Item : Unrecognized_Name_Policy) return String is
   begin
      case Item is
         when Reject_Unrecognized     => return "reject_unrecognized";
         when Use_Default_Credential  => return "use_default_credential";
      end case;
   end Image;

   ---------------------------------------------------------------------------
   --  Shared helpers
   ---------------------------------------------------------------------------

   --  Does this group list hold anything that is not an elliptic curve?
   function Holds_Finite_Field (Value : Groups_Registry.Group_List) return Boolean;

   function Holds_Finite_Field (Value : Groups_Registry.Group_List) return Boolean is
   begin
      for Index in 1 .. Groups_Registry.Length (Value) loop
         if Groups_Registry.Family_Of (Groups_Registry.Element (Value, Index))
           = Groups_Registry.Finite_Field
         then
            return True;
         end if;
      end loop;
      return False;
   end Holds_Finite_Field;

   --  Append the three finite-field groups to a list, after whatever is there,
   --  so a peer offering both a curve and a field gets the curve.
   procedure Append_Finite_Field
     (Value : in out Groups_Registry.Group_List; Added : out Boolean);

   procedure Append_Finite_Field
     (Value : in out Groups_Registry.Group_List; Added : out Boolean)
   is
      Done : Boolean;
   begin
      Added := False;
      for Group in Groups_Registry.Named_Group loop
         if Groups_Registry.Family_Of (Group) = Groups_Registry.Finite_Field then
            Groups_Registry.Append (Value, Group, Done);
            Added := Added or else Done;
         end if;
      end loop;
   end Append_Finite_Field;

   ---------------------------------------------------------------------------
   --  Defaults
   ---------------------------------------------------------------------------

   procedure Secure_Client_Defaults (Item : out Client_Builder) is
   begin
      --  Every field takes its declared default, which is where the secure
      --  policy of specification section 9 lives: TLS 1.3 only, all three
      --  required suites in preference order, X25519 with P-256 and P-384,
      --  native system trust, resumption on, close_notify sent, truncation
      --  detected, no padding. Verification is not a field because it cannot be
      --  turned off.
      --
      --  The component is assigned rather than the whole builder: Client_Builder
      --  is limited, and an "out" parameter of a limited type is not
      --  default-initialized on entry, so the reset has to be explicit.
      Item.Policy := (others => <>);
   end Secure_Client_Defaults;

   procedure Secure_Server_Defaults (Item : out Server_Builder) is
   begin
      --  Server preference, client certificates not requested, ticket issuance
      --  off until keys exist, and no finite-field groups.
      Item.Policy := (others => <>);
   end Secure_Server_Defaults;

   --  Add the restricted TLS 1.2 to a common policy without touching anything
   --  that governs TLS 1.3.
   procedure Add_TLS_1_2 (Item : in out Common_Policy);

   procedure Add_TLS_1_2 (Item : in out Common_Policy) is
      Done : Boolean;
   begin
      Item.Versions := SSL.Versions.TLS_1_3_And_1_2;

      --  Appended after the TLS 1.3 suites, never before. Order is preference
      --  order, so a TLS 1.2 suite ahead of a TLS 1.3 one would let a peer that
      --  speaks both be steered to the older protocol -- which is precisely the
      --  weakening the specification forbids, and which Validate refuses.
      declare
         Extra : constant Suites_Registry.Suite_List :=
           Suites_Registry.Default_TLS_1_2_Suites;
      begin
         for Index in 1 .. Suites_Registry.Length (Extra) loop
            Suites_Registry.Append (Item.Suites, Suites_Registry.Element (Extra, Index), Done);
         end loop;
      end;

      --  The signature schemes already include the PKCS#1 v1.5 entries, last.
      --  They become reachable now, but only for TLS 1.2:
      --  Signature_Schemes.Usable_For_Handshake enforces that independently of
      --  this configuration, so enabling TLS 1.2 cannot make them usable in a
      --  TLS 1.3 CertificateVerify.
      null;
   end Add_TLS_1_2;

   procedure Modern_Compatibility_Client (Item : out Client_Builder) is
   begin
      Secure_Client_Defaults (Item);
      Add_TLS_1_2 (Item.Policy.Common);
   end Modern_Compatibility_Client;

   procedure Modern_Compatibility_Server (Item : out Server_Builder) is
   begin
      Secure_Server_Defaults (Item);
      Add_TLS_1_2 (Item.Policy.Common);
   end Modern_Compatibility_Server;

   ---------------------------------------------------------------------------
   --  Common setters, written once and called from both roles
   ---------------------------------------------------------------------------

   procedure Set_Common_Versions
     (Item : in out Common_Policy; Value : SSL.Versions.Version_Set; Ok : out Boolean);

   procedure Set_Common_Versions
     (Item : in out Common_Policy; Value : SSL.Versions.Version_Set; Ok : out Boolean)
   is
   begin
      Ok := not SSL.Versions.Is_Empty (Value);
      if Ok then
         Item.Versions := Value;
      end if;
   end Set_Common_Versions;

   procedure Set_Common_Limits
     (Item : in out Common_Policy; Value : SSL.Limits.Resource_Limits; Ok : out Boolean);

   procedure Set_Common_Limits
     (Item : in out Common_Policy; Value : SSL.Limits.Resource_Limits; Ok : out Boolean)
   is
   begin
      Ok := SSL.Limits.Is_Valid (Value);
      if Ok then
         Item.Bounds := Value;
      end if;
   end Set_Common_Limits;

   procedure Set_Common_Padding
     (Item : in out Common_Policy; Octets : Byte_Index; Ok : out Boolean);

   procedure Set_Common_Padding
     (Item : in out Common_Policy; Octets : Byte_Index; Ok : out Boolean)
   is
   begin
      if Octets < 0 or else Octets > SSL.Limits.Protocol_Plaintext_Record_Limit then
         Ok := False;
         return;
      end if;
      Item.Padding := Octets;

      --  The bound moves with the setting rather than being a second knob that
      --  can disagree with it. Two fields for one decision is how a
      --  configuration ends up refusing what it was just told to do.
      Item.Bounds.Maximum_Record_Padding := Natural (Octets);
      Ok := True;
   end Set_Common_Padding;

   ---------------------------------------------------------------------------
   --  Client setters
   ---------------------------------------------------------------------------

   procedure Set_Versions
     (Item : in out Client_Builder; Value : SSL.Versions.Version_Set; Ok : out Boolean)
   is
   begin
      Set_Common_Versions (Item.Policy.Common, Value, Ok);
   end Set_Versions;

   procedure Set_Cipher_Suites
     (Item : in out Client_Builder; Value : Suites_Registry.Suite_List; Ok : out Boolean)
   is
   begin
      Ok := not Suites_Registry.Is_Empty (Value);
      if Ok then
         Item.Policy.Common.Suites := Value;
      end if;
   end Set_Cipher_Suites;

   procedure Set_Groups
     (Item : in out Client_Builder; Value : Groups_Registry.Group_List; Ok : out Boolean)
   is
   begin
      --  Finite-field groups arrive only through the named acceptor, in both
      --  roles, so that turning them on is always a separate deliberate act and
      --  never something inherited from a list somebody copied.
      Ok := not Groups_Registry.Is_Empty (Value) and then not Holds_Finite_Field (Value);
      if Ok then
         Item.Policy.Common.Groups := Value;
      end if;
   end Set_Groups;

   procedure Accept_Finite_Field_Groups (Item : in out Client_Builder; Ok : out Boolean) is
   begin
      Append_Finite_Field (Item.Policy.Common.Groups, Ok);
   end Accept_Finite_Field_Groups;

   procedure Set_Key_Share_Groups
     (Item : in out Client_Builder; Value : Groups_Registry.Group_List; Ok : out Boolean)
   is
   begin
      Ok := not Groups_Registry.Is_Empty (Value);
      if Ok then
         Item.Policy.Key_Shares := Value;
      end if;
   end Set_Key_Share_Groups;

   procedure Set_Signature_Schemes
     (Item : in out Client_Builder; Value : Schemes_Registry.Scheme_List; Ok : out Boolean)
   is
   begin
      Ok := not Schemes_Registry.Is_Empty (Value);
      if Ok then
         Item.Policy.Common.Schemes := Value;
      end if;
   end Set_Signature_Schemes;

   procedure Set_Certificate_Signature_Schemes
     (Item : in out Client_Builder; Value : Schemes_Registry.Scheme_List; Ok : out Boolean)
   is
   begin
      Ok := not Schemes_Registry.Is_Empty (Value);
      if Ok then
         Item.Policy.Certificate_Schemes := Value;
      end if;
   end Set_Certificate_Signature_Schemes;

   procedure Set_Application_Protocols
     (Item        : in out Client_Builder;
      Value       : SSL.ALPN.Protocol_List;
      Requirement : SSL.ALPN.ALPN_Requirement;
      Ok          : out Boolean)
   is
   begin
      Ok := SSL.ALPN.Is_Valid_Policy (Requirement, Value);
      if Ok then
         Item.Policy.Common.Protocols := Value;
         Item.Policy.Common.ALPN_Need := Requirement;
      end if;
   end Set_Application_Protocols;

   procedure Set_Expected_Name
     (Item            : in out Client_Builder;
      Value           : SSL.Server_Names.DNS_Name;
      Send_Indication : Boolean := True;
      Ok              : out Boolean)
   is
   begin
      --  A wildcard is a pattern a certificate may carry, never a name a client
      --  is trying to reach. Authenticating "*.example.com" would mean accepting
      --  a certificate for any host under it, which is not what any caller
      --  writing that string means.
      if not SSL.Server_Names.Is_Present (Value)
        or else SSL.Server_Names.Is_Wildcard (Value)
      then
         Ok := False;
         return;
      end if;

      Item.Policy.Expected_Name := Value;
      Item.Policy.Send_Indication := Send_Indication;

      --  The routing name follows the authenticated name unless the caller has
      --  deliberately separated them.
      if not SSL.Server_Names.Is_Present (Item.Policy.Indication) then
         Item.Policy.Indication := Value;
      end if;
      Ok := True;
   end Set_Expected_Name;

   procedure Set_Server_Name_Indication
     (Item : in out Client_Builder; Value : SSL.Server_Names.DNS_Name; Ok : out Boolean)
   is
   begin
      if not SSL.Server_Names.Is_Present (Value)
        or else SSL.Server_Names.Is_Wildcard (Value)
      then
         Ok := False;
         return;
      end if;
      Item.Policy.Indication := Value;
      Item.Policy.Send_Indication := True;
      Ok := True;
   end Set_Server_Name_Indication;

   procedure Set_Expected_Address
     (Item : in out Client_Builder; Value : SSL.Server_Names.IP_Address; Ok : out Boolean)
   is
   begin
      Ok := SSL.Server_Names.Is_Present (Value);
      if Ok then
         Item.Policy.Expected_Address := Value;

         --  RFC 6066 section 3: an address is not a legal server_name. Sending
         --  one is a protocol violation, so the indication is switched off
         --  rather than left for Build to complain about.
         Item.Policy.Send_Indication := False;
      end if;
   end Set_Expected_Address;

   procedure Set_Trust_Source
     (Item         : in out Client_Builder;
      Value        : Trust_Source;
      Include_NSS  : Boolean := False;
      Include_Java : Boolean := False;
      Ok           : out Boolean)
   is
   begin
      Item.Policy.Trust := Value;
      Item.Policy.With_NSS := Include_NSS;
      Item.Policy.With_Java := Include_Java;
      Ok := True;
   end Set_Trust_Source;

   procedure Set_Revocation_Policy
     (Item : in out Client_Builder; Value : Revocation_Policy; Ok : out Boolean)
   is
   begin
      Item.Policy.Revocation := Value;

      --  Demanding a stapled response while not asking for one can never
      --  succeed. Rather than let Build refuse it, asking for it turns the
      --  request on: the caller's intent is unambiguous.
      if Value = Require_Stapled_OCSP then
         Item.Policy.Request_Stapling := True;
      end if;
      Ok := True;
   end Set_Revocation_Policy;

   procedure Set_Anchors
     (Item  : in out Client_Builder;
      Value : not null access constant SSL.Trust.Snapshot;
      Ok    : out Boolean)
   is
   begin
      --  An unbuilt or empty snapshot is refused here rather than at Build, so
      --  the failure names the call that was wrong.
      Ok := SSL.Trust.Is_Built (Value.all) and then SSL.Trust.Anchor_Count (Value.all) > 0;
      if Ok then
         Item.Policy.Trust_Snapshot := Value;
      end if;
   end Set_Anchors;

   procedure Set_Client_Credential
     (Item  : in out Client_Builder;
      Value : not null access constant SSL.Credentials.Credential;
      Ok    : out Boolean)
   is
   begin
      Ok := SSL.Credentials.Is_Loaded (Value.all);
      if Ok then
         Item.Policy.Own_Credential := Credential_Reference (Value);
      end if;
   end Set_Client_Credential;

   procedure Set_Pinning
     (Item : in out Client_Builder;
      Mode : SSL.Trust.Pinning.Pinning_Mode;
      Pins : SSL.Trust.Pinning.Pin_Set;
      Ok   : out Boolean)
   is
   begin
      Ok := SSL.Trust.Pinning.Is_Valid_Policy (Mode, Pins);
      if Ok then
         Item.Policy.Pin_Mode := Mode;
         Item.Policy.Pin_Values := Pins;
      end if;
   end Set_Pinning;

   procedure Set_Resumption (Item : in out Client_Builder; Enabled : Boolean) is
   begin
      Item.Policy.Resumption := Enabled;
   end Set_Resumption;

   procedure Set_Security_Context
     (Item : in out Client_Builder; Value : Security_Context_ID)
   is
   begin
      Item.Policy.Common.Context := Value;
   end Set_Security_Context;

   procedure Set_Limits
     (Item : in out Client_Builder; Value : SSL.Limits.Resource_Limits; Ok : out Boolean)
   is
   begin
      Set_Common_Limits (Item.Policy.Common, Value, Ok);
   end Set_Limits;

   procedure Set_Record_Padding
     (Item : in out Client_Builder; Octets : Byte_Index; Ok : out Boolean)
   is
   begin
      Set_Common_Padding (Item.Policy.Common, Octets, Ok);
   end Set_Record_Padding;

   procedure Set_Close_Behaviour
     (Item              : in out Client_Builder;
      Send_Close_Notify : Boolean;
      Detect_Truncation : Boolean)
   is
   begin
      Item.Policy.Common.Send_Close := Send_Close_Notify;
      Item.Policy.Common.Detect_Truncation := Detect_Truncation;
   end Set_Close_Behaviour;

   ---------------------------------------------------------------------------
   --  Server setters
   ---------------------------------------------------------------------------

   procedure Set_Versions
     (Item : in out Server_Builder; Value : SSL.Versions.Version_Set; Ok : out Boolean)
   is
   begin
      Set_Common_Versions (Item.Policy.Common, Value, Ok);
   end Set_Versions;

   procedure Set_Cipher_Suites
     (Item : in out Server_Builder; Value : Suites_Registry.Suite_List; Ok : out Boolean)
   is
   begin
      Ok := not Suites_Registry.Is_Empty (Value);
      if Ok then
         Item.Policy.Common.Suites := Value;
      end if;
   end Set_Cipher_Suites;

   procedure Set_Groups
     (Item : in out Server_Builder; Value : Groups_Registry.Group_List; Ok : out Boolean)
   is
   begin
      --  Invariant CERT-8. A server cannot acquire finite-field groups here at
      --  all, however the list was assembled -- including a list copied from a
      --  client configuration, which is the realistic way it would happen.
      Ok := not Groups_Registry.Is_Empty (Value) and then not Holds_Finite_Field (Value);
      if Ok then
         Item.Policy.Common.Groups := Value;
      end if;
   end Set_Groups;

   procedure Accept_Finite_Field_Groups_With_Amplification_Risk
     (Item : in out Server_Builder; Ok : out Boolean)
   is
   begin
      Append_Finite_Field (Item.Policy.Common.Groups, Ok);
   end Accept_Finite_Field_Groups_With_Amplification_Risk;

   procedure Set_Signature_Schemes
     (Item : in out Server_Builder; Value : Schemes_Registry.Scheme_List; Ok : out Boolean)
   is
   begin
      Ok := not Schemes_Registry.Is_Empty (Value);
      if Ok then
         Item.Policy.Common.Schemes := Value;
      end if;
   end Set_Signature_Schemes;

   procedure Set_Application_Protocols
     (Item        : in out Server_Builder;
      Value       : SSL.ALPN.Protocol_List;
      Requirement : SSL.ALPN.ALPN_Requirement;
      Selection   : SSL.ALPN.Selection_Policy;
      Ok          : out Boolean)
   is
   begin
      Ok := SSL.ALPN.Is_Valid_Policy (Requirement, Value);
      if Ok then
         Item.Policy.Common.Protocols := Value;
         Item.Policy.Common.ALPN_Need := Requirement;
         Item.Policy.ALPN_Choice := Selection;
      end if;
   end Set_Application_Protocols;

   procedure Set_Preference (Item : in out Server_Builder; Value : Negotiation_Preference) is
   begin
      Item.Policy.Prefer := Value;
   end Set_Preference;

   procedure Set_Client_Authentication
     (Item  : in out Server_Builder;
      Value : SSL.Authentication.Client_Authentication_Policy)
   is
   begin
      Item.Policy.Client_Auth := Value;
   end Set_Client_Authentication;

   procedure Set_Ticket_Issuance (Item : in out Server_Builder; Enabled : Boolean) is
   begin
      Item.Policy.Issue_Tickets := Enabled;
   end Set_Ticket_Issuance;

   procedure Add_Credential
     (Item  : in out Server_Builder;
      Value : not null access constant SSL.Credentials.Credential;
      Ok    : out Boolean)
   is
   begin
      if not SSL.Credentials.Is_Loaded (Value.all)
        or else Item.Policy.Credential_Total = Maximum_Credentials
      then
         Ok := False;
         return;
      end if;
      Item.Policy.Credential_Total := Item.Policy.Credential_Total + 1;
      Item.Policy.Credential_List (Item.Policy.Credential_Total) :=
        Credential_Reference (Value);
      Ok := True;
   end Add_Credential;

   procedure Set_Anchors
     (Item  : in out Server_Builder;
      Value : not null access constant SSL.Trust.Snapshot;
      Ok    : out Boolean)
   is
   begin
      Ok := SSL.Trust.Is_Built (Value.all) and then SSL.Trust.Anchor_Count (Value.all) > 0;
      if Ok then
         Item.Policy.Trust_Snapshot := Value;
      end if;
   end Set_Anchors;

   procedure Set_Name_Policy (Item : in out Server_Builder; Value : Unrecognized_Name_Policy) is
   begin
      Item.Policy.Names := Value;
   end Set_Name_Policy;

   procedure Set_Security_Context
     (Item : in out Server_Builder; Value : Security_Context_ID)
   is
   begin
      Item.Policy.Common.Context := Value;
   end Set_Security_Context;

   procedure Set_Limits
     (Item : in out Server_Builder; Value : SSL.Limits.Resource_Limits; Ok : out Boolean)
   is
   begin
      Set_Common_Limits (Item.Policy.Common, Value, Ok);
   end Set_Limits;

   procedure Set_Record_Padding
     (Item : in out Server_Builder; Octets : Byte_Index; Ok : out Boolean)
   is
   begin
      Set_Common_Padding (Item.Policy.Common, Octets, Ok);
   end Set_Record_Padding;

   procedure Set_Close_Behaviour
     (Item              : in out Server_Builder;
      Send_Close_Notify : Boolean;
      Detect_Truncation : Boolean)
   is
   begin
      Item.Policy.Common.Send_Close := Send_Close_Notify;
      Item.Policy.Common.Detect_Truncation := Detect_Truncation;
   end Set_Close_Behaviour;

   ---------------------------------------------------------------------------
   --  Validation
   ---------------------------------------------------------------------------

   --  The rules both roles share. Every one of them is a configuration that
   --  would otherwise fail at the first handshake, or worse, only against one
   --  particular peer.
   function Validate_Common (Item : Common_Policy) return SSL.Errors.Error_Information;

   function Validate_Common (Item : Common_Policy) return SSL.Errors.Error_Information is
      use SSL.Errors;
   begin
      if SSL.Versions.Is_Empty (Item.Versions) then
         return Make (Code_No_Versions_Enabled, Local_Policy);
      end if;

      if Suites_Registry.Is_Empty (Item.Suites) then
         return Make (Code_No_Cipher_Suites_Enabled, Local_Policy);
      end if;

      if Groups_Registry.Is_Empty (Item.Groups) then
         return Make (Code_No_Groups_Enabled, Local_Policy);
      end if;

      if Schemes_Registry.Is_Empty (Item.Schemes) then
         return Make (Code_No_Signature_Schemes_Enabled, Local_Policy);
      end if;

      --  Every enabled version must have at least one suite and one signature
      --  scheme it can actually use. Enabling a version with nothing to
      --  negotiate is a configuration that advertises what it cannot do.
      for Version in SSL.Versions.Protocol_Version loop
         if SSL.Versions.Contains (Item.Versions, Version) then
            if not Suites_Registry.Supports (Item.Suites, Version) then
               return Make
                 (Code       => Code_Suite_Version_Mismatch,
                  Origin     => Local_Policy,
                  Parameters => [Text_Parameter ("version", SSL.Versions.Image (Version))]);
            end if;

            if not Schemes_Registry.Supports (Item.Schemes, Version) then
               return Make
                 (Code       => Code_Signature_Version_Mismatch,
                  Origin     => Local_Policy,
                  Parameters => [Text_Parameter ("version", SSL.Versions.Image (Version))]);
            end if;
         end if;
      end loop;

      --  Preference order must not put a TLS 1.2 suite ahead of a TLS 1.3 one.
      --
      --  Order is preference order in both roles, so a TLS 1.2 suite listed
      --  first lets a peer that speaks both be steered onto the older protocol.
      --  That is exactly the "must not weaken TLS 1.3" the specification states
      --  about modern-compatibility policy, and it is checkable rather than
      --  merely documented.
      if SSL.Versions.Contains (Item.Versions, SSL.Versions.TLS_1_2)
        and then SSL.Versions.Contains (Item.Versions, SSL.Versions.TLS_1_3)
      then
         declare
            Seen_Legacy : Boolean := False;
         begin
            for Index in 1 .. Suites_Registry.Length (Item.Suites) loop
               declare
                  Suite : constant Suites_Registry.Cipher_Suite :=
                    Suites_Registry.Element (Item.Suites, Index);
               begin
                  if Suites_Registry.Version_Of (Suite) = SSL.Versions.TLS_1_2 then
                     Seen_Legacy := True;
                  elsif Seen_Legacy then
                     return Make
                       (Code       => Code_Compatibility_Weakens_TLS13,
                        Origin     => Local_Policy,
                        Parameters =>
                          [Text_Parameter ("suite", Suites_Registry.Image (Suite)),
                           Numeric_Parameter ("position", Long_Long_Integer (Index))]);
                  end if;
               end;
            end loop;
         end;
      end if;

      if not SSL.ALPN.Is_Valid_Policy (Item.ALPN_Need, Item.Protocols) then
         return Make (Code_Invalid_ALPN_Policy, Local_Policy);
      end if;

      if not SSL.Limits.Is_Valid (Item.Bounds) then
         return Make
           (Code       => Code_Invalid_Limits,
            Origin     => Local_Policy,
            Parameters => [Text_Parameter ("reason", SSL.Limits.Invalidity (Item.Bounds))]);
      end if;

      return No_Error;
   end Validate_Common;

   ---------------------------------------------------------------------------
   --  Fingerprint
   ---------------------------------------------------------------------------

   --  A canonical encoding of the policy, hashed.
   --
   --  Two configurations that negotiate identically must produce the same
   --  octets here, and two that differ in anything a peer could observe must
   --  not. So everything that reaches the wire or decides an outcome is encoded,
   --  in a fixed order, with explicit lengths -- and nothing else is. The
   --  security context is included because a session must not cross contexts;
   --  the close and padding behaviour is included because it changes what the
   --  peer sees.
   function Encode_Common (Item : Common_Policy) return Byte_Array;

   function Encode_Common (Item : Common_Policy) return Byte_Array is
      Buffer  : Byte_Array (1 .. 16_384) := [others => 0];
      Emitter : SSL.Wire.Emitter := SSL.Wire.Writer (Buffer);
      Values  : SSL.Versions.Version_Value_Array;
      Last    : Natural;
   begin
      SSL.Versions.Ordered_Values (Item.Versions, Values, Last);
      SSL.Wire.Put_UInt8 (Buffer, Emitter, Last);
      for Index in 1 .. Last loop
         SSL.Wire.Put_UInt16 (Buffer, Emitter, Natural (Values (Index)));
      end loop;

      SSL.Wire.Put_UInt8 (Buffer, Emitter, Suites_Registry.Length (Item.Suites));
      for Index in 1 .. Suites_Registry.Length (Item.Suites) loop
         SSL.Wire.Put_UInt16
           (Buffer, Emitter,
            Natural (Suites_Registry.Value_Of (Suites_Registry.Element (Item.Suites, Index))));
      end loop;

      SSL.Wire.Put_UInt8 (Buffer, Emitter, Groups_Registry.Length (Item.Groups));
      for Index in 1 .. Groups_Registry.Length (Item.Groups) loop
         SSL.Wire.Put_UInt16
           (Buffer, Emitter,
            Natural (Groups_Registry.Value_Of (Groups_Registry.Element (Item.Groups, Index))));
      end loop;

      SSL.Wire.Put_UInt8 (Buffer, Emitter, Schemes_Registry.Length (Item.Schemes));
      for Index in 1 .. Schemes_Registry.Length (Item.Schemes) loop
         SSL.Wire.Put_UInt16
           (Buffer, Emitter,
            Natural (Schemes_Registry.Value_Of (Schemes_Registry.Element (Item.Schemes, Index))));
      end loop;

      SSL.Wire.Put_UInt8 (Buffer, Emitter, SSL.ALPN.Length (Item.Protocols));
      for Index in 1 .. SSL.ALPN.Length (Item.Protocols) loop
         declare
            Name : constant Byte_Array :=
              SSL.ALPN.Value_Of (SSL.ALPN.Element (Item.Protocols, Index));
         begin
            SSL.Wire.Put_UInt8 (Buffer, Emitter, Natural (Name'Length));
            SSL.Wire.Put_Bytes (Buffer, Emitter, Name);
         end;
      end loop;
      SSL.Wire.Put_UInt8 (Buffer, Emitter, SSL.ALPN.ALPN_Requirement'Pos (Item.ALPN_Need));

      --  The limits that a peer can observe through a refusal.
      SSL.Wire.Put_UInt32
        (Buffer, Emitter, Interfaces.Unsigned_32 (Item.Bounds.Maximum_Plaintext_Record));
      SSL.Wire.Put_UInt32
        (Buffer, Emitter, Interfaces.Unsigned_32 (Item.Bounds.Maximum_Handshake_Message));
      SSL.Wire.Put_UInt32
        (Buffer, Emitter, Interfaces.Unsigned_32 (Item.Bounds.Maximum_Certificate_Message));
      SSL.Wire.Put_UInt16 (Buffer, Emitter, Item.Bounds.Maximum_Certificate_Count);
      SSL.Wire.Put_UInt16 (Buffer, Emitter, Item.Bounds.Maximum_Path_Depth);

      SSL.Wire.Put_UInt24 (Buffer, Emitter, Item.Padding);
      SSL.Wire.Put_UInt8 (Buffer, Emitter, Boolean'Pos (Item.Send_Close));
      SSL.Wire.Put_UInt8 (Buffer, Emitter, Boolean'Pos (Item.Detect_Truncation));

      --  The application security context, so that two otherwise identical
      --  configurations serving different tenants fingerprint differently and
      --  their sessions cannot cross. Reached through SSL's private part, which
      --  a child may see.
      SSL.Wire.Put_UInt8 (Buffer, Emitter, Item.Context.Length);
      for Index in 1 .. Item.Context.Length loop
         SSL.Wire.Put_UInt8 (Buffer, Emitter, Character'Pos (Item.Context.Text (Index)));
      end loop;

      if not SSL.Wire.Is_Valid (Emitter) then
         --  Unreachable with the bounds above; if it ever happens, a
         --  distinguishable constant is safer than a truncated encoding that
         --  would make two different policies fingerprint alike.
         return [1 => 16#FF#];
      end if;

      return Buffer (1 .. SSL.Wire.Written (Emitter));
   end Encode_Common;

   --  The client-only policy, encoded after the common part. The expected
   --  identity is in here and the routing name is separate from it, so two
   --  configurations differing only in which name they authenticate produce
   --  different fingerprints -- which is what stops a session established
   --  against one name being resumed against another.
   function Encode_Client_Extra (Item : Client_Policy) return Byte_Array;

   function Encode_Client_Extra (Item : Client_Policy) return Byte_Array is
      Buffer  : Byte_Array (1 .. 2_048) := [others => 0];
      Emitter : SSL.Wire.Emitter := SSL.Wire.Writer (Buffer);
   begin
      SSL.Wire.Put_UInt8 (Buffer, Emitter, Groups_Registry.Length (Item.Key_Shares));
      for Index in 1 .. Groups_Registry.Length (Item.Key_Shares) loop
         SSL.Wire.Put_UInt16
           (Buffer, Emitter,
            Natural (Groups_Registry.Value_Of
                       (Groups_Registry.Element (Item.Key_Shares, Index))));
      end loop;

      SSL.Wire.Put_UInt8 (Buffer, Emitter, Schemes_Registry.Length (Item.Certificate_Schemes));
      for Index in 1 .. Schemes_Registry.Length (Item.Certificate_Schemes) loop
         SSL.Wire.Put_UInt16
           (Buffer, Emitter,
            Natural (Schemes_Registry.Value_Of
                       (Schemes_Registry.Element (Item.Certificate_Schemes, Index))));
      end loop;

      declare
         Name : constant Byte_Array := SSL.Server_Names.Octets (Item.Expected_Name);
      begin
         SSL.Wire.Put_UInt8 (Buffer, Emitter, Natural (Name'Length));
         SSL.Wire.Put_Bytes (Buffer, Emitter, Name);
      end;

      declare
         Address : constant Byte_Array := SSL.Server_Names.Octets (Item.Expected_Address);
      begin
         SSL.Wire.Put_UInt8 (Buffer, Emitter, Natural (Address'Length));
         SSL.Wire.Put_Bytes (Buffer, Emitter, Address);
      end;

      declare
         Routing : constant Byte_Array := SSL.Server_Names.Octets (Item.Indication);
      begin
         SSL.Wire.Put_UInt8 (Buffer, Emitter, Natural (Routing'Length));
         SSL.Wire.Put_Bytes (Buffer, Emitter, Routing);
      end;

      SSL.Wire.Put_UInt8 (Buffer, Emitter, Boolean'Pos (Item.Send_Indication));
      SSL.Wire.Put_UInt8 (Buffer, Emitter, Trust_Source'Pos (Item.Trust));
      SSL.Wire.Put_UInt8 (Buffer, Emitter, Boolean'Pos (Item.With_NSS));
      SSL.Wire.Put_UInt8 (Buffer, Emitter, Boolean'Pos (Item.With_Java));
      SSL.Wire.Put_UInt8 (Buffer, Emitter, Revocation_Policy'Pos (Item.Revocation));
      SSL.Wire.Put_UInt8 (Buffer, Emitter, Boolean'Pos (Item.Request_Stapling));
      SSL.Wire.Put_UInt8 (Buffer, Emitter, Boolean'Pos (Item.Resumption));

      if not SSL.Wire.Is_Valid (Emitter) then
         return [1 => 16#FF#];
      end if;
      return Buffer (1 .. SSL.Wire.Written (Emitter));
   end Encode_Client_Extra;

   --  The server-only policy. Whether client certificates are asked for is in
   --  here, so a configuration that starts requiring them fingerprints
   --  differently and old sessions do not resume into the stricter policy.
   function Encode_Server_Extra (Item : Server_Policy) return Byte_Array;

   function Encode_Server_Extra (Item : Server_Policy) return Byte_Array is
      Buffer  : Byte_Array (1 .. 64) := [others => 0];
      Emitter : SSL.Wire.Emitter := SSL.Wire.Writer (Buffer);
   begin
      SSL.Wire.Put_UInt8 (Buffer, Emitter, SSL.ALPN.Selection_Policy'Pos (Item.ALPN_Choice));
      SSL.Wire.Put_UInt8 (Buffer, Emitter, Negotiation_Preference'Pos (Item.Prefer));
      SSL.Wire.Put_UInt8
        (Buffer, Emitter,
         SSL.Authentication.Client_Authentication_Policy'Pos (Item.Client_Auth));
      SSL.Wire.Put_UInt8 (Buffer, Emitter, Boolean'Pos (Item.Issue_Tickets));
      SSL.Wire.Put_UInt8 (Buffer, Emitter, Unrecognized_Name_Policy'Pos (Item.Names));

      if not SSL.Wire.Is_Valid (Emitter) then
         return [1 => 16#FF#];
      end if;
      return Buffer (1 .. SSL.Wire.Written (Emitter));
   end Encode_Server_Extra;

   ---------------------------------------------------------------------------
   --  Build
   ---------------------------------------------------------------------------

   procedure Build
     (Item  : in out Client_Builder;
      Into  : out Client_Configuration;
      Error : out SSL.Errors.Error_Information)
   is
      use SSL.Errors;
   begin
      Into.Built := False;
      Error := Validate_Common (Item.Policy.Common);
      if Is_Error (Error) then
         return;
      end if;

      --  A client must say what it expects to authenticate. There is no mode in
      --  which it does not check, so there is no configuration in which this
      --  may be left out.
      if not SSL.Server_Names.Is_Present (Item.Policy.Expected_Name)
        and then not SSL.Server_Names.Is_Present (Item.Policy.Expected_Address)
      then
         Error := Make (Code_Identity_Not_Specified, Local_Policy);
         return;
      end if;

      --  RFC 8446 section 4.2.8: a key share may only be offered for a group
      --  that is also in supported_groups.
      if Groups_Registry.Is_Empty (Item.Policy.Key_Shares)
        or else not Groups_Registry.Is_Subset
                      (Item.Policy.Key_Shares, Item.Policy.Common.Groups)
      then
         Error := Make
           (Code       => Code_Key_Share_Not_Offered,
            Origin     => Local_Policy,
            Parameters =>
              [Text_Parameter ("key_shares", Groups_Registry.Image (Item.Policy.Key_Shares)),
               Text_Parameter ("groups", Groups_Registry.Image (Item.Policy.Common.Groups))]);
         return;
      end if;

      if Schemes_Registry.Is_Empty (Item.Policy.Certificate_Schemes) then
         Error := Make (Code_No_Signature_Schemes_Enabled, Local_Policy);
         return;
      end if;

      --  A client always verifies, so it always needs anchors. This is the rule
      --  that could not be checked until trust snapshots existed; the error code
      --  has been in the taxonomy since the beginning.
      if Item.Policy.Trust_Snapshot = null then
         Error := Make
           (Code       => Code_Trust_Required_But_Absent,
            Origin     => Local_Policy,
            Parameters => [Text_Parameter ("trust_source", Image (Item.Policy.Trust))]);
         return;
      end if;

      if not SSL.Trust.Is_Built (Item.Policy.Trust_Snapshot.all) then
         Error := Make (Code_System_Trust_Unavailable, Local_Policy);
         return;
      end if;

      if SSL.Trust.Anchor_Count (Item.Policy.Trust_Snapshot.all) = 0 then
         Error := Make (Code_Trust_Source_Empty, Local_Policy);
         return;
      end if;

      if Item.Policy.Own_Credential /= null
        and then not SSL.Credentials.Is_Loaded (Item.Policy.Own_Credential.all)
      then
         Error := Make (Code_Credential_Unusable, Local_Policy);
         return;
      end if;

      if not SSL.Trust.Pinning.Is_Valid_Policy
               (Item.Policy.Pin_Mode, Item.Policy.Pin_Values)
      then
         Error := Make (Code_Pin_Without_Identity, Local_Policy);
         return;
      end if;

      --  Demanding a stapled response while not requesting one can never
      --  succeed. The setter turns the request on, so reaching this means the
      --  caller switched it off afterwards.
      if Item.Policy.Revocation = Require_Stapled_OCSP
        and then not Item.Policy.Request_Stapling
      then
         Error := Make (Code_Revocation_Policy_Unsatisfiable, Local_Policy);
         return;
      end if;

      --  An address identity and a server_name are mutually exclusive
      --  (RFC 6066 section 3).
      if Item.Policy.Send_Indication
        and then SSL.Server_Names.Is_Present (Item.Policy.Expected_Address)
        and then not SSL.Server_Names.Is_Present (Item.Policy.Indication)
      then
         Error := Make (Code_Invalid_Server_Name, Local_Policy);
         return;
      end if;

      Into.Policy := Item.Policy;
      Into.Digest :=
        (Digest => SSL.Crypto.SHA_256
                     (Encode_Common (Item.Policy.Common)
                      & Encode_Client_Extra (Item.Policy)));
      Into.Built := True;
      Error := No_Error;
   end Build;

   procedure Build
     (Item  : in out Server_Builder;
      Into  : out Server_Configuration;
      Error : out SSL.Errors.Error_Information)
   is
      use SSL.Errors;
   begin
      Into.Built := False;
      Error := Validate_Common (Item.Policy.Common);
      if Is_Error (Error) then
         return;
      end if;

      --  A server with nothing to present cannot complete a handshake.
      if Item.Policy.Credential_Total = 0 then
         Error := Make (Code_No_Credential_Configured, Local_Policy);
         return;
      end if;

      for Index in 1 .. Item.Policy.Credential_Total loop
         if not SSL.Credentials.Is_Loaded (Item.Policy.Credential_List (Index).all) then
            Error := Make
              (Code       => Code_Credential_Unusable,
               Origin     => Local_Policy,
               Parameters => [Numeric_Parameter ("credential", Long_Long_Integer (Index))]);
            return;
         end if;
      end loop;

      --  Asking for a client certificate without anchors to validate it against
      --  would mean accepting whatever arrived. Refused rather than silently
      --  downgraded to "requested but never checked".
      if Item.Policy.Client_Auth /= SSL.Authentication.Not_Requested
        and then Item.Policy.Trust_Snapshot = null
      then
         Error := Make
           (Code       => Code_Trust_Required_But_Absent,
            Origin     => Local_Policy,
            Parameters =>
              [Text_Parameter ("client_authentication",
                               SSL.Authentication.Image (Item.Policy.Client_Auth))]);
         return;
      end if;

      --  "Tickets disabled until valid ticket keys are configured", enforced.
      --  A server issuing tickets under a key it does not have would be issuing
      --  tickets nobody -- itself included -- can ever decrypt.
      if Item.Policy.Issue_Tickets and then Item.Policy.Ticket_Ring = null then
         Error := Make (Code_Ticket_Issuance_Without_Key, Local_Policy);
         return;
      end if;

      Into.Policy := Item.Policy;
      Into.Digest :=
        (Digest => SSL.Crypto.SHA_256
                     (Encode_Common (Item.Policy.Common)
                      & Encode_Server_Extra (Item.Policy)));
      Into.Built := True;
      Error := No_Error;
   end Build;

   ---------------------------------------------------------------------------
   --  Readers
   ---------------------------------------------------------------------------

   function Is_Valid (Item : Client_Configuration) return Boolean is (Item.Built);
   function Is_Valid (Item : Server_Configuration) return Boolean is (Item.Built);

   function Fingerprint (Item : Client_Configuration) return Configuration_Fingerprint
   is (Item.Digest);
   function Fingerprint (Item : Server_Configuration) return Configuration_Fingerprint
   is (Item.Digest);

   function Versions (Item : Client_Configuration) return SSL.Versions.Version_Set
   is (Item.Policy.Common.Versions);
   function Cipher_Suites (Item : Client_Configuration) return Suites_Registry.Suite_List
   is (Item.Policy.Common.Suites);
   function Groups (Item : Client_Configuration) return Groups_Registry.Group_List
   is (Item.Policy.Common.Groups);
   function Key_Share_Groups (Item : Client_Configuration) return Groups_Registry.Group_List
   is (Item.Policy.Key_Shares);
   function Signature_Schemes (Item : Client_Configuration) return Schemes_Registry.Scheme_List
   is (Item.Policy.Common.Schemes);
   function Certificate_Signature_Schemes (Item : Client_Configuration)
     return Schemes_Registry.Scheme_List
   is (Item.Policy.Certificate_Schemes);
   function Application_Protocols (Item : Client_Configuration) return SSL.ALPN.Protocol_List
   is (Item.Policy.Common.Protocols);
   function ALPN_Requirement (Item : Client_Configuration) return SSL.ALPN.ALPN_Requirement
   is (Item.Policy.Common.ALPN_Need);
   function Bounds (Item : Client_Configuration) return SSL.Limits.Resource_Limits
   is (Item.Policy.Common.Bounds);
   function Expected_Name (Item : Client_Configuration) return SSL.Server_Names.DNS_Name
   is (Item.Policy.Expected_Name);
   function Expected_Address (Item : Client_Configuration) return SSL.Server_Names.IP_Address
   is (Item.Policy.Expected_Address);
   function Server_Name_Indication (Item : Client_Configuration) return SSL.Server_Names.DNS_Name
   is (if Item.Policy.Send_Indication
       then Item.Policy.Indication
       else SSL.Server_Names.No_Name);
   function Sends_Server_Name (Item : Client_Configuration) return Boolean
   is (Item.Policy.Send_Indication
       and then SSL.Server_Names.Is_Present (Item.Policy.Indication));
   function Trust_Source_Of (Item : Client_Configuration) return Trust_Source
   is (Item.Policy.Trust);
   function Uses_NSS_Trust (Item : Client_Configuration) return Boolean
   is (Item.Policy.With_NSS);
   function Uses_Java_Trust (Item : Client_Configuration) return Boolean
   is (Item.Policy.With_Java);
   function Revocation (Item : Client_Configuration) return Revocation_Policy
   is (Item.Policy.Revocation);
   function Requests_Stapled_Status (Item : Client_Configuration) return Boolean
   is (Item.Policy.Request_Stapling);
   function Resumption_Enabled (Item : Client_Configuration) return Boolean
   is (Item.Policy.Resumption);
   function Security_Context_Of (Item : Client_Configuration) return Security_Context_ID
   is (Item.Policy.Common.Context);
   function Sends_Close_Notify (Item : Client_Configuration) return Boolean
   is (Item.Policy.Common.Send_Close);
   function Detects_Truncation (Item : Client_Configuration) return Boolean
   is (Item.Policy.Common.Detect_Truncation);
   function Record_Padding (Item : Client_Configuration) return Byte_Index
   is (Item.Policy.Common.Padding);

   function Anchors (Item : Client_Configuration) return access constant SSL.Trust.Snapshot
   is (Item.Policy.Trust_Snapshot);
   function Has_Anchors (Item : Client_Configuration) return Boolean
   is (Item.Policy.Trust_Snapshot /= null);
   function Client_Credential (Item : Client_Configuration)
     return access constant SSL.Credentials.Credential
   is (Item.Policy.Own_Credential);
   function Has_Client_Credential (Item : Client_Configuration) return Boolean
   is (Item.Policy.Own_Credential /= null);
   function Pinning_Mode_Of (Item : Client_Configuration)
     return SSL.Trust.Pinning.Pinning_Mode
   is (Item.Policy.Pin_Mode);
   function Pins (Item : Client_Configuration) return SSL.Trust.Pinning.Pin_Set
   is (Item.Policy.Pin_Values);

   function Credential_Count (Item : Server_Configuration) return Natural
   is (Item.Policy.Credential_Total);
   function Credential_At (Item : Server_Configuration; Index : Positive)
     return access constant SSL.Credentials.Credential
   is (Item.Policy.Credential_List (Index));
   function Anchors (Item : Server_Configuration) return access constant SSL.Trust.Snapshot
   is (Item.Policy.Trust_Snapshot);
   function Has_Anchors (Item : Server_Configuration) return Boolean
   is (Item.Policy.Trust_Snapshot /= null);

   -------------------------
   -- Select_Credential --
   -------------------------

   function Select_Credential
     (Item    : Server_Configuration;
      Name    : SSL.Server_Names.DNS_Name;
      Offered : SSL.Signature_Schemes.Scheme_List;
      Version : SSL.Versions.Protocol_Version;
      Index   : out Natural) return Boolean
   is
      Best_Index : Natural := 0;
      Best_Score : Natural := 0;

      --  Can this credential produce something the peer will accept, under the
      --  version being negotiated? A credential whose only schemes are PKCS#1
      --  v1.5 is unusable in TLS 1.3 however well its name matches.
      function Usable (Candidate : Credential_Reference) return Boolean is
      begin
         for Position in 1 .. Schemes_Registry.Length (Offered) loop
            declare
               Scheme : constant Schemes_Registry.Signature_Scheme :=
                 Schemes_Registry.Element (Offered, Position);
            begin
               if Schemes_Registry.Usable_For_Handshake (Scheme, Version)
                 and then SSL.Credentials.Supports (Candidate.all, Scheme)
               then
                  return True;
               end if;
            end;
         end loop;
         return False;
      end Usable;

   begin
      Index := 0;

      for Position in 1 .. Item.Policy.Credential_Total loop
         declare
            Candidate : constant Credential_Reference :=
              Item.Policy.Credential_List (Position);
         begin
            if Usable (Candidate) then
               declare
                  --  Specificity first. With no name asked for, every usable
                  --  credential scores one, so the tie-break below picks the
                  --  first added -- which is what "default credential" means.
                  Score : constant Natural :=
                    (if SSL.Server_Names.Is_Present (Name)
                     then SSL.Credentials.Covers (Candidate.all, Name)
                     else 1);
               begin
                  --  Strictly greater, so insertion order breaks ties and
                  --  adding a credential never moves an existing name unless
                  --  the new one is genuinely more specific.
                  if Score > Best_Score then
                     Best_Score := Score;
                     Best_Index := Position;
                  end if;
               end;
            end if;
         end;
      end loop;

      if Best_Index = 0 then
         return False;
      end if;

      --  A name that matched nothing falls back only where policy says so.
      if SSL.Server_Names.Is_Present (Name)
        and then Best_Score = 0
        and then Item.Policy.Names = Reject_Unrecognized
      then
         return False;
      end if;

      Index := Best_Index;
      return True;
   end Select_Credential;

   function Versions (Item : Server_Configuration) return SSL.Versions.Version_Set
   is (Item.Policy.Common.Versions);
   function Cipher_Suites (Item : Server_Configuration) return Suites_Registry.Suite_List
   is (Item.Policy.Common.Suites);
   function Groups (Item : Server_Configuration) return Groups_Registry.Group_List
   is (Item.Policy.Common.Groups);
   function Signature_Schemes (Item : Server_Configuration) return Schemes_Registry.Scheme_List
   is (Item.Policy.Common.Schemes);
   function Application_Protocols (Item : Server_Configuration) return SSL.ALPN.Protocol_List
   is (Item.Policy.Common.Protocols);
   function ALPN_Requirement (Item : Server_Configuration) return SSL.ALPN.ALPN_Requirement
   is (Item.Policy.Common.ALPN_Need);
   function ALPN_Selection (Item : Server_Configuration) return SSL.ALPN.Selection_Policy
   is (Item.Policy.ALPN_Choice);
   function Bounds (Item : Server_Configuration) return SSL.Limits.Resource_Limits
   is (Item.Policy.Common.Bounds);
   function Preference (Item : Server_Configuration) return Negotiation_Preference
   is (Item.Policy.Prefer);
   function Client_Authentication (Item : Server_Configuration)
     return SSL.Authentication.Client_Authentication_Policy
   is (Item.Policy.Client_Auth);
   function Issues_Tickets (Item : Server_Configuration) return Boolean
   is (Item.Policy.Issue_Tickets);
   function Name_Policy (Item : Server_Configuration) return Unrecognized_Name_Policy
   is (Item.Policy.Names);
   function Security_Context_Of (Item : Server_Configuration) return Security_Context_ID
   is (Item.Policy.Common.Context);
   function Sends_Close_Notify (Item : Server_Configuration) return Boolean
   is (Item.Policy.Common.Send_Close);
   function Detects_Truncation (Item : Server_Configuration) return Boolean
   is (Item.Policy.Common.Detect_Truncation);
   function Record_Padding (Item : Server_Configuration) return Byte_Index
   is (Item.Policy.Common.Padding);

   ---------------------------------------------------------------------------
   --  Diagnostics and key logging
   ---------------------------------------------------------------------------

   procedure Set_Diagnostics
     (Item      : in out Client_Builder;
      Value     : not null SSL.Diagnostics.Sink_Reference;
      Level     : SSL.Diagnostics.Detail_Level;
      Redaction : SSL.Diagnostics.Redaction_Level := SSL.Diagnostics.Operational)
   is
   begin
      Item.Policy.Common.Diagnostic_Sink := Value;
      Item.Policy.Common.Diagnostic_Level := Level;
      Item.Policy.Common.Diagnostic_Redaction := Redaction;
   end Set_Diagnostics;

   procedure Set_Diagnostics
     (Item      : in out Server_Builder;
      Value     : not null SSL.Diagnostics.Sink_Reference;
      Level     : SSL.Diagnostics.Detail_Level;
      Redaction : SSL.Diagnostics.Redaction_Level := SSL.Diagnostics.Operational)
   is
   begin
      Item.Policy.Common.Diagnostic_Sink := Value;
      Item.Policy.Common.Diagnostic_Level := Level;
      Item.Policy.Common.Diagnostic_Redaction := Redaction;
   end Set_Diagnostics;

   procedure Set_Unsafe_Key_Logging
     (Item  : in out Client_Builder;
      Value : not null SSL.Unsafe.Key_Logging.Sink_Reference)
   is
   begin
      Item.Policy.Common.Key_Log_Sink := Value;
   end Set_Unsafe_Key_Logging;

   procedure Set_Unsafe_Key_Logging
     (Item  : in out Server_Builder;
      Value : not null SSL.Unsafe.Key_Logging.Sink_Reference)
   is
   begin
      Item.Policy.Common.Key_Log_Sink := Value;
   end Set_Unsafe_Key_Logging;

   function Diagnostic_Sink (Item : Client_Configuration)
     return SSL.Diagnostics.Sink_Reference
   is (Item.Policy.Common.Diagnostic_Sink);
   function Diagnostic_Level (Item : Client_Configuration)
     return SSL.Diagnostics.Detail_Level
   is (Item.Policy.Common.Diagnostic_Level);
   function Diagnostic_Redaction (Item : Client_Configuration)
     return SSL.Diagnostics.Redaction_Level
   is (Item.Policy.Common.Diagnostic_Redaction);
   function Key_Log_Sink (Item : Client_Configuration)
     return SSL.Unsafe.Key_Logging.Sink_Reference
   is (Item.Policy.Common.Key_Log_Sink);

   function Diagnostic_Sink (Item : Server_Configuration)
     return SSL.Diagnostics.Sink_Reference
   is (Item.Policy.Common.Diagnostic_Sink);
   function Diagnostic_Level (Item : Server_Configuration)
     return SSL.Diagnostics.Detail_Level
   is (Item.Policy.Common.Diagnostic_Level);
   function Diagnostic_Redaction (Item : Server_Configuration)
     return SSL.Diagnostics.Redaction_Level
   is (Item.Policy.Common.Diagnostic_Redaction);
   function Key_Log_Sink (Item : Server_Configuration)
     return SSL.Unsafe.Key_Logging.Sink_Reference
   is (Item.Policy.Common.Key_Log_Sink);

   ---------------------------------------------------------------------------
   --  Sessions and tickets
   ---------------------------------------------------------------------------

   procedure Set_Ticket_Keys
     (Item  : in out Server_Builder;
      Value : not null access constant SSL.Ticket_Keys.Ring)
   is
   begin
      Item.Policy.Ticket_Ring := Value;
   end Set_Ticket_Keys;

   procedure Set_Session_Cache
     (Item  : in out Client_Builder;
      Value : not null SSL.Sessions.Client_Caches.Cache_Reference)
   is
   begin
      Item.Policy.Session_Cache := Value;
   end Set_Session_Cache;

   function Ticket_Keys_Of (Item : Server_Configuration)
     return access constant SSL.Ticket_Keys.Ring
   is (Item.Policy.Ticket_Ring);

   function Session_Cache_Of (Item : Client_Configuration)
     return SSL.Sessions.Client_Caches.Cache_Reference
   is (Item.Policy.Session_Cache);

end SSL.Configurations;
