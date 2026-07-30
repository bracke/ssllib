package body SSL.Errors is

   use SSL.Alerts;

   ---------------------------------------------------------------------------
   --  The central classification table
   --
   --  One code, one answer: which family it belongs to, whether it ends the
   --  connection, which alert (if any) the peer is told, whether retrying
   --  could help, and how much of it may be shown.
   --
   --  This is the only place an alert is chosen. A failure site names a code
   --  and nothing else, so the set of alerts a peer can distinguish is a
   --  property of this table -- readable, reviewable, and changeable in one
   --  place -- rather than an emergent property of a hundred call sites. That
   --  is what keeps the alert surface from becoming an oracle.
   ---------------------------------------------------------------------------

   type Classification is record
      Category   : Error_Category;
      Fatal      : Boolean;
      Has_Alert  : Boolean;
      Alert_Kind : Alert_Description;
      Retry      : Retry_Class;
      Disclosure : Disclosure_Class;
   end record;

   function Classify (Code : Error_Code) return Classification;

   --  Shorthands, so the table below reads as a table.
   function Fatal_With
     (Category   : Error_Category;
      Alert_Kind : Alert_Description;
      Retry      : Retry_Class := Retry_New_Connection;
      Disclosure : Disclosure_Class := Operator_Only) return Classification
   is (Category, True, True, Alert_Kind, Retry, Disclosure);

   function Fatal_Silent
     (Category   : Error_Category;
      Retry      : Retry_Class := Retry_New_Connection;
      Disclosure : Disclosure_Class := Operator_Only) return Classification
   is (Category, True, False, Unknown_Alert, Retry, Disclosure);

   function Soft
     (Category   : Error_Category;
      Retry      : Retry_Class := Retry_Same_Connection;
      Disclosure : Disclosure_Class := Operator_Only) return Classification
   is (Category, False, False, Unknown_Alert, Retry, Disclosure);

   --------------
   -- Classify --
   --------------

   function Classify (Code : Error_Code) return Classification is
   begin
      case Code is

         when Code_None =>
            return (No_Failure, False, False, Unknown_Alert, Not_Retryable, Safe_For_Peer);

         ---------------------------------------------------------------------
         --  Configuration. Detected before any byte moves, so there is no
         --  peer to alert and retrying without changing the setup is futile.
         ---------------------------------------------------------------------

         when Code_No_Versions_Enabled
            | Code_No_Cipher_Suites_Enabled
            | Code_No_Groups_Enabled
            | Code_No_Signature_Schemes_Enabled
            | Code_Suite_Version_Mismatch
            | Code_Signature_Version_Mismatch
            | Code_Key_Share_Not_Offered
            | Code_No_Credential_Configured
            | Code_Credential_Unusable
            | Code_Trust_Required_But_Absent
            | Code_System_Trust_Unavailable
            | Code_Trust_Source_Empty
            | Code_Invalid_ALPN_Policy
            | Code_Invalid_Limits
            | Code_Ticket_Issuance_Without_Key
            | Code_Invalid_Server_Name
            | Code_Duplicate_ALPN_Protocol
            | Code_Client_Auth_Without_Credential
            | Code_Pin_Without_Identity
            | Code_Configuration_Not_Validated
            | Code_Revocation_Policy_Unsatisfiable
            | Code_Duplicate_Credential_Identity
            | Code_Legacy_Version_Requested
            | Code_Compatibility_Weakens_TLS13 =>
            return Fatal_Silent (Configuration, Retry_After_Reconfiguration);

         ---------------------------------------------------------------------
         --  Transport. The caller's transport, so the caller already knows
         --  more than this library does; no alert can be sent over a
         --  transport that has failed.
         ---------------------------------------------------------------------

         when Code_Transport_Failed =>
            return Fatal_Silent (Transport, Retry_New_Connection);

         when Code_Transport_Closed_Early
            | Code_Transport_Truncated =>
            --  Truncation is a security event, not a clean close: the peer's
            --  close_notify never arrived, so the stream may have been cut by
            --  someone other than the peer.
            return Fatal_Silent (Transport, Retry_New_Connection);

         when Code_Transport_Interrupted =>
            return Soft (Transport, Retry_Same_Connection);

         when Code_Transport_Not_Set =>
            return Fatal_Silent (Configuration, Retry_After_Reconfiguration);

         ---------------------------------------------------------------------
         --  Record layer. Restricted disclosure throughout: the difference
         --  between a padding failure and a tag failure is exactly the
         --  distinction an attacker wants, so both map to bad_record_mac and
         --  neither is described further to the peer.
         ---------------------------------------------------------------------

         when Code_Record_Header_Malformed =>
            return Fatal_With (Record_Layer, Decode_Error, Retry_New_Connection, Restricted);

         when Code_Record_Length_Excessive
            | Code_Record_Size_Limit_Exceeded =>
            return Fatal_With (Record_Layer, Record_Overflow, Retry_New_Connection, Restricted);

         when Code_Record_Authentication_Failed
            | Code_Record_Padding_Malformed
            | Code_Record_Inner_Type_Invalid =>
            return Fatal_With (Record_Layer, Bad_Record_MAC, Retry_New_Connection, Restricted);

         when Code_Record_Version_Rejected =>
            return Fatal_With (Record_Layer, Protocol_Version, Retry_New_Connection, Restricted);

         when Code_Record_Type_Forbidden
            | Code_Record_Compression_Rejected
            | Code_Record_Plaintext_After_Epoch =>
            return Fatal_With (Record_Layer, Unexpected_Message, Retry_New_Connection, Restricted);

         when Code_Record_Empty_Run_Excessive =>
            return Fatal_With (Record_Layer, Unexpected_Message, Retry_New_Connection, Operator_Only);

         when Code_Record_Sequence_Exhausted =>
            --  Local: this endpoint refuses to reuse a nonce. Not the peer's
            --  fault and nothing the peer can fix.
            return Fatal_With (Record_Layer, Internal_Error, Retry_New_Connection, Operator_Only);

         when Code_Record_Unexpected_CCS
            | Code_Change_Cipher_Spec_Malformed =>
            return Fatal_With (Record_Layer, Unexpected_Message, Retry_New_Connection, Operator_Only);

         ---------------------------------------------------------------------
         --  Protocol and state machine.
         ---------------------------------------------------------------------

         when Code_Unexpected_Handshake_Message
            | Code_Certificate_Verify_Unexpected
            | Code_Post_Handshake_Auth_Requested
            | Code_Early_Data_Offered
            | Code_External_PSK_Offered =>
            return Fatal_With (Protocol, Unexpected_Message);

         when Code_Handshake_Message_Malformed
            | Code_Extension_Malformed
            | Code_Legacy_Session_Id_Mismatch =>
            return Fatal_With (Protocol, Decode_Error);

         when Code_Duplicate_Extension
            | Code_Extension_In_Wrong_Context
            | Code_Legacy_Compression_Offered
            | Code_Hello_Retry_Invariant_Broken
            | Code_Key_Exchange_Value_Invalid
            | Code_PSK_Not_Last_Extension
            | Code_Selected_Identity_Out_Of_Range
            | Code_Hello_Retry_Group_Already_Offered
            | Code_Second_Hello_Retry_Request =>
            return Fatal_With (Protocol, Illegal_Parameter);

         when Code_Unsolicited_Extension =>
            return Fatal_With (Protocol, Unsupported_Extension);

         when Code_Missing_Required_Extension
            | Code_Extended_Master_Secret_Missing =>
            return Fatal_With (Protocol, Missing_Extension);

         when Code_Finished_Verification_Failed
            | Code_Certificate_Verify_Failed
            | Code_Binder_Verification_Failed =>
            --  Restricted: a verification failure must not be described in a
            --  way that says which step of the check failed.
            return Fatal_With (Protocol, Decrypt_Error, Retry_New_Connection, Restricted);

         when Code_Renegotiation_Attempted =>
            return Fatal_With (Protocol, Unexpected_Message);

         when Code_Downgrade_Sentinel_Detected =>
            return Fatal_With (Protocol, Illegal_Parameter);

         when Code_Key_Update_Flood =>
            return Fatal_With (Protocol, Unexpected_Message);

         when Code_Peer_Alert_Received =>
            --  The peer already knows; sending an alert back would be a loop.
            return Fatal_Silent (Protocol, Retry_New_Connection);

         when Code_Empty_Certificate_Not_Permitted =>
            return Fatal_With (Protocol, Certificate_Required);

         when Code_PSK_Mode_Unacceptable =>
            return Fatal_With (Protocol, Illegal_Parameter);

         when Code_Transcript_Unavailable
            | Code_Handshake_Not_Complete
            | Code_Connection_Not_Reusable
            | Code_Write_After_Close_Notify
            | Code_Read_After_Peer_Close =>
            --  Caller-sequencing failures. Nothing goes on the wire and the
            --  connection is not damaged by the attempt.
            return Soft (Protocol, Not_Retryable);

         ---------------------------------------------------------------------
         --  Negotiation. Safe for the peer: the peer chose the offer that did
         --  not overlap, and telling it so is the point of the alert.
         ---------------------------------------------------------------------

         when Code_No_Common_Version
            | Code_Selected_Version_Not_Offered =>
            return Fatal_With (Negotiation, Protocol_Version, Retry_After_Reconfiguration, Safe_For_Peer);

         when Code_No_Common_Cipher_Suite
            | Code_No_Common_Group
            | Code_No_Common_Signature_Scheme =>
            return Fatal_With (Negotiation, Handshake_Failure, Retry_After_Reconfiguration, Safe_For_Peer);

         when Code_No_Application_Protocol_Overlap =>
            return Fatal_With (Negotiation, No_Application_Protocol, Retry_After_Reconfiguration, Safe_For_Peer);

         when Code_Server_Name_Unrecognized =>
            return Fatal_With (Negotiation, Unrecognized_Name, Retry_After_Reconfiguration, Safe_For_Peer);

         when Code_Selected_Suite_Not_Offered
            | Code_Selected_Group_Not_Offered
            | Code_Application_Protocol_Changed =>
            return Fatal_With (Negotiation, Illegal_Parameter);

         ---------------------------------------------------------------------
         --  Cryptographic.
         ---------------------------------------------------------------------

         when Code_Random_Source_Failed
            | Code_Key_Derivation_Failed
            | Code_AEAD_Operation_Failed =>
            return Fatal_With (Cryptographic, Internal_Error, Retry_New_Connection, Operator_Only);

         when Code_Key_Agreement_Failed =>
            return Fatal_With (Cryptographic, Illegal_Parameter, Retry_New_Connection, Restricted);

         when Code_Signature_Generation_Failed =>
            return Fatal_With (Cryptographic, Internal_Error, Retry_New_Connection, Operator_Only);

         when Code_Signature_Verification_Failed =>
            return Fatal_With (Cryptographic, Decrypt_Error, Retry_New_Connection, Restricted);

         when Code_Algorithm_Not_Supported =>
            return Fatal_With (Cryptographic, Handshake_Failure, Retry_After_Reconfiguration, Safe_For_Peer);

         when Code_Weak_Algorithm_Rejected =>
            return Fatal_With (Cryptographic, Insufficient_Security, Retry_After_Reconfiguration, Safe_For_Peer);

         when Code_Key_Algorithm_Mismatch =>
            return Fatal_With (Cryptographic, Illegal_Parameter);

         ---------------------------------------------------------------------
         --  Certificate. The alert set here is the one RFC 8446 section 6.2
         --  defines, and it is deliberately coarse.
         ---------------------------------------------------------------------

         when Code_Certificate_List_Empty =>
            return Fatal_With (Certificate, Decode_Error);

         when Code_Certificate_Malformed =>
            return Fatal_With (Certificate, Bad_Certificate);

         when Code_Certificate_Path_Not_Built
            | Code_Certificate_Untrusted_Anchor
            | Code_Certificate_Self_Signed_Peer =>
            return Fatal_With (Certificate, Unknown_CA);

         when Code_Certificate_Path_Invalid =>
            return Fatal_With (Certificate, Bad_Certificate);

         when Code_Certificate_Expired =>
            return Fatal_With (Certificate, Certificate_Expired);

         when Code_Certificate_Not_Yet_Valid =>
            return Fatal_With (Certificate, Certificate_Expired);

         when Code_Certificate_Purpose_Rejected
            | Code_Certificate_Key_Usage_Rejected =>
            return Fatal_With (Certificate, Unsupported_Certificate);

         when Code_Certificate_Weak_Key =>
            return Fatal_With (Certificate, Insufficient_Security);

         when Code_Certificate_Required_By_Peer =>
            --  The peer asked for a client certificate this endpoint has not
            --  got. Local configuration problem, no alert to send.
            return Fatal_Silent (Configuration, Retry_After_Reconfiguration);

         when Code_Certificate_Not_Provided =>
            return Fatal_With (Certificate, Certificate_Required);

         ---------------------------------------------------------------------
         --  Identity. A valid chain for the wrong name. Never softened, and
         --  never bypassed by pinning.
         ---------------------------------------------------------------------

         when Code_Identity_No_Match
            | Code_Identity_No_Names_Present =>
            return Fatal_With (Identity, Bad_Certificate, Not_Retryable, Operator_Only);

         when Code_Identity_Reference_Malformed
            | Code_Identity_Not_Specified =>
            return Fatal_Silent (Configuration, Retry_After_Reconfiguration);

         ---------------------------------------------------------------------
         --  Revocation.
         ---------------------------------------------------------------------

         when Code_Certificate_Revoked =>
            return Fatal_With (Revocation, Certificate_Revoked, Not_Retryable, Operator_Only);

         when Code_Revocation_Status_Unknown
            | Code_Revocation_Status_Stale
            | Code_Revocation_Status_Absent =>
            return Fatal_With (Revocation, Bad_Certificate_Status_Response);

         when Code_Stapled_Status_Malformed
            | Code_Stapled_Status_Required
            | Code_Stapled_Status_Wrong_Certificate =>
            return Fatal_With (Revocation, Bad_Certificate_Status_Response);

         ---------------------------------------------------------------------
         --  Pinning. A pin is a local decision; the peer is told only that its
         --  certificate was not accepted.
         ---------------------------------------------------------------------

         when Code_Pin_Not_Met
            | Code_Pin_Expired
            | Code_Pin_Scope_Mismatch =>
            return Fatal_With (Pinning, Bad_Certificate, Not_Retryable, Operator_Only);

         ---------------------------------------------------------------------
         --  Session. Almost all of these are soft: a ticket that cannot be
         --  used means a full handshake, not a failure. Only a binder that
         --  does not verify is fatal, and that is a protocol failure recorded
         --  under Code_Binder_Verification_Failed.
         ---------------------------------------------------------------------

         when Code_Ticket_Malformed
            | Code_Ticket_Unknown_Key
            | Code_Ticket_Expired
            | Code_Ticket_Authentication_Failed
            | Code_Ticket_Binding_Mismatch
            | Code_Ticket_Version_Unsupported
            | Code_Session_Not_Resumable
            | Code_Session_Cache_Failed
            | Code_Session_Security_Context_Mismatch
            | Code_Session_Not_Extended_Master_Secret =>
            --  Restricted disclosure: which of these a ticket failed on is a
            --  ticket-forgery oracle if it ever reaches the peer. None of them
            --  produces an alert, and the peer sees only a full handshake.
            return Soft (Session, Retry_Same_Connection, Restricted);

         when Code_Ticket_Key_Not_Active =>
            return Soft (Session, Retry_After_Reconfiguration);

         when Code_Session_Persistence_Key_Absent =>
            return Fatal_Silent (Configuration, Retry_After_Reconfiguration);

         ---------------------------------------------------------------------
         --  Resource.
         ---------------------------------------------------------------------

         when Code_Limit_Exceeded =>
            return Fatal_With (Resource, Record_Overflow, Retry_New_Connection, Operator_Only);

         when Code_Output_Queue_Full
            | Code_Input_Buffer_Full
            | Code_Plaintext_Queue_Full =>
            --  Backpressure, not failure: the caller drains and calls again.
            return Soft (Resource, Retry_Same_Connection);

         when Code_Storage_Exhausted =>
            return Fatal_With (Resource, Internal_Error, Retry_New_Connection, Operator_Only);

         ---------------------------------------------------------------------
         --  Deadline and cancellation. Neither damages the connection by
         --  itself; the caller decides whether to continue or to shut down.
         ---------------------------------------------------------------------

         when Code_Deadline_Reached =>
            return Soft (Deadline, Retry_Same_Connection, Safe_For_Peer);

         when Code_Cancelled =>
            return Soft (Cancellation, Not_Retryable, Safe_For_Peer);

         ---------------------------------------------------------------------
         --  Application and provider.
         ---------------------------------------------------------------------

         when Code_Application_Refused =>
            return Fatal_With (Application_Policy, Access_Denied, Not_Retryable, Operator_Only);

         when Code_Application_Callback_Raised =>
            return Fatal_With (Application_Policy, Internal_Error, Not_Retryable, Operator_Only);

         when Code_Provider_Refused
            | Code_Provider_Unavailable =>
            return Fatal_With (Provider, Internal_Error, Retry_New_Connection, Operator_Only);

         when Code_Provider_Callback_Raised =>
            return Fatal_With (Provider, Internal_Error, Not_Retryable, Operator_Only);

         when Code_Signer_Capability_Missing =>
            return Fatal_Silent (Configuration, Retry_After_Reconfiguration);

         ---------------------------------------------------------------------
         --  Internal.
         ---------------------------------------------------------------------

         when Code_Internal_Invariant_Violated
            | Code_Internal_Not_Reachable =>
            return Fatal_With (Internal, Internal_Error, Not_Retryable, Operator_Only);

         when others =>
            --  An unclassified code is itself an internal failure: the table
            --  and the code list have drifted apart.
            return Fatal_With (Internal, Internal_Error, Not_Retryable, Operator_Only);
      end case;
   end Classify;

   ---------------------------------------------------------------------------
   --  Parameters
   ---------------------------------------------------------------------------

   -------------------
   -- No_Parameters --
   -------------------

   function No_Parameters return Parameter_List is
   begin
      return [];
   end No_Parameters;

   ------------------------
   -- Numeric_Parameter --
   ------------------------

   function Numeric_Parameter (Name : String; Value : Long_Long_Integer) return Parameter is
      Result : Parameter;
      Length : constant Natural := Natural'Min (Name'Length, Parameter_Name_Limit);
   begin
      Result.Kind := Numeric;
      Result.Number := Value;
      Result.Name_Length := Length;
      if Length > 0 then
         Result.Name (1 .. Length) := Name (Name'First .. Name'First + Length - 1);
      end if;
      return Result;
   end Numeric_Parameter;

   --------------------
   -- Text_Parameter --
   --------------------

   function Text_Parameter (Name : String; Value : String) return Parameter is
      Result       : Parameter;
      Name_Length  : constant Natural := Natural'Min (Name'Length, Parameter_Name_Limit);
      Value_Length : constant Natural := Natural'Min (Value'Length, Parameter_Text_Limit);
   begin
      Result.Kind := Text;
      Result.Name_Length := Name_Length;
      if Name_Length > 0 then
         Result.Name (1 .. Name_Length) := Name (Name'First .. Name'First + Name_Length - 1);
      end if;
      Result.Text_Length := Value_Length;
      if Value_Length > 0 then
         Result.Text (1 .. Value_Length) := Value (Value'First .. Value'First + Value_Length - 1);
      end if;
      return Result;
   end Text_Parameter;

   -------------
   -- Name_Of --
   -------------

   function Name_Of (Item : Parameter) return String is
   begin
      return Item.Name (1 .. Item.Name_Length);
   end Name_Of;

   -------------
   -- Kind_Of --
   -------------

   function Kind_Of (Item : Parameter) return Parameter_Kind is
   begin
      return Item.Kind;
   end Kind_Of;

   ---------------
   -- Number_Of --
   ---------------

   function Number_Of (Item : Parameter) return Long_Long_Integer is
   begin
      return Item.Number;
   end Number_Of;

   -------------
   -- Text_Of --
   -------------

   function Text_Of (Item : Parameter) return String is
   begin
      return Item.Text (1 .. Item.Text_Length);
   end Text_Of;

   ---------------------------------------------------------------------------
   --  Error values
   ---------------------------------------------------------------------------

   --------------
   -- No_Error --
   --------------

   function No_Error return Error_Information is
   begin
      return (others => <>);
   end No_Error;

   --------------
   -- Is_Error --
   --------------

   function Is_Error (Item : Error_Information) return Boolean is
   begin
      return Item.Code /= Code_None;
   end Is_Error;

   --------------
   -- Is_Fatal --
   --------------

   function Is_Fatal (Item : Error_Information) return Boolean is
   begin
      return Item.Fatal;
   end Is_Fatal;

   -----------------
   -- Category_Of --
   -----------------

   function Category_Of (Item : Error_Information) return Error_Category is
   begin
      return Item.Category;
   end Category_Of;

   -------------
   -- Code_Of --
   -------------

   function Code_Of (Item : Error_Information) return Error_Code is
   begin
      return Item.Code;
   end Code_Of;

   ---------------
   -- Origin_Of --
   ---------------

   function Origin_Of (Item : Error_Information) return Error_Origin is
   begin
      return Item.Origin;
   end Origin_Of;

   --------------
   -- Retry_Of --
   --------------

   function Retry_Of (Item : Error_Information) return Retry_Class is
   begin
      return Item.Retry;
   end Retry_Of;

   -------------------
   -- Disclosure_Of --
   -------------------

   function Disclosure_Of (Item : Error_Information) return Disclosure_Class is
   begin
      return Item.Disclosure;
   end Disclosure_Of;

   --------------
   -- Stage_Of --
   --------------

   function Stage_Of (Item : Error_Information) return Lifecycle_Stage is
   begin
      return Item.Stage;
   end Stage_Of;

   --------------
   -- Alert_Of --
   --------------

   function Alert_Of (Item : Error_Information) return SSL.Alerts.Alert is
   begin
      return Item.Alert;
   end Alert_Of;

   -------------------
   -- Connection_Of --
   -------------------

   function Connection_Of (Item : Error_Information) return Connection_ID is
   begin
      return Item.Connection;
   end Connection_Of;

   -------------------------
   -- Parameter_Count_Of --
   -------------------------

   function Parameter_Count_Of (Item : Error_Information) return Parameter_Count is
   begin
      return Item.Count;
   end Parameter_Count_Of;

   ------------------
   -- Parameter_At --
   ------------------

   function Parameter_At (Item : Error_Information; Index : Parameter_Index) return Parameter is
   begin
      return Item.Parameters (Index);
   end Parameter_At;

   -------------------
   -- Provider_Text --
   -------------------

   function Provider_Text (Item : Error_Information) return String is
   begin
      return Item.Provider (1 .. Item.Provider_Length);
   end Provider_Text;

   ----------
   -- Make --
   ----------

   function Make
     (Code       : Error_Code;
      Origin     : Error_Origin;
      Stage      : Lifecycle_Stage := Stage_Uninitialized;
      Connection : Connection_ID := No_Connection;
      Parameters : Parameter_List := No_Parameters;
      Provider   : String := "") return Error_Information
   is
      Facts  : constant Classification := Classify (Code);
      Result : Error_Information;
      Kept   : constant Parameter_Count :=
        Parameter_Count (Natural'Min (Parameters'Length, Maximum_Parameters));
      Length : constant Natural := Natural'Min (Provider'Length, Provider_Text_Limit);
   begin
      Result.Category := Facts.Category;
      Result.Code := Code;
      Result.Origin := Origin;
      Result.Fatal := Facts.Fatal;
      Result.Alert :=
        (if Facts.Has_Alert then SSL.Alerts.Local_Alert (Facts.Alert_Kind) else SSL.Alerts.No_Alert);
      Result.Retry := Facts.Retry;
      Result.Disclosure := Facts.Disclosure;
      Result.Stage := Stage;
      Result.Connection := Connection;
      Result.Count := Kept;

      for Index in 1 .. Kept loop
         Result.Parameters (Index) := Parameters (Parameters'First + Index - 1);
      end loop;

      Result.Provider_Length := Length;
      if Length > 0 then
         Result.Provider (1 .. Length) := Provider (Provider'First .. Provider'First + Length - 1);
      end if;

      return Result;
   end Make;

   --------------------------
   -- Application_Refusal --
   --------------------------

   function Application_Refusal (Reason : String) return Error_Information is
   begin
      return Make (Code       => Code_Application_Refused,
                   Origin     => Application_Callback,
                   Provider   => Reason);
   end Application_Refusal;

   ----------------------
   -- Provider_Failure --
   ----------------------

   function Provider_Failure (Reason : String; Fatal : Boolean := True) return Error_Information is
      Result : Error_Information :=
        Make (Code     => Code_Provider_Refused,
              Origin   => External_Provider,
              Provider => Reason);
   begin
      --  The table says a provider refusal is fatal, which is the safe
      --  default; a provider that knows better may say so, and only in the
      --  non-fatal direction. A caller cannot make a non-fatal code fatal.
      if not Fatal then
         Result.Fatal := False;
         Result.Alert := SSL.Alerts.No_Alert;
         Result.Retry := Retry_Same_Connection;
      end if;
      return Result;
   end Provider_Failure;

   -------------------
   -- Limit_Failure --
   -------------------

   function Limit_Failure
     (Kind      : SSL.Limits.Limit_Kind;
      Allowed   : Long_Long_Integer;
      Requested : Long_Long_Integer;
      Origin    : Error_Origin := Peer_Message;
      Stage     : Lifecycle_Stage := Stage_Handshaking) return Error_Information
   is
   begin
      return Make (Code       => Code_Limit_Exceeded,
                   Origin     => Origin,
                   Stage      => Stage,
                   Parameters =>
                     [Text_Parameter ("limit", SSL.Limits.Image (Kind)),
                      Numeric_Parameter ("allowed", Allowed),
                      Numeric_Parameter ("requested", Requested)]);
   end Limit_Failure;

   ---------------------
   -- With_Connection --
   ---------------------

   function With_Connection (Item : Error_Information; Connection : Connection_ID)
     return Error_Information
   is
      Result : Error_Information := Item;
   begin
      Result.Connection := Connection;
      return Result;
   end With_Connection;

   ----------------
   -- With_Stage --
   ----------------

   function With_Stage (Item : Error_Information; Stage : Lifecycle_Stage)
     return Error_Information
   is
      Result : Error_Information := Item;
   begin
      Result.Stage := Stage;
      return Result;
   end With_Stage;

   ---------------------------------------------------------------------------
   --  Rendering
   ---------------------------------------------------------------------------

   -----------
   -- Image --
   -----------

   function Image (Category : Error_Category) return String is
   begin
      case Category is
         when No_Failure         => return "none";
         when Configuration      => return "configuration";
         when Transport          => return "transport";
         when Record_Layer       => return "record";
         when Protocol           => return "protocol";
         when Negotiation        => return "negotiation";
         when Cryptographic      => return "cryptographic";
         when Certificate        => return "certificate";
         when Identity           => return "identity";
         when Revocation         => return "revocation";
         when Pinning            => return "pinning";
         when Session            => return "session";
         when Resource           => return "resource";
         when Deadline           => return "deadline";
         when Cancellation       => return "cancellation";
         when Application_Policy => return "application_policy";
         when Provider           => return "provider";
         when Internal           => return "internal";
      end case;
   end Image;

   function Image (Origin : Error_Origin) return String is
   begin
      case Origin is
         when No_Origin            => return "none";
         when Local_Policy         => return "local_policy";
         when Local_Implementation => return "local_implementation";
         when Peer_Message         => return "peer_message";
         when Peer_Alert           => return "peer_alert";
         when Caller_Transport     => return "caller_transport";
         when Caller_Request       => return "caller_request";
         when Application_Callback => return "application_callback";
         when External_Provider    => return "external_provider";
      end case;
   end Image;

   function Image (Retry : Retry_Class) return String is
   begin
      case Retry is
         when Not_Retryable               => return "not_retryable";
         when Retry_Same_Connection       => return "retry_same_connection";
         when Retry_New_Connection        => return "retry_new_connection";
         when Retry_After_Reconfiguration => return "retry_after_reconfiguration";
      end case;
   end Image;

   function Image (Disclosure : Disclosure_Class) return String is
   begin
      case Disclosure is
         when Safe_For_Peer => return "safe_for_peer";
         when Operator_Only => return "operator_only";
         when Restricted    => return "restricted";
      end case;
   end Image;

   function Image (Stage : Lifecycle_Stage) return String is
   begin
      case Stage is
         when Stage_Uninitialized => return "uninitialized";
         when Stage_Ready         => return "ready";
         when Stage_Handshaking   => return "handshaking";
         when Stage_Established   => return "established";
         when Stage_Closing       => return "closing";
         when Stage_Closed        => return "closed";
         when Stage_Failed        => return "failed";
      end case;
   end Image;

   --  Decimal image without the leading blank Ada'Image inserts.
   function Trimmed (Value : Long_Long_Integer) return String;

   function Trimmed (Value : Long_Long_Integer) return String is
      Text : constant String := Value'Image;
   begin
      if Text (Text'First) = ' ' then
         return Text (Text'First + 1 .. Text'Last);
      end if;
      return Text;
   end Trimmed;

   function Image (Item : Error_Information) return String is
   begin
      if not Is_Error (Item) then
         return "ok";
      end if;

      declare
         Head : constant String :=
           Image (Item.Category) & "/" & Trimmed (Long_Long_Integer (Item.Code))
           & " origin=" & Image (Item.Origin)
           & " stage=" & Image (Item.Stage)
           & (if Item.Fatal then " fatal" else " nonfatal")
           & " alert=" & SSL.Alerts.Image (Item.Alert)
           & " retry=" & Image (Item.Retry);
         Body_Text : String (1 .. 512) := [others => ' '];
         Length    : Natural := 0;

         procedure Append (Text : String);

         procedure Append (Text : String) is
            Room : constant Natural := Natural'Min (Text'Length, Body_Text'Length - Length);
         begin
            if Room > 0 then
               Body_Text (Length + 1 .. Length + Room) :=
                 Text (Text'First .. Text'First + Room - 1);
               Length := Length + Room;
            end if;
         end Append;

      begin
         --  A Restricted error is rendered as its code and category only: its
         --  parameters could describe how far a check got before it failed,
         --  and that is what the classification is refusing to say. Even in a
         --  local log, because logs are shipped.
         if Item.Disclosure /= Restricted then
            for Index in 1 .. Item.Count loop
               declare
                  Fact : constant Parameter := Item.Parameters (Index);
               begin
                  Append (" " & Name_Of (Fact) & "=");
                  case Fact.Kind is
                     when Numeric => Append (Trimmed (Fact.Number));
                     when Text    => Append (Text_Of (Fact));
                  end case;
               end;
            end loop;

            if Item.Provider_Length > 0 then
               Append (" provider=" & Provider_Text (Item));
            end if;
         end if;

         return Head & Body_Text (1 .. Length);
      end;
   end Image;

   ----------------
   -- Peer_Image --
   ----------------

   function Peer_Image (Item : Error_Information) return String is
   begin
      return SSL.Alerts.Image (Item.Alert);
   end Peer_Image;

   ---------------------------------------------------------------------------
   --  Accumulation
   ---------------------------------------------------------------------------

   ------------------
   -- No_Failures --
   ------------------

   function No_Failures return Failure_Record is
   begin
      return (First => No_Error, First_Is_Fatal => False, Secondary => 0);
   end No_Failures;

   --------------------
   -- Record_Failure --
   --------------------

   procedure Record_Failure (Item : in out Failure_Record; Failure : Error_Information) is
   begin
      if not Is_Error (Failure) then
         return;
      end if;

      if not Is_Error (Item.First) then
         --  Nothing recorded yet: this is the explanation.
         Item.First := Failure;
         Item.First_Is_Fatal := Is_Fatal (Failure);
         return;
      end if;

      if not Item.First_Is_Fatal and then Is_Fatal (Failure) then
         --  A soft failure was recorded first -- backpressure, a stale ticket.
         --  The first terminal failure is the one that explains the
         --  connection's state, so it takes the primary slot, and the soft one
         --  becomes a secondary. After this the primary is never displaced.
         Item.First := Failure;
         Item.First_Is_Fatal := True;
      end if;

      if Item.Secondary < Secondary_Cap then
         Item.Secondary := Item.Secondary + 1;
      end if;
   end Record_Failure;

   -------------
   -- Primary --
   -------------

   function Primary (Item : Failure_Record) return Error_Information is
   begin
      return Item.First;
   end Primary;

   ----------------------
   -- Secondary_Count --
   ----------------------

   function Secondary_Count (Item : Failure_Record) return Natural is
   begin
      return Item.Secondary;
   end Secondary_Count;

   -----------------
   -- Has_Failure --
   -----------------

   function Has_Failure (Item : Failure_Record) return Boolean is
   begin
      return Is_Error (Item.First);
   end Has_Failure;

end SSL.Errors;
