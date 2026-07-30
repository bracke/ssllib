with Interfaces;

with SSL.Alerts;
with SSL.Limits;

--  @summary Structured failure information: the value every ordinary failure
--  in this library is reported as.
--
--  Ordinary failures are results, not exceptions. Transport trouble, malformed
--  peer input, a negotiation with no overlap, a certificate that does not
--  validate, a deadline, a cancellation, a limit, a session that cannot be
--  used -- all of these are things a correct program must handle, and a
--  correct program should not have to write an exception handler to find out
--  that they happened. Exceptions in this library are for programming-contract
--  violations, for internal states that cannot occur, and for the Ada stream
--  interface, which has no other way to report failure.
--
--  An Error_Information is immutable and self-contained: it holds no pointer,
--  no view into a connection, and nothing that stops being valid when the
--  connection is finalized. It can be stored, compared, logged and returned
--  from a task other than the one that produced it.
--
--  Every error carries a disclosure classification, because the same failure
--  needs three different accounts of itself: what may be sent to the peer as
--  an alert, what an operator may see in a log, and what must not leave the
--  process at all. Nothing in this record is a secret, and the classification
--  says how much of it may be rendered where.
package SSL.Errors is

   ---------------------------------------------------------------------------
   --  Classification
   ---------------------------------------------------------------------------

   --  The stable family a failure belongs to. An application switching on
   --  this gets behaviour that survives new error codes being added within a
   --  family.
   type Error_Category is
     (No_Failure,
      Configuration,        --  the local setup is unusable, before any bytes
      Transport,            --  the caller's transport failed or ended
      Record_Layer,         --  a record could not be parsed or authenticated
      Protocol,             --  a message arrived that the state machine forbids
      Negotiation,          --  no overlap in version, suite, group or protocol
      Cryptographic,        --  a primitive refused or a verification failed
      Certificate,          --  a chain could not be decoded or validated
      Identity,             --  the chain is valid but not for this name
      Revocation,           --  revocation policy was not satisfied
      Pinning,              --  a pin was configured and not met
      Session,              --  a ticket or cached session could not be used
      Resource,             --  a configured bound was reached
      Deadline,             --  a caller-supplied deadline passed
      Cancellation,         --  the caller cancelled
      Application_Policy,   --  an application callback said no
      Provider,             --  an external signer or provider failed
      Internal);            --  an invariant this library holds did not hold

   --  A stable numeric code. Explicit values, never enumeration positions:
   --  these appear in logs and in machine-readable release reports, and a
   --  reordering of a type declaration must not renumber them.
   type Error_Code is new Interfaces.Unsigned_32;

   --  Where the failure was decided. This is what separates "the peer sent
   --  something wrong" from "we are configured wrong" in a log, and the two
   --  read identically without it.
   type Error_Origin is
     (No_Origin,
      Local_Policy,          --  this endpoint's configuration refused
      Local_Implementation,  --  this endpoint's own code refused
      Peer_Message,          --  something the peer sent
      Peer_Alert,            --  an alert the peer sent
      Caller_Transport,      --  the transport the caller supplied
      Caller_Request,        --  the call the caller made
      Application_Callback,  --  an application-supplied decision or hook
      External_Provider);    --  an external signer, cache or OCSP provider

   --  Whether trying again could work, and at what granularity. A caller
   --  looping on a transport hiccup and a caller reconnecting after a session
   --  went stale need different answers, and guessing from the category is
   --  how retry storms start.
   type Retry_Class is
     (Not_Retryable,
      Retry_Same_Connection,        --  transient: call again on this connection
      Retry_New_Connection,         --  this connection is finished; a new one may work
      Retry_After_Reconfiguration); --  nothing will work until the setup changes

   --  How much of this error may be shown, and to whom.
   type Disclosure_Class is
     (Safe_For_Peer,     --  the alert already says this much
      Operator_Only,     --  fine in a local log, not on the wire
      Restricted);       --  may reveal timing or content structure; log the code only

   --  The connection lifecycle stage the failure was detected in. Recorded so
   --  that a log line does not have to be correlated with another to know
   --  whether the handshake had finished.
   type Lifecycle_Stage is
     (Stage_Uninitialized,
      Stage_Ready,
      Stage_Handshaking,
      Stage_Established,
      Stage_Closing,
      Stage_Closed,
      Stage_Failed);

   ---------------------------------------------------------------------------
   --  Codes
   --
   --  Grouped by category in blocks of a thousand. A code is never reused for
   --  a different meaning and never renumbered; a retired code is left as a
   --  hole.
   ---------------------------------------------------------------------------

   Code_None : constant Error_Code := 0;

   --  Configuration
   Code_No_Versions_Enabled               : constant Error_Code := 1001;
   Code_No_Cipher_Suites_Enabled          : constant Error_Code := 1002;
   Code_No_Groups_Enabled                 : constant Error_Code := 1003;
   Code_No_Signature_Schemes_Enabled      : constant Error_Code := 1004;
   Code_Suite_Version_Mismatch            : constant Error_Code := 1005;
   Code_Signature_Version_Mismatch        : constant Error_Code := 1006;
   Code_Key_Share_Not_Offered             : constant Error_Code := 1007;
   Code_No_Credential_Configured          : constant Error_Code := 1008;
   Code_Credential_Unusable               : constant Error_Code := 1009;
   Code_Trust_Required_But_Absent         : constant Error_Code := 1010;
   Code_System_Trust_Unavailable          : constant Error_Code := 1011;
   Code_Trust_Source_Empty                : constant Error_Code := 1012;
   Code_Invalid_ALPN_Policy               : constant Error_Code := 1013;
   Code_Invalid_Limits                    : constant Error_Code := 1014;
   Code_Ticket_Issuance_Without_Key       : constant Error_Code := 1015;
   Code_Invalid_Server_Name               : constant Error_Code := 1016;
   Code_Duplicate_ALPN_Protocol           : constant Error_Code := 1017;
   Code_Client_Auth_Without_Credential    : constant Error_Code := 1018;
   Code_Pin_Without_Identity              : constant Error_Code := 1019;
   Code_Configuration_Not_Validated       : constant Error_Code := 1020;
   Code_Revocation_Policy_Unsatisfiable   : constant Error_Code := 1021;
   Code_Duplicate_Credential_Identity     : constant Error_Code := 1022;
   Code_Legacy_Version_Requested          : constant Error_Code := 1023;
   Code_Compatibility_Weakens_TLS13       : constant Error_Code := 1024;

   --  Transport
   Code_Transport_Failed                  : constant Error_Code := 2001;
   Code_Transport_Closed_Early            : constant Error_Code := 2002;
   Code_Transport_Truncated               : constant Error_Code := 2003;
   Code_Transport_Interrupted             : constant Error_Code := 2004;
   Code_Transport_Not_Set                 : constant Error_Code := 2005;

   --  Record layer
   Code_Record_Header_Malformed           : constant Error_Code := 3001;
   Code_Record_Length_Excessive           : constant Error_Code := 3002;
   Code_Record_Version_Rejected           : constant Error_Code := 3003;
   Code_Record_Authentication_Failed      : constant Error_Code := 3004;
   Code_Record_Padding_Malformed          : constant Error_Code := 3005;
   Code_Record_Type_Forbidden             : constant Error_Code := 3006;
   Code_Record_Empty_Run_Excessive        : constant Error_Code := 3007;
   Code_Record_Sequence_Exhausted         : constant Error_Code := 3008;
   Code_Record_Inner_Type_Invalid         : constant Error_Code := 3009;
   Code_Record_Compression_Rejected       : constant Error_Code := 3010;
   Code_Record_Unexpected_CCS             : constant Error_Code := 3011;
   Code_Record_Plaintext_After_Epoch      : constant Error_Code := 3012;
   Code_Record_Size_Limit_Exceeded        : constant Error_Code := 3013;

   --  Protocol / state machine
   Code_Unexpected_Handshake_Message      : constant Error_Code := 4001;
   Code_Handshake_Message_Malformed       : constant Error_Code := 4002;
   Code_Duplicate_Extension               : constant Error_Code := 4003;
   Code_Extension_In_Wrong_Context        : constant Error_Code := 4004;
   Code_Unsolicited_Extension             : constant Error_Code := 4005;
   Code_Missing_Required_Extension        : constant Error_Code := 4006;
   Code_Extension_Malformed               : constant Error_Code := 4007;
   Code_Second_Hello_Retry_Request        : constant Error_Code := 4008;
   Code_Hello_Retry_Group_Already_Offered : constant Error_Code := 4009;
   Code_Hello_Retry_Invariant_Broken      : constant Error_Code := 4010;
   Code_Finished_Verification_Failed      : constant Error_Code := 4011;
   Code_Certificate_Verify_Failed         : constant Error_Code := 4012;
   Code_Legacy_Compression_Offered        : constant Error_Code := 4013;
   Code_Legacy_Session_Id_Mismatch        : constant Error_Code := 4014;
   Code_Renegotiation_Attempted           : constant Error_Code := 4015;
   Code_Downgrade_Sentinel_Detected       : constant Error_Code := 4016;
   Code_Extended_Master_Secret_Missing    : constant Error_Code := 4017;
   Code_Key_Update_Flood                  : constant Error_Code := 4018;
   Code_Post_Handshake_Auth_Requested     : constant Error_Code := 4019;
   Code_Peer_Alert_Received               : constant Error_Code := 4020;
   Code_Empty_Certificate_Not_Permitted   : constant Error_Code := 4021;
   Code_Certificate_Verify_Unexpected     : constant Error_Code := 4022;
   Code_Key_Exchange_Value_Invalid        : constant Error_Code := 4023;
   Code_Early_Data_Offered                : constant Error_Code := 4024;
   Code_External_PSK_Offered              : constant Error_Code := 4025;
   Code_Binder_Verification_Failed        : constant Error_Code := 4026;
   Code_PSK_Not_Last_Extension            : constant Error_Code := 4027;
   Code_PSK_Mode_Unacceptable             : constant Error_Code := 4028;
   Code_Selected_Identity_Out_Of_Range    : constant Error_Code := 4029;
   Code_Transcript_Unavailable            : constant Error_Code := 4030;
   Code_Handshake_Not_Complete            : constant Error_Code := 4031;
   Code_Connection_Not_Reusable           : constant Error_Code := 4032;
   Code_Write_After_Close_Notify          : constant Error_Code := 4033;
   Code_Read_After_Peer_Close             : constant Error_Code := 4034;
   Code_Change_Cipher_Spec_Malformed      : constant Error_Code := 4035;

   --  Negotiation
   Code_No_Common_Version                 : constant Error_Code := 4501;
   Code_No_Common_Cipher_Suite            : constant Error_Code := 4502;
   Code_No_Common_Group                   : constant Error_Code := 4503;
   Code_No_Common_Signature_Scheme        : constant Error_Code := 4504;
   Code_No_Application_Protocol_Overlap   : constant Error_Code := 4505;
   Code_Server_Name_Unrecognized          : constant Error_Code := 4506;
   Code_Selected_Suite_Not_Offered        : constant Error_Code := 4507;
   Code_Selected_Group_Not_Offered        : constant Error_Code := 4508;
   Code_Selected_Version_Not_Offered      : constant Error_Code := 4509;
   Code_Application_Protocol_Changed      : constant Error_Code := 4510;

   --  Cryptographic
   Code_Random_Source_Failed              : constant Error_Code := 4801;
   Code_Key_Agreement_Failed              : constant Error_Code := 4802;
   Code_Key_Derivation_Failed             : constant Error_Code := 4803;
   Code_Signature_Generation_Failed       : constant Error_Code := 4804;
   Code_Signature_Verification_Failed     : constant Error_Code := 4805;
   Code_AEAD_Operation_Failed             : constant Error_Code := 4806;
   Code_Algorithm_Not_Supported           : constant Error_Code := 4807;
   Code_Weak_Algorithm_Rejected           : constant Error_Code := 4808;
   Code_Key_Algorithm_Mismatch            : constant Error_Code := 4809;

   --  Certificate
   Code_Certificate_List_Empty            : constant Error_Code := 5001;
   Code_Certificate_Malformed             : constant Error_Code := 5002;
   Code_Certificate_Path_Not_Built        : constant Error_Code := 5003;
   Code_Certificate_Path_Invalid          : constant Error_Code := 5004;
   Code_Certificate_Expired               : constant Error_Code := 5005;
   Code_Certificate_Not_Yet_Valid         : constant Error_Code := 5006;
   Code_Certificate_Purpose_Rejected      : constant Error_Code := 5007;
   Code_Certificate_Key_Usage_Rejected    : constant Error_Code := 5008;
   Code_Certificate_Untrusted_Anchor      : constant Error_Code := 5009;
   Code_Certificate_Weak_Key              : constant Error_Code := 5010;
   Code_Certificate_Self_Signed_Peer      : constant Error_Code := 5011;
   Code_Certificate_Required_By_Peer      : constant Error_Code := 5012;
   Code_Certificate_Not_Provided          : constant Error_Code := 5013;

   --  Identity
   Code_Identity_No_Match                 : constant Error_Code := 5201;
   Code_Identity_No_Names_Present         : constant Error_Code := 5202;
   Code_Identity_Reference_Malformed      : constant Error_Code := 5203;
   Code_Identity_Not_Specified            : constant Error_Code := 5204;

   --  Revocation
   Code_Certificate_Revoked               : constant Error_Code := 5401;
   Code_Revocation_Status_Unknown         : constant Error_Code := 5402;
   Code_Revocation_Status_Stale           : constant Error_Code := 5403;
   Code_Revocation_Status_Absent          : constant Error_Code := 5404;
   Code_Stapled_Status_Malformed          : constant Error_Code := 5405;
   Code_Stapled_Status_Required           : constant Error_Code := 5406;
   Code_Stapled_Status_Wrong_Certificate  : constant Error_Code := 5407;

   --  Pinning
   Code_Pin_Not_Met                       : constant Error_Code := 5601;
   Code_Pin_Expired                       : constant Error_Code := 5602;
   Code_Pin_Scope_Mismatch                : constant Error_Code := 5603;

   --  Session
   Code_Ticket_Malformed                  : constant Error_Code := 6001;
   Code_Ticket_Unknown_Key                : constant Error_Code := 6002;
   Code_Ticket_Expired                    : constant Error_Code := 6003;
   Code_Ticket_Authentication_Failed      : constant Error_Code := 6004;
   Code_Ticket_Binding_Mismatch           : constant Error_Code := 6005;
   Code_Ticket_Version_Unsupported        : constant Error_Code := 6006;
   Code_Session_Not_Resumable             : constant Error_Code := 6007;
   Code_Session_Cache_Failed              : constant Error_Code := 6008;
   Code_Session_Security_Context_Mismatch : constant Error_Code := 6009;
   Code_Ticket_Key_Not_Active             : constant Error_Code := 6010;
   Code_Session_Persistence_Key_Absent    : constant Error_Code := 6011;
   Code_Session_Not_Extended_Master_Secret : constant Error_Code := 6012;

   --  Resource
   Code_Limit_Exceeded                    : constant Error_Code := 7001;
   Code_Output_Queue_Full                 : constant Error_Code := 7002;
   Code_Input_Buffer_Full                 : constant Error_Code := 7003;
   Code_Plaintext_Queue_Full              : constant Error_Code := 7004;
   Code_Storage_Exhausted                 : constant Error_Code := 7005;

   --  Deadline and cancellation
   Code_Deadline_Reached                  : constant Error_Code := 8001;
   Code_Cancelled                         : constant Error_Code := 8002;

   --  Application and provider
   Code_Application_Refused               : constant Error_Code := 9001;
   Code_Application_Callback_Raised       : constant Error_Code := 9002;
   Code_Provider_Refused                  : constant Error_Code := 9003;
   Code_Provider_Callback_Raised          : constant Error_Code := 9004;
   Code_Provider_Unavailable              : constant Error_Code := 9005;
   Code_Signer_Capability_Missing         : constant Error_Code := 9006;

   --  Internal
   Code_Internal_Invariant_Violated       : constant Error_Code := 10001;
   Code_Internal_Not_Reachable            : constant Error_Code := 10002;

   ---------------------------------------------------------------------------
   --  Bounded parameters
   --
   --  A failure often needs one or two facts to be actionable: which limit,
   --  what was asked for, which extension identifier, which server name. They
   --  are held in fixed storage so that carrying them cannot allocate on a
   --  path a hostile peer drives.
   ---------------------------------------------------------------------------

   Maximum_Parameters      : constant := 4;
   Parameter_Name_Limit    : constant := 32;
   Parameter_Text_Limit    : constant := 64;

   subtype Parameter_Count is Natural range 0 .. Maximum_Parameters;
   subtype Parameter_Index is Positive range 1 .. Maximum_Parameters;

   type Parameter_Kind is (Numeric, Text);

   --  One named fact about a failure.
   type Parameter is private;

   --  Build a numeric parameter.
   --  @param Name  short stable name, truncated at Parameter_Name_Limit
   --  @param Value the number
   --  @return the parameter
   function Numeric_Parameter (Name : String; Value : Long_Long_Integer) return Parameter;

   --  Build a text parameter. The text is truncated at Parameter_Text_Limit,
   --  and must never be secret: parameters are rendered wherever the error is.
   --  @param Name  short stable name
   --  @param Value the text
   --  @return the parameter
   function Text_Parameter (Name : String; Value : String) return Parameter;

   function Name_Of (Item : Parameter) return String;
   function Kind_Of (Item : Parameter) return Parameter_Kind;
   function Number_Of (Item : Parameter) return Long_Long_Integer
     with Pre => Kind_Of (Item) = Numeric;
   function Text_Of (Item : Parameter) return String
     with Pre => Kind_Of (Item) = Text;

   type Parameter_List is array (Parameter_Index range <>) of Parameter;

   --  The empty list, for a failure that needs no facts attached. A function
   --  rather than a constant because Parameter is private here and a deferred
   --  constant of a visible array type is not the clearer spelling.
   function No_Parameters return Parameter_List
     with Post => No_Parameters'Result'Length = 0;

   ---------------------------------------------------------------------------
   --  The error value
   ---------------------------------------------------------------------------

   type Error_Information is private;

   --  Success. The value every out parameter starts at.
   function No_Error return Error_Information;

   --  Did something go wrong?
   --  @param Item the value to test
   --  @return True when Item describes a failure
   function Is_Error (Item : Error_Information) return Boolean;

   --  Is this failure terminal for the connection?
   --
   --  A non-fatal error is one a caller may act on and continue with: a
   --  Would_Block that surfaced as a deadline, a session that could not be
   --  resumed. A fatal one has ended the connection.
   --  @param Item the value to test
   --  @return True when the connection cannot continue
   function Is_Fatal (Item : Error_Information) return Boolean;

   function Category_Of (Item : Error_Information) return Error_Category;
   function Code_Of (Item : Error_Information) return Error_Code;
   function Origin_Of (Item : Error_Information) return Error_Origin;
   function Retry_Of (Item : Error_Information) return Retry_Class;
   function Disclosure_Of (Item : Error_Information) return Disclosure_Class;
   function Stage_Of (Item : Error_Information) return Lifecycle_Stage;

   --  The alert this failure maps to, if any. Central mapping: no failure site
   --  chooses its own alert, so the set of alerts a peer can observe is a
   --  property of one table rather than of a hundred call sites.
   --  @param Item the failure
   --  @return the alert, or SSL.Alerts.No_Alert when none is to be sent
   function Alert_Of (Item : Error_Information) return SSL.Alerts.Alert;

   --  The connection this failure belongs to, when it was known.
   function Connection_Of (Item : Error_Information) return Connection_ID;

   --  Bounded facts about the failure.
   function Parameter_Count_Of (Item : Error_Information) return Parameter_Count;
   function Parameter_At (Item : Error_Information; Index : Parameter_Index) return Parameter
     with Pre => Index <= Parameter_Count_Of (Item);

   --  Free-form provider or callback text, when the failure came from outside
   --  this library and the outside said something. Bounded and never secret.
   function Provider_Text (Item : Error_Information) return String;

   --  A stable one-line rendering for an operator log: category, code, origin
   --  and the parameters permitted by the disclosure class. Never includes key
   --  material, plaintext, or anything a Restricted error is holding back.
   --  @param Item the failure
   --  @return the line, without a trailing newline
   function Image (Item : Error_Information) return String;

   --  The account of this failure that is safe to give the peer: the alert
   --  name and nothing else.
   --  @param Item the failure
   --  @return the alert name, or "none"
   function Peer_Image (Item : Error_Information) return String;

   --  Short stable text naming a category, for logs and reports.
   function Image (Category : Error_Category) return String;
   function Image (Origin : Error_Origin) return String;
   function Image (Retry : Retry_Class) return String;
   function Image (Disclosure : Disclosure_Class) return String;
   function Image (Stage : Lifecycle_Stage) return String;

   ---------------------------------------------------------------------------
   --  Construction
   --
   --  Callers build errors for the two cases where the failure is theirs to
   --  report: an application callback that refuses, and an external provider
   --  that fails. Everything else is built inside the library.
   ---------------------------------------------------------------------------

   --  Build a failure. The alert, fatality, retry class and disclosure class
   --  are looked up from Code in the central table, so that two sites
   --  reporting the same code cannot disagree about what the peer is told.
   --  @param Code       which failure
   --  @param Origin     where it was decided
   --  @param Stage      the lifecycle stage it was detected in
   --  @param Connection the connection it belongs to, or No_Connection
   --  @param Parameters bounded facts, at most Maximum_Parameters
   --  @param Provider   bounded provider text, or empty
   --  @return the failure value
   function Make
     (Code       : Error_Code;
      Origin     : Error_Origin;
      Stage      : Lifecycle_Stage := Stage_Uninitialized;
      Connection : Connection_ID := No_Connection;
      Parameters : Parameter_List := No_Parameters;
      Provider   : String := "") return Error_Information
     with Pre => Code /= Code_None;

   --  An application callback refusing. Use this from an ALPN selector, a
   --  certificate decision hook or a session-cache implementation to say no in
   --  a way the engine can act on.
   --  @param Reason short operator-facing text, bounded, never secret
   --  @return the failure value
   function Application_Refusal (Reason : String) return Error_Information;

   --  An external provider failing: a signer that could not sign, a cache that
   --  could not answer.
   --  @param Reason short operator-facing text, bounded, never secret
   --  @param Fatal  True when the connection cannot continue without it
   --  @return the failure value
   function Provider_Failure (Reason : String; Fatal : Boolean := True) return Error_Information;

   --  A configured bound was reached. Recorded with the limit's stable name,
   --  the bound and what was asked for, because "too large" without those
   --  three is not actionable.
   --  @param Kind      which limit
   --  @param Allowed   the configured bound
   --  @param Requested what was asked for
   --  @param Origin    where the oversize value came from
   --  @param Stage     the lifecycle stage
   --  @return the failure value
   function Limit_Failure
     (Kind      : SSL.Limits.Limit_Kind;
      Allowed   : Long_Long_Integer;
      Requested : Long_Long_Integer;
      Origin    : Error_Origin := Peer_Message;
      Stage     : Lifecycle_Stage := Stage_Handshaking) return Error_Information;

   --  Attach the connection identity to a failure built before the connection
   --  was known. Returns a new value; Error_Information is immutable.
   --  @param Item       the failure
   --  @param Connection the connection
   --  @return the failure with the connection recorded
   function With_Connection (Item : Error_Information; Connection : Connection_ID)
     return Error_Information;

   --  Attach the lifecycle stage to a failure built before the stage was
   --  known. Returns a new value.
   --  @param Item  the failure
   --  @param Stage the stage
   --  @return the failure with the stage recorded
   function With_Stage (Item : Error_Information; Stage : Lifecycle_Stage)
     return Error_Information;

   ---------------------------------------------------------------------------
   --  Accumulation
   --
   --  A failing connection produces more than one failure: the first one, and
   --  then everything that could not be done afterwards. Only the first is the
   --  explanation; the rest are consequences. This record keeps the first
   --  exactly and counts the rest, bounded.
   ---------------------------------------------------------------------------

   type Failure_Record is private;

   --  A record holding no failure.
   function No_Failures return Failure_Record;

   --  Record a failure. The first terminal failure is kept exactly and is
   --  never displaced; later ones increment a bounded counter. A non-fatal
   --  failure recorded before any terminal one is kept until a terminal one
   --  arrives.
   --  @param Item    the record to add to
   --  @param Failure the failure to record
   procedure Record_Failure (Item : in out Failure_Record; Failure : Error_Information);

   --  The failure that explains this connection's state.
   --  @param Item the record to read
   --  @return the first terminal failure, or the first failure of any kind, or
   --    No_Error
   function Primary (Item : Failure_Record) return Error_Information;

   --  How many failures arrived after the primary one, counted rather than
   --  kept. Saturates at the configured bound.
   --  @param Item the record to read
   --  @return the count of secondary failures
   function Secondary_Count (Item : Failure_Record) return Natural;

   --  Has any failure been recorded?
   function Has_Failure (Item : Failure_Record) return Boolean;

private

   subtype Name_Text is String (1 .. Parameter_Name_Limit);
   subtype Value_Text is String (1 .. Parameter_Text_Limit);

   type Parameter is record
      Kind         : Parameter_Kind := Numeric;
      Name         : Name_Text := [others => ' '];
      Name_Length  : Natural range 0 .. Parameter_Name_Limit := 0;
      Number       : Long_Long_Integer := 0;
      Text         : Value_Text := [others => ' '];
      Text_Length  : Natural range 0 .. Parameter_Text_Limit := 0;
   end record;

   Provider_Text_Limit : constant := 96;
   subtype Provider_Buffer is String (1 .. Provider_Text_Limit);

   type Parameter_Store is array (Parameter_Index) of Parameter;

   type Error_Information is record
      Category        : Error_Category := No_Failure;
      Code            : Error_Code := Code_None;
      Origin          : Error_Origin := No_Origin;
      Fatal           : Boolean := False;
      Alert           : SSL.Alerts.Alert := SSL.Alerts.No_Alert;
      Retry           : Retry_Class := Not_Retryable;
      Disclosure      : Disclosure_Class := Operator_Only;
      Stage           : Lifecycle_Stage := Stage_Uninitialized;
      Connection      : Connection_ID := No_Connection;
      Count           : Parameter_Count := 0;
      Parameters      : Parameter_Store := [others => <>];
      Provider        : Provider_Buffer := [others => ' '];
      Provider_Length : Natural range 0 .. Provider_Text_Limit := 0;
   end record;

   Secondary_Cap : constant := 255;

   type Failure_Record is record
      First          : Error_Information;
      First_Is_Fatal : Boolean := False;
      Secondary      : Natural range 0 .. Secondary_Cap := 0;
   end record;

end SSL.Errors;
