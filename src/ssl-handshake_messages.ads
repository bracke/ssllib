with Interfaces;

with SSL.ALPN;
with SSL.Cipher_Suites;
with SSL.Errors;
with SSL.Extensions;
with SSL.Limits;
with SSL.Server_Names;
with SSL.Signature_Schemes;
with SSL.Supported_Groups;
with SSL.Configurations;
with SSL.Versions;

--  @summary The handshake message framing, and the codecs for the two hello
--  messages.
--
--  A handshake message is one type octet, a three-octet length, and a body. That
--  framing is the transcript's unit -- SSL.Transcripts absorbs exactly these
--  octets and never a record header -- so it is defined here once and every
--  message goes through it.
--
--  The hello messages are the ones that carry the negotiation, and they are the
--  ones a hostile peer reaches first: a ClientHello is parsed by a server before
--  it has authenticated anything at all, and it is the largest attacker-chosen
--  structure in the protocol. Everything about how they are parsed here follows
--  from that. Every length is checked against a configured bound before the
--  octets behind it are read; every list is bounded; the extension block goes
--  through SSL.Extensions, which enforces the duplicate and context rules before
--  a body is opened; and a parse produces a value or a named failure, never a
--  partly-filled record.
--
--  What a peer sent is kept separately from what this endpoint would have sent.
--  A ClientHello parsed here reports the legacy session identifier, the
--  compression methods and the unrecognized extension identifiers as they
--  arrived, because the transcript hashes what arrived and a re-encoding that
--  differed anywhere would produce a different transcript and fail every
--  Finished.
private package SSL.Handshake_Messages is

   ---------------------------------------------------------------------------
   --  Framing
   ---------------------------------------------------------------------------

   --  The handshake message types this library produces or accepts.
   --
   --  Message_Hash is not a message: it is the synthetic type RFC 8446 section
   --  4.4.1 uses in the HelloRetryRequest transcript transformation, and it
   --  never appears on the wire.
   type Message_Type is
     (Client_Hello,
      Server_Hello,
      New_Session_Ticket,
      Encrypted_Extensions,
      Certificate,
      Certificate_Request,
      Certificate_Verify,
      Finished,
      Key_Update,
      Message_Hash,

      --  Restricted TLS 1.2 only.
      Server_Key_Exchange,
      Server_Hello_Done,
      Client_Key_Exchange,

      --  Not produced and not accepted; recognized so a diagnostic can name
      --  what a peer sent.
      Hello_Request,
      End_Of_Early_Data,
      Unknown_Message);

   type Type_Value is new Interfaces.Unsigned_8;

   Client_Hello_Value         : constant Type_Value := 1;
   Server_Hello_Value         : constant Type_Value := 2;
   New_Session_Ticket_Value   : constant Type_Value := 4;
   End_Of_Early_Data_Value    : constant Type_Value := 5;
   Encrypted_Extensions_Value : constant Type_Value := 8;
   Certificate_Value          : constant Type_Value := 11;
   Server_Key_Exchange_Value  : constant Type_Value := 12;
   Certificate_Request_Value  : constant Type_Value := 13;
   Server_Hello_Done_Value    : constant Type_Value := 14;
   Certificate_Verify_Value   : constant Type_Value := 15;
   Client_Key_Exchange_Value  : constant Type_Value := 16;
   Finished_Value             : constant Type_Value := 20;
   Key_Update_Value           : constant Type_Value := 24;
   Message_Hash_Value         : constant Type_Value := 254;
   Hello_Request_Value        : constant Type_Value := 0;

   function Value_Of (Item : Message_Type) return Type_Value
     with Pre => Item /= Unknown_Message;

   function Type_For (Item : Type_Value) return Message_Type;

   function Image (Item : Message_Type) return String;

   --  The four-octet header every handshake message begins with.
   Header_Length : constant Byte_Index := 4;

   --  Read a message header.
   --  @param Data    the octets, at least four of them
   --  @param Kind    out: the recognized type, or Unknown_Message
   --  @param Value   out: the type octet as it arrived
   --  @param Length  out: the declared body length
   --  @param Error   out: No_Error, or a malformed-header failure
   --  Parse a message header.
   --
   --  Accepts any input, including none. There is deliberately no precondition
   --  on the length: a header parser is the first thing every message reaches,
   --  its argument comes from a peer, and a contract that made "too short" a
   --  programming error would put the burden of checking on every caller and
   --  turn a hostile input into a raised exception at whichever one forgot.
   --  A short buffer is a structured failure like any other.
   procedure Parse_Header
     (Data   : Byte_Array;
      Kind   : out Message_Type;
      Value  : out Type_Value;
      Length : out Byte_Index;
      Error  : out SSL.Errors.Error_Information);

   --  Emit a message header.
   function Encode_Header (Kind : Message_Type; Length : Byte_Index) return Byte_Array
     with Pre => Kind /= Unknown_Message and then Length <= 16#FF_FFFF#,
          Post => Encode_Header'Result'Length = Header_Length;

   --  Is a declared body length acceptable under the limits in force?
   --
   --  Certificate has its own, much larger bound, because a chain is legitimately
   --  larger than anything else and giving everything the certificate bound would
   --  let a peer send a four-megabyte Finished.
   function Length_Permitted
     (Kind   : Message_Type;
      Length : Byte_Index;
      Bounds : SSL.Limits.Resource_Limits) return Boolean;

   ---------------------------------------------------------------------------
   --  ClientHello
   ---------------------------------------------------------------------------

   Random_Length : constant Byte_Index := 32;
   Maximum_Session_Id_Length : constant Byte_Index := 32;

   subtype Random_Bytes is Byte_Array (1 .. Random_Length);

   --  The special random a HelloRetryRequest carries in the ServerHello random
   --  field, RFC 8446 section 4.1.3. A ServerHello whose random is exactly this
   --  is a HelloRetryRequest, and this is the only way to tell.
   function Hello_Retry_Random return Random_Bytes;

   --  A parsed ClientHello.
   --
   --  Holds what arrived, not a normalization of it. The legacy session
   --  identifier is kept verbatim because a TLS 1.3 server must echo it exactly,
   --  and the offered lists are kept in order because order is preference order.
   type Client_Hello_Message is private;

   --  What a peer offered, read back.
   function Legacy_Version (Item : Client_Hello_Message) return SSL.Versions.Version_Value;
   function Random (Item : Client_Hello_Message) return Random_Bytes;
   function Session_Id (Item : Client_Hello_Message) return Byte_Array
     with Post => Session_Id'Result'Length <= Maximum_Session_Id_Length;
   function Offered_Suites (Item : Client_Hello_Message) return SSL.Cipher_Suites.Suite_List;
   function Offered_Groups (Item : Client_Hello_Message) return SSL.Supported_Groups.Group_List;
   function Offered_Schemes (Item : Client_Hello_Message)
     return SSL.Signature_Schemes.Scheme_List;
   function Offered_Protocols (Item : Client_Hello_Message) return SSL.ALPN.Protocol_List;
   function Offered_Versions (Item : Client_Hello_Message) return SSL.Versions.Version_Set;
   function Offered_Name (Item : Client_Hello_Message) return SSL.Server_Names.DNS_Name;
   function Extensions_Seen (Item : Client_Hello_Message) return SSL.Extensions.Seen_Set;

   --  Did the client offer a key share for this group, and what was it?
   --  @param Item  the message
   --  @param Group the group
   --  @param First out: the first octet of the share within the message
   --  @param Last  out: the last octet
   --  @return True when a share for that group was offered
   function Key_Share_For
     (Item  : Client_Hello_Message;
      Group : SSL.Supported_Groups.Named_Group;
      First : out Byte_Index;
      Last  : out Byte_Index) return Boolean;

   --  The groups a key share was offered for, in the order they appeared.
   function Key_Share_Groups (Item : Client_Hello_Message)
     return SSL.Supported_Groups.Group_List;

   --  The record_size_limit the peer asked for, or zero when it asked for none.
   function Requested_Record_Limit (Item : Client_Hello_Message) return Byte_Index;

   --  Did the client ask for a stapled certificate status?
   function Requests_Status (Item : Client_Hello_Message) return Boolean;

   --  The cookie a HelloRetryRequest asked to be echoed, within the message.
   function Cookie_Span
     (Item  : Client_Hello_Message;
      First : out Byte_Index;
      Last  : out Byte_Index) return Boolean;

   ---------------------------------------------------------------------------
   --  The pre_shared_key offer in a ClientHello
   ---------------------------------------------------------------------------

   --  How many identities one ClientHello may offer. The configured bound may
   --  be lower and is applied as well; this is the static ceiling the record
   --  below is sized by.
   Maximum_Offered_Identities : constant := 8;

   --  Did the client offer to resume?
   function Offers_PSK (Item : Client_Hello_Message) return Boolean;

   function PSK_Identity_Count (Item : Client_Hello_Message) return Natural;

   --  Where one offered ticket lies in the message octets.
   procedure PSK_Identity_Span
     (Item  : Client_Hello_Message;
      Index : Positive;
      First : out Byte_Index;
      Last  : out Byte_Index)
     with Pre => Index <= PSK_Identity_Count (Item);

   --  The age the client reports for that ticket, with the server's own
   --  obfuscation offset still added. Subtracting it is the server's business,
   --  because only the server knows what offset it issued.
   function PSK_Obfuscated_Age
     (Item : Client_Hello_Message; Index : Positive) return Interfaces.Unsigned_32
     with Pre => Index <= PSK_Identity_Count (Item);

   --  Where the binder for that identity lies. Positions in the two lists
   --  correspond, and a message whose lists are of different lengths is refused
   --  during the parse rather than leaving the correspondence to be assumed.
   procedure PSK_Binder_Span
     (Item  : Client_Hello_Message;
      Index : Positive;
      First : out Byte_Index;
      Last  : out Byte_Index)
     with Pre => Index <= PSK_Identity_Count (Item);

   --  Where the binders list begins -- at its own two-octet length prefix.
   --
   --  This is the one offset in the protocol that a parser must hand back
   --  rather than a value. RFC 8446 section 4.2.11.2 computes each binder over
   --  the ClientHello truncated immediately before this point, so a server
   --  verifying a binder needs to know where the message stops being covered.
   --  Recomputing it by re-encoding would mean re-encoding a message a hostile
   --  peer wrote, which would have to reproduce it octet for octet.
   --  @param Item the parsed ClientHello
   --  @return the index, within the message octets, of the first octet not
   --    covered by the binders
   function PSK_Binders_Offset (Item : Client_Hello_Message) return Byte_Index
     with Pre => Offers_PSK (Item);

   --  The key exchange modes the client will accept with a PSK.
   --
   --  This library resumes only with a fresh key exchange, so a client offering
   --  psk_ke alone is offering something that will not be taken up. That is a
   --  negotiation outcome rather than a failure: the server falls back to a full
   --  handshake.
   function Allows_PSK_With_DHE (Item : Client_Hello_Message) return Boolean;
   function Allows_PSK_Alone (Item : Client_Hello_Message) return Boolean;

   --  Parse a ClientHello body -- the octets after the four-octet header.
   --
   --  @param Data   the whole message, header included, because the returned
   --    spans index into it and the transcript hashes it entire
   --  @param Bounds the limits in force
   --  @param Item   out: the parsed message; meaningless when Error is set
   --  @param Error  out: No_Error, or the failure
   procedure Parse_Client_Hello
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out Client_Hello_Message;
      Error  : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  ClientHello encoding
   ---------------------------------------------------------------------------

   --  One key share to offer: a group and the public value for it.
   Maximum_Offered_Shares : constant := 4;
   Maximum_Share_Octets : constant Byte_Index := 512;

   type Key_Share_Entry is record
      Group  : SSL.Supported_Groups.Named_Group := SSL.Supported_Groups.X25519;
      Length : Byte_Index range 0 .. Maximum_Share_Octets := 0;
      Value  : Byte_Array (1 .. Maximum_Share_Octets) := [others => 0];
   end record;

   type Key_Share_List is array (1 .. Maximum_Offered_Shares) of Key_Share_Entry;

   --  Build a ClientHello from a configuration and the ephemeral material a
   --  connection has generated.
   --
   --  Extension order is fixed and deterministic, and `pre_shared_key` is
   --  always last -- RFC 8446 section 4.2.11 requires it, because the binder is
   --  computed over the message up to that point and an extension after it would
   --  not be covered. Determinism beyond that requirement is deliberate too: a
   --  ClientHello whose extension order varied would be a fingerprint that
   --  varied, and a peer that ordered its own differently would be
   --  distinguishable from this one for no reason.
   --
   --  The key shares are supplied rather than generated here, because generating
   --  them needs a random source and this package has none -- which is what
   --  keeps message encoding a pure function of its inputs and therefore
   --  reproducible in a test.
   --  @param Config       the client policy
   --  @param Random_Value the 32 random octets
   --  @param Session_Id   the legacy session identifier to send
   --  @param Shares       the key shares, one per group, in offer order
   --  @param Share_Count  how many of them
   --  @param Identity     the ticket to offer, empty to offer none. When it is
   --                      not empty the `pre_shared_key` extension is emitted
   --                      last, with the binder left as zeroes
   --  @param Obfuscated_Age the age to report for that ticket
   --  @param Binder_Length how wide the binder is -- the negotiated hash's
   --                      digest length -- or zero when no ticket is offered
   --  @param Binders_At   out: where the binders list begins, so that the
   --                      caller can hash the message up to that point,
   --                      compute the binder and write it in. The binder covers
   --                      the message up to here and cannot be computed before
   --                      the message exists, which is why this is reported
   --                      rather than left for the caller to find
   --  @param Cookie       the cookie a HelloRetryRequest asked to have echoed,
   --                      empty in a first ClientHello. It is echoed exactly and
   --                      never interpreted: it is the server's own state, and
   --                      a client that changed a single octet of it would be
   --                      handing back state the server cannot recognize
   --  @param Into         out: the complete message, header included
   --  @param Written      out: how many octets hold it
   --  @param Error        out: No_Error, or why it could not be built
   procedure Encode_Client_Hello
     (Config       : SSL.Configurations.Client_Configuration;
      Random_Value : Random_Bytes;
      Session_Id   : Byte_Array;
      Shares       : Key_Share_List;
      Share_Count  : Natural;
      Cookie       : Byte_Array;
      Identity     : Byte_Array;
      Obfuscated_Age : Interfaces.Unsigned_32;
      Binder_Length : Byte_Index;

      --  RFC 5077's ticket, for the TLS 1.2 half of a hello that offers both
      --  versions. Empty with `Offer_Legacy_Ticket` set is the request form.
      Legacy_Ticket : Byte_Array := [1 .. 0 => 0];
      Offer_Legacy_Ticket : Boolean := False;

      Into         : out Byte_Array;
      Written      : out Byte_Index;
      Binders_At   : out Byte_Index;
      Error        : out SSL.Errors.Error_Information)
     with Pre => Session_Id'Length <= Maximum_Session_Id_Length
                 and then Binder_Length in 0 | 32 | 48
                 and then Legacy_Ticket'Length <= 65_535;

   ---------------------------------------------------------------------------
   --  CertificateVerify content
   ---------------------------------------------------------------------------

   --  Which end is signing. Named by role rather than by direction because the
   --  context string is chosen by who is signing, not by who will read it.
   type Signing_Role is (Server_Signing, Client_Signing);

   --  The length of the context string for a role, for the contract below.
   function Context_Length (Role : Signing_Role) return Byte_Index;

   --  The exact octets a TLS 1.3 CertificateVerify signature covers
   --  (RFC 8446 section 4.4.3).
   --
   --  Sixty-four octets of 0x20, then the context string, then a single zero
   --  octet, then the transcript hash. Every part of that is load-bearing:
   --
   --    * The spaces and the zero separator exist so that the structure cannot
   --      collide with anything a TLS 1.2 signature covered, which is what
   --      stops a signature harvested from an old connection being replayed
   --      into a new one.
   --    * The context string differs between the two roles, so a server's
   --      signature cannot be replayed as a client's. Getting this backwards
   --      produces a handshake that works against itself and against nothing
   --      else, which is the failure mode worth designing against.
   --
   --  The strings are written out here rather than composed, because a
   --  composed one is a place for a stray space or a missing colon to hide.
   --  @param Role            whose signature this will be
   --  @param Transcript_Hash the transcript hash at the CertificateVerify point
   --  @return the octets to sign or verify
   function Certificate_Verify_Content
     (Role            : Signing_Role;
      Transcript_Hash : Byte_Array) return Byte_Array
     with Post => Certificate_Verify_Content'Result'Length
                  = 64 + Context_Length (Role) + 1 + Transcript_Hash'Length;

   ---------------------------------------------------------------------------
   --  ServerHello and HelloRetryRequest
   ---------------------------------------------------------------------------

   type Server_Hello_Message is private;

   function Legacy_Version (Item : Server_Hello_Message) return SSL.Versions.Version_Value;
   function Random (Item : Server_Hello_Message) return Random_Bytes;
   function Session_Id (Item : Server_Hello_Message) return Byte_Array;
   function Selected_Suite (Item : Server_Hello_Message) return SSL.Cipher_Suites.Cipher_Suite;
   function Selected_Version (Item : Server_Hello_Message) return SSL.Versions.Version_Value;
   function Extensions_Seen (Item : Server_Hello_Message) return SSL.Extensions.Seen_Set;

   --  Is this a HelloRetryRequest? Decided on the random field being exactly the
   --  RFC 8446 section 4.1.3 constant, which is the only signal there is.
   function Is_Hello_Retry_Request (Item : Server_Hello_Message) return Boolean;

   --  The server's key share, when it sent one.
   function Server_Key_Share
     (Item  : Server_Hello_Message;
      Group : out SSL.Supported_Groups.Named_Group;
      First : out Byte_Index;
      Last  : out Byte_Index) return Boolean;

   --  The group a HelloRetryRequest asked for. A HelloRetryRequest carries a
   --  bare group with no share, which is what distinguishes its key_share from a
   --  ServerHello's.
   function Retry_Group
     (Item  : Server_Hello_Message;
      Group : out SSL.Supported_Groups.Named_Group) return Boolean;

   function Cookie_Span
     (Item  : Server_Hello_Message;
      First : out Byte_Index;
      Last  : out Byte_Index) return Boolean;

   --  The pre_shared_key identity the server selected, when it resumed.
   function Selected_Identity
     (Item  : Server_Hello_Message;
      Index : out Natural) return Boolean;

   --  Parse a ServerHello.
   --
   --  `Legacy` says whether this is a TLS 1.2 hello, and it decides which
   --  extensions are permitted rather than anything about the fixed fields --
   --  those are identical in both versions. TLS 1.3 moved the server-name
   --  acknowledgement and the selected application protocol into
   --  EncryptedExtensions so that they are encrypted; TLS 1.2 has nothing to
   --  encrypt them with and leaves them here. A parser that used one context
   --  for both would refuse a conforming hello from one version or accept a
   --  non-conforming one from the other.
   procedure Parse_Server_Hello
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out Server_Hello_Message;
      Error  : out SSL.Errors.Error_Information;
      Legacy : Boolean := False);

   --  Build a ServerHello.
   --
   --  A ServerHello carries exactly three extensions in TLS 1.3:
   --  supported_versions, which is what actually selects the protocol;
   --  key_share, unless the handshake resumed on a PSK with no group; and
   --  pre_shared_key, when it did resume. Everything else a server has to say
   --  moves to EncryptedExtensions, where it is encrypted -- which is why this
   --  message is so much smaller than its TLS 1.2 ancestor.
   --
   --  The legacy session identifier is echoed rather than chosen. A client that
   --  sent one is running the middlebox compatibility mode of RFC 8446 appendix
   --  D.4, and echoing something else would break it; a client that sent none
   --  gets none back.
   --  @param Random_Value  the 32 random octets, which must not be the retry
   --                       constant -- use Encode_Hello_Retry_Request for that
   --  @param Session_Id    the client's legacy session identifier, echoed
   --  @param Suite         the selected cipher suite
   --  @param Share_Group   the group the server's key share belongs to
   --  @param Share_Value   the server's key share, empty when resuming
   --                       without a group
   --  @param Has_Identity  True when a PSK identity was selected
   --  @param Identity      which one, as an index into the client's list
   --  @param Into          out: the complete message, header included
   --  @param Written       out: how many octets hold it
   --  @param Error         out: No_Error, or why it could not be built
   procedure Encode_Server_Hello
     (Random_Value : Random_Bytes;
      Session_Id   : Byte_Array;
      Suite        : SSL.Cipher_Suites.Cipher_Suite;
      Share_Group  : SSL.Supported_Groups.Named_Group;
      Share_Value  : Byte_Array;
      Has_Identity : Boolean;
      Identity     : Natural;
      Into         : out Byte_Array;
      Written      : out Byte_Index;
      Error        : out SSL.Errors.Error_Information)
     with Pre => Session_Id'Length <= Maximum_Session_Id_Length
                 and then Share_Value'Length <= Maximum_Share_Octets;

   --  Build a HelloRetryRequest.
   --
   --  Structurally a ServerHello whose random is the RFC 8446 section 4.1.3
   --  constant, which is the only thing that distinguishes the two on the wire.
   --  It is a separate subprogram rather than a flag because the two messages
   --  differ in what they may carry -- a retry's key_share is a bare group with
   --  no share behind it -- and a flag would leave both shapes reachable from
   --  one body.
   --  @param Session_Id  the client's legacy session identifier, echoed
   --  @param Suite       the selected cipher suite, which the second ClientHello
   --                     must keep
   --  @param Group       the group the client is being asked to offer
   --  @param Cookie      the cookie to send, empty for none
   --  @param Into        out: the complete message, header included
   --  @param Written     out: how many octets hold it
   --  @param Error       out: No_Error, or why it could not be built
   procedure Encode_Hello_Retry_Request
     (Session_Id : Byte_Array;
      Suite      : SSL.Cipher_Suites.Cipher_Suite;
      Group      : SSL.Supported_Groups.Named_Group;
      Cookie     : Byte_Array;
      Into       : out Byte_Array;
      Written    : out Byte_Index;
      Error      : out SSL.Errors.Error_Information)
     with Pre => Session_Id'Length <= Maximum_Session_Id_Length;

   ---------------------------------------------------------------------------
   --  EncryptedExtensions
   ---------------------------------------------------------------------------

   --  Everything the server has to say that is not needed to decrypt what
   --  follows. It is the first encrypted message of the handshake, which is the
   --  whole point of it: in TLS 1.2 the negotiated application protocol and the
   --  requested server name travelled in clear, and here they do not.
   type Encrypted_Extensions_Message is private;

   function Extensions_Seen (Item : Encrypted_Extensions_Message) return SSL.Extensions.Seen_Set;

   --  The application protocol the server selected, when it selected one.
   function Selected_Protocol
     (Item     : Encrypted_Extensions_Message;
      Protocol : out SSL.ALPN.Protocol_Name) return Boolean;

   --  The record size limit the server asked for, or zero for none
   --  (RFC 8449).
   function Requested_Record_Limit (Item : Encrypted_Extensions_Message) return Byte_Index;

   --  Did the server acknowledge the server name indication? An empty
   --  server_name extension here is that acknowledgement (RFC 6066 section 3).
   function Acknowledged_Server_Name (Item : Encrypted_Extensions_Message) return Boolean;

   --  The groups the server says it supports, when it sent the list. A server
   --  may send supported_groups here to tell a client what to offer next time;
   --  it has no effect on this connection and is recorded, not acted on.
   function Offered_Groups
     (Item : Encrypted_Extensions_Message) return SSL.Supported_Groups.Group_List;

   procedure Parse_Encrypted_Extensions
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out Encrypted_Extensions_Message;
      Error  : out SSL.Errors.Error_Information);

   --  Build an EncryptedExtensions.
   --  @param Protocol       the selected application protocol
   --  @param Has_Protocol   False to send no ALPN extension at all
   --  @param Record_Limit   the limit to request, zero to send none
   --  @param Acknowledge_Name  True to send the empty server_name that
   --                        acknowledges the client's indication
   --  @param Into           out: the complete message, header included
   --  @param Written        out: how many octets hold it
   --  @param Error          out: No_Error, or why it could not be built
   procedure Encode_Encrypted_Extensions
     (Protocol         : SSL.ALPN.Protocol_Name;
      Has_Protocol     : Boolean;
      Record_Limit     : Byte_Index;
      Acknowledge_Name : Boolean;
      Into             : out Byte_Array;
      Written          : out Byte_Index;
      Error            : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  Certificate
   ---------------------------------------------------------------------------

   --  The most-bounded message in the protocol, because it is the largest thing
   --  a peer can make this endpoint hold before anything has been authenticated.
   --  Three separate limits apply: the whole message, each certificate in it,
   --  and how many there may be.
   Maximum_Chain_Entries : constant := 16;

   type Certificate_Message is private;

   --  The certificate_request_context this message answers. Empty in a server's
   --  Certificate; a copy of the CertificateRequest's context in a client's.
   function Request_Context_Span
     (Item  : Certificate_Message;
      First : out Byte_Index;
      Last  : out Byte_Index) return Boolean;

   function Entry_Count (Item : Certificate_Message) return Natural;

   --  Where the DER of one certificate lies in the message octets. A span, not
   --  a copy: cryptolib parses from the caller's buffer and the message outlives
   --  the parse because the transcript holds it.
   procedure Entry_Span
     (Item  : Certificate_Message;
      Index : Positive;
      First : out Byte_Index;
      Last  : out Byte_Index)
     with Pre => Index <= Entry_Count (Item);

   --  Where a stapled OCSP response for one certificate lies, when the peer
   --  attached one. TLS 1.3 puts the staple in the entry's own extensions, so
   --  every certificate may carry its own -- unlike TLS 1.2, where one response
   --  was attached to the whole message.
   function Entry_Status_Span
     (Item  : Certificate_Message;
      Index : Positive;
      First : out Byte_Index;
      Last  : out Byte_Index) return Boolean
     with Pre => Index <= Entry_Count (Item);

   procedure Parse_Certificate
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out Certificate_Message;
      Error  : out SSL.Errors.Error_Information);

   --  One certificate to send, as a span into a buffer the caller owns.
   type Certificate_Span is record
      First : Byte_Index := 1;
      Last  : Byte_Index := 0;
   end record;

   type Certificate_Span_List is array (1 .. Maximum_Chain_Entries) of Certificate_Span;

   --  Build a Certificate message.
   --
   --  An empty chain is permitted and meaningful: it is how a client declines a
   --  certificate request, and it is a different message from not sending one at
   --  all. Whether that decline is acceptable is the server's policy question,
   --  answered elsewhere.
   --  @param Chain        the buffer the certificates lie in
   --  @param Spans        where each of them lies, in order, leaf first
   --  @param Count        how many
   --  @param Context      the certificate_request_context to echo
   --  @param Staple       an OCSP response to attach to the leaf, empty for none
   --  @param Into         out: the complete message, header included
   --  @param Written      out: how many octets hold it
   --  @param Error        out: No_Error, or why it could not be built
   procedure Encode_Certificate
     (Chain   : Byte_Array;
      Spans   : Certificate_Span_List;
      Count   : Natural;
      Context : Byte_Array;
      Staple  : Byte_Array;
      Into    : out Byte_Array;
      Written : out Byte_Index;
      Error   : out SSL.Errors.Error_Information)
     with Pre => Count <= Maximum_Chain_Entries and then Context'Length <= 255;

   ---------------------------------------------------------------------------
   --  CertificateRequest
   ---------------------------------------------------------------------------

   type Certificate_Request_Message is private;

   --  The context to echo in the answering Certificate and to bind the
   --  CertificateVerify to. Opaque to the client: it copies it back unread.
   function Request_Context_Span
     (Item  : Certificate_Request_Message;
      First : out Byte_Index;
      Last  : out Byte_Index) return Boolean;

   function Offered_Schemes
     (Item : Certificate_Request_Message) return SSL.Signature_Schemes.Scheme_List;

   function Offered_Certificate_Schemes
     (Item : Certificate_Request_Message) return SSL.Signature_Schemes.Scheme_List;

   function Extensions_Seen (Item : Certificate_Request_Message) return SSL.Extensions.Seen_Set;

   --  Did the request name acceptable certificate authorities? The list itself
   --  is a hint for choosing among several credentials; it is recorded as
   --  present or absent here and the distinguished names are not decoded,
   --  because decoding a name is ASN.1 and ASN.1 lives in cryptolib.
   function Has_Certificate_Authorities (Item : Certificate_Request_Message) return Boolean;

   procedure Parse_Certificate_Request
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out Certificate_Request_Message;
      Error  : out SSL.Errors.Error_Information);

   --  Build a CertificateRequest.
   --  @param Context  the context, which must be unpredictable when
   --                  post-handshake authentication is possible and is simply
   --                  empty here, because this library does not do it
   --  @param Schemes  the signature schemes a client may sign with
   --  @param Certificate_Schemes  the schemes its certificates may be signed with
   procedure Encode_Certificate_Request
     (Context             : Byte_Array;
      Schemes             : SSL.Signature_Schemes.Scheme_List;
      Certificate_Schemes : SSL.Signature_Schemes.Scheme_List;
      Into                : out Byte_Array;
      Written             : out Byte_Index;
      Error               : out SSL.Errors.Error_Information)
     with Pre => Context'Length <= 255;

   ---------------------------------------------------------------------------
   --  CertificateVerify
   ---------------------------------------------------------------------------

   type Certificate_Verify_Message is private;

   function Scheme
     (Item : Certificate_Verify_Message) return SSL.Signature_Schemes.Signature_Scheme;

   --  True when the scheme octets named something this library implements. A
   --  peer signing under an unknown scheme cannot have signed under one that was
   --  offered, so this is a failure -- but it is reported by the caller, with
   --  the value, rather than losing the value here.
   function Scheme_Recognized (Item : Certificate_Verify_Message) return Boolean;

   function Scheme_Value
     (Item : Certificate_Verify_Message) return SSL.Signature_Schemes.Scheme_Value;

   procedure Signature_Span
     (Item  : Certificate_Verify_Message;
      First : out Byte_Index;
      Last  : out Byte_Index);

   procedure Parse_Certificate_Verify
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out Certificate_Verify_Message;
      Error  : out SSL.Errors.Error_Information);

   procedure Encode_Certificate_Verify
     (Scheme    : SSL.Signature_Schemes.Signature_Scheme;
      Signature : Byte_Array;
      Into      : out Byte_Array;
      Written   : out Byte_Index;
      Error     : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  Finished
   ---------------------------------------------------------------------------

   --  A Finished is a bare HMAC and nothing else, so there is no message type
   --  for it: parsing one produces the span its verify data occupies, and the
   --  comparison against the expected value is the caller's, made in constant
   --  time.
   --
   --  The length is not checked against the suite's digest length here. A
   --  Finished of the wrong length is a Finished that will not match, and
   --  refusing it early with a distinct failure would say which of the two went
   --  wrong.
   --  @param Data   the message octets
   --  @param Bounds the limits in force
   --  @param First  out: where the verify data begins
   --  @param Last   out: where it ends
   --  @param Error  out: No_Error, or the failure
   procedure Parse_Finished
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      First  : out Byte_Index;
      Last   : out Byte_Index;
      Error  : out SSL.Errors.Error_Information);

   procedure Encode_Finished
     (Verify_Data : Byte_Array;
      Into        : out Byte_Array;
      Written     : out Byte_Index;
      Error       : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  NewSessionTicket
   ---------------------------------------------------------------------------

   type New_Session_Ticket_Message is private;

   --  Seconds the ticket may be used for, as the server states it. RFC 8446
   --  section 4.6.1 caps this at seven days, and a server claiming more is
   --  refused rather than silently clamped: the two ends would then disagree
   --  about when the ticket died.
   function Lifetime (Item : New_Session_Ticket_Message) return Interfaces.Unsigned_32;

   --  The obfuscation offset added to the reported age when the ticket is
   --  offered again, so that an observer cannot correlate two offers by age.
   function Age_Add (Item : New_Session_Ticket_Message) return Interfaces.Unsigned_32;

   procedure Nonce_Span
     (Item  : New_Session_Ticket_Message;
      First : out Byte_Index;
      Last  : out Byte_Index);

   procedure Ticket_Span
     (Item  : New_Session_Ticket_Message;
      First : out Byte_Index;
      Last  : out Byte_Index);

   function Extensions_Seen (Item : New_Session_Ticket_Message) return SSL.Extensions.Seen_Set;

   procedure Parse_New_Session_Ticket
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out New_Session_Ticket_Message;
      Error  : out SSL.Errors.Error_Information);

   procedure Encode_New_Session_Ticket
     (Lifetime : Interfaces.Unsigned_32;
      Age_Add  : Interfaces.Unsigned_32;
      Nonce    : Byte_Array;
      Ticket   : Byte_Array;
      Into     : out Byte_Array;
      Written  : out Byte_Index;
      Error    : out SSL.Errors.Error_Information)
     with Pre => Nonce'Length <= 255;

   ---------------------------------------------------------------------------
   --  KeyUpdate
   ---------------------------------------------------------------------------

   --  One octet, and the only one-octet message in the protocol whose value
   --  changes what the receiver must do: `Update_Requested` obliges an answering
   --  KeyUpdate, and answering that one in turn would be an infinite exchange,
   --  so a reply is always `Update_Not_Requested`.
   type Key_Update_Request is (Update_Not_Requested, Update_Requested);

   procedure Parse_Key_Update
     (Data    : Byte_Array;
      Request : out Key_Update_Request;
      Error   : out SSL.Errors.Error_Information);

   procedure Encode_Key_Update
     (Request : Key_Update_Request;
      Into    : out Byte_Array;
      Written : out Byte_Index;
      Error   : out SSL.Errors.Error_Information);

private

   --  A span into the message being parsed, rather than a copy. The message
   --  octets outlive the parse in every caller -- the transcript needs them --
   --  so copying a key share or a cookie would be a second buffer to bound and
   --  to scrub for no gain.
   type Span is record
      Present : Boolean := False;
      First   : Byte_Index := 1;
      Last    : Byte_Index := 0;
   end record;

   Maximum_Recorded_Shares : constant := 8;

   type Share_Record is record
      Group : SSL.Supported_Groups.Named_Group := SSL.Supported_Groups.X25519;
      Body_Span : Span;
   end record;

   type Share_Array is array (1 .. Maximum_Recorded_Shares) of Share_Record;

   subtype Session_Id_Buffer is Byte_Array (1 .. Maximum_Session_Id_Length);

   type PSK_Offer is record
      Identity : Span;
      Binder   : Span;
      Age      : Interfaces.Unsigned_32 := 0;
   end record;

   type PSK_Offer_Array is array (1 .. Maximum_Offered_Identities) of PSK_Offer;

   type Client_Hello_Message is record
      Legacy       : SSL.Versions.Version_Value := SSL.Versions.Legacy_Record_Value;
      Random_Value : Random_Bytes := [others => 0];
      Id_Length    : Byte_Index range 0 .. Maximum_Session_Id_Length := 0;
      Id_Value     : Session_Id_Buffer := [others => 0];
      Suites       : SSL.Cipher_Suites.Suite_List := SSL.Cipher_Suites.No_Suites;
      Groups       : SSL.Supported_Groups.Group_List := SSL.Supported_Groups.No_Groups;
      Schemes      : SSL.Signature_Schemes.Scheme_List := SSL.Signature_Schemes.No_Schemes;
      Protocols    : SSL.ALPN.Protocol_List := SSL.ALPN.No_Protocols;
      Versions     : SSL.Versions.Version_Set := SSL.Versions.No_Versions;
      Name         : SSL.Server_Names.DNS_Name := SSL.Server_Names.No_Name;
      Seen         : SSL.Extensions.Seen_Set := SSL.Extensions.Empty_Set;
      Share_Count  : Natural range 0 .. Maximum_Recorded_Shares := 0;
      Shares       : Share_Array := [others => <>];
      Record_Limit : Byte_Index := 0;
      Status       : Boolean := False;
      Cookie       : Span;
      Has_PSK      : Boolean := False;
      Identity_Count : Natural range 0 .. Maximum_Offered_Identities := 0;
      Identities   : PSK_Offer_Array := [others => <>];
      Binders_At   : Byte_Index := 1;
      PSK_With_DHE : Boolean := False;
      PSK_Alone    : Boolean := False;
   end record;

   type Server_Hello_Message is record
      Legacy        : SSL.Versions.Version_Value := SSL.Versions.Legacy_Record_Value;
      Random_Value  : Random_Bytes := [others => 0];
      Id_Length     : Byte_Index range 0 .. Maximum_Session_Id_Length := 0;
      Id_Value      : Session_Id_Buffer := [others => 0];
      Suite         : SSL.Cipher_Suites.Cipher_Suite :=
        SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256;
      Version       : SSL.Versions.Version_Value := SSL.Versions.Legacy_Record_Value;
      Seen          : SSL.Extensions.Seen_Set := SSL.Extensions.Empty_Set;
      Retry         : Boolean := False;
      Has_Share     : Boolean := False;
      Share_Group   : SSL.Supported_Groups.Named_Group := SSL.Supported_Groups.X25519;
      Share_Body    : Span;
      Has_Retry_Group : Boolean := False;
      Cookie        : Span;
      Has_Identity  : Boolean := False;
      Identity      : Natural := 0;
   end record;

   type Encrypted_Extensions_Message is record
      Seen         : SSL.Extensions.Seen_Set := SSL.Extensions.Empty_Set;
      Has_Protocol : Boolean := False;
      Protocol     : SSL.ALPN.Protocol_Name := SSL.ALPN.No_Protocol;
      Record_Limit : Byte_Index := 0;
      Name_Acked   : Boolean := False;
      Groups       : SSL.Supported_Groups.Group_List := SSL.Supported_Groups.No_Groups;
   end record;

   type Certificate_Entry is record
      Body_Span   : Span;
      Status_Span : Span;
   end record;

   type Certificate_Entry_Array is array (1 .. Maximum_Chain_Entries) of Certificate_Entry;

   type Certificate_Message is record
      Context : Span;
      Count   : Natural range 0 .. Maximum_Chain_Entries := 0;
      Entries : Certificate_Entry_Array := [others => <>];
   end record;

   type Certificate_Request_Message is record
      Context           : Span;
      Schemes           : SSL.Signature_Schemes.Scheme_List := SSL.Signature_Schemes.No_Schemes;
      Certificate_Schemes : SSL.Signature_Schemes.Scheme_List :=
        SSL.Signature_Schemes.No_Schemes;
      Authorities       : Boolean := False;
      Seen              : SSL.Extensions.Seen_Set := SSL.Extensions.Empty_Set;
   end record;

   type Certificate_Verify_Message is record
      Recognized : Boolean := False;
      Named      : SSL.Signature_Schemes.Signature_Scheme :=
        SSL.Signature_Schemes.Ed25519;
      Raw        : SSL.Signature_Schemes.Scheme_Value := 0;
      Signature  : Span;
   end record;

   type New_Session_Ticket_Message is record
      Ticket_Lifetime : Interfaces.Unsigned_32 := 0;
      Ticket_Age_Add  : Interfaces.Unsigned_32 := 0;
      Nonce           : Span;
      Ticket          : Span;
      Seen            : SSL.Extensions.Seen_Set := SSL.Extensions.Empty_Set;
   end record;

end SSL.Handshake_Messages;
