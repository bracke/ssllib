with Interfaces;

with SSL.Errors;
with SSL.Limits;
with SSL.Wire;

--  @summary The closed extension registry: which extensions exist, what their
--  wire identifiers are, and which handshake messages each may appear in.
--
--  Closed, and deliberately so. There is no registration call, no table a caller
--  can add to, and no plugin seam. An extension this library does not know is an
--  extension it does not act on -- its identifier is kept for diagnostics and
--  its body is skipped, which is what RFC 8446 section 4.2 requires of an
--  unrecognized extension in a ClientHello, and what makes an unrecognized
--  extension anywhere else a protocol violation rather than a shrug.
--
--  Three rules are enforced here rather than at each call site, because each of
--  them is the kind of check that is correct in nine parsers and forgotten in
--  the tenth:
--
--    * **No duplicates.** RFC 8446 section 4.2: "There MUST NOT be more than one
--      extension of the same type in a given extension block." A second
--      occurrence is refused, not merged and not last-wins. Last-wins is how a
--      peer gets to show one value to a checker and another to the state machine.
--    * **Exact contexts.** Each extension names the messages it may appear in.
--      `key_share` in an EncryptedExtensions is not an oddity to tolerate; it is
--      a message from an implementation that has misunderstood the protocol, or
--      from something trying to find out what this one tolerates.
--    * **No unsolicited responses.** A server may only send back an extension
--      the client offered. Checking that is the caller's job -- only the caller
--      knows what it sent -- but the shape for doing it is here, in Seen_Set.
private package SSL.Extensions is

   ---------------------------------------------------------------------------
   --  Identity
   ---------------------------------------------------------------------------

   --  The extensions this library recognizes.
   --
   --  Some of these are recognized only in order to be refused: early_data and
   --  post_handshake_auth are features this library does not implement, and a
   --  peer offering one gets a named failure rather than a silent skip.
   type Extension_Kind is
     (--  TLS 1.3, RFC 8446 section 4.2
      Server_Name,
      Status_Request,
      Supported_Groups,
      Signature_Algorithms,
      Application_Layer_Protocol_Negotiation,
      Signature_Algorithms_Cert,
      Supported_Versions,
      PSK_Key_Exchange_Modes,
      Key_Share,
      Pre_Shared_Key,
      Cookie,
      Certificate_Authorities,

      --  RFC 8449
      Record_Size_Limit,

      --  Restricted TLS 1.2
      Extended_Master_Secret,      --  RFC 7627, mandatory here
      Renegotiation_Info,          --  RFC 5746, parsed then never acted on
      Session_Ticket,              --  RFC 5077, stateless tickets only
      EC_Point_Formats,            --  RFC 8422, uncompressed only

      --  Recognized in order to refuse.
      Early_Data,
      Post_Handshake_Auth,

      --  Not a wire value: what an identifier this library does not know maps
      --  to. The number is preserved alongside it.
      Unknown_Extension);

   type Extension_Value is new Interfaces.Unsigned_16;

   --  Wire identifiers, written out rather than derived from positions.
   Server_Name_Value              : constant Extension_Value := 0;
   Status_Request_Value           : constant Extension_Value := 5;
   Supported_Groups_Value         : constant Extension_Value := 10;
   EC_Point_Formats_Value         : constant Extension_Value := 11;
   Signature_Algorithms_Value     : constant Extension_Value := 13;
   ALPN_Value                     : constant Extension_Value := 16;
   Extended_Master_Secret_Value   : constant Extension_Value := 23;
   Record_Size_Limit_Value        : constant Extension_Value := 28;
   Session_Ticket_Value           : constant Extension_Value := 35;
   Pre_Shared_Key_Value           : constant Extension_Value := 41;
   Early_Data_Value               : constant Extension_Value := 42;
   Supported_Versions_Value       : constant Extension_Value := 43;
   Cookie_Value                   : constant Extension_Value := 44;
   PSK_Key_Exchange_Modes_Value   : constant Extension_Value := 45;
   Certificate_Authorities_Value  : constant Extension_Value := 47;
   Post_Handshake_Auth_Value      : constant Extension_Value := 49;
   Signature_Algorithms_Cert_Value : constant Extension_Value := 50;
   Key_Share_Value                : constant Extension_Value := 51;
   Renegotiation_Info_Value       : constant Extension_Value := 16#FF01#;

   function Value_Of (Item : Extension_Kind) return Extension_Value
     with Pre => Item /= Unknown_Extension;

   function Kind_For (Item : Extension_Value) return Extension_Kind;

   --  Is this an extension this library recognizes only in order to refuse it?
   --  Distinguishes "we will not do that" from "we have not heard of that".
   function Is_Refused (Item : Extension_Kind) return Boolean;

   function Image (Item : Extension_Kind) return String;
   function Image (Item : Extension_Value) return String;

   ---------------------------------------------------------------------------
   --  Contexts
   ---------------------------------------------------------------------------

   --  The messages an extension block can appear in.
   --
   --  Three of these look like duplicates and are not. HelloRetryRequest is
   --  separate from ServerHello even though they share a wire encoding, because
   --  a retry may carry a cookie and a bare key_share group and a ServerHello
   --  may not. And a TLS 1.2 ServerHello is separate from a TLS 1.3 one because
   --  the two versions put different things in it: TLS 1.3 moved the server
   --  name acknowledgement and the selected application protocol into
   --  EncryptedExtensions so that they are encrypted, and TLS 1.2 has nothing
   --  to encrypt them with, so they stay in the hello.
   type Message_Context is
     (In_Client_Hello,
      In_Server_Hello,
      In_Legacy_Server_Hello,
      In_Hello_Retry_Request,
      In_Encrypted_Extensions,
      In_Certificate,
      In_Certificate_Request,
      In_New_Session_Ticket);

   function Image (Item : Message_Context) return String;

   --  May this extension appear in this message?
   --
   --  The table is RFC 8446 section 4.2's, plus RFC 8449 for record_size_limit
   --  and the TLS 1.2 extensions in their own messages. An extension with no
   --  permitted context at all -- the refused ones -- answers False everywhere.
   function Permitted (Item : Extension_Kind; Context : Message_Context) return Boolean;

   ---------------------------------------------------------------------------
   --  Duplicate and solicitation tracking
   ---------------------------------------------------------------------------

   --  What has been seen in one extension block, and what was offered in a
   --  ClientHello. One value serves both because they are the same shape: a set
   --  of extension kinds, plus the unknown identifiers, kept for diagnostics.
   type Seen_Set is private;

   --  How many unknown identifiers are remembered. Beyond this they are counted
   --  but not listed, because a peer that sends a thousand unknown extensions
   --  must not make this endpoint allocate for them.
   Remembered_Unknown : constant := 8;

   function Empty_Set return Seen_Set;

   procedure Include (Item : in out Seen_Set; Kind : Extension_Kind; Value : Extension_Value);

   function Contains (Item : Seen_Set; Kind : Extension_Kind) return Boolean;

   --  Was this exact numeric identifier seen? For checking that a server's
   --  response to an extension this library does not implement was solicited,
   --  which cannot be answered by kind alone.
   function Contains (Item : Seen_Set; Value : Extension_Value) return Boolean;

   function Unknown_Count (Item : Seen_Set) return Natural;
   function Unknown_At (Item : Seen_Set; Index : Positive) return Extension_Value
     with Pre => Index <= Natural'Min (Unknown_Count (Item), Remembered_Unknown);

   --  Comma-separated names of everything in the set, for a diagnostic.
   function Image (Item : Seen_Set) return String;

   ---------------------------------------------------------------------------
   --  Reading
   ---------------------------------------------------------------------------

   --  Open the extension block at the cursor: a two-octet total length followed
   --  by the extensions themselves.
   --
   --  A message with no extension block at all is not the same as one with an
   --  empty block, and both occur, so the caller says which it will accept.
   --  @param Data     the message octets
   --  @param Cursor   the cursor, advanced past the whole block
   --  @param Bounds   the limits in force
   --  @param Block    out: a cursor over the block's contents
   --  @param Error    out: No_Error, or a limit or decode failure
   procedure Open_Block
     (Data   : Byte_Array;
      Cursor : in out SSL.Wire.Cursor;
      Bounds : SSL.Limits.Resource_Limits;
      Block  : out SSL.Wire.Cursor;
      Error  : out SSL.Errors.Error_Information);

   --  Read the next extension from an opened block.
   --
   --  Enforces the duplicate rule and the context rule before the caller sees
   --  the body, so a caller that forgets to check either still cannot act on a
   --  malformed block. The body cursor is confined to the extension's own
   --  length, so a parser cannot read past it into the next extension.
   --  @param Data      the message octets
   --  @param Block     the block cursor, advanced past this extension
   --  @param Context   which message this block belongs to
   --  @param Bounds    the limits in force
   --  @param Seen      in out: the duplicate tracker for this block
   --  @param Kind      out: the recognized kind, or Unknown_Extension
   --  @param Value     out: the numeric identifier as it appeared
   --  @param Body_Part out: a cursor over this extension's body
   --  @param Present   out: False when the block is exhausted
   --  @param Error     out: No_Error, or the failure
   procedure Next
     (Data      : Byte_Array;
      Block     : in out SSL.Wire.Cursor;
      Context   : Message_Context;
      Bounds    : SSL.Limits.Resource_Limits;
      Seen      : in out Seen_Set;
      Kind      : out Extension_Kind;
      Value     : out Extension_Value;
      Body_Part : out SSL.Wire.Cursor;
      Present   : out Boolean;
      Error     : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  Writing
   ---------------------------------------------------------------------------

   --  Reserve the block's two-octet length prefix.
   procedure Open_Block
     (Data : in out Byte_Array; Emitter : in out SSL.Wire.Emitter; Mark : out Byte_Index);

   procedure Close_Block
     (Data : in out Byte_Array; Emitter : in out SSL.Wire.Emitter; Mark : Byte_Index);

   --  Begin one extension: its identifier and its reserved length prefix.
   procedure Open_Extension
     (Data    : in out Byte_Array;
      Emitter : in out SSL.Wire.Emitter;
      Kind    : Extension_Kind;
      Mark    : out Byte_Index)
     with Pre => Kind /= Unknown_Extension;

   procedure Close_Extension
     (Data : in out Byte_Array; Emitter : in out SSL.Wire.Emitter; Mark : Byte_Index);

private

   type Kind_Flags is array (Extension_Kind) of Boolean;

   type Unknown_Array is array (1 .. Remembered_Unknown) of Extension_Value;

   type Seen_Set is record
      Present : Kind_Flags := [others => False];
      Count   : Natural := 0;
      Unknown : Unknown_Array := [others => 0];
   end record;

end SSL.Extensions;
