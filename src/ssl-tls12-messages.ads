with Interfaces;

with SSL.ALPN;
with SSL.Cipher_Suites;
with SSL.Configurations;
with SSL.Errors;
with SSL.Extensions;
with SSL.Handshake_Messages;
with SSL.Limits;
with SSL.Signature_Schemes;
with SSL.Supported_Groups;

--  @summary The three handshake messages TLS 1.2 has and TLS 1.3 does not:
--  ServerKeyExchange, ServerHelloDone and ClientKeyExchange.
--
--  Everything else -- the framing, ClientHello, ServerHello, Certificate,
--  CertificateRequest, CertificateVerify, Finished -- is shared with TLS 1.3
--  and lives in `SSL.Handshake_Messages`. The messages here exist because
--  TLS 1.2 negotiates the key exchange in the handshake itself rather than in
--  the hello extensions, so the server has to send its ephemeral share in a
--  message of its own and sign it.
--
--  That signature is the whole security of a TLS 1.2 ECDHE handshake, and what
--  it covers is stated carefully in `SSL.TLS12.Key_Exchange_Signed_Content`:
--  the two randoms and the *exact* parameter octets. Re-encoding the parameters
--  to verify them would produce a signature over something the peer did not
--  sign, which is why the parser reports where they were rather than what they
--  said.
package SSL.TLS12.Messages is

   ---------------------------------------------------------------------------
   --  ServerKeyExchange
   ---------------------------------------------------------------------------

   type Key_Exchange_Message is private;

   --  The named curve the server chose.
   function Group (Item : Key_Exchange_Message) return SSL.Supported_Groups.Named_Group;

   --  Where the server's public point lies in the message octets.
   procedure Share_Span
     (Item  : Key_Exchange_Message;
      First : out Byte_Index;
      Last  : out Byte_Index);

   --  Where the signed ServerECDHParams lie: the curve type, the named curve
   --  and the length-prefixed point, exactly as they arrived.
   --
   --  A span rather than a re-encoding, because the signature is over the
   --  octets the peer sent. Re-encoding them and verifying against that would
   --  verify a signature over something else, and would pass whenever this
   --  library's encoder happened to agree with the peer's.
   procedure Parameters_Span
     (Item  : Key_Exchange_Message;
      First : out Byte_Index;
      Last  : out Byte_Index);

   function Scheme
     (Item : Key_Exchange_Message) return SSL.Signature_Schemes.Signature_Scheme;
   function Scheme_Recognized (Item : Key_Exchange_Message) return Boolean;
   function Scheme_Value
     (Item : Key_Exchange_Message) return SSL.Signature_Schemes.Scheme_Value;

   procedure Signature_Span
     (Item  : Key_Exchange_Message;
      First : out Byte_Index;
      Last  : out Byte_Index);

   --  Parse a ServerKeyExchange.
   --
   --  Only the named-curve form is accepted. The explicit-curve forms of
   --  RFC 8422 let a peer specify arbitrary curve parameters, which means
   --  arbitrary arithmetic on values nobody has vetted; they are refused rather
   --  than implemented.
   procedure Parse_Key_Exchange
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out Key_Exchange_Message;
      Error  : out SSL.Errors.Error_Information);

   --  Build one.
   --  @param Group     the named curve
   --  @param Share     the server's public point
   --  @param Scheme    the signature scheme
   --  @param Signature the signature over the randoms and the parameters
   procedure Encode_Key_Exchange
     (Group     : SSL.Supported_Groups.Named_Group;
      Share     : Byte_Array;
      Scheme    : SSL.Signature_Schemes.Signature_Scheme;
      Signature : Byte_Array;
      Into      : out Byte_Array;
      Written   : out Byte_Index;
      Error     : out SSL.Errors.Error_Information);

   --  The ServerECDHParams a server is about to sign, assembled from the values
   --  rather than from a message. Used on the sending side, where the message
   --  does not exist yet.
   function Encoded_Parameters
     (Group : SSL.Supported_Groups.Named_Group;
      Share : Byte_Array) return Byte_Array
     with Post => Encoded_Parameters'Result'Length = 4 + Share'Length;

   ---------------------------------------------------------------------------
   --  ServerHelloDone
   ---------------------------------------------------------------------------

   --  A message with no body at all. Parsed rather than assumed, because a
   --  ServerHelloDone with a body is a peer that has lost track of the
   --  protocol.
   procedure Parse_Server_Hello_Done
     (Data  : Byte_Array;
      Error : out SSL.Errors.Error_Information);

   procedure Encode_Server_Hello_Done
     (Into    : out Byte_Array;
      Written : out Byte_Index;
      Error   : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  ClientKeyExchange
   ---------------------------------------------------------------------------

   --  For an ECDHE suite this is one length-prefixed public point and nothing
   --  else. The static-RSA form, which carries an encrypted premaster secret,
   --  is not implemented: it has no forward secrecy and it is the shape every
   --  Bleichenbacher variant attacks.
   procedure Parse_Client_Key_Exchange
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      First  : out Byte_Index;
      Last   : out Byte_Index;
      Error  : out SSL.Errors.Error_Information);

   procedure Encode_Client_Key_Exchange
     (Share   : Byte_Array;
      Into    : out Byte_Array;
      Written : out Byte_Index;
      Error   : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  Hellos
   ---------------------------------------------------------------------------

   --  Build a TLS 1.2 ClientHello.
   --
   --  A different encoder from the TLS 1.3 one, and not a mode of it. A TLS 1.2
   --  hello carries no key_share and no supported_versions; it carries
   --  ec_point_formats, extended_master_secret and an empty renegotiation_info,
   --  none of which appears in a TLS 1.3 hello. Trying to serve both from one
   --  encoder would mean a run of conditionals around every extension.
   --  @param Ticket       a ticket to offer, or an empty array to ask for one
   --  @param Offer_Ticket whether to send `session_ticket` at all. A client that
   --                      does not want tickets omits it, and a server that
   --                      never sees it never issues one.
   procedure Encode_Client_Hello
     (Config       : SSL.Configurations.Client_Configuration;
      Random_Value : SSL.Handshake_Messages.Random_Bytes;
      Session_Id   : Byte_Array;
      Ticket       : Byte_Array := [1 .. 0 => 0];
      Offer_Ticket : Boolean := False;
      Into         : out Byte_Array;
      Written      : out Byte_Index;
      Error        : out SSL.Errors.Error_Information)
     with Pre => Session_Id'Length <= 32 and then Ticket'Length <= 65_535;

   --  Build a TLS 1.2 ServerHello.
   --  @param Promise_Ticket whether to include an empty `session_ticket`, which
   --                        is RFC 5077's announcement that a NewSessionTicket
   --                        will follow. A server that sends the ticket without
   --                        the announcement leaves its peer with a message it
   --                        did not agree to receive.
   procedure Encode_Server_Hello
     (Random_Value  : SSL.Handshake_Messages.Random_Bytes;
      Session_Id    : Byte_Array;
      Suite         : SSL.Cipher_Suites.Cipher_Suite;
      Protocol      : SSL.ALPN.Protocol_Name;
      Has_Protocol  : Boolean;
      Acknowledge_Name : Boolean;
      Promise_Ticket   : Boolean := False;
      Into          : out Byte_Array;
      Written       : out Byte_Index;
      Error         : out SSL.Errors.Error_Information)
     with Pre => Session_Id'Length <= 32;

   ---------------------------------------------------------------------------
   --  NewSessionTicket
   ---------------------------------------------------------------------------

   --  RFC 5077's NewSessionTicket, which shares a message type with TLS 1.3's
   --  and shares nothing else. TLS 1.2's body is a lifetime hint and the ticket;
   --  TLS 1.3's adds an age offset, a nonce and an extension block. Parsing one
   --  with the other's parser reads the ticket length out of the middle of the
   --  ticket.
   --
   --      struct {
   --          uint32 ticket_lifetime_hint;
   --          opaque ticket<0..2^16-1>;
   --      } NewSessionTicket;

   --  Where the ticket lies inside the message octets.
   type Ticket_Span is record
      First : Byte_Index := 1;
      Last  : Byte_Index := 0;
   end record;

   --  @param Lifetime how long the server suggests the ticket be kept, seconds
   --  @param Ticket   the sealed ticket
   procedure Encode_New_Session_Ticket
     (Lifetime : Interfaces.Unsigned_32;
      Ticket   : Byte_Array;
      Into     : out Byte_Array;
      Written  : out Byte_Index;
      Error    : out SSL.Errors.Error_Information)
     with Pre => Ticket'Length in 1 .. 65_535;

   --  @param Data     the message
   --  @param Bounds   the limits in force
   --  @param Lifetime out: the server's suggested lifetime in seconds
   --  @param Ticket   out: where the ticket is
   --  @param Error    out: No_Error, or the failure
   procedure Parse_New_Session_Ticket
     (Data     : Byte_Array;
      Bounds   : SSL.Limits.Resource_Limits;
      Lifetime : out Interfaces.Unsigned_32;
      Ticket   : out Ticket_Span;
      Error    : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  Certificate
   ---------------------------------------------------------------------------

   --  TLS 1.2's Certificate is a three-octet list length and then a run of
   --  three-octet-prefixed certificates. It has no certificate_request_context
   --  and no per-entry extensions -- TLS 1.3 added both -- so the TLS 1.3
   --  parser cannot read one. Trying to shim the shapes together reads the
   --  first octets of the next certificate as an extension block, which is how
   --  this parser came to be written rather than reused.
   Maximum_Chain_Entries : constant := 16;

   type Chain_Span is record
      First : Byte_Index := 1;
      Last  : Byte_Index := 0;
   end record;

   type Chain_Span_Array is array (1 .. Maximum_Chain_Entries) of Chain_Span;

   --  Parse one, reporting where each certificate lies in the message octets.
   --  @param Data   the message
   --  @param Bounds the limits in force
   --  @param Spans  out: where each certificate is
   --  @param Count  out: how many there are
   --  @param Error  out: No_Error, or the failure
   procedure Parse_Certificate
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Spans  : out Chain_Span_Array;
      Count  : out Natural;
      Error  : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  The hello extensions TLS 1.2 needs
   ---------------------------------------------------------------------------

   --  What a TLS 1.2 hello said about the things this library insists on.
   type Hello_Extensions is record
      --  RFC 7627. Mandatory here: without it the master secret is not bound to
      --  the handshake and the triple-handshake attack works.
      Extended_Master_Secret : Boolean := False;

      --  RFC 5746. Parsed so that an initial handshake can be told from a
      --  renegotiation, and acted on only to refuse the latter.
      Renegotiation_Info     : Boolean := False;
      Renegotiation_Empty    : Boolean := True;

      --  RFC 8422. Only the uncompressed form is accepted; the compressed ones
      --  need point decompression, which is arithmetic on attacker-chosen
      --  values for no benefit.
      Uncompressed_Points    : Boolean := False;
      Point_Formats_Present  : Boolean := False;

      --  RFC 5077. Three states, not two: absent, present and empty, and
      --  present with a ticket in it. In a ClientHello the empty form asks for
      --  a ticket and the non-empty form offers one; in a ServerHello only the
      --  empty form is legal, and it promises a NewSessionTicket to come.
      Session_Ticket_Present : Boolean := False;
      Session_Ticket         : Ticket_Span;

      --  RFC 7301, in a ServerHello: the one protocol the server selected. In
      --  a ClientHello the list is read by the TLS 1.3 parser, which both
      --  versions share; here only the server's single answer is needed.
      Protocol_Present : Boolean := False;
      Protocol         : Ticket_Span;
   end record;

   --  Read the extensions of a hello that has already been parsed for its
   --  fixed fields, reporting only the four things restricted TLS 1.2 cares
   --  about. Everything else was recorded by the parser and is acted on
   --  nowhere.
   --  @param Data    the whole hello message
   --  @param Context which hello this is
   --  @param Bounds  the limits in force
   --  @param Item    out: what it said
   --  @param Error   out: No_Error, or a malformed block
   procedure Read_Hello_Extensions
     (Data    : Byte_Array;
      Context : SSL.Extensions.Message_Context;
      Bounds  : SSL.Limits.Resource_Limits;
      Item    : out Hello_Extensions;
      Error   : out SSL.Errors.Error_Information);

private

   type Span is record
      Present : Boolean := False;
      First   : Byte_Index := 1;
      Last    : Byte_Index := 0;
   end record;

   type Key_Exchange_Message is record
      Named      : SSL.Supported_Groups.Named_Group := SSL.Supported_Groups.Secp256r1;
      Share      : Span;
      Parameters : Span;
      Recognized : Boolean := False;
      Scheme     : SSL.Signature_Schemes.Signature_Scheme :=
        SSL.Signature_Schemes.ECDSA_Secp256r1_SHA256;
      Raw        : SSL.Signature_Schemes.Scheme_Value := 0;
      Signature  : Span;
   end record;

end SSL.TLS12.Messages;
