with Ada.Streams;

with SSL.Versions;
with SSL.Wire;
with SSL.Server_Names;

package body SSL.TLS12.Messages is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type SSL.ALPN.ALPN_Requirement;
   use type SSL.Extensions.Message_Context;
   use type SSL.Handshake_Messages.Message_Type;
   use type SSL.Versions.Protocol_Version;

   package Messages renames SSL.Handshake_Messages;
   package Groups renames SSL.Supported_Groups;
   package Schemes renames SSL.Signature_Schemes;

   --  RFC 8422 section 5.4: the only curve type this library accepts. The
   --  explicit-prime and explicit-char2 forms let a peer specify arbitrary
   --  curve parameters, which is arbitrary arithmetic on values nobody has
   --  vetted, for no benefit anyone wants.
   Named_Curve_Type : constant Byte := 3;

   ---------------------------------------------------------------------------
   --  Accessors
   ---------------------------------------------------------------------------

   function Group (Item : Key_Exchange_Message) return Groups.Named_Group is (Item.Named);

   procedure Share_Span
     (Item  : Key_Exchange_Message;
      First : out Byte_Index;
      Last  : out Byte_Index)
   is
   begin
      First := Item.Share.First;
      Last := Item.Share.Last;
   end Share_Span;

   procedure Parameters_Span
     (Item  : Key_Exchange_Message;
      First : out Byte_Index;
      Last  : out Byte_Index)
   is
   begin
      First := Item.Parameters.First;
      Last := Item.Parameters.Last;
   end Parameters_Span;

   function Scheme (Item : Key_Exchange_Message) return Schemes.Signature_Scheme is
     (Item.Scheme);
   function Scheme_Recognized (Item : Key_Exchange_Message) return Boolean is
     (Item.Recognized);
   function Scheme_Value (Item : Key_Exchange_Message) return Schemes.Scheme_Value is
     (Item.Raw);

   procedure Signature_Span
     (Item  : Key_Exchange_Message;
      First : out Byte_Index;
      Last  : out Byte_Index)
   is
   begin
      First := Item.Signature.First;
      Last := Item.Signature.Last;
   end Signature_Span;

   ---------------------------------------------------------------------------
   --  Framing
   ---------------------------------------------------------------------------

   --  Check the header, the type, and that the declared body length equals the
   --  octets supplied. The same discipline as every other parser here: a
   --  truncated message must not parse as a shorter well-formed one.
   procedure Begin_Message
     (Data   : Byte_Array;
      Expect : Messages.Message_Type;
      Cursor : out SSL.Wire.Cursor;
      Error  : out SSL.Errors.Error_Information);

   procedure Begin_Message
     (Data   : Byte_Array;
      Expect : Messages.Message_Type;
      Cursor : out SSL.Wire.Cursor;
      Error  : out SSL.Errors.Error_Information)
   is

      Kind     : Messages.Message_Type;
      Raw      : Messages.Type_Value;
      Declared : Byte_Index;
   begin
      Cursor := SSL.Wire.Reader (Empty_Bytes);
      Messages.Parse_Header (Data, Kind, Raw, Declared, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      if Kind /= Expect then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Unexpected_Handshake_Message,
            Origin     => SSL.Errors.Peer_Message,
            Parameters =>
              [SSL.Errors.Text_Parameter ("expected", Messages.Image (Expect)),
               SSL.Errors.Numeric_Parameter ("received", Long_Long_Integer (Raw))]);
         return;
      end if;

      if Data'Length /= Messages.Header_Length + Declared then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      Cursor := SSL.Wire.Reader (Data'First + Messages.Header_Length, Data'Last);
   end Begin_Message;

   function Short_Message return SSL.Errors.Error_Information is
     (SSL.Errors.Make
        (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message));

   ---------------------------------------------------------------------------
   --  ServerKeyExchange
   ---------------------------------------------------------------------------

   procedure Parse_Key_Exchange
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out Key_Exchange_Message;
      Error  : out SSL.Errors.Error_Information)
   is
      pragma Unreferenced (Bounds);

      Cursor : SSL.Wire.Cursor;
      Reset  : Key_Exchange_Message;
      Value  : Natural;
      Length : Natural;

      Parameters_First : Byte_Index;
   begin
      Item := Reset;
      Begin_Message (Data, Messages.Server_Key_Exchange, Cursor, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      Parameters_First := Cursor.Position;

      SSL.Wire.Get_UInt8 (Data, Cursor, Value);
      if not SSL.Wire.Is_Valid (Cursor) or else Byte (Value) /= Named_Curve_Type then
         --  An explicit curve. Refused rather than implemented: it would mean
         --  running arithmetic over parameters a peer chose.
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Key_Exchange_Value_Invalid, SSL.Errors.Peer_Message);
         return;
      end if;

      SSL.Wire.Get_UInt16 (Data, Cursor, Value);
      if not SSL.Wire.Is_Valid (Cursor)
        or else not Groups.Group_For (Groups.Group_Value (Value), Item.Named)
      then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Selected_Group_Not_Offered,
            Origin     => SSL.Errors.Peer_Message,
            Parameters =>
              [SSL.Errors.Text_Parameter
                 ("group", Groups.Image (Groups.Group_Value (Value)))]);
         return;
      end if;

      SSL.Wire.Get_UInt8 (Data, Cursor, Length);
      if not SSL.Wire.Is_Valid (Cursor) or else Length = 0 then
         Error := Short_Message;
         Item := Reset;
         return;
      end if;

      --  The point's length is checked against the group's own width before
      --  anything downstream sees it, exactly as the TLS 1.3 key_share is: a
      --  share of the wrong size for the group it was offered under never
      --  reaches curve arithmetic.
      if Byte_Index (Length) /= Groups.Share_Length (Item.Named) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Key_Exchange_Value_Invalid, SSL.Errors.Peer_Message);
         Item := Reset;
         return;
      end if;

      SSL.Wire.Get_Span
        (Data, Cursor, Byte_Index (Length), Item.Share.First, Item.Share.Last);
      if not SSL.Wire.Is_Valid (Cursor) then
         Error := Short_Message;
         Item := Reset;
         return;
      end if;
      Item.Share.Present := True;

      --  The parameters end where the point ends. Recorded as a span, because
      --  the signature is over the octets that arrived.
      Item.Parameters :=
        (Present => True, First => Parameters_First, Last => Item.Share.Last);

      SSL.Wire.Get_UInt16 (Data, Cursor, Value);
      if not SSL.Wire.Is_Valid (Cursor) then
         Error := Short_Message;
         Item := Reset;
         return;
      end if;
      Item.Raw := Schemes.Scheme_Value (Value);
      Item.Recognized := Schemes.Scheme_For (Item.Raw, Item.Scheme);

      declare
         Signature : SSL.Wire.Cursor;
      begin
         SSL.Wire.Open_Vector_16 (Data, Cursor, 65_535, Signature);
         if not SSL.Wire.Is_Valid (Signature)
           or else SSL.Wire.Remaining (Signature) = 0
         then
            Error := Short_Message;
            Item := Reset;
            return;
         end if;
         SSL.Wire.Get_Span
           (Data, Signature, SSL.Wire.Remaining (Signature),
            Item.Signature.First, Item.Signature.Last);
         Item.Signature.Present := True;
      end;

      if not SSL.Wire.At_End (Cursor) then
         Error := Short_Message;
         Item := Reset;
      end if;
   end Parse_Key_Exchange;

   function Encoded_Parameters
     (Group : Groups.Named_Group;
      Share : Byte_Array) return Byte_Array
   is
      Value : constant Natural := Natural (Groups.Value_Of (Group));
   begin
      return [1 => Named_Curve_Type,
              2 => Byte (Value / 256),
              3 => Byte (Value mod 256),
              4 => Byte (Share'Length)]
        & Share;
   end Encoded_Parameters;

   procedure Encode_Key_Exchange
     (Group     : Groups.Named_Group;
      Share     : Byte_Array;
      Scheme    : Schemes.Signature_Scheme;
      Signature : Byte_Array;
      Into      : out Byte_Array;
      Written   : out Byte_Index;
      Error     : out SSL.Errors.Error_Information)
   is
      Parameters : constant Byte_Array := Encoded_Parameters (Group, Share);
      Emitter    : SSL.Wire.Emitter;
      Body_Mark  : Byte_Index;
      Inner      : Byte_Index;
   begin
      Into := [others => 0];
      Written := 0;
      Error := SSL.Errors.No_Error;

      Emitter := SSL.Wire.Writer (Into);
      SSL.Wire.Put_UInt8
        (Into, Emitter, Natural (Messages.Value_Of (Messages.Server_Key_Exchange)));
      SSL.Wire.Open_Vector_24 (Into, Emitter, Body_Mark);

      SSL.Wire.Put_Bytes (Into, Emitter, Parameters);
      SSL.Wire.Put_UInt16 (Into, Emitter, Natural (Schemes.Value_Of (Scheme)));
      SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
      SSL.Wire.Put_Bytes (Into, Emitter, Signature);
      SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);

      SSL.Wire.Close_Vector_24 (Into, Emitter, Body_Mark);

      if not SSL.Wire.Is_Valid (Emitter) then
         Into := [others => 0];
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Local_Implementation);
         return;
      end if;

      Written := SSL.Wire.Written (Emitter);
   end Encode_Key_Exchange;

   ---------------------------------------------------------------------------
   --  ServerHelloDone
   ---------------------------------------------------------------------------

   procedure Parse_Server_Hello_Done
     (Data  : Byte_Array;
      Error : out SSL.Errors.Error_Information)
   is
      Cursor : SSL.Wire.Cursor;
   begin
      Begin_Message (Data, Messages.Server_Hello_Done, Cursor, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      if not SSL.Wire.At_End (Cursor) then
         --  A ServerHelloDone with a body is a peer that has lost track of the
         --  protocol, and the next thing it sends cannot be trusted to be what
         --  this endpoint expects either.
         Error := Short_Message;
      end if;
   end Parse_Server_Hello_Done;

   procedure Encode_Server_Hello_Done
     (Into    : out Byte_Array;
      Written : out Byte_Index;
      Error   : out SSL.Errors.Error_Information)
   is
   begin
      Into := [others => 0];
      Written := 0;
      Error := SSL.Errors.No_Error;

      if Into'Length < Messages.Header_Length then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Local_Implementation);
         return;
      end if;

      Into (Into'First .. Into'First + Messages.Header_Length - 1) :=
        Messages.Encode_Header (Messages.Server_Hello_Done, 0);
      Written := Messages.Header_Length;
   end Encode_Server_Hello_Done;

   ---------------------------------------------------------------------------
   --  ClientKeyExchange
   ---------------------------------------------------------------------------

   procedure Parse_Client_Key_Exchange
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      First  : out Byte_Index;
      Last   : out Byte_Index;
      Error  : out SSL.Errors.Error_Information)
   is
      pragma Unreferenced (Bounds);

      Cursor : SSL.Wire.Cursor;
      Length : Natural;
   begin
      First := 1;
      Last := 0;

      Begin_Message (Data, Messages.Client_Key_Exchange, Cursor, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Wire.Get_UInt8 (Data, Cursor, Length);
      if not SSL.Wire.Is_Valid (Cursor) or else Length = 0 then
         Error := Short_Message;
         return;
      end if;

      SSL.Wire.Get_Span (Data, Cursor, Byte_Index (Length), First, Last);
      if not SSL.Wire.Is_Valid (Cursor) or else not SSL.Wire.At_End (Cursor) then
         First := 1;
         Last := 0;
         Error := Short_Message;
      end if;
   end Parse_Client_Key_Exchange;

   procedure Encode_Client_Key_Exchange
     (Share   : Byte_Array;
      Into    : out Byte_Array;
      Written : out Byte_Index;
      Error   : out SSL.Errors.Error_Information)
   is
      Emitter   : SSL.Wire.Emitter;
      Body_Mark : Byte_Index;
   begin
      Into := [others => 0];
      Written := 0;
      Error := SSL.Errors.No_Error;

      Emitter := SSL.Wire.Writer (Into);
      SSL.Wire.Put_UInt8
        (Into, Emitter, Natural (Messages.Value_Of (Messages.Client_Key_Exchange)));
      SSL.Wire.Open_Vector_24 (Into, Emitter, Body_Mark);
      SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Share'Length));
      SSL.Wire.Put_Bytes (Into, Emitter, Share);
      SSL.Wire.Close_Vector_24 (Into, Emitter, Body_Mark);

      if not SSL.Wire.Is_Valid (Emitter) then
         Into := [others => 0];
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Local_Implementation);
         return;
      end if;

      Written := SSL.Wire.Written (Emitter);
   end Encode_Client_Key_Exchange;

   ---------------------------------------------------------------------------
   --  Certificate
   ---------------------------------------------------------------------------

   procedure Parse_Certificate
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Spans  : out Chain_Span_Array;
      Count  : out Natural;
      Error  : out SSL.Errors.Error_Information)
   is
      Cursor  : SSL.Wire.Cursor;
      List    : SSL.Wire.Cursor;
      Allowed : constant Natural :=
        Natural'Min (Bounds.Maximum_Certificate_Count, Maximum_Chain_Entries);
   begin
      Spans := [others => <>];
      Count := 0;

      Begin_Message (Data, Messages.Certificate, Cursor, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Wire.Open_Vector_24
        (Data, Cursor, Byte_Index (Bounds.Maximum_Certificate_Message), List);
      if not SSL.Wire.Is_Valid (List) then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Limit_Exceeded,
            Origin     => SSL.Errors.Peer_Message,
            Parameters =>
              [SSL.Errors.Text_Parameter ("limit", "maximum certificate message")]);
         return;
      end if;

      while SSL.Wire.Is_Valid (List) and then not SSL.Wire.At_End (List) loop
         declare
            Der : SSL.Wire.Cursor;
         begin
            if Count = Allowed then
               --  Refused at the bound, before the next length is used for
               --  anything. A chain longer than the configured depth cannot
               --  validate, so reading the rest is work for a message that is
               --  already going to be rejected.
               Error := SSL.Errors.Limit_Failure
                 (SSL.Limits.Certificate_Count,
                  Long_Long_Integer (Allowed),
                  Long_Long_Integer (Count + 1));
               Count := 0;
               return;
            end if;

            SSL.Wire.Open_Vector_24
              (Data, List, Byte_Index (Bounds.Maximum_Certificate), Der);
            if not SSL.Wire.Is_Valid (Der) or else SSL.Wire.Remaining (Der) = 0 then
               Error := SSL.Errors.Make
                 (SSL.Errors.Code_Certificate_Malformed, SSL.Errors.Peer_Message);
               Count := 0;
               return;
            end if;

            Count := Count + 1;
            SSL.Wire.Get_Span
              (Data, Der, SSL.Wire.Remaining (Der),
               Spans (Count).First, Spans (Count).Last);
         end;
      end loop;

      if not SSL.Wire.Is_Valid (List) or else not SSL.Wire.At_End (Cursor) then
         Error := Short_Message;
         Count := 0;
      end if;
   end Parse_Certificate;

   ---------------------------------------------------------------------------
   --  Hellos
   ---------------------------------------------------------------------------

   package Ext renames SSL.Extensions;

   procedure Encode_Client_Hello
     (Config       : SSL.Configurations.Client_Configuration;
      Random_Value : Messages.Random_Bytes;
      Session_Id   : Byte_Array;
      Ticket       : Byte_Array := [1 .. 0 => 0];
      Offer_Ticket : Boolean := False;
      Into         : out Byte_Array;
      Written      : out Byte_Index;
      Error        : out SSL.Errors.Error_Information)
   is
      package Config_Package renames SSL.Configurations;
      package Suites renames SSL.Cipher_Suites;

      Emitter    : SSL.Wire.Emitter;
      Body_Mark  : Byte_Index;
      Block_Mark : Byte_Index;
      Ext_Mark   : Byte_Index;
      Inner      : Byte_Index;
      Deep       : Byte_Index;
   begin
      Into := [others => 0];
      Written := 0;
      Error := SSL.Errors.No_Error;

      Emitter := SSL.Wire.Writer (Into);
      SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Messages.Value_Of (Messages.Client_Hello)));
      SSL.Wire.Open_Vector_24 (Into, Emitter, Body_Mark);

      --  The version field means what it says here: TLS 1.2 negotiates in it,
      --  and there is no supported_versions to override it.
      SSL.Wire.Put_UInt16 (Into, Emitter, Natural (SSL.Versions.TLS_1_2_Value));
      SSL.Wire.Put_Bytes (Into, Emitter, Random_Value);
      SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Session_Id'Length));
      SSL.Wire.Put_Bytes (Into, Emitter, Session_Id);

      --  Only the TLS 1.2 suites. Offering a TLS 1.3 suite in a hello that
      --  cannot negotiate 1.3 would be offering something unusable.
      declare
         Offered : constant Suites.Suite_List := Config_Package.Cipher_Suites (Config);
      begin
         SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
         for Index in 1 .. Suites.Length (Offered) loop
            if Suites.Version_Of (Suites.Element (Offered, Index)) = SSL.Versions.TLS_1_2 then
               SSL.Wire.Put_UInt16
                 (Into, Emitter, Natural (Suites.Value_Of (Suites.Element (Offered, Index))));
            end if;
         end loop;
         SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
      end;

      SSL.Wire.Put_UInt8 (Into, Emitter, 1);
      SSL.Wire.Put_UInt8 (Into, Emitter, 0);          --  null compression only

      Ext.Open_Block (Into, Emitter, Block_Mark);

      if Config_Package.Sends_Server_Name (Config) then
         declare
            Name : constant Byte_Array :=
              SSL.Server_Names.Octets (Config_Package.Server_Name_Indication (Config));
         begin
            Ext.Open_Extension (Into, Emitter, Ext.Server_Name, Ext_Mark);
            SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
            SSL.Wire.Put_UInt8 (Into, Emitter, 0);
            SSL.Wire.Open_Vector_16 (Into, Emitter, Deep);
            SSL.Wire.Put_Bytes (Into, Emitter, Name);
            SSL.Wire.Close_Vector_16 (Into, Emitter, Deep);
            SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
            Ext.Close_Extension (Into, Emitter, Ext_Mark);
         end;
      end if;

      declare
         Offered : constant SSL.Supported_Groups.Group_List :=
           Config_Package.Groups (Config);
      begin
         Ext.Open_Extension (Into, Emitter, Ext.Supported_Groups, Ext_Mark);
         SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
         for Index in 1 .. Groups.Length (Offered) loop
            --  The finite-field groups have no ECDHE meaning, and this
            --  library's TLS 1.2 is ECDHE-only.
            if Groups.Is_Elliptic_Curve (Groups.Element (Offered, Index)) then
               SSL.Wire.Put_UInt16
                 (Into, Emitter,
                  Natural (Groups.Value_Of (Groups.Element (Offered, Index))));
            end if;
         end loop;
         SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
         Ext.Close_Extension (Into, Emitter, Ext_Mark);
      end;

      --  RFC 8422 section 5.1.2: the uncompressed form and nothing else.
      --  Compressed points need decompression, which is arithmetic on
      --  attacker-chosen values for no benefit anyone wants.
      Ext.Open_Extension (Into, Emitter, Ext.EC_Point_Formats, Ext_Mark);
      SSL.Wire.Put_UInt8 (Into, Emitter, 1);
      SSL.Wire.Put_UInt8 (Into, Emitter, 0);
      Ext.Close_Extension (Into, Emitter, Ext_Mark);

      declare
         Offered : constant Schemes.Scheme_List :=
           Config_Package.Signature_Schemes (Config);
      begin
         Ext.Open_Extension (Into, Emitter, Ext.Signature_Algorithms, Ext_Mark);
         SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
         for Index in 1 .. Schemes.Length (Offered) loop
            SSL.Wire.Put_UInt16
              (Into, Emitter,
               Natural (Schemes.Value_Of (Schemes.Element (Offered, Index))));
         end loop;
         SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
         Ext.Close_Extension (Into, Emitter, Ext_Mark);
      end;

      if Config_Package.ALPN_Requirement (Config) /= SSL.ALPN.Not_Offered then
         declare
            Offered : constant SSL.ALPN.Protocol_List :=
              Config_Package.Application_Protocols (Config);
         begin
            Ext.Open_Extension
              (Into, Emitter, Ext.Application_Layer_Protocol_Negotiation, Ext_Mark);
            SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
            for Index in 1 .. SSL.ALPN.Length (Offered) loop
               declare
                  Name : constant Byte_Array :=
                    SSL.ALPN.Value_Of (SSL.ALPN.Element (Offered, Index));
               begin
                  SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Name'Length));
                  SSL.Wire.Put_Bytes (Into, Emitter, Name);
               end;
            end loop;
            SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
            Ext.Close_Extension (Into, Emitter, Ext_Mark);
         end;
      end if;

      --  RFC 7627, and not optional. A server that does not echo it gets a
      --  failed handshake, because without it the master secret is not bound to
      --  this handshake.
      Ext.Open_Extension (Into, Emitter, Ext.Extended_Master_Secret, Ext_Mark);
      Ext.Close_Extension (Into, Emitter, Ext_Mark);

      --  RFC 5746, empty: this is an initial handshake and this library never
      --  renegotiates. Sending it says so; omitting it would leave a server
      --  unable to tell a modern client from an ancient one.
      Ext.Open_Extension (Into, Emitter, Ext.Renegotiation_Info, Ext_Mark);
      SSL.Wire.Put_UInt8 (Into, Emitter, 0);
      Ext.Close_Extension (Into, Emitter, Ext_Mark);

      --  RFC 5077. The extension body *is* the ticket, with no length prefix of
      --  its own: the extension's own length says how long it is. An empty one
      --  asks for a ticket; a full one offers the ticket it holds.
      if Offer_Ticket then
         Ext.Open_Extension (Into, Emitter, Ext.Session_Ticket, Ext_Mark);
         SSL.Wire.Put_Bytes (Into, Emitter, Ticket);
         Ext.Close_Extension (Into, Emitter, Ext_Mark);
      end if;

      Ext.Close_Block (Into, Emitter, Block_Mark);
      SSL.Wire.Close_Vector_24 (Into, Emitter, Body_Mark);

      if not SSL.Wire.Is_Valid (Emitter) then
         Into := [others => 0];
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Local_Implementation);
         return;
      end if;

      Written := SSL.Wire.Written (Emitter);
   end Encode_Client_Hello;

   procedure Encode_Server_Hello
     (Random_Value  : Messages.Random_Bytes;
      Session_Id    : Byte_Array;
      Suite         : SSL.Cipher_Suites.Cipher_Suite;
      Protocol      : SSL.ALPN.Protocol_Name;
      Has_Protocol  : Boolean;
      Acknowledge_Name : Boolean;
      Promise_Ticket   : Boolean := False;
      Into          : out Byte_Array;
      Written       : out Byte_Index;
      Error         : out SSL.Errors.Error_Information)
   is
      Emitter    : SSL.Wire.Emitter;
      Body_Mark  : Byte_Index;
      Block_Mark : Byte_Index;
      Ext_Mark   : Byte_Index;
      Inner      : Byte_Index;
   begin
      Into := [others => 0];
      Written := 0;
      Error := SSL.Errors.No_Error;

      Emitter := SSL.Wire.Writer (Into);
      SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Messages.Value_Of (Messages.Server_Hello)));
      SSL.Wire.Open_Vector_24 (Into, Emitter, Body_Mark);

      SSL.Wire.Put_UInt16 (Into, Emitter, Natural (SSL.Versions.TLS_1_2_Value));
      SSL.Wire.Put_Bytes (Into, Emitter, Random_Value);
      SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Session_Id'Length));
      SSL.Wire.Put_Bytes (Into, Emitter, Session_Id);
      SSL.Wire.Put_UInt16 (Into, Emitter, Natural (SSL.Cipher_Suites.Value_Of (Suite)));
      SSL.Wire.Put_UInt8 (Into, Emitter, 0);

      Ext.Open_Block (Into, Emitter, Block_Mark);

      if Acknowledge_Name then
         Ext.Open_Extension (Into, Emitter, Ext.Server_Name, Ext_Mark);
         Ext.Close_Extension (Into, Emitter, Ext_Mark);
      end if;

      Ext.Open_Extension (Into, Emitter, Ext.EC_Point_Formats, Ext_Mark);
      SSL.Wire.Put_UInt8 (Into, Emitter, 1);
      SSL.Wire.Put_UInt8 (Into, Emitter, 0);
      Ext.Close_Extension (Into, Emitter, Ext_Mark);

      if Has_Protocol then
         declare
            Name : constant Byte_Array := SSL.ALPN.Value_Of (Protocol);
         begin
            Ext.Open_Extension
              (Into, Emitter, Ext.Application_Layer_Protocol_Negotiation, Ext_Mark);
            SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
            SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Name'Length));
            SSL.Wire.Put_Bytes (Into, Emitter, Name);
            SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
            Ext.Close_Extension (Into, Emitter, Ext_Mark);
         end;
      end if;

      --  Echoed, and this server will not complete a handshake without it.
      Ext.Open_Extension (Into, Emitter, Ext.Extended_Master_Secret, Ext_Mark);
      Ext.Close_Extension (Into, Emitter, Ext_Mark);

      Ext.Open_Extension (Into, Emitter, Ext.Renegotiation_Info, Ext_Mark);
      SSL.Wire.Put_UInt8 (Into, Emitter, 0);
      Ext.Close_Extension (Into, Emitter, Ext_Mark);

      --  RFC 5077 section 3.1: in a ServerHello the extension is always empty,
      --  and its presence is the promise that a NewSessionTicket follows.
      if Promise_Ticket then
         Ext.Open_Extension (Into, Emitter, Ext.Session_Ticket, Ext_Mark);
         Ext.Close_Extension (Into, Emitter, Ext_Mark);
      end if;

      Ext.Close_Block (Into, Emitter, Block_Mark);
      SSL.Wire.Close_Vector_24 (Into, Emitter, Body_Mark);

      if not SSL.Wire.Is_Valid (Emitter) then
         Into := [others => 0];
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Local_Implementation);
         return;
      end if;

      Written := SSL.Wire.Written (Emitter);
   end Encode_Server_Hello;

   ---------------------------------------------------------------------------
   --  NewSessionTicket
   ---------------------------------------------------------------------------

   procedure Encode_New_Session_Ticket
     (Lifetime : Interfaces.Unsigned_32;
      Ticket   : Byte_Array;
      Into     : out Byte_Array;
      Written  : out Byte_Index;
      Error    : out SSL.Errors.Error_Information)
   is
      Emitter   : SSL.Wire.Emitter;
      Body_Mark : Byte_Index;
      Inner     : Byte_Index;
   begin
      Into := [others => 0];
      Written := 0;
      Error := SSL.Errors.No_Error;

      Emitter := SSL.Wire.Writer (Into);
      SSL.Wire.Put_UInt8
        (Into, Emitter, Natural (Messages.Value_Of (Messages.New_Session_Ticket)));
      SSL.Wire.Open_Vector_24 (Into, Emitter, Body_Mark);

      SSL.Wire.Put_UInt32 (Into, Emitter, Lifetime);
      SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
      SSL.Wire.Put_Bytes (Into, Emitter, Ticket);
      SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);

      SSL.Wire.Close_Vector_24 (Into, Emitter, Body_Mark);

      if not SSL.Wire.Is_Valid (Emitter) then
         Into := [others => 0];
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Local_Implementation);
         return;
      end if;

      Written := SSL.Wire.Written (Emitter);
   end Encode_New_Session_Ticket;

   procedure Parse_New_Session_Ticket
     (Data     : Byte_Array;
      Bounds   : SSL.Limits.Resource_Limits;
      Lifetime : out Interfaces.Unsigned_32;
      Ticket   : out Ticket_Span;
      Error    : out SSL.Errors.Error_Information)
   is
      Cursor : SSL.Wire.Cursor;
      Inner  : SSL.Wire.Cursor;
      Kind   : Messages.Message_Type;
      Raw    : Messages.Type_Value;
      Length : Byte_Index;
      Reset  : Ticket_Span;
   begin
      Lifetime := 0;
      Ticket := Reset;

      Messages.Parse_Header (Data, Kind, Raw, Length, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      if Kind /= Messages.New_Session_Ticket then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Unexpected_Handshake_Message, SSL.Errors.Peer_Message);
         return;
      end if;

      --  The declared body length against the octets supplied, before any field
      --  is read. Without it a truncated message parses as a shorter one.
      if Data'Length /= Messages.Header_Length + Length then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      Cursor := SSL.Wire.Reader (Data'First + Messages.Header_Length, Data'Last);
      SSL.Wire.Get_UInt32 (Data, Cursor, Lifetime);

      SSL.Wire.Open_Vector_16
        (Data, Cursor, Byte_Index (Bounds.Maximum_Ticket_Size), Inner);
      if not SSL.Wire.Is_Valid (Inner) then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Limit_Exceeded,
            Origin     => SSL.Errors.Peer_Message,
            Parameters => [SSL.Errors.Text_Parameter ("limit", "maximum ticket size")]);
         return;
      end if;

      --  A ticket of no octets is not a ticket. Refused rather than kept,
      --  because a cache holding one would offer it and every server would
      --  decline every connection that offered it.
      if SSL.Wire.Remaining (Inner) = 0 then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Ticket_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      SSL.Wire.Get_Span
        (Data, Inner, SSL.Wire.Remaining (Inner), Ticket.First, Ticket.Last);

      if not SSL.Wire.Is_Valid (Cursor) or else not SSL.Wire.At_End (Cursor) then
         --  Trailing octets inside a message are a protocol violation rather
         --  than padding.
         Ticket := Reset;
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message);
      end if;
   end Parse_New_Session_Ticket;

   ---------------------------------------------------------------------------
   --  Hello extensions
   ---------------------------------------------------------------------------

   procedure Read_Hello_Extensions
     (Data    : Byte_Array;
      Context : Ext.Message_Context;
      Bounds  : SSL.Limits.Resource_Limits;
      Item    : out Hello_Extensions;
      Error   : out SSL.Errors.Error_Information)
   is
      use type Ext.Extension_Kind;

      Cursor  : SSL.Wire.Cursor;
      Block   : SSL.Wire.Cursor;
      Seen    : Ext.Seen_Set := Ext.Empty_Set;
      Kind    : Ext.Extension_Kind;
      Value   : Ext.Extension_Value;
      Part    : SSL.Wire.Cursor;
      Present : Boolean;
      Reset   : Hello_Extensions;
      Skip    : Byte_Index;
   begin
      Item := Reset;
      Error := SSL.Errors.No_Error;

      --  Past the fixed fields to the extension block. The hello has already
      --  been parsed once for those fields, so nothing here re-derives them.
      Cursor := SSL.Wire.Reader (Data'First + Messages.Header_Length, Data'Last);
      SSL.Wire.Skip (Data, Cursor, 2 + 32);        --  version, random

      declare
         Length : Natural;
      begin
         SSL.Wire.Get_UInt8 (Data, Cursor, Length);
         SSL.Wire.Skip (Data, Cursor, Byte_Index (Length));

         if Context = Ext.In_Client_Hello then
            SSL.Wire.Get_UInt16 (Data, Cursor, Length);
            SSL.Wire.Skip (Data, Cursor, Byte_Index (Length));   --  suites
            SSL.Wire.Get_UInt8 (Data, Cursor, Length);
            SSL.Wire.Skip (Data, Cursor, Byte_Index (Length));   --  compression
         else
            SSL.Wire.Skip (Data, Cursor, 3);                     --  suite, compression
         end if;
      end;

      if not SSL.Wire.Is_Valid (Cursor) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      if SSL.Wire.At_End (Cursor) then
         --  No extension block at all. Every flag stays False, which is what
         --  makes the extended-master-secret check refuse.
         return;
      end if;

      Ext.Open_Block (Data, Cursor, Bounds, Block, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      loop
         Ext.Next (Data, Block, Context, Bounds, Seen, Kind, Value, Part, Present, Error);
         exit when SSL.Errors.Is_Error (Error) or else not Present;

         if Kind = Ext.Extended_Master_Secret then
            Item.Extended_Master_Secret := True;

         elsif Kind = Ext.Renegotiation_Info then
            Item.Renegotiation_Info := True;
            declare
               Length : Natural;
            begin
               SSL.Wire.Get_UInt8 (Data, Part, Length);
               --  A non-empty renegotiated_connection means this is a
               --  renegotiation, which this library does not do. Recorded so
               --  the state machine can refuse with a reason.
               Item.Renegotiation_Empty := SSL.Wire.Is_Valid (Part) and then Length = 0;
            end;

         elsif Kind = Ext.Session_Ticket then
            --  RFC 5077: the extension body is the ticket itself, with no
            --  length prefix inside it. An empty body is the request form and
            --  is not an error -- which is why presence and content are two
            --  separate answers here rather than one.
            Item.Session_Ticket_Present := True;
            if SSL.Wire.Remaining (Part) > 0 then
               SSL.Wire.Get_Span
                 (Data, Part, SSL.Wire.Remaining (Part),
                  Item.Session_Ticket.First, Item.Session_Ticket.Last);
            end if;

         elsif Kind = Ext.Application_Layer_Protocol_Negotiation
           and then Context /= Ext.In_Client_Hello
         then
            --  One name inside one list, which is what a server sends. A list
            --  of any other length is a server answering with something other
            --  than a selection.
            declare
               List   : SSL.Wire.Cursor;
               Length : Natural;
            begin
               SSL.Wire.Open_Vector_16 (Data, Part, 255, List);
               SSL.Wire.Get_UInt8 (Data, List, Length);
               if SSL.Wire.Is_Valid (List)
                 and then Length > 0
                 and then SSL.Wire.Remaining (List) = Byte_Index (Length)
               then
                  SSL.Wire.Get_Span
                    (Data, List, Byte_Index (Length),
                     Item.Protocol.First, Item.Protocol.Last);
                  Item.Protocol_Present := True;
               else
                  Error := SSL.Errors.Make
                    (SSL.Errors.Code_Handshake_Message_Malformed,
                     SSL.Errors.Peer_Message);
                  return;
               end if;
            end;

         elsif Kind = Ext.EC_Point_Formats then
            Item.Point_Formats_Present := True;
            declare
               List   : SSL.Wire.Cursor;
               Format : Natural;
            begin
               SSL.Wire.Open_Vector_8 (Data, Part, 255, List);
               while SSL.Wire.Is_Valid (List) and then not SSL.Wire.At_End (List) loop
                  SSL.Wire.Get_UInt8 (Data, List, Format);
                  exit when not SSL.Wire.Is_Valid (List);
                  if Format = 0 then
                     Item.Uncompressed_Points := True;
                  end if;
               end loop;
            end;
         end if;
      end loop;

      Skip := 0;
      pragma Unreferenced (Skip);
   end Read_Hello_Extensions;

end SSL.TLS12.Messages;
