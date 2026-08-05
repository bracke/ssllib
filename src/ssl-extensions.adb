package body SSL.Extensions is

   --------------
   -- Value_Of --
   --------------

   function Value_Of (Item : Extension_Kind) return Extension_Value is
   begin
      case Item is
         when Server_Name                            => return Server_Name_Value;
         when Status_Request                         => return Status_Request_Value;
         when Supported_Groups                       => return Supported_Groups_Value;
         when Signature_Algorithms                   => return Signature_Algorithms_Value;
         when Application_Layer_Protocol_Negotiation => return ALPN_Value;
         when Signature_Algorithms_Cert              => return Signature_Algorithms_Cert_Value;
         when Supported_Versions                     => return Supported_Versions_Value;
         when PSK_Key_Exchange_Modes                 => return PSK_Key_Exchange_Modes_Value;
         when Key_Share                              => return Key_Share_Value;
         when Pre_Shared_Key                         => return Pre_Shared_Key_Value;
         when Cookie                                 => return Cookie_Value;
         when Certificate_Authorities                => return Certificate_Authorities_Value;
         when Record_Size_Limit                      => return Record_Size_Limit_Value;
         when Extended_Master_Secret                 => return Extended_Master_Secret_Value;
         when Renegotiation_Info                     => return Renegotiation_Info_Value;
         when Session_Ticket                         => return Session_Ticket_Value;
         when EC_Point_Formats                       => return EC_Point_Formats_Value;
         when Early_Data                             => return Early_Data_Value;
         when Post_Handshake_Auth                    => return Post_Handshake_Auth_Value;
         when Unknown_Extension                      => return 0;
      end case;
   end Value_Of;

   --------------
   -- Kind_For --
   --------------

   function Kind_For (Item : Extension_Value) return Extension_Kind is
   begin
      case Item is
         when Server_Name_Value              => return Server_Name;
         when Status_Request_Value           => return Status_Request;
         when Supported_Groups_Value         => return Supported_Groups;
         when Signature_Algorithms_Value     => return Signature_Algorithms;
         when ALPN_Value                     => return Application_Layer_Protocol_Negotiation;
         when Signature_Algorithms_Cert_Value => return Signature_Algorithms_Cert;
         when Supported_Versions_Value       => return Supported_Versions;
         when PSK_Key_Exchange_Modes_Value   => return PSK_Key_Exchange_Modes;
         when Key_Share_Value                => return Key_Share;
         when Pre_Shared_Key_Value           => return Pre_Shared_Key;
         when Cookie_Value                   => return Cookie;
         when Certificate_Authorities_Value  => return Certificate_Authorities;
         when Record_Size_Limit_Value        => return Record_Size_Limit;
         when Extended_Master_Secret_Value   => return Extended_Master_Secret;
         when Renegotiation_Info_Value       => return Renegotiation_Info;
         when Session_Ticket_Value           => return Session_Ticket;
         when EC_Point_Formats_Value         => return EC_Point_Formats;
         when Early_Data_Value               => return Early_Data;
         when Post_Handshake_Auth_Value      => return Post_Handshake_Auth;
         when others                         => return Unknown_Extension;
      end case;
   end Kind_For;

   -----------------
   -- Is_Refused --
   -----------------

   function Is_Refused (Item : Extension_Kind) return Boolean is
   begin
      --  0-RTT and post-handshake client authentication are not implemented,
      --  and a peer offering one gets a named failure rather than a silent
      --  skip. See docs/known-limitations.md for why neither will be.
      return Item in Early_Data | Post_Handshake_Auth;
   end Is_Refused;

   -----------
   -- Image --
   -----------

   function Image (Item : Extension_Kind) return String is
   begin
      case Item is
         when Server_Name                            => return "server_name";
         when Status_Request                         => return "status_request";
         when Supported_Groups                       => return "supported_groups";
         when Signature_Algorithms                   => return "signature_algorithms";
         when Application_Layer_Protocol_Negotiation => return "application_layer_protocol_"
                                                          & "negotiation";
         when Signature_Algorithms_Cert              => return "signature_algorithms_cert";
         when Supported_Versions                     => return "supported_versions";
         when PSK_Key_Exchange_Modes                 => return "psk_key_exchange_modes";
         when Key_Share                              => return "key_share";
         when Pre_Shared_Key                         => return "pre_shared_key";
         when Cookie                                 => return "cookie";
         when Certificate_Authorities                => return "certificate_authorities";
         when Record_Size_Limit                      => return "record_size_limit";
         when Extended_Master_Secret                 => return "extended_master_secret";
         when Renegotiation_Info                     => return "renegotiation_info";
         when Session_Ticket                         => return "session_ticket";
         when EC_Point_Formats                       => return "ec_point_formats";
         when Early_Data                             => return "early_data";
         when Post_Handshake_Auth                    => return "post_handshake_auth";
         when Unknown_Extension                      => return "unknown_extension";
      end case;
   end Image;

   function Image (Item : Extension_Value) return String is
      Kind : constant Extension_Kind := Kind_For (Item);
   begin
      if Kind /= Unknown_Extension then
         return Image (Kind);
      end if;

      declare
         Text : constant String := Natural (Item)'Image;
      begin
         return "extension_" & Text (Text'First + 1 .. Text'Last);
      end;
   end Image;

   function Image (Item : Message_Context) return String is
   begin
      case Item is
         when In_Client_Hello          => return "client_hello";
         when In_Server_Hello          => return "server_hello";
         when In_Legacy_Server_Hello   => return "server_hello (tls1.2)";
         when In_Hello_Retry_Request   => return "hello_retry_request";
         when In_Encrypted_Extensions  => return "encrypted_extensions";
         when In_Certificate           => return "certificate";
         when In_Certificate_Request   => return "certificate_request";
         when In_New_Session_Ticket    => return "new_session_ticket";
      end case;
   end Image;

   ---------------
   -- Permitted --
   ---------------

   function Permitted (Item : Extension_Kind; Context : Message_Context) return Boolean is
   begin
      --  RFC 8446 section 4.2's table, read row by row. Written as an explicit
      --  case rather than a data table so that adding an extension without
      --  deciding its contexts does not compile.
      case Item is
         when Server_Name =>
            --  In TLS 1.2 the server's acknowledgement is an empty extension in
            --  the ServerHello; TLS 1.3 moved it into EncryptedExtensions so
            --  that it is encrypted.
            return Context in In_Client_Hello | In_Encrypted_Extensions
                            | In_Legacy_Server_Hello;

         when Status_Request =>
            --  Also legal on a Certificate entry, which is how TLS 1.3 staples
            --  a response to the certificate it is about, and in a TLS 1.2
            --  ServerHello, where it says a CertificateStatus will follow.
            return Context in In_Client_Hello | In_Certificate_Request | In_Certificate
                            | In_Legacy_Server_Hello;

         when Supported_Groups =>
            return Context in In_Client_Hello | In_Encrypted_Extensions;

         when Signature_Algorithms | Signature_Algorithms_Cert | Certificate_Authorities =>
            return Context in In_Client_Hello | In_Certificate_Request;

         when Application_Layer_Protocol_Negotiation =>
            --  The same move: encrypted in TLS 1.3, in the clear in TLS 1.2.
            return Context in In_Client_Hello | In_Encrypted_Extensions
                            | In_Legacy_Server_Hello;

         when Supported_Versions | Key_Share =>
            return Context in In_Client_Hello | In_Server_Hello | In_Hello_Retry_Request;

         when Cookie =>
            return Context in In_Client_Hello | In_Hello_Retry_Request;

         when PSK_Key_Exchange_Modes =>
            return Context = In_Client_Hello;

         when Pre_Shared_Key =>
            return Context in In_Client_Hello | In_Server_Hello;

         when Record_Size_Limit =>
            --  RFC 8449 section 4.
            return Context in In_Client_Hello | In_Encrypted_Extensions;

         when Extended_Master_Secret | Renegotiation_Info | Session_Ticket | EC_Point_Formats =>
            --  TLS 1.2 extensions, which travel in the cleartext hellos. Still
            --  permitted in a TLS 1.3 ServerHello because a client that offered
            --  both versions may receive one from a server that selected 1.2,
            --  and the parser is shared.
            return Context in In_Client_Hello | In_Server_Hello
                            | In_Legacy_Server_Hello;

         when Early_Data | Post_Handshake_Auth =>
            --  Not implemented, so permitted nowhere. A peer that sends one
            --  meets Code_Extension_In_Wrong_Context, and the diagnostic names
            --  the extension.
            return False;

         when Unknown_Extension =>
            --  An unrecognized extension is tolerated only in a ClientHello,
            --  which RFC 8446 section 4.2 requires a server to ignore. Anywhere
            --  else it is unsolicited by construction, because this endpoint
            --  cannot have asked for something it does not know.
            return Context = In_Client_Hello;
      end case;
   end Permitted;

   ---------------------------------------------------------------------------
   --  Seen_Set
   ---------------------------------------------------------------------------

   function Empty_Set return Seen_Set is
   begin
      return (others => <>);
   end Empty_Set;

   procedure Include (Item : in out Seen_Set; Kind : Extension_Kind; Value : Extension_Value) is
   begin
      if Kind /= Unknown_Extension then
         Item.Present (Kind) := True;
         return;
      end if;

      --  Unknown identifiers are counted always and listed up to a bound, so a
      --  peer sending a thousand of them costs a counter and not an allocation.
      Item.Count := Item.Count + 1;
      if Item.Count <= Remembered_Unknown then
         Item.Unknown (Item.Count) := Value;
      end if;
   end Include;

   function Contains (Item : Seen_Set; Kind : Extension_Kind) return Boolean is
   begin
      return Item.Present (Kind);
   end Contains;

   function Contains (Item : Seen_Set; Value : Extension_Value) return Boolean is
      Kind : constant Extension_Kind := Kind_For (Value);
   begin
      if Kind /= Unknown_Extension then
         return Item.Present (Kind);
      end if;

      for Index in 1 .. Natural'Min (Item.Count, Remembered_Unknown) loop
         if Item.Unknown (Index) = Value then
            return True;
         end if;
      end loop;

      --  Beyond the remembered bound this cannot answer truthfully, and says
      --  no. The consequence is that an unsolicited-response check refuses,
      --  which is the safe direction.
      return False;
   end Contains;

   function Unknown_Count (Item : Seen_Set) return Natural is
   begin
      return Item.Count;
   end Unknown_Count;

   function Unknown_At (Item : Seen_Set; Index : Positive) return Extension_Value is
   begin
      return Item.Unknown (Index);
   end Unknown_At;

   function Image (Item : Seen_Set) return String is
      Text : String (1 .. 512) := [others => ' '];
      Used : Natural := 0;

      procedure Append (Value : String);

      procedure Append (Value : String) is
         Room : constant Natural := Natural'Min (Value'Length, Text'Length - Used);
      begin
         if Room > 0 then
            Text (Used + 1 .. Used + Room) := Value (Value'First .. Value'First + Room - 1);
            Used := Used + Room;
         end if;
      end Append;

   begin
      for Kind in Extension_Kind loop
         if Kind /= Unknown_Extension and then Item.Present (Kind) then
            if Used > 0 then
               Append (",");
            end if;
            Append (Image (Kind));
         end if;
      end loop;

      for Index in 1 .. Natural'Min (Item.Count, Remembered_Unknown) loop
         if Used > 0 then
            Append (",");
         end if;
         Append (Image (Item.Unknown (Index)));
      end loop;

      if Used = 0 then
         return "none";
      end if;
      return Text (1 .. Used);
   end Image;

   ---------------------------------------------------------------------------
   --  Reading
   ---------------------------------------------------------------------------

   procedure Open_Block
     (Data   : Byte_Array;
      Cursor : in out SSL.Wire.Cursor;
      Bounds : SSL.Limits.Resource_Limits;
      Block  : out SSL.Wire.Cursor;
      Error  : out SSL.Errors.Error_Information)
   is
      Limit : constant Byte_Index := Byte_Index (Bounds.Maximum_Extension_Block);
   begin
      SSL.Wire.Open_Vector_16 (Data, Cursor, Limit, Block);

      if not SSL.Wire.Is_Valid (Cursor) then
         --  Either the declared block is longer than policy allows or longer
         --  than the message actually is. Both are the peer's doing and neither
         --  reveals which by its alert.
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Extension_Malformed,
            Origin     => SSL.Errors.Peer_Message,
            Parameters => [SSL.Errors.Numeric_Parameter ("block_limit", Long_Long_Integer (Limit))]);
         return;
      end if;

      Error := SSL.Errors.No_Error;
   end Open_Block;

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
      Error     : out SSL.Errors.Error_Information)
   is
      Identifier : Natural;
      Body_Limit : constant Byte_Index := Byte_Index (Bounds.Maximum_Extension_Body);
   begin
      Kind := Unknown_Extension;
      Value := 0;
      Body_Part := SSL.Wire.Reader (1, 0);
      Present := False;
      Error := SSL.Errors.No_Error;

      if not SSL.Wire.Is_Valid (Block) or else SSL.Wire.At_End (Block) then
         return;
      end if;

      SSL.Wire.Get_UInt16 (Data, Block, Identifier);
      if not SSL.Wire.Is_Valid (Block) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      Value := Extension_Value (Identifier);
      Kind := Kind_For (Value);

      --  The duplicate check comes before the body is opened, so a repeated
      --  extension is refused without its second body ever being parsed.
      if Kind /= Unknown_Extension and then Contains (Seen, Kind) then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Duplicate_Extension,
            Origin     => SSL.Errors.Peer_Message,
            Parameters => [SSL.Errors.Text_Parameter ("extension", Image (Kind))]);
         return;
      end if;

      if Kind = Unknown_Extension and then Contains (Seen, Value) then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Duplicate_Extension,
            Origin     => SSL.Errors.Peer_Message,
            Parameters => [SSL.Errors.Text_Parameter ("extension", Image (Value))]);
         return;
      end if;

      --  Then the context rule, also before the body. An extension in a message
      --  it may not appear in is refused whatever its body would have said.
      if not Permitted (Kind, Context) then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Extension_In_Wrong_Context,
            Origin     => SSL.Errors.Peer_Message,
            Parameters =>
              [SSL.Errors.Text_Parameter ("extension", Image (Value)),
               SSL.Errors.Text_Parameter ("context", Image (Context))]);
         return;
      end if;

      SSL.Wire.Open_Vector_16 (Data, Block, Body_Limit, Body_Part);
      if not SSL.Wire.Is_Valid (Block) then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Extension_Malformed,
            Origin     => SSL.Errors.Peer_Message,
            Parameters =>
              [SSL.Errors.Text_Parameter ("extension", Image (Value)),
               SSL.Errors.Numeric_Parameter ("body_limit", Long_Long_Integer (Body_Limit))]);
         return;
      end if;

      Include (Seen, Kind, Value);

      --  The count bound is checked after inclusion, so the failure reports the
      --  count that broke it rather than the one before.
      declare
         Total : Natural := Seen.Count;
      begin
         for Each in Extension_Kind loop
            if Each /= Unknown_Extension and then Seen.Present (Each) then
               Total := Total + 1;
            end if;
         end loop;

         if Total > Bounds.Maximum_Extension_Count then
            Error := SSL.Errors.Limit_Failure
              (Kind      => SSL.Limits.Extension_Count,
               Allowed   => Long_Long_Integer (Bounds.Maximum_Extension_Count),
               Requested => Long_Long_Integer (Total));
            return;
         end if;
      end;

      Present := True;
   end Next;

   ---------------------------------------------------------------------------
   --  Writing
   ---------------------------------------------------------------------------

   procedure Open_Block
     (Data : in out Byte_Array; Emitter : in out SSL.Wire.Emitter; Mark : out Byte_Index)
   is
   begin
      SSL.Wire.Open_Vector_16 (Data, Emitter, Mark);
   end Open_Block;

   procedure Close_Block
     (Data : in out Byte_Array; Emitter : in out SSL.Wire.Emitter; Mark : Byte_Index)
   is
   begin
      SSL.Wire.Close_Vector_16 (Data, Emitter, Mark);
   end Close_Block;

   procedure Open_Extension
     (Data    : in out Byte_Array;
      Emitter : in out SSL.Wire.Emitter;
      Kind    : Extension_Kind;
      Mark    : out Byte_Index)
   is
   begin
      SSL.Wire.Put_UInt16 (Data, Emitter, Natural (Value_Of (Kind)));
      SSL.Wire.Open_Vector_16 (Data, Emitter, Mark);
   end Open_Extension;

   procedure Close_Extension
     (Data : in out Byte_Array; Emitter : in out SSL.Wire.Emitter; Mark : Byte_Index)
   is
   begin
      SSL.Wire.Close_Vector_16 (Data, Emitter, Mark);
   end Close_Extension;

end SSL.Extensions;
