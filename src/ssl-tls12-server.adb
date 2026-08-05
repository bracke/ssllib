with Interfaces;

with SSL.Credentials;
with SSL.Extensions;
with SSL.TLS12.Messages;
with SSL.Versions;

package body SSL.TLS12.Server is

   package Config_Package renames SSL.Configurations;
   package Messages renames SSL.Handshake_Messages;
   package Legacy renames SSL.TLS12.Messages;
   package Groups renames SSL.Supported_Groups;
   package Schemes renames SSL.Signature_Schemes;
   package Suites renames SSL.Cipher_Suites;

   use type SSL.ALPN.ALPN_Requirement;
   use type SSL.Credentials.Key_Kind;
   use type SSL.ALPN.Protocol_Name;
   use type SSL.ALPN.Selection_Policy;
   use type SSL.Server_Names.DNS_Name;
   use type SSL.Ticket_Keys.Ring_Reference;
   use type SSL.Handshake_Messages.Message_Type;
   use type SSL.Versions.Protocol_Version;

   ---------------
   -- Image --
   ---------------

   function Image (Item : Server_State) return String is
     (case Item is
         when Start                         => "start",
         when Received_Client_Hello         => "wait for ClientHello",
         when Wait_Client_Key_Exchange      => "wait for ClientKeyExchange",
         when Wait_Client_Change_Cipher_Spec => "wait for ChangeCipherSpec",
         when Wait_Client_Finished          => "wait for Finished",
         when Connected                     => "connected",
         when Failed                        => "failed");

   function Client_Keys (Item : aliased Machine) return access constant Direction_Keys is
      Reference : constant access constant Direction_Keys := Item.Read_Keys'Access;
   begin
      return Reference;
   end Client_Keys;

   function Server_Keys (Item : aliased Machine) return access constant Direction_Keys is
      Reference : constant access constant Direction_Keys := Item.Write_Keys'Access;
   begin
      return Reference;
   end Server_Keys;

   ---------------------------------------------------------------------------
   --  Shared internals
   ---------------------------------------------------------------------------

   procedure Refuse
     (Item   : in out Machine;
      Result : out Plan;
      Error  : out SSL.Errors.Error_Information;
      Cause  : SSL.Errors.Error_Information);

   procedure Refuse
     (Item   : in out Machine;
      Result : out Plan;
      Error  : out SSL.Errors.Error_Information;
      Cause  : SSL.Errors.Error_Information)
   is
   begin
      Item.State := Failed;
      Result := (Count => 0, Steps => [others => <>]);
      Error := Cause;
   end Refuse;

   function Unexpected (Item : Machine; Kind : Messages.Message_Type)
     return SSL.Errors.Error_Information
   is (SSL.Errors.Make
         (Code       => SSL.Errors.Code_Unexpected_Handshake_Message,
          Origin     => SSL.Errors.Peer_Message,
          Parameters =>
            [SSL.Errors.Text_Parameter ("state", Image (Item.State)),
             SSL.Errors.Text_Parameter ("received", Messages.Image (Kind))]));

   procedure Absorb (Item : in out Machine; Message : Byte_Array);

   procedure Absorb (Item : in out Machine; Message : Byte_Array) is
   begin
      SSL.Transcripts.Absorb (Item.Transcript, Message);
   end Absorb;

   ---------------------------------------------------------------------------
   --  Begin_Handshake
   ---------------------------------------------------------------------------

   procedure Begin_Handshake
     (Item   : in out Machine;
      Config : not null access constant SSL.Configurations.Server_Configuration;
      Now    : SSL.Clocks.Wall_Time;
      Error  : out SSL.Errors.Error_Information)
   is
   begin
      Error := SSL.Errors.No_Error;

      if not Config_Package.Is_Valid (Config.all) then
         Item.State := Failed;
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Configuration_Not_Validated, SSL.Errors.Local_Policy);
         return;
      end if;

      Item.Config := Config;
      Item.Now := Now;
      Item.Bounds := Config_Package.Bounds (Config.all);
      SSL.Transcripts.Start (Item.Transcript);
      Item.State := Received_Client_Hello;
   end Begin_Handshake;

   ---------------------------------------------------------------------------
   --  ClientHello, and the whole server flight
   ---------------------------------------------------------------------------

   --  Choose a TLS 1.2 suite from the intersection, in whichever order the
   --  configuration says wins.
   --  A TLS 1.2 suite names the authentication algorithm as well as the key
   --  exchange: `ECDHE_RSA` and `ECDHE_ECDSA` differ in nothing else. So the
   --  suite has to match the credential that will be presented under it. A
   --  server that chose `ECDHE_ECDSA` and then sent an RSA certificate would
   --  get "wrong certificate type" from any client that checked -- which is
   --  exactly what OpenSSL said the first time this was pointed at it.
   --
   --  RFC 8422 puts EdDSA in the ECDSA family, which is why an Ed25519 key
   --  authenticates an `ECDHE_ECDSA` suite.
   function Suits_Credential
     (Suite : Suites.Cipher_Suite; Kind : SSL.Credentials.Key_Kind) return Boolean;

   function Suits_Credential
     (Suite : Suites.Cipher_Suite; Kind : SSL.Credentials.Key_Kind) return Boolean
   is
      use type Suites.Authentication_Kind;
   begin
      case Suites.Authentication_Of (Suite) is
         when Suites.RSA_Signature =>
            return Kind = SSL.Credentials.RSA_Key;

         when Suites.ECDSA_Or_EdDSA =>
            return Kind /= SSL.Credentials.RSA_Key;

         when Suites.Signature_In_Extension =>
            --  A TLS 1.3 suite, which names no authentication at all. Not
            --  reachable here, and answered False rather than True so that a
            --  future caller cannot get a TLS 1.3 suite past this check.
            return False;
      end case;
   end Suits_Credential;

   function Choose_Suite
     (Item     : Machine;
      Offered  : Suites.Suite_List;
      Kind     : SSL.Credentials.Key_Kind;
      Selected : out Suites.Cipher_Suite) return Boolean;

   function Choose_Suite
     (Item     : Machine;
      Offered  : Suites.Suite_List;
      Kind     : SSL.Credentials.Key_Kind;
      Selected : out Suites.Cipher_Suite) return Boolean
   is
      use type SSL.Configurations.Negotiation_Preference;

      Mine : constant Suites.Suite_List := Config_Package.Cipher_Suites (Item.Config.all);
   begin
      Selected := Suites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;

      if Config_Package.Preference (Item.Config.all) = Config_Package.Server_Preference then
         for Index in 1 .. Suites.Length (Mine) loop
            if Suites.Contains (Offered, Suites.Element (Mine, Index))
              and then Suites.Version_Of (Suites.Element (Mine, Index)) = SSL.Versions.TLS_1_2
              and then Suits_Credential (Suites.Element (Mine, Index), Kind)
            then
               Selected := Suites.Element (Mine, Index);
               return True;
            end if;
         end loop;
      else
         for Index in 1 .. Suites.Length (Offered) loop
            if Suites.Contains (Mine, Suites.Element (Offered, Index))
              and then Suites.Version_Of (Suites.Element (Offered, Index))
                       = SSL.Versions.TLS_1_2
              and then Suits_Credential (Suites.Element (Offered, Index), Kind)
            then
               Selected := Suites.Element (Offered, Index);
               return True;
            end if;
         end loop;
      end if;

      return False;
   end Choose_Suite;

   procedure Handle_Client_Hello
     (Item    : in out Machine;
      Message : Byte_Array;
      Source  : in out SSL.Crypto.Random_Source;
      Into    : in out Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Set_Ticket_Keys
     (Item  : in out Machine;
      Value : SSL.Ticket_Keys.Ring_Reference)
   is
   begin
      Item.Ring := Value;
   end Set_Ticket_Keys;

   procedure Set_Issues_Tickets (Item : in out Machine; Value : Boolean) is
   begin
      Item.Issues := Value;
   end Set_Issues_Tickets;

   --  Can the ticket in this hello be taken up?
   --
   --  Every answer but `True` means a full handshake, which is an ordinary
   --  outcome and not a failure. Nothing here is reported to the peer: a client
   --  that could tell "unknown key" from "wrong name" from "expired" would have
   --  an oracle for a server's key rotation and its virtual hosts.
   procedure Consider_Ticket
     (Item       : in out Machine;
      Message    : Byte_Array;
      Hello      : Messages.Client_Hello_Message;
      Extensions : Legacy.Hello_Extensions;
      Accepted   : out Boolean);

   procedure Consider_Ticket
     (Item       : in out Machine;
      Message    : Byte_Array;
      Hello      : Messages.Client_Hello_Message;
      Extensions : Legacy.Hello_Extensions;
      Accepted   : out Boolean)
   is
      Local  : SSL.Errors.Error_Information;
      Usable : Boolean;
      First  : constant Byte_Index := Extensions.Session_Ticket.First;
      Last   : constant Byte_Index := Extensions.Session_Ticket.Last;
   begin
      Accepted := False;

      if Item.Ring = null
        or else not Extensions.Session_Ticket_Present
        or else Last < First
      then
         return;
      end if;

      SSL.Ticket_Keys.Open
        (Item   => Item.Ring.all,
         Ticket => Message (First .. Last),
         Now    => Item.Now,
         Into   => Item.Offered,
         Usable => Usable,
         Error  => Local);
      if not Usable then
         return;
      end if;

      if SSL.Sessions.Version (Item.Offered) /= SSL.Versions.TLS_1_2 then
         --  A ticket this server sealed for a TLS 1.3 session. Its secret is a
         --  resumption PSK, not a master secret, and the two are not
         --  interchangeable.
         SSL.Sessions.Wipe (Item.Offered);
         return;
      end if;

      --  The suite has to be one the client still offers and one this server
      --  still permits: a session established under a suite that policy has
      --  since withdrawn must not come back through a ticket.
      if not Suites.Contains
               (Messages.Offered_Suites (Hello),
                SSL.Sessions.Cipher_Suite (Item.Offered))
        or else not Suites.Contains
                      (Config_Package.Cipher_Suites (Item.Config.all),
                       SSL.Sessions.Cipher_Suite (Item.Offered))
      then
         SSL.Sessions.Wipe (Item.Offered);
         return;
      end if;

      --  And the name. A ticket issued for one host is not a claim about
      --  another, and a server serving several would otherwise let a session
      --  established with one of them resume against any of them.
      if SSL.Sessions.Server_Name (Item.Offered)
           /= Messages.Offered_Name (Hello)
      then
         SSL.Sessions.Wipe (Item.Offered);
         return;
      end if;

      --  And the application protocol. A session established under `h2` must
      --  not resume under `http/1.1`: an application that dispatched on the
      --  protocol would be dispatching wrongly, and the protocol is not
      --  renegotiated on an abbreviated handshake -- it is inherited.
      if SSL.Sessions.Has_Protocol (Item.Offered) /= Item.Has_Protocol
        or else (Item.Has_Protocol
                 and then SSL.Sessions.Protocol (Item.Offered) /= Item.Protocol)
      then
         SSL.Sessions.Wipe (Item.Offered);
         return;
      end if;

      Item.Suite := SSL.Sessions.Cipher_Suite (Item.Offered);
      Accepted := True;
   end Consider_Ticket;

   --  The rest of an abbreviated handshake's first flight: the key block from
   --  the session's master secret and the two fresh randoms, then the epoch
   --  switch and this server's Finished.
   --
   --  The client's Finished is what proves it holds the master secret inside
   --  the ticket. There is no binder in TLS 1.2 and none is needed: a peer with
   --  a stolen ticket and no secret cannot produce one, and this server sends
   --  nothing under the new keys that it would not have sent anyway.
   procedure Complete_Abbreviated
     (Item   : in out Machine;
      Into   : in out Byte_Array;
      Cursor : in out Byte_Index;
      Result : in out Plan;
      Error  : out SSL.Errors.Error_Information);

   procedure Complete_Abbreviated
     (Item   : in out Machine;
      Into   : in out Byte_Array;
      Cursor : in out Byte_Index;
      Result : in out Plan;
      Error  : out SSL.Errors.Error_Information)
   is
      Local  : SSL.Errors.Error_Information;
      Secret : Byte_Array (1 .. 64) := [others => 0];
      Length : Byte_Index;
   begin
      Error := SSL.Errors.No_Error;

      SSL.Sessions.Get_Secret (Item.Offered, Secret, Length);
      if Length /= Master_Secret_Length then
         SSL.Crypto.Scrub (Secret);
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Ticket_Malformed, SSL.Errors.Local_Implementation));
         return;
      end if;

      SSL.Secrets.Set (Item.Master, Secret (1 .. Length));
      SSL.Crypto.Scrub (Secret);
      SSL.Sessions.Wipe (Item.Offered);

      Derive_Key_Block
        (Suite         => Item.Suite,
         Master        => Item.Master,
         Client_Random => Item.Client_Random,
         Server_Random => Item.Server_Random,
         Client_Side   => Item.Read_Keys,
         Server_Side   => Item.Write_Keys,
         Error         => Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Add (Result, Send_Change_Cipher_Spec);
      Add (Result, Install_Write_Keys);

      declare
         Verify : Byte_Array (1 .. Verify_Data_Length) := [others => 0];
         Span   : constant Byte_Index :=
           Messages.Header_Length + Verify_Data_Length;
      begin
         Compute_Finished
           (Algorithm       => Suites.Hash_Of (Item.Suite),
            Master          => Item.Master,
            Which           => Server_Finished,
            Transcript_Hash => SSL.Transcripts.Hash (Item.Transcript),
            Into            => Verify,
            Error           => Local);
         if SSL.Errors.Is_Error (Local) then
            SSL.Crypto.Scrub (Verify);
            Refuse (Item, Result, Error, Local);
            return;
         end if;

         if Into'Last - Cursor + 1 < Span then
            SSL.Crypto.Scrub (Verify);
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_Output_Queue_Full,
                       SSL.Errors.Local_Implementation));
            return;
         end if;

         Into (Cursor .. Cursor + Messages.Header_Length - 1) :=
           Messages.Encode_Header (Messages.Finished, Verify_Data_Length);
         Into (Cursor + Messages.Header_Length .. Cursor + Span - 1) := Verify;
         SSL.Crypto.Scrub (Verify);

         Absorb (Item, Into (Cursor .. Cursor + Span - 1));
         Add (Result, Send_Handshake, Cursor, Cursor + Span - 1);
         Cursor := Cursor + Span;
      end;

      Item.State := Wait_Client_Change_Cipher_Spec;
   end Complete_Abbreviated;

   procedure Handle_Client_Hello
     (Item    : in out Machine;
      Message : Byte_Array;
      Source  : in out SSL.Crypto.Random_Source;
      Into    : in out Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Hello      : Messages.Client_Hello_Message;
      Extensions : Legacy.Hello_Extensions;
      Local      : SSL.Errors.Error_Information;
      Cursor     : Byte_Index := Into'First;
      Length     : Byte_Index;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Messages.Parse_Client_Hello (Message, Item.Bounds, Hello, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Legacy.Read_Hello_Extensions
        (Message, SSL.Extensions.In_Client_Hello, Item.Bounds, Extensions, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      if not Extensions.Extended_Master_Secret then
         --  RFC 7627. A client that will not negotiate it gets no connection:
         --  without it the master secret is not bound to this handshake.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Extended_Master_Secret_Missing,
                    SSL.Errors.Peer_Message));
         return;
      end if;

      if Extensions.Renegotiation_Info and then not Extensions.Renegotiation_Empty then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Renegotiation_Attempted, SSL.Errors.Peer_Message));
         return;
      end if;

      if Extensions.Point_Formats_Present and then not Extensions.Uncompressed_Points then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Key_Exchange_Value_Invalid, SSL.Errors.Peer_Message));
         return;
      end if;

      Item.Client_Random := Messages.Random (Hello);
      Item.Name := Messages.Offered_Name (Hello);

      declare
         Sent : constant Byte_Array := Messages.Session_Id (Hello);
      begin
         Item.Echo_Length := Sent'Length;
         if Sent'Length > 0 then
            Item.Echo (1 .. Sent'Length) := Sent;
         end if;
      end;

      --  ALPN.
      declare
         Need   : constant SSL.ALPN.ALPN_Requirement :=
           Config_Package.ALPN_Requirement (Item.Config.all);
         Policy : constant SSL.ALPN.Selection_Policy :=
           Config_Package.ALPN_Selection (Item.Config.all);
         Chosen : SSL.ALPN.Protocol_Name;
      begin
         if Need /= SSL.ALPN.Not_Offered
           and then not SSL.ALPN.Is_Empty (Messages.Offered_Protocols (Hello))
         then
            if SSL.ALPN.Select_Protocol
                 (Policy      => (if Policy = SSL.ALPN.Application_Selector
                                  then SSL.ALPN.Server_Order else Policy),
                  Server_List => Config_Package.Application_Protocols (Item.Config.all),
                  Client_List => Messages.Offered_Protocols (Hello),
                  Selected    => Chosen)
            then
               Item.Protocol := Chosen;
               Item.Has_Protocol := True;
            elsif Need = SSL.ALPN.Required then
               Refuse (Item, Result, Error,
                       SSL.Errors.Make
                         (SSL.Errors.Code_No_Application_Protocol_Overlap,
                          SSL.Errors.Peer_Message));
               return;
            end if;
         elsif Need = SSL.ALPN.Required then
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_No_Application_Protocol_Overlap,
                       SSL.Errors.Peer_Message));
            return;
         end if;
      end;

      --  A ticket, considered once the name and the application protocol are
      --  known, because both are part of what a session is bound to. An
      --  accepted ticket brings its own cipher suite, so the suite is chosen
      --  only when there is no ticket to take it from.
      Consider_Ticket (Item, Message, Hello, Extensions, Item.Is_Resumed);

      if not Item.Is_Resumed then
         --  The credential first, because the suite has to match it. Choosing
         --  a suite and then finding a credential for it is the wrong way
         --  round: a server with one key would advertise suites it cannot
         --  authenticate.
         if not Config_Package.Select_Credential
                  (Item    => Item.Config.all,
                   Name    => Messages.Offered_Name (Hello),
                   Offered => Messages.Offered_Schemes (Hello),
                   Version => SSL.Versions.TLS_1_2,
                   Index   => Item.Credential_Index)
         then
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_No_Credential_Configured, SSL.Errors.Local_Policy));
            return;
         end if;

         if not Choose_Suite
                  (Item, Messages.Offered_Suites (Hello),
                   SSL.Credentials.Key_Type
                     (Config_Package.Credential_At
                        (Item.Config.all, Item.Credential_Index).all),
                   Item.Suite)
         then
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_No_Common_Cipher_Suite, SSL.Errors.Peer_Message));
            return;
         end if;

         --  An elliptic group both ends have. The finite-field ones mean nothing
         --  in an ECDHE key exchange.
         declare
            Mine    : constant Groups.Group_List := Config_Package.Groups (Item.Config.all);
            Offered : constant Groups.Group_List := Messages.Offered_Groups (Hello);
            Found   : Boolean := False;
         begin
            for Index in 1 .. Groups.Length (Mine) loop
               if Groups.Is_Elliptic_Curve (Groups.Element (Mine, Index))
                 and then Groups.Contains (Offered, Groups.Element (Mine, Index))
               then
                  Item.Named := Groups.Element (Mine, Index);
                  Found := True;
                  exit;
               end if;
            end loop;

            if not Found then
               Refuse (Item, Result, Error,
                       SSL.Errors.Make
                         (SSL.Errors.Code_No_Common_Group, SSL.Errors.Peer_Message));
               return;
            end if;
         end;
      end if;

      --  Whether a ticket will be issued at the end of this handshake, decided
      --  here because the ServerHello has to say so several messages before the
      --  ticket exists. Not on a resumed handshake: this server does not renew
      --  a ticket it just accepted, so a session lives exactly as long as the
      --  ticket that carried it and then costs one full handshake.
      Item.Will_Issue :=
        Extensions.Session_Ticket_Present
          and then Item.Issues
          and then not Item.Is_Resumed
          and then Item.Ring /= null
          and then SSL.Ticket_Keys.Has_Active_Key (Item.Ring.all);

      SSL.Transcripts.Select_Algorithm (Item.Transcript, Suites.Hash_Of (Item.Suite));
      Absorb (Item, Message);

      SSL.Crypto.Fill (Source, Item.Server_Random, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      --  ServerHello.
      declare
         Region : Byte_Array (1 .. Into'Last - Cursor + 1) := [others => 0];
      begin
         --  The session identifier is echoed only on a resumption, because
         --  under RFC 5077 section 3.4 that echo *is* the acceptance: a server
         --  that echoed it on a full handshake would be telling every client
         --  that its ticket had been taken up. On a full handshake this server
         --  sends none at all, which is also the honest answer -- it does no
         --  session-identifier caching, so there is no identifier to give out.
         Legacy.Encode_Server_Hello
           (Random_Value     => Item.Server_Random,
            Session_Id       =>
              (if Item.Is_Resumed then Item.Echo (1 .. Item.Echo_Length)
               else [1 .. 0 => 0]),
            Suite            => Item.Suite,
            Protocol         => Item.Protocol,
            Has_Protocol     => Item.Has_Protocol,
            Acknowledge_Name => SSL.Server_Names.Is_Present (Item.Name),
            Promise_Ticket   => Item.Will_Issue,
            Into             => Region,
            Written          => Length,
            Error            => Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;
         Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
      end;
      Absorb (Item, Into (Cursor .. Cursor + Length - 1));
      Add (Result, Send_Handshake, Cursor, Cursor + Length - 1);
      Cursor := Cursor + Length;

      if Item.Is_Resumed then
         --  The abbreviated handshake ends here on this side: no certificate,
         --  no key exchange, no signature. This server goes first with its
         --  epoch switch and its Finished, and the client answers.
         Complete_Abbreviated (Item, Into, Cursor, Result, Error);
         return;
      end if;

      --  Certificate. TLS 1.2's has no request context: it is a three-octet
      --  list length and then the entries.
      declare
         Credential : constant access constant SSL.Credentials.Credential :=
           Config_Package.Credential_At (Item.Config.all, Item.Credential_Index);
         Count : constant Positive := SSL.Credentials.Chain_Length (Credential.all);
         Total : Byte_Index := 0;
      begin
         for Index in 1 .. Count loop
            Total := Total + 3 + SSL.Credentials.Certificate_At (Credential.all, Index)'Length;
         end loop;

         declare
            Region : Byte_Array (1 .. Into'Last - Cursor + 1) := [others => 0];
            At_Now : Byte_Index := Messages.Header_Length + 4;
         begin
            Region (1 .. Messages.Header_Length) :=
              Messages.Encode_Header (Messages.Certificate, Total + 3);
            Region (Messages.Header_Length + 1) := Byte (Total / 65_536);
            Region (Messages.Header_Length + 2) := Byte ((Total / 256) mod 256);
            Region (Messages.Header_Length + 3) := Byte (Total mod 256);

            for Index in 1 .. Count loop
               declare
                  One : constant Byte_Array :=
                    SSL.Credentials.Certificate_At (Credential.all, Index);
               begin
                  Region (At_Now) := Byte (One'Length / 65_536);
                  Region (At_Now + 1) := Byte ((One'Length / 256) mod 256);
                  Region (At_Now + 2) := Byte (One'Length mod 256);
                  Region (At_Now + 3 .. At_Now + 2 + One'Length) := One;
                  At_Now := At_Now + 3 + One'Length;
               end;
            end loop;

            Length := At_Now - 1;
            Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
         end;
      end;
      Absorb (Item, Into (Cursor .. Cursor + Length - 1));
      Add (Result, Send_Handshake, Cursor, Cursor + Length - 1);
      Cursor := Cursor + Length;

      --  ServerKeyExchange: the ephemeral share, signed over the two randoms
      --  and the exact parameter octets. That signature is the whole security
      --  of a TLS 1.2 ECDHE handshake.
      declare
         Credential : constant access constant SSL.Credentials.Credential :=
           Config_Package.Credential_At (Item.Config.all, Item.Credential_Index);
         Offered : constant Schemes.Scheme_List := Messages.Offered_Schemes (Hello);
         Mine    : constant Schemes.Scheme_List :=
           SSL.Credentials.Supported_Schemes (Credential.all);
         Found   : Boolean := False;
      begin
         SSL.Crypto.Generate (Item.Exchange, Item.Named, Source, Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;

         for Index in 1 .. Schemes.Length (Mine) loop
            if Schemes.Contains (Offered, Schemes.Element (Mine, Index))
              and then Schemes.Usable_For_Handshake
                         (Schemes.Element (Mine, Index), SSL.Versions.TLS_1_2)
            then
               Item.Scheme := Schemes.Element (Mine, Index);
               Found := True;
               exit;
            end if;
         end loop;

         if not Found then
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_No_Common_Signature_Scheme,
                       SSL.Errors.Local_Policy));
            return;
         end if;

         declare
            Share      : constant Byte_Array := SSL.Crypto.Public_Share (Item.Exchange);
            Parameters : constant Byte_Array :=
              Legacy.Encoded_Parameters (Item.Named, Share);
            Content    : constant Byte_Array :=
              Key_Exchange_Signed_Content
                (Client_Random => Item.Client_Random,
                 Server_Random => Item.Server_Random,
                 Parameters    => Parameters);
            Buffer  : Byte_Array (1 .. SSL.Credentials.Maximum_Signature_Length) :=
              [others => 0];
            Written : Byte_Index;
            Region  : Byte_Array (1 .. Into'Last - Cursor + 1) := [others => 0];
         begin
            SSL.Credentials.Sign
              (Item        => Credential.all,
               Scheme      => Item.Scheme,
               Signed_Data => Content,
               Signature   => Buffer,
               Length      => Written,
               Error       => Local);
            if SSL.Errors.Is_Error (Local) then
               Refuse (Item, Result, Error, Local);
               return;
            end if;

            Legacy.Encode_Key_Exchange
              (Group     => Item.Named,
               Share     => Share,
               Scheme    => Item.Scheme,
               Signature => Buffer (1 .. Written),
               Into      => Region,
               Written   => Length,
               Error     => Local);
            if SSL.Errors.Is_Error (Local) then
               Refuse (Item, Result, Error, Local);
               return;
            end if;
            Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
         end;
      end;
      Absorb (Item, Into (Cursor .. Cursor + Length - 1));
      Add (Result, Send_Handshake, Cursor, Cursor + Length - 1);
      Cursor := Cursor + Length;

      --  ServerHelloDone.
      declare
         Region : Byte_Array (1 .. Into'Last - Cursor + 1) := [others => 0];
      begin
         Legacy.Encode_Server_Hello_Done (Region, Length, Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;
         Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
      end;
      Absorb (Item, Into (Cursor .. Cursor + Length - 1));
      Add (Result, Send_Handshake, Cursor, Cursor + Length - 1);

      Item.State := Wait_Client_Key_Exchange;
   end Handle_Client_Hello;

   ---------------------------------------------------------------------------
   --  ClientKeyExchange
   ---------------------------------------------------------------------------

   procedure Handle_Client_Key_Exchange
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_Client_Key_Exchange
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Local : SSL.Errors.Error_Information;
      First : Byte_Index;
      Last  : Byte_Index;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Legacy.Parse_Client_Key_Exchange (Message, Item.Bounds, First, Last, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      SSL.Crypto.Agree
        (Item       => Item.Exchange,
         Peer_Share => Message (First .. Last),
         Target     => Item.Shared,
         Error      => Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Absorb (Item, Message);

      --  The master secret, bound to the transcript through this message. That
      --  binding is the extended master secret.
      Derive_Extended_Master
        (Algorithm    => Suites.Hash_Of (Item.Suite),
         Premaster    => Item.Shared,
         Session_Hash => SSL.Transcripts.Hash (Item.Transcript),
         Into         => Item.Master,
         Error        => Local);
      SSL.Secrets.Wipe (Item.Shared);
      SSL.Crypto.Wipe (Item.Exchange);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Derive_Key_Block
        (Suite         => Item.Suite,
         Master        => Item.Master,
         Client_Random => Item.Client_Random,
         Server_Random => Item.Server_Random,
         Client_Side   => Item.Read_Keys,
         Server_Side   => Item.Write_Keys,
         Error         => Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Item.State := Wait_Client_Change_Cipher_Spec;
   end Handle_Client_Key_Exchange;

   ---------------------------------------------------------------------------
   --  ChangeCipherSpec and the client's Finished
   ---------------------------------------------------------------------------

   procedure Handle_Change_Cipher_Spec
     (Item   : in out Machine;
      Result : out Plan;
      Error  : out SSL.Errors.Error_Information)
   is
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      if Item.State /= Wait_Client_Change_Cipher_Spec then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Record_Unexpected_CCS, SSL.Errors.Peer_Message));
         return;
      end if;

      Add (Result, Install_Read_Keys);
      Item.State := Wait_Client_Finished;
   end Handle_Change_Cipher_Spec;

   --  How long a ticket may be resumed for. A day: long enough that a client
   --  coming back tomorrow morning still resumes, short enough that a stolen
   --  ticket is not a standing invitation.
   Ticket_Lifetime : constant Natural := 86_400;

   --  Seal this connection into a ticket and put a NewSessionTicket into the
   --  output.
   --
   --  Every failure here costs the ticket and not the connection. A server that
   --  dropped a working handshake because it could not seal its own state would
   --  be turning a lost optimization into a lost connection.
   procedure Issue_Ticket
     (Item   : in out Machine;
      Into   : in out Byte_Array;
      Cursor : in out Byte_Index;
      Result : in out Plan);

   procedure Issue_Ticket
     (Item   : in out Machine;
      Into   : in out Byte_Array;
      Cursor : in out Byte_Index;
      Result : in out Plan)
   is
      Local   : SSL.Errors.Error_Information;
      Secret  : Byte_Array (1 .. Master_Secret_Length) := [others => 0];
      Sealed  : Byte_Array (1 .. SSL.Ticket_Keys.Maximum_Ticket) := [others => 0];
      Written : Byte_Index;
      Session : SSL.Sessions.Session;

      --  Default-initialized, which is what "no fingerprint" is: this type has
      --  no other way to say it, and inventing a value would be inventing a
      --  claim.
      Blank_Setup   : Configuration_Fingerprint;
      Blank_Anchors : Trust_Fingerprint;
   begin
      SSL.Secrets.Get (Item.Master, Secret);

      SSL.Sessions.Store
        (Item          => Session,
         Version       => SSL.Versions.TLS_1_2,
         Suite         => Item.Suite,
         Name          => Item.Name,
         Protocol      => Item.Protocol,
         Has_Protocol  => Item.Has_Protocol,
         Issued        => Item.Now,
         Lifetime      => Ticket_Lifetime,
         Context       => Default_Security_Context,

         --  The two fingerprints are the client's side of a session's
         --  bindings: they stop a *cache* offering a session under a policy it
         --  was not established under. This server never offers this session
         --  anywhere -- it seals it, and on the way back it checks the name,
         --  the suite and the protocol itself -- so there is nothing here for
         --  them to bind, and a value invented to fill them would be a value
         --  something might one day believe.
         Setup         => Blank_Setup,
         Anchors       => Blank_Anchors,

         --  The peer, from this end, is the client. This profile requests no
         --  client certificate, so it is anonymous.
         Authenticated => False,
         Ticket_Bytes  => [1 => 0],
         Age_Add       => 0,
         Nonce_Bytes   => [1 .. 0 => 0],
         Secret        => Secret,
         Error         => Local);
      SSL.Crypto.Scrub (Secret);
      if SSL.Errors.Is_Error (Local) then
         SSL.Sessions.Wipe (Session);
         return;
      end if;

      SSL.Ticket_Keys.Seal (Item.Ring.all, Session, Sealed, Written, Local);
      SSL.Sessions.Wipe (Session);
      if SSL.Errors.Is_Error (Local) or else Written = 0 then
         SSL.Crypto.Scrub (Sealed);
         return;
      end if;

      declare
         Region : Byte_Array (1 .. Into'Last - Cursor + 1) := [others => 0];
         Length : Byte_Index;
      begin
         Legacy.Encode_New_Session_Ticket
           (Lifetime => Interfaces.Unsigned_32 (Ticket_Lifetime),
            Ticket   => Sealed (1 .. Written),
            Into     => Region,
            Written  => Length,
            Error    => Local);
         SSL.Crypto.Scrub (Sealed);
         if SSL.Errors.Is_Error (Local) then
            return;
         end if;

         Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
         Absorb (Item, Into (Cursor .. Cursor + Length - 1));
         Add (Result, Send_Handshake, Cursor, Cursor + Length - 1);
         Cursor := Cursor + Length;
      end;
   end Issue_Ticket;

   procedure Handle_Client_Finished
     (Item    : in out Machine;
      Message : Byte_Array;
      Into    : in out Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_Client_Finished
     (Item    : in out Machine;
      Message : Byte_Array;
      Into    : in out Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Local    : SSL.Errors.Error_Information;
      First    : Byte_Index;
      Last     : Byte_Index;
      Expected : Byte_Array (1 .. Verify_Data_Length) := [others => 0];
      Matches  : Boolean;
      Cursor   : Byte_Index := Into'First;
      Length   : Byte_Index;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Messages.Parse_Finished (Message, Item.Bounds, First, Last, Local);
      if SSL.Errors.Is_Error (Local) or else Last - First + 1 /= Verify_Data_Length then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Finished_Verification_Failed,
                    SSL.Errors.Peer_Message));
         return;
      end if;

      Compute_Finished
        (Algorithm       => Suites.Hash_Of (Item.Suite),
         Master          => Item.Master,
         Which           => Client_Finished,
         Transcript_Hash => SSL.Transcripts.Hash (Item.Transcript),
         Into            => Expected,
         Error           => Local);
      if SSL.Errors.Is_Error (Local) then
         SSL.Crypto.Scrub (Expected);
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Matches := SSL.Crypto.Equal (Expected, Message (First .. Last));
      SSL.Crypto.Scrub (Expected);

      if not Matches then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Finished_Verification_Failed,
                    SSL.Errors.Peer_Message));
         return;
      end if;

      Absorb (Item, Message);

      if Item.Is_Resumed then
         --  On an abbreviated handshake this server has already sent its
         --  Finished, and the client's is the last message of the handshake.
         Add (Result, Handshake_Complete);
         Item.State := Connected;
         return;
      end if;

      --  RFC 5077 section 3.3: the NewSessionTicket goes here, after the
      --  client's Finished and before this server's ChangeCipherSpec, so it is
      --  covered by the Finished this server is about to compute.
      if Item.Will_Issue then
         Issue_Ticket (Item, Into, Cursor, Result);
      end if;

      --  This server's own epoch switch, then its Finished under the new keys.
      Add (Result, Send_Change_Cipher_Spec);
      Add (Result, Install_Write_Keys);

      declare
         Verify : Byte_Array (1 .. Verify_Data_Length) := [others => 0];
         Region : Byte_Array (1 .. Into'Last - Cursor + 1) := [others => 0];
      begin
         Compute_Finished
           (Algorithm       => Suites.Hash_Of (Item.Suite),
            Master          => Item.Master,
            Which           => Server_Finished,
            Transcript_Hash => SSL.Transcripts.Hash (Item.Transcript),
            Into            => Verify,
            Error           => Local);
         if SSL.Errors.Is_Error (Local) then
            SSL.Crypto.Scrub (Verify);
            Refuse (Item, Result, Error, Local);
            return;
         end if;

         Region (1 .. Messages.Header_Length) :=
           Messages.Encode_Header (Messages.Finished, Verify_Data_Length);
         Region (Messages.Header_Length + 1
                 .. Messages.Header_Length + Verify_Data_Length) := Verify;
         Length := Messages.Header_Length + Verify_Data_Length;
         SSL.Crypto.Scrub (Verify);

         Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
         Absorb (Item, Into (Cursor .. Cursor + Length - 1));
         Add (Result, Send_Handshake, Cursor, Cursor + Length - 1);
      end;

      Add (Result, Handshake_Complete);
      Item.State := Connected;
   end Handle_Client_Finished;

   ---------------------------------------------------------------------------
   --  The dispatcher
   ---------------------------------------------------------------------------

   procedure Handle_Message
     (Item    : in out Machine;
      Message : Byte_Array;
      Source  : in out SSL.Crypto.Random_Source;
      Into    : in out Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Kind   : Messages.Message_Type;
      Raw    : Messages.Type_Value;
      Length : Byte_Index;
      Local  : SSL.Errors.Error_Information;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Messages.Parse_Header (Message, Kind, Raw, Length, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      case Item.State is
         when Received_Client_Hello =>
            if Kind = Messages.Client_Hello then
               Handle_Client_Hello (Item, Message, Source, Into, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Client_Key_Exchange =>
            if Kind = Messages.Client_Key_Exchange then
               Handle_Client_Key_Exchange (Item, Message, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Client_Finished =>
            if Kind = Messages.Finished then
               Handle_Client_Finished (Item, Message, Into, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Client_Change_Cipher_Spec | Connected | Start | Failed =>
            Refuse (Item, Result, Error, Unexpected (Item, Kind));
      end case;
   end Handle_Message;

   ---------------
   -- Wipe --
   ---------------

   procedure Wipe (Item : in out Machine) is
   begin
      --  The recovered session first: it holds a master secret, and it is the
      --  one field here that can outlive the handshake that opened it.
      SSL.Sessions.Wipe (Item.Offered);
      SSL.Crypto.Wipe (Item.Exchange);
      SSL.Secrets.Wipe (Item.Shared);
      SSL.Secrets.Wipe (Item.Master);
      TLS12.Wipe (Item.Write_Keys);
      TLS12.Wipe (Item.Read_Keys);
      SSL.Transcripts.Start (Item.Transcript);
   end Wipe;

end SSL.TLS12.Server;
