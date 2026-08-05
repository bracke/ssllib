with Ada.Streams;
with Interfaces;

with SSL.Extensions;
with SSL.TLS12.Messages;
with SSL.Trust;
with SSL.Trust.Pinning;
with SSL.Trust.Revocation;
with SSL.Versions;

package body SSL.TLS12.Client is

   package Config_Package renames SSL.Configurations;
   package Messages renames SSL.Handshake_Messages;
   package Legacy renames SSL.TLS12.Messages;
   package Groups renames SSL.Supported_Groups;
   package Schemes renames SSL.Signature_Schemes;
   package Suites renames SSL.Cipher_Suites;
   package Validation renames SSL.Certificate_Validation;

   use type Ada.Streams.Stream_Element_Array;
   use type SSL.ALPN.ALPN_Requirement;
   use type SSL.Cipher_Suites.Cipher_Suite;
   use type SSL.Handshake_Messages.Message_Type;
   use type SSL.Trust.Pinning.Pinning_Mode;
   use type SSL.Versions.Protocol_Version;
   use type SSL.Versions.Version_Value;

   ---------------
   -- Image --
   ---------------

   function Image (Item : Client_State) return String is
     (case Item is
         when Start                   => "start",
         when Wait_Server_Hello       => "wait for ServerHello",
         when Wait_Certificate        => "wait for Certificate",
         when Wait_Key_Exchange       => "wait for ServerKeyExchange",
         when Wait_Request_Or_Done    => "wait for CertificateRequest or ServerHelloDone",
         when Wait_Session_Ticket     => "wait for NewSessionTicket",
         when Wait_Change_Cipher_Spec => "wait for ChangeCipherSpec",
         when Wait_Finished           => "wait for Finished",
         when Connected               => "connected",
         when Failed                  => "failed");

   function Client_Keys (Item : aliased Machine) return access constant Direction_Keys is
      Reference : constant access constant Direction_Keys := Item.Write_Keys'Access;
   begin
      return Reference;
   end Client_Keys;

   function Server_Keys (Item : aliased Machine) return access constant Direction_Keys is
      Reference : constant access constant Direction_Keys := Item.Read_Keys'Access;
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

   ---------------------------------------------------------------------------
   --  Tickets
   ---------------------------------------------------------------------------

   procedure Request_Tickets (Item : in out Machine; Value : Boolean) is
   begin
      Item.Wants_Tickets := Value;
   end Request_Tickets;

   procedure Offer_Session (Item : in out Machine; Value : SSL.Sessions.Session) is
      use type SSL.Versions.Protocol_Version;
   begin
      if not SSL.Sessions.Is_Present (Value)
        or else SSL.Sessions.Version (Value) /= SSL.Versions.TLS_1_2
      then
         --  A TLS 1.3 session offered to a TLS 1.2 machine. Declined silently:
         --  its secret is a resumption PSK derived under a schedule this
         --  protocol does not have, and there is nothing this end could do with
         --  it but a full handshake, which is what happens anyway.
         return;
      end if;

      SSL.Sessions.Copy (Item.Offered, Value);
      Item.Has_Offer := True;
      Item.Wants_Tickets := True;
   end Offer_Session;

   function Offered_Ticket (Item : Machine) return Byte_Array is
   begin
      if not Item.Has_Offer then
         return [1 .. 0 => 0];
      end if;

      return SSL.Sessions.Ticket (Item.Offered);
   end Offered_Ticket;

   procedure Take_New_Session
     (Item    : in out Machine;
      Context : Security_Context_ID;
      Setup   : Configuration_Fingerprint;
      Anchors : Trust_Fingerprint;
      Into    : in out SSL.Sessions.Session;
      Present : out Boolean)
   is
      Local  : SSL.Errors.Error_Information;
      Secret : Byte_Array (1 .. Master_Secret_Length) := [others => 0];
   begin
      Present := False;

      if not Item.Has_New_Ticket or else Item.State /= Connected then
         --  Only a handshake that finished establishes a session. A ticket
         --  received during one that then failed describes a connection that
         --  never existed.
         return;
      end if;

      SSL.Secrets.Get (Item.Master, Secret);

      SSL.Sessions.Store
        (Item          => Into,
         Version       => SSL.Versions.TLS_1_2,
         Suite         => Item.Suite,
         Name          => Item.Name,
         Protocol      => Item.Protocol,
         Has_Protocol  => Item.Has_Protocol,
         Issued        => Item.Now,
         Lifetime      => Item.New_Lifetime,
         Context       => Context,
         Setup         => Setup,
         Anchors       => Anchors,
         Authenticated => Item.Peer_Accepted,
         Ticket_Bytes  => Item.New_Ticket (1 .. Item.New_Ticket_Length),

         --  Neither applies to TLS 1.2: the age offset and the nonce are both
         --  TLS 1.3 constructions, and writing something plausible into them
         --  would be writing something false.
         Age_Add       => 0,
         Nonce_Bytes   => [1 .. 0 => 0],
         Secret        => Secret,
         Error         => Local);
      SSL.Crypto.Scrub (Secret);

      Present := not SSL.Errors.Is_Error (Local);

      --  Taken once. A machine that kept handing out the same ticket would let
      --  a driver store several sessions that are all the same session.
      Item.Has_New_Ticket := False;
      Item.New_Ticket := [others => 0];
      Item.New_Ticket_Length := 0;
   end Take_New_Session;

   procedure Begin_Handshake
     (Item   : in out Machine;
      Config : not null access constant SSL.Configurations.Client_Configuration;
      Now    : SSL.Clocks.Wall_Time;
      Source : in out SSL.Crypto.Random_Source;
      Into   : in out Byte_Array;
      Result : out Plan;
      Error  : out SSL.Errors.Error_Information)
   is
      Local   : SSL.Errors.Error_Information;
      Written : Byte_Index;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      if not Config_Package.Is_Valid (Config.all) then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make (SSL.Errors.Code_Configuration_Not_Validated,
                                  SSL.Errors.Local_Policy));
         return;
      end if;

      if not SSL.Versions.Contains
               (Config_Package.Versions (Config.all), SSL.Versions.TLS_1_2)
      then
         --  This machine is only reached when the policy permits TLS 1.2. A
         --  configuration that does not is a caller mistake rather than a peer
         --  one, and it is named as such.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make (SSL.Errors.Code_No_Common_Version,
                                  SSL.Errors.Local_Policy));
         return;
      end if;

      Item.Config := Config;
      Item.Now := Now;
      Item.Bounds := Config_Package.Bounds (Config.all);
      Item.Name := Config_Package.Server_Name_Indication (Config.all);

      SSL.Transcripts.Start (Item.Transcript);

      SSL.Crypto.Fill (Source, Item.Client_Random, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;
      SSL.Crypto.Fill (Source, Item.Session, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Legacy.Encode_Client_Hello
        (Config       => Config.all,
         Random_Value => Item.Client_Random,
         Session_Id   => Item.Session,
         Ticket       => Offered_Ticket (Item),
         Offer_Ticket => Item.Wants_Tickets,
         Into         => Into,
         Written      => Written,
         Error        => Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Absorb (Item, Into (Into'First .. Into'First + Written - 1));
      Add (Result, Send_Handshake, Into'First, Into'First + Written - 1);
      Item.State := Wait_Server_Hello;
   end Begin_Handshake;

   procedure Adopt_Hello
     (Item         : in out Machine;
      Config       : not null access constant SSL.Configurations.Client_Configuration;
      Now          : SSL.Clocks.Wall_Time;
      Hello        : Byte_Array;
      Random_Value : SSL.Handshake_Messages.Random_Bytes;
      Session_Id   : Byte_Array;
      Error        : out SSL.Errors.Error_Information)
   is
   begin
      Error := SSL.Errors.No_Error;

      Item.Config := Config;
      Item.Now := Now;
      Item.Bounds := Config_Package.Bounds (Config.all);
      Item.Name := Config_Package.Server_Name_Indication (Config.all);
      Item.Client_Random := Random_Value;
      Item.Session := [others => 0];
      if Session_Id'Length > 0 then
         Item.Session (1 .. Session_Id'Length) := Session_Id;
      end if;

      --  The transcript starts with the hello that was actually sent, absorbed
      --  as it went out. Re-encoding it here would produce a transcript the
      --  server does not share.
      SSL.Transcripts.Start (Item.Transcript);
      Absorb (Item, Hello);

      Item.State := Wait_Server_Hello;
   end Adopt_Hello;

   ---------------------------------------------------------------------------
   --  ServerHello
   ---------------------------------------------------------------------------

   procedure Handle_Server_Hello
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   --  Take up an accepted ticket: the session's master secret becomes this
   --  connection's, and the key block comes from it and the two fresh randoms.
   --
   --  Nothing else is inherited implicitly. The authentication, the name and
   --  the protocol come from the session because that is what a session *is* --
   --  the record of a handshake that authenticated -- and every one of them was
   --  checked against this connection's requirements before the ticket was
   --  offered at all.
   procedure Resume
     (Item   : in out Machine;
      Result : out Plan;
      Error  : out SSL.Errors.Error_Information);

   procedure Resume
     (Item   : in out Machine;
      Result : out Plan;
      Error  : out SSL.Errors.Error_Information)
   is
      Local  : SSL.Errors.Error_Information;
      Secret : Byte_Array (1 .. 64) := [others => 0];
      Length : Byte_Index;
   begin
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

      Item.Name := SSL.Sessions.Server_Name (Item.Offered);
      Item.Has_Protocol := SSL.Sessions.Has_Protocol (Item.Offered);
      if Item.Has_Protocol then
         Item.Protocol := SSL.Sessions.Protocol (Item.Offered);
      end if;
      Item.Peer_Accepted := SSL.Sessions.Peer_Authenticated (Item.Offered);

      Derive_Key_Block
        (Suite         => Item.Suite,
         Master        => Item.Master,
         Client_Random => Item.Client_Random,
         Server_Random => Item.Server_Random,
         Client_Side   => Item.Write_Keys,
         Server_Side   => Item.Read_Keys,
         Error         => Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      SSL.Sessions.Wipe (Item.Offered);
      Item.Has_Offer := False;
      Item.Is_Resumed := True;

      --  The abbreviated handshake reverses the Finished order: the server
      --  sends its ChangeCipherSpec and Finished first, and this end answers.
      --  So there is nothing to send here.
      Item.State :=
        (if Item.Expect_Ticket then Wait_Session_Ticket else Wait_Change_Cipher_Spec);
   end Resume;

   procedure Handle_Server_Hello
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Parsed     : Messages.Server_Hello_Message;
      Extensions : Legacy.Hello_Extensions;
      Local      : SSL.Errors.Error_Information;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Messages.Parse_Server_Hello (Message, Item.Bounds, Parsed, Local, Legacy => True);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      if Messages.Selected_Version (Parsed) /= SSL.Versions.TLS_1_2_Value then
         --  A server that answered a TLS 1.2 hello with anything else. If it
         --  selected 1.3 the engine would have routed this elsewhere, so
         --  reaching here means it selected something older, which this library
         --  does not implement.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Selected_Version_Not_Offered, SSL.Errors.Peer_Message));
         return;
      end if;

      if SSL.Versions.Has_Downgrade_Sentinel (Messages.Random (Parsed)) then
         --  RFC 8446 section 4.1.3. This client offered TLS 1.2 only, so a
         --  sentinel here means a 1.3-capable server thinks it was talking to a
         --  client that offered 1.3 -- which means the offer was rewritten.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Downgrade_Sentinel_Detected, SSL.Errors.Peer_Message));
         return;
      end if;

      if not Suites.Contains
               (Config_Package.Cipher_Suites (Item.Config.all),
                Messages.Selected_Suite (Parsed))
        or else Suites.Version_Of (Messages.Selected_Suite (Parsed)) /= SSL.Versions.TLS_1_2
      then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Selected_Suite_Not_Offered, SSL.Errors.Peer_Message));
         return;
      end if;

      Item.Suite := Messages.Selected_Suite (Parsed);
      Item.Server_Random := Messages.Random (Parsed);

      Legacy.Read_Hello_Extensions
        (Message, SSL.Extensions.In_Legacy_Server_Hello, Item.Bounds, Extensions, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      if not Extensions.Extended_Master_Secret then
         --  RFC 7627, and this is where it is enforced. Without it the master
         --  secret is not bound to this handshake, and two connections can be
         --  made to share one -- the triple-handshake attack. A server that
         --  will not do it gets no connection.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Extended_Master_Secret_Missing,
                    SSL.Errors.Peer_Message));
         return;
      end if;
      Item.Extended_Master := True;

      if Extensions.Renegotiation_Info and then not Extensions.Renegotiation_Empty then
         --  A non-empty renegotiated_connection in an initial handshake. This
         --  library never renegotiates, so there is nothing this could
         --  correctly be.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Renegotiation_Attempted, SSL.Errors.Peer_Message));
         return;
      end if;

      if Extensions.Point_Formats_Present and then not Extensions.Uncompressed_Points then
         --  A server offering only compressed point formats. Decompressing a
         --  point is arithmetic on an attacker-chosen value for no benefit, so
         --  this library does not, and a server that offers nothing else has
         --  offered nothing usable.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Key_Exchange_Value_Invalid, SSL.Errors.Peer_Message));
         return;
      end if;

      --  The application protocol the server selected. Checked against what
      --  this client offered rather than taken on trust: a server answering
      --  with a protocol nobody offered has selected nothing, and an
      --  application dispatching on it would dispatch on the server's choice
      --  of subject rather than its own.
      if Extensions.Protocol_Present then
         declare
            Octets : constant Byte_Array :=
              Message (Extensions.Protocol.First .. Extensions.Protocol.Last);
            Chosen : SSL.ALPN.Protocol_Name;
         begin
            if not SSL.ALPN.Make (Octets, Chosen)
              or else not SSL.ALPN.Contains
                            (Config_Package.Application_Protocols (Item.Config.all),
                             Chosen)
            then
               Refuse (Item, Result, Error,
                       SSL.Errors.Make
                         (SSL.Errors.Code_No_Application_Protocol_Overlap,
                          SSL.Errors.Peer_Message));
               return;
            end if;
            Item.Protocol := Chosen;
            Item.Has_Protocol := True;
         end;

      elsif Config_Package.ALPN_Requirement (Item.Config.all) = SSL.ALPN.Required then
         --  Required and not answered.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_No_Application_Protocol_Overlap,
                    SSL.Errors.Peer_Message));
         return;
      end if;

      --  The transcript hash is the suite's, and the suite is now known.
      SSL.Transcripts.Select_Algorithm (Item.Transcript, Suites.Hash_Of (Item.Suite));
      Absorb (Item, Message);

      --  RFC 5077 section 3.4: the server accepted the ticket exactly when it
      --  echoed the session identifier the client sent. The identifier is
      --  thirty-two random octets, so an echo is not something a server that
      --  did not accept could produce by accident.
      Item.Expect_Ticket := Extensions.Session_Ticket_Present;

      if Item.Has_Offer
        and then Messages.Session_Id (Parsed)'Length = Item.Session'Length
        and then Messages.Session_Id (Parsed) = Item.Session
      then
         if SSL.Sessions.Cipher_Suite (Item.Offered) /= Item.Suite then
            --  Resuming under a suite other than the one the session was
            --  established under. The master secret is the session's, but the
            --  PRF and the key block would be another suite's, so the two ends
            --  would derive different keys and the Finished would fail with no
            --  cause attached. Refused where it can still be named.
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_Selected_Suite_Not_Offered,
                       SSL.Errors.Peer_Message));
            return;
         end if;

         Resume (Item, Result, Error);
         return;
      end if;

      if Item.Has_Offer then
         --  The offer was declined, which is ordinary. The session goes now
         --  rather than at the end of the handshake: it is a secret this
         --  connection has no further use for.
         SSL.Sessions.Wipe (Item.Offered);
         Item.Has_Offer := False;
      end if;

      Item.State := Wait_Certificate;
   end Handle_Server_Hello;

   ---------------------------------------------------------------------------
   --  Certificate
   ---------------------------------------------------------------------------

   procedure Handle_Certificate
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_Certificate
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Local : SSL.Errors.Error_Information;
      Spans : Legacy.Chain_Span_Array;
      Count : Natural;
      Total : Byte_Index := 0;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Legacy.Parse_Certificate (Message, Item.Bounds, Spans, Count, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      if Count = 0 then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Certificate_List_Empty, SSL.Errors.Peer_Message));
         return;
      end if;

      for Index in 1 .. Count loop
         Total := Total + (Spans (Index).Last - Spans (Index).First + 1);
      end loop;

      declare
         Chain   : aliased Validation.Chain_Storage (Length => Total);
         Cursor  : Byte_Index := 1;
         Anchors : constant access constant SSL.Trust.Snapshot :=
           Config_Package.Anchors (Item.Config.all);
      begin
         if Anchors = null then
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_Trust_Required_But_Absent,
                       SSL.Errors.Local_Policy));
            return;
         end if;

         for Index in 1 .. Count loop
            declare
               Width : constant Byte_Index :=
                 Spans (Index).Last - Spans (Index).First + 1;
            begin
               Chain.Spans (Index) := (First => Cursor, Last => Cursor + Width - 1);
               Chain.Octets (Cursor .. Cursor + Width - 1) :=
                 Message (Spans (Index).First .. Spans (Index).Last);
               Cursor := Cursor + Width;
            end;
         end loop;

         Validation.Validate
           (Chain    => Chain,
            Count    => Count,
            Anchors  => Anchors.all,
            Identity =>
              (if SSL.Server_Names.Is_Present
                    (Config_Package.Expected_Name (Item.Config.all))
               then Validation.For_Name (Config_Package.Expected_Name (Item.Config.all))
               else Validation.For_Address
                      (Config_Package.Expected_Address (Item.Config.all))),
            Role     => Validation.Server_Certificate,
            At_Time  => Item.Now,
            Bounds   => Item.Bounds,
            Result   => Item.Peer,
            Error    => Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;

         --  Revocation then pinning, in that order: both are judgements about a
         --  chain that has already been accepted.
         SSL.Trust.Revocation.Evaluate
           (Policy    => Config_Package.Revocation (Item.Config.all),
            Answer    => SSL.Trust.Revocation.Status_Unknown,
            Source    => SSL.Trust.Revocation.Stapled_By_Peer,
            Available => False,
            At_Time   => Item.Now,
            Bounds    => Item.Bounds,
            Error     => Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;

         if Config_Package.Pinning_Mode_Of (Item.Config.all)
            /= SSL.Trust.Pinning.No_Pinning
         then
            SSL.Trust.Pinning.Evaluate
              (Mode       => Config_Package.Pinning_Mode_Of (Item.Config.all),
               Pins       => Config_Package.Pins (Item.Config.all),
               Leaf       => Validation.Leaf_Fingerprint (Item.Peer),
               Public_Key => Validation.Public_Key_Fingerprint (Item.Peer),
               Name       => Config_Package.Expected_Name (Item.Config.all),
               Protocol   => Item.Protocol,
               At_Time    => Item.Now,
               Error      => Local);
            if SSL.Errors.Is_Error (Local) then
               Refuse (Item, Result, Error, Local);
               return;
            end if;
         end if;
      end;

      Item.Peer_Accepted := True;
      Absorb (Item, Message);
      Item.State := Wait_Key_Exchange;
   end Handle_Certificate;

   ---------------------------------------------------------------------------
   --  ServerKeyExchange
   ---------------------------------------------------------------------------

   --  The random source is a parameter here and nowhere else: this is the one
   --  handler that needs one, and carrying it through the other five would be
   --  noise at every call site.
   procedure Handle_Key_Exchange
     (Item    : in out Machine;
      Message : Byte_Array;
      Source  : in out SSL.Crypto.Random_Source;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_Key_Exchange
     (Item    : in out Machine;
      Message : Byte_Array;
      Source  : in out SSL.Crypto.Random_Source;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Parsed : Legacy.Key_Exchange_Message;
      Local  : SSL.Errors.Error_Information;

      Parameters_First : Byte_Index;
      Parameters_Last  : Byte_Index;
      Signature_First  : Byte_Index;
      Signature_Last   : Byte_Index;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Legacy.Parse_Key_Exchange (Message, Item.Bounds, Parsed, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      if not Groups.Contains (Config_Package.Groups (Item.Config.all), Legacy.Group (Parsed))
      then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (Code       => SSL.Errors.Code_Selected_Group_Not_Offered,
                    Origin     => SSL.Errors.Peer_Message,
                    Parameters =>
                      [SSL.Errors.Text_Parameter
                         ("group", Groups.Image (Legacy.Group (Parsed)))]));
         return;
      end if;
      Item.Named := Legacy.Group (Parsed);

      if not Legacy.Scheme_Recognized (Parsed)
        or else not Schemes.Contains
                      (Config_Package.Signature_Schemes (Item.Config.all),
                       Legacy.Scheme (Parsed))
        or else not Schemes.Usable_For_Handshake
                      (Legacy.Scheme (Parsed), SSL.Versions.TLS_1_2)
      then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (Code       => SSL.Errors.Code_No_Common_Signature_Scheme,
                    Origin     => SSL.Errors.Peer_Message,
                    Parameters =>
                      [SSL.Errors.Text_Parameter
                         ("scheme", Schemes.Image (Legacy.Scheme_Value (Parsed)))]));
         return;
      end if;
      Item.Scheme := Legacy.Scheme (Parsed);

      Legacy.Parameters_Span (Parsed, Parameters_First, Parameters_Last);
      Legacy.Signature_Span (Parsed, Signature_First, Signature_Last);

      --  The signature is over the two randoms and the parameters exactly as
      --  they arrived. This is the whole security of a TLS 1.2 ECDHE
      --  handshake: without it the ephemeral share is unauthenticated and
      --  anyone in the path can substitute their own.
      SSL.Crypto.Verify_Signature
        (Scheme      => Item.Scheme,
         Public_Key  => Validation.Leaf_Public_Key (Item.Peer),
         Signed_Data =>
           Key_Exchange_Signed_Content
             (Client_Random => Item.Client_Random,
              Server_Random => Item.Server_Random,
              Parameters    => Message (Parameters_First .. Parameters_Last)),
         Signature   => Message (Signature_First .. Signature_Last),
         Error       => Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Signature_Verification_Failed,
                    SSL.Errors.Peer_Message));
         return;
      end if;

      --  The agreement itself, once the share has been proved to come from the
      --  certificate this client accepted.
      declare
         Share_First : Byte_Index;
         Share_Last  : Byte_Index;
      begin
         Legacy.Share_Span (Parsed, Share_First, Share_Last);

         SSL.Crypto.Generate (Item.Exchange, Item.Named, Source, Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;

         SSL.Crypto.Agree
           (Item       => Item.Exchange,
            Peer_Share => Message (Share_First .. Share_Last),
            Target     => Item.Shared,
            Error      => Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;
      end;

      Absorb (Item, Message);
      Item.State := Wait_Request_Or_Done;
   end Handle_Key_Exchange;

   ---------------------------------------------------------------------------
   --  The client's second flight
   ---------------------------------------------------------------------------

   procedure Handle_Server_Hello_Done
     (Item    : in out Machine;
      Message : Byte_Array;
      Into    : in out Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_Server_Hello_Done
     (Item    : in out Machine;
      Message : Byte_Array;
      Into    : in out Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Local  : SSL.Errors.Error_Information;
      Cursor : Byte_Index := Into'First;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Legacy.Parse_Server_Hello_Done (Message, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;
      Absorb (Item, Message);

      --  A client that was asked for a certificate declines with an empty one.
      --  Sending a chain would need a signature, and ECDSA signing is blocked
      --  on CryptoLib; sending a chain this endpoint cannot then prove it holds
      --  the key for would be worse than declining.
      if Item.Certificate_Requested then
         declare
            Region : Byte_Array (1 .. Into'Last - Cursor + 1) := [others => 0];
            Length : Byte_Index;
         begin
            --  TLS 1.2's empty Certificate is a three-octet zero length and
            --  nothing else.
            Region (1 .. Messages.Header_Length) :=
              Messages.Encode_Header (Messages.Certificate, 3);
            Region (Messages.Header_Length + 1 .. Messages.Header_Length + 3) :=
              [others => 0];
            Length := Messages.Header_Length + 3;

            Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
            Absorb (Item, Into (Cursor .. Cursor + Length - 1));
            Add (Result, Send_Handshake, Cursor, Cursor + Length - 1);
            Cursor := Cursor + Length;
         end;
      end if;

      --  ClientKeyExchange.
      declare
         Region : Byte_Array (1 .. Into'Last - Cursor + 1) := [others => 0];
         Length : Byte_Index;
      begin
         Legacy.Encode_Client_Key_Exchange
           (Share   => SSL.Crypto.Public_Share (Item.Exchange),
            Into    => Region,
            Written => Length,
            Error   => Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;

         Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
         Absorb (Item, Into (Cursor .. Cursor + Length - 1));
         Add (Result, Send_Handshake, Cursor, Cursor + Length - 1);
         Cursor := Cursor + Length;
      end;

      --  The master secret, bound to the transcript through ClientKeyExchange.
      --  That binding is the extended master secret and is why this library
      --  refuses a peer that will not negotiate it.
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
         Client_Side   => Item.Write_Keys,
         Server_Side   => Item.Read_Keys,
         Error         => Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      --  The epoch switch, then the write keys, then the Finished under them.
      --  That order is the protocol's and getting it wrong sends the Finished
      --  in the clear.
      Add (Result, Send_Change_Cipher_Spec);
      Add (Result, Install_Write_Keys);

      declare
         Region : Byte_Array (1 .. Into'Last - Cursor + 1) := [others => 0];
         Verify : Byte_Array (1 .. Verify_Data_Length) := [others => 0];
         Length : Byte_Index;
      begin
         Compute_Finished
           (Algorithm       => Suites.Hash_Of (Item.Suite),
            Master          => Item.Master,
            Which           => Client_Finished,
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

      Item.State := Wait_Change_Cipher_Spec;
   end Handle_Server_Hello_Done;

   ---------------------------------------------------------------------------
   --  ChangeCipherSpec and the server's Finished
   ---------------------------------------------------------------------------

   procedure Handle_Change_Cipher_Spec
     (Item   : in out Machine;
      Result : out Plan;
      Error  : out SSL.Errors.Error_Information)
   is
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      if Item.State /= Wait_Change_Cipher_Spec then
         --  A ChangeCipherSpec at any other point is a peer changing epoch
         --  before it has established what to change to.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Record_Unexpected_CCS, SSL.Errors.Peer_Message));
         return;
      end if;

      Add (Result, Install_Read_Keys);
      Item.State := Wait_Finished;
   end Handle_Change_Cipher_Spec;

   --  A NewSessionTicket, in either of the two places one can arrive.
   --
   --  It is a handshake message, so it goes into the transcript, and the
   --  server's Finished covers it. A machine that recorded the ticket without
   --  absorbing the message would compute a Finished the server does not agree
   --  with, which is a failure that says nothing about its cause.
   procedure Handle_New_Session_Ticket
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_New_Session_Ticket
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Local    : SSL.Errors.Error_Information;
      Lifetime : Interfaces.Unsigned_32;
      Ticket   : Legacy.Ticket_Span;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Legacy.Parse_New_Session_Ticket (Message, Item.Bounds, Lifetime, Ticket, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Absorb (Item, Message);

      if Ticket.Last - Ticket.First + 1 > SSL.Sessions.Maximum_Ticket then
         --  Too large to keep. Not a failure: the connection is unaffected and
         --  the next one costs a full handshake. Half a ticket is not a ticket,
         --  so it is dropped rather than truncated.
         return;
      end if;

      Item.New_Ticket_Length := Ticket.Last - Ticket.First + 1;
      Item.New_Ticket (1 .. Item.New_Ticket_Length) :=
        Message (Ticket.First .. Ticket.Last);
      Item.New_Lifetime := Natural (Lifetime);
      Item.Has_New_Ticket := True;
   end Handle_New_Session_Ticket;

   --  `Into` is only used on the abbreviated handshake, where this end answers
   --  the server's Finished with its own. On a full handshake the client's
   --  Finished has already gone out and nothing is written here.
   procedure Handle_Finished
     (Item    : in out Machine;
      Message : Byte_Array;
      Into    : in out Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_Finished
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
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Messages.Parse_Finished (Message, Item.Bounds, First, Last, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      if Last - First + 1 /= Verify_Data_Length then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Finished_Verification_Failed,
                    SSL.Errors.Peer_Message));
         return;
      end if;

      --  Over the transcript as it stands *before* this message is absorbed,
      --  which is what the server computed it over.
      Compute_Finished
        (Algorithm       => Suites.Hash_Of (Item.Suite),
         Master          => Item.Master,
         Which           => Server_Finished,
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
         --  The abbreviated handshake: the server went first, so this end
         --  answers with its own epoch switch and its own Finished, over the
         --  transcript that now includes the server's.
         Add (Result, Send_Change_Cipher_Spec);
         Add (Result, Install_Write_Keys);

         declare
            Verify : Byte_Array (1 .. Verify_Data_Length) := [others => 0];
            Length : constant Byte_Index :=
              Messages.Header_Length + Verify_Data_Length;
         begin
            Compute_Finished
              (Algorithm       => Suites.Hash_Of (Item.Suite),
               Master          => Item.Master,
               Which           => Client_Finished,
               Transcript_Hash => SSL.Transcripts.Hash (Item.Transcript),
               Into            => Verify,
               Error           => Local);
            if SSL.Errors.Is_Error (Local) then
               SSL.Crypto.Scrub (Verify);
               Refuse (Item, Result, Error, Local);
               return;
            end if;

            if Into'Length < Length then
               SSL.Crypto.Scrub (Verify);
               Refuse (Item, Result, Error,
                       SSL.Errors.Make
                         (SSL.Errors.Code_Output_Queue_Full,
                          SSL.Errors.Local_Implementation));
               return;
            end if;

            Into (Into'First .. Into'First + Messages.Header_Length - 1) :=
              Messages.Encode_Header (Messages.Finished, Verify_Data_Length);
            Into (Into'First + Messages.Header_Length
                  .. Into'First + Length - 1) := Verify;
            SSL.Crypto.Scrub (Verify);

            Absorb (Item, Into (Into'First .. Into'First + Length - 1));
            Add (Result, Send_Handshake, Into'First, Into'First + Length - 1);
         end;
      end if;

      Add (Result, Handshake_Complete);
      Item.State := Connected;
   end Handle_Finished;

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
         when Wait_Server_Hello =>
            if Kind = Messages.Server_Hello then
               Handle_Server_Hello (Item, Message, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Certificate =>
            if Kind = Messages.Certificate then
               Handle_Certificate (Item, Message, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Key_Exchange =>
            if Kind = Messages.Server_Key_Exchange then
               Handle_Key_Exchange (Item, Message, Source, Result, Error);
            else
               --  A suite that needed no ServerKeyExchange would be a static
               --  one, and this library offers none.
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Request_Or_Done =>
            case Kind is
               when Messages.Certificate_Request =>
                  Item.Certificate_Requested := True;
                  Absorb (Item, Message);
               when Messages.Server_Hello_Done =>
                  Handle_Server_Hello_Done (Item, Message, Into, Result, Error);
               when others =>
                  Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end case;

         when Wait_Finished =>
            if Kind = Messages.Finished then
               Handle_Finished (Item, Message, Into, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Session_Ticket =>
            if Kind = Messages.New_Session_Ticket then
               Handle_New_Session_Ticket (Item, Message, Result, Error);
               if not SSL.Errors.Is_Error (Error) then
                  Item.Expect_Ticket := False;
                  Item.State := Wait_Change_Cipher_Spec;
               end if;
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Change_Cipher_Spec =>
            --  The full handshake's NewSessionTicket: RFC 5077 puts it after
            --  the client's Finished and before the server's ChangeCipherSpec,
            --  which is exactly here. Accepted only when the server said in its
            --  ServerHello that one was coming.
            if Kind = Messages.New_Session_Ticket and then Item.Expect_Ticket then
               Handle_New_Session_Ticket (Item, Message, Result, Error);
               if not SSL.Errors.Is_Error (Error) then
                  Item.Expect_Ticket := False;
               end if;
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Connected | Start | Failed =>
            --  After the handshake finished. TLS 1.2 has no post-handshake
            --  messages this library accepts: a HelloRequest is a
            --  renegotiation invitation and is refused with everything else.
            Refuse (Item, Result, Error, Unexpected (Item, Kind));
      end case;
   end Handle_Message;

   ---------------
   -- Wipe --
   ---------------

   procedure Wipe (Item : in out Machine) is
   begin
      SSL.Crypto.Wipe (Item.Exchange);
      SSL.Secrets.Wipe (Item.Shared);
      SSL.Secrets.Wipe (Item.Master);
      TLS12.Wipe (Item.Write_Keys);
      TLS12.Wipe (Item.Read_Keys);
      SSL.Transcripts.Start (Item.Transcript);

      --  The session and the ticket go too. A ticket is not a secret by
      --  itself, but a ticket together with the master secret this machine
      --  holds is a resumable connection, and the two live in the same object.
      SSL.Sessions.Wipe (Item.Offered);
      Item.Has_Offer := False;
      Item.New_Ticket := [others => 0];
      Item.New_Ticket_Length := 0;
      Item.Has_New_Ticket := False;
   end Wipe;

end SSL.TLS12.Client;
