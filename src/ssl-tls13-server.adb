with SSL.ALPN;
with SSL.Authentication;
with SSL.Cipher_Suites;
with SSL.Credentials;
with SSL.Handshake_Messages;
with SSL.Server_Names;
with SSL.Signature_Schemes;
with SSL.Supported_Groups;
with SSL.Transcripts;
with SSL.Trust;
with SSL.Versions;

package body SSL.TLS13.Server is

   package Config_Package renames SSL.Configurations;
   package Messages renames SSL.Handshake_Messages;
   package Groups renames SSL.Supported_Groups;
   package Schedules renames SSL.Key_Schedule;
   package Schemes renames SSL.Signature_Schemes;
   package Suites renames SSL.Cipher_Suites;
   package Validation renames SSL.Certificate_Validation;

   use type SSL.ALPN.ALPN_Requirement;
   use type SSL.ALPN.Selection_Policy;
   use type SSL.Authentication.Client_Authentication_Policy;
   use type SSL.Cipher_Suites.Cipher_Suite;
   use type SSL.Configurations.Negotiation_Preference;
   use type SSL.Handshake_Messages.Message_Type;
   use type SSL.Supported_Groups.Named_Group;
   use type SSL.Versions.Protocol_Version;
   use type SSL.Ticket_Keys.Ring_Reference;

   ---------------
   -- Image --
   ---------------

   function Image (Item : Server_State) return String is
     (case Item is
         when Start                          => "start",
         when Received_Client_Hello          => "wait for ClientHello",
         when Wait_Second_Client_Hello        => "wait for the second ClientHello",
         when Wait_Client_Flight             => "wait for the client's second flight",
         when Wait_Client_Certificate_Verify => "wait for the client's CertificateVerify",
         when Wait_Client_Finished           => "wait for the client's Finished",
         when Connected                      => "connected",
         when Failed                         => "failed");

   function Context_Of (Item : aliased Machine) return access constant Handshake_Context is
      Reference : constant access constant Handshake_Context := Item.Context'Access;
   begin
      return Reference;
   end Context_Of;

   function Schedule_Of (Item : aliased in out Machine) return access SSL.Key_Schedule.Schedule is
      Reference : constant access SSL.Key_Schedule.Schedule := Item.Context.Schedule'Access;
   begin
      return Reference;
   end Schedule_Of;

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

   --  Choose the cipher suite.
   --
   --  Whose order wins is a configured decision, not a fixed one. Server
   --  preference is the usual choice -- an operator who has ranked the suites
   --  wants that ranking honoured -- but client preference is what a deployment
   --  wants when the clients are the ones that know their own hardware.
   function Choose_Suite
     (Item     : Machine;
      Offered  : Suites.Suite_List;
      Selected : out Suites.Cipher_Suite) return Boolean;

   function Choose_Suite
     (Item     : Machine;
      Offered  : Suites.Suite_List;
      Selected : out Suites.Cipher_Suite) return Boolean
   is
      Mine : constant Suites.Suite_List := Config_Package.Cipher_Suites (Item.Config.all);
   begin
      Selected := Suites.TLS_AES_128_GCM_SHA256;

      if Config_Package.Preference (Item.Config.all) = Config_Package.Server_Preference then
         for Index in 1 .. Suites.Length (Mine) loop
            if Suites.Contains (Offered, Suites.Element (Mine, Index))
              and then Suites.Version_Of (Suites.Element (Mine, Index)) = SSL.Versions.TLS_1_3
            then
               Selected := Suites.Element (Mine, Index);
               return True;
            end if;
         end loop;
      else
         for Index in 1 .. Suites.Length (Offered) loop
            if Suites.Contains (Mine, Suites.Element (Offered, Index))
              and then Suites.Version_Of (Suites.Element (Offered, Index)) = SSL.Versions.TLS_1_3
            then
               Selected := Suites.Element (Offered, Index);
               return True;
            end if;
         end loop;
      end if;

      return False;
   end Choose_Suite;

   --  Choose the group, and say whether the client already supplied a share for
   --  it. When it did not, the handshake needs a HelloRetryRequest.
   procedure Choose_Group
     (Item      : Machine;
      Hello     : Messages.Client_Hello_Message;
      Selected  : out Groups.Named_Group;
      Have_Share : out Boolean;
      Found     : out Boolean);

   procedure Choose_Group
     (Item      : Machine;
      Hello     : Messages.Client_Hello_Message;
      Selected  : out Groups.Named_Group;
      Have_Share : out Boolean;
      Found     : out Boolean)
   is
      Mine     : constant Groups.Group_List := Config_Package.Groups (Item.Config.all);
      Offered  : constant Groups.Group_List := Messages.Offered_Groups (Hello);
      Shared   : constant Groups.Group_List := Messages.Key_Share_Groups (Hello);
   begin
      Selected := Groups.X25519;
      Have_Share := False;
      Found := False;

      --  A group the client has already sent a share for is preferred over one
      --  it has only listed, whatever the preference order says. Choosing a
      --  listed-but-unshared group when a shared one is acceptable costs a
      --  whole extra round trip for nothing.
      for Index in 1 .. Groups.Length (Mine) loop
         if Groups.Contains (Shared, Groups.Element (Mine, Index)) then
            Selected := Groups.Element (Mine, Index);
            Have_Share := True;
            Found := True;
            return;
         end if;
      end loop;

      for Index in 1 .. Groups.Length (Mine) loop
         if Groups.Contains (Offered, Groups.Element (Mine, Index)) then
            Selected := Groups.Element (Mine, Index);
            Found := True;
            return;
         end if;
      end loop;
   end Choose_Group;

   procedure Set_Ticket_Keys
     (Item  : in out Machine;
      Value : SSL.Ticket_Keys.Ring_Reference)
   is
   begin
      Item.Ring := Value;
   end Set_Ticket_Keys;

   --  Consider a client's pre_shared_key offer.
   --
   --  Everything about this is "decline rather than fail". A ticket this server
   --  cannot open, one bound to a different suite, one whose binder does not
   --  verify -- each means a full handshake, which is the outcome a client that
   --  offered nothing would have got anyway. The one exception is a binder that
   --  is present and wrong, which is a peer claiming a key it does not have and
   --  ends the connection.
   procedure Consider_Offer
     (Item     : in out Machine;
      Message  : Byte_Array;
      Hello    : Messages.Client_Hello_Message;
      Suite    : Suites.Cipher_Suite;
      Accepted : out Boolean;
      Error    : out SSL.Errors.Error_Information);

   procedure Consider_Offer
     (Item     : in out Machine;
      Message  : Byte_Array;
      Hello    : Messages.Client_Hello_Message;
      Suite    : Suites.Cipher_Suite;
      Accepted : out Boolean;
      Error    : out SSL.Errors.Error_Information)
   is
      Local  : SSL.Errors.Error_Information;
      Usable : Boolean;
      First  : Byte_Index;
      Last   : Byte_Index;
   begin
      Accepted := False;
      Error := SSL.Errors.No_Error;

      if Item.Ring = null
        or else not Messages.Offers_PSK (Hello)
        or else Messages.PSK_Identity_Count (Hello) = 0
      then
         return;
      end if;

      --  This library resumes only with a fresh key exchange. A client that
      --  will not accept psk_dhe_ke is offering something with no forward
      --  secrecy, and the offer is declined rather than taken up.
      if not Messages.Allows_PSK_With_DHE (Hello) then
         return;
      end if;

      --  Only the first identity is considered. A client that wanted a
      --  particular session put it first, and trying each in turn would mean
      --  doing a decryption per identity for a peer that pays nothing to list
      --  them.
      Messages.PSK_Identity_Span (Hello, 1, First, Last);

      SSL.Ticket_Keys.Open
        (Item   => Item.Ring.all,
         Ticket => Message (First .. Last),
         Now    => Item.Now,
         Into   => Item.Offered,
         Usable => Usable,
         Error  => Local);
      if not Usable then
         --  Undifferentiated by construction, and declined rather than
         --  reported: a full handshake follows and the peer learns nothing
         --  about why.
         return;
      end if;

      if SSL.Sessions.Cipher_Suite (Item.Offered) /= Suite then
         --  The pre-shared key is derived under the session's own hash, so
         --  resuming under another suite would resume under a key neither end
         --  can derive.
         SSL.Sessions.Wipe (Item.Offered);
         return;
      end if;

      --  The binder. Everything up to this point could have been done by an
      --  attacker holding a stolen ticket; the binder is what proves the peer
      --  also holds the key inside it.
      declare
         Width  : constant Byte_Index :=
           SSL.Cipher_Suites.Digest_Length (Suites.Hash_Of (Suite));
         Secret : Byte_Array (1 .. 64) := [others => 0];
         Length : Byte_Index;
         Expected : Byte_Array (1 .. Width) := [others => 0];
         Offset : constant Byte_Index := Messages.PSK_Binders_Offset (Hello);
         Binder_First : Byte_Index;
         Binder_Last  : Byte_Index;
      begin
         Messages.PSK_Binder_Span (Hello, 1, Binder_First, Binder_Last);
         if Binder_Last - Binder_First + 1 /= Width then
            SSL.Sessions.Wipe (Item.Offered);
            return;
         end if;

         SSL.Transcripts.Select_Algorithm
           (Item.Context.Transcript, Suites.Hash_Of (Suite));
         Schedules.Start (Item.Context.Schedule, Suite);

         SSL.Sessions.Get_Secret (Item.Offered, Secret, Length);
         Schedules.Derive_Early_From_PSK
           (Item.Context.Schedule, Secret (1 .. Length), Local);
         SSL.Crypto.Scrub (Secret);
         if SSL.Errors.Is_Error (Local) then
            SSL.Sessions.Wipe (Item.Offered);
            Schedules.Wipe (Item.Context.Schedule);
            return;
         end if;

         --  Over the ClientHello truncated immediately before the binders,
         --  which is exactly the span the client hashed.
         Absorb (Item.Context, Message (Message'First .. Offset - 1));

         Schedules.Compute_Binder
           (Item            => Item.Context.Schedule,
            Transcript_Hash => SSL.Transcripts.Hash (Item.Context.Transcript),
            Is_External     => False,
            Into            => Expected,
            Error           => Local);
         if SSL.Errors.Is_Error (Local) then
            SSL.Crypto.Scrub (Expected);
            SSL.Sessions.Wipe (Item.Offered);
            return;
         end if;

         if not SSL.Crypto.Equal (Expected, Message (Binder_First .. Binder_Last)) then
            --  A ticket this server issued, presented with a binder that does
            --  not match it. That is a peer claiming a key it does not hold,
            --  and it ends the connection rather than falling back: falling
            --  back would make this a free oracle for testing stolen tickets.
            SSL.Crypto.Scrub (Expected);
            SSL.Sessions.Wipe (Item.Offered);
            Error := SSL.Errors.Make
              (SSL.Errors.Code_Binder_Verification_Failed, SSL.Errors.Peer_Message);
            return;
         end if;
         SSL.Crypto.Scrub (Expected);

         --  The rest of the ClientHello, so the transcript holds the whole of
         --  it exactly as the client absorbed it.
         Absorb (Item.Context, Message (Offset .. Message'Last));

         Accepted := True;
         Item.Resumed := True;
         Item.Context.Result.Resumed := True;
         Item.Context.Result.Peer_Authenticated := False;
      end;
   end Consider_Offer;

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
      SSL.Transcripts.Start (Item.Context.Transcript);
      Item.State := Received_Client_Hello;
   end Begin_Handshake;

   ---------------------------------------------------------------------------
   --  The ClientHello and the whole server flight
   ---------------------------------------------------------------------------

   --  Everything from EncryptedExtensions to the server's Finished. Written as
   --  one sequence because it is one flight: the messages are consecutive, they
   --  all go under handshake keys, and the transcript must see them in order.
   procedure Write_Server_Flight
     (Item   : in out Machine;
      Hello  : Messages.Client_Hello_Message;
      Into   : in out Byte_Array;
      Cursor : in out Byte_Index;
      Result : in out Plan;
      Error  : out SSL.Errors.Error_Information);

   procedure Write_Server_Flight
     (Item   : in out Machine;
      Hello  : Messages.Client_Hello_Message;
      Into   : in out Byte_Array;
      Cursor : in out Byte_Index;
      Result : in out Plan;
      Error  : out SSL.Errors.Error_Information)
   is
      --  Null when this handshake resumed, in which case nothing below reaches
      --  it: the resumed path returns before the Certificate is written.
      Credential : constant access constant SSL.Credentials.Credential :=
        (if Item.Credential_Index = 0 then null
         else Config_Package.Credential_At (Item.Config.all, Item.Credential_Index));

      --  Write one message that a subprogram has produced into Region, then
      --  absorb it and add the step. Every message below goes through this, so
      --  none of them can be sent without being in the transcript.
      procedure Emit (Length : Byte_Index);

      procedure Emit (Length : Byte_Index) is
      begin
         Absorb (Item.Context, Into (Cursor .. Cursor + Length - 1));
         Add (Result, Send_Handshake, Cursor, Cursor + Length - 1);
         Cursor := Cursor + Length;
      end Emit;

      Length : Byte_Index;
      First  : Byte_Index;
      Last   : Byte_Index;
   begin
      Error := SSL.Errors.No_Error;

      --  EncryptedExtensions.
      declare
         Region : Byte_Array (1 .. Into'Last - Cursor + 1);
      begin
         Messages.Encode_Encrypted_Extensions
           (Protocol         => Item.Context.Result.Protocol,
            Has_Protocol     => Item.Context.Result.Has_Protocol,
            Record_Limit     => 0,
            Acknowledge_Name =>
              SSL.Server_Names.Is_Present (Messages.Offered_Name (Hello)),
            Into             => Region,
            Written          => Length,
            Error            => Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;
         Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
      end;
      Emit (Length);

      --  CertificateRequest, when the policy asks a client to authenticate.
      if Config_Package.Client_Authentication (Item.Config.all)
         /= SSL.Authentication.Not_Requested
      then
         declare
            Region : Byte_Array (1 .. Into'Last - Cursor + 1);
         begin
            Messages.Encode_Certificate_Request
              (Context             => Empty_Bytes,
               Schemes             => Config_Package.Signature_Schemes (Item.Config.all),
               Certificate_Schemes => Schemes.No_Schemes,
               Into                => Region,
               Written             => Length,
               Error               => Error);
            if SSL.Errors.Is_Error (Error) then
               return;
            end if;
            Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
         end;
         Emit (Length);
         Item.Requested_Client_Certificate := True;
      end if;

      --  Certificate and CertificateVerify, unless this handshake resumed. A
      --  resumed one sends neither: the server has already proved, by producing
      --  keys that work, that it holds the pre-shared key from the earlier
      --  handshake, and signing again would prove nothing new.
      if Item.Resumed then
         Write_Finished
           (Item      => Item.Context,
            Which     => Schedules.Server_Side,
            Into      => Into,
            At_Offset => Cursor,
            First     => First,
            Last      => Last,
            Error     => Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;
         Add (Result, Send_Handshake, First, Last);
         Cursor := Last + 1;

         Schedules.Derive_Master
           (Item                 => Item.Context.Schedule,
            Server_Finished_Hash => SSL.Transcripts.Hash (Item.Context.Transcript),
            Error                => Error);
         return;
      end if;

      declare
         Count : constant Positive := SSL.Credentials.Chain_Length (Credential.all);
         Total : Byte_Index := 0;
      begin
         for Index in 1 .. Count loop
            Total := Total + SSL.Credentials.Certificate_At (Credential.all, Index)'Length;
         end loop;

         declare
            Chain  : Byte_Array (1 .. Total);
            Spans  : Messages.Certificate_Span_List := [others => <>];
            At_Now : Byte_Index := 1;
            Region : Byte_Array (1 .. Into'Last - Cursor + 1);
         begin
            for Index in 1 .. Count loop
               declare
                  One : constant Byte_Array :=
                    SSL.Credentials.Certificate_At (Credential.all, Index);
               begin
                  Chain (At_Now .. At_Now + One'Length - 1) := One;
                  Spans (Index) := (First => At_Now, Last => At_Now + One'Length - 1);
                  At_Now := At_Now + One'Length;
               end;
            end loop;

            Messages.Encode_Certificate
              (Chain   => Chain,
               Spans   => Spans,
               Count   => Count,
               Context => Empty_Bytes,
               Staple  => Empty_Bytes,
               Into    => Region,
               Written => Length,
               Error   => Error);
            if SSL.Errors.Is_Error (Error) then
               return;
            end if;
            Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
         end;
      end;
      Emit (Length);

      --  CertificateVerify. The transcript hash is taken after the Certificate
      --  has been absorbed and before this message is, which is exactly what
      --  the signature is defined to cover.
      declare
         Chosen    : Schemes.Signature_Scheme;
         Found     : Boolean := False;
         Offered   : constant Schemes.Scheme_List := Messages.Offered_Schemes (Hello);
         Mine      : constant Schemes.Scheme_List :=
           SSL.Credentials.Supported_Schemes (Credential.all);
      begin
         Chosen := Schemes.Ed25519;
         for Index in 1 .. Schemes.Length (Mine) loop
            if Schemes.Contains (Offered, Schemes.Element (Mine, Index))
              and then Schemes.Usable_For_Handshake
                         (Schemes.Element (Mine, Index), SSL.Versions.TLS_1_3)
            then
               Chosen := Schemes.Element (Mine, Index);
               Found := True;
               exit;
            end if;
         end loop;

         if not Found then
            Error := SSL.Errors.Make
              (SSL.Errors.Code_No_Common_Signature_Scheme, SSL.Errors.Local_Policy);
            return;
         end if;

         declare
            Content : constant Byte_Array :=
              Messages.Certificate_Verify_Content
                (Messages.Server_Signing, SSL.Transcripts.Hash (Item.Context.Transcript));
            Buffer  : Byte_Array (1 .. SSL.Credentials.Maximum_Signature_Length);
            Written : Byte_Index;
            Region  : Byte_Array (1 .. Into'Last - Cursor + 1);
         begin
            SSL.Credentials.Sign
              (Item        => Credential.all,
               Scheme      => Chosen,
               Signed_Data => Content,
               Signature   => Buffer,
               Length      => Written,
               Error       => Error);
            if SSL.Errors.Is_Error (Error) then
               return;
            end if;

            Messages.Encode_Certificate_Verify
              (Scheme    => Chosen,
               Signature => Buffer (1 .. Written),
               Into      => Region,
               Written   => Length,
               Error     => Error);
            if SSL.Errors.Is_Error (Error) then
               return;
            end if;
            Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
         end;
      end;
      Emit (Length);

      --  Finished. Write_Finished absorbs it itself, so it is not passed
      --  through Emit.
      Write_Finished
        (Item      => Item.Context,
         Which     => Schedules.Server_Side,
         Into      => Into,
         At_Offset => Cursor,
         First     => First,
         Last      => Last,
         Error     => Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;
      Add (Result, Send_Handshake, First, Last);
      Cursor := Last + 1;

      --  The application traffic secrets are bound to the transcript through
      --  this Finished, so they can be derived now -- which is what lets the
      --  step after this one install the write keys and lets this server send
      --  application data without waiting for the client's flight.
      Schedules.Derive_Master
        (Item                 => Item.Context.Schedule,
         Server_Finished_Hash => SSL.Transcripts.Hash (Item.Context.Transcript),
         Error                => Error);
   end Write_Server_Flight;

   procedure Handle_Client_Hello
     (Item    : in out Machine;
      Message : Byte_Array;
      Source  : in out SSL.Crypto.Random_Source;
      Into    : in out Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_Client_Hello
     (Item    : in out Machine;
      Message : Byte_Array;
      Source  : in out SSL.Crypto.Random_Source;
      Into    : in out Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Hello  : Messages.Client_Hello_Message;
      Local  : SSL.Errors.Error_Information;
      Suite  : Suites.Cipher_Suite;
      Group  : Groups.Named_Group;
      Have   : Boolean;
      Found  : Boolean;
      Cursor : Byte_Index := Into'First;
      Length : Byte_Index;
      Random_Value : Messages.Random_Bytes;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Messages.Parse_Client_Hello (Message, Item.Bounds, Hello, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      --  The version is decided by supported_versions and by nothing else. A
      --  ClientHello without it is a pre-1.3 client, which the TLS 1.2 machine
      --  handles; this one refuses rather than guessing.
      if not SSL.Versions.Contains (Messages.Offered_Versions (Hello), SSL.Versions.TLS_1_3) then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_No_Common_Version, SSL.Errors.Peer_Message));
         return;
      end if;

      if not Choose_Suite (Item, Messages.Offered_Suites (Hello), Suite) then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_No_Common_Cipher_Suite, SSL.Errors.Peer_Message));
         return;
      end if;

      Choose_Group (Item, Hello, Group, Have, Found);
      if not Found then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_No_Common_Group, SSL.Errors.Peer_Message));
         return;
      end if;

      --  The echoed legacy session identifier.
      declare
         Sent : constant Byte_Array := Messages.Session_Id (Hello);
      begin
         Item.Echo_Length := Sent'Length;
         if Sent'Length > 0 then
            Item.Echo (1 .. Sent'Length) := Sent;
         end if;
      end;

      if Item.State = Received_Client_Hello then
         if not Item.Resumed then
            SSL.Transcripts.Select_Algorithm
              (Item.Context.Transcript, Suites.Hash_Of (Suite));
         end if;
      elsif Suite /= Item.Context.Result.Suite then
         --  RFC 8446 section 4.1.4: the second ClientHello may not change the
         --  suite the retry committed to, because the transcript transform was
         --  applied under that suite's hash.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Hello_Retry_Invariant_Broken, SSL.Errors.Peer_Message));
         return;
      end if;

      Item.Context.Result.Suite := Suite;
      Item.Context.Result.Version := SSL.Versions.TLS_1_3;
      Item.Context.Result.Name := Messages.Offered_Name (Hello);

      --  A HelloRetryRequest, when the chosen group has no share behind it.
      if not Have then
         if Item.Context.Retried then
            --  A second retry would mean the client answered the first one
            --  without supplying the group it was asked for.
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_Hello_Retry_Invariant_Broken,
                       SSL.Errors.Peer_Message));
            return;
         end if;

         Absorb (Item.Context, Message);
         SSL.Transcripts.Apply_Hello_Retry_Transform (Item.Context.Transcript);
         Item.Context.Retried := True;

         declare
            Region : Byte_Array (1 .. Into'Last - Cursor + 1);
         begin
            Messages.Encode_Hello_Retry_Request
              (Session_Id => Item.Echo (1 .. Item.Echo_Length),
               Suite      => Suite,
               Group      => Group,
               Cookie     => Empty_Bytes,
               Into       => Region,
               Written    => Length,
               Error      => Local);
            if SSL.Errors.Is_Error (Local) then
               Refuse (Item, Result, Error, Local);
               return;
            end if;
            Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
         end;

         Absorb (Item.Context, Into (Cursor .. Cursor + Length - 1));
         Add (Result, Send_Handshake, Cursor, Cursor + Length - 1);
         Add (Result, Send_Compatibility_CCS);
         Item.State := Wait_Second_Client_Hello;
         return;
      end if;

      --  A pre_shared_key offer, considered before the hello is absorbed:
      --  verifying the binder means hashing the message in two pieces, and
      --  Consider_Offer does that absorbing itself when it takes the offer up.
      declare
         Accepted : Boolean;
      begin
         Consider_Offer (Item, Message, Hello, Suite, Accepted, Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;

         if not Accepted then
            --  Absorb the ClientHello whole. After a retry the transform has
            --  already been applied and the first hello is inside it, so this
            --  is the second one.
            Absorb (Item.Context, Message);
         end if;
      end;

      --  ALPN.
      declare
         Need     : constant SSL.ALPN.ALPN_Requirement :=
           Config_Package.ALPN_Requirement (Item.Config.all);
         Policy   : constant SSL.ALPN.Selection_Policy :=
           Config_Package.ALPN_Selection (Item.Config.all);
         Chosen   : SSL.ALPN.Protocol_Name;
      begin
         if Need /= SSL.ALPN.Not_Offered
           and then not SSL.ALPN.Is_Empty (Messages.Offered_Protocols (Hello))
         then
            --  An application selector is the engine's to call: it is
            --  application code, and calling application code from inside a
            --  state machine is what the provider boundary exists to avoid.
            --  Until the engine supplies one, server list order decides, which
            --  is the conservative fallback -- it never selects a protocol the
            --  configuration did not list.
            if SSL.ALPN.Select_Protocol
                 (Policy      => (if Policy = SSL.ALPN.Application_Selector
                                  then SSL.ALPN.Server_Order else Policy),
                  Server_List => Config_Package.Application_Protocols (Item.Config.all),
                  Client_List => Messages.Offered_Protocols (Hello),
                  Selected    => Chosen)
            then
               Item.Context.Result.Protocol := Chosen;
               Item.Context.Result.Has_Protocol := True;
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

      if Messages.Requested_Record_Limit (Hello) > 0 then
         Item.Context.Result.Send_Limit := Messages.Requested_Record_Limit (Hello);
      end if;

      --  The credential, chosen from the name the client asked for and the
      --  schemes it will accept. A resumed handshake needs none: it sends no
      --  Certificate and signs nothing.
      if not Item.Resumed and then not Config_Package.Select_Credential
               (Item    => Item.Config.all,
                Name    => Messages.Offered_Name (Hello),
                Offered => Messages.Offered_Schemes (Hello),
                Version => SSL.Versions.TLS_1_3,
                Index   => Item.Credential_Index)
      then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_No_Credential_Configured, SSL.Errors.Local_Policy));
         return;
      end if;

      --  Key agreement, then the ServerHello that commits to it.
      declare
         Peer_First : Byte_Index;
         Peer_Last  : Byte_Index;
      begin
         if not Messages.Key_Share_For (Hello, Group, Peer_First, Peer_Last) then
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_Key_Share_Not_Offered, SSL.Errors.Peer_Message));
            return;
         end if;

         SSL.Crypto.Generate (Item.Exchange, Group, Source, Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;

         Item.Context.Result.Group := Group;
         Item.Context.Result.Has_Group := True;

         SSL.Crypto.Fill (Source, Random_Value, Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;

         declare
            Region : Byte_Array (1 .. Into'Last - Cursor + 1);
         begin
            Messages.Encode_Server_Hello
              (Random_Value => Random_Value,
               Session_Id   => Item.Echo (1 .. Item.Echo_Length),
               Suite        => Suite,
               Share_Group  => Group,
               Share_Value  => SSL.Crypto.Public_Share (Item.Exchange),
               Has_Identity => Item.Resumed,
               Identity     => 0,
               Into         => Region,
               Written      => Length,
               Error        => Local);
            if SSL.Errors.Is_Error (Local) then
               Refuse (Item, Result, Error, Local);
               return;
            end if;
            Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
         end;

         Absorb (Item.Context, Into (Cursor .. Cursor + Length - 1));
         Add (Result, Send_Handshake, Cursor, Cursor + Length - 1);
         Cursor := Cursor + Length;

         if not Item.Context.Retried then
            --  The compatibility ChangeCipherSpec goes out once, after the
            --  first message this server sends under its own keys.
            Add (Result, Send_Compatibility_CCS);
         end if;

         if not Item.Resumed then
            --  When the offer was taken up the schedule was started and the
            --  early secret derived from the ticket's key before the binder was
            --  checked; doing either again would discard that.
            Schedules.Start (Item.Context.Schedule, Suite);
            Schedules.Derive_Early_Without_PSK (Item.Context.Schedule, Local);
            if SSL.Errors.Is_Error (Local) then
               Refuse (Item, Result, Error, Local);
               return;
            end if;
         end if;

         SSL.Crypto.Agree
           (Item       => Item.Exchange,
            Peer_Share => Message (Peer_First .. Peer_Last),
            Target     => Item.Context.Shared,
            Error      => Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;
         SSL.Crypto.Wipe (Item.Exchange);

         Schedules.Derive_Handshake
           (Item            => Item.Context.Schedule,
            Shared_Secret   => Item.Context.Shared.Value,
            Transcript_Hash => SSL.Transcripts.Hash (Item.Context.Transcript),
            Error           => Local);
         Item.Context.Shared.Wipe;
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;
      end;

      --  Write keys first: everything that follows in this flight is encrypted
      --  under them. Read keys go in at the same point, because the client's
      --  answering flight will arrive under its own handshake key.
      Add (Result, Install_Write_Handshake_Keys);
      Add (Result, Install_Read_Handshake_Keys);

      Write_Server_Flight (Item, Hello, Into, Cursor, Result, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      --  A server may write application data as soon as its own Finished is
      --  out; it does not wait for the client's. The read direction stays on
      --  handshake keys until the client's Finished has been verified.
      Add (Result, Install_Write_Application_Keys);

      Item.State :=
        (if Item.Requested_Client_Certificate
         then Wait_Client_Flight else Wait_Client_Finished);
   end Handle_Client_Hello;

   ---------------------------------------------------------------------------
   --  The client's second flight
   ---------------------------------------------------------------------------

   procedure Handle_Client_Certificate
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_Client_Certificate
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Parsed : Messages.Certificate_Message;
      Local  : SSL.Errors.Error_Information;
      Count  : Natural;
      Total  : Byte_Index := 0;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Messages.Parse_Certificate (Message, Item.Bounds, Parsed, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Count := Messages.Entry_Count (Parsed);

      if Count = 0 then
         --  An empty Certificate is a client declining. Whether that is
         --  acceptable is the policy's answer, and it is the only place the two
         --  client-authentication modes differ.
         if Config_Package.Client_Authentication (Item.Config.all)
            = SSL.Authentication.Required
         then
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_Certificate_Not_Provided, SSL.Errors.Peer_Message));
            return;
         end if;

         Item.Client_Sent_Certificate := False;
         Absorb (Item.Context, Message);
         --  No CertificateVerify follows an empty Certificate: there is no
         --  certificate for one to be about.
         Item.State := Wait_Client_Finished;
         return;
      end if;

      if Count > Validation.Maximum_Chain then
         Refuse (Item, Result, Error,
                 SSL.Errors.Limit_Failure
                   (SSL.Limits.Certificate_Count,
                    Long_Long_Integer (Validation.Maximum_Chain),
                    Long_Long_Integer (Count)));
         return;
      end if;

      for Index in 1 .. Count loop
         declare
            From : Byte_Index;
            To   : Byte_Index;
         begin
            Messages.Entry_Span (Parsed, Index, From, To);
            Total := Total + (To - From + 1);
         end;
      end loop;

      declare
         Chain   : aliased Validation.Chain_Storage (Length => Total);
         Cursor  : Byte_Index := 1;
         Anchors : constant access constant SSL.Trust.Snapshot :=
           Config_Package.Anchors (Item.Config.all);
      begin
         if Anchors = null then
            --  Asking for a client certificate with nothing to judge it against
            --  is a configuration that cannot work; Build refuses it, and this
            --  is the second opinion.
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_Trust_Required_But_Absent, SSL.Errors.Local_Policy));
            return;
         end if;

         for Index in 1 .. Count loop
            declare
               From : Byte_Index;
               To   : Byte_Index;
            begin
               Messages.Entry_Span (Parsed, Index, From, To);
               Chain.Spans (Index) := (First => Cursor, Last => Cursor + (To - From));
               Chain.Octets (Cursor .. Cursor + (To - From)) := Message (From .. To);
               Cursor := Cursor + (To - From) + 1;
            end;
         end loop;

         --  No expected identity: a client certificate is not checked against a
         --  name here, because which name a client should present is an
         --  application question and the answer is not in the protocol.
         Validation.Validate
           (Chain    => Chain,
            Count    => Count,
            Anchors  => Anchors.all,
            Identity => Validation.No_Identity,
            Role     => Validation.Client_Certificate,
            At_Time  => Item.Now,
            Bounds   => Item.Bounds,
            Result   => Item.Client_Peer,
            Error    => Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;
      end;

      Item.Client_Sent_Certificate := True;
      Absorb (Item.Context, Message);
      Item.State := Wait_Client_Certificate_Verify;
   end Handle_Client_Certificate;

   procedure Handle_Client_Certificate_Verify
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_Client_Certificate_Verify
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Parsed : Messages.Certificate_Verify_Message;
      Local  : SSL.Errors.Error_Information;
      First  : Byte_Index;
      Last   : Byte_Index;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Messages.Parse_Certificate_Verify (Message, Item.Bounds, Parsed, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      if not Messages.Scheme_Recognized (Parsed)
        or else not Schemes.Contains
                      (Config_Package.Signature_Schemes (Item.Config.all),
                       Messages.Scheme (Parsed))
        or else not Schemes.Usable_For_Handshake
                      (Messages.Scheme (Parsed), SSL.Versions.TLS_1_3)
      then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (Code       => SSL.Errors.Code_No_Common_Signature_Scheme,
                    Origin     => SSL.Errors.Peer_Message,
                    Parameters =>
                      [SSL.Errors.Text_Parameter
                         ("scheme", Schemes.Image (Messages.Scheme_Value (Parsed)))]));
         return;
      end if;

      Messages.Signature_Span (Parsed, First, Last);

      Verify_Peer_Signature
        (Signing_Role    => Messages.Client_Signing,
         Scheme          => Messages.Scheme (Parsed),
         Public_Key      => Validation.Leaf_Public_Key (Item.Client_Peer),
         Transcript_Hash => SSL.Transcripts.Hash (Item.Context.Transcript),
         Signature       => Message (First .. Last),
         Error           => Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Item.Client_Is_Authenticated := True;
      Absorb (Item.Context, Message);
      Item.State := Wait_Client_Finished;
   end Handle_Client_Certificate_Verify;

   procedure Handle_Client_Finished
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_Client_Finished
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Local       : SSL.Errors.Error_Information;
      First       : Byte_Index;
      Last        : Byte_Index;
      Before : Byte_Array (1 .. Schedules.Digest_Width (Item.Context.Schedule));
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      --  The transcript as it stands before the client's Finished is absorbed,
      --  which is exactly what that Finished is computed over.
      SSL.Transcripts.Hash (Item.Context.Transcript, Before);

      Messages.Parse_Finished (Message, Item.Bounds, First, Last, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Verify_Peer_Finished
        (Item            => Item.Context,
         Which           => Schedules.Client_Side,
         Transcript_Hash => Before,
         Verify_Data     => Message (First .. Last),
         Error           => Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Absorb (Item.Context, Message);
      Item.Context.Peer_Finished_Verified := True;

      --  Only the resumption master secret is left: the application traffic
      --  secrets were derived when this server's own Finished was written.
      Schedules.Derive_Resumption
        (Item                 => Item.Context.Schedule,
         Client_Finished_Hash => SSL.Transcripts.Hash (Item.Context.Transcript),
         Error                => Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Item.Context.Result.Peer_Authenticated := Item.Client_Is_Authenticated;

      Add (Result, Install_Read_Application_Keys);
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
         when Received_Client_Hello | Wait_Second_Client_Hello =>
            if Kind = Messages.Client_Hello then
               Handle_Client_Hello (Item, Message, Source, Into, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Client_Flight =>
            if Kind = Messages.Certificate then
               Handle_Client_Certificate (Item, Message, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Client_Certificate_Verify =>
            if Kind = Messages.Certificate_Verify then
               Handle_Client_Certificate_Verify (Item, Message, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Client_Finished =>
            if Kind = Messages.Finished then
               Handle_Client_Finished (Item, Message, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Connected =>
            --  Post-handshake traffic belongs to the engine.
            Refuse (Item, Result, Error, Unexpected (Item, Kind));

         when Start | Failed =>
            Refuse (Item, Result, Error, Unexpected (Item, Kind));
      end case;
   end Handle_Message;

   ---------------
   -- Wipe --
   ---------------

   procedure Wipe (Item : in out Machine) is
   begin
      TLS13.Wipe (Item.Context);
      SSL.Crypto.Wipe (Item.Exchange);
      Item.Echo := [others => 0];
      Item.Echo_Length := 0;
   end Wipe;

end SSL.TLS13.Server;
