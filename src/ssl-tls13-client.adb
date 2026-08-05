with SSL.ALPN;
with SSL.Credentials;
with SSL.Cipher_Suites;
with SSL.Key_Schedule;
with SSL.Server_Names;
with SSL.Signature_Schemes;
with SSL.Supported_Groups;
with SSL.Transcripts;
with SSL.Trust;
with SSL.Sessions;
with SSL.Trust.Pinning;
with SSL.Trust.Revocation;
with SSL.Versions;

package body SSL.TLS13.Client is

   package Config_Package renames SSL.Configurations;
   package Messages renames SSL.Handshake_Messages;
   package Groups renames SSL.Supported_Groups;
   package Schedules renames SSL.Key_Schedule;
   package Schemes renames SSL.Signature_Schemes;
   package Validation renames SSL.Certificate_Validation;

   use type SSL.Cipher_Suites.Cipher_Suite;
   use type SSL.Handshake_Messages.Message_Type;
   use type SSL.Supported_Groups.Named_Group;
   use type SSL.Versions.Version_Value;
   use type SSL.ALPN.ALPN_Requirement;
   use type SSL.Trust.Pinning.Pinning_Mode;

   ---------------
   -- Image --
   ---------------

   function Image (Item : Client_State) return String is
     (case Item is
         when Start                       => "start",
         when Wait_Server_Hello           => "wait for ServerHello",
         when Wait_Encrypted_Extensions   => "wait for EncryptedExtensions",
         when Wait_Certificate_Or_Request => "wait for Certificate or CertificateRequest",
         when Wait_Certificate            => "wait for Certificate",
         when Wait_Certificate_Verify     => "wait for CertificateVerify",
         when Wait_Finished               => "wait for Finished",
         when Connected                   => "connected",
         when Failed                      => "failed");

   --------------------
   -- Context_Of --
   --------------------

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

   --  Move to Failed and hand back the failure. Every refusal below goes
   --  through here, so that a state machine cannot be left in a state that says
   --  it is still expecting something after it has refused.
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

   --  Generate the ephemeral keypairs and fill in the key_share list.
   --
   --  One share per configured key-share group, in configuration order. Offering
   --  more than one costs a keypair per group and saves a round trip whenever
   --  the server prefers the second; offering only the first would make a retry
   --  the common case rather than the exception.
   procedure Generate_Shares
     (Item   : in out Machine;
      Only   : Groups.Named_Group;
      Single : Boolean;
      Source : in out SSL.Crypto.Random_Source;
      Error  : out SSL.Errors.Error_Information);

   procedure Generate_Shares
     (Item   : in out Machine;
      Only   : Groups.Named_Group;
      Single : Boolean;
      Source : in out SSL.Crypto.Random_Source;
      Error  : out SSL.Errors.Error_Information)
   is
      Wanted : constant Groups.Group_List :=
        Config_Package.Key_Share_Groups (Item.Config.all);
      Count  : Natural := 0;
   begin
      Error := SSL.Errors.No_Error;

      for Index in 1 .. Item.Offered_Count loop
         SSL.Crypto.Wipe (Item.Pairs (Index));
      end loop;
      Item.Offered_Count := 0;

      for Index in 1 .. Groups.Length (Wanted) loop
         declare
            Group : constant Groups.Named_Group := Groups.Element (Wanted, Index);
         begin
            if not Single or else Group = Only then
               exit when Count = Messages.Maximum_Offered_Shares;
               Count := Count + 1;
               SSL.Crypto.Generate (Item.Pairs (Count), Group, Source, Error);
               if SSL.Errors.Is_Error (Error) then
                  return;
               end if;
               Item.Offered (Count).Group := Group;
               declare
                  Share : constant Byte_Array := SSL.Crypto.Public_Share (Item.Pairs (Count));
               begin
                  Item.Offered (Count).Length := Share'Length;
                  Item.Offered (Count).Value (1 .. Share'Length) := Share;
               end;
            end if;
         end;
      end loop;

      if Single and then Count = 0 then
         --  A retry asked for a group this client does not offer a share for.
         --  Generating one anyway would be offering a group the policy left
         --  out, which is the policy being overridden by the peer.
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Selected_Group_Not_Offered,
            Origin     => SSL.Errors.Peer_Message,
            Parameters => [SSL.Errors.Text_Parameter ("group", Groups.Image (Only))]);
         return;
      end if;

      if Count = 0 then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_No_Groups_Enabled, SSL.Errors.Local_Policy);
         return;
      end if;

      Item.Offered_Count := Count;
   end Generate_Shares;

   --  Write a ClientHello into the output buffer and absorb it.
   procedure Write_Client_Hello
     (Item   : in out Machine;
      Into   : in out Byte_Array;
      First  : out Byte_Index;
      Last   : out Byte_Index;
      Error  : out SSL.Errors.Error_Information);

   procedure Write_Client_Hello
     (Item   : in out Machine;
      Into   : in out Byte_Array;
      First  : out Byte_Index;
      Last   : out Byte_Index;
      Error  : out SSL.Errors.Error_Information)
   is
      Written    : Byte_Index;
      Binders_At : Byte_Index;

      Offering : constant Boolean := SSL.Sessions.Is_Present (Item.Offer);
      Width    : constant Byte_Index :=
        (if Offering
         then SSL.Cipher_Suites.Digest_Length
                (SSL.Cipher_Suites.Hash_Of (SSL.Sessions.Cipher_Suite (Item.Offer)))
         else 0);
   begin
      First := Into'First;
      Last := Into'First - 1;

      Messages.Encode_Client_Hello
        (Config         => Item.Config.all,
         Random_Value   => Item.Random_Value,
         Session_Id     => Item.Session,
         Shares         => Item.Offered,
         Share_Count    => Item.Offered_Count,
         Cookie         => Item.Cookie (1 .. Item.Cookie_Length),
         Identity       => (if Offering then SSL.Sessions.Ticket (Item.Offer)
                            else Empty_Bytes),
         Obfuscated_Age => (if Offering then SSL.Sessions.Age_Add (Item.Offer) else 0),
         Binder_Length  => Width,
         Legacy_Ticket  => Item.Legacy_Ticket (1 .. Item.Legacy_Ticket_Length),
         Offer_Legacy_Ticket => Item.Offer_Legacy,
         Into           => Into,
         Written        => Written,
         Binders_At     => Binders_At,
         Error          => Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      Last := Into'First + Written - 1;

      if not Offering then
         Absorb (Item.Context, Into (First .. Last));
         return;
      end if;

      --  The binder is HMAC over the transcript of this ClientHello truncated
      --  immediately before the binders list. So the truncated form is absorbed
      --  first, the binder computed against that, written into the message, and
      --  only then is the remainder absorbed -- which leaves the transcript
      --  holding the whole message, exactly as a server will hash it.
      declare
         Local  : SSL.Errors.Error_Information;
         Binder : Byte_Array (1 .. Width) := [others => 0];
         Secret : Byte_Array (1 .. 64) := [others => 0];
         Length : Byte_Index;
      begin
         SSL.Transcripts.Select_Algorithm
           (Item.Context.Transcript,
            SSL.Cipher_Suites.Hash_Of (SSL.Sessions.Cipher_Suite (Item.Offer)));

         Schedules.Start (Item.Context.Schedule, SSL.Sessions.Cipher_Suite (Item.Offer));
         SSL.Sessions.Get_Secret (Item.Offer, Secret, Length);
         Schedules.Derive_Early_From_PSK
           (Item.Context.Schedule, Secret (1 .. Length), Local);
         SSL.Crypto.Scrub (Secret);
         if SSL.Errors.Is_Error (Local) then
            Error := Local;
            return;
         end if;

         Absorb (Item.Context, Into (First .. Binders_At - 1));

         Schedules.Compute_Binder
           (Item            => Item.Context.Schedule,
            Transcript_Hash => SSL.Transcripts.Hash (Item.Context.Transcript),
            Is_External     => False,
            Into            => Binder,
            Error           => Local);
         if SSL.Errors.Is_Error (Local) then
            SSL.Crypto.Scrub (Binder);
            Error := Local;
            return;
         end if;

         --  Two octets of list length, one of binder length, then the binder.
         Into (Binders_At + 3 .. Binders_At + 2 + Width) := Binder;
         SSL.Crypto.Scrub (Binder);

         Absorb (Item.Context, Into (Binders_At .. Last));
         Item.Offered_Session := True;
      end;
   end Write_Client_Hello;

   ---------------------------------------------------------------------------
   --  Begin_Handshake
   ---------------------------------------------------------------------------

   procedure Begin_Handshake
     (Item   : in out Machine;
      Config : not null access constant SSL.Configurations.Client_Configuration;
      Now    : SSL.Clocks.Wall_Time;
      Source : in out SSL.Crypto.Random_Source;
      Into   : in out Byte_Array;
      Result : out Plan;
      Error  : out SSL.Errors.Error_Information)
   is
      First : Byte_Index;
      Last  : Byte_Index;
      Local : SSL.Errors.Error_Information;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      if not Config_Package.Is_Valid (Config.all) then
         --  A configuration that never went through Build. Refusing here rather
         --  than proceeding is the whole point of the validity flag: an unbuilt
         --  configuration has not had its refusals applied.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make (SSL.Errors.Code_Configuration_Not_Validated,
                                  SSL.Errors.Local_Policy));
         return;
      end if;

      Item.Config := Config;
      Item.Now := Now;
      Item.Bounds := Config_Package.Bounds (Config.all);

      SSL.Transcripts.Start (Item.Context.Transcript);
      Item.Context.Result.Name := Config_Package.Server_Name_Indication (Config.all);

      SSL.Crypto.Fill (Source, Item.Random_Value, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      --  A non-empty legacy session identifier is the middlebox compatibility
      --  mode of RFC 8446 appendix D.4. It is random rather than fixed because
      --  a constant would be a fingerprint, and it means nothing: the server
      --  echoes it and neither end derives anything from it.
      SSL.Crypto.Fill (Source, Item.Session, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Generate_Shares (Item, Groups.X25519, Single => False, Source => Source, Error => Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Write_Client_Hello (Item, Into, First, Last, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Add (Result, Send_Handshake, First, Last);
      Item.State := Wait_Server_Hello;
   end Begin_Handshake;

   ---------------------------------------------------------------------------
   --  ServerHello and HelloRetryRequest
   ---------------------------------------------------------------------------

   procedure Handle_Server_Hello
     (Item    : in out Machine;
      Message : Byte_Array;
      Source  : in out SSL.Crypto.Random_Source;
      Into    : in out Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_Server_Hello
     (Item    : in out Machine;
      Message : Byte_Array;
      Source  : in out SSL.Crypto.Random_Source;
      Into    : in out Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Parsed : Messages.Server_Hello_Message;
      Local  : SSL.Errors.Error_Information;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Messages.Parse_Server_Hello (Message, Item.Bounds, Parsed, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      --  The suite must be one this client offered. A server that selects
      --  anything else has either not read the ClientHello or is not the party
      --  the ClientHello was addressed to.
      if not SSL.Cipher_Suites.Contains
               (Config_Package.Cipher_Suites (Item.Config.all),
                Messages.Selected_Suite (Parsed))
      then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (Code       => SSL.Errors.Code_Selected_Suite_Not_Offered,
                    Origin     => SSL.Errors.Peer_Message,
                    Parameters =>
                      [SSL.Errors.Text_Parameter
                         ("suite",
                          SSL.Cipher_Suites.Image (Messages.Selected_Suite (Parsed)))]));
         return;
      end if;

      if Messages.Selected_Version (Parsed) /= SSL.Versions.TLS_1_3_Value then
         --  This machine speaks TLS 1.3 and nothing else. A server selecting
         --  1.2 is handled by the separate TLS 1.2 machine, and a server
         --  selecting anything else is refused outright.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Selected_Version_Not_Offered, SSL.Errors.Peer_Message));
         return;
      end if;

      --  RFC 8446 appendix D.4: the server echoes the legacy session
      --  identifier exactly. A server that changed it is not the server this
      --  ClientHello reached, or the ClientHello was rewritten in flight.
      if not SSL.Crypto.Equal (Messages.Session_Id (Parsed), Item.Session) then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Legacy_Session_Id_Mismatch, SSL.Errors.Peer_Message));
         return;
      end if;

      if Messages.Is_Hello_Retry_Request (Parsed) then
         declare
            Group : Groups.Named_Group;
            First : Byte_Index;
            Last  : Byte_Index;
         begin
            if Item.Context.Retried then
               --  RFC 8446 section 4.1.4: at most one. Without this a server
               --  could drive an unbounded retry loop, and each round would
               --  cost this client a fresh keypair.
               Refuse (Item, Result, Error,
                       SSL.Errors.Make
                         (SSL.Errors.Code_Second_Hello_Retry_Request,
                          SSL.Errors.Peer_Message));
               return;
            end if;

            if not Messages.Retry_Group (Parsed, Group) then
               --  A retry that asks for nothing is a retry with no purpose;
               --  answering it would send the same ClientHello again.
               Refuse (Item, Result, Error,
                       SSL.Errors.Make
                         (SSL.Errors.Code_Hello_Retry_Invariant_Broken,
                          SSL.Errors.Peer_Message));
               return;
            end if;

            if not Groups.Contains (Config_Package.Groups (Item.Config.all), Group) then
               Refuse (Item, Result, Error,
                       SSL.Errors.Make
                         (Code       => SSL.Errors.Code_Selected_Group_Not_Offered,
                          Origin     => SSL.Errors.Peer_Message,
                          Parameters =>
                            [SSL.Errors.Text_Parameter ("group", Groups.Image (Group))]));
               return;
            end if;

            for Index in 1 .. Item.Offered_Count loop
               if Item.Offered (Index).Group = Group then
                  --  RFC 8446 section 4.1.4: asking for a group whose share was
                  --  already supplied is forbidden. It buys the server nothing
                  --  and it is how a retry loop would be built.
                  Refuse (Item, Result, Error,
                          SSL.Errors.Make
                            (Code       => SSL.Errors.Code_Hello_Retry_Group_Already_Offered,
                             Origin     => SSL.Errors.Peer_Message,
                             Parameters =>
                               [SSL.Errors.Text_Parameter ("group", Groups.Image (Group))]));
                  return;
               end if;
            end loop;

            --  The transcript becomes the synthetic message_hash form before
            --  the retry itself is absorbed, and the hash the transform uses is
            --  the one the selected suite fixes -- which is why the algorithm is
            --  selected here rather than after ServerHello.
            SSL.Transcripts.Select_Algorithm
              (Item.Context.Transcript,
               SSL.Cipher_Suites.Hash_Of (Messages.Selected_Suite (Parsed)));
            SSL.Transcripts.Apply_Hello_Retry_Transform (Item.Context.Transcript);
            Absorb (Item.Context, Message);
            Item.Context.Retried := True;
            Item.Context.Result.Suite := Messages.Selected_Suite (Parsed);

            --  Echo the cookie exactly, if there is one.
            declare
               From : Byte_Index;
               To   : Byte_Index;
            begin
               if Messages.Cookie_Span (Parsed, From, To) then
                  if To - From + 1 > Maximum_Cookie then
                     Refuse (Item, Result, Error,
                             SSL.Errors.Limit_Failure
                               (SSL.Limits.Cookie_Length,
                                Long_Long_Integer (Maximum_Cookie),
                                Long_Long_Integer (To - From + 1)));
                     return;
                  end if;
                  Item.Cookie_Length := To - From + 1;
                  Item.Cookie (1 .. Item.Cookie_Length) := Message (From .. To);
               else
                  Item.Cookie_Length := 0;
               end if;
            end;

            Generate_Shares (Item, Group, Single => True, Source => Source, Error => Local);
            if SSL.Errors.Is_Error (Local) then
               Refuse (Item, Result, Error, Local);
               return;
            end if;

            Write_Client_Hello (Item, Into, First, Last, Local);
            if SSL.Errors.Is_Error (Local) then
               Refuse (Item, Result, Error, Local);
               return;
            end if;

            --  A compatibility ChangeCipherSpec goes out with the second
            --  ClientHello, which is where RFC 8446 appendix D.4 puts it.
            Add (Result, Send_Compatibility_CCS);
            Add (Result, Send_Handshake, First, Last);
            return;
         end;
      end if;

      --  Did the server take the offer?
      declare
         Index : Natural;
      begin
         if Messages.Selected_Identity (Parsed, Index) then
            if not Item.Offered_Session or else Index /= 0 then
               --  An answer to an offer this client did not make, or a
               --  selection outside the one identity it offered. Either way the
               --  server is claiming a session that does not exist here.
               Refuse (Item, Result, Error,
                       SSL.Errors.Make
                         (SSL.Errors.Code_Selected_Identity_Out_Of_Range,
                          SSL.Errors.Peer_Message));
               return;
            end if;

            if Messages.Selected_Suite (Parsed)
               /= SSL.Sessions.Cipher_Suite (Item.Offer)
            then
               --  The pre-shared key is derived under the session's own hash,
               --  so a server resuming under a different suite would be
               --  resuming under a key neither end can derive.
               Refuse (Item, Result, Error,
                       SSL.Errors.Make
                         (SSL.Errors.Code_Session_Security_Context_Mismatch,
                          SSL.Errors.Peer_Message));
               return;
            end if;

            Item.Resumed := True;
            Item.Context.Result.Resumed := True;

            --  A resumed connection inherits the authentication of the one that
            --  issued the ticket. It proves possession of an earlier key rather
            --  than of a certificate, and the metadata says so.
            Item.Context.Result.Peer_Authenticated :=
              SSL.Sessions.Peer_Authenticated (Item.Offer);
            Item.Peer_Certificate_Accepted := True;
         end if;
      end;

      --  An ordinary ServerHello. From here the connection is committed to a
      --  suite, so the transcript's hash is fixed and the key schedule starts.
      if Item.Context.Retried
        and then Messages.Selected_Suite (Parsed) /= Item.Context.Result.Suite
      then
         --  RFC 8446 section 4.1.4: the suite must not change between the retry
         --  and the ServerHello. If it did, the transform above was applied
         --  under the wrong hash.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Hello_Retry_Invariant_Broken, SSL.Errors.Peer_Message));
         return;
      end if;

      if SSL.Versions.Has_Downgrade_Sentinel (Messages.Random (Parsed)) then
         --  RFC 8446 section 4.1.3. This client offered TLS 1.3 and the server
         --  selected it, so a sentinel here means something rewrote the offer
         --  and the server answered the rewritten one.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Downgrade_Sentinel_Detected, SSL.Errors.Peer_Message));
         return;
      end if;

      Item.Context.Result.Suite := Messages.Selected_Suite (Parsed);
      Item.Context.Result.Version := SSL.Versions.TLS_1_3;

      if not Item.Context.Retried and then not Item.Offered_Session then
         SSL.Transcripts.Select_Algorithm
           (Item.Context.Transcript,
            SSL.Cipher_Suites.Hash_Of (Item.Context.Result.Suite));
      end if;
      Absorb (Item.Context, Message);

      declare
         Group : Groups.Named_Group;
         From  : Byte_Index;
         To    : Byte_Index;
         Which : Natural := 0;
      begin
         if not Messages.Server_Key_Share (Parsed, Group, From, To) then
            --  No PSK-only handshakes here, so a ServerHello with no key share
            --  offers no forward secrecy and there is nothing to agree on.
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_Key_Share_Not_Offered, SSL.Errors.Peer_Message));
            return;
         end if;

         for Index in 1 .. Item.Offered_Count loop
            if Item.Offered (Index).Group = Group then
               Which := Index;
            end if;
         end loop;

         if Which = 0 then
            --  A share for a group this client did not send one for. There is
            --  no private key on this side to agree with.
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (Code       => SSL.Errors.Code_Selected_Group_Not_Offered,
                       Origin     => SSL.Errors.Peer_Message,
                       Parameters =>
                         [SSL.Errors.Text_Parameter ("group", Groups.Image (Group))]));
            return;
         end if;

         Item.Context.Result.Group := Group;
         Item.Context.Result.Has_Group := True;

         if not Item.Offered_Session then
            --  When a session was offered the schedule was started and the
            --  early secret derived from its pre-shared key before the binder
            --  was computed; doing either again would discard that.
            Schedules.Start (Item.Context.Schedule, Item.Context.Result.Suite);
            Schedules.Derive_Early_Without_PSK (Item.Context.Schedule, Local);
            if SSL.Errors.Is_Error (Local) then
               Refuse (Item, Result, Error, Local);
               return;
            end if;
         elsif not Item.Resumed then
            --  Offered and declined. The early secret derived from the ticket
            --  is not the one this handshake uses, so the schedule starts again
            --  from nothing.
            Schedules.Wipe (Item.Context.Schedule);
            Schedules.Start (Item.Context.Schedule, Item.Context.Result.Suite);
            Schedules.Derive_Early_Without_PSK (Item.Context.Schedule, Local);
            if SSL.Errors.Is_Error (Local) then
               Refuse (Item, Result, Error, Local);
               return;
            end if;
         end if;

         SSL.Crypto.Agree
           (Item        => Item.Pairs (Which),
            Peer_Share  => Message (From .. To),
            Target      => Item.Context.Shared,
            Error       => Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;

         --  The private scalars have done their work. All of them go, including
         --  the ones for groups the server did not pick: holding a key that
         --  will never be used again is holding a key for an attacker to find.
         for Index in 1 .. Item.Offered_Count loop
            SSL.Crypto.Wipe (Item.Pairs (Index));
         end loop;

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

      --  Both directions move to handshake keys at the same moment on a client:
      --  everything after ServerHello is encrypted, in both directions.
      Add (Result, Install_Read_Handshake_Keys);
      Add (Result, Install_Write_Handshake_Keys);
      Item.Handshake_Keys_Installed := True;
      Item.State := Wait_Encrypted_Extensions;
   end Handle_Server_Hello;

   ---------------------------------------------------------------------------
   --  EncryptedExtensions
   ---------------------------------------------------------------------------

   procedure Handle_Encrypted_Extensions
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_Encrypted_Extensions
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Parsed   : Messages.Encrypted_Extensions_Message;
      Local    : SSL.Errors.Error_Information;
      Protocol : SSL.ALPN.Protocol_Name;
      Need     : constant SSL.ALPN.ALPN_Requirement :=
        Config_Package.ALPN_Requirement (Item.Config.all);
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Messages.Parse_Encrypted_Extensions (Message, Item.Bounds, Parsed, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      if Messages.Selected_Protocol (Parsed, Protocol) then
         if Need = SSL.ALPN.Not_Offered then
            --  An answer to a question this client did not ask. RFC 8446
            --  section 4.2 forbids it and it is exactly the shape of a server
            --  trying to steer a connection into a protocol nobody chose.
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (Code       => SSL.Errors.Code_Unsolicited_Extension,
                       Origin     => SSL.Errors.Peer_Message,
                       Parameters =>
                         [SSL.Errors.Text_Parameter ("extension", "application_layer_protocol_negotiation")]));
            return;
         end if;

         if not SSL.ALPN.Contains
                  (Config_Package.Application_Protocols (Item.Config.all), Protocol)
         then
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (Code       => SSL.Errors.Code_No_Application_Protocol_Overlap,
                       Origin     => SSL.Errors.Peer_Message,
                       Parameters =>
                         [SSL.Errors.Text_Parameter ("selected", SSL.ALPN.Image (Protocol))]));
            return;
         end if;

         Item.Context.Result.Protocol := Protocol;
         Item.Context.Result.Has_Protocol := True;

      elsif Need = SSL.ALPN.Required then
         --  The policy said the connection is only meaningful under one of
         --  these protocols. A server that selects none has not agreed to any
         --  of them, and carrying on would be carrying on under an unknown
         --  protocol.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_No_Application_Protocol_Overlap,
                    SSL.Errors.Peer_Message));
         return;
      end if;

      if Messages.Requested_Record_Limit (Parsed) > 0 then
         Item.Context.Result.Send_Limit := Messages.Requested_Record_Limit (Parsed);
      end if;

      Absorb (Item.Context, Message);

      --  A resumed handshake carries no Certificate and no CertificateVerify:
      --  the server has already proved, by producing keys that work, that it
      --  holds the pre-shared key from the earlier handshake.
      Item.State := (if Item.Resumed then Wait_Finished else Wait_Certificate_Or_Request);
   end Handle_Encrypted_Extensions;

   ---------------------------------------------------------------------------
   --  CertificateRequest
   ---------------------------------------------------------------------------

   procedure Handle_Certificate_Request
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_Certificate_Request
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
   is
      Parsed : Messages.Certificate_Request_Message;
      Local  : SSL.Errors.Error_Information;
      First  : Byte_Index;
      Last   : Byte_Index;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Messages.Parse_Certificate_Request (Message, Item.Bounds, Parsed, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      if Messages.Request_Context_Span (Parsed, First, Last) then
         if Last - First + 1 > Maximum_Context then
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message));
            return;
         end if;
         Item.Context_Length := Last - First + 1;
         if Item.Context_Length > 0 then
            Item.Request_Context (1 .. Item.Context_Length) := Message (First .. Last);
         end if;
      end if;

      Item.Asked_For_Certificate := True;
      Item.Requested_Schemes := Messages.Offered_Schemes (Parsed);
      Absorb (Item.Context, Message);
      Item.State := Wait_Certificate;
   end Handle_Certificate_Request;

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
         --  A server that sends no certificate has not authenticated, and this
         --  library does not do anonymous server authentication.
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (SSL.Errors.Code_Certificate_List_Empty, SSL.Errors.Peer_Message));
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

      --  A server's certificate_request_context is empty (RFC 8446 section
      --  4.4.2). A non-empty one means this message answers a request that was
      --  never made.
      declare
         From : Byte_Index;
         To   : Byte_Index;
      begin
         if Messages.Request_Context_Span (Parsed, From, To) and then To >= From then
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message));
            return;
         end if;
      end;

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
         Chain : aliased Validation.Chain_Storage (Length => Total);
         Cursor : Byte_Index := 1;
         Anchors : constant access constant SSL.Trust.Snapshot :=
           Config_Package.Anchors (Item.Config.all);
      begin
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

         if Anchors = null then
            Refuse (Item, Result, Error,
                    SSL.Errors.Make
                      (SSL.Errors.Code_Trust_Required_But_Absent,
                       SSL.Errors.Local_Policy));
            return;
         end if;

         --  The fixed pipeline: path, purpose, key usage, identity. Revocation
         --  and pinning follow it, in that order, because both are judgements
         --  about a chain that has already been accepted.
         Validation.Validate
           (Chain    => Chain,
            Count    => Count,
            Anchors  => Anchors.all,
            Identity =>
              (if SSL.Server_Names.Is_Present (Config_Package.Expected_Name (Item.Config.all))
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

         --  Revocation, after the path and before pinning. That order is the
         --  pipeline's: revocation is a judgement about a chain that has
         --  already been accepted, and running it first would mean judging on
         --  an untrusted issuer's assertion.
         declare
            Policy : constant Config_Package.Revocation_Policy :=
              Config_Package.Revocation (Item.Config.all);
            Answer : SSL.Trust.Revocation.Status_Answer :=
              SSL.Trust.Revocation.Status_Unknown;
            Available : Boolean := False;
            From      : Byte_Index;
            To        : Byte_Index;
         begin
            if Messages.Entry_Status_Span (Parsed, 1, From, To) then
               --  Only what the peer stapled. This library fetches nothing: a
               --  handshake that reached out to a responder would leak who was
               --  connecting to whom, and would block on a service the
               --  connection has no relationship with.
               Available := True;
               Validation.Check_Stapled_Status
                 (Chain    => Chain,
                  Count    => Count,
                  Response => Message (From .. To),
                  At_Time  => Item.Now,
                  Bounds   => Item.Bounds,
                  Answer   => Answer);
            end if;

            SSL.Trust.Revocation.Evaluate
              (Policy    => Policy,
               Answer    => Answer,
               Source    => SSL.Trust.Revocation.Stapled_By_Peer,
               Available => Available,
               At_Time   => Item.Now,
               Bounds    => Item.Bounds,
               Error     => Local);
            if SSL.Errors.Is_Error (Local) then
               Refuse (Item, Result, Error, Local);
               return;
            end if;
         end;

         if Config_Package.Pinning_Mode_Of (Item.Config.all) /= SSL.Trust.Pinning.No_Pinning then
            SSL.Trust.Pinning.Evaluate
              (Mode       => Config_Package.Pinning_Mode_Of (Item.Config.all),
               Pins       => Config_Package.Pins (Item.Config.all),
               Leaf       => Validation.Leaf_Fingerprint (Item.Peer),
               Public_Key => Validation.Public_Key_Fingerprint (Item.Peer),
               Name       => Config_Package.Expected_Name (Item.Config.all),
               Protocol   => Item.Context.Result.Protocol,
               At_Time    => Item.Now,
               Error      => Local);
            if SSL.Errors.Is_Error (Local) then
               Refuse (Item, Result, Error, Local);
               return;
            end if;
         end if;
      end;

      Item.Peer_Certificate_Accepted := True;
      Item.Context.Result.Peer_Authenticated := True;
      Absorb (Item.Context, Message);
      Item.State := Wait_Certificate_Verify;
   end Handle_Certificate;

   ---------------------------------------------------------------------------
   --  CertificateVerify
   ---------------------------------------------------------------------------

   procedure Handle_Certificate_Verify
     (Item    : in out Machine;
      Message : Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information);

   procedure Handle_Certificate_Verify
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

      if not Messages.Scheme_Recognized (Parsed) then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (Code       => SSL.Errors.Code_No_Common_Signature_Scheme,
                    Origin     => SSL.Errors.Peer_Message,
                    Parameters =>
                      [SSL.Errors.Text_Parameter
                         ("scheme", Schemes.Image (Messages.Scheme_Value (Parsed)))]));
         return;
      end if;

      --  The scheme must be one this client offered, and it must be usable for
      --  a handshake signature. The second is not implied by the first: PKCS#1
      --  v1.5 may sign a certificate and may not sign a CertificateVerify
      --  (RFC 8446 section 4.2.3).
      if not Schemes.Contains
               (Config_Package.Signature_Schemes (Item.Config.all), Messages.Scheme (Parsed))
        or else not Schemes.Usable_For_Handshake
                      (Messages.Scheme (Parsed), SSL.Versions.TLS_1_3)
      then
         Refuse (Item, Result, Error,
                 SSL.Errors.Make
                   (Code       => SSL.Errors.Code_No_Common_Signature_Scheme,
                    Origin     => SSL.Errors.Peer_Message,
                    Parameters =>
                      [SSL.Errors.Text_Parameter
                         ("scheme", Schemes.Image (Messages.Scheme (Parsed)))]));
         return;
      end if;

      Messages.Signature_Span (Parsed, First, Last);

      --  The transcript hash is taken before this message is absorbed, because
      --  the signature covers everything up to but not including itself.
      Verify_Peer_Signature
        (Signing_Role    => Messages.Server_Signing,
         Scheme          => Messages.Scheme (Parsed),
         Public_Key      => Validation.Leaf_Public_Key (Item.Peer),
         Transcript_Hash => SSL.Transcripts.Hash (Item.Context.Transcript),
         Signature       => Message (First .. Last),
         Error           => Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Item.Context.Result.Peer_Scheme := Messages.Scheme (Parsed);
      Absorb (Item.Context, Message);
      Item.State := Wait_Finished;
   end Handle_Certificate_Verify;

   ---------------------------------------------------------------------------
   --  Finished, and this client's own second flight
   ---------------------------------------------------------------------------

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
      Local  : SSL.Errors.Error_Information;
      First  : Byte_Index;
      Last   : Byte_Index;
      Cursor : Byte_Index := Into'First;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Messages.Parse_Finished (Message, Item.Bounds, First, Last, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      Verify_Peer_Finished
        (Item            => Item.Context,
         Which           => Schedules.Server_Side,
         Transcript_Hash => SSL.Transcripts.Hash (Item.Context.Transcript),
         Verify_Data     => Message (First .. Last),
         Error           => Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      --  Absorbed only now. RFC 8446 makes the server's Finished part of the
      --  transcript the application traffic secrets are bound to, and absorbing
      --  it before it verified would mean deriving keys from a transcript this
      --  endpoint had not yet accepted.
      Absorb (Item.Context, Message);
      Item.Context.Peer_Finished_Verified := True;

      declare
         Server_Hash : constant Byte_Array := SSL.Transcripts.Hash (Item.Context.Transcript);
      begin
         --  A certificate this client was asked for, sent before its Finished
         --  so that the Finished covers it.
         if Item.Asked_For_Certificate then
            declare
               Chosen : Schemes.Signature_Scheme := Schemes.Ed25519;
               Usable : Boolean := False;
            begin
               --  A credential is only sent when there is one *and* a scheme
               --  both ends accept for it. Sending a chain this endpoint then
               --  could not sign for would be worse than declining: the server
               --  would wait for a CertificateVerify that never came, and the
               --  handshake would fail with the shape of a protocol error
               --  rather than the shape of a client that has no certificate.
               if Config_Package.Has_Client_Credential (Item.Config.all) then
                  declare
                     Mine : constant Schemes.Scheme_List :=
                       SSL.Credentials.Supported_Schemes
                         (Config_Package.Client_Credential (Item.Config.all).all);
                  begin
                     for Index in 1 .. Schemes.Length (Mine) loop
                        if Schemes.Contains
                             (Item.Requested_Schemes, Schemes.Element (Mine, Index))
                          and then Schemes.Usable_For_Handshake
                                     (Schemes.Element (Mine, Index), SSL.Versions.TLS_1_3)
                        then
                           Chosen := Schemes.Element (Mine, Index);
                           Usable := True;
                           exit;
                        end if;
                     end loop;
                  end;
               end if;

               if Usable then
                  declare
                     Credential : constant access constant SSL.Credentials.Credential :=
                       Config_Package.Client_Credential (Item.Config.all);
                     Count : constant Positive :=
                       SSL.Credentials.Chain_Length (Credential.all);
                     Total : Byte_Index := 0;
                  begin
                     for Index in 1 .. Count loop
                        Total := Total
                          + SSL.Credentials.Certificate_At (Credential.all, Index)'Length;
                     end loop;

                     declare
                        Chain  : Byte_Array (1 .. Total);
                        Spans  : Messages.Certificate_Span_List := [others => <>];
                        At_Now : Byte_Index := 1;
                        Region : Byte_Array (1 .. Into'Last - Cursor + 1);
                        Length : Byte_Index;
                     begin
                        for Index in 1 .. Count loop
                           declare
                              One : constant Byte_Array :=
                                SSL.Credentials.Certificate_At (Credential.all, Index);
                           begin
                              Chain (At_Now .. At_Now + One'Length - 1) := One;
                              Spans (Index) :=
                                (First => At_Now, Last => At_Now + One'Length - 1);
                              At_Now := At_Now + One'Length;
                           end;
                        end loop;

                        --  The request's context, echoed exactly. RFC 8446
                        --  section 4.4.2 requires it, and it is what ties this
                        --  Certificate to the request that asked for it.
                        Messages.Encode_Certificate
                          (Chain   => Chain,
                           Spans   => Spans,
                           Count   => Count,
                           Context => Item.Request_Context (1 .. Item.Context_Length),
                           Staple  => Empty_Bytes,
                           Into    => Region,
                           Written => Length,
                           Error   => Local);
                        if SSL.Errors.Is_Error (Local) then
                           Refuse (Item, Result, Error, Local);
                           return;
                        end if;

                        Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
                        Absorb (Item.Context, Into (Cursor .. Cursor + Length - 1));
                        Add (Result, Send_Handshake, Cursor, Cursor + Length - 1);
                        Cursor := Cursor + Length;
                     end;

                     --  CertificateVerify. The transcript hash is taken after
                     --  the Certificate has been absorbed and before this
                     --  message is, which is exactly what the signature is
                     --  defined to cover -- and the context string is the
                     --  client's, not the server's, which is what stops a
                     --  signature made by one end being replayed as the
                     --  other's.
                     declare
                        Content : constant Byte_Array :=
                          Messages.Certificate_Verify_Content
                            (Messages.Client_Signing,
                             SSL.Transcripts.Hash (Item.Context.Transcript));
                        Buffer  : Byte_Array
                          (1 .. SSL.Credentials.Maximum_Signature_Length);
                        Written : Byte_Index;
                        Region  : Byte_Array (1 .. Into'Last - Cursor + 1);
                        Length  : Byte_Index;
                     begin
                        SSL.Credentials.Sign
                          (Item        => Credential.all,
                           Scheme      => Chosen,
                           Signed_Data => Content,
                           Signature   => Buffer,
                           Length      => Written,
                           Error       => Local);
                        if SSL.Errors.Is_Error (Local) then
                           Refuse (Item, Result, Error, Local);
                           return;
                        end if;

                        Messages.Encode_Certificate_Verify
                          (Scheme    => Chosen,
                           Signature => Buffer (1 .. Written),
                           Into      => Region,
                           Written   => Length,
                           Error     => Local);
                        if SSL.Errors.Is_Error (Local) then
                           Refuse (Item, Result, Error, Local);
                           return;
                        end if;

                        Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
                        Absorb (Item.Context, Into (Cursor .. Cursor + Length - 1));
                        Add (Result, Send_Handshake, Cursor, Cursor + Length - 1);
                        Cursor := Cursor + Length;
                     end;

                     Item.Sent_A_Certificate := True;
                  end;

               else
                  --  No credential, or none this server would accept a
                  --  signature from. An empty Certificate is the conforming
                  --  answer: it declines and lets the server decide whether
                  --  that ends the connection.
                  declare
                     Empty  : constant Messages.Certificate_Span_List := [others => <>];
                     Region : Byte_Array (1 .. Into'Last - Cursor + 1);
                     Length : Byte_Index;
                  begin
                     Messages.Encode_Certificate
                       (Chain   => Empty_Bytes,
                        Spans   => Empty,
                        Count   => 0,
                        Context => Item.Request_Context (1 .. Item.Context_Length),
                        Staple  => Empty_Bytes,
                        Into    => Region,
                        Written => Length,
                        Error   => Local);
                     if SSL.Errors.Is_Error (Local) then
                        Refuse (Item, Result, Error, Local);
                        return;
                     end if;
                     Into (Cursor .. Cursor + Length - 1) := Region (1 .. Length);
                     Absorb (Item.Context, Into (Cursor .. Cursor + Length - 1));
                     Add (Result, Send_Handshake, Cursor, Cursor + Length - 1);
                     Cursor := Cursor + Length;
                  end;

                  --  An empty Certificate is never followed by a
                  --  CertificateVerify: there is no certificate for it to be
                  --  about.
                  Item.Sent_A_Certificate := False;
               end if;
            end;
         end if;

         Write_Finished
           (Item      => Item.Context,
            Which     => Schedules.Client_Side,
            Into      => Into,
            At_Offset => Cursor,
            First     => First,
            Last      => Last,
            Error     => Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;
         Add (Result, Send_Handshake, First, Last);

         --  Two milestones, derived separately because they are separate. The
         --  application traffic secrets are bound to the transcript through the
         --  server's Finished; the resumption master secret through this
         --  client's own, which has only just been written.
         Schedules.Derive_Master
           (Item                 => Item.Context.Schedule,
            Server_Finished_Hash => Server_Hash,
            Error                => Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;

         Schedules.Derive_Resumption
           (Item                 => Item.Context.Schedule,
            Client_Finished_Hash => SSL.Transcripts.Hash (Item.Context.Transcript),
            Error                => Local);
         if SSL.Errors.Is_Error (Local) then
            Refuse (Item, Result, Error, Local);
            return;
         end if;
      end;

      --  Read first: the server is already writing application data by the time
      --  this flight goes out, so the read direction must be ready before the
      --  write direction changes underneath the Finished that was just queued.
      Add (Result, Install_Read_Application_Keys);
      Add (Result, Install_Write_Application_Keys);
      Add (Result, Handshake_Complete);

      Item.Application_Keys_Installed := True;
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
      Kind    : Messages.Message_Type;
      Raw     : Messages.Type_Value;
      Length  : Byte_Index;
      Local   : SSL.Errors.Error_Information;
   begin
      Result := (Count => 0, Steps => [others => <>]);
      Error := SSL.Errors.No_Error;

      Messages.Parse_Header (Message, Kind, Raw, Length, Local);
      if SSL.Errors.Is_Error (Local) then
         Refuse (Item, Result, Error, Local);
         return;
      end if;

      --  The dispatch is on the state first and the message type second, not
      --  the other way round. A message that is well-formed but arrives in the
      --  wrong state is not a message this endpoint can act on, and deciding
      --  that here means no handler has to check where it was called from.
      case Item.State is
         when Wait_Server_Hello =>
            if Kind = Messages.Server_Hello then
               Handle_Server_Hello (Item, Message, Source, Into, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Encrypted_Extensions =>
            if Kind = Messages.Encrypted_Extensions then
               Handle_Encrypted_Extensions (Item, Message, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Certificate_Or_Request =>
            case Kind is
               when Messages.Certificate_Request =>
                  Handle_Certificate_Request (Item, Message, Result, Error);
               when Messages.Certificate =>
                  Handle_Certificate (Item, Message, Result, Error);
               when others =>
                  Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end case;

         when Wait_Certificate =>
            if Kind = Messages.Certificate then
               Handle_Certificate (Item, Message, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Certificate_Verify =>
            if Kind = Messages.Certificate_Verify then
               Handle_Certificate_Verify (Item, Message, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Wait_Finished =>
            if Kind = Messages.Finished then
               Handle_Finished (Item, Message, Into, Result, Error);
            else
               Refuse (Item, Result, Error, Unexpected (Item, Kind));
            end if;

         when Connected =>
            --  Post-handshake messages. NewSessionTicket and KeyUpdate are the
            --  engine's to act on, because both change state the engine owns --
            --  the session cache and the traffic states -- and neither belongs
            --  to the handshake this machine ran.
            Refuse (Item, Result, Error, Unexpected (Item, Kind));

         when Start | Failed =>
            --  Excluded by the precondition; listed so that adding a state is a
            --  compile error here rather than a silent fall-through.
            Refuse (Item, Result, Error, Unexpected (Item, Kind));
      end case;
   end Handle_Message;

   --------------------------
   -- Offer_Session --
   --------------------------

   procedure Offer_Session (Item : in out Machine; Value : SSL.Sessions.Session) is
      use type SSL.Versions.Protocol_Version;
   begin
      if SSL.Sessions.Is_Present (Value)
        and then SSL.Sessions.Version (Value) = SSL.Versions.TLS_1_2
      then
         --  A TLS 1.2 session. Only its ticket travels in this hello, and it
         --  travels in the extension a TLS 1.2 server reads; nothing about it
         --  reaches the key schedule here.
         declare
            Ticket : constant Byte_Array := SSL.Sessions.Ticket (Value);
         begin
            if Ticket'Length in 1 .. SSL.Sessions.Maximum_Ticket then
               Item.Legacy_Ticket (1 .. Ticket'Length) := Ticket;
               Item.Legacy_Ticket_Length := Ticket'Length;
               Item.Offer_Legacy := True;
            end if;
         end;
         return;
      end if;

      SSL.Sessions.Copy (Item.Offer, Value);
   end Offer_Session;

   procedure Request_Legacy_Tickets (Item : in out Machine; Value : Boolean) is
   begin
      Item.Offer_Legacy := Item.Offer_Legacy or else Value;
   end Request_Legacy_Tickets;

   ---------------
   -- Wipe --
   ---------------

   procedure Wipe (Item : in out Machine) is
   begin
      TLS13.Wipe (Item.Context);
      for Index in Item.Pairs'Range loop
         SSL.Crypto.Wipe (Item.Pairs (Index));
      end loop;
      Item.Offered := [others => <>];
      Item.Offered_Count := 0;
      Item.Cookie := [others => 0];
      Item.Cookie_Length := 0;
      Item.Request_Context := [others => 0];
      Item.Context_Length := 0;
      SSL.Sessions.Wipe (Item.Offer);
      Item.Offered_Session := False;
   end Wipe;

end SSL.TLS13.Client;
