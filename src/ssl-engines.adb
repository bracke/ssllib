with Interfaces;

with SSL.ALPN;
with SSL.Certificate_Validation;
with SSL.Cipher_Suites;
with SSL.Crypto;
with SSL.Handshake_Messages;
with SSL.Key_Schedule;
with SSL.Server_Names;
with SSL.Signature_Schemes;
with SSL.Supported_Groups;
with SSL.Trust;

package body SSL.Engines is

   package Machines_Client renames SSL.TLS13.Client;
   package Machines_Server renames SSL.TLS13.Server;
   package Legacy_Client renames SSL.TLS12.Client;
   package Legacy_Server renames SSL.TLS12.Server;
   package Legacy_Records renames SSL.TLS12.Records;
   package Messages renames SSL.Handshake_Messages;
   package Validation renames SSL.Certificate_Validation;

   use type SSL.Diagnostics.Sink_Reference;
   use type SSL.Sessions.Client_Caches.Cache_Reference;
   use type SSL.Ticket_Keys.Ring_Reference;


   use type SSL.Alerts.Alert_Description;
   use type SSL.Records.Content_Type;
   use type SSL.Key_Schedule.Epoch;
   use type SSL.TLS13.Step_Kind;
   use type SSL.TLS12.Step_Kind;
   use type SSL.TLS13.Client.Client_State;
   use type SSL.TLS13.Server.Server_State;
   use type SSL.Versions.Protocol_Version;
   use type SSL.Versions.Version_Value;
   use type SSL.Handshake_Messages.Message_Type;
   use type SSL.Handshake_Messages.Key_Update_Request;

   --  How long a ticket this library issues may live, in seconds.
   --
   --  A day. RFC 8446 section 4.6.1 caps a ticket at seven days; a day is short
   --  enough that a stolen ticket key stops being useful quickly, and long
   --  enough that a client reconnecting the next morning still resumes. A
   --  deployment that wants a different figure sets it on its ticket-key ring,
   --  which is where the decision belongs.
   Ticket_Lifetime : constant Natural := 86_400;

   --  One shared random source per engine would be another field to scrub; a
   --  system-entropy source holds no state worth protecting, so it is created
   --  where it is needed.
   procedure Entropy (Item : out SSL.Crypto.Random_Source);

   procedure Entropy (Item : out SSL.Crypto.Random_Source) is
   begin
      SSL.Crypto.Use_System_Entropy (Item);
   end Entropy;

   ---------------
   -- Image --
   ---------------

   function Image (Item : Lifecycle) return String is
     (case Item is
         when Uninitialized => "uninitialized",
         when Ready         => "ready",
         when Handshaking   => "handshaking",
         when Established   => "established",
         when Closing       => "closing",
         when Closed        => "closed",
         when Failed        => "failed");

   ----------------------
   -- Failure_Of --
   ----------------------

   function Failure_Of (Item : Engine) return SSL.Errors.Error_Information is
     (SSL.Errors.Primary (Item.Failure));

   ---------------------------------------------------------------------------
   --  Diagnostics
   ---------------------------------------------------------------------------

   --  Emit an event, if anybody is listening.
   --
   --  The level filter is applied inside Emit_Safely, so a connection with no
   --  sink costs one null test per event and a connection with a sink at the
   --  wrong level costs one comparison. Neither is worth guarding at every call
   --  site, which is why the sites below simply say what happened.
   procedure Note (Item : in out Engine; What : SSL.Diagnostics.Event);

   procedure Note (Item : in out Engine; What : SSL.Diagnostics.Event) is
   begin
      if Item.Watcher = null then
         return;
      end if;
      SSL.Diagnostics.Emit_Safely (Item.Watcher.all, What, Item.Level, Item.Redaction);
   end Note;

   ---------------------------------------------------------------------------
   --  Failing
   ---------------------------------------------------------------------------

   --  End the connection, record the cause, and queue the alert the error
   --  taxonomy chose for it.
   --
   --  The alert is never chosen here. `SSL.Errors.Classify` owns that mapping
   --  and is the only place it exists, so that the alert surface a peer can
   --  observe is one reviewable table rather than a decision at every failure
   --  site.
   --  Seal an alert under whichever record layer this connection is running.
   --
   --  There are two, and an alert has to go out under the one in force. Only
   --  the TLS 1.3 layer was consulted here once, which meant a TLS 1.2
   --  connection sent no close_notify at all: it marked itself closed and let
   --  the socket drop, and every correct peer reported that as a truncation
   --  attack -- which is exactly what OpenSSL and GnuTLS both said the first
   --  time this was pointed at them.
   --  @param Item    the engine
   --  @param Alert   the encoded alert body
   --  @param Into    out: the sealed record
   --  @param Written out: how many octets hold it
   --  @param Sealed  out: False when no layer was active and nothing was
   --                 written, which is not a failure -- a connection that never
   --                 protected anything has nothing to close down politely
   --  @param Error   out: No_Error, or why it could not be sealed
   procedure Seal_Alert
     (Item    : in out Engine;
      Alert   : Byte_Array;
      Into    : out Byte_Array;
      Written : out Byte_Index;
      Sealed  : out Boolean;
      Error   : out SSL.Errors.Error_Information);

   procedure Seal_Alert
     (Item    : in out Engine;
      Alert   : Byte_Array;
      Into    : out Byte_Array;
      Written : out Byte_Index;
      Sealed  : out Boolean;
      Error   : out SSL.Errors.Error_Information)
   is
   begin
      Into := [others => 0];
      Written := 0;
      Sealed := False;
      Error := SSL.Errors.No_Error;

      if Item.Running = TLS12_Protocol then
         if not Legacy_Records.Is_Active (Item.Legacy_Write) then
            return;
         end if;

         Legacy_Records.Protect
           (Item      => Item.Legacy_Write,
            Content   => SSL.Records.Alert_Content,
            Plaintext => Alert,
            Into      => Into,
            Written   => Written,
            Error     => Error);

      else
         if not SSL.Records.Is_Active (Item.Write_State)
           or else SSL.Records.Is_Closed (Item.Write_State)
         then
            return;
         end if;

         SSL.Records.Protect
           (Item      => Item.Write_State,
            Inner     => SSL.Records.Alert_Content,
            Plaintext => Alert,
            Padding   => 0,
            Into      => Into,
            Written   => Written,
            Error     => Error);
      end if;

      Sealed := not SSL.Errors.Is_Error (Error);
   end Seal_Alert;

   procedure Fail
     (Item  : in out Engine;
      Cause : SSL.Errors.Error_Information;
      Error : out SSL.Errors.Error_Information);

   procedure Fail
     (Item  : in out Engine;
      Cause : SSL.Errors.Error_Information;
      Error : out SSL.Errors.Error_Information)
   is
      Alert : constant SSL.Alerts.Alert := SSL.Errors.Alert_Of (Cause);
   begin
      SSL.Errors.Record_Failure (Item.Failure, Cause);
      Error := SSL.Errors.Primary (Item.Failure);

      if SSL.Alerts.Is_Present (Alert) and then not Item.Alert_Sent then
         --  The alert goes out under whatever keys this connection has reached,
         --  or in the clear when it has reached none. A queued alert the caller
         --  never drains is a caller that chose not to tell the peer, which is
         --  their decision to make and not this library's to force.
         declare
            Local       : SSL.Errors.Error_Information;
            Body_Octets : constant Byte_Array := SSL.Alerts.Encode (Alert);
            Sealed      : Byte_Array (1 .. 256) := [others => 0];
            Written     : Byte_Index;
            Ok          : Boolean;
            Protected_Now : Boolean;
         begin
            Item.Alert_Sent := True;
            Item.Alert_Value := SSL.Alerts.Description_Of (Alert);

            Seal_Alert (Item, Body_Octets, Sealed, Written, Protected_Now, Local);

            if not Protected_Now and then not SSL.Errors.Is_Error (Local) then
               --  Nothing was ever protected, so the alert goes out in the
               --  clear. A peer that has no keys either can still read it, and
               --  it is the only way to say anything at all at this point.
               SSL.Records.Emit_Plaintext
                 (Content   => SSL.Records.Alert_Content,
                  Version   => SSL.Versions.Legacy_Record_Value,
                  Plaintext => Body_Octets,
                  Into      => Sealed,
                  Written   => Written,
                  Error     => Local);
            end if;

            if not SSL.Errors.Is_Error (Local) and then Item.Output.Is_Reserved then
               Item.Output.Append (Sealed (1 .. Written), Ok);
            end if;
         end;
      end if;

      Item.State := Failed;
      SSL.Records.Close (Item.Read_State);
      SSL.Records.Close (Item.Write_State);

      Note (Item, SSL.Diagnostics.Make
              (SSL.Diagnostics.Connection_Failed, Error, Item.Identity));
   end Fail;

   ---------------------------------------------------------------------------
   --  Carrying out a state machine's plan
   ---------------------------------------------------------------------------

   --  Cut one flight of handshake octets into records and queue them.
   --
   --  A handshake message may be larger than a record, so this fragments; and
   --  several messages may share a record, which is why the caller hands over a
   --  whole span rather than one message at a time.
   procedure Queue_Handshake
     (Item  : in out Engine;
      Data  : Byte_Array;
      Error : out SSL.Errors.Error_Information);

   procedure Queue_Handshake
     (Item  : in out Engine;
      Data  : Byte_Array;
      Error : out SSL.Errors.Error_Information)
   is
      Limit  : constant Byte_Index := Byte_Index (Item.Bounds.Maximum_Plaintext_Record);
      Cursor : Byte_Index := Data'First;
      Ok     : Boolean;
   begin
      Error := SSL.Errors.No_Error;

      while Cursor <= Data'Last loop
         declare
            Chunk   : constant Byte_Index := Byte_Index'Min (Limit, Data'Last - Cursor + 1);
            Sealed  : Byte_Array (1 .. Chunk + 512) := [others => 0];
            Written : Byte_Index;
            Local   : SSL.Errors.Error_Information;
         begin
            if Item.Running = TLS12_Protocol then
               if Legacy_Records.Is_Active (Item.Legacy_Write) then
                  --  TLS 1.2 keeps the real content type in the clear, so the
                  --  record says `handshake` rather than hiding it.
                  Legacy_Records.Protect
                    (Item      => Item.Legacy_Write,
                     Content   => SSL.Records.Handshake_Content,
                     Plaintext => Data (Cursor .. Cursor + Chunk - 1),
                     Into      => Sealed,
                     Written   => Written,
                     Error     => Local);
               else
                  SSL.Records.Emit_Plaintext
                    (Content   => SSL.Records.Handshake_Content,
                     Version   => SSL.Versions.TLS_1_2_Value,
                     Plaintext => Data (Cursor .. Cursor + Chunk - 1),
                     Into      => Sealed,
                     Written   => Written,
                     Error     => Local);
               end if;

            elsif SSL.Records.Is_Active (Item.Write_State) then
               SSL.Records.Protect
                 (Item      => Item.Write_State,
                  Inner     => SSL.Records.Handshake_Content,
                  Plaintext => Data (Cursor .. Cursor + Chunk - 1),
                  Padding   => 0,
                  Into      => Sealed,
                  Written   => Written,
                  Error     => Local);
            else
               SSL.Records.Emit_Plaintext
                 (Content   => SSL.Records.Handshake_Content,
                  Version   => SSL.Versions.Legacy_Record_Value,
                  Plaintext => Data (Cursor .. Cursor + Chunk - 1),
                  Into      => Sealed,
                  Written   => Written,
                  Error     => Local);
            end if;

            if SSL.Errors.Is_Error (Local) then
               Error := Local;
               return;
            end if;

            Item.Output.Append (Sealed (1 .. Written), Ok);
            if not Ok then
               --  The output queue is sized to hold a whole flight, so a flight
               --  that does not fit is this library having mis-sized it rather
               --  than anything a peer did.
               Error := SSL.Errors.Make
                 (SSL.Errors.Code_Output_Queue_Full, SSL.Errors.Local_Implementation);
               return;
            end if;

            Cursor := Cursor + Chunk;
         end;
      end loop;
   end Queue_Handshake;

   --  Install one direction's traffic keys, from whichever machine is running.
   procedure Install
     (Item    : in out Engine;
      Reading : Boolean;
      Epoch   : SSL.Key_Schedule.Epoch;
      Error   : out SSL.Errors.Error_Information);

   procedure Install
     (Item    : in out Engine;
      Reading : Boolean;
      Epoch   : SSL.Key_Schedule.Epoch;
      Error   : out SSL.Errors.Error_Information)
   is
      Role : constant SSL.TLS13.Endpoint_Role :=
        (if Item.Kind = Client_Endpoint
         then SSL.TLS13.Client_Endpoint else SSL.TLS13.Server_Endpoint);
   begin
      --  The two directions are separate objects, so the branch is on which one
      --  rather than on a conditional expression: an `out` parameter cannot be
      --  chosen by an expression, and writing it out makes the pairing of
      --  direction and traffic state visible.
      if Reading then
         if Item.Kind = Client_Endpoint then
            SSL.TLS13.Install_Traffic_Keys
              (Machines_Client.Context_Of (Item.Client).all, Role, True, Epoch,
               Item.Read_State, Error);
         else
            SSL.TLS13.Install_Traffic_Keys
              (Machines_Server.Context_Of (Item.Server).all, Role, True, Epoch,
               Item.Read_State, Error);
         end if;
      else
         if Item.Kind = Client_Endpoint then
            SSL.TLS13.Install_Traffic_Keys
              (Machines_Client.Context_Of (Item.Client).all, Role, False, Epoch,
               Item.Write_State, Error);
         else
            SSL.TLS13.Install_Traffic_Keys
              (Machines_Server.Context_Of (Item.Server).all, Role, False, Epoch,
               Item.Write_State, Error);
         end if;
      end if;

      if not SSL.Errors.Is_Error (Error)
        and then Epoch = SSL.Key_Schedule.Application_Epoch
      then
         if Reading then
            Item.Read_Application := True;
         else
            Item.Write_Application := True;
         end if;
      end if;
   end Install;

   --  Build the connection metadata from whichever machine ran.
   procedure Complete_Handshake (Item : in out Engine);

   procedure Complete_Handshake (Item : in out Engine) is
      Outcome : constant SSL.TLS13.Negotiated :=
        (if Item.Kind = Client_Endpoint
         then Machines_Client.Outcome (Item.Client)
         else Machines_Server.Outcome (Item.Server));

      Authenticated : constant Boolean :=
        (if Item.Kind = Client_Endpoint
         then True
         else Machines_Server.Client_Authenticated (Item.Server));

      --  Read only when there is one to read. Both accessors have a
      --  precondition saying so, and reading through it would be reading a
      --  validation result no validation produced.
      Peer : constant Validation.Validation_Result :=
        (if Item.Kind = Client_Endpoint
         then Machines_Client.Peer_Certificate (Item.Client)
         elsif Authenticated
         then Machines_Server.Client_Certificate (Item.Server)
         else Validation.No_Result);
   begin
      SSL.Connection_Metadata.Establish
        (Item          => Item.Metadata,
         Identity      => Item.Identity,
         Context       => Item.Context,
         Version       => Outcome.Version,
         Suite         => Outcome.Suite,
         Group         => Outcome.Group,
         Protocol      => Outcome.Protocol,
         Has_Protocol  => Outcome.Has_Protocol,
         Name          => Outcome.Name,
         Authenticated => Authenticated,
         Scheme        => Outcome.Peer_Scheme,
         Leaf          => Validation.Leaf_Fingerprint (Peer),
         Public_Key    => Validation.Public_Key_Fingerprint (Peer),
         Depth         => Validation.Path_Length (Peer),
         Was_Resumed   => Outcome.Resumed);

      Item.State := Established;

      declare
         What : SSL.Diagnostics.Event :=
           SSL.Diagnostics.Make (SSL.Diagnostics.Handshake_Completed, Item.Identity);
      begin
         --  What was negotiated, never what was configured, and never a secret.
         --  The redaction level decides whether these travel; nothing here is
         --  of the kind that must not.
         SSL.Diagnostics.Add (What, "suite", SSL.Cipher_Suites.Image (Outcome.Suite));
         SSL.Diagnostics.Add (What, "group", SSL.Supported_Groups.Image (Outcome.Group));
         if Outcome.Has_Protocol then
            SSL.Diagnostics.Add (What, "protocol", SSL.ALPN.Image (Outcome.Protocol));
         end if;
         SSL.Diagnostics.Add
           (What, "peer", (if Authenticated then "authenticated" else "anonymous"));
         Note (Item, What);
      end;
   end Complete_Handshake;

   --  Declared here because Execute calls it and it is defined further down,
   --  next to the rest of the session handling.
   procedure Issue_Initial_Tickets (Item : in out Engine);

   --  The metadata a finished TLS 1.2 handshake reports.
   procedure Complete_Legacy_Handshake (Item : in out Engine);

   procedure Complete_Legacy_Handshake (Item : in out Engine) is
      Suite : constant SSL.Cipher_Suites.Cipher_Suite :=
        (if Item.Kind = Client_Endpoint
         then Legacy_Client.Cipher_Suite (Item.Legacy_Client)
         else Legacy_Server.Cipher_Suite (Item.Legacy_Server));

      Named : constant SSL.Supported_Groups.Named_Group :=
        (if Item.Kind = Client_Endpoint
         then Legacy_Client.Group (Item.Legacy_Client)
         else Legacy_Server.Group (Item.Legacy_Server));

      Name : constant SSL.Server_Names.DNS_Name :=
        (if Item.Kind = Client_Endpoint
         then Legacy_Client.Server_Name (Item.Legacy_Client)
         else Legacy_Server.Server_Name (Item.Legacy_Server));

      --  A TLS 1.2 client authenticates its server; a TLS 1.2 server in this
      --  library never asks for a client certificate, so its peer is anonymous.
      Authenticated : constant Boolean := Item.Kind = Client_Endpoint;

      Has_A_Protocol : constant Boolean :=
        (if Item.Kind = Client_Endpoint
         then Legacy_Client.Has_Protocol (Item.Legacy_Client)
         else Legacy_Server.Has_Protocol (Item.Legacy_Server));

      Was_Resumed : constant Boolean :=
        (if Item.Kind = Client_Endpoint
         then Legacy_Client.Resumed (Item.Legacy_Client)
         else Legacy_Server.Resumed (Item.Legacy_Server));
   begin
      SSL.Connection_Metadata.Establish
        (Item          => Item.Metadata,
         Identity      => Item.Identity,
         Context       => Item.Context,
         Version       => SSL.Versions.TLS_1_2,
         Suite         => Suite,
         Group         => Named,
         Protocol      =>
           (if Has_A_Protocol
            then (if Item.Kind = Client_Endpoint
                  then Legacy_Client.Protocol (Item.Legacy_Client)
                  else Legacy_Server.Protocol (Item.Legacy_Server))
            else SSL.ALPN.No_Protocol),
         Has_Protocol  => Has_A_Protocol,
         Name          => Name,
         Authenticated => Authenticated,
         Scheme        =>
           (if Item.Kind = Client_Endpoint
            then Legacy_Client.Peer_Scheme (Item.Legacy_Client)
            else SSL.Signature_Schemes.ECDSA_Secp256r1_SHA256),
         Leaf          =>
           Validation.Leaf_Fingerprint
             (if Item.Kind = Client_Endpoint
              then Legacy_Client.Peer_Certificate (Item.Legacy_Client)
              else Validation.No_Result),
         Public_Key    =>
           Validation.Public_Key_Fingerprint
             (if Item.Kind = Client_Endpoint
              then Legacy_Client.Peer_Certificate (Item.Legacy_Client)
              else Validation.No_Result),
         Depth         =>
           Validation.Path_Length
             (if Item.Kind = Client_Endpoint
              then Legacy_Client.Peer_Certificate (Item.Legacy_Client)
              else Validation.No_Result),
         Was_Resumed   => Was_Resumed);

      Item.State := Established;

      declare
         What : SSL.Diagnostics.Event :=
           SSL.Diagnostics.Make (SSL.Diagnostics.Handshake_Completed, Item.Identity);
      begin
         SSL.Diagnostics.Add (What, "version", "tls1.2");
         SSL.Diagnostics.Add (What, "suite", SSL.Cipher_Suites.Image (Suite));
         SSL.Diagnostics.Add (What, "group", SSL.Supported_Groups.Image (Named));
         SSL.Diagnostics.Add (What, "resumed", (if Was_Resumed then "yes" else "no"));
         Note (Item, What);
      end;

      --  A session the handshake earned, into the cache. Only a client has one
      --  to keep: a server's session went out inside the ticket it sealed.
      if Item.Kind = Client_Endpoint and then Item.Cache /= null then
         declare
            Local   : SSL.Errors.Error_Information;
            Present : Boolean;
            Stored  : Boolean;
         begin
            Legacy_Client.Take_New_Session
              (Item    => Item.Legacy_Client,
               Context => Item.Context,
               Setup   => Item.Setup,
               Anchors => Item.Anchors,
               Into    => Item.Pending_Session,
               Present => Present);

            if Present then
               SSL.Sessions.Client_Caches.Store_Safely
                 (Item.Cache.all, Item.Pending_Session, Stored, Local);
               if Stored then
                  Note (Item, SSL.Diagnostics.Make
                          (SSL.Diagnostics.Ticket_Received, Item.Identity));
               end if;
            end if;

            SSL.Sessions.Wipe (Item.Pending_Session);
         end;
      end if;
   end Complete_Legacy_Handshake;

   --  Carry out a plan in the order it was given.
   --
   --  The order is the whole point. A key installation between two messages of
   --  one flight means the messages before it go out under the old key and the
   --  ones after it under the new one, and a driver that reordered the steps --
   --  or that queued all the messages first and installed afterwards -- would
   --  encrypt at least one record under a key the peer will not use.
   procedure Execute
     (Item   : in out Engine;
      Result : SSL.TLS13.Plan;
      Region : Byte_Array;
      Error  : out SSL.Errors.Error_Information);

   procedure Execute
     (Item   : in out Engine;
      Result : SSL.TLS13.Plan;
      Region : Byte_Array;
      Error  : out SSL.Errors.Error_Information)
   is
      Local : SSL.Errors.Error_Information;
      Ok    : Boolean;
   begin
      Error := SSL.Errors.No_Error;

      for Index in 1 .. Result.Count loop
         declare
            This : constant SSL.TLS13.Step := Result.Steps (Index);
         begin
            case This.Kind is
               when SSL.TLS13.Send_Handshake =>
                  Queue_Handshake (Item, Region (This.First .. This.Last), Local);

               when SSL.TLS13.Send_Compatibility_CCS =>
                  --  RFC 8446 appendix D.4. One octet, always 0x01, always in
                  --  the clear, and never in the transcript: it exists so that
                  --  a middlebox watching for a TLS 1.2 shape sees one.
                  declare
                     Sealed  : Byte_Array (1 .. 8) := [others => 0];
                     Written : Byte_Index;
                  begin
                     SSL.Records.Emit_Plaintext
                       (Content   => SSL.Records.Change_Cipher_Spec,
                        Version   => SSL.Versions.Legacy_Record_Value,
                        Plaintext => [1 => 1],
                        Into      => Sealed,
                        Written   => Written,
                        Error     => Local);
                     if not SSL.Errors.Is_Error (Local) then
                        Item.Output.Append (Sealed (1 .. Written), Ok);
                        if not Ok then
                           Local := SSL.Errors.Make
                             (SSL.Errors.Code_Output_Queue_Full,
                              SSL.Errors.Local_Implementation);
                        end if;
                     end if;
                  end;

               when SSL.TLS13.Install_Write_Handshake_Keys =>
                  Install (Item, Reading => False,
                           Epoch => SSL.Key_Schedule.Handshake_Epoch, Error => Local);

               when SSL.TLS13.Install_Read_Handshake_Keys =>
                  Install (Item, Reading => True,
                           Epoch => SSL.Key_Schedule.Handshake_Epoch, Error => Local);

               when SSL.TLS13.Install_Write_Application_Keys =>
                  Install (Item, Reading => False,
                           Epoch => SSL.Key_Schedule.Application_Epoch, Error => Local);

               when SSL.TLS13.Install_Read_Application_Keys =>
                  Install (Item, Reading => True,
                           Epoch => SSL.Key_Schedule.Application_Epoch, Error => Local);

               when SSL.TLS13.Handshake_Complete =>
                  Complete_Handshake (Item);
                  --  Tickets go out with the flight that completes the
                  --  handshake, so a client has one before it has sent
                  --  anything. Issuing later would work too and would cost the
                  --  client a round trip it did not need.
                  Issue_Initial_Tickets (Item);
                  Local := SSL.Errors.No_Error;
            end case;

            if SSL.Errors.Is_Error (Local) then
               Fail (Item, Local, Error);
               return;
            end if;
         end;
      end loop;
   end Execute;

   ---------------------------------------------------------------------------
   --  Starting
   ---------------------------------------------------------------------------

   --  Reserve the three queues and the flight staging buffer. One place, so a
   --  client and a server cannot end up with different capacities.
   procedure Reserve_Buffers (Item : in out Engine; Ok : out Boolean);

   procedure Reserve_Buffers (Item : in out Engine; Ok : out Boolean) is
      Step : Boolean;
   begin
      Item.Input.Reserve (Input_Capacity, Step);
      Ok := Step;
      Item.Output.Reserve (Output_Capacity, Step);
      Ok := Ok and then Step;
      Item.Plaintext.Reserve (Plain_Capacity, Step);
      Ok := Ok and then Step;
      Item.Handshake.Reserve (Flight_Capacity, Step);
      Ok := Ok and then Step;
      Item.Flight.Reserve (Flight_Capacity, Step);
      Ok := Ok and then Step;
   end Reserve_Buffers;

   procedure Start_Client
     (Item     : in out Engine;
      Config   : not null access constant SSL.Configurations.Client_Configuration;
      Identity : Connection_ID;
      Now      : SSL.Clocks.Wall_Time;
      Error    : out SSL.Errors.Error_Information)
   is
      Ok : Boolean;
   begin
      Error := SSL.Errors.No_Error;

      Reserve_Buffers (Item, Ok);
      if not Ok then
         Fail (Item, SSL.Errors.Make
                 (SSL.Errors.Code_Storage_Exhausted, SSL.Errors.Local_Implementation), Error);
         return;
      end if;

      Item.Kind := Client_Endpoint;
      Item.Bounds := SSL.Configurations.Bounds (Config.all);
      Item.Now := Now;
      Item.Identity := Identity;
      Item.Context := SSL.Configurations.Security_Context_Of (Config.all);
      Item.Padding := SSL.Configurations.Record_Padding (Config.all);
      Item.Watcher := SSL.Configurations.Diagnostic_Sink (Config.all);
      Item.Level := SSL.Configurations.Diagnostic_Level (Config.all);
      Item.Redaction := SSL.Configurations.Diagnostic_Redaction (Config.all);
      Item.Offered_Versions := SSL.Configurations.Versions (Config.all);
      Item.Client_Policy := Config;
      Item.Cache := SSL.Configurations.Session_Cache_Of (Config.all);
      Item.Setup := SSL.Configurations.Fingerprint (Config.all);
      if SSL.Configurations.Has_Anchors (Config.all) then
         Item.Anchors := SSL.Trust.Fingerprint (SSL.Configurations.Anchors (Config.all).all);
      end if;

      --  A session to offer, if the cache has one bound to this connection.
      --  Looked up before the ClientHello is built, because the offer has to be
      --  in it: a session found later would be one offered in a handshake that
      --  had already committed to not resuming.
      if Item.Cache /= null then
         declare
            Found : Boolean;
            Local : SSL.Errors.Error_Information;
         begin
            SSL.Sessions.Client_Caches.Look_Up_Safely
              (Item    => Item.Cache.all,
               Name    => SSL.Configurations.Expected_Name (Config.all),
               Context => Item.Context,
               At_Time => Now,
               Into    => Item.Pending_Session,
               Found   => Found,
               Error   => Local);

            if Found
              and then SSL.Sessions.Matches
                         (Item    => Item.Pending_Session,
                          Name    => SSL.Configurations.Expected_Name (Config.all),
                          Context => Item.Context,
                          Setup   => Item.Setup,
                          Anchors => Item.Anchors,
                          At_Time => Now)
            then
               Machines_Client.Offer_Session (Item.Client, Item.Pending_Session);

               --  A TLS 1.2 session is kept here as well as offered. The
               --  TLS 1.3 machine puts its ticket in the hello and knows
               --  nothing else about it; if the server selects TLS 1.2 the
               --  TLS 1.2 machine needs the master secret, and this is the
               --  only copy of it that survives that far.
               if SSL.Sessions.Version (Item.Pending_Session) = SSL.Versions.TLS_1_2
               then
                  SSL.Sessions.Copy (Item.Legacy_Session, Item.Pending_Session);
                  Item.Has_Legacy_Session := True;
               end if;
            end if;

            --  Ask for a TLS 1.2 ticket even with nothing to offer: a cache
            --  with nowhere to start would never acquire a first session.
            Machines_Client.Request_Legacy_Tickets
              (Item.Client,
               SSL.Versions.Contains (Item.Offered_Versions, SSL.Versions.TLS_1_2));

            --  The engine's copy has done its work either way. The machine has
            --  its own.
            SSL.Sessions.Wipe (Item.Pending_Session);
         end;
      end if;

      declare
         Source : SSL.Crypto.Random_Source;
         Result : SSL.TLS13.Plan;
         Region : Byte_Array (1 .. Flight_Capacity) := [others => 0];
         Local  : SSL.Errors.Error_Information;
      begin
         Entropy (Source);
         Machines_Client.Begin_Handshake
           (Item   => Item.Client,
            Config => Config,
            Now    => Now,
            Source => Source,
            Into   => Region,
            Result => Result,
            Error  => Local);
         if SSL.Errors.Is_Error (Local) then
            Fail (Item, Local, Error);
            return;
         end if;

         Item.State := Handshaking;
         Note (Item, SSL.Diagnostics.Make
                 (SSL.Diagnostics.Connection_Started, Item.Identity));

         --  Keep the hello. If the server turns out to want TLS 1.2, the
         --  TLS 1.2 machine adopts these exact octets: they are already in the
         --  peer's transcript, and re-encoding them would produce a transcript
         --  the two ends do not share.
         for Index in 1 .. Result.Count loop
            if Result.Steps (Index).Kind = SSL.TLS13.Send_Handshake then
               declare
                  Width : constant Byte_Index :=
                    Result.Steps (Index).Last - Result.Steps (Index).First + 1;
               begin
                  if Width <= Item.Hello_Bytes'Length then
                     Item.Hello_Length := Width;
                     Item.Hello_Bytes (1 .. Width) :=
                       Region (Result.Steps (Index).First .. Result.Steps (Index).Last);
                  end if;
               end;
            end if;
         end loop;

         Execute (Item, Result, Region, Error);
      end;
   end Start_Client;

   procedure Start_Server
     (Item     : in out Engine;
      Config   : not null access constant SSL.Configurations.Server_Configuration;
      Identity : Connection_ID;
      Now      : SSL.Clocks.Wall_Time;
      Error    : out SSL.Errors.Error_Information)
   is
      Ok    : Boolean;
      Local : SSL.Errors.Error_Information;
   begin
      Error := SSL.Errors.No_Error;

      Reserve_Buffers (Item, Ok);
      if not Ok then
         Fail (Item, SSL.Errors.Make
                 (SSL.Errors.Code_Storage_Exhausted, SSL.Errors.Local_Implementation), Error);
         return;
      end if;

      Item.Kind := Server_Endpoint;
      Item.Bounds := SSL.Configurations.Bounds (Config.all);
      Item.Now := Now;
      Item.Identity := Identity;
      Item.Context := SSL.Configurations.Security_Context_Of (Config.all);
      Item.Padding := SSL.Configurations.Record_Padding (Config.all);
      Item.Watcher := SSL.Configurations.Diagnostic_Sink (Config.all);
      Item.Level := SSL.Configurations.Diagnostic_Level (Config.all);
      Item.Redaction := SSL.Configurations.Diagnostic_Redaction (Config.all);
      Item.Offered_Versions := SSL.Configurations.Versions (Config.all);
      Item.Server_Policy := Config;
      Item.Ring := SSL.Configurations.Ticket_Keys_Of (Config.all);
      Item.Issues := SSL.Configurations.Issues_Tickets (Config.all);
      Item.Setup := SSL.Configurations.Fingerprint (Config.all);
      if SSL.Configurations.Has_Anchors (Config.all) then
         Item.Anchors := SSL.Trust.Fingerprint (SSL.Configurations.Anchors (Config.all).all);
      end if;

      Machines_Server.Begin_Handshake (Item.Server, Config, Now, Local);
      if SSL.Errors.Is_Error (Local) then
         Fail (Item, Local, Error);
         return;
      end if;

      --  The same ring both seals and opens: a server that could issue a ticket
      --  it could not later open would be issuing tickets for nobody.
      Machines_Server.Set_Ticket_Keys (Item.Server, Item.Ring);

      --  A server produces nothing until it has heard a ClientHello, so it goes
      --  straight to Handshaking with an empty output queue.
      Item.State := Handshaking;
      Note (Item, SSL.Diagnostics.Make (SSL.Diagnostics.Connection_Started, Item.Identity));
   end Start_Server;

   ---------------------------------------------------------------------------
   --  Encrypted input and output
   ---------------------------------------------------------------------------

   procedure Supply_Encrypted
     (Item     : in out Engine;
      Data     : Byte_Array;
      Consumed : out Byte_Index;
      Error    : out SSL.Errors.Error_Information)
   is
   begin
      Consumed := 0;
      Error := SSL.Errors.No_Error;

      if Is_Terminal (Item.State) then
         Error := Failure_Of (Item);
         return;
      end if;

      if Item.Stream_Ended then
         --  Octets after the stream ended are octets the transport invented.
         Fail (Item, SSL.Errors.Make
                 (SSL.Errors.Code_Transport_Failed, SSL.Errors.Caller_Transport), Error);
         return;
      end if;

      Item.Input.Append_Partial (Data, Consumed);
   end Supply_Encrypted;

   procedure Report_End_Of_Stream
     (Item  : in out Engine;
      Error : out SSL.Errors.Error_Information)
   is
   begin
      Error := SSL.Errors.No_Error;
      Item.Stream_Ended := True;

      if Is_Terminal (Item.State) then
         return;
      end if;

      if Item.Peer_Notified then
         --  The peer said goodbye and then the stream ended, which is what an
         --  orderly close looks like.
         Item.State := Closed;
         return;
      end if;

      --  The stream ended without a close_notify. That is a truncation, and it
      --  is an attack whenever the application protocol has no length of its
      --  own: an attacker who can close the connection can otherwise make a
      --  response look complete when it is not.
      Item.Truncated := True;
      Fail (Item, SSL.Errors.Make
              (SSL.Errors.Code_Transport_Truncated, SSL.Errors.Caller_Transport), Error);
   end Report_End_Of_Stream;

   procedure Report_Transport_Failure
     (Item   : in out Engine;
      Reason : String)
   is
      Ignored : SSL.Errors.Error_Information;
   begin
      if Is_Terminal (Item.State) then
         return;
      end if;

      Fail (Item,
            SSL.Errors.Make
              (Code     => SSL.Errors.Code_Transport_Failed,
               Origin   => SSL.Errors.Caller_Transport,
               Provider => Reason),
            Ignored);
   end Report_Transport_Failure;

   function Pending_Encrypted (Item : Engine) return Byte_Index is
     (if Item.Output.Is_Reserved then Item.Output.Length else 0);

   procedure Peek_Encrypted
     (Item  : Engine;
      Into  : out Byte_Array;
      Count : out Byte_Index)
   is
   begin
      Into := [others => 0];
      Count := 0;
      if Item.Output.Is_Reserved then
         Item.Output.Peek (Into, Count);
      end if;
   end Peek_Encrypted;

   procedure Consume_Encrypted (Item : in out Engine; Count : Byte_Index) is
   begin
      Item.Output.Consume (Count);

      --  A close_notify that has actually left is what ends an orderly
      --  shutdown. Until then the connection is Closing, because the peer has
      --  not been told anything.
      if Item.Shutdown_Sent and then Item.Output.Is_Empty and then Item.State = Closing then
         Item.State := Closed;
      end if;
   end Consume_Encrypted;

   ---------------------------------------------------------------------------
   --  Application data
   ---------------------------------------------------------------------------

   function Pending_Plaintext (Item : Engine) return Byte_Index is
     (if Item.Plaintext.Is_Reserved then Item.Plaintext.Length else 0);

   procedure Peek_Plaintext
     (Item  : Engine;
      Into  : out Byte_Array;
      Count : out Byte_Index)
   is
   begin
      Into := [others => 0];
      Count := 0;
      if Item.Plaintext.Is_Reserved then
         Item.Plaintext.Peek (Into, Count);
      end if;
   end Peek_Plaintext;

   procedure Consume_Plaintext (Item : in out Engine; Count : Byte_Index) is
   begin
      Item.Plaintext.Consume (Count);
   end Consume_Plaintext;

   --  Declared here because Write_Plaintext calls it and it is defined below,
   --  next to the rest of the KeyUpdate handling where it belongs.
   procedure Schedule_Update_If_Due
     (Item  : in out Engine;
      Error : out SSL.Errors.Error_Information);

   procedure Write_Plaintext
     (Item     : in out Engine;
      Data     : Byte_Array;
      Accepted : out Byte_Index;
      Error    : out SSL.Errors.Error_Information)
   is
      Limit : constant Byte_Index :=
        Byte_Index (Item.Bounds.Maximum_Plaintext_Record);
      Cursor : Byte_Index := Data'First;
   begin
      Accepted := 0;
      Error := SSL.Errors.No_Error;

      --  Ordered most-specific first. A connection that has been shut down is
      --  also terminal and also not Established, and reporting either of those
      --  instead would tell the caller less than it already knows.
      if Item.Shutdown_Sent then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Write_After_Close_Notify, SSL.Errors.Caller_Request);
         return;
      end if;

      if Item.Peer_Notified then
         --  The peer said it would send nothing more. It did not promise to
         --  read anything more either, and writing into a closed direction is a
         --  write nobody will see.
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Read_After_Peer_Close, SSL.Errors.Caller_Request);
         return;
      end if;

      if Item.State /= Established then
         Error := (if Is_Terminal (Item.State) and then SSL.Errors.Has_Failure (Item.Failure)
                   then Failure_Of (Item)
                   else SSL.Errors.Make
                          (SSL.Errors.Code_Handshake_Not_Complete,
                           SSL.Errors.Caller_Request));
         return;
      end if;

      --  Queue a KeyUpdate first when this direction's usage has reached the
      --  advisory threshold, so that it goes out while there is still room
      --  under the current key. Waiting until the hard limit would leave the
      --  connection with nothing it may legally send.
      Schedule_Update_If_Due (Item, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      --  One record at a time, stopping when the output queue is full. Stopping
      --  is the backpressure: an engine that kept accepting would be an
      --  unbounded buffer an application could grow without ever draining.
      while Cursor <= Data'Last loop
         declare
            Chunk : constant Byte_Index :=
              Byte_Index'Min (Limit, Data'Last - Cursor + 1);
            --  Sized for whichever record construction is running. The TLS 1.3
            --  traffic state is not active on a TLS 1.2 connection, so asking
            --  it for the suite would fail its own precondition.
            Sealed : Byte_Array
              (1 .. Chunk + SSL.Records.Header_Length
                  + (if Item.Running = TLS12_Protocol
                     then Legacy_Records.Expansion
                            (Legacy_Records.Suite_Of (Item.Legacy_Write))
                     else SSL.Records.Expansion
                            (SSL.Records.Suite_Of (Item.Write_State),
                             Item.Padding))) := [others => 0];
            Written : Byte_Index;
            Local   : SSL.Errors.Error_Information;
            Ok      : Boolean;
         begin
            exit when Item.Output.Space < Sealed'Length;

            if Item.Running = TLS12_Protocol then
               Legacy_Records.Protect
                 (Item      => Item.Legacy_Write,
                  Content   => SSL.Records.Application_Content,
                  Plaintext => Data (Cursor .. Cursor + Chunk - 1),
                  Into      => Sealed,
                  Written   => Written,
                  Error     => Local);
            else
               SSL.Records.Protect
                 (Item      => Item.Write_State,
                  Inner     => SSL.Records.Application_Content,
                  Plaintext => Data (Cursor .. Cursor + Chunk - 1),
                  Padding   => Item.Padding,
                  Into      => Sealed,
                  Written   => Written,
                  Error     => Local);
            end if;
            if SSL.Errors.Is_Error (Local) then
               Fail (Item, Local, Error);
               return;
            end if;

            Item.Output.Append (Sealed (1 .. Written), Ok);
            if not Ok then
               exit;
            end if;

            Accepted := Accepted + Chunk;
            Cursor := Cursor + Chunk;
         end;
      end loop;
   end Write_Plaintext;

   ---------------------------------------------------------------------------
   --  KeyUpdate
   ---------------------------------------------------------------------------

   --  Advance one direction's traffic secret and reinstall the key.
   --
   --  Which end's secret advances is decided by direction, not by role: a
   --  KeyUpdate replaces the sender's own write key and the receiver's own read
   --  key, and those are the same secret seen from two ends.
   procedure Advance_Direction
     (Item    : in out Engine;
      Reading : Boolean;
      Error   : out SSL.Errors.Error_Information);

   procedure Advance_Direction
     (Item    : in out Engine;
      Reading : Boolean;
      Error   : out SSL.Errors.Error_Information)
   is
      Role : constant SSL.TLS13.Endpoint_Role :=
        (if Item.Kind = Client_Endpoint
         then SSL.TLS13.Client_Endpoint else SSL.TLS13.Server_Endpoint);
      Which : constant SSL.Key_Schedule.Party := SSL.TLS13.Party_For (Role, Reading);
   begin
      if Item.Kind = Client_Endpoint then
         SSL.Key_Schedule.Advance_Traffic_Secret
           (Machines_Client.Schedule_Of (Item.Client).all, Which, Error);
      else
         SSL.Key_Schedule.Advance_Traffic_Secret
           (Machines_Server.Schedule_Of (Item.Server).all, Which, Error);
      end if;
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      Install (Item, Reading, SSL.Key_Schedule.Application_Epoch, Error);
   end Advance_Direction;

   --  Queue a KeyUpdate and then replace the write key, in that order.
   procedure Send_Key_Update
     (Item     : in out Engine;
      Ask_Peer : Boolean;
      Error    : out SSL.Errors.Error_Information);

   procedure Send_Key_Update
     (Item     : in out Engine;
      Ask_Peer : Boolean;
      Error    : out SSL.Errors.Error_Information)
   is
      Region  : Byte_Array (1 .. 32) := [others => 0];
      Written : Byte_Index;
      Local   : SSL.Errors.Error_Information;
   begin
      Error := SSL.Errors.No_Error;

      Messages.Encode_Key_Update
        (Request => (if Ask_Peer
                     then Messages.Update_Requested else Messages.Update_Not_Requested),
         Into    => Region,
         Written => Written,
         Error   => Local);
      if SSL.Errors.Is_Error (Local) then
         Fail (Item, Local, Error);
         return;
      end if;

      --  Queued under the *old* key. Installing first would produce a message
      --  the peer cannot read, and it would read it as a forgery.
      Queue_Handshake (Item, Region (1 .. Written), Local);
      if SSL.Errors.Is_Error (Local) then
         Fail (Item, Local, Error);
         return;
      end if;

      --  A KeyUpdate is not in the transcript. RFC 8446 section 4.6.3 puts it
      --  after the handshake, and the transcript ended with the Finished
      --  messages; absorbing it would change hashes both ends have already
      --  used.
      Advance_Direction (Item, Reading => False, Error => Local);
      if SSL.Errors.Is_Error (Local) then
         Fail (Item, Local, Error);
         return;
      end if;

      Note (Item, SSL.Diagnostics.Make (SSL.Diagnostics.Key_Update_Sent, Item.Identity));
   end Send_Key_Update;

   procedure Request_Key_Update
     (Item     : in out Engine;
      Ask_Peer : Boolean;
      Error    : out SSL.Errors.Error_Information)
   is
   begin
      Error := SSL.Errors.No_Error;

      if Item.State /= Established then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Not_Complete, SSL.Errors.Caller_Request);
         return;
      end if;

      Send_Key_Update (Item, Ask_Peer, Error);
   end Request_Key_Update;

   --  Act on a KeyUpdate the peer sent.
   procedure Receive_Key_Update
     (Item    : in out Engine;
      Message : Byte_Array;
      Error   : out SSL.Errors.Error_Information);

   procedure Receive_Key_Update
     (Item    : in out Engine;
      Message : Byte_Array;
      Error   : out SSL.Errors.Error_Information)
   is
      Request : Messages.Key_Update_Request;
      Local   : SSL.Errors.Error_Information;
   begin
      Error := SSL.Errors.No_Error;

      Messages.Parse_Key_Update (Message, Request, Local);
      if SSL.Errors.Is_Error (Local) then
         Fail (Item, Local, Error);
         return;
      end if;

      Note (Item, SSL.Diagnostics.Make (SSL.Diagnostics.Key_Update_Received, Item.Identity));

      Item.Peer_Updates := Item.Peer_Updates + 1;
      if Item.Peer_Updates > Item.Bounds.Maximum_Peer_Key_Updates then
         --  A flood. Each one obliges this endpoint to derive a key and, when
         --  requested, to send one back; the peer pays four octets.
         Fail (Item, SSL.Errors.Make
                 (SSL.Errors.Code_Key_Update_Flood, SSL.Errors.Peer_Message), Error);
         return;
      end if;

      --  The peer's new key applies to everything after this message, so the
      --  read key changes now and not before.
      Advance_Direction (Item, Reading => True, Error => Local);
      if SSL.Errors.Is_Error (Local) then
         Fail (Item, Local, Error);
         return;
      end if;

      if Request = Messages.Update_Requested then
         --  Answered with update_not_requested. Answering with a request would
         --  oblige an answer to the answer, which is an exchange with no end.
         Send_Key_Update (Item, Ask_Peer => False, Error => Error);
      end if;
   end Receive_Key_Update;

   --  Schedule an update when usage approaches the configured threshold.
   --
   --  Checked before protecting rather than after, so the update is queued
   --  while there is still room under the current key to send it. At the hard
   --  limit the record layer refuses outright and the connection fails closed,
   --  which is the correct end: one more record under an exhausted key would be
   --  worse than no connection.
   procedure Schedule_Update_If_Due
     (Item  : in out Engine;
      Error : out SSL.Errors.Error_Information)
   is
   begin
      Error := SSL.Errors.No_Error;

      if Item.State /= Established or else Item.Shutdown_Sent then
         return;
      end if;
      if not SSL.Records.Is_Active (Item.Write_State) then
         return;
      end if;
      if not SSL.Records.Update_Advisable (Item.Write_State, Item.Bounds) then
         return;
      end if;

      Send_Key_Update (Item, Ask_Peer => False, Error => Error);
   end Schedule_Update_If_Due;

   ---------------------------------------------------------------------------
   --  Sessions
   ---------------------------------------------------------------------------

   procedure Issue_Initial_Tickets (Item : in out Engine) is
      Ignored : SSL.Errors.Error_Information;
   begin
      --  Two, which is what every widely deployed server sends. One would mean
      --  a client that resumed twice in quick succession fell back on the
      --  second; more would be work nobody asked for. A ticket is single-use,
      --  so the count is how many resumptions this connection has paid for.
      for Round in 1 .. 2 loop
         Issue_Ticket (Item, Ignored);
      end loop;
   end Issue_Initial_Tickets;

   procedure Issue_Ticket
     (Item  : in out Engine;
      Error : out SSL.Errors.Error_Information)
   is
      Source : SSL.Crypto.Random_Source;
      Local  : SSL.Errors.Error_Information;
   begin
      Error := SSL.Errors.No_Error;

      --  Every reason not to issue is a state rather than a failure: a client
      --  never issues, a server with tickets disabled does not, one with no
      --  active key does not, and one that has issued its allowance stops.
      if Item.Kind /= Server_Endpoint
        or else not Item.Issues
        or else Item.Ring = null
        or else not SSL.Ticket_Keys.Has_Active_Key (Item.Ring.all)
        or else Item.State /= Established
        or else Item.Tickets_Issued >= Item.Bounds.Maximum_Tickets_Per_Connection
      then
         return;
      end if;

      SSL.Crypto.Use_System_Entropy (Source);

      declare
         Schedule : constant access constant SSL.Key_Schedule.Schedule :=
           Machines_Server.Context_Of (Item.Server).Schedule'Access;
         Width    : constant Byte_Index := SSL.Key_Schedule.Digest_Width (Schedule.all);
         Outcome  : constant SSL.TLS13.Negotiated := Machines_Server.Outcome (Item.Server);

         --  Each ticket gets its own nonce, so that several from one connection
         --  yield unrelated pre-shared keys. Without that, a client offering one
         --  would be offering all of them.
         Nonce  : Byte_Array (1 .. 8) := [others => 0];
         Secret : Byte_Array (1 .. Width) := [others => 0];

         Sealed  : Byte_Array (1 .. SSL.Ticket_Keys.Maximum_Ticket) := [others => 0];
         Written : Byte_Index;
      begin
         SSL.Crypto.Fill (Source, Nonce, Local);
         if SSL.Errors.Is_Error (Local) then
            Error := Local;
            return;
         end if;

         SSL.Key_Schedule.Resumption_PSK (Schedule.all, Nonce, Secret, Local);
         if SSL.Errors.Is_Error (Local) then
            SSL.Crypto.Scrub (Secret);
            Error := Local;
            return;
         end if;

         SSL.Sessions.Store
           (Item          => Item.Pending_Session,
            Version       => Outcome.Version,
            Suite         => Outcome.Suite,
            Name          => Outcome.Name,
            Protocol      => Outcome.Protocol,
            Has_Protocol  => Outcome.Has_Protocol,
            Issued        => Item.Now,
            Lifetime      => Ticket_Lifetime,
            Context       => Item.Context,
            Setup         => Item.Setup,
            Anchors       => Item.Anchors,
            Authenticated => Machines_Server.Client_Authenticated (Item.Server),
            --  The ticket octets are not known yet -- they are what this is
            --  about to produce -- so a placeholder goes in and the sealed form
            --  never reads it back.
            Ticket_Bytes  => [1 => 0],
            Age_Add       => 0,
            Nonce_Bytes   => Nonce,
            Secret        => Secret,
            Error         => Local);
         SSL.Crypto.Scrub (Secret);

         if SSL.Errors.Is_Error (Local) then
            Error := Local;
            return;
         end if;

         SSL.Ticket_Keys.Seal
           (Item    => Item.Ring.all,
            Value   => Item.Pending_Session,
            Into    => Sealed,
            Written => Written,
            Error   => Local);
         SSL.Sessions.Wipe (Item.Pending_Session);

         if SSL.Errors.Is_Error (Local) then
            Error := Local;
            return;
         end if;

         declare
            Region : Byte_Array (1 .. Flight_Capacity) := [others => 0];
            Length : Byte_Index;
         begin
            Messages.Encode_New_Session_Ticket
              (Lifetime => Interfaces.Unsigned_32 (Ticket_Lifetime),
               Age_Add  => 0,
               Nonce    => Nonce,
               Ticket   => Sealed (1 .. Written),
               Into     => Region,
               Written  => Length,
               Error    => Local);
            if SSL.Errors.Is_Error (Local) then
               Error := Local;
               return;
            end if;

            Queue_Handshake (Item, Region (1 .. Length), Local);
            if SSL.Errors.Is_Error (Local) then
               Fail (Item, Local, Error);
               return;
            end if;
         end;

         Item.Tickets_Issued := Item.Tickets_Issued + 1;
      end;
   end Issue_Ticket;

   --  Take a NewSessionTicket a server sent and put a session in the cache.
   procedure Accept_Ticket
     (Item    : in out Engine;
      Message : Byte_Array;
      Error   : out SSL.Errors.Error_Information);

   procedure Accept_Ticket
     (Item    : in out Engine;
      Message : Byte_Array;
      Error   : out SSL.Errors.Error_Information)
   is
      Parsed : Messages.New_Session_Ticket_Message;
      Local  : SSL.Errors.Error_Information;
   begin
      Error := SSL.Errors.No_Error;

      --  Parsed whether or not there is anywhere to put it: a malformed ticket
      --  is a malformed message, and a peer that cannot frame one cannot be
      --  trusted to have framed anything else.
      Messages.Parse_New_Session_Ticket (Message, Item.Bounds, Parsed, Local);
      if SSL.Errors.Is_Error (Local) then
         Fail (Item, Local, Error);
         return;
      end if;

      if Item.Kind /= Client_Endpoint or else Item.Cache = null then
         --  Nowhere to keep it. Discarding is correct and costs nothing: the
         --  next connection does a full handshake, which is what a client with
         --  no cache does anyway.
         return;
      end if;

      declare
         Schedule : constant access constant SSL.Key_Schedule.Schedule :=
           Machines_Client.Context_Of (Item.Client).Schedule'Access;
         Width    : constant Byte_Index := SSL.Key_Schedule.Digest_Width (Schedule.all);

         Nonce_First : Byte_Index;
         Nonce_Last  : Byte_Index;
         First       : Byte_Index;
         Last        : Byte_Index;

         Secret  : Byte_Array (1 .. Width) := [others => 0];
         Kept    : Boolean;
         Outcome : constant SSL.TLS13.Negotiated := Machines_Client.Outcome (Item.Client);
      begin
         Messages.Nonce_Span (Parsed, Nonce_First, Nonce_Last);
         Messages.Ticket_Span (Parsed, First, Last);

         SSL.Key_Schedule.Resumption_PSK
           (Schedule.all, Message (Nonce_First .. Nonce_Last), Secret, Local);
         if SSL.Errors.Is_Error (Local) then
            SSL.Crypto.Scrub (Secret);
            --  A derivation failure is this endpoint's, not the peer's, and it
            --  costs a resumption rather than the connection.
            return;
         end if;

         SSL.Sessions.Store
           (Item          => Item.Pending_Session,
            Version       => Outcome.Version,
            Suite         => Outcome.Suite,
            Name          => Outcome.Name,
            Protocol      => Outcome.Protocol,
            Has_Protocol  => Outcome.Has_Protocol,
            Issued        => Item.Now,
            Lifetime      => Natural (Messages.Lifetime (Parsed)),
            Context       => Item.Context,
            Setup         => Item.Setup,
            Anchors       => Item.Anchors,
            Authenticated => Outcome.Peer_Authenticated,
            Ticket_Bytes  => Message (First .. Last),
            Age_Add       => Messages.Age_Add (Parsed),
            Nonce_Bytes   => Message (Nonce_First .. Nonce_Last),
            Secret        => Secret,
            Error         => Local);
         SSL.Crypto.Scrub (Secret);

         if SSL.Errors.Is_Error (Local) then
            return;
         end if;

         SSL.Sessions.Client_Caches.Store_Safely
           (Item.Cache.all, Item.Pending_Session, Kept, Local);
         SSL.Sessions.Wipe (Item.Pending_Session);

         if Kept then
            Note (Item, SSL.Diagnostics.Make
                    (SSL.Diagnostics.Ticket_Received, Item.Identity));
         end if;
      end;
   end Accept_Ticket;

   ---------------------------------------------------------------------------
   --  Exported key material
   ---------------------------------------------------------------------------

   procedure Export_Keying_Material
     (Item        : Engine;
      Label       : String;
      Context     : Byte_Array;
      Has_Context : Boolean;
      Into        : out Byte_Array;
      Error       : out SSL.Errors.Error_Information)
   is
   begin
      Into := [others => 0];

      if Item.State not in Established | Closing | Closed then
         --  Before the handshake there is no exporter master secret, and
         --  anything produced would not be bound to a connection either end had
         --  authenticated.
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Not_Complete, SSL.Errors.Caller_Request);
         return;
      end if;

      if Item.Kind = Client_Endpoint then
         SSL.Key_Schedule.Export
           (Item        => Machines_Client.Context_Of (Item.Client).Schedule,
            Label       => Label,
            Context     => Context,
            Has_Context => Has_Context,
            Into        => Into,
            Error       => Error);
      else
         SSL.Key_Schedule.Export
           (Item        => Machines_Server.Context_Of (Item.Server).Schedule,
            Label       => Label,
            Context     => Context,
            Has_Context => Has_Context,
            Into        => Into,
            Error       => Error);
      end if;

      if SSL.Errors.Is_Error (Error) then
         Into := [others => 0];
      end if;
   end Export_Keying_Material;

   ---------------------------------------------------------------------------
   --  Shutdown and cancellation
   ---------------------------------------------------------------------------

   procedure Begin_Shutdown
     (Item  : in out Engine;
      Error : out SSL.Errors.Error_Information)
   is
      Body_Octets : constant Byte_Array :=
        SSL.Alerts.Encode (SSL.Alerts.Local_Alert (SSL.Alerts.Close_Notify));
      Sealed  : Byte_Array (1 .. 256) := [others => 0];
      Written : Byte_Index;
      Local   : SSL.Errors.Error_Information;
      Ok      : Boolean;
      Protected_Now : Boolean;
   begin
      Error := SSL.Errors.No_Error;

      if Is_Terminal (Item.State) or else Item.Shutdown_Sent then
         return;
      end if;

      Seal_Alert (Item, Body_Octets, Sealed, Written, Protected_Now, Local);

      if SSL.Errors.Is_Error (Local) then
         Fail (Item, Local, Error);
         return;
      end if;

      if not Protected_Now then
         --  Nothing was ever encrypted, so there is nothing to close down
         --  politely. The connection simply ends.
         Item.State := Closed;
         Item.Shutdown_Sent := True;
         return;
      end if;

      Item.Output.Append (Sealed (1 .. Written), Ok);
      if not Ok then
         Fail (Item, SSL.Errors.Make
                 (SSL.Errors.Code_Output_Queue_Full, SSL.Errors.Local_Implementation), Error);
         return;
      end if;

      Item.Shutdown_Sent := True;
      Item.State := Closing;

      --  Closed on whichever layer was used, so that nothing more goes out
      --  after the close_notify under either one.
      if Item.Running = TLS12_Protocol then
         Legacy_Records.Close (Item.Legacy_Write);
      else
         SSL.Records.Close (Item.Write_State);
      end if;
   end Begin_Shutdown;

   procedure Cancel (Item : in out Engine; Reason : SSL.Cancellation.Token) is
      Ignored : SSL.Errors.Error_Information;
   begin
      if Is_Terminal (Item.State) then
         return;
      end if;

      if SSL.Cancellation.Is_Cancelled (Reason) then
         --  No alert: a cancellation is this endpoint giving up, and telling
         --  the peer would mean waiting for the telling to be sent, which is
         --  the waiting the caller has just declined to do.
         SSL.Errors.Record_Failure
           (Item.Failure,
            SSL.Errors.Make (SSL.Errors.Code_Cancelled, SSL.Errors.Caller_Request));
         Item.State := Failed;
         SSL.Records.Close (Item.Read_State);
         SSL.Records.Close (Item.Write_State);
      end if;
      Ignored := SSL.Errors.No_Error;
   end Cancel;

   procedure Set_Deadline (Item : in out Engine; Value : SSL.Clocks.Deadline) is
   begin
      Item.Expires_At := Value;
   end Set_Deadline;

   ---------------------------------------------------------------------------
   --  Carrying out a TLS 1.2 plan
   ---------------------------------------------------------------------------

   --  The TLS 1.2 vocabulary, which differs from TLS 1.3's in one item and that
   --  item is the whole epoch model: `Send_Change_Cipher_Spec` here is the real
   --  switch, and the record after it uses the new keys.
   procedure Execute_Legacy
     (Item   : in out Engine;
      Result : SSL.TLS12.Plan;
      Region : Byte_Array;
      Error  : out SSL.Errors.Error_Information);

   procedure Execute_Legacy
     (Item   : in out Engine;
      Result : SSL.TLS12.Plan;
      Region : Byte_Array;
      Error  : out SSL.Errors.Error_Information)
   is
      Local : SSL.Errors.Error_Information;
      Ok    : Boolean;
   begin
      Error := SSL.Errors.No_Error;

      for Index in 1 .. Result.Count loop
         declare
            This : constant SSL.TLS12.Step := Result.Steps (Index);
         begin
            Local := SSL.Errors.No_Error;

            case This.Kind is
               when SSL.TLS12.Send_Handshake =>
                  Queue_Handshake (Item, Region (This.First .. This.Last), Local);

               when SSL.TLS12.Send_Change_Cipher_Spec =>
                  --  One octet, always 0x01, always in the clear, and never in
                  --  the transcript. Unlike TLS 1.3's compatibility record this
                  --  one means something: everything after it is protected.
                  declare
                     Sealed  : Byte_Array (1 .. 8) := [others => 0];
                     Written : Byte_Index;
                  begin
                     SSL.Records.Emit_Plaintext
                       (Content   => SSL.Records.Change_Cipher_Spec,
                        Version   => SSL.Versions.TLS_1_2_Value,
                        Plaintext => [1 => 1],
                        Into      => Sealed,
                        Written   => Written,
                        Error     => Local);
                     if not SSL.Errors.Is_Error (Local) then
                        Item.Output.Append (Sealed (1 .. Written), Ok);
                        if not Ok then
                           Local := SSL.Errors.Make
                             (SSL.Errors.Code_Output_Queue_Full,
                              SSL.Errors.Local_Implementation);
                        end if;
                     end if;
                  end;

               when SSL.TLS12.Install_Write_Keys =>
                  if Item.Kind = Client_Endpoint then
                     Legacy_Records.Install
                       (Item.Legacy_Write,
                        Legacy_Client.Cipher_Suite (Item.Legacy_Client),
                        Legacy_Client.Client_Keys (Item.Legacy_Client).all);
                  else
                     Legacy_Records.Install
                       (Item.Legacy_Write,
                        Legacy_Server.Cipher_Suite (Item.Legacy_Server),
                        Legacy_Server.Server_Keys (Item.Legacy_Server).all);
                  end if;

               when SSL.TLS12.Install_Read_Keys =>
                  if Item.Kind = Client_Endpoint then
                     Legacy_Records.Install
                       (Item.Legacy_Read,
                        Legacy_Client.Cipher_Suite (Item.Legacy_Client),
                        Legacy_Client.Server_Keys (Item.Legacy_Client).all);
                  else
                     Legacy_Records.Install
                       (Item.Legacy_Read,
                        Legacy_Server.Cipher_Suite (Item.Legacy_Server),
                        Legacy_Server.Client_Keys (Item.Legacy_Server).all);
                  end if;

               when SSL.TLS12.Handshake_Complete =>
                  Complete_Legacy_Handshake (Item);
            end case;

            if SSL.Errors.Is_Error (Local) then
               Fail (Item, Local, Error);
               return;
            end if;
         end;
      end loop;
   end Execute_Legacy;

   ---------------------------------------------------------------------------
   --  The record loop
   ---------------------------------------------------------------------------

   --  Feed one complete handshake message to whichever machine is running, and
   --  carry out whatever it asks for.
   --  Is this ServerHello selecting something other than TLS 1.3?
   --
   --  Decided on supported_versions and on nothing else, which is what RFC 8446
   --  section 4.2.1 says decides it. A hello without the extension is a TLS 1.2
   --  hello however its legacy version field reads.
   function Should_Fall_Back (Item : Engine; Message : Byte_Array) return Boolean;

   function Should_Fall_Back (Item : Engine; Message : Byte_Array) return Boolean is
      Kind     : Messages.Message_Type;
      Raw      : Messages.Type_Value;
      Length   : Byte_Index;
      Local    : SSL.Errors.Error_Information;
      Parsed   : Messages.Server_Hello_Message;
   begin
      if Item.Running /= TLS13_Protocol
        or else Machines_Client.State_Of (Item.Client)
                /= Machines_Client.Wait_Server_Hello
        or else Item.Hello_Length = 0
      then
         return False;
      end if;

      Messages.Parse_Header (Message, Kind, Raw, Length, Local);
      if SSL.Errors.Is_Error (Local) or else Kind /= Messages.Server_Hello then
         return False;
      end if;

      --  Parsed under the legacy extension rules, because a TLS 1.2 hello may
      --  carry extensions a TLS 1.3 one may not, and refusing it here would
      --  turn a version choice into a decode failure.
      Messages.Parse_Server_Hello (Message, Item.Bounds, Parsed, Local, Legacy => True);
      if SSL.Errors.Is_Error (Local) then
         return False;
      end if;

      return Messages.Selected_Version (Parsed) /= SSL.Versions.TLS_1_3_Value;
   end Should_Fall_Back;

   --  Hand the connection to the TLS 1.2 client machine and replay the hello.
   procedure Fall_Back
     (Item          : in out Engine;
      Message       : Byte_Array;
      Source        : in out SSL.Crypto.Random_Source;
      Region        : in out Byte_Array;
      Result_Legacy : Boolean;
      Error         : out SSL.Errors.Error_Information);

   procedure Fall_Back
     (Item          : in out Engine;
      Message       : Byte_Array;
      Source        : in out SSL.Crypto.Random_Source;
      Region        : in out Byte_Array;
      Result_Legacy : Boolean;
      Error         : out SSL.Errors.Error_Information)
   is
      pragma Unreferenced (Result_Legacy);

      Local       : SSL.Errors.Error_Information;
      Legacy_Plan : SSL.TLS12.Plan;
   begin
      Error := SSL.Errors.No_Error;

      if not SSL.Versions.Contains (Item.Offered_Versions, SSL.Versions.TLS_1_2) then
         --  The server selected a version this configuration did not offer.
         Fail (Item, SSL.Errors.Make
                 (SSL.Errors.Code_Selected_Version_Not_Offered,
                  SSL.Errors.Peer_Message), Error);
         return;
      end if;

      --  The random and the legacy session identifier are read back out of the
      --  hello that was sent rather than remembered alongside it. Remembering
      --  them would be a second copy to keep in step with the octets, and the
      --  octets are what the server hashed and signed over.
      declare
         Sent : Messages.Client_Hello_Message;
      begin
         Messages.Parse_Client_Hello
           (Item.Hello_Bytes (1 .. Item.Hello_Length), Item.Bounds, Sent, Local);
         if SSL.Errors.Is_Error (Local) then
            Fail (Item, Local, Error);
            return;
         end if;

         Item.Hello_Random := Messages.Random (Sent);

         declare
            Identifier : constant Byte_Array := Messages.Session_Id (Sent);
         begin
            Item.Hello_Session_Length := Identifier'Length;
            if Identifier'Length > 0 then
               Item.Hello_Session (1 .. Identifier'Length) := Identifier;
            end if;
         end;
      end;

      --  What the hello offered, handed to the machine that can use it. The
      --  TLS 1.2 machine has to know before it sees the ServerHello, because
      --  the ServerHello is where an acceptance is announced.
      if Item.Has_Legacy_Session then
         Legacy_Client.Offer_Session (Item.Legacy_Client, Item.Legacy_Session);
         SSL.Sessions.Wipe (Item.Legacy_Session);
         Item.Has_Legacy_Session := False;
      else
         Legacy_Client.Request_Tickets (Item.Legacy_Client, Item.Cache /= null);
      end if;

      Legacy_Client.Adopt_Hello
        (Item         => Item.Legacy_Client,
         Config       => Item.Client_Policy,
         Now          => Item.Now,
         Hello        => Item.Hello_Bytes (1 .. Item.Hello_Length),
         Random_Value => Item.Hello_Random,
         Session_Id   => Item.Hello_Session (1 .. Item.Hello_Session_Length),
         Error        => Local);
      if SSL.Errors.Is_Error (Local) then
         Fail (Item, Local, Error);
         return;
      end if;

      Item.Running := TLS12_Protocol;

      --  The TLS 1.3 machine is finished with. Scrubbed now rather than left
      --  holding an ephemeral private key nothing will ever use.
      Machines_Client.Wipe (Item.Client);

      Legacy_Client.Handle_Message
        (Item.Legacy_Client, Message, Source, Region, Legacy_Plan, Local);
      if SSL.Errors.Is_Error (Local) then
         Fail (Item, Local, Error);
         return;
      end if;

      Execute_Legacy (Item, Legacy_Plan, Region, Error);
   end Fall_Back;

   --  Does this ClientHello want TLS 1.2 rather than TLS 1.3?
   function Should_Serve_Legacy (Item : Engine; Message : Byte_Array) return Boolean;

   function Should_Serve_Legacy (Item : Engine; Message : Byte_Array) return Boolean is
      Kind   : Messages.Message_Type;
      Raw    : Messages.Type_Value;
      Length : Byte_Index;
      Local  : SSL.Errors.Error_Information;
      Hello  : Messages.Client_Hello_Message;
   begin
      if not SSL.Versions.Contains (Item.Offered_Versions, SSL.Versions.TLS_1_2) then
         return False;
      end if;

      Messages.Parse_Header (Message, Kind, Raw, Length, Local);
      if SSL.Errors.Is_Error (Local) or else Kind /= Messages.Client_Hello then
         return False;
      end if;

      Messages.Parse_Client_Hello (Message, Item.Bounds, Hello, Local);
      if SSL.Errors.Is_Error (Local) then
         return False;
      end if;

      --  A client that offers TLS 1.3 gets TLS 1.3: this server never chooses
      --  the older protocol when the newer one is on the table, whatever the
      --  configuration's preference order says about suites.
      return not SSL.Versions.Contains
                   (Messages.Offered_Versions (Hello), SSL.Versions.TLS_1_3);
   end Should_Serve_Legacy;

   procedure Serve_Legacy
     (Item    : in out Engine;
      Message : Byte_Array;
      Source  : in out SSL.Crypto.Random_Source;
      Region  : in out Byte_Array;
      Error   : out SSL.Errors.Error_Information);

   procedure Serve_Legacy
     (Item    : in out Engine;
      Message : Byte_Array;
      Source  : in out SSL.Crypto.Random_Source;
      Region  : in out Byte_Array;
      Error   : out SSL.Errors.Error_Information)
   is
      Local       : SSL.Errors.Error_Information;
      Legacy_Plan : SSL.TLS12.Plan;
   begin
      Error := SSL.Errors.No_Error;

      Legacy_Server.Set_Ticket_Keys (Item.Legacy_Server, Item.Ring);
      Legacy_Server.Set_Issues_Tickets (Item.Legacy_Server, Item.Issues);

      Legacy_Server.Begin_Handshake
        (Item.Legacy_Server, Item.Server_Policy, Item.Now, Local);
      if SSL.Errors.Is_Error (Local) then
         Fail (Item, Local, Error);
         return;
      end if;

      Item.Running := TLS12_Protocol;
      Machines_Server.Wipe (Item.Server);

      Legacy_Server.Handle_Message
        (Item.Legacy_Server, Message, Source, Region, Legacy_Plan, Local);
      if SSL.Errors.Is_Error (Local) then
         Fail (Item, Local, Error);
         return;
      end if;

      Execute_Legacy (Item, Legacy_Plan, Region, Error);
   end Serve_Legacy;

   procedure Deliver_Handshake
     (Item    : in out Engine;
      Message : Byte_Array;
      Error   : out SSL.Errors.Error_Information);

   procedure Deliver_Handshake
     (Item    : in out Engine;
      Message : Byte_Array;
      Error   : out SSL.Errors.Error_Information)
   is
      Source : SSL.Crypto.Random_Source;
      Result : SSL.TLS13.Plan;
      Region : Byte_Array (1 .. Flight_Capacity) := [others => 0];
      Local  : SSL.Errors.Error_Information;
   begin
      Error := SSL.Errors.No_Error;
      Entropy (Source);

      --  A TLS 1.2 connection has its own machines and its own plan vocabulary.
      if Item.Running = TLS12_Protocol then
         declare
            Legacy_Plan : SSL.TLS12.Plan;
         begin
            if Item.Kind = Client_Endpoint then
               Legacy_Client.Handle_Message
                 (Item.Legacy_Client, Message, Source, Region, Legacy_Plan, Local);
            else
               Legacy_Server.Handle_Message
                 (Item.Legacy_Server, Message, Source, Region, Legacy_Plan, Local);
            end if;

            if SSL.Errors.Is_Error (Local) then
               Fail (Item, Local, Error);
               return;
            end if;

            Execute_Legacy (Item, Legacy_Plan, Region, Error);
            return;
         end;
      end if;

      if Item.Kind = Client_Endpoint then
         --  A ServerHello that does not select TLS 1.3 is the point at which a
         --  connection that offered both versions becomes a TLS 1.2 one. The
         --  hello this client already sent is adopted rather than resent: it is
         --  in the server's transcript, and a second one would be a second
         --  handshake.
         if Should_Fall_Back (Item, Message) then
            Fall_Back (Item, Message, Source, Region, Result_Legacy => True,
                       Error => Error);
            return;
         end if;

         Machines_Client.Handle_Message
           (Item    => Item.Client,
            Message => Message,
            Source  => Source,
            Into    => Region,
            Result  => Result,
            Error   => Local);
      else
         --  A server decides the version when it reads the hello, which is the
         --  only message that carries the offer.
         if Item.State = Handshaking
           and then Machines_Server.State_Of (Item.Server)
                    = Machines_Server.Received_Client_Hello
           and then Should_Serve_Legacy (Item, Message)
         then
            Serve_Legacy (Item, Message, Source, Region, Error);
            return;
         end if;

         Machines_Server.Handle_Message
           (Item    => Item.Server,
            Message => Message,
            Source  => Source,
            Into    => Region,
            Result  => Result,
            Error   => Local);
      end if;

      if SSL.Errors.Is_Error (Local) then
         Fail (Item, Local, Error);
         return;
      end if;

      Execute (Item, Result, Region, Error);
   end Deliver_Handshake;

   --  Post-handshake handshake messages. Only two exist here -- KeyUpdate and
   --  NewSessionTicket -- and neither belongs to the handshake the state
   --  machine ran, which is why they are handled at this level rather than
   --  passed down to a machine that has finished.
   procedure Deliver_Post_Handshake
     (Item    : in out Engine;
      Message : Byte_Array;
      Error   : out SSL.Errors.Error_Information);

   procedure Deliver_Post_Handshake
     (Item    : in out Engine;
      Message : Byte_Array;
      Error   : out SSL.Errors.Error_Information)
   is
      Kind   : Messages.Message_Type;
      Raw    : Messages.Type_Value;
      Length : Byte_Index;
      Local  : SSL.Errors.Error_Information;
   begin
      Error := SSL.Errors.No_Error;

      Messages.Parse_Header (Message, Kind, Raw, Length, Local);
      if SSL.Errors.Is_Error (Local) then
         Fail (Item, Local, Error);
         return;
      end if;

      case Kind is
         when Messages.Key_Update =>
            Receive_Key_Update (Item, Message, Error);

         when Messages.New_Session_Ticket =>
            Accept_Ticket (Item, Message, Error);

         when others =>
            --  Everything else is a message for a handshake that has finished.
            --  Post-handshake client authentication is one of the features this
            --  library declines, and a CertificateRequest here is exactly that.
            Fail (Item,
                  SSL.Errors.Make
                    (Code       => SSL.Errors.Code_Unexpected_Handshake_Message,
                     Origin     => SSL.Errors.Peer_Message,
                     Parameters =>
                       [SSL.Errors.Text_Parameter ("received", Messages.Image (Kind))]),
                  Error);
      end case;
   end Deliver_Post_Handshake;

   --  Take whole handshake messages out of the reassembly queue and deliver
   --  them. A message that has not fully arrived stays where it is.
   procedure Drain_Handshake
     (Item  : in out Engine;
      Error : out SSL.Errors.Error_Information);

   procedure Drain_Handshake
     (Item  : in out Engine;
      Error : out SSL.Errors.Error_Information)
   is
      Header : Byte_Array (1 .. Messages.Header_Length);
      Copied : Byte_Index;
   begin
      Error := SSL.Errors.No_Error;

      while Item.Handshake.Length >= Messages.Header_Length loop
         Item.Handshake.Peek (Header, Copied);

         declare
            Declared : constant Byte_Index :=
              65_536 * Byte_Index (Header (2))
              + 256 * Byte_Index (Header (3))
              + Byte_Index (Header (4));
            Whole    : constant Byte_Index := Messages.Header_Length + Declared;
         begin
            if Declared > Byte_Index (Item.Bounds.Maximum_Handshake_Message) then
               --  Refused on the declared length, before the octets behind it
               --  are waited for: a peer that declares a megabyte does not get
               --  to make this endpoint hold one.
               Fail (Item,
                     SSL.Errors.Limit_Failure
                       (SSL.Limits.Handshake_Message,
                        Long_Long_Integer (Item.Bounds.Maximum_Handshake_Message),
                        Long_Long_Integer (Declared)),
                     Error);
               return;
            end if;

            exit when Item.Handshake.Length < Whole;

            declare
               Message : Byte_Array (1 .. Whole);
            begin
               Item.Handshake.Peek (Message, Copied);
               Item.Handshake.Consume (Whole);
               if Item.State = Established then
                  Deliver_Post_Handshake (Item, Message, Error);
               else
                  Deliver_Handshake (Item, Message, Error);
               end if;
               if SSL.Errors.Is_Error (Error) then
                  return;
               end if;
            end;
         end;

         exit when Is_Terminal (Item.State);
      end loop;
   end Drain_Handshake;

   --  Act on one record's recovered content.
   procedure Dispatch_Content
     (Item    : in out Engine;
      Inner   : SSL.Records.Content_Type;
      Content : Byte_Array;
      Error   : out SSL.Errors.Error_Information);

   procedure Dispatch_Content
     (Item    : in out Engine;
      Inner   : SSL.Records.Content_Type;
      Content : Byte_Array;
      Error   : out SSL.Errors.Error_Information)
   is
      Ok : Boolean;
   begin
      Error := SSL.Errors.No_Error;

      case Inner is
         when SSL.Records.Handshake_Content =>
            if Content'Length = 0 then
               --  RFC 8446 section 5.1 forbids an empty handshake fragment. It
               --  is also free work for a peer to send, which is why the run of
               --  them is bounded above.
               Fail (Item, SSL.Errors.Make
                       (SSL.Errors.Code_Handshake_Message_Malformed,
                        SSL.Errors.Peer_Message), Error);
               return;
            end if;

            Item.Handshake.Append (Content, Ok);
            if not Ok then
               Fail (Item, SSL.Errors.Make
                       (SSL.Errors.Code_Input_Buffer_Full, SSL.Errors.Peer_Message), Error);
               return;
            end if;
            Drain_Handshake (Item, Error);

         when SSL.Records.Application_Content =>
            if Item.State /= Established then
               --  Application data before the handshake finished is data nobody
               --  has authenticated the sender of.
               Fail (Item, SSL.Errors.Make
                       (SSL.Errors.Code_Record_Type_Forbidden,
                        SSL.Errors.Peer_Message), Error);
               return;
            end if;
            if Item.Peer_Notified then
               Fail (Item, SSL.Errors.Make
                       (SSL.Errors.Code_Read_After_Peer_Close,
                        SSL.Errors.Peer_Message), Error);
               return;
            end if;

            Item.Plaintext.Append (Content, Ok);
            if not Ok then
               --  Not reachable from the loop above, which stops before
               --  opening a record that would not fit. Kept because this
               --  procedure is called from more than one place and a queue
               --  that cannot take what it was handed must not lose it
               --  quietly: growing the queue would be an unbounded buffer a
               --  peer controls the size of.
               Fail (Item, SSL.Errors.Make
                       (SSL.Errors.Code_Plaintext_Queue_Full,
                        SSL.Errors.Local_Implementation), Error);
            end if;

         when SSL.Records.Alert_Content =>
            if Content'Length /= 2 then
               Fail (Item, SSL.Errors.Make
                       (SSL.Errors.Code_Record_Inner_Type_Invalid,
                        SSL.Errors.Peer_Message), Error);
               return;
            end if;

            declare
               Alert : constant SSL.Alerts.Alert :=
                 SSL.Alerts.Peer_Alert (Content (Content'First), Content (Content'Last));
            begin
               Note (Item, SSL.Diagnostics.Make
                       (SSL.Diagnostics.Peer_Alert_Received, Item.Identity));

               if SSL.Alerts.Is_Close_Notify (Alert) then
                  Item.Peer_Notified := True;
                  SSL.Records.Close (Item.Read_State);
                  if Item.Shutdown_Sent then
                     Item.State := (if Item.Output.Is_Empty then Closed else Closing);
                  end if;
                  return;
               end if;

               --  Terminality is decided on the description, never on the level
               --  octet the peer chose: a peer calling handshake_failure a
               --  warning does not make it survivable.
               if SSL.Alerts.Is_Terminal (Alert) then
                  Fail (Item,
                        SSL.Errors.Make
                          (Code       => SSL.Errors.Code_Peer_Alert_Received,
                           Origin     => SSL.Errors.Peer_Alert,
                           Parameters =>
                             [SSL.Errors.Text_Parameter
                                ("alert", SSL.Alerts.Image (Alert))]),
                        Error);
               end if;
            end;

         when SSL.Records.Change_Cipher_Spec =>
            if Item.Running = TLS12_Protocol then
               --  In TLS 1.2 this is the real epoch switch: the record after it
               --  uses the new keys. It goes to the machine, which says when to
               --  install them.
               declare
                  Legacy_Plan : SSL.TLS12.Plan;

                  --  A ChangeCipherSpec produces no octets of its own, so the
                  --  region a plan would write into is never touched.
                  Region      : constant Byte_Array (1 .. 1) := [others => 0];
                  Local       : SSL.Errors.Error_Information;
               begin
                  if Item.Kind = Client_Endpoint then
                     Legacy_Client.Handle_Change_Cipher_Spec
                       (Item.Legacy_Client, Legacy_Plan, Local);
                  else
                     Legacy_Server.Handle_Change_Cipher_Spec
                       (Item.Legacy_Server, Legacy_Plan, Local);
                  end if;

                  if SSL.Errors.Is_Error (Local) then
                     Fail (Item, Local, Error);
                     return;
                  end if;

                  Execute_Legacy (Item, Legacy_Plan, Region, Error);
               end;
               return;
            end if;

            --  In TLS 1.3 it is only ever the compatibility artefact, and
            --  bounded. RFC 8446 appendix D.4 permits it and gives it no
            --  meaning, so acting on it in any way would be acting on something
            --  a peer can send at will.
            Item.Compatibility_CCS := Item.Compatibility_CCS + 1;
            if Item.Compatibility_CCS > Item.Bounds.Maximum_Compatibility_CCS then
               Fail (Item, SSL.Errors.Make
                       (SSL.Errors.Code_Record_Unexpected_CCS,
                        SSL.Errors.Peer_Message), Error);
            end if;

         when SSL.Records.Invalid_Content =>
            Fail (Item, SSL.Errors.Make
                    (SSL.Errors.Code_Record_Inner_Type_Invalid,
                     SSL.Errors.Peer_Message), Error);
      end case;
   end Dispatch_Content;

   procedure Advance
     (Item  : in out Engine;
      Now   : SSL.Clocks.Monotonic_Time;
      Error : out SSL.Errors.Error_Information)
   is
      Header_Octets : Byte_Array (1 .. SSL.Records.Header_Length);
      Copied        : Byte_Index;
   begin
      Error := SSL.Errors.No_Error;

      if Is_Terminal (Item.State) then
         Error := Failure_Of (Item);
         return;
      end if;

      if SSL.Clocks.Is_Set (Item.Expires_At) and then SSL.Clocks.Has_Expired (Item.Expires_At, Now) then
         --  Reported, not enforced. Nothing here waits, so a deadline is a fact
         --  the caller asked to be told about rather than something this
         --  procedure can act on.
         Fail (Item, SSL.Errors.Make
                 (SSL.Errors.Code_Deadline_Reached, SSL.Errors.Caller_Request), Error);
         return;
      end if;

      while Item.Input.Length >= SSL.Records.Header_Length loop
         Item.Input.Peek (Header_Octets, Copied);

         declare
            Header : SSL.Records.Record_Header;
            Local  : SSL.Errors.Error_Information;
         begin
            SSL.Records.Parse_Header (Header_Octets, Header, Local);
            if SSL.Errors.Is_Error (Local) then
               Fail (Item, Local, Error);
               return;
            end if;

            exit when Item.Input.Length < SSL.Records.Header_Length + Header.Length;

            --  Room for what this record could yield, before it is opened.
            --
            --  Backpressure, rather than the refusal that stood here. A record
            --  whose plaintext would not fit was decrypted anyway and then
            --  failed the connection: an application reading slower than its
            --  peer sends killed its own connection, which is not what a full
            --  queue means. It means wait.
            --
            --  So the record stays in the input queue, undecrypted, and this
            --  loop stops. Nothing is lost and nothing is forced: the input
            --  queue fills, Ready stops asking the transport for more, and the
            --  peer's own flow control does the rest -- which is what the
            --  window on the other side is for.
            --
            --  Measured against the ciphertext length because the plaintext
            --  length is inside the ciphertext: it is an upper bound, and
            --  erring towards waiting is the safe direction.
            exit when Item.State = Established
              and then Item.Plaintext.Is_Reserved
              and then Item.Plaintext.Space < Header.Length;

            declare
               Whole : Byte_Array
                 (1 .. SSL.Records.Header_Length + Header.Length) := [others => 0];
               Plain : Byte_Array (1 .. Header.Length) := [others => 0];
               Inner : SSL.Records.Content_Type;
               Taken : Byte_Index;
            begin
               Item.Input.Peek (Whole, Copied);
               Item.Input.Consume (Whole'Length);

               if Item.Running = TLS12_Protocol
                 and then Header.Content /= SSL.Records.Change_Cipher_Spec
                 and then Legacy_Records.Is_Active (Item.Legacy_Read)
               then
                  --  TLS 1.2's record construction, which is its own: the
                  --  content type stays in the clear and the additional data
                  --  carries the plaintext length.
                  Legacy_Records.Open
                    (Item     => Item.Legacy_Read,
                     Header   => Whole (1 .. SSL.Records.Header_Length),
                     Fragment => Whole (SSL.Records.Header_Length + 1 .. Whole'Last),
                     Into     => Plain,
                     Written  => Taken,
                     Error    => Local);
                  Inner := Header.Content;

               elsif Item.Running = TLS12_Protocol
                 and then Header.Content /= SSL.Records.Change_Cipher_Spec
               then
                  --  Before the epoch switch a TLS 1.2 record is in the clear.
                  Inner := Header.Content;
                  Taken := Header.Length;
                  Plain (1 .. Taken) :=
                    Whole (SSL.Records.Header_Length + 1 .. Whole'Last);
                  Local := SSL.Errors.No_Error;

               elsif Header.Content = SSL.Records.Change_Cipher_Spec then
                  --  Never decrypted, at any point in the connection. A
                  --  compatibility ChangeCipherSpec keeps its own outer type
                  --  and travels in the clear even after the read epoch has
                  --  changed (RFC 8446 appendix D.4), so handing it to the AEAD
                  --  would fail a precondition on a record that is not a
                  --  forgery. It carries no meaning either way; only the count
                  --  of them matters, and that is bounded below.
                  Inner := SSL.Records.Change_Cipher_Spec;
                  Taken := 0;
                  Local := SSL.Errors.No_Error;

               elsif SSL.Records.Is_Active (Item.Read_State) then
                  SSL.Records.Open
                    (Item       => Item.Read_State,
                     Header     => Whole (1 .. SSL.Records.Header_Length),
                     Ciphertext => Whole (SSL.Records.Header_Length + 1 .. Whole'Last),
                     Into       => Plain,
                     Written    => Taken,
                     Inner      => Inner,
                     Error      => Local);
               else
                  Inner := Header.Content;
                  Taken := Header.Length;
                  Plain (1 .. Taken) :=
                    Whole (SSL.Records.Header_Length + 1 .. Whole'Last);
                  Local := SSL.Errors.No_Error;
               end if;

               if SSL.Errors.Is_Error (Local) then
                  Fail (Item, Local, Error);
                  return;
               end if;

               --  A bounded run of records that carried nothing. Each one costs
               --  this endpoint a decryption and costs the peer almost nothing,
               --  so the run is capped rather than tolerated indefinitely.
               if Taken = 0 and then Inner /= SSL.Records.Change_Cipher_Spec then
                  Item.Empty_Records := Item.Empty_Records + 1;
                  if Item.Empty_Records > Item.Bounds.Maximum_Consecutive_Empty_Records then
                     Fail (Item, SSL.Errors.Make
                             (SSL.Errors.Code_Record_Empty_Run_Excessive,
                              SSL.Errors.Peer_Message), Error);
                     return;
                  end if;
               else
                  Item.Empty_Records := 0;
               end if;

               Dispatch_Content (Item, Inner, Plain (1 .. Taken), Error);
               if SSL.Errors.Is_Error (Error) then
                  return;
               end if;
            end;
         end;

         exit when Is_Terminal (Item.State);
      end loop;
   end Advance;

   ---------------------------------------------------------------------------
   --  Readiness
   ---------------------------------------------------------------------------

   function Ready (Item : Engine) return Readiness is
     (Wants_Transport_Read  =>
        Item.State in Handshaking | Established | Closing
        and then not Item.Stream_Ended
        and then (Item.Input.Is_Reserved and then Item.Input.Space > 0),
      Wants_Transport_Write => Pending_Encrypted (Item) > 0,
      Accepts_Plaintext     =>
        Item.State = Established
        and then not Item.Shutdown_Sent
        and then (Item.Output.Is_Reserved and then Item.Output.Space > 0),
      Has_Plaintext         => Pending_Plaintext (Item) > 0,
      Handshake_Complete    => Item.State in Established | Closing | Closed,
      Peer_Closed           => Item.Peer_Notified,
      Terminal              => Is_Terminal (Item.State));

   ---------------
   -- Wipe --
   ---------------

   procedure Wipe (Item : in out Engine) is
   begin
      Machines_Client.Wipe (Item.Client);
      Machines_Server.Wipe (Item.Server);
      SSL.Records.Wipe (Item.Read_State);
      SSL.Records.Wipe (Item.Write_State);
      Item.Input.Wipe;
      Item.Output.Wipe;
      Item.Plaintext.Wipe;
      Item.Handshake.Wipe;
      Item.Flight.Wipe;
   end Wipe;

end SSL.Engines;
