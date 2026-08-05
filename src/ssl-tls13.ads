with SSL.ALPN;
with SSL.Cipher_Suites;
with SSL.Crypto;
with SSL.Errors;
with SSL.Handshake_Messages;
with SSL.Key_Schedule;
with SSL.Limits;
with SSL.Records;
with SSL.Secrets;
with SSL.Server_Names;
with SSL.Signature_Schemes;
with SSL.Supported_Groups;
with SSL.Transcripts;
with SSL.Versions;

--  @summary What the TLS 1.3 client and server state machines share: the
--  handshake context, the shared verification steps, and the vocabulary each
--  machine answers its driver in.
--
--  The two machines are separate -- a client and a server have different
--  flights, different obligations and different failure modes, and a single
--  machine parameterized by role would encode that difference as a scattering
--  of `if Role = ...`. What they genuinely share lives here: the transcript and
--  key schedule and how the two are stepped together, the arithmetic of
--  installing traffic keys, and the two verifications that are identical
--  whichever end performs them -- a peer's CertificateVerify and a peer's
--  Finished.
--
--  **These machines do no input and no output.** A machine is handed one
--  complete handshake message and a buffer to write into, and answers with an
--  ordered plan: send these octets, install these keys, the handshake is
--  complete. Everything that touches a socket is the engine's, above this. That
--  is what makes a handshake testable without a network, and it is what keeps
--  the ordering of key installation -- the part of TLS 1.3 that is easiest to
--  get subtly wrong -- in one reviewable place rather than spread across an I/O
--  loop.
private package SSL.TLS13 is

   ---------------------------------------------------------------------------
   --  What a machine answers with
   ---------------------------------------------------------------------------

   --  One thing the driver must do, in the order it must do it.
   --
   --  Key installation is a step rather than something the driver infers,
   --  because in TLS 1.3 the two directions change keys at different moments
   --  and the moments are not symmetric. A server installs its write keys
   --  after ServerHello and its read keys at the same time; a client installs
   --  both when it has processed ServerHello; the application keys go in for
   --  writing before the client's Finished on the server and after it on the
   --  client. A driver that worked that out for itself would be a second place
   --  for it to be wrong.
   type Step_Kind is
     (Send_Handshake,
      --  A span of the output buffer holding one complete handshake message,
      --  already absorbed into the transcript.

      Send_Compatibility_CCS,
      --  A ChangeCipherSpec sent only to make middleboxes see something they
      --  recognize (RFC 8446 appendix D.4). It carries no meaning and is not
      --  in the transcript.

      Install_Write_Handshake_Keys,
      Install_Read_Handshake_Keys,
      Install_Write_Application_Keys,
      Install_Read_Application_Keys,

      Handshake_Complete);
      --  Everything is verified and both directions are on application keys.

   type Step is record
      Kind  : Step_Kind := Handshake_Complete;
      First : Byte_Index := 1;
      Last  : Byte_Index := 0;
   end record;

   Maximum_Steps : constant := 16;

   type Step_Array is array (1 .. Maximum_Steps) of Step;

   --  An ordered plan. Bounded, because a flight has a fixed maximum shape and
   --  an unbounded one would be a place for a peer to make this endpoint do
   --  arbitrary work.
   type Plan is record
      Count : Natural range 0 .. Maximum_Steps := 0;
      Steps : Step_Array := [others => <>];
   end record;

   function Is_Empty (Item : Plan) return Boolean is (Item.Count = 0);

   ---------------------------------------------------------------------------
   --  What was negotiated
   ---------------------------------------------------------------------------

   --  Settled during the handshake and read-only afterwards. This is what the
   --  connection metadata is built from, so everything an application may ask
   --  about a finished connection has to be here.
   type Negotiated is record
      Version      : SSL.Versions.Protocol_Version := SSL.Versions.TLS_1_3;
      Suite        : SSL.Cipher_Suites.Cipher_Suite :=
        SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256;
      Group        : SSL.Supported_Groups.Named_Group := SSL.Supported_Groups.X25519;
      Has_Group    : Boolean := False;
      Protocol     : SSL.ALPN.Protocol_Name := SSL.ALPN.No_Protocol;
      Has_Protocol : Boolean := False;
      Name         : SSL.Server_Names.DNS_Name := SSL.Server_Names.No_Name;
      Resumed      : Boolean := False;
      Peer_Authenticated : Boolean := False;
      Peer_Scheme  : SSL.Signature_Schemes.Signature_Scheme :=
        SSL.Signature_Schemes.Ed25519;
      Send_Limit   : Byte_Index := SSL.Limits.Protocol_Plaintext_Record_Limit;
      --  What the peer asked us to keep our records under (RFC 8449).
   end record;

   ---------------------------------------------------------------------------
   --  The handshake context
   ---------------------------------------------------------------------------

   --  The widest shared secret any supported group produces, which is the
   --  8192-bit finite-field group at 1024 octets -- except that this library
   --  offers nothing above ffdhe4096, so 512 is the real ceiling and is what
   --  SSL.Secrets can hold.
   Maximum_Shared_Secret : constant SSL.Secrets.Secret_Capacity :=
     SSL.Secrets.Maximum_Capacity;

   --  Everything both machines carry. Limited, because it holds a key schedule
   --  and a shared secret and neither may be copied. The ephemeral keypairs are
   --  not here: a client offers several and a server generates exactly one, so
   --  each machine owns its own and this type does not pretend they are the
   --  same shape.
   type Handshake_Context is limited record
      Transcript : SSL.Transcripts.Transcript;
      Schedule   : aliased SSL.Key_Schedule.Schedule;
      Shared     : SSL.Secrets.Secret (Maximum_Shared_Secret);
      Result     : Negotiated;

      --  Was a HelloRetryRequest exchanged? At most one is permitted, and the
      --  flag is what enforces "at most".
      Retried    : Boolean := False;

      --  Has the peer's Finished been verified? Nothing that depends on the
      --  peer being authenticated may happen before this.
      Peer_Finished_Verified : Boolean := False;
   end record;

   --  Scrub everything the context holds, in one place, so that a failure path
   --  cannot forget one of them.
   procedure Wipe (Item : in out Handshake_Context);

   --  Absorb one complete handshake message -- type octet, three-octet length
   --  and body -- into the transcript.
   --
   --  The exact octets, never a re-encoding. A message this endpoint received
   --  is absorbed as it arrived, and a message it sent is absorbed as it was
   --  written, because a canonical re-encoding that differed anywhere would
   --  produce a transcript the peer does not share and a Finished that verifies
   --  against nothing.
   procedure Absorb (Item : in out Handshake_Context; Message : Byte_Array)
     with Pre => Message'Length >= 4;

   ---------------------------------------------------------------------------
   --  Traffic keys
   ---------------------------------------------------------------------------

   --  Which end of the connection this machine is.
   type Endpoint_Role is (Client_Endpoint, Server_Endpoint);

   --  Whose secret a direction uses. Reading uses the peer's; writing uses our
   --  own. Getting this backwards produces a connection that decrypts nothing,
   --  which is the failure this function exists to have exactly one answer for.
   function Party_For
     (Role : Endpoint_Role; Reading : Boolean) return SSL.Key_Schedule.Party
   is (case Role is
          when Client_Endpoint =>
            (if Reading then SSL.Key_Schedule.Server_Side else SSL.Key_Schedule.Client_Side),
          when Server_Endpoint =>
            (if Reading then SSL.Key_Schedule.Client_Side else SSL.Key_Schedule.Server_Side));

   --  Derive and install one direction's traffic key for one epoch.
   --  @param Item  the context, whose schedule has reached the epoch's stage
   --  @param Role  which end this is
   --  @param Reading  True for the read direction
   --  @param Epoch which epoch's keys
   --  @param State in out: the traffic state to install into
   --  @param Error out: No_Error, or a derivation failure
   procedure Install_Traffic_Keys
     (Item    : Handshake_Context;
      Role    : Endpoint_Role;
      Reading : Boolean;
      Epoch   : SSL.Key_Schedule.Epoch;
      State   : in out SSL.Records.Traffic_State;
      Error   : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  The two verifications neither machine owns alone
   ---------------------------------------------------------------------------

   --  Verify a peer's CertificateVerify.
   --
   --  The transcript hash must be the one taken *before* the CertificateVerify
   --  was absorbed, which is why it is a parameter: taking it here would mean
   --  this subprogram had to know whether its caller had absorbed the message
   --  yet, and that is exactly the kind of ordering assumption that becomes a
   --  signature verified over the wrong octets.
   --  @param Signing_Role     whose signature this is
   --  @param Scheme           the scheme the peer named
   --  @param Public_Key       the peer's key, from its leaf certificate
   --  @param Transcript_Hash  the hash before the CertificateVerify
   --  @param Signature        the signature as it arrived
   --  @param Error            out: No_Error, or a verification failure
   procedure Verify_Peer_Signature
     (Signing_Role    : SSL.Handshake_Messages.Signing_Role;
      Scheme          : SSL.Signature_Schemes.Signature_Scheme;
      Public_Key      : Byte_Array;
      Transcript_Hash : Byte_Array;
      Signature       : Byte_Array;
      Error           : out SSL.Errors.Error_Information);

   --  Verify a peer's Finished, in constant time.
   --
   --  The comparison is constant-time and the transcript hash is again taken
   --  before the message was absorbed. A Finished that does not match ends the
   --  connection: there is no partial acceptance and no retry, because the only
   --  thing a mismatch can mean is that the two ends do not share a transcript.
   --  @param Item             the context, at Handshake_Stage
   --  @param Which            whose Finished
   --  @param Transcript_Hash  the hash before the Finished
   --  @param Verify_Data      the verify_data as it arrived
   --  @param Error            out: No_Error, or Code_Finished_Verification_Failed
   procedure Verify_Peer_Finished
     (Item            : Handshake_Context;
      Which           : SSL.Key_Schedule.Party;
      Transcript_Hash : Byte_Array;
      Verify_Data     : Byte_Array;
      Error           : out SSL.Errors.Error_Information);

   --  Write this endpoint's own Finished into a buffer and absorb it.
   --  @param Item    in out: the context; the message is absorbed
   --  @param Which   whose Finished this is
   --  @param Into    in out: the output buffer
   --  @param At_Offset where in it to start writing
   --  @param First   out: where the message begins
   --  @param Last    out: where it ends
   --  @param Error   out: No_Error, or a derivation or buffer failure
   procedure Write_Finished
     (Item      : in out Handshake_Context;
      Which     : SSL.Key_Schedule.Party;
      Into      : in out Byte_Array;
      At_Offset : Byte_Index;
      First     : out Byte_Index;
      Last      : out Byte_Index;
      Error     : out SSL.Errors.Error_Information);

   ---------------------------------------------------------------------------
   --  Plan construction
   ---------------------------------------------------------------------------

   --  Append a step. A plan that would overflow is a programming error in this
   --  library, not a peer-induced condition, so it raises rather than
   --  returning a failure: no flight in TLS 1.3 has sixteen steps, and one that
   --  did would mean the machine had lost track of where it was.
   procedure Add
     (Item  : in out Plan;
      Kind  : Step_Kind;
      First : Byte_Index := 1;
      Last  : Byte_Index := 0)
     with Pre => Item.Count < Maximum_Steps;

end SSL.TLS13;
