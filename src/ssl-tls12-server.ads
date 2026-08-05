with SSL.Certificate_Validation;
with SSL.Cipher_Suites;
with SSL.Clocks;
with SSL.Configurations;
with SSL.Crypto;
with SSL.Errors;
with SSL.Handshake_Messages;
with SSL.Limits;
with SSL.Secrets;
with SSL.Server_Names;
with SSL.Sessions;
with SSL.Signature_Schemes;
with SSL.Supported_Groups;
with SSL.Ticket_Keys;
with SSL.Transcripts;

with SSL.ALPN;

--  @summary The restricted TLS 1.2 server handshake, as an explicit state
--  machine.
--
--  The mirror of `SSL.TLS12.Client`, and separate from the TLS 1.3 server for
--  the same reasons. What it insists on is the same list: ECDHE, AEAD,
--  extended master secret, null compression, no renegotiation. A client that
--  cannot meet those terms gets a failed handshake with a named reason.
--
--  One thing worth stating that is easy to miss: this server **signs the
--  ephemeral parameters**, not the transcript. That is the TLS 1.2 design, and
--  it is why the signed content is assembled from the two randoms and the exact
--  parameter octets rather than from a hash of everything so far. A server that
--  signed something else would produce a handshake no client completes; a
--  client that verified something else would accept a substituted share.
package SSL.TLS12.Server is

   type Server_State is
     (Start,
      Received_Client_Hello,
      Wait_Client_Key_Exchange,
      Wait_Client_Change_Cipher_Spec,
      Wait_Client_Finished,
      Connected,
      Failed);

   function Image (Item : Server_State) return String;

   type Machine is limited private;

   function State_Of (Item : Machine) return Server_State;
   function Is_Complete (Item : Machine) return Boolean;

   function Cipher_Suite (Item : Machine) return SSL.Cipher_Suites.Cipher_Suite;
   function Group (Item : Machine) return SSL.Supported_Groups.Named_Group;
   function Server_Name (Item : Machine) return SSL.Server_Names.DNS_Name;

   --  The application protocol that was negotiated, if any. Reported so that a
   --  finished TLS 1.2 connection can say what it agreed to rather than saying
   --  nothing, which is what it used to say.
   function Has_Protocol (Item : Machine) return Boolean;
   function Protocol (Item : Machine) return SSL.ALPN.Protocol_Name
     with Pre => Has_Protocol (Item);

   function Client_Keys (Item : aliased Machine) return access constant Direction_Keys;
   function Server_Keys (Item : aliased Machine) return access constant Direction_Keys;

   --  Did this handshake resume a session rather than establish one?
   function Resumed (Item : Machine) return Boolean;

   ---------------------------------------------------------------------------
   --  Tickets (RFC 5077)
   ---------------------------------------------------------------------------

   --  The keys tickets are sealed under.
   --
   --  Without a ring this server issues nothing and accepts nothing, which is
   --  the specified "tickets disabled until valid ticket keys are configured":
   --  a server that issued tickets under a key it invented would be a server
   --  whose tickets survive nothing, including its own restart.
   procedure Set_Ticket_Keys
     (Item  : in out Machine;
      Value : SSL.Ticket_Keys.Ring_Reference)
     with Pre => State_Of (Item) = Start;

   --  Whether to issue tickets at all. Separate from having a ring, because a
   --  server may need to open the tickets it has already issued while it stops
   --  issuing new ones.
   procedure Set_Issues_Tickets (Item : in out Machine; Value : Boolean)
     with Pre => State_Of (Item) = Start;

   --  Prepare the machine. A server says nothing until it hears a ClientHello.
   procedure Begin_Handshake
     (Item   : in out Machine;
      Config : not null access constant SSL.Configurations.Server_Configuration;
      Now    : SSL.Clocks.Wall_Time;
      Error  : out SSL.Errors.Error_Information)
     with Pre => State_Of (Item) = Start;

   procedure Handle_Message
     (Item    : in out Machine;
      Message : Byte_Array;
      Source  : in out SSL.Crypto.Random_Source;
      Into    : in out Byte_Array;
      Result  : out Plan;
      Error   : out SSL.Errors.Error_Information)
     with Pre => State_Of (Item) not in Start | Failed;

   procedure Handle_Change_Cipher_Spec
     (Item   : in out Machine;
      Result : out Plan;
      Error  : out SSL.Errors.Error_Information);

   procedure Wipe (Item : in out Machine);

private

   type Machine is limited record
      Config : access constant SSL.Configurations.Server_Configuration;
      Now    : SSL.Clocks.Wall_Time := SSL.Clocks.No_Wall_Time;
      Bounds : SSL.Limits.Resource_Limits := SSL.Limits.Default_Limits;
      State  : Server_State := Start;

      Transcript : SSL.Transcripts.Transcript;

      Suite : SSL.Cipher_Suites.Cipher_Suite :=
        SSL.Cipher_Suites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
      Named : SSL.Supported_Groups.Named_Group := SSL.Supported_Groups.Secp256r1;
      Name  : SSL.Server_Names.DNS_Name := SSL.Server_Names.No_Name;

      Protocol     : SSL.ALPN.Protocol_Name := SSL.ALPN.No_Protocol;
      Has_Protocol : Boolean := False;
      Scheme       : SSL.Signature_Schemes.Signature_Scheme :=
        SSL.Signature_Schemes.ECDSA_Secp256r1_SHA256;

      Client_Random : SSL.Handshake_Messages.Random_Bytes := [others => 0];
      Server_Random : SSL.Handshake_Messages.Random_Bytes := [others => 0];

      Echo_Length : Byte_Index range 0 .. 32 := 0;
      Echo        : Byte_Array (1 .. 32) := [others => 0];

      Credential_Index : Natural := 0;

      Exchange : SSL.Crypto.Key_Exchange_Pair;
      Shared   : SSL.Secrets.Secret (SSL.Secrets.Agreement_Capacity);
      Master   : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);

      Write_Keys : aliased Direction_Keys;
      Read_Keys  : aliased Direction_Keys;

      Peer : SSL.Certificate_Validation.Validation_Result;

      --  RFC 5077.
      Ring       : SSL.Ticket_Keys.Ring_Reference;
      Issues     : Boolean := False;
      Is_Resumed : Boolean := False;

      --  Set when the client asked for a ticket and this server intends to
      --  send one. Two facts rather than one, because the ServerHello has to
      --  promise the ticket several messages before the ticket is built.
      Will_Issue : Boolean := False;

      --  The session recovered from an offered ticket. Live only for the span
      --  of the hello that carried it.
      Offered : SSL.Sessions.Session;
   end record;

   function State_Of (Item : Machine) return Server_State is (Item.State);
   function Is_Complete (Item : Machine) return Boolean is (Item.State = Connected);
   function Cipher_Suite (Item : Machine) return SSL.Cipher_Suites.Cipher_Suite is
     (Item.Suite);
   function Group (Item : Machine) return SSL.Supported_Groups.Named_Group is (Item.Named);
   function Server_Name (Item : Machine) return SSL.Server_Names.DNS_Name is (Item.Name);
   function Has_Protocol (Item : Machine) return Boolean is (Item.Has_Protocol);
   function Protocol (Item : Machine) return SSL.ALPN.Protocol_Name is (Item.Protocol);
   function Resumed (Item : Machine) return Boolean is (Item.Is_Resumed);

end SSL.TLS12.Server;
