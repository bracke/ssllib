with Ada.Streams;
with Interfaces;

with SSL.ALPN;
with SSL.Cipher_Suites;
with SSL.Crypto;
with SSL.Server_Names;
with SSL.Versions;
with SSL.Wire;

package body SSL.Ticket_Keys is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Interfaces.Unsigned_64;

   --  The format's own version, authenticated as part of the header.
   --  Two, not one: version one had no protocol version in the body, so every
   --  session it carried was read back as TLS 1.3. The number is authenticated
   --  along with everything else, so a ticket in the old format is refused
   --  rather than misread -- which costs one full handshake per outstanding
   --  ticket and nothing else.
   Format_Version : constant Byte := 2;

   --  Which protocol this ticket is for. TLS 1.2 tickets, when they exist, get
   --  their own value, so that one can never be presented as the other.
   Family_TLS_1_3 : constant Byte := 1;

   --  What the ticket is for. One value today; present so that a future ticket
   --  with another purpose cannot be accepted as a resumption ticket.
   Purpose_Resumption : constant Byte := 1;

   --  Fixed rather than negotiated: a ticket is not a negotiation, and letting
   --  the format carry an algorithm identifier would let a peer choose it.
   Ticket_AEAD : constant SSL.Cipher_Suites.AEAD_Algorithm := SSL.Cipher_Suites.AES_256_GCM;

   Key_Material_Length : constant Byte_Index := 32;
   Tag_Length          : constant Byte_Index := 16;

   --  Format version, family, purpose, key identifier, nonce. Everything a
   --  server needs in order to decide *which key* to try, and nothing that
   --  would tell an observer anything about the session.
   Header_Length : constant Byte_Index := 1 + 1 + 1 + Identifier_Length + 12;

   ---------------------------------------------------------------------------
   --  The ring
   ---------------------------------------------------------------------------

   function Has_Active_Key (Item : Ring) return Boolean is
   begin
      for Index in 1 .. Item.Count loop
         if Item.Keys (Index).State = Active then
            return True;
         end if;
      end loop;
      return False;
   end Has_Active_Key;

   function Key_Count (Item : Ring) return Natural is (Item.Count);

   --  Demote whatever is issuing. Its tickets must keep opening, so it becomes
   --  Decrypt_Only rather than Retired: a rotation that cut off every
   --  outstanding ticket at once would turn a routine operation into a
   --  thundering herd of full handshakes.
   procedure Demote_Active (Item : in out Ring);

   procedure Demote_Active (Item : in out Ring) is
   begin
      for Index in 1 .. Item.Count loop
         if Item.Keys (Index).State = Active then
            Item.Keys (Index).State := Decrypt_Only;
         end if;
      end loop;
   end Demote_Active;

   --  Make room for one more key, retiring the oldest if the ring is full.
   --
   --  Retiring rather than refusing: a server that could not rotate because its
   --  ring was full would keep issuing under an old key indefinitely, which is
   --  worse than losing the ability to open the oldest outstanding tickets.
   procedure Make_Room (Item : in out Ring; Slot : out Natural);

   procedure Make_Room (Item : in out Ring; Slot : out Natural) is
   begin
      for Index in 1 .. Item.Count loop
         if Item.Keys (Index).State = Retired then
            Slot := Index;
            SSL.Secrets.Wipe (Item.Keys (Index).Material);
            return;
         end if;
      end loop;

      if Item.Count < Maximum_Keys then
         Item.Count := Item.Count + 1;
         Slot := Item.Count;
         return;
      end if;

      --  Full and none retired: the oldest goes. Slot one is the oldest,
      --  because this shifts the ring down and keeps that fact in one place.
      SSL.Secrets.Wipe (Item.Keys (1).Material);
      for Index in 1 .. Maximum_Keys - 1 loop
         Item.Keys (Index).State := Item.Keys (Index + 1).State;
         Item.Keys (Index).Identifier := Item.Keys (Index + 1).Identifier;
         Item.Keys (Index).Lifetime := Item.Keys (Index + 1).Lifetime;
         SSL.Secrets.Copy (Item.Keys (Index).Material, Item.Keys (Index + 1).Material);
      end loop;
      Slot := Maximum_Keys;
      SSL.Secrets.Wipe (Item.Keys (Slot).Material);
   end Make_Room;

   procedure Rotate
     (Item     : in out Ring;
      Lifetime : Natural := Default_Lifetime;
      Now      : SSL.Clocks.Wall_Time := SSL.Clocks.Current_UTC;
      Error    : out SSL.Errors.Error_Information)
   is
      pragma Unreferenced (Now);

      Source   : SSL.Crypto.Random_Source;
      Material : Byte_Array (1 .. Key_Material_Length) := [others => 0];
      Name     : Byte_Array (1 .. Identifier_Length) := [others => 0];
      Slot     : Natural;
   begin
      Error := SSL.Errors.No_Error;

      --  System entropy, and only here. A ticket key generated from anything
      --  weaker would be a ticket key an attacker could guess, and every
      --  session resumable under it would go with it.
      SSL.Crypto.Use_System_Entropy (Source);

      SSL.Crypto.Fill (Source, Material, Error);
      if SSL.Errors.Is_Error (Error) then
         SSL.Crypto.Scrub (Material);
         return;
      end if;

      --  Random rather than a counter. A counter would tell an observer how
      --  many times this server had rotated, which is a small leak and an
      --  entirely avoidable one.
      SSL.Crypto.Fill (Source, Name, Error);
      if SSL.Errors.Is_Error (Error) then
         SSL.Crypto.Scrub (Material);
         return;
      end if;

      Demote_Active (Item);
      Make_Room (Item, Slot);

      Item.Keys (Slot).State := Active;
      Item.Keys (Slot).Identifier := Name;
      Item.Keys (Slot).Lifetime := Lifetime;
      SSL.Secrets.Set (Item.Keys (Slot).Material, Material);

      --  The copy in this frame has done its work. Scrubbed here rather than
      --  left to fall out of scope, because an ordinary local going out of
      --  scope is not an erasure.
      SSL.Crypto.Scrub (Material);
   end Rotate;

   procedure Install
     (Item       : in out Ring;
      Identifier : Byte_Array;
      Material   : Byte_Array;
      Lifetime   : Natural := Default_Lifetime;
      Now        : SSL.Clocks.Wall_Time := SSL.Clocks.Current_UTC;
      Error      : out SSL.Errors.Error_Information)
   is
      pragma Unreferenced (Now);

      Slot : Natural;
   begin
      Error := SSL.Errors.No_Error;

      for Index in 1 .. Item.Count loop
         if Item.Keys (Index).Identifier = Identifier then
            --  Two keys with one name would make "which key opened this
            --  ticket" ambiguous, and the answer decides whether it is
            --  accepted.
            Error := SSL.Errors.Make
              (SSL.Errors.Code_Ticket_Unknown_Key, SSL.Errors.Local_Policy);
            return;
         end if;
      end loop;

      Demote_Active (Item);
      Make_Room (Item, Slot);

      Item.Keys (Slot).State := Active;
      Item.Keys (Slot).Identifier := Identifier;
      Item.Keys (Slot).Lifetime := Lifetime;
      SSL.Secrets.Set (Item.Keys (Slot).Material, Material);
   end Install;

   procedure Wipe (Item : in out Ring) is
   begin
      for Index in Item.Keys'Range loop
         SSL.Secrets.Wipe (Item.Keys (Index).Material);
         Item.Keys (Index).State := Retired;
         Item.Keys (Index).Identifier := [others => 0];
      end loop;
      Item.Count := 0;
   end Wipe;

   ---------------------------------------------------------------------------
   --  The sealed body
   ---------------------------------------------------------------------------

   --  Two instants, the bindings, and the resumption secret with its length.
   Body_Length : constant Byte_Index :=
     8 + 8            --  issued, expires
     + 2              --  suite
     + 32 + 32        --  configuration and trust fingerprints
     + 1 + 64         --  security context label
     + 1 + 255        --  protocol
     + 1 + 255        --  server name
     + 1              --  peer authenticated
     + 1 + 64;        --  resumption secret

   --  Write the body, field by field and never as a record: a record's layout
   --  is the compiler's decision, and a ticket outlives the process that wrote
   --  it.
   procedure Encode_Body
     (Value   : SSL.Sessions.Session;
      Into    : out Byte_Array;
      Written : out Byte_Index);

   procedure Encode_Body
     (Value   : SSL.Sessions.Session;
      Into    : out Byte_Array;
      Written : out Byte_Index)
   is
      Emitter : SSL.Wire.Emitter;

      procedure Put_Text (Text : String);

      procedure Put_Text (Text : String) is
      begin
         SSL.Wire.Put_UInt8 (Into, Emitter, Text'Length);
         for Character_Item of Text loop
            SSL.Wire.Put_UInt8 (Into, Emitter, Character'Pos (Character_Item));
         end loop;
      end Put_Text;

      Secret : Byte_Array (1 .. 64) := [others => 0];
      Length : Byte_Index;
   begin
      Into := [others => 0];
      Emitter := SSL.Wire.Writer (Into);

      SSL.Wire.Put_UInt64
        (Into, Emitter, SSL.Clocks.Seconds_Since_Epoch (SSL.Sessions.Issued (Value)));
      SSL.Wire.Put_UInt64
        (Into, Emitter, SSL.Clocks.Seconds_Since_Epoch (SSL.Sessions.Expires (Value)));

      --  The protocol version, written down rather than assumed. It was
      --  assumed once -- every sealed session was a TLS 1.3 one -- and the
      --  assumption survived into a release where it was no longer true: a
      --  TLS 1.2 session came back out of its own ticket claiming to be
      --  TLS 1.3, and the server declined every resumption it had just issued.
      SSL.Wire.Put_UInt16
        (Into, Emitter, Natural (SSL.Versions.Value_Of (SSL.Sessions.Version (Value))));

      SSL.Wire.Put_UInt16
        (Into, Emitter,
         Natural (SSL.Cipher_Suites.Value_Of (SSL.Sessions.Cipher_Suite (Value))));

      SSL.Wire.Put_Bytes (Into, Emitter, Digest_Of (SSL.Sessions.Configuration (Value)));
      SSL.Wire.Put_Bytes (Into, Emitter, Digest_Of (SSL.Sessions.Trust (Value)));
      Put_Text (Label_Of (SSL.Sessions.Security_Context (Value)));

      if SSL.Sessions.Has_Protocol (Value) then
         declare
            Name : constant Byte_Array :=
              SSL.ALPN.Value_Of (SSL.Sessions.Protocol (Value));
         begin
            SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Name'Length));
            SSL.Wire.Put_Bytes (Into, Emitter, Name);
         end;
      else
         SSL.Wire.Put_UInt8 (Into, Emitter, 0);
      end if;

      Put_Text
        (if SSL.Server_Names.Is_Present (SSL.Sessions.Server_Name (Value))
         then SSL.Server_Names.Image (SSL.Sessions.Server_Name (Value))
         else "");

      SSL.Wire.Put_UInt8
        (Into, Emitter, (if SSL.Sessions.Peer_Authenticated (Value) then 1 else 0));

      SSL.Sessions.Get_Secret (Value, Secret, Length);
      SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Length));
      SSL.Wire.Put_Bytes (Into, Emitter, Secret (1 .. Length));
      SSL.Crypto.Scrub (Secret);

      Written := (if SSL.Wire.Is_Valid (Emitter) then SSL.Wire.Written (Emitter) else 0);
   end Encode_Body;

   --  Read the body back. Only ever reached with octets the AEAD has already
   --  authenticated, which is why it can be this direct: nothing here is
   --  parsing attacker-chosen input.
   procedure Decode_Body
     (Data : Byte_Array;
      Into : in out SSL.Sessions.Session;
      Ok   : out Boolean);

   procedure Decode_Body
     (Data : Byte_Array;
      Into : in out SSL.Sessions.Session;
      Ok   : out Boolean)
   is
      use type SSL.Versions.Protocol_Version;

      Cursor : SSL.Wire.Cursor := SSL.Wire.Reader (Data);
      Number : Interfaces.Unsigned_64;
      Value  : Natural;
      Length : Natural;

      Issued  : SSL.Clocks.Wall_Time;
      Expires : SSL.Clocks.Wall_Time;
      Version : SSL.Versions.Protocol_Version;
      Suite   : SSL.Cipher_Suites.Cipher_Suite;
      Setup   : Configuration_Fingerprint;
      Anchors : Trust_Fingerprint;
      Context : Security_Context_ID := Default_Security_Context;

      Protocol      : SSL.ALPN.Protocol_Name := SSL.ALPN.No_Protocol;
      Has_Protocol  : Boolean := False;
      Name          : SSL.Server_Names.DNS_Name := SSL.Server_Names.No_Name;
      Authenticated : Boolean := False;

      procedure Get_Text (Limit : Natural; Text : out String; Taken : out Natural);

      procedure Get_Text (Limit : Natural; Text : out String; Taken : out Natural) is
         Octet : Natural;
      begin
         Text := [others => ' '];
         Taken := 0;
         SSL.Wire.Get_UInt8 (Data, Cursor, Length);
         if not SSL.Wire.Is_Valid (Cursor) or else Length > Limit then
            return;
         end if;
         for Index in 1 .. Length loop
            SSL.Wire.Get_UInt8 (Data, Cursor, Octet);
            Text (Text'First + Index - 1) := Character'Val (Octet);
         end loop;
         Taken := Length;
      end Get_Text;
   begin
      Ok := False;

      SSL.Wire.Get_UInt64 (Data, Cursor, Number);
      Issued := SSL.Clocks.From_Seconds_Since_Epoch (Number);
      SSL.Wire.Get_UInt64 (Data, Cursor, Number);
      Expires := SSL.Clocks.From_Seconds_Since_Epoch (Number);

      SSL.Wire.Get_UInt16 (Data, Cursor, Value);
      if not SSL.Versions.Version_For (SSL.Versions.Version_Value (Value), Version) then
         return;
      end if;

      SSL.Wire.Get_UInt16 (Data, Cursor, Value);
      if not SSL.Cipher_Suites.Suite_For (SSL.Cipher_Suites.Suite_Value (Value), Suite) then
         return;
      end if;

      --  The suite has to belong to the version. A ticket claiming a TLS 1.3
      --  suite under TLS 1.2 could only come from this server's own key, but
      --  it would still be a session no handshake could use, and the place to
      --  find that out is here rather than three messages later.
      if SSL.Cipher_Suites.Version_Of (Suite) /= Version then
         return;
      end if;

      declare
         Digest : Byte_Array (1 .. 32) := [others => 0];
      begin
         SSL.Wire.Get_Bytes (Data, Cursor, Digest);
         Setup := Configuration_From_Digest (Digest);
         SSL.Wire.Get_Bytes (Data, Cursor, Digest);
         Anchors := Trust_From_Digest (Digest);
      end;

      declare
         Label : String (1 .. 64);
         Taken : Natural;
      begin
         Get_Text (64, Label, Taken);
         if not SSL.Wire.Is_Valid (Cursor) then
            return;
         end if;
         Context := Security_Context (Label (1 .. Taken));
      end;

      SSL.Wire.Get_UInt8 (Data, Cursor, Length);
      if not SSL.Wire.Is_Valid (Cursor) or else Length > 255 then
         return;
      end if;
      if Length > 0 then
         declare
            Octets : Byte_Array (1 .. Byte_Index (Length)) := [others => 0];
         begin
            SSL.Wire.Get_Bytes (Data, Cursor, Octets);
            Has_Protocol := SSL.ALPN.Make (Octets, Protocol);
            if not Has_Protocol then
               return;
            end if;
         end;
      end if;

      declare
         Text   : String (1 .. 255);
         Taken  : Natural;
         Status : SSL.Server_Names.Name_Status;
      begin
         Get_Text (255, Text, Taken);
         if not SSL.Wire.Is_Valid (Cursor) then
            return;
         end if;
         if Taken > 0 then
            SSL.Server_Names.Parse (Text (1 .. Taken), Name, Status);
         end if;
      end;

      SSL.Wire.Get_UInt8 (Data, Cursor, Value);
      Authenticated := Value /= 0;

      SSL.Wire.Get_UInt8 (Data, Cursor, Length);
      if not SSL.Wire.Is_Valid (Cursor) or else Length = 0 or else Length > 64 then
         return;
      end if;

      declare
         Secret : Byte_Array (1 .. Byte_Index (Length)) := [others => 0];
         Local  : SSL.Errors.Error_Information;
      begin
         SSL.Wire.Get_Bytes (Data, Cursor, Secret);
         if not SSL.Wire.Is_Valid (Cursor) then
            SSL.Crypto.Scrub (Secret);
            return;
         end if;

         --  Rebuilt with the difference between the two instants, because a
         --  session is stored with a lifetime rather than an expiry and the two
         --  must not drift apart.
         SSL.Sessions.Store
           (Item          => Into,
            Version       => Version,
            Suite         => Suite,
            Name          => Name,
            Protocol      => Protocol,
            Has_Protocol  => Has_Protocol,
            Issued        => Issued,
            Lifetime      =>
              Natural (SSL.Clocks.Seconds_Since_Epoch (Expires)
                       - SSL.Clocks.Seconds_Since_Epoch (Issued)),
            Context       => Context,
            Setup         => Setup,
            Anchors       => Anchors,
            Authenticated => Authenticated,
            Ticket_Bytes  => [1 => 0],
            Age_Add       => 0,
            Nonce_Bytes   => Empty_Bytes,
            Secret        => Secret,
            Error         => Local);
         SSL.Crypto.Scrub (Secret);
         Ok := not SSL.Errors.Is_Error (Local);
      end;
   end Decode_Body;

   ---------------------------------------------------------------------------
   --  Sealing and opening
   ---------------------------------------------------------------------------

   procedure Seal
     (Item    : Ring;
      Value   : SSL.Sessions.Session;
      Into    : out Byte_Array;
      Written : out Byte_Index;
      Error   : out SSL.Errors.Error_Information)
   is
      Slot   : Natural := 0;
      Source : SSL.Crypto.Random_Source;
   begin
      Into := [others => 0];
      Written := 0;
      Error := SSL.Errors.No_Error;

      for Index in 1 .. Item.Count loop
         if Item.Keys (Index).State = Active then
            Slot := Index;
         end if;
      end loop;

      if Slot = 0 then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Ticket_Key_Not_Active, SSL.Errors.Local_Policy);
         return;
      end if;

      SSL.Crypto.Use_System_Entropy (Source);

      declare
         Nonce  : Byte_Array (1 .. 12) := [others => 0];
         Header : Byte_Array (1 .. Header_Length) := [others => 0];
         Plain  : Byte_Array (1 .. Body_Length) := [others => 0];
         Filled : Byte_Index;
         Local  : SSL.Errors.Error_Information;
      begin
         SSL.Crypto.Fill (Source, Nonce, Local);
         if SSL.Errors.Is_Error (Local) then
            Error := Local;
            return;
         end if;

         Header (1) := Format_Version;
         Header (2) := Family_TLS_1_3;
         Header (3) := Purpose_Resumption;
         Header (4 .. 3 + Identifier_Length) := Item.Keys (Slot).Identifier;
         Header (4 + Identifier_Length .. Header_Length) := Nonce;

         Encode_Body (Value, Plain, Filled);
         if Filled = 0 or else Header_Length + Filled + Tag_Length > Into'Length then
            SSL.Crypto.Scrub (Plain);
            Error := SSL.Errors.Make
              (SSL.Errors.Code_Ticket_Malformed, SSL.Errors.Local_Implementation);
            return;
         end if;

         declare
            Sealed : Byte_Array (1 .. Filled + Tag_Length) := [others => 0];
         begin
            --  The header is the additional data, so a peer that altered the
            --  version, the family, the purpose or the key identifier would
            --  produce a ticket that no longer authenticates.
            SSL.Crypto.Seal
              (Algorithm  => Ticket_AEAD,
               Key        => Item.Keys (Slot).Material,
               Nonce      => Nonce,
               Additional => Header,
               Plaintext  => Plain (1 .. Filled),
               Wire       => Sealed,
               Error      => Local);
            SSL.Crypto.Scrub (Plain);

            if SSL.Errors.Is_Error (Local) then
               Error := Local;
               return;
            end if;

            Into (Into'First .. Into'First + Header_Length - 1) := Header;
            Into (Into'First + Header_Length
                  .. Into'First + Header_Length + Sealed'Length - 1) := Sealed;
            Written := Header_Length + Sealed'Length;
         end;
      end;
   end Seal;

   procedure Open
     (Item   : Ring;
      Ticket : Byte_Array;
      Now    : SSL.Clocks.Wall_Time;
      Into   : in out SSL.Sessions.Session;
      Usable : out Boolean;
      Error  : out SSL.Errors.Error_Information)
   is
      --  One refusal for every reason. Unknown key, wrong version, bad tag,
      --  expired -- a server whose answers differed between them would be an
      --  oracle for probing its key rotation, and none of the differences is
      --  something a legitimate client could act on.
      procedure Refuse;

      procedure Refuse is
      begin
         SSL.Sessions.Wipe (Into);
         Usable := False;
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Ticket_Malformed, SSL.Errors.Peer_Message);
      end Refuse;

      Slot : Natural := 0;
   begin
      Usable := False;
      Error := SSL.Errors.No_Error;

      if Ticket'Length <= Header_Length + Tag_Length
        or else Ticket'Length > Maximum_Ticket
      then
         Refuse;
         return;
      end if;

      declare
         Header : constant Byte_Array (1 .. Header_Length) :=
           Ticket (Ticket'First .. Ticket'First + Header_Length - 1);
         Name   : constant Byte_Array (1 .. Identifier_Length) :=
           Header (4 .. 3 + Identifier_Length);
         Nonce  : constant Byte_Array (1 .. 12) :=
           Header (4 + Identifier_Length .. Header_Length);
         Sealed : constant Byte_Array :=
           Ticket (Ticket'First + Header_Length .. Ticket'Last);
      begin
         if Header (1) /= Format_Version
           or else Header (2) /= Family_TLS_1_3
           or else Header (3) /= Purpose_Resumption
         then
            Refuse;
            return;
         end if;

         --  A retired key is not tried at all: retaining the ability to open
         --  its tickets is exactly what retirement withdraws.
         for Index in 1 .. Item.Count loop
            if Item.Keys (Index).State in Active | Decrypt_Only
              and then Item.Keys (Index).Identifier = Name
            then
               Slot := Index;
            end if;
         end loop;

         if Slot = 0 then
            Refuse;
            return;
         end if;

         declare
            Plain : Byte_Array (1 .. Sealed'Length - Tag_Length) := [others => 0];
            Local : SSL.Errors.Error_Information;
            Ok    : Boolean;
         begin
            --  Authenticated before anything is parsed.
            SSL.Crypto.Open
              (Algorithm  => Ticket_AEAD,
               Key        => Item.Keys (Slot).Material,
               Nonce      => Nonce,
               Additional => Header,
               Wire       => Sealed,
               Plaintext  => Plain,
               Error      => Local);

            if SSL.Errors.Is_Error (Local) then
               SSL.Crypto.Scrub (Plain);
               Refuse;
               return;
            end if;

            Decode_Body (Plain, Into, Ok);
            SSL.Crypto.Scrub (Plain);

            if not Ok then
               Refuse;
               return;
            end if;
         end;

         --  Expiry last, so that a ticket failing it has been through the same
         --  work as one that passes.
         if not SSL.Sessions.Is_Live (Into, Now) then
            Refuse;
            return;
         end if;

         Usable := True;
      end;
   end Open;

end SSL.Ticket_Keys;
