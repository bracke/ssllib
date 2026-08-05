package body SSL.TLS13 is

   package Schedules renames SSL.Key_Schedule;

   ----------------
   -- Wipe --
   ----------------

   procedure Wipe (Item : in out Handshake_Context) is
   begin
      Schedules.Wipe (Item.Schedule);
      Item.Shared.Wipe;
      SSL.Transcripts.Start (Item.Transcript);
      Item.Peer_Finished_Verified := False;
   end Wipe;

   ------------------
   -- Absorb --
   ------------------

   procedure Absorb (Item : in out Handshake_Context; Message : Byte_Array) is
   begin
      SSL.Transcripts.Absorb (Item.Transcript, Message);
   end Absorb;

   ----------------
   -- Add --
   ----------------

   procedure Add
     (Item  : in out Plan;
      Kind  : Step_Kind;
      First : Byte_Index := 1;
      Last  : Byte_Index := 0)
   is
   begin
      Item.Count := Item.Count + 1;
      Item.Steps (Item.Count) := (Kind => Kind, First => First, Last => Last);
   end Add;

   ---------------------------------
   -- Install_Traffic_Keys --
   ---------------------------------

   procedure Install_Traffic_Keys
     (Item    : Handshake_Context;
      Role    : Endpoint_Role;
      Reading : Boolean;
      Epoch   : Schedules.Epoch;
      State   : in out SSL.Records.Traffic_State;
      Error   : out SSL.Errors.Error_Information)
   is
      Suite : constant SSL.Cipher_Suites.Cipher_Suite := Schedules.Suite_Of (Item.Schedule);
      Width : constant Byte_Index :=
        SSL.Cipher_Suites.Key_Length (SSL.Cipher_Suites.AEAD_Of (Suite));

      Which : constant Schedules.Party := Party_For (Role, Reading);

      Key : Byte_Array (1 .. Width) := [others => 0];
      IV  : Byte_Array (1 .. 12) := [others => 0];
   begin
      Schedules.Traffic_Key (Item.Schedule, Which, Epoch, Key, IV, Error);
      if SSL.Errors.Is_Error (Error) then
         SSL.Crypto.Scrub (Key);
         SSL.Crypto.Scrub (IV);
         return;
      end if;

      SSL.Records.Install
        (Item       => State,
         Suite      => Suite,
         Key        => Key,
         IV         => IV,
         Generation => Schedules.Generation (Item.Schedule, Which));

      --  The key is in the traffic state now and this copy has no further
      --  purpose. It is scrubbed here rather than left to fall out of scope,
      --  because an ordinary local going out of scope is not an erasure.
      SSL.Crypto.Scrub (Key);
      SSL.Crypto.Scrub (IV);
   end Install_Traffic_Keys;

   ----------------------------------
   -- Verify_Peer_Signature --
   ----------------------------------

   procedure Verify_Peer_Signature
     (Signing_Role    : SSL.Handshake_Messages.Signing_Role;
      Scheme          : SSL.Signature_Schemes.Signature_Scheme;
      Public_Key      : Byte_Array;
      Transcript_Hash : Byte_Array;
      Signature       : Byte_Array;
      Error           : out SSL.Errors.Error_Information)
   is
      Content : constant Byte_Array :=
        SSL.Handshake_Messages.Certificate_Verify_Content (Signing_Role, Transcript_Hash);
   begin
      SSL.Crypto.Verify_Signature
        (Scheme      => Scheme,
         Public_Key  => Public_Key,
         Signed_Data => Content,
         Signature   => Signature,
         Error       => Error);

      if SSL.Errors.Is_Error (Error) then
         --  Reported as a CertificateVerify failure rather than as a generic
         --  signature failure, because those are different events: one means a
         --  peer could not prove it holds the key its certificate names, and
         --  the other could be anything in the path.
         Error := SSL.Errors.Make
           (Code   => SSL.Errors.Code_Certificate_Verify_Failed,
            Origin => SSL.Errors.Peer_Message);
      end if;
   end Verify_Peer_Signature;

   ---------------------------------
   -- Verify_Peer_Finished --
   ---------------------------------

   procedure Verify_Peer_Finished
     (Item            : Handshake_Context;
      Which           : Schedules.Party;
      Transcript_Hash : Byte_Array;
      Verify_Data     : Byte_Array;
      Error           : out SSL.Errors.Error_Information)
   is
      Width    : constant Byte_Index := Schedules.Digest_Width (Item.Schedule);
      Expected : Byte_Array (1 .. Width) := [others => 0];
      Matches  : Boolean;
   begin
      if Verify_Data'Length /= Width or else Transcript_Hash'Length /= Width then
         --  A Finished of the wrong length cannot match, and saying so before
         --  computing anything avoids a comparison over mismatched lengths.
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Finished_Verification_Failed, SSL.Errors.Peer_Message);
         return;
      end if;

      Schedules.Compute_Finished (Item.Schedule, Which, Transcript_Hash, Expected, Error);
      if SSL.Errors.Is_Error (Error) then
         SSL.Crypto.Scrub (Expected);
         return;
      end if;

      Matches := SSL.Crypto.Equal (Expected, Verify_Data);
      SSL.Crypto.Scrub (Expected);

      if not Matches then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Finished_Verification_Failed, SSL.Errors.Peer_Message);
      end if;
   end Verify_Peer_Finished;

   --------------------------
   -- Write_Finished --
   --------------------------

   procedure Write_Finished
     (Item      : in out Handshake_Context;
      Which     : Schedules.Party;
      Into      : in out Byte_Array;
      At_Offset : Byte_Index;
      First     : out Byte_Index;
      Last      : out Byte_Index;
      Error     : out SSL.Errors.Error_Information)
   is
      Width  : constant Byte_Index := Schedules.Digest_Width (Item.Schedule);
      Digest : Byte_Array (1 .. Width) := [others => 0];
      Verify : Byte_Array (1 .. Width) := [others => 0];
      Length : Byte_Index;
   begin
      First := At_Offset;
      Last := At_Offset - 1;

      if At_Offset > Into'Last then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Local_Implementation);
         return;
      end if;

      SSL.Transcripts.Hash (Item.Transcript, Digest);
      Schedules.Compute_Finished (Item.Schedule, Which, Digest, Verify, Error);
      SSL.Crypto.Scrub (Digest);
      if SSL.Errors.Is_Error (Error) then
         SSL.Crypto.Scrub (Verify);
         return;
      end if;

      declare
         Region : Byte_Array (1 .. Into'Last - At_Offset + 1);
      begin
         SSL.Handshake_Messages.Encode_Finished (Verify, Region, Length, Error);
         SSL.Crypto.Scrub (Verify);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;
         Into (At_Offset .. At_Offset + Length - 1) := Region (1 .. Length);
         Last := At_Offset + Length - 1;
      end;

      Absorb (Item, Into (First .. Last));
   end Write_Finished;

end SSL.TLS13;
