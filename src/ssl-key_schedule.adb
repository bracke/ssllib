with SSL.Crypto;

package body SSL.Key_Schedule is

   --  RFC 8446 section 7.1 labels, spelled exactly as the specification does.
   --  They are the domain separation of the whole schedule: two secrets derived
   --  from the same input under different labels are unrelated, and a
   --  misspelling here is a handshake that fails against every other
   --  implementation and succeeds against itself.
   Label_Derived            : constant String := "derived";
   Label_External_Binder    : constant String := "ext binder";
   Label_Resumption_Binder  : constant String := "res binder";
   Label_Client_Handshake   : constant String := "c hs traffic";
   Label_Server_Handshake   : constant String := "s hs traffic";
   Label_Client_Application : constant String := "c ap traffic";
   Label_Server_Application : constant String := "s ap traffic";
   Label_Exporter_Master    : constant String := "exp master";
   Label_Resumption_Master  : constant String := "res master";
   Label_Key                : constant String := "key";
   Label_IV                 : constant String := "iv";
   Label_Finished           : constant String := "finished";
   Label_Traffic_Update     : constant String := "traffic upd";
   Label_Exporter           : constant String := "exporter";
   Label_Resumption         : constant String := "resumption";

   function Hash_Of (Item : Schedule) return SSL.Cipher_Suites.Hash_Algorithm
   is (SSL.Cipher_Suites.Hash_Of (Item.Suite));

   function AEAD_Of (Item : Schedule) return SSL.Cipher_Suites.AEAD_Algorithm
   is (SSL.Cipher_Suites.AEAD_Of (Item.Suite));

   -----------
   -- Start --
   -----------

   procedure Start (Item : in out Schedule; Suite : SSL.Cipher_Suites.Cipher_Suite) is
   begin
      Wipe (Item);
      Item.Suite := Suite;
      Item.Started := True;
      Item.Reached := Unstarted;
      Item.With_PSK := False;
   end Start;

   ----------------
   -- Is_Started --
   ----------------

   function Is_Started (Item : Schedule) return Boolean is
   begin
      return Item.Started;
   end Is_Started;

   -------------------
   -- Current_Stage --
   -------------------

   function Current_Stage (Item : Schedule) return Stage is
   begin
      return Item.Reached;
   end Current_Stage;

   ---------------
   -- Suite_Of --
   ---------------

   function Suite_Of (Item : Schedule) return SSL.Cipher_Suites.Cipher_Suite is
   begin
      return Item.Suite;
   end Suite_Of;

   ----------
   -- Wipe --
   ----------

   procedure Wipe (Item : in out Schedule) is
   begin
      SSL.Secrets.Wipe (Item.Early);
      SSL.Secrets.Wipe (Item.Binder);
      SSL.Secrets.Wipe (Item.Handshake);
      SSL.Secrets.Wipe (Item.Master);
      SSL.Secrets.Wipe (Item.Exporter);
      SSL.Secrets.Wipe (Item.Resumption);

      for Side in Party loop
         SSL.Secrets.Wipe (Item.Sides (Side).Handshake_Traffic);
         SSL.Secrets.Wipe (Item.Sides (Side).Application);
         Item.Sides (Side).Generation := 0;
      end loop;

      Item.Started := False;
      Item.Reached := Unstarted;
      Item.With_PSK := False;
   end Wipe;

   ----------------------
   -- Digest_Width --
   ----------------------

   function Digest_Width (Item : Schedule) return Byte_Index is
   begin
      return SSL.Cipher_Suites.Digest_Length (Hash_Of (Item));
   end Digest_Width;

   -----------------
   -- Key_Width --
   -----------------

   function Key_Width (Item : Schedule) return Byte_Index is
   begin
      return SSL.Cipher_Suites.Key_Length (AEAD_Of (Item));
   end Key_Width;

   ---------------------------------------------------------------------------
   --  Stage 1
   ---------------------------------------------------------------------------

   --  Shared tail of the two early-secret entry points: Extract with an empty
   --  salt over the supplied input keying material, then the binder key.
   procedure Complete_Early
     (Item  : in out Schedule;
      Input : Byte_Array;
      Error : out SSL.Errors.Error_Information);

   ---------------------
   -- Complete_Early --
   ---------------------

   procedure Complete_Early
     (Item  : in out Schedule;
      Input : Byte_Array;
      Error : out SSL.Errors.Error_Information)
   is
      Width      : constant Byte_Index := Digest_Width (Item);
      Empty_Hash : constant Byte_Array := SSL.Crypto.Digest (Hash_Of (Item), Empty_Bytes);
   begin
      --  RFC 8446 section 7.1: the first Extract takes a zero-length salt. The
      --  RFC writes it as a string of Hash.length zeroes; RFC 5869 defines an
      --  empty salt as exactly that, so the empty array is the same input.
      SSL.Crypto.Extract
        (Algorithm => Hash_Of (Item),
         Salt      => Empty_Bytes,
         Input     => Input,
         Target    => Item.Early,
         Error     => Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      --  The binder key is derived here rather than on demand, because it is
      --  derived from the early secret with an empty transcript and that is
      --  true only at this moment: once the handshake stage is reached the
      --  early secret is no longer needed and is scrubbed.
      SSL.Crypto.Derive_Secret
        (Algorithm       => Hash_Of (Item),
         Secret          => Item.Early,
         Label           => (if Item.With_PSK then Label_Resumption_Binder
                             else Label_External_Binder),
         Transcript_Hash => Empty_Hash,
         Target          => Item.Binder,
         Error           => Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      pragma Assert (SSL.Secrets.Length (Item.Early) = Width);
      Item.Reached := Early_Stage;
   end Complete_Early;

   -----------------------------
   -- Derive_Early_From_PSK --
   -----------------------------

   procedure Derive_Early_From_PSK
     (Item  : in out Schedule;
      PSK   : Byte_Array;
      Error : out SSL.Errors.Error_Information)
   is
   begin
      Item.With_PSK := True;
      Complete_Early (Item, PSK, Error);
      if SSL.Errors.Is_Error (Error) then
         Item.With_PSK := False;
      end if;
   end Derive_Early_From_PSK;

   --------------------------------
   -- Derive_Early_Without_PSK --
   --------------------------------

   procedure Derive_Early_Without_PSK
     (Item  : in out Schedule;
      Error : out SSL.Errors.Error_Information)
   is
      Zeroes : constant Byte_Array (1 .. Digest_Width (Item)) := [others => 0];
   begin
      Item.With_PSK := False;
      Complete_Early (Item, Zeroes, Error);
   end Derive_Early_Without_PSK;

   ----------------
   -- Used_PSK --
   ----------------

   function Used_PSK (Item : Schedule) return Boolean is
   begin
      return Item.With_PSK;
   end Used_PSK;

   ---------------------
   -- Compute_Binder --
   ---------------------

   procedure Compute_Binder
     (Item            : Schedule;
      Transcript_Hash : Byte_Array;
      Is_External     : Boolean;
      Into            : out Byte_Array;
      Error           : out SSL.Errors.Error_Information)
   is
      pragma Unreferenced (Is_External);
      Finished : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
   begin
      Into := [others => 0];

      --  The binder is a Finished-shaped MAC: a "finished" key expanded from
      --  the binder key, then HMAC over the partial transcript.
      SSL.Crypto.Expand_Label
        (Algorithm => Hash_Of (Item),
         Secret    => Item.Binder,
         Label     => Label_Finished,
         Context   => Empty_Bytes,
         Target    => Finished,
         Length    => Digest_Width (Item),
         Error     => Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Crypto.HMAC (Hash_Of (Item), Finished, Transcript_Hash, Into);
      SSL.Secrets.Wipe (Finished);
   end Compute_Binder;

   ---------------------------------------------------------------------------
   --  Stage 2
   ---------------------------------------------------------------------------

   -----------------------
   -- Derive_Handshake --
   -----------------------

   procedure Derive_Handshake
     (Item            : in out Schedule;
      Shared_Secret   : Byte_Array;
      Transcript_Hash : Byte_Array;
      Error           : out SSL.Errors.Error_Information)
   is
      Width      : constant Byte_Index := Digest_Width (Item);
      Empty_Hash : constant Byte_Array := SSL.Crypto.Digest (Hash_Of (Item), Empty_Bytes);
      Salt       : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
      Salt_Octets : Byte_Array (1 .. Width) := [others => 0];
   begin
      --  Derive-Secret(Early, "derived", "") is the salt for the second Extract.
      SSL.Crypto.Derive_Secret
        (Algorithm       => Hash_Of (Item),
         Secret          => Item.Early,
         Label           => Label_Derived,
         Transcript_Hash => Empty_Hash,
         Target          => Salt,
         Error           => Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Secrets.Get (Salt, Salt_Octets);
      SSL.Crypto.Extract
        (Algorithm => Hash_Of (Item),
         Salt      => Salt_Octets,
         Input     => Shared_Secret,
         Target    => Item.Handshake,
         Error     => Error);
      SSL.Secrets.Wipe (Salt);
      SSL.Crypto.Scrub (Salt_Octets);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Crypto.Derive_Secret
        (Algorithm       => Hash_Of (Item),
         Secret          => Item.Handshake,
         Label           => Label_Client_Handshake,
         Transcript_Hash => Transcript_Hash,
         Target          => Item.Sides (Client_Side).Handshake_Traffic,
         Error           => Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Crypto.Derive_Secret
        (Algorithm       => Hash_Of (Item),
         Secret          => Item.Handshake,
         Label           => Label_Server_Handshake,
         Transcript_Hash => Transcript_Hash,
         Target          => Item.Sides (Server_Side).Handshake_Traffic,
         Error           => Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      --  The early secret and the binder key have no further use. Scrubbing
      --  them here rather than at the end of the connection is what makes an
      --  attacker who compromises the process after the handshake unable to
      --  recover them.
      SSL.Secrets.Wipe (Item.Early);
      SSL.Secrets.Wipe (Item.Binder);

      Item.Reached := Handshake_Stage;
   end Derive_Handshake;

   ---------------------------------------------------------------------------
   --  Stage 3
   ---------------------------------------------------------------------------

   --------------------
   -- Derive_Master --
   --------------------

   procedure Derive_Master
     (Item                 : in out Schedule;
      Server_Finished_Hash : Byte_Array;
      Error                : out SSL.Errors.Error_Information)
   is
      Width       : constant Byte_Index := Digest_Width (Item);
      Empty_Hash  : constant Byte_Array := SSL.Crypto.Digest (Hash_Of (Item), Empty_Bytes);
      Zeroes      : constant Byte_Array (1 .. Width) := [others => 0];
      Salt        : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
      Salt_Octets : Byte_Array (1 .. Width) := [others => 0];
   begin
      SSL.Crypto.Derive_Secret
        (Algorithm       => Hash_Of (Item),
         Secret          => Item.Handshake,
         Label           => Label_Derived,
         Transcript_Hash => Empty_Hash,
         Target          => Salt,
         Error           => Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Secrets.Get (Salt, Salt_Octets);
      SSL.Crypto.Extract
        (Algorithm => Hash_Of (Item),
         Salt      => Salt_Octets,
         Input     => Zeroes,
         Target    => Item.Master,
         Error     => Error);
      SSL.Secrets.Wipe (Salt);
      SSL.Crypto.Scrub (Salt_Octets);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      --  The application traffic secrets and the exporter master secret are
      --  bound to the transcript through the server's Finished.
      SSL.Crypto.Derive_Secret
        (Algorithm       => Hash_Of (Item),
         Secret          => Item.Master,
         Label           => Label_Client_Application,
         Transcript_Hash => Server_Finished_Hash,
         Target          => Item.Sides (Client_Side).Application,
         Error           => Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Crypto.Derive_Secret
        (Algorithm       => Hash_Of (Item),
         Secret          => Item.Master,
         Label           => Label_Server_Application,
         Transcript_Hash => Server_Finished_Hash,
         Target          => Item.Sides (Server_Side).Application,
         Error           => Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Crypto.Derive_Secret
        (Algorithm       => Hash_Of (Item),
         Secret          => Item.Master,
         Label           => Label_Exporter_Master,
         Transcript_Hash => Server_Finished_Hash,
         Target          => Item.Exporter,
         Error           => Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      Item.Sides (Client_Side).Generation := 0;
      Item.Sides (Server_Side).Generation := 0;
      Item.Reached := Master_Stage;
   end Derive_Master;

   --------------------------------
   -- Derive_Resumption --
   --------------------------------

   procedure Derive_Resumption
     (Item                 : in out Schedule;
      Client_Finished_Hash : Byte_Array;
      Error                : out SSL.Errors.Error_Information)
   is
   begin
      --  A different milestone from the one above, and getting the two the
      --  wrong way round yields a ticket that resumes to nothing -- which both
      --  ends would find out one connection later, with no evidence pointing
      --  back here.
      SSL.Crypto.Derive_Secret
        (Algorithm       => Hash_Of (Item),
         Secret          => Item.Master,
         Label           => Label_Resumption_Master,
         Transcript_Hash => Client_Finished_Hash,
         Target          => Item.Resumption,
         Error           => Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      Item.Resumption_Ready := True;
   end Derive_Resumption;

   function Has_Resumption (Item : Schedule) return Boolean is (Item.Resumption_Ready);

   ---------------------------------------------------------------------------
   --  Products
   ---------------------------------------------------------------------------

   ------------------
   -- Traffic_Key --
   ------------------

   procedure Traffic_Key
     (Item        : Schedule;
      Which       : Party;
      Which_Epoch : Epoch;
      Key         : out Byte_Array;
      IV          : out Byte_Array;
      Error       : out SSL.Errors.Error_Information)
   is
      Source : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
   begin
      Key := [others => 0];
      IV := [others => 0];

      --  A copy, because Expand_Label takes a Secret and the stage secret must
      --  not be handed out. The copy is scrubbed before return.
      case Which_Epoch is
         when Handshake_Epoch =>
            SSL.Secrets.Copy (Source, Item.Sides (Which).Handshake_Traffic);
         when Application_Epoch =>
            SSL.Secrets.Copy (Source, Item.Sides (Which).Application);
      end case;

      SSL.Crypto.Expand_Label_Into
        (Algorithm => Hash_Of (Item),
         Secret    => Source,
         Label     => Label_Key,
         Context   => Empty_Bytes,
         Into      => Key,
         Error     => Error);
      if SSL.Errors.Is_Error (Error) then
         SSL.Secrets.Wipe (Source);
         Key := [others => 0];
         return;
      end if;

      SSL.Crypto.Expand_Label_Into
        (Algorithm => Hash_Of (Item),
         Secret    => Source,
         Label     => Label_IV,
         Context   => Empty_Bytes,
         Into      => IV,
         Error     => Error);
      SSL.Secrets.Wipe (Source);

      if SSL.Errors.Is_Error (Error) then
         Key := [others => 0];
         IV := [others => 0];
      end if;
   end Traffic_Key;

   -------------------
   -- Finished_Key --
   -------------------

   procedure Finished_Key
     (Item  : Schedule;
      Which : Party;
      Into  : out Byte_Array;
      Error : out SSL.Errors.Error_Information)
   is
      Source : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
   begin
      Into := [others => 0];
      SSL.Secrets.Copy (Source, Item.Sides (Which).Handshake_Traffic);
      SSL.Crypto.Expand_Label_Into
        (Algorithm => Hash_Of (Item),
         Secret    => Source,
         Label     => Label_Finished,
         Context   => Empty_Bytes,
         Into      => Into,
         Error     => Error);
      SSL.Secrets.Wipe (Source);
      if SSL.Errors.Is_Error (Error) then
         Into := [others => 0];
      end if;
   end Finished_Key;

   -----------------------
   -- Compute_Finished --
   -----------------------

   procedure Compute_Finished
     (Item            : Schedule;
      Which           : Party;
      Transcript_Hash : Byte_Array;
      Into            : out Byte_Array;
      Error           : out SSL.Errors.Error_Information)
   is
      Key_Octets : Byte_Array (1 .. Digest_Width (Item)) := [others => 0];
   begin
      Into := [others => 0];
      Finished_Key (Item, Which, Key_Octets, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Crypto.HMAC_Octets (Hash_Of (Item), Key_Octets, Transcript_Hash, Into);
      SSL.Crypto.Scrub (Key_Octets);
   end Compute_Finished;

   -------------------------------
   -- Advance_Traffic_Secret --
   -------------------------------

   procedure Advance_Traffic_Secret
     (Item  : in out Schedule;
      Which : Party;
      Error : out SSL.Errors.Error_Information)
   is
      Next : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
   begin
      SSL.Crypto.Expand_Label
        (Algorithm => Hash_Of (Item),
         Secret    => Item.Sides (Which).Application,
         Label     => Label_Traffic_Update,
         Context   => Empty_Bytes,
         Target    => Next,
         Length    => Digest_Width (Item),
         Error     => Error);
      if SSL.Errors.Is_Error (Error) then
         SSL.Secrets.Wipe (Next);
         return;
      end if;

      --  Copy forward and scrub the old secret. After this the retired key
      --  cannot be recovered from the schedule, which is what an update is for.
      SSL.Secrets.Copy (Item.Sides (Which).Application, Next);
      SSL.Secrets.Wipe (Next);
      Item.Sides (Which).Generation := Item.Sides (Which).Generation + 1;
   end Advance_Traffic_Secret;

   ----------------
   -- Generation --
   ----------------

   function Generation (Item : Schedule; Which : Party) return Natural is
   begin
      return Item.Sides (Which).Generation;
   end Generation;

   ------------
   -- Export --
   ------------

   procedure Export
     (Item        : Schedule;
      Label       : String;
      Context     : Byte_Array;
      Has_Context : Boolean;
      Into        : out Byte_Array;
      Error       : out SSL.Errors.Error_Information)
   is
      Empty_Hash : constant Byte_Array := SSL.Crypto.Digest (Hash_Of (Item), Empty_Bytes);
      Stage_One  : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
   begin
      Into := [others => 0];

      --  RFC 8446 section 7.5, first step: Derive-Secret over the exporter
      --  master secret with the caller's label and an empty transcript.
      SSL.Crypto.Derive_Secret
        (Algorithm       => Hash_Of (Item),
         Secret          => Item.Exporter,
         Label           => Label,
         Transcript_Hash => Empty_Hash,
         Target          => Stage_One,
         Error           => Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      --  Second step: Expand-Label under "exporter" with the hash of the
      --  context.
      --
      --  In TLS 1.3 an absent context and an empty one give the same output,
      --  and that is the specification's own choice rather than a shortcut
      --  here: RFC 8446 section 7.5 says that when no context is used the
      --  context value is the empty string, so both paths hash the empty
      --  string. The flag is still a parameter because TLS 1.2's exporter is
      --  different -- RFC 5705 length-prefixes the context and distinguishes
      --  its absence -- and a schedule interface that dropped the flag could
      --  not express that.
      declare
         Context_Hash : constant Byte_Array :=
           (if Has_Context
            then SSL.Crypto.Digest (Hash_Of (Item), Context)
            else Empty_Hash);
      begin
         SSL.Crypto.Expand_Label_Into
           (Algorithm => Hash_Of (Item),
            Secret    => Stage_One,
            Label     => Label_Exporter,
            Context   => Context_Hash,
            Into      => Into,
            Error     => Error);
      end;

      SSL.Secrets.Wipe (Stage_One);
      if SSL.Errors.Is_Error (Error) then
         Into := [others => 0];
      end if;
   end Export;

   ---------------------
   -- Resumption_PSK --
   ---------------------

   procedure Resumption_PSK
     (Item  : Schedule;
      Nonce : Byte_Array;
      Into  : out Byte_Array;
      Error : out SSL.Errors.Error_Information)
   is
   begin
      Into := [others => 0];
      SSL.Crypto.Expand_Label_Into
        (Algorithm => Hash_Of (Item),
         Secret    => Item.Resumption,
         Label     => Label_Resumption,
         Context   => Nonce,
         Into      => Into,
         Error     => Error);
      if SSL.Errors.Is_Error (Error) then
         Into := [others => 0];
      end if;
   end Resumption_PSK;

end SSL.Key_Schedule;
