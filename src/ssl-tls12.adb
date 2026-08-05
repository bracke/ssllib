with Ada.Streams;

with SSL.Crypto;

package body SSL.TLS12 is

   use type Ada.Streams.Stream_Element_Array;
   use type SSL.Cipher_Suites.AEAD_Algorithm;

   --  The labels, written out rather than composed. A composed label is a place
   --  for a stray space or a missing word to hide, and a Finished computed
   --  under a label that differs by one character verifies against nothing --
   --  with no evidence pointing at the label.
   Extended_Master_Label : constant String := "extended master secret";
   Key_Expansion_Label   : constant String := "key expansion";
   Client_Finished_Label : constant String := "client finished";
   Server_Finished_Label : constant String := "server finished";

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

   ---------------
   -- PRF --
   ---------------

   procedure PRF
     (Algorithm : SSL.Cipher_Suites.Hash_Algorithm;
      Secret    : SSL.Secrets.Secret;
      Label     : String;
      Seed      : Byte_Array;
      Into      : out Byte_Array;
      Error     : out SSL.Errors.Error_Information)
   is
      Width : constant Byte_Index := SSL.Cipher_Suites.Digest_Length (Algorithm);

      --  The full seed is the label followed by the caller's seed. Built once
      --  and reused for every block, because it is the same in all of them.
      Full : Byte_Array (1 .. Byte_Index (Label'Length) + Seed'Length) := [others => 0];

      --  A(i). A(0) is the seed itself; each later one is the HMAC of the one
      --  before.
      Current : Byte_Array (1 .. Width) := [others => 0];
      Block   : Byte_Array (1 .. Width) := [others => 0];

      Produced : Byte_Index := 0;
   begin
      Into := [others => 0];
      Error := SSL.Errors.No_Error;

      for Index in Label'Range loop
         Full (Byte_Index (Index - Label'First + 1)) := Byte (Character'Pos (Label (Index)));
      end loop;
      if Seed'Length > 0 then
         Full (Byte_Index (Label'Length) + 1 .. Full'Last) := Seed;
      end if;

      --  A(1) = HMAC(secret, seed).
      SSL.Crypto.HMAC (Algorithm, Secret, Full, Current);

      while Produced < Into'Length loop
         --  HMAC(secret, A(i) || seed) is the next block of output.
         declare
            Input : constant Byte_Array := Current & Full;
            Take  : Byte_Index;
         begin
            SSL.Crypto.HMAC (Algorithm, Secret, Input, Block);

            Take := Byte_Index'Min (Width, Into'Length - Produced);
            Into (Into'First + Produced .. Into'First + Produced + Take - 1) :=
              Block (1 .. Take);
            Produced := Produced + Take;
         end;

         exit when Produced >= Into'Length;

         --  A(i+1) = HMAC(secret, A(i)).
         declare
            Next : Byte_Array (1 .. Width) := [others => 0];
         begin
            SSL.Crypto.HMAC (Algorithm, Secret, Current, Next);
            Current := Next;
            SSL.Crypto.Scrub (Next);
         end;
      end loop;

      --  Every intermediate here is a function of the secret, so every one of
      --  them is scrubbed -- including on the failure paths above, which fall
      --  through to this point.
      SSL.Crypto.Scrub (Current);
      SSL.Crypto.Scrub (Block);
      SSL.Crypto.Scrub (Full);
   end PRF;

   ---------------------------------------------------------------------------
   --  The master secret
   ---------------------------------------------------------------------------

   procedure Derive_Extended_Master
     (Algorithm    : SSL.Cipher_Suites.Hash_Algorithm;
      Premaster    : SSL.Secrets.Secret;
      Session_Hash : Byte_Array;
      Into         : in out SSL.Secrets.Secret;
      Error        : out SSL.Errors.Error_Information)
   is
      Material : Byte_Array (1 .. Master_Secret_Length) := [others => 0];
   begin
      PRF
        (Algorithm => Algorithm,
         Secret    => Premaster,
         Label     => Extended_Master_Label,
         Seed      => Session_Hash,
         Into      => Material,
         Error     => Error);

      if not SSL.Errors.Is_Error (Error) then
         SSL.Secrets.Set (Into, Material);
      end if;

      SSL.Crypto.Scrub (Material);
   end Derive_Extended_Master;

   ---------------------------------------------------------------------------
   --  The key block
   ---------------------------------------------------------------------------

   procedure Wipe (Item : in out Direction_Keys) is
   begin
      SSL.Secrets.Wipe (Item.Key);
      SSL.Crypto.Scrub (Item.Fixed_IV);
      Item.Fixed_IV_Length := 0;
   end Wipe;

   procedure Derive_Key_Block
     (Suite         : SSL.Cipher_Suites.Cipher_Suite;
      Master        : SSL.Secrets.Secret;
      Client_Random : Byte_Array;
      Server_Random : Byte_Array;
      Client_Side   : in out Direction_Keys;
      Server_Side   : in out Direction_Keys;
      Error         : out SSL.Errors.Error_Information)
   is
      AEAD : constant SSL.Cipher_Suites.AEAD_Algorithm := SSL.Cipher_Suites.AEAD_Of (Suite);

      Key_Width : constant Byte_Index := SSL.Cipher_Suites.Key_Length (AEAD);

      --  The fixed half of the nonce. Four octets for the GCM suites, whose
      --  nonce is four fixed and eight explicit; twelve for ChaCha20-Poly1305,
      --  whose RFC 7905 construction has no explicit part at all and instead
      --  exclusive-ors the sequence number into a twelve-octet fixed IV, the
      --  way TLS 1.3 does. That difference is why this is a length rather than
      --  a constant.
      Fixed_Width : constant Byte_Index :=
        (if AEAD = SSL.Cipher_Suites.ChaCha20_Poly1305 then 12 else 4);

      --  Client key, server key, client IV, server IV. No MAC keys: these are
      --  AEAD suites, and a CBC suite would need them.
      Block : Byte_Array (1 .. 2 * Key_Width + 2 * Fixed_Width) := [others => 0];

      --  RFC 5246 section 6.3: the seed is server_random then client_random,
      --  which is the opposite order from the Finished seeds. Getting it
      --  backwards yields a key block both ends compute differently.
      Seed : constant Byte_Array := Server_Random & Client_Random;

      Cursor : Byte_Index := 1;
   begin
      Wipe (Client_Side);
      Wipe (Server_Side);

      PRF
        (Algorithm => SSL.Cipher_Suites.Hash_Of (Suite),
         Secret    => Master,
         Label     => Key_Expansion_Label,
         Seed      => Seed,
         Into      => Block,
         Error     => Error);
      if SSL.Errors.Is_Error (Error) then
         SSL.Crypto.Scrub (Block);
         return;
      end if;

      SSL.Secrets.Set (Client_Side.Key, Block (Cursor .. Cursor + Key_Width - 1));
      Cursor := Cursor + Key_Width;

      SSL.Secrets.Set (Server_Side.Key, Block (Cursor .. Cursor + Key_Width - 1));
      Cursor := Cursor + Key_Width;

      Client_Side.Fixed_IV_Length := Fixed_Width;
      Client_Side.Fixed_IV (1 .. Fixed_Width) := Block (Cursor .. Cursor + Fixed_Width - 1);
      Cursor := Cursor + Fixed_Width;

      Server_Side.Fixed_IV_Length := Fixed_Width;
      Server_Side.Fixed_IV (1 .. Fixed_Width) := Block (Cursor .. Cursor + Fixed_Width - 1);

      SSL.Crypto.Scrub (Block);
   end Derive_Key_Block;

   ---------------------------------------------------------------------------
   --  Finished
   ---------------------------------------------------------------------------

   procedure Compute_Finished
     (Algorithm       : SSL.Cipher_Suites.Hash_Algorithm;
      Master          : SSL.Secrets.Secret;
      Which           : Finished_Party;
      Transcript_Hash : Byte_Array;
      Into            : out Byte_Array;
      Error           : out SSL.Errors.Error_Information)
   is
   begin
      PRF
        (Algorithm => Algorithm,
         Secret    => Master,
         Label     =>
           (case Which is
               when Client_Finished => Client_Finished_Label,
               when Server_Finished => Server_Finished_Label),
         Seed      => Transcript_Hash,
         Into      => Into,
         Error     => Error);
   end Compute_Finished;

   ---------------------------------------------------------------------------
   --  The signed ServerKeyExchange parameters
   ---------------------------------------------------------------------------

   function Key_Exchange_Signed_Content
     (Client_Random : Byte_Array;
      Server_Random : Byte_Array;
      Parameters    : Byte_Array) return Byte_Array
   is (Client_Random & Server_Random & Parameters);

end SSL.TLS12;
