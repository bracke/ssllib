package body SSL.Transcripts is

   use SSL.Cipher_Suites;

   -----------
   -- Start --
   -----------

   procedure Start (Item : out Transcript) is
   begin
      Item.Selected := False;
      Item.Algorithm := SHA_256;
      Item.Changed := False;
      Item.Count := 0;
      SSL.Crypto.Start (Item.SHA256_State, SHA_256);
      SSL.Crypto.Start (Item.SHA384_State, SHA_384);
   end Start;

   -----------------------
   -- Select_Algorithm --
   -----------------------

   procedure Select_Algorithm
     (Item : in out Transcript; Algorithm : SSL.Cipher_Suites.Hash_Algorithm)
   is
   begin
      Item.Algorithm := Algorithm;
      Item.Selected := True;
   end Select_Algorithm;

   --------------------
   -- Has_Algorithm --
   --------------------

   function Has_Algorithm (Item : Transcript) return Boolean is
   begin
      return Item.Selected;
   end Has_Algorithm;

   ------------------
   -- Algorithm_Of --
   ------------------

   function Algorithm_Of (Item : Transcript) return SSL.Cipher_Suites.Hash_Algorithm is
   begin
      return Item.Algorithm;
   end Algorithm_Of;

   ------------
   -- Absorb --
   ------------

   procedure Absorb (Item : in out Transcript; Data : Byte_Array) is
   begin
      SSL.Crypto.Update (Item.SHA256_State, Data);
      SSL.Crypto.Update (Item.SHA384_State, Data);
      Item.Count := Item.Count + Data'Length;
   end Absorb;

   --------------
   -- Absorbed --
   --------------

   function Absorbed (Item : Transcript) return Byte_Index is
   begin
      return Item.Count;
   end Absorbed;

   ----------
   -- Hash --
   ----------

   procedure Hash (Item : Transcript; Into : out Byte_Array) is
   begin
      case Item.Algorithm is
         when SHA_256 => SSL.Crypto.Snapshot (Item.SHA256_State, Into);
         when SHA_384 => SSL.Crypto.Snapshot (Item.SHA384_State, Into);
      end case;
   end Hash;

   function Hash (Item : Transcript) return Byte_Array is
      Result : Byte_Array (1 .. Digest_Length (Item.Algorithm));
   begin
      Hash (Item, Result);
      return Result;
   end Hash;

   -----------------------------------
   -- Apply_Hello_Retry_Transform --
   -----------------------------------

   procedure Apply_Hello_Retry_Transform (Item : in out Transcript) is

      --  Restart one context with the synthetic message_hash message standing
      --  for everything absorbed so far.
      procedure Transform
        (State     : in out SSL.Crypto.Hash_Context;
         Algorithm : SSL.Cipher_Suites.Hash_Algorithm);

      procedure Transform
        (State     : in out SSL.Crypto.Hash_Context;
         Algorithm : SSL.Cipher_Suites.Hash_Algorithm)
      is
         Width  : constant Byte_Index := Digest_Length (Algorithm);
         Digest : Byte_Array (1 .. Width);
         Header : Byte_Array (1 .. 4);
      begin
         SSL.Crypto.Snapshot (State, Digest);

         --  message_hash || 00 00 Hash.length. The length is the digest width,
         --  which is 32 or 48 and so fits the low octet; the two octets above
         --  it are zero.
         Header (1) := Byte (Message_Hash_Type);
         Header (2) := 0;
         Header (3) := 0;
         Header (4) := Byte (Width);

         SSL.Crypto.Start (State, Algorithm);
         SSL.Crypto.Update (State, Header);
         SSL.Crypto.Update (State, Digest);
      end Transform;

   begin
      Transform (Item.SHA256_State, SHA_256);
      Transform (Item.SHA384_State, SHA_384);

      --  The octet count is now the synthetic message's, not the original
      --  ClientHello's: the bound this feeds is on how much a peer can make
      --  this endpoint hash, and the first ClientHello has been paid for.
      Item.Count := 4 + Digest_Length (Item.Algorithm);
      Item.Changed := True;
   end Apply_Hello_Retry_Transform;

   ------------------
   -- Transformed --
   ------------------

   function Transformed (Item : Transcript) return Boolean is
   begin
      return Item.Changed;
   end Transformed;

end SSL.Transcripts;
