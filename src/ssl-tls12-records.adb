with Ada.Streams;

with SSL.Crypto;
with SSL.Secrets;
with SSL.Versions;

package body SSL.TLS12.Records is

   use type Ada.Streams.Stream_Element;
   use type Interfaces.Unsigned_64;
   use type SSL.Cipher_Suites.AEAD_Algorithm;

   Tag_Length : constant Byte_Index := 16;

   --  RFC 5246 section 6.2.3.3: eight octets, sent in the clear at the front of
   --  every GCM fragment. RFC 7905 gave ChaCha20-Poly1305 none.
   function Explicit_Length
     (Suite : SSL.Cipher_Suites.Cipher_Suite) return Byte_Index
   is (if SSL.Cipher_Suites.AEAD_Of (Suite) = SSL.Cipher_Suites.ChaCha20_Poly1305
       then 0 else 8);

   function Expansion (Suite : SSL.Cipher_Suites.Cipher_Suite) return Byte_Index is
     (Explicit_Length (Suite) + Tag_Length);

   --  The largest sequence number that may be used. Reaching it ends the
   --  connection: TLS 1.2 has no key update, so there is nothing to move to.
   Sequence_Ceiling : constant Interfaces.Unsigned_64 := Interfaces.Unsigned_64'Last - 1;

   ------------------
   -- Install --
   ------------------

   procedure Install
     (Item  : in out Traffic_State;
      Suite : SSL.Cipher_Suites.Cipher_Suite;
      Keys  : Direction_Keys)
   is
   begin
      Item.Suite := Suite;
      SSL.Secrets.Copy (Item.Keys.Key, Keys.Key);
      Item.Keys.Fixed_IV := Keys.Fixed_IV;
      Item.Keys.Fixed_IV_Length := Keys.Fixed_IV_Length;
      Item.Counter := 0;
      Item.Active := True;
      Item.Shut := False;
   end Install;

   procedure Wipe (Item : in out Traffic_State) is
   begin
      TLS12.Wipe (Item.Keys);
      Item.Active := False;
      Item.Counter := 0;
   end Wipe;

   procedure Close (Item : in out Traffic_State) is
   begin
      Item.Shut := True;
   end Close;

   ---------------------------------------------------------------------------
   --  Nonce and additional data
   ---------------------------------------------------------------------------

   --  The twelve-octet nonce for this record.
   --
   --  Two constructions, and which one is used is a property of the suite
   --  rather than of the version: GCM concatenates four fixed octets with the
   --  eight explicit ones, and ChaCha20-Poly1305 exclusive-ors the sequence
   --  number into a twelve-octet fixed IV.
   function Nonce
     (Item : Traffic_State; Explicit : Byte_Array) return Byte_Array;

   function Nonce
     (Item : Traffic_State; Explicit : Byte_Array) return Byte_Array
   is
      Result : Byte_Array (1 .. 12) := [others => 0];
   begin
      if SSL.Cipher_Suites.AEAD_Of (Item.Suite) = SSL.Cipher_Suites.ChaCha20_Poly1305 then
         Result := Item.Keys.Fixed_IV;

         --  The sequence number, big-endian, into the last eight octets.
         declare
            Counter : Interfaces.Unsigned_64 := Item.Counter;
         begin
            for Offset in reverse 5 .. 12 loop
               Result (Byte_Index (Offset)) :=
                 Result (Byte_Index (Offset))
                 xor Byte (Counter mod 256);
               Counter := Counter / 256;
            end loop;
         end;
      else
         Result (1 .. 4) := Item.Keys.Fixed_IV (1 .. 4);
         Result (5 .. 12) := Explicit;
      end if;
      return Result;
   end Nonce;

   --  RFC 5246 section 6.2.3.3: seq_num || type || version || length, where the
   --  length is the *plaintext* length. That last point is the difference from
   --  TLS 1.3, whose additional data is the header and therefore carries the
   --  ciphertext length.
   function Additional
     (Item      : Traffic_State;
      Content   : SSL.Records.Content_Type;
      Plaintext : Byte_Index) return Byte_Array;

   function Additional
     (Item      : Traffic_State;
      Content   : SSL.Records.Content_Type;
      Plaintext : Byte_Index) return Byte_Array
   is
      Result  : Byte_Array (1 .. 13) := [others => 0];
      Counter : Interfaces.Unsigned_64 := Item.Counter;
   begin
      for Offset in reverse 1 .. 8 loop
         Result (Byte_Index (Offset)) := Byte (Counter mod 256);
         Counter := Counter / 256;
      end loop;

      Result (9) := SSL.Records.Octet_For (Content);
      Result (10) := Byte (Natural (SSL.Versions.TLS_1_2_Value) / 256);
      Result (11) := Byte (Natural (SSL.Versions.TLS_1_2_Value) mod 256);
      Result (12) := Byte (Plaintext / 256);
      Result (13) := Byte (Plaintext mod 256);
      return Result;
   end Additional;

   ---------------------------------------------------------------------------
   --  Protection
   ---------------------------------------------------------------------------

   procedure Protect
     (Item      : in out Traffic_State;
      Content   : SSL.Records.Content_Type;
      Plaintext : Byte_Array;
      Into      : out Byte_Array;
      Written   : out Byte_Index;
      Error     : out SSL.Errors.Error_Information)
   is
      Explicit_Width : constant Byte_Index := Explicit_Length (Item.Suite);
      Fragment_Width : constant Byte_Index :=
        Explicit_Width + Plaintext'Length + Tag_Length;
   begin
      Into := [others => 0];
      Written := 0;
      Error := SSL.Errors.No_Error;

      if Item.Counter >= Sequence_Ceiling then
         --  Refused before the AEAD is reached. There is no key update in
         --  TLS 1.2, so a connection at the ceiling has nothing to move to and
         --  ends rather than reusing a nonce.
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Record_Sequence_Exhausted, SSL.Errors.Local_Implementation);
         return;
      end if;

      if Into'Length < SSL.Records.Header_Length + Fragment_Width then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Output_Queue_Full, SSL.Errors.Local_Implementation);
         return;
      end if;

      declare
         Explicit : Byte_Array (1 .. Explicit_Width) := [others => 0];
         Counter  : Interfaces.Unsigned_64 := Item.Counter;
      begin
         --  The explicit part is the sequence number. It is not a secret -- it
         --  travels in the clear -- and it must not repeat under one key, which
         --  the sequence number guarantees.
         for Offset in reverse 1 .. Explicit_Width loop
            Explicit (Offset) := Byte (Counter mod 256);
            Counter := Counter / 256;
         end loop;

         declare
            Header : constant Byte_Array :=
              SSL.Records.Encode_Header
                ((Content => Content,
                  Version => SSL.Versions.TLS_1_2_Value,
                  Length  => Fragment_Width));
            Sealed : Byte_Array (1 .. Plaintext'Length + Tag_Length) := [others => 0];
            Local  : SSL.Errors.Error_Information;
         begin
            SSL.Crypto.Seal
              (Algorithm  => SSL.Cipher_Suites.AEAD_Of (Item.Suite),
               Key        => Item.Keys.Key,
               Nonce      => Nonce (Item, Explicit),
               Additional => Additional (Item, Content, Plaintext'Length),
               Plaintext  => Plaintext,
               Wire       => Sealed,
               Error      => Local);
            if SSL.Errors.Is_Error (Local) then
               SSL.Crypto.Scrub (Sealed);
               Error := Local;
               return;
            end if;

            Into (Into'First .. Into'First + SSL.Records.Header_Length - 1) := Header;
            if Explicit_Width > 0 then
               Into (Into'First + SSL.Records.Header_Length
                     .. Into'First + SSL.Records.Header_Length + Explicit_Width - 1) :=
                 Explicit;
            end if;
            Into (Into'First + SSL.Records.Header_Length + Explicit_Width
                  .. Into'First + SSL.Records.Header_Length + Fragment_Width - 1) := Sealed;

            Written := SSL.Records.Header_Length + Fragment_Width;
         end;
      end;

      --  Advanced only now, after the AEAD succeeded. A failed protect leaves
      --  the sequence where it was, so nothing can be sent twice under one
      --  nonce.
      Item.Counter := Item.Counter + 1;
   end Protect;

   procedure Open
     (Item     : in out Traffic_State;
      Header   : Byte_Array;
      Fragment : Byte_Array;
      Into     : out Byte_Array;
      Written  : out Byte_Index;
      Error    : out SSL.Errors.Error_Information)
   is
      Explicit_Width : constant Byte_Index := Explicit_Length (Item.Suite);

      Parsed : SSL.Records.Record_Header;
      Local  : SSL.Errors.Error_Information;
   begin
      Into := [others => 0];
      Written := 0;

      SSL.Records.Parse_Header (Header, Parsed, Local);
      if SSL.Errors.Is_Error (Local) then
         Error := Local;
         return;
      end if;

      if Fragment'Length < Explicit_Width + Tag_Length then
         --  Too short to hold what it must. Reported as an authentication
         --  failure rather than as a malformed record, because the two are
         --  indistinguishable to a peer and giving them different answers would
         --  say which check it failed.
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Record_Authentication_Failed, SSL.Errors.Peer_Message);
         return;
      end if;

      if Item.Counter >= Sequence_Ceiling then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Record_Sequence_Exhausted, SSL.Errors.Local_Implementation);
         return;
      end if;

      declare
         Explicit : constant Byte_Array :=
           Fragment (Fragment'First .. Fragment'First + Explicit_Width - 1);
         Sealed   : constant Byte_Array :=
           Fragment (Fragment'First + Explicit_Width .. Fragment'Last);
         Recovered : Byte_Array (1 .. Sealed'Length - Tag_Length) := [others => 0];
      begin
         if Into'Length < Recovered'Length then
            Error := SSL.Errors.Make
              (SSL.Errors.Code_Record_Length_Excessive, SSL.Errors.Peer_Message);
            return;
         end if;

         SSL.Crypto.Open
           (Algorithm  => SSL.Cipher_Suites.AEAD_Of (Item.Suite),
            Key        => Item.Keys.Key,
            Nonce      => Nonce (Item, Explicit),
            Additional => Additional (Item, Parsed.Content, Recovered'Length),
            Wire       => Sealed,
            Plaintext  => Recovered,
            Error      => Local);

         if SSL.Errors.Is_Error (Local) then
            --  Nothing of the output is exposed. A record whose tag did not
            --  verify produces no plaintext at all, so there is nothing for a
            --  caller to accidentally treat as authentic.
            SSL.Crypto.Scrub (Recovered);
            Into := [others => 0];
            Error := SSL.Errors.Make
              (SSL.Errors.Code_Record_Authentication_Failed, SSL.Errors.Peer_Message);
            return;
         end if;

         Into (Into'First .. Into'First + Recovered'Length - 1) := Recovered;
         Written := Recovered'Length;
         SSL.Crypto.Scrub (Recovered);
      end;

      Item.Counter := Item.Counter + 1;
      Error := SSL.Errors.No_Error;
   end Open;

end SSL.TLS12.Records;
