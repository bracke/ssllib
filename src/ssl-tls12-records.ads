with Interfaces;

with SSL.Cipher_Suites;
with SSL.Errors;
with SSL.Records;

use type SSL.Records.Content_Type;

--  @summary The TLS 1.2 record layer, which is a different construction from
--  TLS 1.3's and not a variation on it.
--
--  Four differences, and every one of them is a place where reusing the TLS 1.3
--  code would have produced records no peer can read:
--
--    * **The outer content type is the real one.** TLS 1.2 says `handshake` on
--      a handshake record and `alert` on an alert. TLS 1.3 says
--      `application_data` on everything and hides the real type inside the
--      encryption; TLS 1.2 has nothing to hide it in.
--    * **The additional data is different.** TLS 1.2 authenticates
--      `seq_num || type || version || length`, where the length is the
--      *plaintext* length. TLS 1.3 authenticates the five-octet header, whose
--      length is the *ciphertext* length. Neither is a subset of the other.
--    * **The GCM nonce is split.** Four fixed octets from the key block and
--      eight explicit ones sent in the clear at the front of every fragment.
--      TLS 1.3 has a twelve-octet static IV exclusive-ored with the sequence
--      number and sends nothing.
--    * **ChaCha20-Poly1305 is the exception.** RFC 7905 gave it the TLS 1.3
--      construction -- twelve fixed octets exclusive-ored with the sequence
--      number, nothing explicit -- years before TLS 1.3 existed. So one of the
--      three suites here behaves like 1.3 and two do not, and the difference is
--      in the suite rather than in the version.
--
--  The nonce-uniqueness argument is the same as TLS 1.3's and is worth stating
--  again: a nonce is a function of the key block's fixed part and the sequence
--  number; the sequence advances only after a successful operation; and it
--  never wraps, because this endpoint refuses to protect once it reaches the
--  ceiling. There is no key update in TLS 1.2, so a connection that reaches the
--  ceiling ends.
package SSL.TLS12.Records is

   --  One direction's protection state. Limited: it holds a key and scrubs it.
   type Traffic_State is limited private;

   function Is_Active (Item : Traffic_State) return Boolean;
   function Is_Closed (Item : Traffic_State) return Boolean;

   function Sequence (Item : Traffic_State) return Interfaces.Unsigned_64;

   --  Install this direction's key block half.
   --
   --  The sequence number starts at zero, and this is the only thing that sets
   --  it there. TLS 1.2 has no key update, so it happens exactly once per
   --  direction per connection.
   procedure Install
     (Item  : in out Traffic_State;
      Suite : SSL.Cipher_Suites.Cipher_Suite;
      Keys  : Direction_Keys);

   procedure Wipe (Item : in out Traffic_State);
   procedure Close (Item : in out Traffic_State);

   --  How much protection adds: the explicit nonce, if the suite has one, plus
   --  the tag.
   function Expansion (Suite : SSL.Cipher_Suites.Cipher_Suite) return Byte_Index;

   --  The suite this direction is protecting under.
   function Suite_Of (Item : Traffic_State) return SSL.Cipher_Suites.Cipher_Suite;

   --  Protect one record.
   --
   --  Writes the whole record -- header, explicit nonce if any, ciphertext,
   --  tag -- and advances the sequence number only if the AEAD succeeded.
   --  @param Item      the traffic state
   --  @param Content   the record's content type, which travels in the clear
   --  @param Plaintext the fragment
   --  @param Into      out: the whole record
   --  @param Written   out: how many octets hold it
   --  @param Error     out: No_Error, or the failure
   procedure Protect
     (Item      : in out Traffic_State;
      Content   : SSL.Records.Content_Type;
      Plaintext : Byte_Array;
      Into      : out Byte_Array;
      Written   : out Byte_Index;
      Error     : out SSL.Errors.Error_Information)
     with Pre => Is_Active (Item)
                 and then not Is_Closed (Item)
                 and then Content /= SSL.Records.Invalid_Content;

   --  Open one record.
   --
   --  On any failure the output is zeroed, the count is zero, and the failure
   --  is Code_Record_Authentication_Failed. No alternate key is tried and no
   --  alternate sequence number is tried.
   --  @param Item       the traffic state, advanced on success
   --  @param Header     the five header octets as received
   --  @param Fragment   the record fragment, explicit nonce included
   --  @param Into       out: the recovered plaintext
   --  @param Written    out: how many octets of Into hold it
   --  @param Error      out: No_Error, or the failure
   procedure Open
     (Item     : in out Traffic_State;
      Header   : Byte_Array;
      Fragment : Byte_Array;
      Into     : out Byte_Array;
      Written  : out Byte_Index;
      Error    : out SSL.Errors.Error_Information)
     with Pre => Is_Active (Item)
                 and then not Is_Closed (Item)
                 and then Header'Length = SSL.Records.Header_Length;

private

   type Traffic_State is limited record
      Active   : Boolean := False;
      Shut     : Boolean := False;
      Suite    : SSL.Cipher_Suites.Cipher_Suite :=
        SSL.Cipher_Suites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
      Keys     : Direction_Keys;
      Counter  : Interfaces.Unsigned_64 := 0;
   end record;

   function Is_Active (Item : Traffic_State) return Boolean is (Item.Active);
   function Is_Closed (Item : Traffic_State) return Boolean is (Item.Shut);
   function Sequence (Item : Traffic_State) return Interfaces.Unsigned_64 is (Item.Counter);
   function Suite_Of (Item : Traffic_State) return SSL.Cipher_Suites.Cipher_Suite is
     (Item.Suite);

end SSL.TLS12.Records;
