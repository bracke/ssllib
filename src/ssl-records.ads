with Interfaces;

private with SSL.Secrets;

with SSL.Cipher_Suites;
with SSL.Errors;
with SSL.Limits;
with SSL.Versions;

--  @summary The TLS record layer: the five-octet header, the AEAD protection of
--  a record, and the per-direction traffic state that makes nonce reuse
--  structurally impossible.
--
--  Three things live here and they are separable on purpose.
--
--  The header codec is explicit, octet by octet. There is no unchecked
--  conversion of five wire octets into an Ada record anywhere in this library,
--  and there is no representation clause standing in for one. A record header is
--  parsed by reading three fields out of five octets and writing them into three
--  named components, which is slower by an amount nobody can measure and cannot
--  be made wrong by a change of endianness, alignment or padding.
--
--  The traffic state is one per direction, and it owns the AEAD key, the static
--  IV, the sequence number and the counters. It is the seat of the
--  no-nonce-reuse invariant (REC-1 in the invariant registry): a nonce is a
--  function of the static IV and the sequence number, the sequence number is
--  incremented only after a successful protect or open, and it is reset to zero
--  only when the key changes. There is no operation on this type that sets a
--  sequence number, no operation that reuses a key with a sequence number that
--  has already been used, and no operation that retries an open with a different
--  sequence number after a failure. The absence of those operations is the
--  guarantee; a check would only be a second opinion.
--
--  The protection step implements RFC 8446 section 5.2: the outer content type
--  is always application_data, the outer version is always 0x0303, the five-octet
--  header is the AEAD's additional data, and the plaintext being protected is
--  the content followed by the real content type followed by zero padding.
--  Padding is removed only after the tag has verified, so a padding oracle has
--  nothing to observe: an unauthenticated record produces no plaintext at all,
--  and the failure is bad_record_mac whether the tag was wrong or the padding
--  was malformed.
private package SSL.Records is

   --  Sequence numbers are 64-bit unsigned, and the contracts below compare
   --  them, so the operators are made visible here rather than only in the body.
   use type Interfaces.Unsigned_64;

   ---------------------------------------------------------------------------
   --  Content types
   ---------------------------------------------------------------------------

   --  The record and inner content types this library recognizes.
   --
   --  Invalid_Content is not a wire value: it is what an unrecognized type
   --  octet maps to, and every path that produces it refuses the record.
   type Content_Type is
     (Change_Cipher_Spec,
      Alert_Content,
      Handshake_Content,
      Application_Content,
      Invalid_Content);

   Change_Cipher_Spec_Octet : constant := 20;
   Alert_Octet              : constant := 21;
   Handshake_Octet          : constant := 22;
   Application_Data_Octet   : constant := 23;

   function Content_For (Octet : Byte) return Content_Type;
   function Octet_For (Item : Content_Type) return Byte
     with Pre => Item /= Invalid_Content;
   function Image (Item : Content_Type) return String;

   ---------------------------------------------------------------------------
   --  The header
   ---------------------------------------------------------------------------

   Header_Length : constant Byte_Index := 5;

   --  A parsed record header. Three named fields, never a view over wire octets.
   type Record_Header is record
      Content : Content_Type := Invalid_Content;
      Version : SSL.Versions.Version_Value := SSL.Versions.Legacy_Record_Value;
      Length  : Byte_Index := 0;
   end record;

   --  Parse five octets.
   --
   --  Accepts any length up to the wire maximum; whether the length is
   --  acceptable under the configured limits is a separate question with a
   --  separate answer, because a record that is too long for policy and a
   --  record whose header is malformed are different failures.
   --  @param Data   exactly five octets
   --  @param Item   out: the parsed header
   --  @param Error  out: No_Error, or Code_Record_Header_Malformed for an
   --    unrecognized content type
   procedure Parse_Header
     (Data  : Byte_Array;
      Item  : out Record_Header;
      Error : out SSL.Errors.Error_Information)
     with Pre => Data'Length = Header_Length;

   --  Emit five octets.
   --  @param Item the header to encode
   --  @return exactly five octets
   function Encode_Header (Item : Record_Header) return Byte_Array
     with Pre => Item.Content /= Invalid_Content and then Item.Length <= 16#FFFF#,
          Post => Encode_Header'Result'Length = Header_Length;

   --  The largest ciphertext length a record header may declare: RFC 8446
   --  section 5.2 caps a protected record's fragment at 2^14 + 256.
   Maximum_Ciphertext_Length : constant Byte_Index := 16_384 + 256;

   ---------------------------------------------------------------------------
   --  Traffic state
   ---------------------------------------------------------------------------

   --  One direction's protection state. Limited: it holds a key.
   type Traffic_State is limited private;

   --  Is a key installed?
   function Is_Active (Item : Traffic_State) return Boolean;

   --  Install a key and IV, starting a new generation with the sequence number
   --  at zero.
   --
   --  This is the only way a sequence number returns to zero, and it always
   --  comes with a new key, which is what makes (key, nonce) pairs unique
   --  across a connection.
   --  @param Item       the traffic state
   --  @param Suite      the negotiated suite, fixing the AEAD
   --  @param Key        the traffic key, the AEAD's key length
   --  @param IV         the static IV, twelve octets
   --  @param Generation which generation this is: zero for the handshake epoch
   --    and for the first application epoch, incremented by each KeyUpdate
   procedure Install
     (Item       : in out Traffic_State;
      Suite      : SSL.Cipher_Suites.Cipher_Suite;
      Key        : Byte_Array;
      IV         : Byte_Array;
      Generation : Natural)
     with Pre => Key'Length = SSL.Cipher_Suites.Key_Length
                              (SSL.Cipher_Suites.AEAD_Of (Suite))
                 and then IV'Length = 12,
          Post => Is_Active (Item) and then Sequence (Item) = 0;

   --  Scrub the key and IV and mark the state inactive.
   procedure Wipe (Item : in out Traffic_State);

   --  Refuse any further use of this direction, after a close or a failure.
   procedure Close (Item : in out Traffic_State)
     with Post => Is_Closed (Item);

   function Is_Closed (Item : Traffic_State) return Boolean;

   --  The next sequence number to be used. Exposed for diagnostics and for the
   --  usage-limit checks; there is deliberately no setter.
   function Sequence (Item : Traffic_State) return Interfaces.Unsigned_64;

   --  Which generation the installed key belongs to.
   function Generation_Of (Item : Traffic_State) return Natural;

   --  Records and octets protected or opened under the current key.
   function Record_Count (Item : Traffic_State) return Long_Long_Integer;
   function Octet_Count (Item : Traffic_State) return Long_Long_Integer;

   --  Has this direction reached the point where a KeyUpdate should be
   --  scheduled? Checked before protecting, so the update is queued while there
   --  is still room to send it.
   function Update_Advisable
     (Item : Traffic_State; Bounds : SSL.Limits.Resource_Limits) return Boolean;

   --  Has this direction reached the point where no further record may be
   --  protected under the current key? At this point the connection either
   --  completes a key update or fails closed; it does not protect one more
   --  record.
   function Update_Required
     (Item : Traffic_State; Bounds : SSL.Limits.Resource_Limits) return Boolean;

   ---------------------------------------------------------------------------
   --  Protection
   ---------------------------------------------------------------------------

   --  The largest expansion protection adds: the inner content-type octet, the
   --  padding the caller asked for, and the tag.
   function Expansion
     (Suite : SSL.Cipher_Suites.Cipher_Suite; Padding : Byte_Index) return Byte_Index
   is (1 + Padding + SSL.Cipher_Suites.Tag_Length (SSL.Cipher_Suites.AEAD_Of (Suite)));

   --  Protect one record.
   --
   --  Writes the complete record -- header, ciphertext, tag -- into Into, and
   --  advances the sequence number only if the AEAD succeeded. A failure leaves
   --  the sequence number where it was and the state usable for nothing: the
   --  caller's only correct response is to fail the connection.
   --  @param Item      the traffic state, advanced on success
   --  @param Inner     the content type of the plaintext
   --  @param Plaintext the content; may be empty
   --  @param Padding   zero octets to append inside the protected plaintext
   --  @param Into      out: the whole record
   --  @param Written   out: how many octets of Into hold the record
   --  @param Error     out: No_Error, or the failure
   procedure Protect
     (Item      : in out Traffic_State;
      Inner     : Content_Type;
      Plaintext : Byte_Array;
      Padding   : Byte_Index;
      Into      : out Byte_Array;
      Written   : out Byte_Index;
      Error     : out SSL.Errors.Error_Information)
     with Pre => Is_Active (Item)
                 and then not Is_Closed (Item)
                 and then Inner /= Invalid_Content
                 and then Padding >= 0
                 and then Into'Length >= Header_Length + Plaintext'Length
                                         + Expansion (Suite_Of (Item), Padding);

   --  Open one record.
   --
   --  Ciphertext is the record's fragment, without the header; Header is the
   --  header exactly as received, which is the AEAD's additional data. The
   --  sequence number advances only if the tag verified.
   --
   --  On any failure Plaintext is zeroed, Written is zero, and the failure is
   --  Code_Record_Authentication_Failed. No alternate key is tried, no
   --  alternate sequence number is tried, and the distinction between a bad tag
   --  and bad padding is not reported.
   --  @param Item       the traffic state, advanced on success
   --  @param Header     the five header octets as received
   --  @param Ciphertext the record fragment
   --  @param Into       out: the recovered content, padding already removed
   --  @param Written    out: how many octets of Into hold content
   --  @param Inner      out: the recovered inner content type
   --  @param Error      out: No_Error, or the failure
   procedure Open
     (Item       : in out Traffic_State;
      Header     : Byte_Array;
      Ciphertext : Byte_Array;
      Into       : out Byte_Array;
      Written    : out Byte_Index;
      Inner      : out Content_Type;
      Error      : out SSL.Errors.Error_Information)
     with Pre => Is_Active (Item)
                 and then not Is_Closed (Item)
                 and then Header'Length = Header_Length
                 and then Ciphertext'Length
                          >= SSL.Cipher_Suites.Tag_Length
                               (SSL.Cipher_Suites.AEAD_Of (Suite_Of (Item)))
                 and then Into'Length >= Ciphertext'Length;

   function Suite_Of (Item : Traffic_State) return SSL.Cipher_Suites.Cipher_Suite
     with Pre => Is_Active (Item);

   ---------------------------------------------------------------------------
   --  Nonce construction
   --
   --  Exposed so that the record-layer tests can check it against RFC 8446
   --  section 5.3 directly rather than only through a round trip, which would
   --  pass even if both directions were wrong the same way.
   ---------------------------------------------------------------------------

   --  RFC 8446 section 5.3: encode the sequence number as a 64-bit big-endian
   --  value, left-pad it with zeroes to the IV's length, and exclusive-or it
   --  with the static IV.
   --  @param Static_IV the per-epoch static IV
   --  @param Sequence  the record sequence number
   --  @return the per-record nonce, the same length as Static_IV
   function Nonce
     (Static_IV : Byte_Array;
      Sequence  : Interfaces.Unsigned_64) return Byte_Array
     with Pre => Static_IV'Length >= 8,
          Post => Nonce'Result'Length = Static_IV'Length;

   ---------------------------------------------------------------------------
   --  Plaintext records
   --
   --  Before the first key is installed, and for the narrow
   --  ChangeCipherSpec window TLS 1.3 permits, records are unprotected.
   ---------------------------------------------------------------------------

   --  Emit an unprotected record.
   --  @param Content   the content type, as it appears in the header
   --  @param Version   the version octet pair for the header
   --  @param Plaintext the fragment
   --  @param Into      out: the whole record
   --  @param Written   out: how many octets hold the record
   --  @param Error     out: No_Error, or a limit failure
   procedure Emit_Plaintext
     (Content   : Content_Type;
      Version   : SSL.Versions.Version_Value;
      Plaintext : Byte_Array;
      Into      : out Byte_Array;
      Written   : out Byte_Index;
      Error     : out SSL.Errors.Error_Information)
     with Pre => Content /= Invalid_Content
                 and then Into'Length >= Header_Length + Plaintext'Length;

private

   --  The largest sequence number that may be used. RFC 8446 section 5.3
   --  forbids wrapping; this library refuses to protect a record at the
   --  ceiling rather than wrapping, and the ceiling is unreachable in practice
   --  because the configured record limits are many orders of magnitude below
   --  it.
   Maximum_Sequence : constant Interfaces.Unsigned_64 := Interfaces.Unsigned_64'Last;

   Maximum_Key_Length : constant Byte_Index := 32;
   Nonce_Length       : constant Byte_Index := 12;

   type Traffic_State is limited record
      Active     : Boolean := False;
      Closed     : Boolean := False;
      Suite      : SSL.Cipher_Suites.Cipher_Suite := SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256;
      Key        : SSL.Secrets.Secret (SSL.Secrets.Traffic_Capacity);
      Static_IV  : Byte_Array (1 .. Nonce_Length) := [others => 0];
      Next       : Interfaces.Unsigned_64 := 0;
      Generation : Natural := 0;
      Records    : Long_Long_Integer := 0;
      Octets     : Long_Long_Integer := 0;
   end record;

end SSL.Records;
