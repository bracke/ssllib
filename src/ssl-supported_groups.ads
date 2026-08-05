with Interfaces;

--  @summary The named groups this library will agree a shared secret over, and
--  ordered lists of them.
--
--  Seven groups: X25519, secp256r1, secp384r1, secp521r1 and the RFC 7919
--  finite-field groups ffdhe2048, ffdhe3072 and ffdhe4096. All are ephemeral;
--  there is no static or anonymous variant of any of them.
--
--  The finite-field groups are offered but not preferred, and are not in the
--  default set. An ffdhe4096 exponentiation is thousands of times the work of
--  an X25519 multiplication for comparable strength, and its key share is 512
--  octets against 32. They are here for peers and policies that require
--  finite-field key exchange, and a caller that does not need them should not
--  enable them.
--
--  ffdhe6144 and ffdhe8192 are implemented by CryptoLib and are deliberately
--  not offered here: the specification's optional set stops at ffdhe4096, and
--  their code points are recognized only so a diagnostic can name what a peer
--  asked for.
--
--  A group's identity, its wire code point and the size of a key share over it
--  are three separate facts. The last of them is what bounds a peer's
--  key_share entry before anything is done with it: a share of the wrong length
--  for the group it claims is rejected on the length alone, before the point is
--  handed to any curve arithmetic.
package SSL.Supported_Groups is
   pragma Preelaborate;

   type Named_Group is
     (X25519,
      Secp256r1,
      Secp384r1,
      Secp521r1,
      FFDHE2048,
      FFDHE3072,
      FFDHE4096);

   --  Which family a group belongs to. The distinction is not cosmetic: a key
   --  share is a curve point for one family and a fixed-width integer for the
   --  other, the validation rules differ, and the sizes differ by an order of
   --  magnitude.
   type Group_Family is (Elliptic_Curve, Finite_Field);

   type Group_Value is new Interfaces.Unsigned_16;

   Secp256r1_Value : constant Group_Value := 23;
   Secp384r1_Value : constant Group_Value := 24;
   Secp521r1_Value : constant Group_Value := 25;
   X25519_Value    : constant Group_Value := 29;

   FFDHE2048_Value : constant Group_Value := 256;
   FFDHE3072_Value : constant Group_Value := 257;
   FFDHE4096_Value : constant Group_Value := 258;

   --  Recognized so a diagnostic can say a peer asked for one of these rather
   --  than reporting a bare number. Not offered; see the note above.
   FFDHE6144_Value : constant Group_Value := 259;
   FFDHE8192_Value : constant Group_Value := 260;

   function Value_Of (Item : Named_Group) return Group_Value;

   --  The group a wire value names, when this library implements it.
   function Group_For (Item : Group_Value; Value : out Named_Group) return Boolean;

   --  Is this a group defined by an RFC but not offered here? Distinguishes
   --  "we do not offer that group" from "we do not know that number".
   function Is_Known_Unoffered (Item : Group_Value) return Boolean;

   --  Which family the group belongs to.
   function Family_Of (Item : Named_Group) return Group_Family;

   --  Octets in a key_share entry for this group.
   --
   --  For X25519 the 32-octet u-coordinate (RFC 8446 section 4.2.8.2); for the
   --  NIST curves the uncompressed point 0x04 || X || Y, so 65, 97 or 133; for
   --  the finite-field groups the value left-padded with zeroes to the length
   --  of p (RFC 8446 section 4.2.8.1), so 256, 384 or 512.
   --
   --  This is what bounds a peer's key_share before any arithmetic sees it: a
   --  share of the wrong length for the group it was offered under is rejected
   --  on the length alone.
   function Share_Length (Item : Named_Group) return Byte_Index
     with Post => Share_Length'Result in 32 | 65 | 97 | 133 | 256 | 384 | 512;

   --  Octets in the shared secret this group produces. For the finite-field
   --  groups this is the width of p, unhashed, which is what TLS 1.3 feeds into
   --  the key schedule.
   function Secret_Length (Item : Named_Group) return Byte_Index
     with Post => Secret_Length'Result in 32 | 48 | 66 | 256 | 384 | 512;

   --  Is this group an elliptic curve rather than a finite field?
   function Is_Elliptic_Curve (Item : Named_Group) return Boolean
     with Post => Is_Elliptic_Curve'Result = (Family_Of (Item) = Elliptic_Curve);

   function Image (Item : Named_Group) return String;
   function Image (Item : Group_Value) return String;

   ---------------------------------------------------------------------------
   --  Ordered group lists
   ---------------------------------------------------------------------------

   Maximum_Groups : constant := 7;

   subtype Group_Count is Natural range 0 .. Maximum_Groups;
   subtype Group_Position is Positive range 1 .. Maximum_Groups;

   type Group_List is private;

   function No_Groups return Group_List
     with Post => Length (No_Groups'Result) = 0;

   --  X25519, P-256, P-384: the required set, in preference order. X25519 first
   --  because it is the fastest and has no invalid-curve or point-validation
   --  pitfalls; P-256 second because it is the most widely deployed; P-384 for
   --  peers whose policy demands it.
   --
   --  The finite-field groups are deliberately absent from the default. A
   --  caller whose policy requires them adds them; a caller who does not need
   --  them should not be paying for a 512-octet key share and a 4096-bit
   --  exponentiation because a default said so.
   function Default_Groups return Group_List
     with Post => Length (Default_Groups'Result) = 3;

   --  The three finite-field groups, in ascending strength, for a caller
   --  assembling a policy that requires them.
   function Finite_Field_Groups return Group_List
     with Post => Length (Finite_Field_Groups'Result) = 3;

   --  The groups a ClientHello sends an actual key share for by default:
   --  X25519 and P-256. Sending a share for every supported group would cost
   --  two more scalar multiplications and 230 more octets on every connection
   --  to save a HelloRetryRequest that almost never happens.
   function Default_Key_Share_Groups return Group_List
     with Post => Length (Default_Key_Share_Groups'Result) = 2;

   function Length (Item : Group_List) return Group_Count;
   function Is_Empty (Item : Group_List) return Boolean;

   function Element (Item : Group_List; Index : Group_Position) return Named_Group
     with Pre => Index <= Length (Item);

   function Contains (Item : Group_List; Value : Named_Group) return Boolean;
   function Position (Item : Group_List; Value : Named_Group) return Group_Count;

   procedure Append (Item : in out Group_List; Value : Named_Group; Ok : out Boolean);

   --  Is every group in Subset also in Item? Used to check that a
   --  configuration's key-share groups are a subset of its supported groups,
   --  which RFC 8446 section 4.2.8 requires.
   function Is_Subset (Subset : Group_List; Item : Group_List) return Boolean;

   function Image (Item : Group_List) return String;

private

   type Group_Array is array (Group_Position) of Named_Group;

   type Group_List is record
      Count : Group_Count := 0;
      Items : Group_Array := [others => X25519];
   end record;

end SSL.Supported_Groups;
