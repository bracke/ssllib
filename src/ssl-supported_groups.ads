with Interfaces;

--  @summary The named groups this library will agree a shared secret over, and
--  ordered lists of them.
--
--  Four groups: X25519, secp256r1, secp384r1 and secp521r1. All are elliptic
--  curve and all are ephemeral. There is no static or anonymous variant, and
--  the finite-field groups of RFC 7919 are absent: CryptoLib provides the SSH
--  MODP groups, not ffdhe2048/3072/4096, and a group this library cannot both
--  implement and test against authoritative vectors is one it does not offer.
--  See docs/known-limitations.md.
--
--  A group's identity, its wire code point and the size of a key share over it
--  are three separate facts. The last of them is what bounds a peer's
--  key_share entry before anything is done with it: a share of the wrong length
--  for the group it claims is rejected on the length alone, before the point is
--  handed to any curve arithmetic.
package SSL.Supported_Groups is
   pragma Preelaborate;

   type Named_Group is (X25519, Secp256r1, Secp384r1, Secp521r1);

   type Group_Value is new Interfaces.Unsigned_16;

   Secp256r1_Value : constant Group_Value := 23;
   Secp384r1_Value : constant Group_Value := 24;
   Secp521r1_Value : constant Group_Value := 25;
   X25519_Value    : constant Group_Value := 29;

   --  Recognized so a diagnostic can say a peer asked for a finite-field group
   --  this release does not implement, rather than reporting a bare number.
   FFDHE2048_Value : constant Group_Value := 256;
   FFDHE3072_Value : constant Group_Value := 257;
   FFDHE4096_Value : constant Group_Value := 258;

   function Value_Of (Item : Named_Group) return Group_Value;

   --  The group a wire value names, when this library implements it.
   function Group_For (Item : Group_Value; Value : out Named_Group) return Boolean;

   --  Is this a group defined by an RFC but not implemented here? Distinguishes
   --  "we do not do that group" from "we do not know that number".
   function Is_Known_Unimplemented (Item : Group_Value) return Boolean;

   --  Octets in a key_share entry for this group: 32 for X25519 (RFC 8446
   --  section 4.2.8.2), and the uncompressed point 0x04 || X || Y for the NIST
   --  curves, so 65, 97 and 133 octets.
   function Share_Length (Item : Named_Group) return Byte_Index
     with Post => Share_Length'Result in 32 | 65 | 97 | 133;

   --  Octets in the shared secret this group produces.
   function Secret_Length (Item : Named_Group) return Byte_Index
     with Post => Secret_Length'Result in 32 | 48 | 66;

   --  Is this group an elliptic curve rather than a finite field? True for all
   --  four; the question exists so the record of what the code assumes is in
   --  the code and not only in a comment.
   function Is_Elliptic_Curve (Item : Named_Group) return Boolean
     with Post => Is_Elliptic_Curve'Result;

   function Image (Item : Named_Group) return String;
   function Image (Item : Group_Value) return String;

   ---------------------------------------------------------------------------
   --  Ordered group lists
   ---------------------------------------------------------------------------

   Maximum_Groups : constant := 4;

   subtype Group_Count is Natural range 0 .. Maximum_Groups;
   subtype Group_Position is Positive range 1 .. Maximum_Groups;

   type Group_List is private;

   function No_Groups return Group_List
     with Post => Length (No_Groups'Result) = 0;

   --  X25519, P-256, P-384: the required set, in preference order. X25519 first
   --  because it is the fastest and has no invalid-curve or point-validation
   --  pitfalls; P-256 second because it is the most widely deployed; P-384 for
   --  peers whose policy demands it.
   function Default_Groups return Group_List
     with Post => Length (Default_Groups'Result) = 3;

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
