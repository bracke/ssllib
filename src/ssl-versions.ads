with Interfaces;

--  @summary The protocol versions this library speaks, and the sets of them a
--  configuration can enable.
--
--  Two versions exist here and no more. TLS 1.3 is the whole protocol; TLS 1.2
--  is a deliberately restricted subset -- ECDHE and AEAD only, Extended Master
--  Secret mandatory -- kept for peers that cannot yet speak TLS 1.3. SSL 2.0,
--  SSL 3.0, TLS 1.0 and TLS 1.1 are not implemented and are not reachable
--  through any configuration; a peer offering only those is refused with
--  protocol_version.
--
--  The distinction between a version's identity and its wire encoding matters
--  more in TLS 1.3 than it looks. A TLS 1.3 ClientHello puts 0x0303 in the
--  legacy_version field and announces 0x0304 inside supported_versions, and a
--  TLS 1.3 record carries 0x0303 in its header forever. So there are three
--  different questions -- what did we negotiate, what goes in legacy_version,
--  what goes in a record header -- and this package answers them separately
--  rather than letting one value stand in for all three.
package SSL.Versions is
   pragma Preelaborate;

   --  A version this library implements.
   type Protocol_Version is (TLS_1_2, TLS_1_3);

   --  A 16-bit version as it appears on the wire.
   type Version_Value is new Interfaces.Unsigned_16;

   TLS_1_2_Value : constant Version_Value := 16#0303#;
   TLS_1_3_Value : constant Version_Value := 16#0304#;

   --  The value that goes in a TLS 1.3 ClientHello's legacy_version field and
   --  in every TLS 1.3 record header, regardless of what was negotiated
   --  (RFC 8446 sections 4.1.2 and 5.1). It is the TLS 1.2 value, and it is
   --  there for middleboxes, not for version negotiation.
   Legacy_Record_Value : constant Version_Value := 16#0303#;

   --  Values this library recognizes but refuses, kept named so that a
   --  diagnostic can say which obsolete version a peer offered rather than
   --  reporting an unknown number.
   SSL_3_0_Value : constant Version_Value := 16#0300#;
   TLS_1_0_Value : constant Version_Value := 16#0301#;
   TLS_1_1_Value : constant Version_Value := 16#0302#;

   --  The wire value of a version.
   function Value_Of (Item : Protocol_Version) return Version_Value;

   --  The version a wire value names, when this library implements it.
   --  @param Item  the wire value
   --  @param Value out: the version, unchanged when the result is False
   --  @return True when Item is 0x0303 or 0x0304
   function Version_For (Item : Version_Value; Value : out Protocol_Version) return Boolean;

   --  Is this the wire value of a protocol this library deliberately refuses?
   --  Used to tell "obsolete" from "unknown" in a diagnostic.
   --  @param Item the wire value
   --  @return True for SSL 3.0, TLS 1.0 and TLS 1.1
   function Is_Refused_Legacy (Item : Version_Value) return Boolean;

   --  Stable text naming a version, for diagnostics and reports.
   function Image (Item : Protocol_Version) return String;

   --  Stable text naming a wire value, including the refused legacy ones and
   --  unknown numbers.
   function Image (Item : Version_Value) return String;

   ---------------------------------------------------------------------------
   --  Version sets
   --
   --  Immutable and tiny: with two members a set is two Booleans. Kept as a
   --  private type anyway, so that adding a version later does not change any
   --  caller's code.
   ---------------------------------------------------------------------------

   type Version_Set is private;

   --  The empty set. A configuration holding this is invalid.
   function No_Versions return Version_Set;

   --  TLS 1.3 alone: the secure default.
   function TLS_1_3_Only return Version_Set;

   --  TLS 1.3 and the restricted TLS 1.2: the modern-compatibility default.
   --  Enabling TLS 1.2 never changes how TLS 1.3 is negotiated.
   function TLS_1_3_And_1_2 return Version_Set;

   --  A set holding exactly one version.
   function Only (Item : Protocol_Version) return Version_Set;

   --  Is a version in the set?
   function Contains (Item : Version_Set; Value : Protocol_Version) return Boolean;

   --  Add a version. Returns a new set; Version_Set is immutable.
   function Including (Item : Version_Set; Value : Protocol_Version) return Version_Set
     with Post => Contains (Including'Result, Value);

   --  Remove a version. Returns a new set.
   function Excluding (Item : Version_Set; Value : Protocol_Version) return Version_Set
     with Post => not Contains (Excluding'Result, Value);

   --  How many versions are enabled.
   function Count (Item : Version_Set) return Natural
     with Post => Count'Result <= 2;

   function Is_Empty (Item : Version_Set) return Boolean
     with Post => Is_Empty'Result = (Count (Item) = 0);

   --  The highest enabled version, which is the one this endpoint prefers.
   --  Version negotiation in TLS is always highest-common, in both roles.
   --  @param Item the set, which must not be empty
   --  @return TLS 1.3 when enabled, otherwise TLS 1.2
   function Highest (Item : Version_Set) return Protocol_Version
     with Pre => not Is_Empty (Item);

   --  The lowest enabled version.
   function Lowest (Item : Version_Set) return Protocol_Version
     with Pre => not Is_Empty (Item);

   --  Stable text listing the set, for diagnostics: "tls1.3", "tls1.2+tls1.3".
   function Image (Item : Version_Set) return String;

   --  Storage for Ordered_Values. Two entries because there are two versions.
   type Version_Value_Array is array (1 .. 2) of Version_Value;

   --  The set encoded as a supported_versions extension body would list it,
   --  highest first: the order a ClientHello must use.
   --  @param Item the set
   --  @param Into out: receives the wire values, highest first
   --  @param Last out: the last index written; zero for an empty set
   procedure Ordered_Values
     (Item : Version_Set;
      Into : out Version_Value_Array;
      Last : out Natural)
     with Post => Last <= 2;

private

   type Version_Set is record
      Has_1_2 : Boolean := False;
      Has_1_3 : Boolean := False;
   end record;

end SSL.Versions;
