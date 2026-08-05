# ssl-versions

Generated from `src/ssl-versions.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

The protocol versions this library speaks, and the sets of them a
configuration can enable.

Two versions exist here and no more. TLS 1.3 is the whole protocol; TLS 1.2
is a deliberately restricted subset -- ECDHE and AEAD only, Extended Master
Secret mandatory -- kept for peers that cannot yet speak TLS 1.3. SSL 2.0,
SSL 3.0, TLS 1.0 and TLS 1.1 are not implemented and are not reachable
through any configuration; a peer offering only those is refused with
protocol_version.

The distinction between a version's identity and its wire encoding matters
more in TLS 1.3 than it looks. A TLS 1.3 ClientHello puts 0x0303 in the
legacy_version field and announces 0x0304 inside supported_versions, and a
TLS 1.3 record carries 0x0303 in its header forever. So there are three
different questions -- what did we negotiate, what goes in legacy_version,
what goes in a record header -- and this package answers them separately
rather than letting one value stand in for all three.

A version this library implements.

```ada
type Protocol_Version is (TLS_1_2, TLS_1_3);
```

A 16-bit version as it appears on the wire.

```ada
type Version_Value is new Interfaces.Unsigned_16;
```

The wire value of a version.

```ada
function Value_Of (Item : Protocol_Version) return Version_Value;
```

The version a wire value names, when this library implements it.
@param Item  the wire value
@param Value out: the version, unchanged when the result is False
@return True when Item is 0x0303 or 0x0304

-------------------------------------------------------------------------
Downgrade sentinels
-------------------------------------------------------------------------

RFC 8446 section 4.1.3: a server that supports TLS 1.3 but negotiates
something older writes one of these into the last eight octets of its
ServerHello random. A client that supports TLS 1.3 and sees one after
negotiating the older version knows an attacker removed 1.3 from its
offer, because a genuine older server could not have produced it.

The sentinel is the one anti-downgrade mechanism in the protocol that
works without either end having to remember anything, and it costs a
comparison. It is written out here rather than derived, because these
are opaque constants the specification fixes.

```ada
subtype Downgrade_Sentinel is Byte_Array (1 .. 8);
```

Does this ServerHello random end in a downgrade sentinel?
@param Random_Value the 32 random octets as they arrived
@return True when the last eight octets are either sentinel

```ada
function Has_Downgrade_Sentinel (Random_Value : Byte_Array) return Boolean
  with Pre => Random_Value'Length = 32;
```

```ada
function Version_For (Item : Version_Value; Value : out Protocol_Version) return Boolean;
```

Is this the wire value of a protocol this library deliberately refuses?
Used to tell "obsolete" from "unknown" in a diagnostic.
@param Item the wire value
@return True for SSL 3.0, TLS 1.0 and TLS 1.1

```ada
function Is_Refused_Legacy (Item : Version_Value) return Boolean;
```

Stable text naming a version, for diagnostics and reports.

```ada
function Image (Item : Protocol_Version) return String;
```

Stable text naming a wire value, including the refused legacy ones and
unknown numbers.

```ada
function Image (Item : Version_Value) return String;
```

-------------------------------------------------------------------------
Version sets

Immutable and tiny: with two members a set is two Booleans. Kept as a
private type anyway, so that adding a version later does not change any
caller's code.
-------------------------------------------------------------------------


```ada
type Version_Set is private;
```

The empty set. A configuration holding this is invalid.

```ada
function No_Versions return Version_Set;
```

TLS 1.3 alone: the secure default.

```ada
function TLS_1_3_Only return Version_Set;
```

TLS 1.3 and the restricted TLS 1.2: the modern-compatibility default.
Enabling TLS 1.2 never changes how TLS 1.3 is negotiated.

```ada
function TLS_1_3_And_1_2 return Version_Set;
```

A set holding exactly one version.

```ada
function Only (Item : Protocol_Version) return Version_Set;
```

Is a version in the set?

```ada
function Contains (Item : Version_Set; Value : Protocol_Version) return Boolean;
```

Add a version. Returns a new set; Version_Set is immutable.

```ada
function Including (Item : Version_Set; Value : Protocol_Version) return Version_Set
  with Post => Contains (Including'Result, Value);
```

Remove a version. Returns a new set.

```ada
function Excluding (Item : Version_Set; Value : Protocol_Version) return Version_Set
  with Post => not Contains (Excluding'Result, Value);
```

How many versions are enabled.

```ada
function Count (Item : Version_Set) return Natural
  with Post => Count'Result <= 2;
```

```ada
function Is_Empty (Item : Version_Set) return Boolean
  with Post => Is_Empty'Result = (Count (Item) = 0);
```

The highest enabled version, which is the one this endpoint prefers.
Version negotiation in TLS is always highest-common, in both roles.
@param Item the set, which must not be empty
@return TLS 1.3 when enabled, otherwise TLS 1.2

```ada
function Highest (Item : Version_Set) return Protocol_Version
  with Pre => not Is_Empty (Item);
```

The lowest enabled version.

```ada
function Lowest (Item : Version_Set) return Protocol_Version
  with Pre => not Is_Empty (Item);
```

Stable text listing the set, for diagnostics: "tls1.3", "tls1.2+tls1.3".

```ada
function Image (Item : Version_Set) return String;
```

Storage for Ordered_Values. Two entries because there are two versions.

```ada
type Version_Value_Array is array (1 .. 2) of Version_Value;
```

The set encoded as a supported_versions extension body would list it,
highest first: the order a ClientHello must use.
@param Item the set
@param Into out: receives the wire values, highest first
@param Last out: the last index written; zero for an empty set

```ada
procedure Ordered_Values
  (Item : Version_Set;
   Into : out Version_Value_Array;
   Last : out Natural)
  with Post => Last <= 2;
```


