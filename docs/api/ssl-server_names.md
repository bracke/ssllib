# ssl-server_names

Generated from `src/ssl-server_names.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

Validated DNS names for SNI, for the identity a client expects to
authenticate, and for a server's credential routing.

Three things are commonly conflated and are kept apart here, because
conflating them is how a client ends up authenticating a name it did not
intend to reach:

* the transport destination -- the host and port the caller connected to.
This library never sees it and never derives anything from it.
* the routing name -- what goes in the server_name extension, so that a
server hosting many names can choose a credential. It is a hint, and it
is not authenticated.
* the expected identity -- the name the presented certificate must match.
This is the only one that decides anything about trust.

They are usually the same string. When they are not -- a connection through
a proxy, a pinned service reached by address, a test against a staging host
-- the caller must be able to say so, and a library that derives all three
from one parameter cannot express it.

A name here is a normalized ASCII A-label form: lower case, no trailing dot,
no IP literal. Case folding is done against the ASCII range only and never
through a locale-sensitive routine, because a Turkish locale folds "I"
differently and a hostname comparison must not depend on the process locale.

Internationalized names must be converted to A-label form (RFC 5890) by the
caller before they reach this package. This library does not implement IDNA:
doing it correctly needs Unicode tables, and doing it incorrectly is a
security bug. Names that are already A-labels -- which is what a resolver
handed the caller -- pass through unchanged. See docs/alpn-sni.md.

A validated DNS name.

```ada
type DNS_Name is private;
```

The absent name, for a connection with no SNI and no expected DNS
identity.

```ada
function No_Name return DNS_Name;
```

```ada
function Is_Present (Item : DNS_Name) return Boolean;
```

Why a name was refused.

```ada
type Name_Status is
  (Ok,
   Empty_Name,
   Too_Long,
   Empty_Label,
   Label_Too_Long,
   Invalid_Character,
   Leading_Or_Trailing_Hyphen,
   Looks_Like_IP_Address,
   Not_ASCII,
   Wildcard_Not_Permitted,
   Wildcard_Not_Leftmost,
   Wildcard_Label_Not_Alone,
   Too_Few_Labels_For_Wildcard);
```

```ada
function Image (Item : Name_Status) return String;
```

Parse and normalize a DNS name.

Accepts letters, digits, hyphen and dot; lower-cases ASCII letters;
removes a single trailing dot. Refuses an IP address literal, because an
address is not a DNS name and putting one in SNI is forbidden by RFC 6066
section 3 -- a caller wanting to authenticate an address uses
Expected_IP_Address instead.
@param Text   the name as text
@param Item   out: the normalized name, No_Name on refusal
@param Status out: Ok, or why it was refused

```ada
procedure Parse (Text : String; Item : out DNS_Name; Status : out Name_Status);
```

Parse a name that may be a leftmost wildcard, for a server's credential
routing table and for a pin scope. "*.example.com" is accepted;
"*.com" is not (too few labels), "a*.example.com" is not (the wildcard
label must be exactly "*"), and "www.*.example.com" is not (not
leftmost). These are the restrictions that keep a wildcard from matching
more than the operator meant.
@param Text   the pattern as text
@param Item   out: the normalized pattern, No_Name on refusal
@param Status out: Ok, or why it was refused

```ada
procedure Parse_Pattern (Text : String; Item : out DNS_Name; Status : out Name_Status);
```

Parse, raising on refusal. For literals in program text and examples.

```ada
function Name (Text : String) return DNS_Name;
```

The normalized text.

```ada
function Image (Item : DNS_Name) return String
  with Post => Image'Result'Length <= Maximum_Name_Length;
```

The normalized text as octets, which is what goes in the server_name
extension.

```ada
function Octets (Item : DNS_Name) return Byte_Array
  with Post => Octets'Result'Length <= Maximum_Name_Length;
```

```ada
function Length (Item : DNS_Name) return Natural
  with Post => Length'Result <= Maximum_Name_Length;
```

Is this a wildcard pattern rather than an exact name?

```ada
function Is_Wildcard (Item : DNS_Name) return Boolean;
```

How many labels the name has. Used to order wildcard patterns by
specificity, so that "*.a.example.com" is preferred over "*.example.com".

```ada
function Label_Count (Item : DNS_Name) return Natural;
```

Exact equality of normalized names. Both sides are already lower case, so
this is octet equality and no folding happens here.

```ada
function "=" (Left, Right : DNS_Name) return Boolean;
```

Does Candidate match Pattern?

For an exact pattern this is equality. For a wildcard pattern the
wildcard replaces exactly one label, and only the leftmost: RFC 6125
section 6.4.3. A wildcard never matches a name with fewer labels, never
matches across a dot, and never matches the bare parent domain.
@param Candidate the name being checked
@param Pattern   the exact name or wildcard pattern
@return True when Candidate is covered by Pattern

```ada
function Matches (Candidate : DNS_Name; Pattern : DNS_Name) return Boolean;
```

How specific a match is, for choosing between several patterns that all
match. Higher is more specific: an exact match beats any wildcard, and a
wildcard with more labels beats one with fewer. Zero means no match.
@param Candidate the name being checked
@param Pattern   the exact name or wildcard pattern
@return the specificity, or zero when Pattern does not match

```ada
function Match_Specificity (Candidate : DNS_Name; Pattern : DNS_Name) return Natural;
```

Would this text be accepted as a DNS name? A convenience for validating
configuration without building a name.

```ada
function Is_Valid_Name (Text : String) return Boolean;
```

-------------------------------------------------------------------------
IP identities

A client may expect to authenticate an IP address rather than a DNS name,
which the certificate answers through an iPAddress subjectAltName. An
address is never sent in SNI.
-------------------------------------------------------------------------

A binary IP address: four octets for IPv4, sixteen for IPv6, which is the
form an iPAddress subjectAltName holds.

```ada
type IP_Address is private;
```

```ada
function No_Address return IP_Address;
```

```ada
function Is_Present (Item : IP_Address) return Boolean;
```

Build an address from its binary octets.
@param Value four or sixteen octets
@param Item  out: the address, No_Address on refusal
@return True when Value was four or sixteen octets

```ada
function Make_Address (Value : Byte_Array; Item : out IP_Address) return Boolean;
```

Parse a dotted-quad IPv4 address or a colon-form IPv6 address.
@param Text the address as text
@param Item out: the address, No_Address on refusal
@return True when Text was a valid literal

```ada
function Parse_Address (Text : String; Item : out IP_Address) return Boolean;
```

The binary octets, as an iPAddress subjectAltName holds them.

```ada
function Octets (Item : IP_Address) return Byte_Array
  with Post => Octets'Result'Length in 0 | 4 | 16;
```

Text form, for diagnostics.

```ada
function Image (Item : IP_Address) return String;
```

```ada
function "=" (Left, Right : IP_Address) return Boolean;
```

Does this text look like an IP address literal? Used by Parse to refuse
one as a DNS name.

```ada
function Looks_Like_Address (Text : String) return Boolean;
```


