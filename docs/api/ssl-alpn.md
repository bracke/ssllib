# ssl-alpn

Generated from `src/ssl-alpn.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

Application-Layer Protocol Negotiation names and the policy for
choosing between them.

An ALPN protocol name is an opaque byte string of 1 to 255 octets
(RFC 7301 section 3.1). It is not text: this library makes no UTF-8
assumption about it, does no case folding, and compares octets. "h2" and
"H2" are different protocols, and a library that treated them as the same
would negotiate a protocol the peer did not offer.

Order is preference order and is preserved exactly. Duplicates are refused
at configuration time rather than ignored, because a duplicate changes
nothing about the outcome and hides a mistake in the list the operator
wrote.

A selected protocol is bound into any session established under it, and a
session is never resumed under a different one -- see SSL.Sessions. That
matters because the application above has already dispatched on the protocol
by the time resumption is considered.

One protocol name.

```ada
type Protocol_Name is private;
```

The absent name, for "no protocol was negotiated".

```ada
function No_Protocol return Protocol_Name;
```

```ada
function Is_Present (Item : Protocol_Name) return Boolean;
```

Build a name from octets.
@param Value the octets, 1 .. 255 of them
@param Item  out: the name, No_Protocol when the length is out of range
@return True when Value was an acceptable length

```ada
function Make (Value : Byte_Array; Item : out Protocol_Name) return Boolean;
```

Build a name from a String, for the common case of a name whose octets
are ASCII: "h2", "http/1.1", "imap", "smtp". The String's characters are
taken as octets with no encoding conversion, so a character above 127 is
refused rather than silently encoded.
@param Value the characters, 1 .. 255 of them, all below 128
@param Item  out: the name, No_Protocol on refusal
@return True when Value was acceptable

```ada
function Make (Value : String; Item : out Protocol_Name) return Boolean;
```

Same as Make from a String but raising on a bad literal, for use in
constant declarations and examples where the name is a literal the
programmer controls. This is a programming-contract violation, not an
ordinary failure, which is why it is allowed to raise.
@param Value the characters, 1 .. 255 of them, all below 128
@return the name

```ada
function Protocol (Value : String) return Protocol_Name
  with Pre => Value'Length in 1 .. 255;
```

The name's octets.

```ada
function Value_Of (Item : Protocol_Name) return Byte_Array
  with Post => Value_Of'Result'Length <= Maximum_Name_Length;
```

```ada
function Length (Item : Protocol_Name) return Byte_Index
  with Post => Length'Result <= Maximum_Name_Length;
```

Octet equality. Names are compared as octets, never case-folded.

```ada
function "=" (Left, Right : Protocol_Name) return Boolean;
```

A rendering safe for a log: the octets when they are all printable ASCII,
otherwise a hexadecimal form. A protocol name comes from the peer in the
server role, so it must not be pasted into a log unescaped.

```ada
function Image (Item : Protocol_Name) return String;
```

```ada
subtype Protocol_Count is Natural range 0 .. Maximum_Protocols;
```

```ada
subtype Protocol_Position is Positive range 1 .. Maximum_Protocols;
```

```ada
type Protocol_List is private;
```

```ada
function No_Protocols return Protocol_List
  with Post => Length (No_Protocols'Result) = 0;
```

```ada
function Length (Item : Protocol_List) return Protocol_Count;
```

```ada
function Is_Empty (Item : Protocol_List) return Boolean;
```

```ada
function Element (Item : Protocol_List; Index : Protocol_Position) return Protocol_Name
  with Pre => Index <= Length (Item);
```

```ada
function Contains (Item : Protocol_List; Value : Protocol_Name) return Boolean;
```

```ada
function Position (Item : Protocol_List; Value : Protocol_Name) return Protocol_Count;
```

Append a name.
@param Item  the list
@param Value the name to append
@param Ok    out: False when Value is absent, already present, or the
list is full

```ada
procedure Append (Item : in out Protocol_List; Value : Protocol_Name; Ok : out Boolean);
```

Comma-separated safe images, for diagnostics.

```ada
function Image (Item : Protocol_List) return String;
```

-------------------------------------------------------------------------
Policy
-------------------------------------------------------------------------

Whether a protocol must be agreed.

Not_Offered: the extension is not sent and not honoured.
Optional: offered, and a handshake with no overlap continues with no
protocol selected.
Required: offered, and a handshake with no overlap fails with
no_application_protocol. This is the right setting whenever the
application above cannot serve an unknown protocol, which is most of
the time and is why it is worth stating explicitly.

```ada
type ALPN_Requirement is (Not_Offered, Optional, Required);
```

How a server picks from the overlap.

Server_Order: walk the server's list and take the first the client also
offered. The server's policy wins, which is what an operator who
ordered the list meant.
Client_Order: walk the client's list and take the first the server also
offers. RFC 7301 permits either.
Application_Selector: hand both lists to the application.

```ada
type Selection_Policy is (Server_Order, Client_Order, Application_Selector);
```

Choose a protocol by list order.
@param Policy      Server_Order or Client_Order
@param Server_List the server's configured list, in its own order
@param Client_List the client's offered list, in its order
@param Selected    out: the chosen name, No_Protocol when there is no
overlap
@return True when a protocol was chosen

```ada
function Select_Protocol
  (Policy      : Selection_Policy;
   Server_List : Protocol_List;
   Client_List : Protocol_List;
   Selected    : out Protocol_Name) return Boolean
  with Pre => Policy /= Application_Selector;
```

Is this policy internally consistent?

Required with an empty list is the one combination that cannot work: it
asks for a protocol to be agreed and offers none, so every handshake
would fail. Refused at configuration time rather than at the first
connection.
@param Requirement what the policy demands
@param Item        the configured list
@return True when the pair is usable

```ada
function Is_Valid_Policy (Requirement : ALPN_Requirement; Item : Protocol_List) return Boolean;
```


