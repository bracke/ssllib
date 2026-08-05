# ssl-alerts

Generated from `src/ssl-alerts.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

TLS alerts: the two-octet message that says a connection is over
and, at most, why.

An alert is the only diagnostic a peer ever receives, and it is a narrow
one on purpose: the descriptions are a closed set chosen so that a
determined attacker learns as little as possible from the difference
between them. This library maps every internal failure through one central
table (see SSL.Errors) rather than choosing an alert at each failure site,
because a bespoke alert per site is how implementations grow oracles.

In TLS 1.3 every alert is fatal except close_notify and user_canceled. The
warning/fatal level octet still travels, and this library sends the level
the protocol requires, but it does not act on a peer's claim that a fatal
condition was only a warning.

The wire value of an alert description, kept as a number rather than an
enumeration position so that a peer's unknown description survives
unmodified into a diagnostic. RFC 8446 section 6.

```ada
type Alert_Value is new Interfaces.Unsigned_8;
```

The alert level octet.

```ada
type Alert_Level is (Warning_Level, Fatal_Level);
```

The descriptions this library recognizes. Unknown_Alert is not a wire
value: it is what a received description that is not in this set maps
to, and the numeric value is preserved alongside it.

```ada
type Alert_Description is
  (Close_Notify,
   Unexpected_Message,
   Bad_Record_MAC,
   Record_Overflow,
   Handshake_Failure,
   Bad_Certificate,
   Unsupported_Certificate,
   Certificate_Revoked,
   Certificate_Expired,
   Certificate_Unknown,
   Illegal_Parameter,
   Unknown_CA,
   Access_Denied,
   Decode_Error,
   Decrypt_Error,
   Protocol_Version,
   Insufficient_Security,
   Internal_Error,
   Inappropriate_Fallback,
   User_Canceled,
   Missing_Extension,
   Unsupported_Extension,
   Unrecognized_Name,
   Bad_Certificate_Status_Response,
   Unknown_PSK_Identity,
   Certificate_Required,
   No_Application_Protocol,
   Unknown_Alert);
```

A received or generated alert as a value: what it says, what it says on
the wire, and at what level. Immutable.

```ada
type Alert is private;
```

The alert that means nothing has gone wrong and nothing was sent.

```ada
function No_Alert return Alert;
```

Was an alert actually generated or received?
@param Item the alert to test
@return True when Item names a real alert

```ada
function Is_Present (Item : Alert) return Boolean;
```

Build an alert this endpoint will send. The level follows the protocol:
close_notify and user_canceled are warnings, everything else is fatal.
@param Description which alert to send
@return the alert value

```ada
function Local_Alert (Description : Alert_Description) return Alert
  with Pre => Description /= Unknown_Alert;
```

Interpret an alert received from a peer, preserving its numeric
description even when this library does not recognize it.
@param Level_Octet       the level octet as received
@param Description_Octet the description octet as received
@return the alert, with Description = Unknown_Alert for an unrecognized
description and Value carrying what the peer actually sent

```ada
function Peer_Alert (Level_Octet : Byte; Description_Octet : Byte) return Alert;
```

What the alert says, or Unknown_Alert.
@param Item the alert to inspect
@return the recognized description

```ada
function Description_Of (Item : Alert) return Alert_Description;
```

The description octet as it appeared or will appear on the wire. For an
unrecognized peer alert this is the only faithful account of it.
@param Item the alert to inspect
@return the wire value

```ada
function Value_Of (Item : Alert) return Alert_Value;
```

The level octet as it appeared or will appear on the wire.
@param Item the alert to inspect
@return Warning_Level or Fatal_Level

```ada
function Level_Of (Item : Alert) return Alert_Level;
```

Does this alert end the connection?

True for everything except close_notify and user_canceled, regardless of
the level octet the peer chose: in TLS 1.3 a peer claiming that
handshake_failure was only a warning does not make it survivable, and
treating it as one is how an implementation is talked into continuing
without keys it should have.
@param Item the alert to test
@return True when the connection must terminate

```ada
function Is_Terminal (Item : Alert) return Boolean;
```

Did the peer close cleanly?
@param Item the alert to test
@return True for close_notify

```ada
function Is_Close_Notify (Item : Alert) return Boolean;
```

The two octets of the alert message body, in wire order.
@param Item the alert to encode
@return level octet then description octet

```ada
function Encode (Item : Alert) return Byte_Array
  with Pre => Is_Present (Item), Post => Encode'Result'Length = 2;
```

Stable lower-case text naming a description, for diagnostics. An
unrecognized peer description renders as "alert_<number>" so that the
number is not lost.
@param Item the alert to name
@return the name, never empty

```ada
function Image (Item : Alert) return String;
```

Stable lower-case text for a recognized description.
@param Description the description to name
@return the RFC name in lower case

```ada
function Image (Description : Alert_Description) return String;
```

Map a wire description octet to the description this library
recognizes, or Unknown_Alert.
@param Item the wire value
@return the recognized description or Unknown_Alert

```ada
function Description_For (Item : Alert_Value) return Alert_Description;
```

The wire value of a recognized description.
@param Description the description to encode
@return the wire value

```ada
function Value_For (Description : Alert_Description) return Alert_Value
  with Pre => Description /= Unknown_Alert;
```


