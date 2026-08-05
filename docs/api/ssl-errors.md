# ssl-errors

Generated from `src/ssl-errors.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

Structured failure information: the value every ordinary failure
in this library is reported as.

Ordinary failures are results, not exceptions. Transport trouble, malformed
peer input, a negotiation with no overlap, a certificate that does not
validate, a deadline, a cancellation, a limit, a session that cannot be
used -- all of these are things a correct program must handle, and a
correct program should not have to write an exception handler to find out
that they happened. Exceptions in this library are for programming-contract
violations, for internal states that cannot occur, and for the Ada stream
interface, which has no other way to report failure.

An Error_Information is immutable and self-contained: it holds no pointer,
no view into a connection, and nothing that stops being valid when the
connection is finalized. It can be stored, compared, logged and returned
from a task other than the one that produced it.

Every error carries a disclosure classification, because the same failure
needs three different accounts of itself: what may be sent to the peer as
an alert, what an operator may see in a log, and what must not leave the
process at all. Nothing in this record is a secret, and the classification
says how much of it may be rendered where.

-------------------------------------------------------------------------
Classification
-------------------------------------------------------------------------

The stable family a failure belongs to. An application switching on
this gets behaviour that survives new error codes being added within a
family.

```ada
type Error_Category is
  (No_Failure,
   Configuration,        --  the local setup is unusable, before any bytes
   Transport,            --  the caller's transport failed or ended
   Record_Layer,         --  a record could not be parsed or authenticated
   Protocol,             --  a message arrived that the state machine forbids
   Negotiation,          --  no overlap in version, suite, group or protocol
   Cryptographic,        --  a primitive refused or a verification failed
   Certificate,          --  a chain could not be decoded or validated
   Identity,             --  the chain is valid but not for this name
   Revocation,           --  revocation policy was not satisfied
   Pinning,              --  a pin was configured and not met
   Session,              --  a ticket or cached session could not be used
   Resource,             --  a configured bound was reached
   Deadline,             --  a caller-supplied deadline passed
   Cancellation,         --  the caller cancelled
   Application_Policy,   --  an application callback said no
   Provider,             --  an external signer or provider failed
   Internal);            --  an invariant this library holds did not hold

--  A stable numeric code. Explicit values, never enumeration positions:
--  these appear in logs and in machine-readable release reports, and a
--  reordering of a type declaration must not renumber them.
type Error_Code is new Interfaces.Unsigned_32;
```

Where the failure was decided. This is what separates "the peer sent
something wrong" from "we are configured wrong" in a log, and the two
read identically without it.

```ada
type Error_Origin is
  (No_Origin,
   Local_Policy,          --  this endpoint's configuration refused
   Local_Implementation,  --  this endpoint's own code refused
   Peer_Message,          --  something the peer sent
   Peer_Alert,            --  an alert the peer sent
   Caller_Transport,      --  the transport the caller supplied
   Caller_Request,        --  the call the caller made
   Application_Callback,  --  an application-supplied decision or hook
   External_Provider);    --  an external signer, cache or OCSP provider

--  Whether trying again could work, and at what granularity. A caller
--  looping on a transport hiccup and a caller reconnecting after a session
--  went stale need different answers, and guessing from the category is
--  how retry storms start.
type Retry_Class is
  (Not_Retryable,
   Retry_Same_Connection,        --  transient: call again on this connection
   Retry_New_Connection,         --  this connection is finished; a new one may work
   Retry_After_Reconfiguration); --  nothing will work until the setup changes

--  How much of this error may be shown, and to whom.
type Disclosure_Class is
  (Safe_For_Peer,     --  the alert already says this much
   Operator_Only,     --  fine in a local log, not on the wire
   Restricted);       --  may reveal timing or content structure; log the code only

--  The connection lifecycle stage the failure was detected in. Recorded so
--  that a log line does not have to be correlated with another to know
--  whether the handshake had finished.
type Lifecycle_Stage is
  (Stage_Uninitialized,
   Stage_Ready,
   Stage_Handshaking,
   Stage_Established,
   Stage_Closing,
   Stage_Closed,
   Stage_Failed);
```

```ada
subtype Parameter_Count is Natural range 0 .. Maximum_Parameters;
```

```ada
subtype Parameter_Index is Positive range 1 .. Maximum_Parameters;
```

```ada
type Parameter_Kind is (Numeric, Text);
```

One named fact about a failure.

```ada
type Parameter is private;
```

Build a numeric parameter.
@param Name  short stable name, truncated at Parameter_Name_Limit
@param Value the number
@return the parameter

```ada
function Numeric_Parameter (Name : String; Value : Long_Long_Integer) return Parameter;
```

Build a text parameter. The text is truncated at Parameter_Text_Limit,
and must never be secret: parameters are rendered wherever the error is.
@param Name  short stable name
@param Value the text
@return the parameter

```ada
function Text_Parameter (Name : String; Value : String) return Parameter;
```

```ada
function Name_Of (Item : Parameter) return String;
```

```ada
function Kind_Of (Item : Parameter) return Parameter_Kind;
```

```ada
function Number_Of (Item : Parameter) return Long_Long_Integer
  with Pre => Kind_Of (Item) = Numeric;
```

```ada
function Text_Of (Item : Parameter) return String
  with Pre => Kind_Of (Item) = Text;
```

```ada
type Parameter_List is array (Parameter_Index range <>) of Parameter;
```

The empty list, for a failure that needs no facts attached. A function
rather than a constant because Parameter is private here and a deferred
constant of a visible array type is not the clearer spelling.

```ada
function No_Parameters return Parameter_List
  with Post => No_Parameters'Result'Length = 0;
```

-------------------------------------------------------------------------
The error value
-------------------------------------------------------------------------


```ada
type Error_Information is private;
```

Success. The value every out parameter starts at.

```ada
function No_Error return Error_Information;
```

Did something go wrong?
@param Item the value to test
@return True when Item describes a failure

```ada
function Is_Error (Item : Error_Information) return Boolean;
```

Is this failure terminal for the connection?

A non-fatal error is one a caller may act on and continue with: a
Would_Block that surfaced as a deadline, a session that could not be
resumed. A fatal one has ended the connection.
@param Item the value to test
@return True when the connection cannot continue

```ada
function Is_Fatal (Item : Error_Information) return Boolean;
```

```ada
function Category_Of (Item : Error_Information) return Error_Category;
```

```ada
function Code_Of (Item : Error_Information) return Error_Code;
```

```ada
function Origin_Of (Item : Error_Information) return Error_Origin;
```

```ada
function Retry_Of (Item : Error_Information) return Retry_Class;
```

```ada
function Disclosure_Of (Item : Error_Information) return Disclosure_Class;
```

```ada
function Stage_Of (Item : Error_Information) return Lifecycle_Stage;
```

The alert this failure maps to, if any. Central mapping: no failure site
chooses its own alert, so the set of alerts a peer can observe is a
property of one table rather than of a hundred call sites.
@param Item the failure
@return the alert, or SSL.Alerts.No_Alert when none is to be sent

```ada
function Alert_Of (Item : Error_Information) return SSL.Alerts.Alert;
```

The connection this failure belongs to, when it was known.

```ada
function Connection_Of (Item : Error_Information) return Connection_ID;
```

Bounded facts about the failure.

```ada
function Parameter_Count_Of (Item : Error_Information) return Parameter_Count;
```

```ada
function Parameter_At (Item : Error_Information; Index : Parameter_Index) return Parameter
  with Pre => Index <= Parameter_Count_Of (Item);
```

Free-form provider or callback text, when the failure came from outside
this library and the outside said something. Bounded and never secret.

```ada
function Provider_Text (Item : Error_Information) return String;
```

A stable one-line rendering for an operator log: category, code, origin
and the parameters permitted by the disclosure class. Never includes key
material, plaintext, or anything a Restricted error is holding back.
@param Item the failure
@return the line, without a trailing newline

```ada
function Image (Item : Error_Information) return String;
```

The account of this failure that is safe to give the peer: the alert
name and nothing else.
@param Item the failure
@return the alert name, or "none"

```ada
function Peer_Image (Item : Error_Information) return String;
```

Short stable text naming a category, for logs and reports.

```ada
function Image (Category : Error_Category) return String;
```

```ada
function Image (Origin : Error_Origin) return String;
```

```ada
function Image (Retry : Retry_Class) return String;
```

```ada
function Image (Disclosure : Disclosure_Class) return String;
```

```ada
function Image (Stage : Lifecycle_Stage) return String;
```

-------------------------------------------------------------------------
Construction

Callers build errors for the two cases where the failure is theirs to
report: an application callback that refuses, and an external provider
that fails. Everything else is built inside the library.
-------------------------------------------------------------------------

Build a failure. The alert, fatality, retry class and disclosure class
are looked up from Code in the central table, so that two sites
reporting the same code cannot disagree about what the peer is told.
@param Code       which failure
@param Origin     where it was decided
@param Stage      the lifecycle stage it was detected in
@param Connection the connection it belongs to, or No_Connection
@param Parameters bounded facts, at most Maximum_Parameters
@param Provider   bounded provider text, or empty
@return the failure value

```ada
function Make
  (Code       : Error_Code;
   Origin     : Error_Origin;
   Stage      : Lifecycle_Stage := Stage_Uninitialized;
   Connection : Connection_ID := No_Connection;
   Parameters : Parameter_List := No_Parameters;
   Provider   : String := "") return Error_Information
  with Pre => Code /= Code_None;
```

An application callback refusing. Use this from an ALPN selector, a
certificate decision hook or a session-cache implementation to say no in
a way the engine can act on.
@param Reason short operator-facing text, bounded, never secret
@return the failure value

```ada
function Application_Refusal (Reason : String) return Error_Information;
```

An external provider failing: a signer that could not sign, a cache that
could not answer.
@param Reason short operator-facing text, bounded, never secret
@param Fatal  True when the connection cannot continue without it
@return the failure value

```ada
function Provider_Failure (Reason : String; Fatal : Boolean := True) return Error_Information;
```

A configured bound was reached. Recorded with the limit's stable name,
the bound and what was asked for, because "too large" without those
three is not actionable.
@param Kind      which limit
@param Allowed   the configured bound
@param Requested what was asked for
@param Origin    where the oversize value came from
@param Stage     the lifecycle stage
@return the failure value

```ada
function Limit_Failure
  (Kind      : SSL.Limits.Limit_Kind;
   Allowed   : Long_Long_Integer;
   Requested : Long_Long_Integer;
   Origin    : Error_Origin := Peer_Message;
   Stage     : Lifecycle_Stage := Stage_Handshaking) return Error_Information;
```

Attach the connection identity to a failure built before the connection
was known. Returns a new value; Error_Information is immutable.
@param Item       the failure
@param Connection the connection
@return the failure with the connection recorded

```ada
function With_Connection (Item : Error_Information; Connection : Connection_ID)
  return Error_Information;
```

Attach the lifecycle stage to a failure built before the stage was
known. Returns a new value.
@param Item  the failure
@param Stage the stage
@return the failure with the stage recorded

```ada
function With_Stage (Item : Error_Information; Stage : Lifecycle_Stage)
  return Error_Information;
```

-------------------------------------------------------------------------
Accumulation

A failing connection produces more than one failure: the first one, and
then everything that could not be done afterwards. Only the first is the
explanation; the rest are consequences. This record keeps the first
exactly and counts the rest, bounded.
-------------------------------------------------------------------------


```ada
type Failure_Record is private;
```

A record holding no failure.

```ada
function No_Failures return Failure_Record;
```

Record a failure. The first terminal failure is kept exactly and is
never displaced; later ones increment a bounded counter. A non-fatal
failure recorded before any terminal one is kept until a terminal one
arrives.
@param Item    the record to add to
@param Failure the failure to record

```ada
procedure Record_Failure (Item : in out Failure_Record; Failure : Error_Information);
```

The failure that explains this connection's state.
@param Item the record to read
@return the first terminal failure, or the first failure of any kind, or
No_Error

```ada
function Primary (Item : Failure_Record) return Error_Information;
```

How many failures arrived after the primary one, counted rather than
kept. Saturates at the configured bound.
@param Item the record to read
@return the count of secondary failures

```ada
function Secondary_Count (Item : Failure_Record) return Natural;
```

Has any failure been recorded?

```ada
function Has_Failure (Item : Failure_Record) return Boolean;
```


