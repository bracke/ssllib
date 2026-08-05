# ssl-trust-pinning

Generated from `src/ssl-trust-pinning.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

Certificate and public-key pins: an additional condition a peer's
chain must meet, never a substitute for one.

A pin says "this specific key, please". It does not say "and never mind which
name this certificate is for", and this package will not let it mean that.
`Require_Valid_Path_And_Pin` requires both the path and the pin; `Pin_Only`
relaxes the path requirement and **still** requires identity matching. The
failure that ordering prevents is a pinned certificate legitimately issued
for a different name being accepted for this one -- which is exactly what
happens when an implementation treats a pin match as a full substitute for
verification.

Pins are over SHA-256 of the whole certificate, or of the
SubjectPublicKeyInfo. The second outlives certificate renewal, which is why
it is usually the right one: pinning the certificate means the pin has to be
updated every time the certificate is, and a pin that has to be updated on a
schedule is a pin that will one day be updated wrongly or not at all.

Every pin carries an activation period. A pin with no end date is a hostage
to fortune: the key it names will eventually be retired, and a pin that
outlives its key locks the application out of its own service. Making the
period explicit at least puts the date where somebody can read it.

-------------------------------------------------------------------------
Policy
-------------------------------------------------------------------------


```ada
type Pinning_Mode is
  (No_Pinning,
   --  Pins are not consulted.

   Require_Valid_Path_And_Pin,
   --  The chain must validate to a trust anchor *and* match a pin. The usual
   --  choice: it adds a condition without removing one.

   Pin_Only);
```

The chain need not reach a configured trust anchor, but must match a
pin and must still match the expected identity. For an internal service
whose certificate authority is not in any trust store.


```ada
function Image (Item : Pinning_Mode) return String;
```

-------------------------------------------------------------------------
Pins
-------------------------------------------------------------------------

One pin: a digest, what it is over, what it applies to, and when it is in
force.

```ada
type Pin is private;
```

Build a pin.

Scope narrows what the pin applies to. A pin with no name applies to every
connection the configuration makes, which is right for a single-purpose
client and wrong for anything that talks to more than one service.
@param Digest      the fingerprint, over a certificate or an SPKI
@param Name        the identity this pin applies to, or No_Name for all
@param Protocol    the ALPN protocol it applies to, or No_Protocol for all
@param Not_Before  when the pin starts being enforced
@param Not_After   when it stops; must be after Not_Before
@param Item        out: the pin
@return True when the period is usable

```ada
function Make
  (Digest     : Certificate_Fingerprint;
   Name       : SSL.Server_Names.DNS_Name;
   Protocol   : SSL.ALPN.Protocol_Name;
   Not_Before : SSL.Clocks.Wall_Time;
   Not_After  : SSL.Clocks.Wall_Time;
   Item       : out Pin) return Boolean;
```

```ada
function Digest_Of (Item : Pin) return Certificate_Fingerprint;
```

```ada
function Name_Of (Item : Pin) return SSL.Server_Names.DNS_Name;
```

```ada
function Protocol_Of (Item : Pin) return SSL.ALPN.Protocol_Name;
```

Is this pin in force at a given time?

```ada
function Is_Active (Item : Pin; At_Time : SSL.Clocks.Wall_Time) return Boolean;
```

Does this pin apply to a connection to this name under this protocol?

A pin with no name applies to every name; a pin with a name applies only
where the name matches, which lets one configuration hold pins for several
services without any of them applying to the wrong one.

```ada
function Applies
  (Item     : Pin;
   Name     : SSL.Server_Names.DNS_Name;
   Protocol : SSL.ALPN.Protocol_Name) return Boolean;
```

```ada
type Pin_Set is private;
```

```ada
function No_Pins return Pin_Set;
```

```ada
function Length (Item : Pin_Set) return Natural
  with Post => Length'Result <= Maximum_Pins;
```

```ada
function Element (Item : Pin_Set; Index : Positive) return Pin
  with Pre => Index <= Length (Item);
```

```ada
procedure Append (Item : in out Pin_Set; Value : Pin; Ok : out Boolean);
```

How many pins in the set are in force for this connection right now.

Zero is the case worth naming: a set that holds pins, none of which
applies here, must not be read as "pinning satisfied". Evaluate reports it
as a scope mismatch rather than a pass.

```ada
function Applicable_Count
  (Item     : Pin_Set;
   Name     : SSL.Server_Names.DNS_Name;
   Protocol : SSL.ALPN.Protocol_Name;
   At_Time  : SSL.Clocks.Wall_Time) return Natural;
```

-------------------------------------------------------------------------
Evaluation
-------------------------------------------------------------------------

Decide whether a peer's leaf satisfies the pinning policy.

Both fingerprints are taken because a set may hold pins of either kind,
and a certificate pin and an SPKI pin over the same bytes are different
values -- `SSL.Certificate_Fingerprint` carries which it is, so a pin
cannot be matched against the wrong kind of digest.
@param Mode        the policy
@param Pins        the configured pins
@param Leaf        the peer leaf's certificate fingerprint
@param Public_Key  the peer leaf's SPKI fingerprint
@param Name        the identity this connection expects
@param Protocol    the negotiated ALPN protocol, or No_Protocol
@param At_Time     the current wall time
@param Error       out: No_Error when the policy is satisfied

```ada
procedure Evaluate
  (Mode       : Pinning_Mode;
   Pins       : Pin_Set;
   Leaf       : Certificate_Fingerprint;
   Public_Key : Certificate_Fingerprint;
   Name       : SSL.Server_Names.DNS_Name;
   Protocol   : SSL.ALPN.Protocol_Name;
   At_Time    : SSL.Clocks.Wall_Time;
   Error      : out SSL.Errors.Error_Information);
```

Is this policy usable as configured?

A mode that consults pins with no pins configured can never succeed, and
is refused at configuration time rather than failing every handshake.

```ada
function Is_Valid_Policy (Mode : Pinning_Mode; Pins : Pin_Set) return Boolean;
```


