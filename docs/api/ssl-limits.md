# ssl-limits

Generated from `src/ssl-limits.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

Immutable resource bounds. Every count and length a peer can
influence is bounded here, and the bound is checked before the storage is
reserved rather than after.

A TLS implementation reads attacker-chosen lengths before it can
authenticate anything: the record length, the handshake message length, the
certificate list length, the extension block length. Each of those is an
invitation to allocate. This package is the single place the answers live,
so that a hostile peer meets a refusal of a stated size rather than a
memory exhaustion whose size nobody knows.

The type is a plain immutable record so a configuration can hold one by
value and share it between tasks. Build one with Default_Limits and
override fields, or use one of the named profiles.

```ada
type Resource_Limits is record

   ------------------------------------------------------------------------
   --  Record layer
   ------------------------------------------------------------------------

   --  Largest plaintext this endpoint will emit in one record, and the
   --  largest it will accept after removing padding. Never above
   --  Protocol_Plaintext_Record_Limit.
   Maximum_Plaintext_Record : Positive := Protocol_Plaintext_Record_Limit;
```

Why a limit refused, as a value a structured error can carry. The name
is the diagnostic: an operator reading "certificate_count" knows which
bound to raise, and a peer learns only that something was too large.

```ada
type Limit_Kind is
  (Plaintext_Record,
   Record_Padding,
   Consecutive_Empty_Records,
   Compatibility_CCS,
   Handshake_Message,
   Certificate_Message,
   Certificate_Size,
   Certificate_Count,
   Path_Depth,
   Handshake_Message_Count,
   Extension_Block,
   Extension_Count,
   Extension_Body,
   ALPN_Protocols,
   Server_Name_Length,
   Cipher_Suites,
   Supported_Groups,
   Signature_Schemes,
   Key_Shares,
   PSK_Identities,
   Certificate_Authorities,
   Cookie_Length,
   Ciphertext_Queue,
   Plaintext_Queue,
   Input_Buffer,
   Trust_Anchors,
   OCSP_Response,
   OCSP_Response_Count,
   CRL_Size,
   CRL_Count,
   Pins,
   Ticket_Size,
   Ticket_Count,
   Session_Cache_Entries,
   Ticket_Decrypt_Keys,
   Peer_Key_Updates,
   Record_Usage,
   Octet_Usage,
   Diagnostic_Events,
   Secondary_Errors);
```

Short stable text naming a limit, for diagnostics and error parameters.
@param Kind the limit that refused
@return lower-case snake-case text, stable across releases

```ada
function Image (Kind : Limit_Kind) return String;
```

The configured value of one limit, so a diagnostic can report both what
was asked for and what was allowed.
@param Item the limits in force
@param Kind which limit to read
@return the bound, as a count of octets or of items

```ada
function Value (Item : Resource_Limits; Kind : Limit_Kind) return Long_Long_Integer;
```

Are these limits internally consistent and usable?

Rejects a plaintext record above what TLS can express, queues too small
to hold one record, a certificate larger than the message containing it,
a soft key-update threshold at or above the hard ceiling, and an input
buffer that cannot hold one maximum-size protected record. A
configuration built on inconsistent limits would deadlock rather than
refuse, which is the failure this check exists to prevent.
@param Item the limits to check
@return True when every bound is usable and mutually consistent

```ada
function Is_Valid (Item : Resource_Limits) return Boolean;
```

Which rule Is_Valid broke, for a configuration error message.
@param Item the limits to check
@return empty when Is_Valid, otherwise short text naming the rule

```ada
function Invalidity (Item : Resource_Limits) return String;
```


