with Ada.Streams;

--  @summary Root of ssllib: the byte view every other package speaks, and the
--  typed stable identifiers that name things across the API.
--
--  ssllib provides TLS 1.3 and a deliberately restricted modern TLS 1.2 for
--  authenticated, confidential, integrity-protected bidirectional byte streams
--  over a transport the caller owns. It opens no sockets, reads no clocks,
--  looks at no environment variables and starts no tasks of its own.
--
--  The name is historical. SSL 2.0 and SSL 3.0 are not implemented, and
--  neither are TLS 1.0 and TLS 1.1.
--
--  Ownership boundaries, which the rest of the library holds to:
--
--    * every hash, MAC, KDF, AEAD, key agreement, signature, ASN.1, X.509,
--      PKIX, OCSP and CRL operation is CryptoLib's;
--    * every native trust-anchor source is Truststores';
--    * the remaining genuine host differences are Hostkit's;
--    * what is left -- the protocol -- is this library's.
--
--  Bytes are Ada.Streams.Stream_Element_Array throughout, because that is
--  what CryptoLib speaks and what Ada streams speak, so no conversion layer
--  sits between the caller, this library and the cryptography.
package SSL is
   pragma Preelaborate;

   --  Arithmetic and comparison on octet positions, made directly visible here
   --  so that every child unit has it without repeating the use clause. A use
   --  clause in a parent's visible part is visible in its children, and offset
   --  arithmetic is what this library is largely made of: a per-file "use type"
   --  would be noise in fifty places. Octet arithmetic and octet-run equality
   --  are made visible in the individual units that need them -- the record
   --  layer's nonce construction and the few places two octet runs are compared
   --  -- rather than here, so that a unit doing neither says so by not asking.
   use type Ada.Streams.Stream_Element_Offset;

   --  One octet on the wire or in a buffer.
   subtype Byte is Ada.Streams.Stream_Element;

   --  A run of octets. Every wire encoding, every plaintext buffer and every
   --  secret in this library is one of these or a bounded record holding one.
   subtype Byte_Array is Ada.Streams.Stream_Element_Array;

   --  An index into a Byte_Array. Lengths and counts of octets use this so
   --  that arithmetic on them cannot silently overflow a Natural on a
   --  32-bit target.
   subtype Byte_Index is Ada.Streams.Stream_Element_Offset;

   --  The empty octet run, for the many places the protocol allows one: an
   --  empty context, an empty salt, an empty extension body.
   Empty_Bytes : constant Byte_Array (1 .. 0) := [others => 0];

   ---------------------------------------------------------------------------
   --  Stable identifiers
   --
   --  Each of these names one thing for the life of a process. They are
   --  immutable, comparable and hashable, and they carry no payload a caller
   --  could mistake for the thing itself: a Credential_ID does not let anyone
   --  reach the private key, and a Session_ID does not let anyone reach the
   --  resumption secret.
   ---------------------------------------------------------------------------

   --  Names one connection. Assigned when the connection object is
   --  initialized and never reused within a process run, so a diagnostic
   --  event can be attributed to a connection that has already been
   --  finalized.
   type Connection_ID is private;

   --  Names one loaded credential -- a certificate chain and the signing
   --  capability that goes with it -- within one configuration.
   type Credential_ID is private;

   --  Names one resumable session in a cache. Distinct from the TLS 1.2
   --  legacy session_id field on the wire, which this library does not use
   --  for resumption.
   type Session_ID is private;

   --  Names an application security context. A session is only offered for
   --  resumption to a connection whose context matches the one it was
   --  established under, which is how an application keeps sessions
   --  belonging to different users or tenants from being crossed.
   type Security_Context_ID is private;

   --  A configuration's identity as a value: two configurations with the same
   --  fingerprint negotiate the same way. Sessions are bound to it, so a
   --  configuration change invalidates resumption rather than silently
   --  resuming under policy the session was not established under.
   type Configuration_Fingerprint is private;

   --  A trust snapshot's identity as a value. Bound into sessions for the
   --  same reason.
   type Trust_Fingerprint is private;

   --  A certificate's identity as a value: SHA-256 over the DER, or over the
   --  SubjectPublicKeyInfo, according to how it was taken.
   type Certificate_Fingerprint is private;

   --  The two things a Certificate_Fingerprint can be over.
   type Fingerprint_Subject is (Whole_Certificate, Public_Key_Info);

   ---------------------------------------------------------------------------
   --  Identifier operations
   ---------------------------------------------------------------------------

   --  The unset value of each identifier kind. Distinguishable from every
   --  assigned value, so "no credential selected" is not the same as "the
   --  first credential".
   function No_Connection return Connection_ID;
   function No_Credential return Credential_ID;
   function No_Session return Session_ID;
   function Default_Security_Context return Security_Context_ID;

   --  Is this an assigned identifier rather than the unset one?
   --  @param Item the identifier to test
   --  @return True when Item names something
   function Is_Present (Item : Connection_ID) return Boolean;
   function Is_Present (Item : Credential_ID) return Boolean;
   function Is_Present (Item : Session_ID) return Boolean;

   --  Every identifier type above is a non-limited private type, so the
   --  predefined "=" is visible to callers and is the right comparison: each
   --  is a scalar or a fixed-size record with no padding a caller can set.
   --  There is deliberately no ordering, because none of these has a
   --  meaningful order and an accidental one invites sorting by it.

   --  Build an application security context from a caller-chosen label. The
   --  label is not secret and is not sent on the wire; it separates cache
   --  domains. An empty label is the default context.
   --  @param Label the caller's name for the context, up to 64 characters
   --  @return the context identifier
   function Security_Context (Label : String) return Security_Context_ID
     with Pre => Label'Length <= 64;

   --  Lower-case hexadecimal image of a fingerprint, for logs and for
   --  comparison against a pin an operator wrote down. Never a secret.
   --  @param Item the fingerprint to render
   --  @return 64 hexadecimal characters
   function Image (Item : Certificate_Fingerprint) return String
     with Post => Image'Result'Length = 64;
   function Image (Item : Configuration_Fingerprint) return String
     with Post => Image'Result'Length = 64;
   function Image (Item : Trust_Fingerprint) return String
     with Post => Image'Result'Length = 64;

   --  A decimal image of a connection identifier, for correlating diagnostic
   --  events. Not stable across process runs.
   --  @param Item the connection identifier to render
   --  @return the decimal image, or "-" for No_Connection
   function Image (Item : Connection_ID) return String;

   --  What a fingerprint was taken over.
   --  @param Item the fingerprint to inspect
   --  @return Whole_Certificate or Public_Key_Info
   function Subject_Of (Item : Certificate_Fingerprint) return Fingerprint_Subject;

   --  Parse a certificate or SPKI fingerprint from its hexadecimal image, for
   --  reading a pin out of application configuration.
   --  @param Text    64 hexadecimal characters, either case
   --  @param Subject what the digest is over
   --  @param Item    out: the parsed fingerprint, unchanged on failure
   --  @return True when Text was 64 valid hexadecimal characters
   function Parse_Fingerprint
     (Text    : String;
      Subject : Fingerprint_Subject;
      Item    : out Certificate_Fingerprint) return Boolean;

private

   --  Every identifier is a scalar or a fixed digest. None of them holds a
   --  pointer, so copying one cannot extend the lifetime of anything, and
   --  none of them holds secret material, so none needs wiping.

   type Connection_ID is new Natural;
   type Credential_ID is new Natural;
   type Session_ID is new Natural;

   --  Named for what it is rather than "Digest_Length": children of SSL see
   --  this private part, and a name that generic would hide
   --  SSL.Cipher_Suites.Digest_Length everywhere in the hierarchy.
   Fingerprint_Digest_Length : constant := 32;
   subtype Digest_Bytes is Byte_Array (1 .. Fingerprint_Digest_Length);

   Null_Digest : constant Digest_Bytes := [others => 0];

   Context_Label_Limit : constant := 64;

   type Security_Context_ID is record
      --  The label is held as a fixed buffer rather than hashed, so a
      --  diagnostic can name the context an application chose without the
      --  application having to keep a side table.
      Length : Natural range 0 .. Context_Label_Limit := 0;
      Text   : String (1 .. Context_Label_Limit) := [others => ' '];
   end record;

   type Configuration_Fingerprint is record
      Digest : Digest_Bytes := Null_Digest;
   end record;

   type Trust_Fingerprint is record
      Digest : Digest_Bytes := Null_Digest;
   end record;

   type Certificate_Fingerprint is record
      Subject : Fingerprint_Subject := Whole_Certificate;
      Digest  : Digest_Bytes := Null_Digest;
   end record;

end SSL;
