with SSL.Clocks;
with SSL.Errors;
with SSL.Limits;
with SSL.Server_Names;
with SSL.Trust;
with SSL.Trust.Revocation;

--  @summary The certificate validation pipeline, run in one fixed order.
--
--  The order is the point of this package. Specification section 15 lays it out
--  and it is not arbitrary: decode, parse, bounded path build, path validation,
--  purpose, key usage, identity, revocation, pinning. Each step assumes the
--  previous one has passed, and running them in a different order produces
--  answers that are wrong in ways that are hard to see.
--
--  Two orderings in particular:
--
--    * **Identity is checked after the path, never instead of it.** A chain that
--      does not validate is not saved by carrying the right name, and a chain
--      that validates is not accepted for a name it was not issued for.
--    * **Revocation is checked after the path, not before.** Asking whether a
--      certificate is revoked before knowing whether it is even trusted means
--      acting on an assertion from an issuer nobody has vouched for.
--
--  Everything cryptographic and everything about X.509 belongs to CryptoLib.
--  This package chooses the anchors, applies the bounds, sequences the steps and
--  maps CryptoLib's verdicts onto this library's error taxonomy. It parses no
--  ASN.1 and verifies no signature itself.
--
--  Identity matching uses subjectAltName only. There is no Common Name fallback,
--  and there is no configuration that adds one -- see docs/security-model.md.
private package SSL.Certificate_Validation is

   ---------------------------------------------------------------------------
   --  What the caller expects to authenticate
   ---------------------------------------------------------------------------

   --  What a validated chain is being checked against.
   --
   --  Exactly one of the two is present. A connection authenticating an address
   --  has no DNS name to check, and one authenticating a name has no address;
   --  requiring the caller to say which keeps the "check whichever happens to be
   --  set" ambiguity out of the pipeline.
   type Expected_Identity is private;

   function For_Name (Value : SSL.Server_Names.DNS_Name) return Expected_Identity
     with Pre => SSL.Server_Names.Is_Present (Value)
                 and then not SSL.Server_Names.Is_Wildcard (Value);

   function For_Address (Value : SSL.Server_Names.IP_Address) return Expected_Identity
     with Pre => SSL.Server_Names.Is_Present (Value);

   --  No identity at all: only legal when validating a *client* certificate,
   --  where there is no name the server expects and authorization is the
   --  application's business.
   function No_Identity return Expected_Identity;

   function Has_Identity (Item : Expected_Identity) return Boolean;

   ---------------------------------------------------------------------------
   --  What the chain will be used for
   ---------------------------------------------------------------------------

   --  Which end presented the chain. Decides the extended key usage the leaf
   --  must carry, which is the check that stops a client certificate being
   --  accepted as a server's.
   type Certificate_Role is (Server_Certificate, Client_Certificate);

   function Image (Item : Certificate_Role) return String;

   ---------------------------------------------------------------------------
   --  How a chain is handed over
   --
   --  A span per certificate into one octet run: the shape the Certificate
   --  message parser produces and the shape SSL.Credentials holds, so nothing
   --  is copied in order to validate it.
   ---------------------------------------------------------------------------

   Maximum_Chain : constant := 16;

   type Certificate_Span is record
      First : Byte_Index := 1;
      Last  : Byte_Index := 0;
   end record;

   type Span_List is array (1 .. Maximum_Chain) of Certificate_Span;

   type Chain_Storage (Length : Byte_Index) is record
      Spans  : Span_List := [others => <>];
      Octets : Byte_Array (1 .. Length) := [others => 0];
   end record;

   ---------------------------------------------------------------------------
   --  The outcome
   ---------------------------------------------------------------------------

   --  What a successful validation established.
   type Validation_Result is private;

   --  A result describing no validation, for a connection where the peer did
   --  not present a certificate. Its path length is zero and its fingerprints
   --  are absent, which is what distinguishes it from one that succeeded.
   function No_Result return Validation_Result;

   function Path_Length (Item : Validation_Result) return Natural;
   function Leaf_Fingerprint (Item : Validation_Result) return Certificate_Fingerprint;
   function Public_Key_Fingerprint (Item : Validation_Result) return Certificate_Fingerprint;

   --  The leaf's SubjectPublicKeyInfo public key, which CertificateVerify needs
   --  to check the peer's signature. Public material.
   function Leaf_Public_Key (Item : Validation_Result) return Byte_Array;

   --  Which key algorithm the leaf holds, so the caller can check that the
   --  scheme the peer signed with matches the key it presented.
   type Leaf_Key_Kind is (RSA_Key, ECDSA_P256, ECDSA_P384, ECDSA_P521, Ed25519_Key, Ed448_Key);
   function Leaf_Key_Type (Item : Validation_Result) return Leaf_Key_Kind;

   ---------------------------------------------------------------------------
   --  The pipeline
   ---------------------------------------------------------------------------

   --  Validate a peer's certificate chain.
   --
   --  Chain is the DER of each certificate, leaf first, exactly as the
   --  Certificate message carried them. Nothing is re-encoded.
   --
   --  Revocation and pinning are *not* run here: they need evidence and policy
   --  the caller holds, and running them from inside would mean this package
   --  reaching for a network or a provider. The caller runs
   --  SSL.Trust.Revocation.Evaluate and SSL.Trust.Pinning.Evaluate against this
   --  result, in that order, which is the order the specification states.
   --
   --  @param Chain     the certificates, leaf first
   --  @param Count     how many of them
   --  @param Anchors   the trust snapshot
   --  @param Identity  what the leaf must be for
   --  @param Role      which end presented it
   --  @param At_Time   the wall time validity is judged against
   --  @param Bounds    the limits in force
   --  @param Result    out: what was established, meaningless when Error is set
   --  @param Error     out: No_Error, or the first step that refused
   ---------------------------------------------------------------------------
   --  Stapled revocation status
   ---------------------------------------------------------------------------

   --  What a stapled OCSP response says about the leaf certificate.
   --
   --  The response is the octets the peer attached to its Certificate message,
   --  and everything about reading them -- the DER, the signature, the
   --  freshness window, whether the responder was entitled to speak for this
   --  issuer -- is CryptoLib's. This translates the answer into this library's
   --  own vocabulary and does nothing else.
   --
   --  **Nothing is fetched.** If a peer stapled no response, there is no
   --  response. This library opens no socket to go and find one: a TLS
   --  handshake that reached out to a third party would leak who was
   --  connecting to whom, and would block on a service the connection has no
   --  relationship with.
   --
   --  A chain of one -- a self-signed certificate -- has no issuer to have
   --  signed a statement about it, and reports `Wrong_Issuer` rather than
   --  pretending to have checked.
   --  @param Chain    the peer's chain, as it was validated
   --  @param Count    how many certificates it holds
   --  @param Response the stapled response, as it arrived
   --  @param At_Time  the wall clock, for the freshness window
   --  @param Bounds   the limits in force
   --  @param Answer   out: what the response said, or why it could not say
   procedure Check_Stapled_Status
     (Chain    : aliased Chain_Storage;
      Count    : Positive;
      Response : Byte_Array;
      At_Time  : SSL.Clocks.Wall_Time;
      Bounds   : SSL.Limits.Resource_Limits;
      Answer   : out SSL.Trust.Revocation.Status_Answer);

   procedure Validate
     (Chain    : aliased Chain_Storage;
      Count    : Positive;
      Anchors  : aliased SSL.Trust.Snapshot;
      Identity : Expected_Identity;
      Role     : Certificate_Role;
      At_Time  : SSL.Clocks.Wall_Time;
      Bounds   : SSL.Limits.Resource_Limits;
      Result   : out Validation_Result;
      Error    : out SSL.Errors.Error_Information);

private

   Maximum_Public_Key : constant Byte_Index := 1024;

   type Expected_Identity is record
      Name    : SSL.Server_Names.DNS_Name := SSL.Server_Names.No_Name;
      Address : SSL.Server_Names.IP_Address := SSL.Server_Names.No_Address;
   end record;

   type Validation_Result is record
      Path        : Natural := 0;
      Leaf_Digest : Certificate_Fingerprint;
      Key_Digest  : Certificate_Fingerprint;
      Key_Kind    : Leaf_Key_Kind := RSA_Key;
      Key_Length  : Byte_Index range 0 .. Maximum_Public_Key := 0;
      Key_Octets  : Byte_Array (1 .. Maximum_Public_Key) := [others => 0];
   end record;

end SSL.Certificate_Validation;
