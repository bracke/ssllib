with SSL.Errors;
with SSL.Signature_Schemes;

--  @summary External signers: a signing capability this library calls but does
--  not hold the key for.
--
--  For a hardware security module, a TPM, a remote signing service, or any
--  arrangement in which the private key is somewhere `ssllib` cannot reach. The
--  application implements the interface; this library calls it at exactly one
--  point in the handshake and treats the result as a signature.
--
--  Three properties the interface is shaped around, each of which is a way an
--  external signer differs from a key in memory:
--
--    * **It declares what it can do, up front.** Credential selection happens
--      before any signature is attempted, and asking a signer to sign under a
--      scheme it cannot produce -- to find out whether it can -- would mean a
--      failed handshake per attempt. `Supports` is asked first and must be
--      answerable without touching the device.
--    * **It may need serialized access.** A single HSM session cannot be driven
--      from two connections at once. A signer says so, and the engine serializes
--      calls to it rather than assuming either way.
--    * **It may raise.** It is application code, and application code has bugs
--      and talks to hardware that fails. Every call is made inside a handler
--      that converts an exception into a structured provider failure, so a
--      signer that raises fails one connection rather than unwinding through a
--      state machine.
--
--  A signer is never asked to hash. It receives the exact octets a
--  CertificateVerify covers and must apply the scheme's own transformation --
--  which for RSA-PSS means MGF1 with the matching hash and a salt equal to the
--  digest length (RFC 8446 section 4.2.3), and for EdDSA means the algorithm's
--  own internal hashing. Handing a signer a digest instead would work for some
--  schemes and silently produce a wrong signature for others.
package SSL.Credentials.Signers is

   ---------------------------------------------------------------------------
   --  The interface an application implements
   ---------------------------------------------------------------------------

   type External_Signer is limited interface;

   type Signer_Reference is access all External_Signer'Class;

   --  Can this signer produce a signature under this scheme?
   --
   --  Must answer without contacting the device, and must not change its answer
   --  during a connection: selection happens once, before the signature is
   --  needed, and a signer that changed its mind afterwards would fail a
   --  handshake that had already committed to it.
   --  @param Item   the signer
   --  @param Scheme the scheme in question
   --  @return True when Sign will be attempted under this scheme
   function Supports
     (Item   : External_Signer;
      Scheme : SSL.Signature_Schemes.Signature_Scheme) return Boolean is abstract;

   --  Does this signer require that only one call be in flight at a time?
   --
   --  True for a device with a single session. The engine serializes calls when
   --  this is True and does not when it is False; it never guesses.
   function Requires_Serialized_Access (Item : External_Signer) return Boolean is abstract;

   --  The public key this signer's private key belongs to, in the encoding a
   --  SubjectPublicKeyInfo carries it.
   --
   --  Used to check, at configuration time, that the signer and the certificate
   --  it is paired with are actually a pair -- the same key/certificate mismatch
   --  an in-memory credential is checked for, caught at the same point.
   function Public_Key (Item : External_Signer) return Byte_Array is abstract;

   --  Produce a signature over the exact octets supplied.
   --
   --  Signed_Data is the complete structure a CertificateVerify covers. The
   --  implementation applies the scheme's own transformation and nothing else:
   --  it must not hash first, and it must not wrap the result.
   --
   --  On failure, set Length to zero and leave Signature untouched. Raising is
   --  permitted -- it will be caught and converted -- but returning a failure is
   --  better, because an exception carries no reason this library can record.
   --  @param Item        the signer
   --  @param Scheme      the scheme, which Supports has already accepted
   --  @param Signed_Data the exact octets to sign
   --  @param Signature   out: the signature in the encoding TLS carries
   --  @param Length      out: how many octets were written, zero on failure
   procedure Sign
     (Item        : in out External_Signer;
      Scheme      : SSL.Signature_Schemes.Signature_Scheme;
      Signed_Data : Byte_Array;
      Signature   : out Byte_Array;
      Length      : out Byte_Index) is abstract;

   --  Short text naming this signer, for diagnostics. Never secret, and never
   --  the key: something an operator can match against their own inventory.
   function Description (Item : External_Signer) return String is abstract;

   ---------------------------------------------------------------------------
   --  Calling one
   ---------------------------------------------------------------------------

   --  Call a signer, converting every failure mode into a structured result.
   --
   --  This is the boundary. An exception from application code stops here and
   --  becomes a provider failure attributed to the signer, rather than
   --  propagating into a handshake that has traffic keys installed and buffers
   --  to scrub.
   --  @param Item        the signer
   --  @param Scheme      the scheme
   --  @param Signed_Data the exact octets to sign
   --  @param Signature   out: the signature; zeroed on failure
   --  @param Length      out: how many octets hold it, zero on failure
   --  @param Error       out: No_Error, or a provider failure naming the signer
   procedure Sign_Externally
     (Item        : in out External_Signer'Class;
      Scheme      : SSL.Signature_Schemes.Signature_Scheme;
      Signed_Data : Byte_Array;
      Signature   : out Byte_Array;
      Length      : out Byte_Index;
      Error       : out SSL.Errors.Error_Information)
     with Pre => Signature'Length >= Maximum_Signature_Length;

   --  Ask a signer what it supports, with the same protection.
   --
   --  A signer that raises while being asked a question is a signer that cannot
   --  be selected, which is reported rather than allowed to propagate out of
   --  credential selection.
   --  @param Item   the signer
   --  @param Scheme the scheme in question
   --  @return True only when the signer answered and answered yes
   function Supports_Safely
     (Item   : External_Signer'Class;
      Scheme : SSL.Signature_Schemes.Signature_Scheme) return Boolean;

end SSL.Credentials.Signers;
