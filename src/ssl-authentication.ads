with SSL.Clocks;
with SSL.Server_Names;
with SSL.Signature_Schemes;

--  @summary What authenticated a peer, and how -- as a value an application can
--  read after the handshake and store alongside whatever it did as a result.
--
--  The distinction this package exists to keep is between a peer authenticated
--  *now*, by a certificate chain validated against trust anchors during this
--  handshake, and a peer authenticated *earlier*, whose identity this connection
--  inherited by resuming a session. Both are legitimate. They are not the same
--  fact, and an application that treats them as the same cannot tell how old its
--  evidence is.
--
--  RFC 8446 section 2.2 is explicit that a resumed handshake does not
--  re-authenticate: the PSK proves possession of a secret established when the
--  original certificate was checked, and nothing about the certificate now. If
--  that certificate has since been revoked, a resumption will not notice. So
--  Resumed carries the time of the original authentication, and an application
--  with a policy about how stale its evidence may be has the number it needs.
package SSL.Authentication is

   ---------------------------------------------------------------------------
   --  Client authentication policy
   ---------------------------------------------------------------------------

   --  What a server asks of a client.
   --
   --  Requested_Optional means the CertificateRequest is sent and an empty
   --  Certificate is accepted; the application then sees an unauthenticated
   --  peer and decides. Required means an empty Certificate fails the handshake
   --  with certificate_required. The two are separated because "ask and let the
   --  application decide" and "ask and refuse without" are different policies
   --  that a single Boolean would conflate.
   type Client_Authentication_Policy is
     (Not_Requested,
      Requested_Optional,
      Required);

   function Image (Item : Client_Authentication_Policy) return String;

   ---------------------------------------------------------------------------
   --  How a peer came to be trusted
   ---------------------------------------------------------------------------

   type Authentication_Basis is
     (Unauthenticated,
      --  No certificate was presented, or none was asked for. On a client this
      --  never happens for the server: a TLS 1.3 server is always
      --  authenticated, and a handshake that could not authenticate one fails
      --  rather than reporting this.

      Certificate_Chain,
      --  A chain was presented and validated against the trust snapshot during
      --  this handshake, and the expected identity matched.

      Resumed_Session);
      --  Identity inherited from an earlier handshake through a PSK. Nothing
      --  about the peer's certificate was checked during this handshake.

   function Image (Item : Authentication_Basis) return String;

   ---------------------------------------------------------------------------
   --  The outcome
   ---------------------------------------------------------------------------

   type Peer_Authentication is private;

   --  A peer that was not authenticated.
   function Unauthenticated_Peer return Peer_Authentication
     with Post => Basis_Of (Unauthenticated_Peer'Result) = Unauthenticated;

   function Basis_Of (Item : Peer_Authentication) return Authentication_Basis;

   --  Was the peer authenticated at all, on either basis?
   function Is_Authenticated (Item : Peer_Authentication) return Boolean
     with Post => Is_Authenticated'Result = (Basis_Of (Item) /= Unauthenticated);

   --  Was the peer's certificate chain validated during *this* handshake?
   --
   --  The question an application should ask when its decision depends on the
   --  certificate being good now rather than having been good once.
   function Is_Freshly_Authenticated (Item : Peer_Authentication) return Boolean
     with Post => Is_Freshly_Authenticated'Result = (Basis_Of (Item) = Certificate_Chain);

   --  When the certificate chain was last actually validated. For a fresh
   --  authentication this is the current handshake; for a resumption it is the
   --  handshake the session came from, which may be hours old.
   function Authenticated_At (Item : Peer_Authentication) return SSL.Clocks.Wall_Time;

   --  The DNS name that was matched against the certificate, when the
   --  expected identity was a name. Absent when the identity was an address or
   --  when the peer was not authenticated.
   function Verified_Name (Item : Peer_Authentication) return SSL.Server_Names.DNS_Name;

   --  The IP address that was matched, when the expected identity was one.
   function Verified_Address (Item : Peer_Authentication) return SSL.Server_Names.IP_Address;

   --  The scheme the peer signed its CertificateVerify with. Absent for a
   --  resumption, which has no CertificateVerify.
   --  @param Item   the outcome
   --  @param Scheme out: the scheme
   --  @return True when this handshake carried a CertificateVerify
   function Signature_Used
     (Item   : Peer_Authentication;
      Scheme : out SSL.Signature_Schemes.Signature_Scheme) return Boolean;

   --  How many certificates were in the validated path, leaf through anchor.
   --  Zero for a resumption or an unauthenticated peer.
   function Path_Length (Item : Peer_Authentication) return Natural;

   --  The leaf certificate's SHA-256 fingerprint, and its SubjectPublicKeyInfo
   --  fingerprint. Carried through a resumption, so that an application pinning
   --  on either can check a resumed connection without a certificate present.
   --  @param Item        the outcome
   --  @param Fingerprint out: the fingerprint
   --  @return True when a fingerprint is available
   function Leaf_Fingerprint
     (Item        : Peer_Authentication;
      Fingerprint : out Certificate_Fingerprint) return Boolean;

   function Public_Key_Fingerprint
     (Item        : Peer_Authentication;
      Fingerprint : out Certificate_Fingerprint) return Boolean;

   --  A one-line rendering for a log. Never secret: everything here is either
   --  public certificate material or a policy outcome.
   function Image (Item : Peer_Authentication) return String;

   ---------------------------------------------------------------------------
   --  Construction
   --
   --  Used by the handshake once validation has finished, and by the session
   --  layer when a resumption inherits an earlier outcome. Public because an
   --  application writing a test double for a connection needs to produce one.
   ---------------------------------------------------------------------------

   --  Record a chain validated during this handshake.
   function Fresh
     (At_Time      : SSL.Clocks.Wall_Time;
      Name         : SSL.Server_Names.DNS_Name;
      Address      : SSL.Server_Names.IP_Address;
      Scheme       : SSL.Signature_Schemes.Signature_Scheme;
      Path_Length  : Positive;
      Leaf         : Certificate_Fingerprint;
      Public_Key   : Certificate_Fingerprint) return Peer_Authentication
     with Post => Basis_Of (Fresh'Result) = Certificate_Chain;

   --  Record an identity inherited through resumption. Takes the earlier
   --  outcome so that the original authentication time and the fingerprints
   --  travel with it, and deliberately drops the signature scheme, because no
   --  signature was made in this handshake.
   function Resumed (From : Peer_Authentication) return Peer_Authentication
     with Pre => Is_Authenticated (From),
          Post => Basis_Of (Resumed'Result) = Resumed_Session;

private

   type Peer_Authentication is record
      Basis        : Authentication_Basis := Unauthenticated;
      At_Time      : SSL.Clocks.Wall_Time := SSL.Clocks.No_Wall_Time;
      Name         : SSL.Server_Names.DNS_Name := SSL.Server_Names.No_Name;
      Address      : SSL.Server_Names.IP_Address := SSL.Server_Names.No_Address;
      Has_Scheme   : Boolean := False;
      Scheme       : SSL.Signature_Schemes.Signature_Scheme :=
        SSL.Signature_Schemes.Ed25519;
      Path         : Natural := 0;
      Has_Leaf     : Boolean := False;
      Leaf         : Certificate_Fingerprint;
      Has_Key      : Boolean := False;
      Public_Key   : Certificate_Fingerprint;
   end record;

end SSL.Authentication;
