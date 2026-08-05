with SSL.Clocks;
with SSL.Errors;
with SSL.Limits;

--  @summary Revocation status: what the policy demands, and where the evidence
--  comes from.
--
--  **Nothing here ever opens a network connection.** Not in any mode, not as a
--  fallback, not "just for OCSP". A TLS library that fetched its own revocation
--  status during a handshake would be blocking on a third party the caller never
--  chose, leaking the identity of the site being visited to that third party, and
--  opening a socket the caller did not ask for. Status arrives stapled by the
--  peer, or from the application; there is no third way.
--
--  The consequence is honest and worth stating rather than discovering:
--  `Require_Valid_Status` is only satisfiable when the peer staples or the
--  application supplies. A client that sets it and provides neither will fail
--  every handshake, which is why `Is_Satisfiable` exists and why the
--  configuration checks it.
--
--  An explicitly revoked certificate always fails, in every mode including
--  `Revocation_Disabled`. Disabling revocation checking means not going looking;
--  it does not mean ignoring a revocation that arrived anyway.
package SSL.Trust.Revocation is

   ---------------------------------------------------------------------------
   --  Policy
   ---------------------------------------------------------------------------

   type Revocation_Policy is
     (Revocation_Disabled,
      --  Do not seek status. A revocation that arrives regardless is still
      --  honoured -- see the note above.

      Check_When_Available,
      --  Use whatever status is to hand. Absent status is not a failure. The
      --  default: it costs nothing and catches the revocations that are
      --  advertised.

      Require_Valid_Status,
      --  Every certificate that can carry status must have valid, current
      --  status. Absent or stale status fails the handshake.

      Require_Stapled_OCSP);
      --  As above, and the status must have arrived stapled by the peer rather
      --  than from the application. For a client that will not trust its own
      --  cache over the server's own assertion.

   function Image (Item : Revocation_Policy) return String;

   --  Can this policy ever succeed given what is available?
   --
   --  A policy demanding status while the connection neither requests stapling
   --  nor has an application provider can never be satisfied, and is refused at
   --  configuration time rather than failing every handshake identically.
   function Is_Satisfiable
     (Item              : Revocation_Policy;
      Requests_Stapling : Boolean;
      Has_Provider      : Boolean) return Boolean;

   ---------------------------------------------------------------------------
   --  Evidence
   ---------------------------------------------------------------------------

   --  Where a piece of status came from. Kept because Require_Stapled_OCSP
   --  distinguishes them, and because a diagnostic that says only "revoked" is
   --  harder to act on than one that says where the claim came from.
   type Evidence_Source is (Stapled_By_Peer, Supplied_By_Application);

   function Image (Item : Evidence_Source) return String;

   --  What the evidence said. These are CryptoLib's answers, re-expressed so
   --  that nothing outside the certificate adapter depends on CryptoLib's
   --  enumeration.
   type Status_Answer is
     (Not_Revoked,
      Revoked,
      Status_Unknown,
      Status_Stale,
      Wrong_Issuer,
      Untrusted_Signature,
      Unsupported_Statement,
      Malformed_Status);

   function Image (Item : Status_Answer) return String;

   --  Is this answer a definite statement that the certificate is good?
   function Is_Affirmative (Item : Status_Answer) return Boolean
     with Post => Is_Affirmative'Result = (Item = Not_Revoked);

   --  Is this answer a definite statement that it is bad?
   --
   --  Only Revoked is. Everything else means the question was not answered, and
   --  the difference matters: an unanswered question is a policy decision, and a
   --  revocation is not.
   function Is_Revocation (Item : Status_Answer) return Boolean
     with Post => Is_Revocation'Result = (Item = Revoked);

   ---------------------------------------------------------------------------
   --  Decision
   ---------------------------------------------------------------------------

   --  Decide whether one certificate's revocation status satisfies the policy.
   --
   --  @param Policy    what is demanded
   --  @param Answer    what the evidence said, or Status_Unknown for none at all
   --  @param Source    where the evidence came from
   --  @param Available whether any evidence was found at all
   --  @param At_Time   the current wall time, for the diagnostic
   --  @param Bounds    the limits in force
   --  @param Error     out: No_Error when the policy is satisfied
   procedure Evaluate
     (Policy    : Revocation_Policy;
      Answer    : Status_Answer;
      Source    : Evidence_Source;
      Available : Boolean;
      At_Time   : SSL.Clocks.Wall_Time;
      Bounds    : SSL.Limits.Resource_Limits;
      Error     : out SSL.Errors.Error_Information);

end SSL.Trust.Revocation;
