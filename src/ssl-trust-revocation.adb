package body SSL.Trust.Revocation is

   -----------
   -- Image --
   -----------

   function Image (Item : Revocation_Policy) return String is
   begin
      case Item is
         when Revocation_Disabled  => return "disabled";
         when Check_When_Available => return "check_when_available";
         when Require_Valid_Status => return "require_valid_status";
         when Require_Stapled_OCSP => return "require_stapled_ocsp";
      end case;
   end Image;

   function Image (Item : Evidence_Source) return String is
   begin
      case Item is
         when Stapled_By_Peer         => return "stapled_by_peer";
         when Supplied_By_Application => return "supplied_by_application";
      end case;
   end Image;

   function Image (Item : Status_Answer) return String is
   begin
      case Item is
         when Not_Revoked           => return "not_revoked";
         when Revoked               => return "revoked";
         when Status_Unknown        => return "unknown";
         when Status_Stale          => return "stale";
         when Wrong_Issuer          => return "wrong_issuer";
         when Untrusted_Signature   => return "untrusted_signature";
         when Unsupported_Statement => return "unsupported_statement";
         when Malformed_Status      => return "malformed";
      end case;
   end Image;

   function Is_Affirmative (Item : Status_Answer) return Boolean is (Item = Not_Revoked);
   function Is_Revocation (Item : Status_Answer) return Boolean is (Item = Revoked);

   ----------------------
   -- Is_Satisfiable --
   ----------------------

   function Is_Satisfiable
     (Item              : Revocation_Policy;
      Requests_Stapling : Boolean;
      Has_Provider      : Boolean) return Boolean
   is
   begin
      case Item is
         when Revocation_Disabled | Check_When_Available =>
            --  Neither demands anything, so both are always satisfiable.
            return True;

         when Require_Valid_Status =>
            --  Status has to be able to arrive from somewhere.
            return Requests_Stapling or else Has_Provider;

         when Require_Stapled_OCSP =>
            --  Only the peer's own staple counts, so the request must be sent.
            return Requests_Stapling;
      end case;
   end Is_Satisfiable;

   --------------
   -- Evaluate --
   --------------

   procedure Evaluate
     (Policy    : Revocation_Policy;
      Answer    : Status_Answer;
      Source    : Evidence_Source;
      Available : Boolean;
      At_Time   : SSL.Clocks.Wall_Time;
      Bounds    : SSL.Limits.Resource_Limits;
      Error     : out SSL.Errors.Error_Information)
   is
      pragma Unreferenced (Bounds);
      use SSL.Errors;
   begin
      Error := No_Error;

      --  An explicit revocation always fails, in every mode. Disabling
      --  revocation checking means not going looking for status; it has never
      --  meant ignoring a revocation that arrived anyway, and a library that
      --  read it that way would discard the one answer that matters most.
      if Available and then Is_Revocation (Answer) then
         Error := Make
           (Code       => Code_Certificate_Revoked,
            Origin     => Peer_Message,
            Parameters =>
              [Text_Parameter ("source", Image (Source)),
               Text_Parameter ("at", SSL.Clocks.Image (At_Time))]);
         return;
      end if;

      case Policy is
         when Revocation_Disabled =>
            return;

         when Check_When_Available =>
            --  Absent or inconclusive status is not a failure here; that is
            --  what "when available" means. A revocation has already been
            --  handled above.
            return;

         when Require_Valid_Status | Require_Stapled_OCSP =>
            if not Available then
               Error := Make
                 (Code       => Code_Revocation_Status_Absent,
                  Origin     => Local_Policy,
                  Parameters => [Text_Parameter ("policy", Image (Policy))]);
               return;
            end if;

            --  Only the peer's own staple counts under the stricter mode. An
            --  application-supplied response may be from a cache the peer has
            --  no knowledge of, which is precisely what this mode declines to
            --  rely on.
            if Policy = Require_Stapled_OCSP and then Source /= Stapled_By_Peer then
               Error := Make
                 (Code       => Code_Stapled_Status_Required,
                  Origin     => Local_Policy,
                  Parameters => [Text_Parameter ("source", Image (Source))]);
               return;
            end if;

            case Answer is
               when Not_Revoked =>
                  return;

               when Revoked =>
                  --  Unreachable: handled above, before the policy is consulted.
                  Error := Make (Code_Certificate_Revoked, Peer_Message);

               when Status_Stale =>
                  Error := Make
                    (Code       => Code_Revocation_Status_Stale,
                     Origin     => Peer_Message,
                     Parameters => [Text_Parameter ("at", SSL.Clocks.Image (At_Time))]);

               when Wrong_Issuer | Untrusted_Signature =>
                  --  A response that does not belong to this certificate, or
                  --  that nobody trusted, is worse than no response: it is an
                  --  attempt to answer a question about something else.
                  Error := Make
                    (Code       => Code_Stapled_Status_Wrong_Certificate,
                     Origin     => Peer_Message,
                     Parameters => [Text_Parameter ("answer", Image (Answer))]);

               when Malformed_Status =>
                  Error := Make
                    (Code   => Code_Stapled_Status_Malformed,
                     Origin => Peer_Message);

               when Status_Unknown | Unsupported_Statement =>
                  Error := Make
                    (Code       => Code_Revocation_Status_Unknown,
                     Origin     => Peer_Message,
                     Parameters => [Text_Parameter ("answer", Image (Answer))]);
            end case;
      end case;
   end Evaluate;

end SSL.Trust.Revocation;
