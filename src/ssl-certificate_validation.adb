with Ada.Streams;

with CryptoLib.ASN1;
with CryptoLib.ASN1.Errors;
with CryptoLib.X509;
with CryptoLib.X509.Certificates;
with CryptoLib.X509.Identity;
with CryptoLib.X509.Path_Building;
with CryptoLib.OCSP;
with CryptoLib.X509.Purposes;
with CryptoLib.X509.Revocation;
with CryptoLib.X509.Validation;

with SSL.Crypto;

package body SSL.Certificate_Validation is

   -------------------
   -- No_Result --
   -------------------

   function No_Result return Validation_Result is
      Blank : Validation_Result;
   begin
      return Blank;
   end No_Result;

   use type Ada.Streams.Stream_Element_Array;
   use type CryptoLib.ASN1.Errors.Decode_Status;
   use type CryptoLib.X509.Identity.Match_Result;
   use type CryptoLib.X509.Public_Key_Algorithm;
   use type CryptoLib.X509.Purposes.Purpose_Result;
   use type CryptoLib.X509.Validation.Validation_Failure;

   package X509 renames CryptoLib.X509;

   ---------------------------------------------------------------------------
   --  Identity and role
   ---------------------------------------------------------------------------

   function For_Name (Value : SSL.Server_Names.DNS_Name) return Expected_Identity
   is ((Name => Value, Address => SSL.Server_Names.No_Address));

   function For_Address (Value : SSL.Server_Names.IP_Address) return Expected_Identity
   is ((Name => SSL.Server_Names.No_Name, Address => Value));

   function No_Identity return Expected_Identity is ((others => <>));

   function Has_Identity (Item : Expected_Identity) return Boolean
   is (SSL.Server_Names.Is_Present (Item.Name)
       or else SSL.Server_Names.Is_Present (Item.Address));

   function Image (Item : Certificate_Role) return String is
   begin
      case Item is
         when Server_Certificate => return "server_certificate";
         when Client_Certificate => return "client_certificate";
      end case;
   end Image;

   ---------------------------------------------------------------------------
   --  Result accessors
   ---------------------------------------------------------------------------

   function Path_Length (Item : Validation_Result) return Natural is (Item.Path);
   function Leaf_Fingerprint (Item : Validation_Result) return Certificate_Fingerprint
   is (Item.Leaf_Digest);
   function Public_Key_Fingerprint (Item : Validation_Result) return Certificate_Fingerprint
   is (Item.Key_Digest);
   function Leaf_Public_Key (Item : Validation_Result) return Byte_Array
   is (Item.Key_Octets (1 .. Item.Key_Length));
   function Leaf_Key_Type (Item : Validation_Result) return Leaf_Key_Kind is (Item.Key_Kind);

   ---------------------------------------------------------------------------
   --  The candidate pool
   --
   --  CryptoLib's path builder walks a pool of candidate issuers, asking which
   --  of them is a trust anchor. The pool here is the peer's chain followed by
   --  the snapshot's anchors, which is exactly the set a path may be built from:
   --  intermediates the peer supplied, and roots this endpoint already trusted.
   --
   --  A peer's own self-signed certificate is never an anchor. It is in the pool
   --  as a candidate issuer, and Is_Trust_Anchor answers on where the
   --  certificate came from rather than on what it says about itself -- which is
   --  the difference between a chain that reaches trust and one that merely
   --  claims to.
   ---------------------------------------------------------------------------

   type Pool
     (Chain_Ref  : not null access constant Chain_Storage;
      Chain_Size : Positive;
      Anchor_Ref : not null access constant SSL.Trust.Snapshot;
      Limits_Ref : not null access constant CryptoLib.ASN1.Decode_Limits)
   is limited new CryptoLib.X509.Path_Building.Candidate_Source
     and CryptoLib.X509.Validation.Path_Source with record
      Path_Count   : Natural := 0;
      Path_Indices : CryptoLib.X509.Path_Building.Path_Indices :=
        [others => 1];
   end record;

   overriding function Count (Source : Pool) return Natural;
   overriding function Candidate
     (Source : Pool; Index : Positive) return X509.Certificates.Certificate;
   overriding function Is_Trust_Anchor
     (Source : Pool; Item : X509.Certificates.Certificate) return Boolean;

   overriding function Length (Source : Pool) return Positive;
   overriding function Certificate_At
     (Source : Pool; Index : Positive) return X509.Certificates.Certificate;

   --  How many anchors are in the pool after the chain.
   function Anchor_Total (Source : Pool) return Natural is
   begin
      return SSL.Trust.Anchor_Count (Source.Anchor_Ref.all);
   end Anchor_Total;

   overriding function Count (Source : Pool) return Natural is
   begin
      return Source.Chain_Size + Anchor_Total (Source);
   end Count;

   --  Decode candidate Index. Indices one through Chain_Size are the peer's
   --  chain; the rest are anchors.
   overriding function Candidate
     (Source : Pool; Index : Positive) return X509.Certificates.Certificate
   is
      Status : CryptoLib.ASN1.Errors.Decode_Status;
   begin
      if Index <= Source.Chain_Size then
         declare
            Span : constant Certificate_Span := Source.Chain_Ref.Spans (Index);
         begin
            return X509.Certificates.Decode_DER
              (Source.Chain_Ref.Octets (Span.First .. Span.Last),
               Source.Limits_Ref.all,
               Status);
         end;
      end if;

      return X509.Certificates.Decode_DER
        (SSL.Trust.Anchor_At (Source.Anchor_Ref.all, Index - Source.Chain_Size),
         Source.Limits_Ref.all,
         Status);
   end Candidate;

   overriding function Is_Trust_Anchor
     (Source : Pool; Item : X509.Certificates.Certificate) return Boolean
   is
      Subject : constant CryptoLib.ASN1.Octets :=
        X509.Certificates.DER_Bytes (Item);
   begin
      --  Anchor-ness is decided by provenance: is this certificate one of the
      --  ones the snapshot holds? Not by whether it is self-signed, and not by
      --  anything it asserts about itself. A peer that sends its own root gets
      --  that root treated as an untrusted intermediate.
      for Index in 1 .. Anchor_Total (Source) loop
         if SSL.Trust.Anchor_At (Source.Anchor_Ref.all, Index) = Subject then
            return True;
         end if;
      end loop;
      return False;
   end Is_Trust_Anchor;

   overriding function Length (Source : Pool) return Positive is
   begin
      return Positive'Max (Source.Path_Count, 1);
   end Length;

   overriding function Certificate_At
     (Source : Pool; Index : Positive) return X509.Certificates.Certificate is
   begin
      return Candidate (Source, Source.Path_Indices (Index));
   end Certificate_At;

   ---------------------------------------------------------------------------
   --  Verdict mapping
   ---------------------------------------------------------------------------

   function Mapped_Path_Failure
     (Failure : X509.Validation.Validation_Failure) return SSL.Errors.Error_Information;

   function Mapped_Path_Failure
     (Failure : X509.Validation.Validation_Failure) return SSL.Errors.Error_Information
   is
      use SSL.Errors;
      use X509.Validation;

      --  The failure name is carried as provider text rather than mapped onto a
      --  distinct code per cause. The alert a peer sees is chosen from the code,
      --  and giving each PKIX failure its own code would give a peer a way to
      --  distinguish them.
      Detail : constant String := "cryptolib:" & Failure_Image (Failure);
   begin
      case Failure is
         when None =>
            return No_Error;

         when Certificate_Expired =>
            return Make (Code_Certificate_Expired, Peer_Message, Provider => Detail);

         when Certificate_Not_Yet_Valid =>
            return Make (Code_Certificate_Not_Yet_Valid, Peer_Message, Provider => Detail);

         when No_Trust_Anchor =>
            return Make (Code_Certificate_Untrusted_Anchor, Peer_Message, Provider => Detail);

         when Weak_Key =>
            return Make (Code_Certificate_Weak_Key, Peer_Message, Provider => Detail);

         when Invalid_Key_Usage =>
            return Make (Code_Certificate_Key_Usage_Rejected, Peer_Message, Provider => Detail);

         when Malformed_Certificate =>
            return Make (Code_Certificate_Malformed, Peer_Message, Provider => Detail);

         when others =>
            --  Invalid signature, issuer mismatch, basic constraints, path
            --  length, name constraints, unknown critical extension, duplicate,
            --  policy. All of them mean the same thing to a peer -- the chain
            --  did not validate -- and all of them map to bad_certificate.
            return Make (Code_Certificate_Path_Invalid, Peer_Message, Provider => Detail);
      end case;
   end Mapped_Path_Failure;

   ---------------------------------------------------------------------------
   --  The pipeline
   ---------------------------------------------------------------------------

   procedure Validate
     (Chain    : aliased Chain_Storage;
      Count    : Positive;
      Anchors  : aliased SSL.Trust.Snapshot;
      Identity : Expected_Identity;
      Role     : Certificate_Role;
      At_Time  : SSL.Clocks.Wall_Time;
      Bounds   : SSL.Limits.Resource_Limits;
      Result   : out Validation_Result;
      Error    : out SSL.Errors.Error_Information)
   is
      Fresh  : Validation_Result;
      Limits : aliased constant CryptoLib.ASN1.Decode_Limits :=
        (Maximum_Input_Size     => Bounds.Maximum_Certificate,
         Maximum_Nesting_Depth  => 16,
         Maximum_Sequence_Items => 1024,
         Maximum_String_Length  => 64 * 1024);

      Status      : CryptoLib.ASN1.Errors.Decode_Status;
   begin
      Result := Fresh;

      --  Step 0: bounds, before anything is decoded.
      if Count > Bounds.Maximum_Certificate_Count or else Count > Maximum_Chain then
         Error := SSL.Errors.Limit_Failure
           (Kind      => SSL.Limits.Certificate_Count,
            Allowed   => Long_Long_Integer
                           (Natural'Min (Bounds.Maximum_Certificate_Count, Maximum_Chain)),
            Requested => Long_Long_Integer (Count));
         return;
      end if;

      if not SSL.Trust.Is_Built (Anchors) or else SSL.Trust.Anchor_Count (Anchors) = 0 then
         --  No anchors means no chain can validate. Reported as a configuration
         --  failure rather than as a certificate failure, because it is one.
         Error := SSL.Errors.Make
           (Code   => SSL.Errors.Code_Trust_Required_But_Absent,
            Origin => SSL.Errors.Local_Policy);
         return;
      end if;

      --  Step 1 and 2: decode and parse the leaf. Everything after this needs it.
      declare
         Span : constant Certificate_Span := Chain.Spans (1);
         Leaf : constant X509.Certificates.Certificate :=
           X509.Certificates.Decode_DER
             (Chain.Octets (Span.First .. Span.Last), Limits, Status);
      begin
         if Status /= CryptoLib.ASN1.Errors.Ok
           or else not X509.Certificates.Is_Present (Leaf)
         then
            Error := SSL.Errors.Make
              (Code   => SSL.Errors.Code_Certificate_Malformed,
               Origin => SSL.Errors.Peer_Message);
            return;
         end if;

         --  Step 3: bounded path build, then step 4: path validation. Both are
         --  CryptoLib's; the bound on how far the search may go is this
         --  library's, from the configured limits.
         declare
            --  References, not copies: both parameters are declared aliased.
            --  A chain can be four megabytes and a trust snapshot larger, and
            --  validating one must not begin by duplicating it.
            Walker : Pool (Chain_Ref  => Chain'Access,
                           Chain_Size => Count,
                           Anchor_Ref => Anchors'Access,
                           Limits_Ref => Limits'Access);

            Search : constant X509.Path_Building.Search_Limits :=
              (Maximum_Depth => Positive'Min (Bounds.Maximum_Path_Depth,
                                              X509.Path_Building.Maximum_Path),
               Maximum_Links => 200);

            Built : constant X509.Path_Building.Build_Result :=
              X509.Path_Building.Build_Path (Leaf, Walker, Search);
         begin
            if not Built.Found then
               Error := SSL.Errors.Make
                 (Code       => SSL.Errors.Code_Certificate_Path_Not_Built,
                  Origin     => SSL.Errors.Peer_Message,
                  Parameters =>
                    [SSL.Errors.Numeric_Parameter
                       ("candidates_examined", Long_Long_Integer (Built.Examined)),
                     SSL.Errors.Numeric_Parameter
                       ("search_exhausted", (if Built.Exhausted then 1 else 0))]);
               return;
            end if;

            Walker.Path_Count := Built.Length;
            Walker.Path_Indices := Built.Indices;

            --  The clock is checked before the moment is built, not after.
            --  Every field accessor on Wall_Time requires a present value, so
            --  constructing the moment first would raise rather than refuse --
            --  which is what the "no clock" case caught.
            if not SSL.Clocks.Is_Present (At_Time) then
               --  Without a wall clock, validity cannot be judged. Refusing is
               --  the only safe answer: the alternative is accepting an expired
               --  certificate because nobody knew what day it was.
               Error := SSL.Errors.Make
                 (Code     => SSL.Errors.Code_Certificate_Path_Invalid,
                  Origin   => SSL.Errors.Local_Policy,
                  Provider => "no wall-clock time supplied for validity");
               return;
            end if;

            declare
               Policy : X509.Validation.Validation_Policy :=
                 X509.Validation.Default_Policy;
               Moment : constant X509.Certificate_Time :=
                 (Year   => SSL.Clocks.Year_Of (At_Time),
                  Month  => SSL.Clocks.Month_Of (At_Time),
                  Day    => SSL.Clocks.Day_Of (At_Time),
                  Hour   => SSL.Clocks.Hour_Of (At_Time),
                  Minute => SSL.Clocks.Minute_Of (At_Time),
                  Second => SSL.Clocks.Second_Of (At_Time));
            begin
               Policy.Maximum_Path_Length := Search.Maximum_Depth;

               declare
                  Verdict : constant X509.Validation.Validation_Result :=
                    X509.Validation.Validate_Path (Walker, Moment, Policy);
               begin
                  if not Verdict.Valid then
                     Error := Mapped_Path_Failure (Verdict.Failure);
                     return;
                  end if;
               end;
            end;

            Result.Path := Built.Length;
         end;

         --  Step 5 and 6: purpose and key usage. This is what stops a client
         --  certificate being accepted as a server's.
         declare
            Purpose : constant X509.Purposes.Certificate_Purpose :=
              (case Role is
                  when Server_Certificate => X509.Purposes.TLS_Server,
                  when Client_Certificate => X509.Purposes.TLS_Client);
            Verdict : constant X509.Purposes.Purpose_Result :=
              X509.Purposes.Check_Purpose (Leaf, Purpose);
         begin
            if Verdict /= X509.Purposes.Permitted then
               Error := SSL.Errors.Make
                 (Code       => SSL.Errors.Code_Certificate_Purpose_Rejected,
                  Origin     => SSL.Errors.Peer_Message,
                  Parameters =>
                    [SSL.Errors.Text_Parameter ("role", Image (Role)),
                     SSL.Errors.Text_Parameter
                       ("reason", X509.Purposes.Result_Image (Verdict))]);
               return;
            end if;
         end;

         --  Step 7: identity. After the path, never instead of it.
         if Has_Identity (Identity) then
            declare
               --  subjectAltName only. Allow_Common_Name_Fallback stays False,
               --  which is CryptoLib's default and is not configurable here.
               Policy : constant X509.Identity.Matching_Policy :=
                 (Allow_Wildcards            => True,
                  Allow_Common_Name_Fallback => False);
               Outcome : X509.Identity.Match_Result;
            begin
               if SSL.Server_Names.Is_Present (Identity.Name) then
                  Outcome := X509.Identity.Match_DNS_Name
                    (Leaf, SSL.Server_Names.Image (Identity.Name), Policy);
               else
                  Outcome := X509.Identity.Match_IP_Address
                    (Leaf, SSL.Server_Names.Octets (Identity.Address), Policy);
               end if;

               if Outcome /= X509.Identity.Matched then
                  Error := SSL.Errors.Make
                    (Code       => (if Outcome = X509.Identity.No_Names_Present
                                    then SSL.Errors.Code_Identity_No_Names_Present
                                    else SSL.Errors.Code_Identity_No_Match),
                     Origin     => SSL.Errors.Peer_Message,
                     Parameters =>
                       [SSL.Errors.Text_Parameter
                          ("expected",
                           (if SSL.Server_Names.Is_Present (Identity.Name)
                            then SSL.Server_Names.Image (Identity.Name)
                            else SSL.Server_Names.Image (Identity.Address)))],
                     Provider   => "cryptolib:" & X509.Identity.Result_Image (Outcome));
                  return;
               end if;
            end;
         elsif Role = Server_Certificate then
            --  A server chain with nothing to check it against is a caller
            --  error, not a peer error: SSL.Configurations refuses a client
            --  with no expected identity, so reaching here means the pipeline
            --  was driven wrongly.
            Error := SSL.Errors.Make
              (Code   => SSL.Errors.Code_Identity_Not_Specified,
               Origin => SSL.Errors.Caller_Request);
            return;
         end if;

         --  What the caller needs from the leaf. Revocation and pinning run
         --  next, in the caller, against this.
         declare
            Key : constant CryptoLib.ASN1.Octets := X509.Certificates.Public_Key (Leaf);
         begin
            if Key'Length > Maximum_Public_Key then
               Error := SSL.Errors.Make
                 (Code   => SSL.Errors.Code_Certificate_Malformed,
                  Origin => SSL.Errors.Peer_Message);
               return;
            end if;

            Result.Key_Length := Key'Length;
            Result.Key_Octets (1 .. Key'Length) := Key;

            case X509.Certificates.Public_Key_Algorithm_Of (Leaf) is
               when X509.RSA        => Result.Key_Kind := RSA_Key;
               when X509.ECDSA_P256 => Result.Key_Kind := ECDSA_P256;
               when X509.ECDSA_P384 => Result.Key_Kind := ECDSA_P384;
               when X509.ECDSA_P521 => Result.Key_Kind := ECDSA_P521;
               when X509.Ed25519    => Result.Key_Kind := Ed25519_Key;
               when X509.Ed448      => Result.Key_Kind := Ed448_Key;
               when others =>
                  Error := SSL.Errors.Make
                    (Code   => SSL.Errors.Code_Certificate_Purpose_Rejected,
                     Origin => SSL.Errors.Peer_Message);
                  return;
            end case;

            Result.Leaf_Digest :=
              (Subject => Whole_Certificate,
               Digest  => SSL.Crypto.SHA_256
                            (Chain.Octets (Span.First .. Span.Last)));
            Result.Key_Digest :=
              (Subject => Public_Key_Info,
               Digest  => SSL.Crypto.SHA_256
                            (X509.Certificates.Public_Key_Info_Bytes (Leaf)));
         end;
      end;

      Error := SSL.Errors.No_Error;
   end Validate;

   ---------------------------------------------------------------------------
   --  Stapled revocation status
   ---------------------------------------------------------------------------

   --  CryptoLib's answer in this library's own vocabulary. One place, so that
   --  no other unit depends on CryptoLib's enumeration.
   function Translate
     (Answer : X509.Revocation.Revocation_Answer)
      return SSL.Trust.Revocation.Status_Answer
   is (case Answer is
          when X509.Revocation.Not_Revoked    => SSL.Trust.Revocation.Not_Revoked,
          when X509.Revocation.Revoked        => SSL.Trust.Revocation.Revoked,
          when X509.Revocation.Unknown        => SSL.Trust.Revocation.Status_Unknown,
          when X509.Revocation.Stale          => SSL.Trust.Revocation.Status_Stale,
          when X509.Revocation.Wrong_Issuer   => SSL.Trust.Revocation.Wrong_Issuer,
          when X509.Revocation.Untrusted_Signature =>
            SSL.Trust.Revocation.Untrusted_Signature,
          when X509.Revocation.Unsupported_Statement =>
            SSL.Trust.Revocation.Unsupported_Statement,
          when X509.Revocation.Malformed      => SSL.Trust.Revocation.Malformed_Status);

   procedure Check_Stapled_Status
     (Chain    : aliased Chain_Storage;
      Count    : Positive;
      Response : Byte_Array;
      At_Time  : SSL.Clocks.Wall_Time;
      Bounds   : SSL.Limits.Resource_Limits;
      Answer   : out SSL.Trust.Revocation.Status_Answer)
   is
      Limits : constant CryptoLib.ASN1.Decode_Limits :=
        (Maximum_Input_Size     => Bounds.Maximum_OCSP_Response,
         Maximum_Nesting_Depth  => 16,
         Maximum_Sequence_Items => 1024,
         Maximum_String_Length  => 64 * 1024);
   begin
      Answer := SSL.Trust.Revocation.Malformed_Status;

      if Response'Length = 0
        or else Response'Length > Byte_Index (Bounds.Maximum_OCSP_Response)
      then
         return;
      end if;

      if not SSL.Clocks.Is_Present (At_Time) then
         --  Without a clock there is no freshness window, and a signed "not
         --  revoked" from years ago would read as current. That is exactly what
         --  the window exists to prevent, so the answer is that nothing was
         --  established rather than that the certificate is good.
         Answer := SSL.Trust.Revocation.Status_Stale;
         return;
      end if;

      if Count < 2 then
         --  A chain of one has no issuer to have signed a statement about it.
         --  Reported as wrong-issuer rather than as an affirmative, because
         --  nothing was checked.
         Answer := SSL.Trust.Revocation.Wrong_Issuer;
         return;
      end if;

      declare
         Status : CryptoLib.ASN1.Errors.Decode_Status;

         Leaf : constant X509.Certificates.Certificate :=
           X509.Certificates.Decode_DER
             (Chain.Octets (Chain.Spans (1).First .. Chain.Spans (1).Last),
              Limits, Status);
      begin
         if Status /= CryptoLib.ASN1.Errors.Ok then
            return;
         end if;

         declare
            Issuer : constant X509.Certificates.Certificate :=
              X509.Certificates.Decode_DER
                (Chain.Octets (Chain.Spans (2).First .. Chain.Spans (2).Last),
                 Limits, Status);
         begin
            if Status /= CryptoLib.ASN1.Errors.Ok then
               return;
            end if;

            declare
               Decoded : CryptoLib.OCSP.Response :=
                 CryptoLib.OCSP.Decode_Response (Response, Limits, Status);
               Moment  : constant X509.Certificate_Time :=
                 (Year   => SSL.Clocks.Year_Of (At_Time),
                  Month  => SSL.Clocks.Month_Of (At_Time),
                  Day    => SSL.Clocks.Day_Of (At_Time),
                  Hour   => SSL.Clocks.Hour_Of (At_Time),
                  Minute => SSL.Clocks.Minute_Of (At_Time),
                  Second => SSL.Clocks.Second_Of (At_Time));
            begin
               if Status /= CryptoLib.ASN1.Errors.Ok
                 or else not CryptoLib.OCSP.Is_Present (Decoded)
               then
                  return;
               end if;

               --  Everything from here -- the signature, the responder's
               --  authority, the freshness window, whether the response is even
               --  about this certificate -- is CryptoLib's. This translates the
               --  answer and does nothing else.
               Answer := Translate
                 (X509.Revocation.Check_Against_OCSP
                    (Item     => Leaf,
                     Issuer   => Issuer,
                     Response => Decoded,
                     At_Time  => Moment));
            end;
         end;
      end;
   end Check_Stapled_Status;

end SSL.Certificate_Validation;
