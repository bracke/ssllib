package body SSL.Authentication is

   -----------
   -- Image --
   -----------

   function Image (Item : Client_Authentication_Policy) return String is
   begin
      case Item is
         when Not_Requested      => return "not_requested";
         when Requested_Optional => return "requested_optional";
         when Required           => return "required";
      end case;
   end Image;

   function Image (Item : Authentication_Basis) return String is
   begin
      case Item is
         when Unauthenticated   => return "unauthenticated";
         when Certificate_Chain => return "certificate_chain";
         when Resumed_Session   => return "resumed_session";
      end case;
   end Image;

   ---------------------------
   -- Unauthenticated_Peer --
   ---------------------------

   function Unauthenticated_Peer return Peer_Authentication is
   begin
      return (others => <>);
   end Unauthenticated_Peer;

   ---------------
   -- Basis_Of --
   ---------------

   function Basis_Of (Item : Peer_Authentication) return Authentication_Basis is
   begin
      return Item.Basis;
   end Basis_Of;

   -----------------------
   -- Is_Authenticated --
   -----------------------

   function Is_Authenticated (Item : Peer_Authentication) return Boolean is
   begin
      return Item.Basis /= Unauthenticated;
   end Is_Authenticated;

   ---------------------------------
   -- Is_Freshly_Authenticated --
   ---------------------------------

   function Is_Freshly_Authenticated (Item : Peer_Authentication) return Boolean is
   begin
      return Item.Basis = Certificate_Chain;
   end Is_Freshly_Authenticated;

   -----------------------
   -- Authenticated_At --
   -----------------------

   function Authenticated_At (Item : Peer_Authentication) return SSL.Clocks.Wall_Time is
   begin
      return Item.At_Time;
   end Authenticated_At;

   --------------------
   -- Verified_Name --
   --------------------

   function Verified_Name (Item : Peer_Authentication) return SSL.Server_Names.DNS_Name is
   begin
      return Item.Name;
   end Verified_Name;

   -----------------------
   -- Verified_Address --
   -----------------------

   function Verified_Address (Item : Peer_Authentication) return SSL.Server_Names.IP_Address is
   begin
      return Item.Address;
   end Verified_Address;

   ---------------------
   -- Signature_Used --
   ---------------------

   function Signature_Used
     (Item   : Peer_Authentication;
      Scheme : out SSL.Signature_Schemes.Signature_Scheme) return Boolean
   is
   begin
      Scheme := Item.Scheme;
      return Item.Has_Scheme;
   end Signature_Used;

   -----------------
   -- Path_Length --
   -----------------

   function Path_Length (Item : Peer_Authentication) return Natural is
   begin
      return Item.Path;
   end Path_Length;

   ----------------------
   -- Leaf_Fingerprint --
   ----------------------

   function Leaf_Fingerprint
     (Item        : Peer_Authentication;
      Fingerprint : out Certificate_Fingerprint) return Boolean
   is
   begin
      Fingerprint := Item.Leaf;
      return Item.Has_Leaf;
   end Leaf_Fingerprint;

   ---------------------------------
   -- Public_Key_Fingerprint --
   ---------------------------------

   function Public_Key_Fingerprint
     (Item        : Peer_Authentication;
      Fingerprint : out Certificate_Fingerprint) return Boolean
   is
   begin
      Fingerprint := Item.Public_Key;
      return Item.Has_Key;
   end Public_Key_Fingerprint;

   -----------
   -- Fresh --
   -----------

   function Fresh
     (At_Time      : SSL.Clocks.Wall_Time;
      Name         : SSL.Server_Names.DNS_Name;
      Address      : SSL.Server_Names.IP_Address;
      Scheme       : SSL.Signature_Schemes.Signature_Scheme;
      Path_Length  : Positive;
      Leaf         : Certificate_Fingerprint;
      Public_Key   : Certificate_Fingerprint) return Peer_Authentication
   is
   begin
      return (Basis      => Certificate_Chain,
              At_Time    => At_Time,
              Name       => Name,
              Address    => Address,
              Has_Scheme => True,
              Scheme     => Scheme,
              Path       => Path_Length,
              Has_Leaf   => True,
              Leaf       => Leaf,
              Has_Key    => True,
              Public_Key => Public_Key);
   end Fresh;

   -------------
   -- Resumed --
   -------------

   function Resumed (From : Peer_Authentication) return Peer_Authentication is
      Result : Peer_Authentication := From;
   begin
      Result.Basis := Resumed_Session;

      --  The signature scheme is dropped deliberately. No CertificateVerify was
      --  made in this handshake, and reporting the earlier one would let an
      --  application believe it had seen a signature it did not see.
      Result.Has_Scheme := False;

      --  The path length goes too, for the same reason: no path was built.
      Result.Path := 0;

      --  The authentication time is *not* updated. It is the age of the
      --  evidence, and a resumption does not refresh it -- which is the whole
      --  point of keeping this field.
      return Result;
   end Resumed;

   -----------
   -- Image --
   -----------

   function Image (Item : Peer_Authentication) return String is
   begin
      case Item.Basis is
         when Unauthenticated =>
            return "unauthenticated";

         when Certificate_Chain =>
            declare
               Identity : constant String :=
                 (if SSL.Server_Names.Is_Present (Item.Name)
                  then SSL.Server_Names.Image (Item.Name)
                  elsif SSL.Server_Names.Is_Present (Item.Address)
                  then SSL.Server_Names.Image (Item.Address)
                  else "no-identity");
            begin
               return "certificate_chain identity=" & Identity
                 & " scheme=" & SSL.Signature_Schemes.Image (Item.Scheme)
                 & " path=" & Item.Path'Image
                 & " at=" & SSL.Clocks.Image (Item.At_Time);
            end;

         when Resumed_Session =>
            declare
               Identity : constant String :=
                 (if SSL.Server_Names.Is_Present (Item.Name)
                  then SSL.Server_Names.Image (Item.Name)
                  elsif SSL.Server_Names.Is_Present (Item.Address)
                  then SSL.Server_Names.Image (Item.Address)
                  else "no-identity");
            begin
               --  The original time is rendered, and labelled, because the
               --  reader's question is how old this evidence is.
               return "resumed_session identity=" & Identity
                 & " originally_authenticated_at=" & SSL.Clocks.Image (Item.At_Time);
            end;
      end case;
   end Image;

end SSL.Authentication;
