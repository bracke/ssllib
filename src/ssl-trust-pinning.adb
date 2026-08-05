package body SSL.Trust.Pinning is

   use type SSL.ALPN.Protocol_Name;

   -----------
   -- Image --
   -----------

   function Image (Item : Pinning_Mode) return String is
   begin
      case Item is
         when No_Pinning                 => return "no_pinning";
         when Require_Valid_Path_And_Pin => return "require_valid_path_and_pin";
         when Pin_Only                   => return "pin_only";
      end case;
   end Image;

   ----------
   -- Make --
   ----------

   function Make
     (Digest     : Certificate_Fingerprint;
      Name       : SSL.Server_Names.DNS_Name;
      Protocol   : SSL.ALPN.Protocol_Name;
      Not_Before : SSL.Clocks.Wall_Time;
      Not_After  : SSL.Clocks.Wall_Time;
      Item       : out Pin) return Boolean
   is
      use type SSL.Clocks.Wall_Time;
   begin
      Item := (Digest     => Digest,
               Name       => Name,
               Protocol   => Protocol,
               Not_Before => Not_Before,
               Not_After  => Not_After);

      --  Both ends are required. A pin with no end date outlives the key it
      --  names, and the day the key is retired it locks the application out of
      --  its own service -- with no date anywhere for anyone to have noticed.
      if not SSL.Clocks.Is_Present (Not_Before)
        or else not SSL.Clocks.Is_Present (Not_After)
      then
         return False;
      end if;

      return Not_Before < Not_After;
   end Make;

   ---------------
   -- Accessors --
   ---------------

   function Digest_Of (Item : Pin) return Certificate_Fingerprint is (Item.Digest);
   function Name_Of (Item : Pin) return SSL.Server_Names.DNS_Name is (Item.Name);
   function Protocol_Of (Item : Pin) return SSL.ALPN.Protocol_Name is (Item.Protocol);

   ----------------
   -- Is_Active --
   ----------------

   function Is_Active (Item : Pin; At_Time : SSL.Clocks.Wall_Time) return Boolean is
      use type SSL.Clocks.Wall_Time;
   begin
      --  An absent current time makes no pin active, because Wall_Time orders an
      --  absent value before every present one: the comparison refuses rather
      --  than passing. That is the safe direction -- a pin that could not be
      --  evaluated is a pin that is not satisfied.
      if not SSL.Clocks.Is_Present (At_Time) then
         return False;
      end if;
      return Item.Not_Before <= At_Time and then At_Time < Item.Not_After;
   end Is_Active;

   --------------
   -- Applies --
   --------------

   function Applies
     (Item     : Pin;
      Name     : SSL.Server_Names.DNS_Name;
      Protocol : SSL.ALPN.Protocol_Name) return Boolean
   is
   begin
      --  A pin with no name applies everywhere; a pin with one applies only
      --  where it matches. The pin's name may be a wildcard pattern, so the
      --  comparison is a match rather than an equality.
      if SSL.Server_Names.Is_Present (Item.Name) then
         if not SSL.Server_Names.Is_Present (Name) then
            return False;
         end if;
         if not SSL.Server_Names.Matches (Name, Item.Name) then
            return False;
         end if;
      end if;

      if SSL.ALPN.Is_Present (Item.Protocol) then
         if not SSL.ALPN.Is_Present (Protocol) then
            return False;
         end if;
         if not (Item.Protocol = Protocol) then
            return False;
         end if;
      end if;

      return True;
   end Applies;

   ---------------------------------------------------------------------------
   --  Sets
   ---------------------------------------------------------------------------

   function No_Pins return Pin_Set is ((others => <>));
   function Length (Item : Pin_Set) return Natural is (Item.Count);
   function Element (Item : Pin_Set; Index : Positive) return Pin is (Item.Items (Index));

   procedure Append (Item : in out Pin_Set; Value : Pin; Ok : out Boolean) is
   begin
      if Item.Count = Maximum_Pins then
         Ok := False;
         return;
      end if;
      Item.Count := Item.Count + 1;
      Item.Items (Item.Count) := Value;
      Ok := True;
   end Append;

   -------------------------
   -- Applicable_Count --
   -------------------------

   function Applicable_Count
     (Item     : Pin_Set;
      Name     : SSL.Server_Names.DNS_Name;
      Protocol : SSL.ALPN.Protocol_Name;
      At_Time  : SSL.Clocks.Wall_Time) return Natural
   is
      Total : Natural := 0;
   begin
      for Index in 1 .. Item.Count loop
         if Applies (Item.Items (Index), Name, Protocol)
           and then Is_Active (Item.Items (Index), At_Time)
         then
            Total := Total + 1;
         end if;
      end loop;
      return Total;
   end Applicable_Count;

   --------------
   -- Evaluate --
   --------------

   procedure Evaluate
     (Mode       : Pinning_Mode;
      Pins       : Pin_Set;
      Leaf       : Certificate_Fingerprint;
      Public_Key : Certificate_Fingerprint;
      Name       : SSL.Server_Names.DNS_Name;
      Protocol   : SSL.ALPN.Protocol_Name;
      At_Time    : SSL.Clocks.Wall_Time;
      Error      : out SSL.Errors.Error_Information)
   is
      Applicable : Natural := 0;
      Expired    : Natural := 0;
   begin
      Error := SSL.Errors.No_Error;

      if Mode = No_Pinning then
         return;
      end if;

      for Index in 1 .. Pins.Count loop
         declare
            Candidate : constant Pin := Pins.Items (Index);
         begin
            if Applies (Candidate, Name, Protocol) then
               if Is_Active (Candidate, At_Time) then
                  Applicable := Applicable + 1;

                  --  A certificate pin and an SPKI pin over the same octets are
                  --  different values, because Certificate_Fingerprint carries
                  --  which subject it is over. So one equality test cannot match
                  --  the wrong kind of digest.
                  if Candidate.Digest = Leaf or else Candidate.Digest = Public_Key then
                     return;
                  end if;
               else
                  Expired := Expired + 1;
               end if;
            end if;
         end;
      end loop;

      --  No pin applied here at all. This is not a pass: a set that holds pins,
      --  none of which covers this connection, means the configuration intended
      --  pinning and does not cover what it is doing.
      if Applicable = 0 then
         if Expired > 0 then
            Error := SSL.Errors.Make
              (Code       => SSL.Errors.Code_Pin_Expired,
               Origin     => SSL.Errors.Local_Policy,
               Parameters => [SSL.Errors.Numeric_Parameter
                                ("expired_pins", Long_Long_Integer (Expired))]);
         else
            Error := SSL.Errors.Make
              (Code       => SSL.Errors.Code_Pin_Scope_Mismatch,
               Origin     => SSL.Errors.Local_Policy,
               Parameters => [SSL.Errors.Numeric_Parameter
                                ("configured_pins", Long_Long_Integer (Pins.Count))]);
         end if;
         return;
      end if;

      --  Pins applied and none matched.
      Error := SSL.Errors.Make
        (Code       => SSL.Errors.Code_Pin_Not_Met,
         Origin     => SSL.Errors.Local_Policy,
         Parameters => [SSL.Errors.Numeric_Parameter
                          ("applicable_pins", Long_Long_Integer (Applicable))]);
   end Evaluate;

   ------------------------
   -- Is_Valid_Policy --
   ------------------------

   function Is_Valid_Policy (Mode : Pinning_Mode; Pins : Pin_Set) return Boolean is
   begin
      case Mode is
         when No_Pinning =>
            --  Configured pins that will not be consulted are not an error;
            --  they are a policy somebody has turned off.
            return True;
         when Require_Valid_Path_And_Pin | Pin_Only =>
            return Pins.Count > 0;
      end case;
   end Is_Valid_Policy;

end SSL.Trust.Pinning;
