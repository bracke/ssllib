with Tests_Internals;
with Tests_Policy;
with Tests_Public;

package body Tests_Suite is

   Internals_Case : aliased Tests_Internals.Test_Case;
   Policy_Case    : aliased Tests_Policy.Test_Case;
   Public_Case    : aliased Tests_Public.Test_Case;

   -----------
   -- Suite --
   -----------

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      Result : constant AUnit.Test_Suites.Access_Test_Suite :=
        AUnit.Test_Suites.New_Suite;
   begin
      AUnit.Test_Suites.Add_Test (Result, Public_Case'Access);
      AUnit.Test_Suites.Add_Test (Result, Policy_Case'Access);
      AUnit.Test_Suites.Add_Test (Result, Internals_Case'Access);
      return Result;
   end Suite;

end Tests_Suite;
