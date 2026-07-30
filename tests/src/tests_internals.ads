with AUnit;
with AUnit.Test_Cases;

--  @summary AUnit cases over ssllib's private children, delegating to
--  SSL.Internal_Tests.
--
--  Registration is what runs a check. A check written in SSL.Internal_Tests and
--  not registered here passes without testing anything, which is the failure
--  mode this suite's structure is arranged to make visible: every
--  Check_<Name> has a Run_Check_<Name> wrapper registered below, and the
--  tooling's test-suite audit refuses a build where one does not.
package Tests_Internals is

   type Test_Case is new AUnit.Test_Cases.Test_Case with null record;

   overriding function Name (T : Test_Case) return AUnit.Message_String;
   overriding procedure Register_Tests (T : in out Test_Case);

end Tests_Internals;
