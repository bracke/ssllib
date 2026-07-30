with AUnit;
with AUnit.Test_Cases;

--  @summary AUnit cases over the public API: identifiers, versions, suites,
--  groups, signature schemes, ALPN, server names, limits, alerts and errors.
--
--  These are the packages an application sees, so the checks here are written
--  the way an application would use them, not the way the implementation is
--  built. Several of them are negative: what a name parser refuses, what a
--  policy combination refuses, and which alert a failure maps to are all part of
--  the contract, and a suite that only checked the happy path would let any of
--  them change silently.
package Tests_Public is

   type Test_Case is new AUnit.Test_Cases.Test_Case with null record;

   overriding function Name (T : Test_Case) return AUnit.Message_String;
   overriding procedure Register_Tests (T : in out Test_Case);

end Tests_Public;
