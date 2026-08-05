with AUnit;
with AUnit.Test_Cases;

--  @summary AUnit cases over the configuration layer: clocks, cancellation,
--  authentication outcomes, and the builders with their validation.
--
--  The negative cases are the point of this file. A configuration that cannot
--  work must be refused at Build with a named reason, not accepted and left to
--  fail at the first handshake -- or, worse, at the first handshake against one
--  particular peer. So most of what is checked here is what the builders and
--  Build *refuse*.
package Tests_Policy is

   type Test_Case is new AUnit.Test_Cases.Test_Case with null record;

   overriding function Name (T : Test_Case) return AUnit.Message_String;
   overriding procedure Register_Tests (T : in out Test_Case);

end Tests_Policy;
