with AUnit.Test_Suites;

--  @summary The suite, built from one test case per topic.
--
--  A topic added to the suite is a topic that runs; a topic left out passes
--  without testing anything. Both this and Register_Tests inside each case are
--  checked by the ssllib_tools test-suite audit.
package Tests_Suite is

   function Suite return AUnit.Test_Suites.Access_Test_Suite;

end Tests_Suite;
