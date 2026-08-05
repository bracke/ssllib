with AUnit;

--  @summary The one place the whole suite asserts through, plus hexadecimal
--  helpers.
--
--  Every check goes through Expect rather than calling AUnit.Assertions.Assert
--  directly, so that there is a single place to change how a failure is
--  reported and a single place a reviewer has to read to know what a failing
--  test prints.
--
--  The internal checks in SSL.Internal_Tests return a diagnostic string --
--  empty for pass -- rather than asserting themselves, because they live in the
--  SSL hierarchy and the runtime library must not depend on AUnit. Expect_Ok is
--  the adapter between the two conventions.
package Tests_Support is

   --  Assert a condition, reporting Message when it does not hold.
   procedure Expect (Condition : Boolean; Message : String);

   --  Assert that an internal check passed. The check's own diagnostic is the
   --  failure message, so a failing test says what disagreed rather than only
   --  which check failed.
   --  @param Diagnostic the empty string for a pass, otherwise the detail
   --  @param Label      what was being checked
   procedure Expect_Ok (Diagnostic : String; Label : String);

   --  Assert that two strings are equal, reporting both when they are not.
   procedure Expect_Equal (Actual : String; Expected : String; Label : String);

   --  An AUnit message string from ordinary text.
   --  Compare two counts, reporting both when they differ.
   procedure Expect_Equal (Actual : Natural; Expected : Natural; Label : String);

   --  Where Needle first appears in Haystack, or zero. Used to assert that a
   --  rendering does or does not carry a particular piece of text -- which is
   --  how the redaction rules are checked.
   function Index_Of (Haystack : String; Needle : String) return Natural;

   function Message (Text : String) return AUnit.Message_String;

end Tests_Support;
