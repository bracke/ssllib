with AUnit.Assertions;

package body Tests_Support is

   ------------
   -- Expect --
   ------------

   procedure Expect (Condition : Boolean; Message : String) is
   begin
      AUnit.Assertions.Assert (Condition, Message);
   end Expect;

   ----------------
   -- Expect_Ok --
   ----------------

   procedure Expect_Ok (Diagnostic : String; Label : String) is
   begin
      Expect (Diagnostic = "", Label & " -- " & Diagnostic);
   end Expect_Ok;

   -------------------
   -- Expect_Equal --
   -------------------

   procedure Expect_Equal (Actual : String; Expected : String; Label : String) is
   begin
      Expect (Actual = Expected,
              Label & ": expected """ & Expected & """, got """ & Actual & """");
   end Expect_Equal;

   -------------
   -- Message --
   -------------

   function Message (Text : String) return AUnit.Message_String is
   begin
      return AUnit.Format (Text);
   end Message;

end Tests_Support;
