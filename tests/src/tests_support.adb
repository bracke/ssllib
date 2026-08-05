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

   ----------------------
   -- Expect_Equal --
   ----------------------

   procedure Expect_Equal (Actual : Natural; Expected : Natural; Label : String) is
   begin
      Expect_Equal (Actual'Image, Expected'Image, Label);
   end Expect_Equal;

   ------------------
   -- Index_Of --
   ------------------

   function Index_Of (Haystack : String; Needle : String) return Natural is
   begin
      if Needle'Length = 0 or else Needle'Length > Haystack'Length then
         return 0;
      end if;

      for Start in Haystack'First .. Haystack'Last - Needle'Length + 1 loop
         if Haystack (Start .. Start + Needle'Length - 1) = Needle then
            return Start;
         end if;
      end loop;
      return 0;
   end Index_Of;

end Tests_Support;
