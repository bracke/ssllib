with Ada.Command_Line;

with AUnit.Reporter.Text;
with AUnit.Run;
with AUnit;

with Tests_Suite;

use type AUnit.Status;

--  The AUnit runner, and nothing else. One line per test, a total, and a
--  non-zero exit status when anything failed, so the Ada tooling can gate on it
--  without parsing the output.
procedure Ssllib_Tests is
   function Run is new AUnit.Run.Test_Runner_With_Status (Tests_Suite.Suite);
   Reporter : AUnit.Reporter.Text.Text_Reporter;
   Result   : AUnit.Status;
begin
   Result := Run (Reporter);
   if Result /= AUnit.Success then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Ssllib_Tests;
