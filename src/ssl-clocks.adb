with Ada.Calendar.Formatting;
with Ada.Calendar.Time_Zones;

package body SSL.Clocks is

   use type Ada.Real_Time.Time;
   use type Ada.Real_Time.Time_Span;

   -------------------
   -- No_Wall_Time --
   -------------------

   function No_Wall_Time return Wall_Time is
   begin
      return (others => <>);
   end No_Wall_Time;

   ----------------
   -- Is_Present --
   ----------------

   function Is_Present (Item : Wall_Time) return Boolean is
   begin
      return Item.Present;
   end Is_Present;

   ---------
   -- UTC --
   ---------

   function UTC
     (Year   : Year_Number;
      Month  : Month_Number;
      Day    : Day_Number;
      Hour   : Hour_Number := 0;
      Minute : Minute_Number := 0;
      Second : Second_Number := 0) return Wall_Time
   is
   begin
      return (Present => True,
              Year    => Year,
              Month   => Month,
              Day     => Day,
              Hour    => Hour,
              Minute  => Minute,
              Second  => Second);
   end UTC;

   -----------------------
   -- From_Calendar_UTC --
   -----------------------

   function From_Calendar_UTC (Item : Ada.Calendar.Time) return Wall_Time is
      Year    : Ada.Calendar.Year_Number;
      Month   : Ada.Calendar.Month_Number;
      Day     : Ada.Calendar.Day_Number;
      Hour    : Ada.Calendar.Formatting.Hour_Number;
      Minute  : Ada.Calendar.Formatting.Minute_Number;
      Second  : Ada.Calendar.Formatting.Second_Number;
      Sub     : Ada.Calendar.Formatting.Second_Duration;
      Leap    : Boolean;
   begin
      --  Split with an explicit zero time-zone offset. Ada.Calendar.Split
      --  without one yields local time on most implementations, and a local
      --  reading would shift a certificate's validity window by the machine's
      --  offset from UTC.
      Ada.Calendar.Formatting.Split
        (Date       => Item,
         Year       => Year,
         Month      => Month,
         Day        => Day,
         Hour       => Hour,
         Minute     => Minute,
         Second     => Second,
         Sub_Second => Sub,
         Leap_Second => Leap,
         Time_Zone  => Ada.Calendar.Time_Zones.Time_Offset (0));

      --  Sub-second precision is dropped: X.509 validity has none, and every
      --  comparison this value takes part in is against another one-second
      --  value.
      return UTC (Year   => Natural (Year),
                  Month  => Natural (Month),
                  Day    => Natural (Day),
                  Hour   => Natural (Hour),
                  Minute => Natural (Minute),
                  Second => Natural (Second));
   end From_Calendar_UTC;

   ------------------
   -- Current_UTC --
   ------------------

   function Current_UTC return Wall_Time is
   begin
      return From_Calendar_UTC (Ada.Calendar.Clock);
   end Current_UTC;

   ---------------
   -- Accessors --
   ---------------

   function Year_Of (Item : Wall_Time) return Year_Number is (Item.Year);
   function Month_Of (Item : Wall_Time) return Month_Number is (Item.Month);
   function Day_Of (Item : Wall_Time) return Day_Number is (Item.Day);
   function Hour_Of (Item : Wall_Time) return Hour_Number is (Item.Hour);
   function Minute_Of (Item : Wall_Time) return Minute_Number is (Item.Minute);
   function Second_Of (Item : Wall_Time) return Second_Number is (Item.Second);

   ---------
   -- "<" --
   ---------

   function "<" (Left, Right : Wall_Time) return Boolean is
   begin
      --  An absent time sorts before every present one, which makes a
      --  "not yet valid" check against an unset clock refuse rather than pass.
      if not Left.Present then
         return Right.Present;
      end if;
      if not Right.Present then
         return False;
      end if;

      if Left.Year /= Right.Year then
         return Left.Year < Right.Year;
      end if;
      if Left.Month /= Right.Month then
         return Left.Month < Right.Month;
      end if;
      if Left.Day /= Right.Day then
         return Left.Day < Right.Day;
      end if;
      if Left.Hour /= Right.Hour then
         return Left.Hour < Right.Hour;
      end if;
      if Left.Minute /= Right.Minute then
         return Left.Minute < Right.Minute;
      end if;
      return Left.Second < Right.Second;
   end "<";

   function "<=" (Left, Right : Wall_Time) return Boolean is
   begin
      return not (Right < Left);
   end "<=";

   -----------
   -- Image --
   -----------

   function Image (Item : Wall_Time) return String is

      function Padded (Value : Natural; Width : Positive) return String is
         Text   : constant String := Value'Image;
         Digits_Text : constant String := Text (Text'First + 1 .. Text'Last);
      begin
         if Digits_Text'Length >= Width then
            return Digits_Text;
         end if;
         return [1 .. Width - Digits_Text'Length => '0'] & Digits_Text;
      end Padded;

   begin
      if not Item.Present then
         return "none";
      end if;

      return Padded (Item.Year, 4) & "-" & Padded (Item.Month, 2) & "-"
        & Padded (Item.Day, 2) & "T" & Padded (Item.Hour, 2) & ":"
        & Padded (Item.Minute, 2) & ":" & Padded (Item.Second, 2) & "Z";
   end Image;

   ---------------------------------------------------------------------------
   --  Monotonic time
   ---------------------------------------------------------------------------

   -------------------------
   -- Current_Monotonic --
   -------------------------

   function Current_Monotonic return Monotonic_Time is
   begin
      return (Value => Ada.Real_Time.Clock);
   end Current_Monotonic;

   -----------------------------
   -- Elapsed_Milliseconds --
   -----------------------------

   function Elapsed_Milliseconds (From : Monotonic_Time; To : Monotonic_Time) return Natural is
   begin
      if To.Value <= From.Value then
         return 0;
      end if;

      declare
         Span    : constant Ada.Real_Time.Time_Span := To.Value - From.Value;
         Seconds : constant Duration := Ada.Real_Time.To_Duration (Span);
         Millis  : constant Duration := Seconds * 1000.0;
      begin
         --  Saturate rather than overflow. A span this long means a caller kept
         --  a connection open for weeks, which is legal and which no deadline
         --  arithmetic needs to represent exactly.
         if Millis >= Duration (Natural'Last) then
            return Natural'Last;
         end if;
         return Natural (Millis);
      end;
   end Elapsed_Milliseconds;

   ------------------
   -- No_Deadline --
   ------------------

   function No_Deadline return Deadline is
   begin
      return (others => <>);
   end No_Deadline;

   ------------
   -- Is_Set --
   ------------

   function Is_Set (Item : Deadline) return Boolean is
   begin
      return Item.Set;
   end Is_Set;

   -----------------
   -- At_Offset --
   -----------------

   function At_Offset (From : Monotonic_Time; Milliseconds : Natural) return Deadline is
   begin
      return (Set   => True,
              Value => From.Value + Ada.Real_Time.Milliseconds (Milliseconds));
   end At_Offset;

   -------------------------
   -- In_Milliseconds --
   -------------------------

   function In_Milliseconds (Milliseconds : Natural) return Deadline is
   begin
      return At_Offset (Current_Monotonic, Milliseconds);
   end In_Milliseconds;

   -----------------
   -- Has_Expired --
   -----------------

   function Has_Expired (Item : Deadline; At_Time : Monotonic_Time) return Boolean is
   begin
      return Item.Set and then At_Time.Value >= Item.Value;
   end Has_Expired;

   -------------------------------
   -- Remaining_Milliseconds --
   -------------------------------

   function Remaining_Milliseconds (Item : Deadline; At_Time : Monotonic_Time) return Natural is
   begin
      if not Item.Set then
         --  Uniformly "wait at most this long", so a caller can pass the result
         --  to a poll without branching on whether a deadline was set.
         return Natural'Last;
      end if;
      return Elapsed_Milliseconds (At_Time, (Value => Item.Value));
   end Remaining_Milliseconds;

   ---------------------------------------------------------------------------
   --  Instants as a number
   ---------------------------------------------------------------------------

   --  Days from 1970-01-01 to a civil date, by Howard Hinnant's `days_from_civil`.
   --
   --  Written out rather than reached for through Ada.Calendar because
   --  Ada.Calendar's own epoch is 1901 and its arithmetic goes through Duration,
   --  which is a fixed-point type with a range this library must not depend on
   --  for dates a century out. This is integer arithmetic with no such limit,
   --  and it is exact for every date in the proleptic Gregorian calendar.
   function Days_From_Civil
     (Year : Integer; Month : Integer; Day : Integer) return Long_Long_Integer;

   function Days_From_Civil
     (Year : Integer; Month : Integer; Day : Integer) return Long_Long_Integer
   is
      --  March-based years, so that the leap day falls at the end and the
      --  century rules need no special case.
      Shifted : constant Long_Long_Integer :=
        Long_Long_Integer (Year) - (if Month <= 2 then 1 else 0);
      Era     : constant Long_Long_Integer :=
        (if Shifted >= 0 then Shifted else Shifted - 399) / 400;
      Year_Of_Era : constant Long_Long_Integer := Shifted - Era * 400;
      Day_Of_Year : constant Long_Long_Integer :=
        (153 * (Long_Long_Integer (Month) + (if Month > 2 then -3 else 9)) + 2) / 5
        + Long_Long_Integer (Day) - 1;
      Day_Of_Era  : constant Long_Long_Integer :=
        Year_Of_Era * 365 + Year_Of_Era / 4 - Year_Of_Era / 100 + Day_Of_Year;
   begin
      return Era * 146_097 + Day_Of_Era - 719_468;
   end Days_From_Civil;

   --  The inverse, `civil_from_days`.
   procedure Civil_From_Days
     (Days  : Long_Long_Integer;
      Year  : out Integer;
      Month : out Integer;
      Day   : out Integer);

   procedure Civil_From_Days
     (Days  : Long_Long_Integer;
      Year  : out Integer;
      Month : out Integer;
      Day   : out Integer)
   is
      Shifted     : constant Long_Long_Integer := Days + 719_468;
      Era         : constant Long_Long_Integer :=
        (if Shifted >= 0 then Shifted else Shifted - 146_096) / 146_097;
      Day_Of_Era  : constant Long_Long_Integer := Shifted - Era * 146_097;
      Year_Of_Era : constant Long_Long_Integer :=
        (Day_Of_Era - Day_Of_Era / 1_460 + Day_Of_Era / 36_524 - Day_Of_Era / 146_096) / 365;
      Day_Of_Year : constant Long_Long_Integer :=
        Day_Of_Era - (365 * Year_Of_Era + Year_Of_Era / 4 - Year_Of_Era / 100);
      Month_Prime : constant Long_Long_Integer := (5 * Day_Of_Year + 2) / 153;
   begin
      Day := Integer (Day_Of_Year - (153 * Month_Prime + 2) / 5 + 1);
      Month := Integer (Month_Prime + (if Month_Prime < 10 then 3 else -9));
      Year := Integer (Year_Of_Era + Era * 400 + (if Month <= 2 then 1 else 0));
   end Civil_From_Days;

   -----------------------------------
   -- Seconds_Since_Epoch --
   -----------------------------------

   function Seconds_Since_Epoch (Item : Wall_Time) return Interfaces.Unsigned_64 is
      use type Interfaces.Unsigned_64;

      Days : constant Long_Long_Integer :=
        Days_From_Civil (Integer (Item.Year), Integer (Item.Month), Integer (Item.Day));
      Total : constant Long_Long_Integer :=
        Days * 86_400
        + Long_Long_Integer (Item.Hour) * 3_600
        + Long_Long_Integer (Item.Minute) * 60
        + Long_Long_Integer (Item.Second);
   begin
      --  Anything before the epoch is reported as zero rather than wrapping.
      --  This library's uses -- ticket lifetimes and validity windows -- have no
      --  meaning before 1970, and a wrapped value would be a very large one.
      if Total <= 0 then
         return 0;
      end if;
      return Interfaces.Unsigned_64 (Total);
   end Seconds_Since_Epoch;

   -----------------------------------------
   -- From_Seconds_Since_Epoch --
   -----------------------------------------

   function From_Seconds_Since_Epoch (Value : Interfaces.Unsigned_64) return Wall_Time is
      use type Interfaces.Unsigned_64;

      --  The last instant this type can hold. Saturating here rather than
      --  wrapping is the whole point: a wrapped expiry is an expiry in the
      --  past, and would silently accept a ticket it should refuse.
      Ceiling : constant Interfaces.Unsigned_64 :=
        Interfaces.Unsigned_64
          (Days_From_Civil (Integer (Year_Number'Last), 12, 31) * 86_400
           + 23 * 3_600 + 59 * 60 + 59);

      Clamped : constant Interfaces.Unsigned_64 :=
        (if Value > Ceiling then Ceiling else Value);

      Days      : constant Long_Long_Integer := Long_Long_Integer (Clamped / 86_400);
      Remainder : constant Long_Long_Integer := Long_Long_Integer (Clamped mod 86_400);

      Year  : Integer;
      Month : Integer;
      Day   : Integer;
   begin
      Civil_From_Days (Days, Year, Month, Day);

      if Year < Year_Number'First then
         --  Before this type's range. Reported as its first instant, which
         --  compares before everything and therefore refuses rather than
         --  accepts.
         return UTC (Year_Number'First, 1, 1);
      end if;

      return UTC
        (Year   => Year_Number (Year),
         Month  => Month_Number (Month),
         Day    => Day_Number (Day),
         Hour   => Hour_Number (Remainder / 3_600),
         Minute => Minute_Number ((Remainder mod 3_600) / 60),
         Second => Second_Number (Remainder mod 60));
   end From_Seconds_Since_Epoch;

   --------------------
   -- Advanced --
   --------------------

   function Advanced (Item : Wall_Time; Seconds : Natural) return Wall_Time is
      use type Interfaces.Unsigned_64;
   begin
      return From_Seconds_Since_Epoch
        (Seconds_Since_Epoch (Item) + Interfaces.Unsigned_64 (Seconds));
   end Advanced;

end SSL.Clocks;
