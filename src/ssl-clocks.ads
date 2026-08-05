with Interfaces;
private with Ada.Real_Time;

with Ada.Calendar;

--  @summary The two clocks this library needs, kept apart because they answer
--  different questions.
--
--  Certificate validity is a question about the world: a certificate is valid
--  between two dates, and only a wall clock knows what date it is. Deadlines are
--  questions about elapsed duration, and only a monotonic clock answers those
--  without moving when the system clock is stepped. Using either for the other's
--  job is a bug that shows up rarely and badly -- a deadline that fires an hour
--  early because NTP corrected a drift, or a certificate check that has no idea
--  what year it is.
--
--  Neither clock is read inside the engine. Time enters the engine as a
--  parameter, which is what makes the engine a function of its inputs: a test
--  can make a certificate expire without touching the machine's clock, and a
--  byte-boundary or mutation replay produces the same answer every time. The
--  reading functions here are for callers -- the blocking wrapper reads the
--  monotonic clock, and an application reads the wall clock when it sets up a
--  connection.
package SSL.Clocks is

   ---------------------------------------------------------------------------
   --  Wall time
   --
   --  UTC, to the second, broken down. Held as fields rather than as a scalar
   --  offset because that is the shape X.509 validity is expressed in, and
   --  because a broken-down UTC value has no time-zone ambiguity for a reader
   --  of a log to get wrong.
   ---------------------------------------------------------------------------

   subtype Year_Number is Natural range 1900 .. 9999;
   subtype Month_Number is Natural range 1 .. 12;
   subtype Day_Number is Natural range 1 .. 31;
   subtype Hour_Number is Natural range 0 .. 23;
   subtype Minute_Number is Natural range 0 .. 59;

   --  Leap seconds reach 60. Accepted on input because a certificate could
   --  carry one; never produced.
   subtype Second_Number is Natural range 0 .. 60;

   type Wall_Time is private;

   --  The value meaning "no time supplied". A validity check against it fails
   --  closed rather than passing, so an unset clock cannot accidentally
   --  validate an expired certificate.
   function No_Wall_Time return Wall_Time;

   function Is_Present (Item : Wall_Time) return Boolean;

   --  Build a UTC instant from its fields. The day is not checked against the
   --  month, because this value is only ever compared against another of the
   --  same shape and a nonsensical date compares consistently.
   function UTC
     (Year   : Year_Number;
      Month  : Month_Number;
      Day    : Day_Number;
      Hour   : Hour_Number := 0;
      Minute : Minute_Number := 0;
      Second : Second_Number := 0) return Wall_Time
     with Post => Is_Present (UTC'Result);

   --  Convert from Ada.Calendar, interpreting the value as UTC.
   --
   --  Ada.Calendar.Split yields local time on most implementations, so this
   --  uses Ada.Calendar.Formatting with a zero time-zone offset. A caller
   --  holding local time must convert it; this library does not guess at a
   --  zone, because guessing wrong shifts a certificate's validity window by
   --  hours.
   --  @param Item the calendar time, interpreted as UTC
   --  @return the wall time
   function From_Calendar_UTC (Item : Ada.Calendar.Time) return Wall_Time
     with Post => Is_Present (From_Calendar_UTC'Result);

   --  Read the system wall clock, as UTC. For callers; never called inside the
   --  engine.
   function Current_UTC return Wall_Time
     with Post => Is_Present (Current_UTC'Result);

   function Year_Of (Item : Wall_Time) return Year_Number with Pre => Is_Present (Item);
   function Month_Of (Item : Wall_Time) return Month_Number with Pre => Is_Present (Item);
   function Day_Of (Item : Wall_Time) return Day_Number with Pre => Is_Present (Item);
   function Hour_Of (Item : Wall_Time) return Hour_Number with Pre => Is_Present (Item);
   function Minute_Of (Item : Wall_Time) return Minute_Number with Pre => Is_Present (Item);
   function Second_Of (Item : Wall_Time) return Second_Number with Pre => Is_Present (Item);

   --  Chronological order. An absent time is ordered before every present one,
   --  so that a "not yet valid" check against an unset clock refuses.
   function "<" (Left, Right : Wall_Time) return Boolean;
   function "<=" (Left, Right : Wall_Time) return Boolean;

   --  ISO 8601 in UTC: "2026-07-30T13:01:00Z". Never a secret; safe for logs.
   function Image (Item : Wall_Time) return String;

   ---------------------------------------------------------------------------
   --  Instants as a number
   ---------------------------------------------------------------------------

   --  Seconds since 1970-01-01T00:00:00Z, in the proleptic Gregorian calendar
   --  and ignoring leap seconds.
   --
   --  Two things need this and neither is satisfied by the field form: a
   --  session ticket has to carry an instant across a process boundary, and a
   --  lifetime has to be added to one. Doing either by manipulating year,
   --  month and day would mean implementing calendar arithmetic at the call
   --  site, once per call site.
   --
   --  Leap seconds are ignored deliberately. TLS uses time for validity windows
   --  and ticket lifetimes, both measured in hours or days, and a
   --  leap-second-aware conversion would need a table that goes stale. The
   --  cost is that two instants a leap second apart may compare equal, which
   --  changes nothing this library decides.
   --  @param Item the instant, which must be present
   --  @return the count of seconds, zero for anything before the epoch
   function Seconds_Since_Epoch (Item : Wall_Time) return Interfaces.Unsigned_64
     with Pre => Is_Present (Item);

   --  The inverse. Values beyond the year range this type holds saturate at its
   --  last representable instant rather than wrapping, because a wrapped
   --  expiry is an expiry in the past and would silently accept what it should
   --  refuse.
   function From_Seconds_Since_Epoch (Value : Interfaces.Unsigned_64) return Wall_Time
     with Post => Is_Present (From_Seconds_Since_Epoch'Result);

   --  This instant plus a number of seconds.
   function Advanced (Item : Wall_Time; Seconds : Natural) return Wall_Time
     with Pre => Is_Present (Item), Post => Is_Present (Advanced'Result);

   ---------------------------------------------------------------------------
   --  Monotonic time
   --
   --  Sourced from Ada.Real_Time, which is monotonic by definition in every
   --  conforming implementation and needs no platform-specific code. The
   --  specification assigned monotonic clocks to Hostkit; Hostkit has none and
   --  does not need one. See docs/known-limitations.md.
   ---------------------------------------------------------------------------

   type Monotonic_Time is private;

   --  Read the monotonic clock. For callers -- the blocking wrapper and the
   --  synchronized wrapper -- never from inside the engine.
   function Current_Monotonic return Monotonic_Time;

   --  Milliseconds from Left to Right, saturating rather than overflowing. A
   --  negative interval reports zero: time did not go backwards, the caller
   --  passed the arguments the other way round.
   function Elapsed_Milliseconds (From : Monotonic_Time; To : Monotonic_Time) return Natural;

   --  A point by which an operation must have finished.
   type Deadline is private;

   --  No deadline at all: a blocking call waits indefinitely.
   function No_Deadline return Deadline;

   function Is_Set (Item : Deadline) return Boolean;

   --  A deadline the given number of milliseconds after a stated instant. The
   --  instant is a parameter so that a caller can compute a deadline without
   --  reading a clock, which is what a deterministic test needs.
   function At_Offset (From : Monotonic_Time; Milliseconds : Natural) return Deadline
     with Post => Is_Set (At_Offset'Result);

   --  A deadline the given number of milliseconds from now. Reads the clock.
   function In_Milliseconds (Milliseconds : Natural) return Deadline
     with Post => Is_Set (In_Milliseconds'Result);

   --  Has the deadline passed at the stated instant? An unset deadline never
   --  expires.
   function Has_Expired (Item : Deadline; At_Time : Monotonic_Time) return Boolean
     with Post => (if not Is_Set (Item) then not Has_Expired'Result);

   --  How long is left, in milliseconds, at the stated instant. Zero when
   --  expired; Natural'Last for an unset deadline, so that a caller passing
   --  this to a poll can treat it uniformly as "wait at most this long".
   function Remaining_Milliseconds (Item : Deadline; At_Time : Monotonic_Time) return Natural
     with Post => (if not Is_Set (Item) then Remaining_Milliseconds'Result = Natural'Last);

private

   type Wall_Time is record
      Present : Boolean := False;
      Year    : Year_Number := 1900;
      Month   : Month_Number := 1;
      Day     : Day_Number := 1;
      Hour    : Hour_Number := 0;
      Minute  : Minute_Number := 0;
      Second  : Second_Number := 0;
   end record;

   type Monotonic_Time is record
      Value : Ada.Real_Time.Time := Ada.Real_Time.Time_First;
   end record;

   type Deadline is record
      Set   : Boolean := False;
      Value : Ada.Real_Time.Time := Ada.Real_Time.Time_First;
   end record;

end SSL.Clocks;
