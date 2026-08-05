with SSL.Errors;

--  @summary Structured diagnostic events, and the sink an application supplies
--  to receive them.
--
--  A TLS failure that an operator cannot explain is a failure they cannot fix,
--  and a library that says only "handshake failed" makes every incident an
--  exercise in guessing. So this library emits structured events -- a level, a
--  connection, a code, and bounded named facts -- and hands them to a sink the
--  application provides.
--
--  Three things this package deliberately does not do:
--
--    * **It does not write anywhere.** No files, no syslog, no standard error.
--      An application that wants events in a file writes a sink that puts them
--      there, and owns the file handle, the rotation and the permissions.
--    * **It does not read the environment.** Nothing here can be switched on by
--      setting a variable, because a security-relevant setting that an
--      environment variable controls is a setting an attacker who can set
--      environment variables controls.
--    * **It never logs secret material.** Not keys, not pre-shared keys, not
--      binders, not ticket contents, not application plaintext. The redaction
--      level below governs how much of the *non*-secret detail travels; it
--      never opens a door to the secret kind.
--
--  A sink is application code, so every call into one is made inside a handler:
--  a sink that raises loses its event and does not unwind a connection.
package SSL.Diagnostics is

   ---------------------------------------------------------------------------
   --  How much to say
   ---------------------------------------------------------------------------

   --  Increasing detail. Each level includes everything below it.
   type Detail_Level is
     (Off,
      --  Nothing at all. The default, because a library that logged by default
      --  would be writing into an application's output uninvited.

      Errors_Only,
      --  Failures, and nothing that went right.

      Connection_Summary,
      --  One event when a connection is established and one when it ends.

      Handshake_Summary,
      --  What was negotiated and what was proved: version, suite, group,
      --  protocol, whether the peer authenticated, whether it resumed.

      Detailed_Protocol);
      --  Individual messages, extensions, state transitions. Verbose enough to
      --  follow a handshake message by message, and intended for a developer
      --  reproducing a problem rather than for a production deployment.

   function Image (Item : Detail_Level) return String;

   --  How much of the non-secret detail may travel.
   --
   --  Separate from the level because they answer different questions: the
   --  level is how much to say, and this is how much of what is said may leave
   --  the machine. A deployment shipping logs to a third party wants
   --  Detailed_Protocol with Strict redaction, and there is no way to express
   --  that with one setting.
   type Redaction_Level is
     (Strict,
      --  Category and code only. No server names, no certificate subjects, no
      --  addresses, no protocol identifiers. For logs that leave the machine.

      Operational,
      --  The facts an operator needs to act: which server name, which
      --  extension, which limit, which fingerprint. Not the contents of
      --  anything.

      Explicit_Debug);
      --  Everything a failure carries that is not secret, including the values
      --  a Restricted failure normally withholds. Enabled deliberately and
      --  temporarily; the name says so.

   function Image (Item : Redaction_Level) return String;

   ---------------------------------------------------------------------------
   --  What an event is
   ---------------------------------------------------------------------------

   --  The kinds of thing worth an event. Closed, so that a reader of a log can
   --  know the whole vocabulary, and so that adding one is a decision rather
   --  than a string somebody typed.
   type Event_Kind is
     (Connection_Started,
      Handshake_Message_Sent,
      Handshake_Message_Received,
      Handshake_Completed,
      Key_Update_Sent,
      Key_Update_Received,
      Certificate_Accepted,
      Certificate_Refused,
      Session_Resumed,
      Ticket_Received,
      Ticket_Refused,
      Peer_Alert_Received,
      Alert_Sent,
      Connection_Closed,
      Connection_Failed);

   function Image (Item : Event_Kind) return String;

   --  At what level an event of this kind becomes visible.
   function Level_Of (Item : Event_Kind) return Detail_Level;

   --  One event. Bounded in every dimension: an event carries at most four
   --  named facts, each with a bounded name and a bounded value, because
   --  diagnostics are produced on paths a hostile peer drives and an unbounded
   --  event would be an unbounded allocation it controls.
   type Event is private;

   function Kind_Of (Item : Event) return Event_Kind;
   function Connection_Of (Item : Event) return Connection_ID;
   function Failure_Of (Item : Event) return SSL.Errors.Error_Information;
   function Has_Failure (Item : Event) return Boolean;

   --  A rendering suitable for a log line, filtered by the redaction level.
   --
   --  Never includes key material, plaintext, or anything a `Restricted`
   --  failure is withholding -- whatever the redaction level says. The level
   --  governs the non-secret detail and nothing else.
   --  @param Item      the event
   --  @param Redaction how much of the non-secret detail may travel
   --  @return one line, without a trailing newline
   function Image (Item : Event; Redaction : Redaction_Level) return String;

   ---------------------------------------------------------------------------
   --  Building one
   ---------------------------------------------------------------------------

   function Make
     (Kind       : Event_Kind;
      Connection : Connection_ID := No_Connection) return Event;

   function Make
     (Kind       : Event_Kind;
      Failure    : SSL.Errors.Error_Information;
      Connection : Connection_ID := No_Connection) return Event;

   --  Attach a named fact. Silently ignored past the fourth, because an event
   --  that raised while being built would turn a diagnostic into a failure.
   procedure Add
     (Item : in out Event; Name : String; Value : String);
   procedure Add
     (Item : in out Event; Name : String; Value : Long_Long_Integer);

   ---------------------------------------------------------------------------
   --  The sink an application implements
   ---------------------------------------------------------------------------

   type Sink is limited interface;

   type Sink_Reference is access all Sink'Class;

   --  Receive one event.
   --
   --  Called on the task that produced the event, synchronously, on a path that
   --  may be a handshake. An implementation that does anything slow should
   --  queue and return.
   --
   --  May raise: it will be caught and the event dropped. Losing a diagnostic
   --  is better than unwinding a connection that has keys installed.
   procedure Emit (Item : in out Sink; What : Event) is abstract;

   --  Short text naming this sink, for the failure recorded when it raises.
   function Description (Item : Sink) return String is abstract;

   --  Call a sink, converting every failure mode into nothing at all.
   --
   --  Deliberately reports no error. A diagnostic sink that fails is not a
   --  connection problem, and turning it into one would mean an application
   --  could break its own connections by writing a bad logger.
   procedure Emit_Safely
     (Item      : in out Sink'Class;
      What      : Event;
      Level     : Detail_Level;
      Redaction : Redaction_Level);

private

   Maximum_Facts : constant := 4;
   Name_Limit    : constant := 32;
   Value_Limit   : constant := 64;

   type Fact is record
      Name_Length  : Natural range 0 .. Name_Limit := 0;
      Name_Text    : String (1 .. Name_Limit) := [others => ' '];
      Value_Length : Natural range 0 .. Value_Limit := 0;
      Value_Text   : String (1 .. Value_Limit) := [others => ' '];
   end record;

   type Fact_Array is array (1 .. Maximum_Facts) of Fact;

   type Event is record
      Kind       : Event_Kind := Connection_Started;
      Connection : Connection_ID := No_Connection;
      Failure    : SSL.Errors.Error_Information := SSL.Errors.No_Error;
      Count      : Natural range 0 .. Maximum_Facts := 0;
      Facts      : Fact_Array := [others => <>];
   end record;

   function Kind_Of (Item : Event) return Event_Kind is (Item.Kind);
   function Connection_Of (Item : Event) return Connection_ID is (Item.Connection);
   function Failure_Of (Item : Event) return SSL.Errors.Error_Information is (Item.Failure);
   function Has_Failure (Item : Event) return Boolean is
     (SSL.Errors.Is_Error (Item.Failure));

end SSL.Diagnostics;
