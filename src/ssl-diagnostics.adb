package body SSL.Diagnostics is

   ---------------
   -- Image --
   ---------------

   function Image (Item : Detail_Level) return String is
     (case Item is
         when Off                => "off",
         when Errors_Only        => "errors only",
         when Connection_Summary => "connection summary",
         when Handshake_Summary  => "handshake summary",
         when Detailed_Protocol  => "detailed protocol");

   function Image (Item : Redaction_Level) return String is
     (case Item is
         when Strict         => "strict",
         when Operational    => "operational",
         when Explicit_Debug => "explicit debug");

   function Image (Item : Event_Kind) return String is
     (case Item is
         when Connection_Started         => "connection started",
         when Handshake_Message_Sent     => "handshake message sent",
         when Handshake_Message_Received => "handshake message received",
         when Handshake_Completed        => "handshake completed",
         when Key_Update_Sent            => "key update sent",
         when Key_Update_Received        => "key update received",
         when Certificate_Accepted       => "certificate accepted",
         when Certificate_Refused        => "certificate refused",
         when Session_Resumed            => "session resumed",
         when Ticket_Received            => "ticket received",
         when Ticket_Refused             => "ticket refused",
         when Peer_Alert_Received        => "peer alert received",
         when Alert_Sent                 => "alert sent",
         when Connection_Closed          => "connection closed",
         when Connection_Failed          => "connection failed");

   ------------------
   -- Level_Of --
   ------------------

   function Level_Of (Item : Event_Kind) return Detail_Level is
     (case Item is
         --  The failures. Visible at every level above Off, because a
         --  deployment that logs nothing else still wants these.
         when Connection_Failed | Certificate_Refused | Peer_Alert_Received
            | Alert_Sent | Ticket_Refused => Errors_Only,

         --  The two ends of a connection's life.
         when Connection_Started | Connection_Closed => Connection_Summary,

         --  What was negotiated and what was proved.
         when Handshake_Completed | Certificate_Accepted | Session_Resumed
            | Ticket_Received => Handshake_Summary,

         --  Message by message. For reproducing a problem, not for production.
         when Handshake_Message_Sent | Handshake_Message_Received
            | Key_Update_Sent | Key_Update_Received => Detailed_Protocol);

   ---------------------------------------------------------------------------
   --  Building
   ---------------------------------------------------------------------------

   function Make
     (Kind       : Event_Kind;
      Connection : Connection_ID := No_Connection) return Event
   is
      Result : Event;
   begin
      Result.Kind := Kind;
      Result.Connection := Connection;
      return Result;
   end Make;

   function Make
     (Kind       : Event_Kind;
      Failure    : SSL.Errors.Error_Information;
      Connection : Connection_ID := No_Connection) return Event
   is
      Result : Event := Make (Kind, Connection);
   begin
      Result.Failure := Failure;
      return Result;
   end Make;

   --  Copy a string into fixed storage, truncating. Truncation rather than
   --  refusal: a diagnostic that failed because a name was long would be a
   --  diagnostic lost at exactly the moment it was interesting.
   procedure Place (Into : out String; Length : out Natural; Text : String; Limit : Natural);

   procedure Place (Into : out String; Length : out Natural; Text : String; Limit : Natural) is
   begin
      Into := [others => ' '];
      Length := Natural'Min (Text'Length, Limit);
      if Length > 0 then
         Into (Into'First .. Into'First + Length - 1) :=
           Text (Text'First .. Text'First + Length - 1);
      end if;
   end Place;

   procedure Add (Item : in out Event; Name : String; Value : String) is
   begin
      if Item.Count = Maximum_Facts then
         --  Silently dropped. An event that raised while being built would turn
         --  a diagnostic into a failure, which is the wrong way round.
         return;
      end if;

      Item.Count := Item.Count + 1;
      Place (Item.Facts (Item.Count).Name_Text,
             Item.Facts (Item.Count).Name_Length, Name, Name_Limit);
      Place (Item.Facts (Item.Count).Value_Text,
             Item.Facts (Item.Count).Value_Length, Value, Value_Limit);
   end Add;

   procedure Add (Item : in out Event; Name : String; Value : Long_Long_Integer) is
      Text : constant String := Value'Image;
   begin
      --  'Image leads with a space for a non-negative number. Trimmed, because
      --  a log line with a stray space in the middle of a value reads as two
      --  fields.
      Add (Item, Name,
           (if Text'Length > 1 and then Text (Text'First) = ' '
            then Text (Text'First + 1 .. Text'Last) else Text));
   end Add;

   ---------------
   -- Image --
   ---------------

   function Image (Item : Event; Redaction : Redaction_Level) return String is

      function Facts return String;

      function Facts return String is
      begin
         if Redaction = Strict or else Item.Count = 0 then
            --  Strict says the kind and the code and nothing else. A named fact
            --  is by definition something about this particular connection, and
            --  that is exactly what a log leaving the machine should not carry.
            return "";
         end if;

         declare
            Line : String (1 .. Maximum_Facts * (Name_Limit + Value_Limit + 3)) :=
              [others => ' '];
            Last : Natural := 0;

            procedure Append (Text : String);

            procedure Append (Text : String) is
            begin
               if Last + Text'Length <= Line'Length then
                  Line (Last + 1 .. Last + Text'Length) := Text;
                  Last := Last + Text'Length;
               end if;
            end Append;
         begin
            for Index in 1 .. Item.Count loop
               Append (" ");
               Append (Item.Facts (Index).Name_Text (1 .. Item.Facts (Index).Name_Length));
               Append ("=");
               Append (Item.Facts (Index).Value_Text (1 .. Item.Facts (Index).Value_Length));
            end loop;
            return Line (1 .. Last);
         end;
      end Facts;

      Head : constant String :=
        Image (Item.Kind)
        & (if Is_Present (Item.Connection)
           then " connection=" & Image (Item.Connection) else "");
   begin
      if Has_Failure (Item) then
         --  The failure's own rendering already applies the disclosure rules:
         --  a Restricted failure shows its category and code and withholds its
         --  parameters, whatever redaction level is in force here. This adds to
         --  that filtering and never subtracts from it.
         return Head & " " & SSL.Errors.Image (Item.Failure) & Facts;
      end if;

      return Head & Facts;
   end Image;

   ---------------------------------------------------------------------------
   --  Calling a sink
   ---------------------------------------------------------------------------

   procedure Emit_Safely
     (Item      : in out Sink'Class;
      What      : Event;
      Level     : Detail_Level;
      Redaction : Redaction_Level)
   is
      pragma Unreferenced (Redaction);
   begin
      if Level = Off or else Level_Of (What.Kind) > Level then
         --  Filtered before the sink is called, so that a level nobody asked
         --  for costs a comparison rather than a call into application code.
         return;
      end if;

      begin
         Item.Emit (What);
      exception
         when others =>
            --  Deliberately nothing. A diagnostic sink that fails is not a
            --  connection problem, and turning it into one would let an
            --  application break its own connections by writing a bad logger.
            null;
      end;
   end Emit_Safely;

end SSL.Diagnostics;
