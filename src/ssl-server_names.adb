with Ada.Streams;

package body SSL.Server_Names is

   use type Ada.Streams.Stream_Element_Array;

   --  ASCII-only case folding. Deliberately not Ada.Characters.Handling.
   --  To_Lower, which is defined over the whole Character range and, in the
   --  Latin-1 sense, folds characters a hostname comparison must leave alone.
   function Lower (Item : Character) return Character
   is (if Item in 'A' .. 'Z'
       then Character'Val (Character'Pos (Item) + 32)
       else Item);

   function Is_Name_Character (Item : Character) return Boolean
   is (Item in 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '-' | '_');

   --  Underscore is not legal in a hostname under RFC 1123, but it occurs in
   --  practice in service names (_acme-challenge, SRV-style labels) and in
   --  internal networks. Accepting it in a name this library only compares --
   --  never resolves -- costs nothing, and refusing it would make ssllib
   --  unable to verify certificates that other implementations accept.

   -----------
   -- Image --
   -----------

   function Image (Item : Name_Status) return String is
   begin
      case Item is
         when Ok                          => return "ok";
         when Empty_Name                  => return "empty_name";
         when Too_Long                    => return "too_long";
         when Empty_Label                 => return "empty_label";
         when Label_Too_Long              => return "label_too_long";
         when Invalid_Character           => return "invalid_character";
         when Leading_Or_Trailing_Hyphen  => return "leading_or_trailing_hyphen";
         when Looks_Like_IP_Address       => return "looks_like_ip_address";
         when Not_ASCII                   => return "not_ascii";
         when Wildcard_Not_Permitted      => return "wildcard_not_permitted";
         when Wildcard_Not_Leftmost       => return "wildcard_not_leftmost";
         when Wildcard_Label_Not_Alone    => return "wildcard_label_not_alone";
         when Too_Few_Labels_For_Wildcard => return "too_few_labels_for_wildcard";
      end case;
   end Image;

   -------------
   -- No_Name --
   -------------

   function No_Name return DNS_Name is
   begin
      return (Used => 0, Wildcard => False, Labels => 0, Text => [others => ' ']);
   end No_Name;

   ----------------
   -- Is_Present --
   ----------------

   function Is_Present (Item : DNS_Name) return Boolean is
   begin
      return Item.Used > 0;
   end Is_Present;

   --------------------------
   -- Looks_Like_Address --
   --------------------------

   function Looks_Like_Address (Text : String) return Boolean is
      Digits_Only : Boolean := True;
   begin
      --  A colon can only be an IPv6 literal: it is not a legal hostname
      --  character.
      for Character_Item of Text loop
         if Character_Item = ':' then
            return True;
         end if;
         if Character_Item not in '0' .. '9' | '.' then
            Digits_Only := False;
         end if;
      end loop;

      --  A name whose every character is a digit or a dot cannot be a hostname
      --  either: the rightmost label of a hostname cannot be all digits
      --  (RFC 1123 section 2.1), and this is what "192.0.2.1" looks like.
      return Digits_Only and then Text'Length > 0;
   end Looks_Like_Address;

   --  Shared parser. Allow_Wildcard decides whether a leading "*" label is
   --  accepted; everything else is identical, which is why the two public
   --  entry points are one implementation.
   procedure Parse_Internal
     (Text            : String;
      Allow_Wildcard  : Boolean;
      Item            : out DNS_Name;
      Status          : out Name_Status);

   ---------------------
   -- Parse_Internal --
   ---------------------

   procedure Parse_Internal
     (Text            : String;
      Allow_Wildcard  : Boolean;
      Item            : out DNS_Name;
      Status          : out Name_Status)
   is
      Source_Last  : Natural := Text'Last;
      Result       : DNS_Name := No_Name;
      Out_Cursor   : Natural := 0;
      Label_Start  : Natural;
      Label_Length : Natural;
      Index        : Natural;
      Is_Wildcard  : Boolean := False;
      Has_Star     : Boolean := False;
      Label_Total  : Natural := 0;
   begin
      Item := No_Name;
      Status := Ok;

      if Text'Length = 0 then
         Status := Empty_Name;
         return;
      end if;

      --  A single trailing dot is the fully-qualified form and is dropped;
      --  everything downstream compares names without it.
      if Text (Source_Last) = '.' then
         Source_Last := Source_Last - 1;
         if Source_Last < Text'First then
            Status := Empty_Name;
            return;
         end if;
      end if;

      if Source_Last - Text'First + 1 > Maximum_Name_Length then
         Status := Too_Long;
         return;
      end if;

      for Character_Item of Text (Text'First .. Source_Last) loop
         if Character'Pos (Character_Item) > 127 then
            --  An internationalized name must arrive as an A-label. This
            --  library does not do the Unicode work, and guessing would be
            --  worse than refusing.
            Status := Not_ASCII;
            return;
         end if;
      end loop;

      if Looks_Like_Address (Text (Text'First .. Source_Last)) then
         Status := Looks_Like_IP_Address;
         return;
      end if;

      Index := Text'First;
      loop
         Label_Start := Index;
         while Index <= Source_Last and then Text (Index) /= '.' loop
            Index := Index + 1;
         end loop;
         Label_Length := Index - Label_Start;

         if Label_Length = 0 then
            Status := Empty_Label;
            return;
         end if;

         if Label_Length > Maximum_Label_Length then
            Status := Label_Too_Long;
            return;
         end if;

         Label_Total := Label_Total + 1;

         --  The wildcard test is "does this label contain a star", not "does it
         --  begin with one". "a*.example.com" is a partial wildcard, and
         --  reporting it as an invalid character would be true but useless: the
         --  operator wrote a wildcard and needs to be told which wildcard rule
         --  it broke.
         Has_Star := False;
         for Position in Label_Start .. Label_Start + Label_Length - 1 loop
            if Text (Position) = '*' then
               Has_Star := True;
               exit;
            end if;
         end loop;

         if Has_Star then
            if not Allow_Wildcard then
               Status := Wildcard_Not_Permitted;
               return;
            end if;

            if Label_Total /= 1 then
               --  RFC 6125 section 6.4.3: the wildcard is only ever the
               --  leftmost label.
               Status := Wildcard_Not_Leftmost;
               return;
            end if;

            if Label_Length /= 1 then
               --  "a*.example.com" and "*x.example.com" are partial wildcards.
               --  They are permitted by no current specification and are
               --  accepted by no current browser; accepting them here would
               --  make a pin or a routing entry match more than the operator
               --  can see.
               Status := Wildcard_Label_Not_Alone;
               return;
            end if;

            Is_Wildcard := True;
         else
            for Position in Label_Start .. Label_Start + Label_Length - 1 loop
               if not Is_Name_Character (Text (Position)) then
                  Status := Invalid_Character;
                  return;
               end if;
            end loop;

            if Text (Label_Start) = '-'
              or else Text (Label_Start + Label_Length - 1) = '-'
            then
               Status := Leading_Or_Trailing_Hyphen;
               return;
            end if;
         end if;

         --  Copy the label, folded, followed by its separator.
         if Out_Cursor > 0 then
            Out_Cursor := Out_Cursor + 1;
            Result.Text (Out_Cursor) := '.';
         end if;
         for Position in Label_Start .. Label_Start + Label_Length - 1 loop
            Out_Cursor := Out_Cursor + 1;
            Result.Text (Out_Cursor) := Lower (Text (Position));
         end loop;

         exit when Index > Source_Last;
         Index := Index + 1;   --  step over the dot

         if Index > Source_Last then
            --  A dot at the end that was not the single trailing dot already
            --  removed, so this is "a..b" territory.
            Status := Empty_Label;
            return;
         end if;
      end loop;

      if Is_Wildcard and then Label_Total < 3 then
         --  "*.com" would match every second-level domain in a registry. Three
         --  labels is the least that can be meaningful.
         Status := Too_Few_Labels_For_Wildcard;
         return;
      end if;

      Result.Used := Out_Cursor;
      Result.Wildcard := Is_Wildcard;
      Result.Labels := Label_Total;
      Item := Result;
   end Parse_Internal;

   -----------
   -- Parse --
   -----------

   procedure Parse (Text : String; Item : out DNS_Name; Status : out Name_Status) is
   begin
      Parse_Internal (Text, Allow_Wildcard => False, Item => Item, Status => Status);
   end Parse;

   --------------------
   -- Parse_Pattern --
   --------------------

   procedure Parse_Pattern (Text : String; Item : out DNS_Name; Status : out Name_Status) is
   begin
      Parse_Internal (Text, Allow_Wildcard => True, Item => Item, Status => Status);
   end Parse_Pattern;

   ----------
   -- Name --
   ----------

   function Name (Text : String) return DNS_Name is
      Result : DNS_Name;
      Status : Name_Status;
   begin
      Parse (Text, Result, Status);
      if Status /= Ok then
         raise Constraint_Error with "invalid DNS name literal: " & Image (Status);
      end if;
      return Result;
   end Name;

   -----------
   -- Image --
   -----------

   function Image (Item : DNS_Name) return String is
   begin
      return Item.Text (1 .. Item.Used);
   end Image;

   ------------
   -- Octets --
   ------------

   function Octets (Item : DNS_Name) return Byte_Array is
      Result : Byte_Array (1 .. Byte_Index (Item.Used));
   begin
      for Index in Result'Range loop
         Result (Index) := Byte (Character'Pos (Item.Text (Natural (Index))));
      end loop;
      return Result;
   end Octets;

   ------------
   -- Length --
   ------------

   function Length (Item : DNS_Name) return Natural is
   begin
      return Item.Used;
   end Length;

   -----------------
   -- Is_Wildcard --
   -----------------

   function Is_Wildcard (Item : DNS_Name) return Boolean is
   begin
      return Item.Wildcard;
   end Is_Wildcard;

   -----------------
   -- Label_Count --
   -----------------

   function Label_Count (Item : DNS_Name) return Natural is
   begin
      return Item.Labels;
   end Label_Count;

   ---------
   -- "=" --
   ---------

   function "=" (Left, Right : DNS_Name) return Boolean is
   begin
      return Left.Used = Right.Used
        and then Left.Wildcard = Right.Wildcard
        and then Left.Text (1 .. Left.Used) = Right.Text (1 .. Right.Used);
   end "=";

   -------------
   -- Matches --
   -------------

   function Matches (Candidate : DNS_Name; Pattern : DNS_Name) return Boolean is
   begin
      return Match_Specificity (Candidate, Pattern) > 0;
   end Matches;

   -------------------------
   -- Match_Specificity --
   -------------------------

   function Match_Specificity (Candidate : DNS_Name; Pattern : DNS_Name) return Natural is
   begin
      if not Is_Present (Candidate) or else not Is_Present (Pattern) then
         return 0;
      end if;

      --  A wildcard pattern never matches a wildcard candidate: a candidate is
      --  a concrete name, and a "*" in it is not one.
      if Candidate.Wildcard then
         return 0;
      end if;

      if not Pattern.Wildcard then
         if Candidate.Used = Pattern.Used
           and then Candidate.Text (1 .. Candidate.Used) = Pattern.Text (1 .. Pattern.Used)
         then
            --  An exact match is always more specific than any wildcard, so it
            --  scores above the highest label count a wildcard could reach.
            return Maximum_Name_Length + 1;
         end if;
         return 0;
      end if;

      --  Wildcard: the pattern is "*." followed by the parent, and the
      --  candidate must have exactly one more label than the parent, with that
      --  extra label being its leftmost and containing no dot.
      declare
         Parent_First : constant Natural := 3;   --  after "*."
         Parent_Length : constant Natural := Pattern.Used - Parent_First + 1;
         Dot_Position : Natural := 0;
      begin
         if Parent_Length = 0 then
            return 0;
         end if;

         if Candidate.Labels /= Pattern.Labels then
            return 0;
         end if;

         for Index in 1 .. Candidate.Used loop
            if Candidate.Text (Index) = '.' then
               Dot_Position := Index;
               exit;
            end if;
         end loop;

         if Dot_Position = 0 then
            return 0;
         end if;

         --  The wildcard must stand for a non-empty label.
         if Dot_Position = 1 then
            return 0;
         end if;

         if Candidate.Used - Dot_Position /= Parent_Length then
            return 0;
         end if;

         if Candidate.Text (Dot_Position + 1 .. Candidate.Used)
           /= Pattern.Text (Parent_First .. Pattern.Used)
         then
            return 0;
         end if;

         --  More labels in the pattern is a narrower wildcard, so it scores
         --  higher: "*.a.example.com" beats "*.example.com".
         return Pattern.Labels;
      end;
   end Match_Specificity;

   --------------------
   -- Is_Valid_Name --
   --------------------

   function Is_Valid_Name (Text : String) return Boolean is
      Result : DNS_Name;
      Status : Name_Status;
   begin
      Parse (Text, Result, Status);
      return Status = Ok;
   end Is_Valid_Name;

   ---------------------------------------------------------------------------
   --  IP addresses
   ---------------------------------------------------------------------------

   -----------------
   -- No_Address --
   -----------------

   function No_Address return IP_Address is
   begin
      return (Used => 0, Octets => [others => 0]);
   end No_Address;

   ----------------
   -- Is_Present --
   ----------------

   function Is_Present (Item : IP_Address) return Boolean is
   begin
      return Item.Used > 0;
   end Is_Present;

   -------------------
   -- Make_Address --
   -------------------

   function Make_Address (Value : Byte_Array; Item : out IP_Address) return Boolean is
   begin
      Item := No_Address;
      if Value'Length /= 4 and then Value'Length /= 16 then
         return False;
      end if;
      Item.Used := Value'Length;
      Item.Octets (1 .. Value'Length) := Value;
      return True;
   end Make_Address;

   --------------------
   -- Parse_Address --
   --------------------

   function Parse_Address (Text : String; Item : out IP_Address) return Boolean is

      --  IPv4 dotted quad.
      function Parse_V4 (Source : String; Into : out Byte_Array) return Boolean;

      function Parse_V4 (Source : String; Into : out Byte_Array) return Boolean is
         Index  : Natural := Source'First;
         Field  : Natural := 0;
         Value  : Natural;
         Digits_Seen : Natural;
      begin
         Into := [others => 0];
         loop
            Value := 0;
            Digits_Seen := 0;
            while Index <= Source'Last and then Source (Index) in '0' .. '9' loop
               Value := Value * 10 + (Character'Pos (Source (Index)) - Character'Pos ('0'));
               Digits_Seen := Digits_Seen + 1;
               if Value > 255 or else Digits_Seen > 3 then
                  return False;
               end if;
               Index := Index + 1;
            end loop;

            if Digits_Seen = 0 then
               return False;
            end if;

            Field := Field + 1;
            if Field > 4 then
               return False;
            end if;
            Into (Into'First + Byte_Index (Field) - 1) := Byte (Value);

            exit when Index > Source'Last;
            if Source (Index) /= '.' then
               return False;
            end if;
            Index := Index + 1;
         end loop;

         return Field = 4;
      end Parse_V4;

      --  IPv6, including "::" compression and a trailing IPv4 form.
      function Parse_V6 (Source : String; Into : out Byte_Array) return Boolean;

      function Parse_V6 (Source : String; Into : out Byte_Array) return Boolean is
         Head   : Byte_Array (1 .. 16) := [others => 0];
         Tail   : Byte_Array (1 .. 16) := [others => 0];
         Head_Used : Byte_Index := 0;
         Tail_Used : Byte_Index := 0;
         Seen_Gap  : Boolean := False;
         Index     : Natural := Source'First;
         Into_Head : Boolean := True;

         procedure Store (Value : Natural);

         procedure Store (Value : Natural) is
         begin
            if Into_Head then
               Head (Head_Used + 1) := Byte (Value / 256);
               Head (Head_Used + 2) := Byte (Value mod 256);
               Head_Used := Head_Used + 2;
            else
               Tail (Tail_Used + 1) := Byte (Value / 256);
               Tail (Tail_Used + 2) := Byte (Value mod 256);
               Tail_Used := Tail_Used + 2;
            end if;
         end Store;

      begin
         Into := [others => 0];

         --  Leading "::"
         if Source'Length >= 2
           and then Source (Index) = ':' and then Source (Index + 1) = ':'
         then
            Seen_Gap := True;
            Into_Head := False;
            Index := Index + 2;
            if Index > Source'Last then
               return True;   --  "::" is the all-zero address
            end if;
         end if;

         loop
            --  A group of one to four hexadecimal digits, or an embedded IPv4.
            declare
               Start : constant Natural := Index;
               Value : Natural := 0;
               Count : Natural := 0;
               Has_Dot : Boolean := False;
            begin
               while Index <= Source'Last
                 and then Source (Index) in '0' .. '9' | 'a' .. 'f' | 'A' .. 'F'
               loop
                  declare
                     Character_Item : constant Character := Source (Index);
                     Digit : constant Natural :=
                       (if Character_Item in '0' .. '9'
                        then Character'Pos (Character_Item) - Character'Pos ('0')
                        elsif Character_Item in 'a' .. 'f'
                        then 10 + Character'Pos (Character_Item) - Character'Pos ('a')
                        else 10 + Character'Pos (Character_Item) - Character'Pos ('A'));
                  begin
                     Value := Value * 16 + Digit;
                  end;
                  Count := Count + 1;
                  if Count > 4 then
                     return False;
                  end if;
                  Index := Index + 1;
               end loop;

               if Index <= Source'Last and then Source (Index) = '.' then
                  Has_Dot := True;
               end if;

               if Has_Dot then
                  --  Embedded IPv4 in the last 32 bits.
                  declare
                     Quad : Byte_Array (1 .. 4);
                  begin
                     if not Parse_V4 (Source (Start .. Source'Last), Quad) then
                        return False;
                     end if;
                     if Into_Head then
                        if Head_Used + 4 > 16 then
                           return False;
                        end if;
                        Head (Head_Used + 1 .. Head_Used + 4) := Quad;
                        Head_Used := Head_Used + 4;
                     else
                        if Tail_Used + 4 > 16 then
                           return False;
                        end if;
                        Tail (Tail_Used + 1 .. Tail_Used + 4) := Quad;
                        Tail_Used := Tail_Used + 4;
                     end if;
                     Index := Source'Last + 1;
                     exit;
                  end;
               end if;

               if Count = 0 then
                  return False;
               end if;

               if Into_Head then
                  if Head_Used + 2 > 16 then
                     return False;
                  end if;
               else
                  if Tail_Used + 2 > 16 then
                     return False;
                  end if;
               end if;
               Store (Value);
            end;

            exit when Index > Source'Last;

            if Source (Index) /= ':' then
               return False;
            end if;
            Index := Index + 1;

            if Index <= Source'Last and then Source (Index) = ':' then
               if Seen_Gap then
                  return False;   --  only one "::" is allowed
               end if;
               Seen_Gap := True;
               Into_Head := False;
               Index := Index + 1;
               exit when Index > Source'Last;
            elsif Index > Source'Last then
               return False;   --  a trailing single colon
            end if;
         end loop;

         if Seen_Gap then
            if Head_Used + Tail_Used > 14 then
               --  "::" must stand for at least one all-zero group.
               return False;
            end if;
            Into (1 .. Head_Used) := Head (1 .. Head_Used);
            Into (17 - Tail_Used .. 16) := Tail (1 .. Tail_Used);
         else
            if Head_Used /= 16 then
               return False;
            end if;
            Into := Head;
         end if;

         return True;
      end Parse_V6;

      Has_Colon : Boolean := False;
      V4_Bytes  : Byte_Array (1 .. 4);
      V6_Bytes  : Byte_Array (1 .. 16);
   begin
      Item := No_Address;

      if Text'Length = 0 then
         return False;
      end if;

      for Character_Item of Text loop
         if Character_Item = ':' then
            Has_Colon := True;
            exit;
         end if;
      end loop;

      if Has_Colon then
         if not Parse_V6 (Text, V6_Bytes) then
            return False;
         end if;
         return Make_Address (V6_Bytes, Item);
      end if;

      if not Parse_V4 (Text, V4_Bytes) then
         return False;
      end if;
      return Make_Address (V4_Bytes, Item);
   end Parse_Address;

   ------------
   -- Octets --
   ------------

   function Octets (Item : IP_Address) return Byte_Array is
   begin
      return Item.Octets (1 .. Item.Used);
   end Octets;

   -----------
   -- Image --
   -----------

   function Image (Item : IP_Address) return String is
      Hex : constant String := "0123456789abcdef";
   begin
      if Item.Used = 0 then
         return "none";
      end if;

      if Item.Used = 4 then
         declare
            Text : String (1 .. 15) := [others => ' '];
            Used : Natural := 0;

            procedure Add (Value : String);

            procedure Add (Value : String) is
            begin
               Text (Used + 1 .. Used + Value'Length) := Value;
               Used := Used + Value'Length;
            end Add;

         begin
            for Index in 1 .. 4 loop
               if Index > 1 then
                  Add (".");
               end if;
               declare
                  Number : constant String := Natural (Item.Octets (Byte_Index (Index)))'Image;
               begin
                  Add (Number (Number'First + 1 .. Number'Last));
               end;
            end loop;
            return Text (1 .. Used);
         end;
      end if;

      --  IPv6 in the uncompressed eight-group form. Not the shortest legal
      --  spelling, but unambiguous, which is what a log line needs.
      declare
         Text   : String (1 .. 39);
         Cursor : Positive := 1;
      begin
         for Group in 0 .. 7 loop
            if Group > 0 then
               Text (Cursor) := ':';
               Cursor := Cursor + 1;
            end if;
            declare
               High : constant Natural := Natural (Item.Octets (Byte_Index (2 * Group + 1)));
               Low  : constant Natural := Natural (Item.Octets (Byte_Index (2 * Group + 2)));
            begin
               Text (Cursor) := Hex (1 + High / 16);
               Text (Cursor + 1) := Hex (1 + High mod 16);
               Text (Cursor + 2) := Hex (1 + Low / 16);
               Text (Cursor + 3) := Hex (1 + Low mod 16);
               Cursor := Cursor + 4;
            end;
         end loop;
         return Text;
      end;
   end Image;

   ---------
   -- "=" --
   ---------

   function "=" (Left, Right : IP_Address) return Boolean is
   begin
      return Left.Used = Right.Used
        and then Left.Octets (1 .. Left.Used) = Right.Octets (1 .. Right.Used);
   end "=";

end SSL.Server_Names;
