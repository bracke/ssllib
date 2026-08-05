with Ada.Streams;

with SSL.Wire;

package body SSL.Handshake_Messages is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type SSL.Extensions.Extension_Kind;
   use type SSL.Server_Names.Name_Status;
   use type SSL.ALPN.ALPN_Requirement;
   use type SSL.Supported_Groups.Named_Group;

   package Ext renames SSL.Extensions;
   package Groups renames SSL.Supported_Groups;
   package Suites renames SSL.Cipher_Suites;
   package Schemes renames SSL.Signature_Schemes;

   --  RFC 8446 section 4.1.3: the SHA-256 of "HelloRetryRequest", written out
   --  as the constant the specification gives rather than computed, because a
   --  computed one would be a second place for the string to be wrong.
   Retry_Random : constant Random_Bytes :=
     [16#CF#, 16#21#, 16#AD#, 16#74#, 16#E5#, 16#9A#, 16#61#, 16#11#,
      16#BE#, 16#1D#, 16#8C#, 16#02#, 16#1E#, 16#65#, 16#B8#, 16#91#,
      16#C2#, 16#A2#, 16#11#, 16#16#, 16#7A#, 16#BB#, 16#8C#, 16#5E#,
      16#07#, 16#9E#, 16#09#, 16#E2#, 16#C8#, 16#A8#, 16#33#, 16#9C#];

   function Hello_Retry_Random return Random_Bytes is (Retry_Random);

   ---------------------------------------------------------------------------
   --  Framing
   ---------------------------------------------------------------------------

   function Value_Of (Item : Message_Type) return Type_Value is
   begin
      case Item is
         when Client_Hello         => return Client_Hello_Value;
         when Server_Hello         => return Server_Hello_Value;
         when New_Session_Ticket   => return New_Session_Ticket_Value;
         when Encrypted_Extensions => return Encrypted_Extensions_Value;
         when Certificate          => return Certificate_Value;
         when Certificate_Request  => return Certificate_Request_Value;
         when Certificate_Verify   => return Certificate_Verify_Value;
         when Finished             => return Finished_Value;
         when Key_Update           => return Key_Update_Value;
         when Message_Hash         => return Message_Hash_Value;
         when Server_Key_Exchange  => return Server_Key_Exchange_Value;
         when Server_Hello_Done    => return Server_Hello_Done_Value;
         when Client_Key_Exchange  => return Client_Key_Exchange_Value;
         when Hello_Request        => return Hello_Request_Value;
         when End_Of_Early_Data    => return End_Of_Early_Data_Value;
         when Unknown_Message      => return 0;
      end case;
   end Value_Of;

   function Type_For (Item : Type_Value) return Message_Type is
   begin
      case Item is
         when Client_Hello_Value         => return Client_Hello;
         when Server_Hello_Value         => return Server_Hello;
         when New_Session_Ticket_Value   => return New_Session_Ticket;
         when End_Of_Early_Data_Value    => return End_Of_Early_Data;
         when Encrypted_Extensions_Value => return Encrypted_Extensions;
         when Certificate_Value          => return Certificate;
         when Server_Key_Exchange_Value  => return Server_Key_Exchange;
         when Certificate_Request_Value  => return Certificate_Request;
         when Server_Hello_Done_Value    => return Server_Hello_Done;
         when Certificate_Verify_Value   => return Certificate_Verify;
         when Client_Key_Exchange_Value  => return Client_Key_Exchange;
         when Finished_Value             => return Finished;
         when Key_Update_Value           => return Key_Update;
         when Message_Hash_Value         => return Message_Hash;
         when Hello_Request_Value        => return Hello_Request;
         when others                     => return Unknown_Message;
      end case;
   end Type_For;

   function Image (Item : Message_Type) return String is
   begin
      case Item is
         when Client_Hello         => return "client_hello";
         when Server_Hello         => return "server_hello";
         when New_Session_Ticket   => return "new_session_ticket";
         when Encrypted_Extensions => return "encrypted_extensions";
         when Certificate          => return "certificate";
         when Certificate_Request  => return "certificate_request";
         when Certificate_Verify   => return "certificate_verify";
         when Finished             => return "finished";
         when Key_Update           => return "key_update";
         when Message_Hash         => return "message_hash";
         when Server_Key_Exchange  => return "server_key_exchange";
         when Server_Hello_Done    => return "server_hello_done";
         when Client_Key_Exchange  => return "client_key_exchange";
         when Hello_Request        => return "hello_request";
         when End_Of_Early_Data    => return "end_of_early_data";
         when Unknown_Message      => return "unknown_message";
      end case;
   end Image;

   procedure Parse_Header
     (Data   : Byte_Array;
      Kind   : out Message_Type;
      Value  : out Type_Value;
      Length : out Byte_Index;
      Error  : out SSL.Errors.Error_Information)
   is
      First : constant Byte_Index := Data'First;
   begin
      Kind := Unknown_Message;
      Value := 0;
      Length := 0;

      if Data'Length < Header_Length then
         --  Not enough octets to be a header. Reported rather than assumed
         --  away: this is the first thing every message reaches and its
         --  argument comes from a peer.
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      Value := Type_Value (Data (First));
      Kind := Type_For (Value);
      Length := 65_536 * Byte_Index (Data (First + 1))
        + 256 * Byte_Index (Data (First + 2))
        + Byte_Index (Data (First + 3));

      if Kind = Unknown_Message then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Unexpected_Handshake_Message,
            Origin     => SSL.Errors.Peer_Message,
            Parameters =>
              [SSL.Errors.Numeric_Parameter ("message_type", Long_Long_Integer (Value))]);
         return;
      end if;

      --  message_hash is synthetic and never travels. A peer sending one is
      --  trying to inject a transcript transformation.
      if Kind = Message_Hash then
         Error := SSL.Errors.Make
           (Code   => SSL.Errors.Code_Unexpected_Handshake_Message,
            Origin => SSL.Errors.Peer_Message);
         return;
      end if;

      Error := SSL.Errors.No_Error;
   end Parse_Header;

   function Encode_Header (Kind : Message_Type; Length : Byte_Index) return Byte_Array is
   begin
      return [1 => Byte (Value_Of (Kind)),
              2 => Byte (Length / 65_536),
              3 => Byte ((Length / 256) mod 256),
              4 => Byte (Length mod 256)];
   end Encode_Header;

   function Length_Permitted
     (Kind   : Message_Type;
      Length : Byte_Index;
      Bounds : SSL.Limits.Resource_Limits) return Boolean
   is
   begin
      if Length < 0 then
         return False;
      end if;

      --  A certificate chain is legitimately larger than anything else, and
      --  giving every message the certificate bound would let a peer send a
      --  four-megabyte Finished.
      if Kind = Certificate then
         return Length <= Byte_Index (Bounds.Maximum_Certificate_Message);
      end if;

      return Length <= Byte_Index (Bounds.Maximum_Handshake_Message);
   end Length_Permitted;

   ---------------------------------------------------------------------------
   --  Shared extension-body parsers
   ---------------------------------------------------------------------------

   --  The pre_shared_key offer of a ClientHello: a list of identities with
   --  their reported ages, then a list of binders.
   --
   --  Three things have to hold for the offer to be usable, and all three are
   --  checked here rather than left to the state machine: the two lists must be
   --  the same length, because a binder is matched to an identity by position;
   --  the offset where the binders begin must be recorded, because that is
   --  where the message stops being covered by them; and every binder must be
   --  long enough to be a hash, because a zero-length one would compare equal to
   --  a truncated expected value.
   procedure Read_PSK_Offer
     (Data      : Byte_Array;
      Body_Part : in out SSL.Wire.Cursor;
      Bounds    : SSL.Limits.Resource_Limits;
      Item      : in out Client_Hello_Message;
      Error     : out SSL.Errors.Error_Information);

   --  supported_versions in a ClientHello: a one-octet-prefixed list of
   --  two-octet versions.
   procedure Read_Client_Versions
     (Data   : Byte_Array;
      Body_Part : in out SSL.Wire.Cursor;
      Bounds : SSL.Limits.Resource_Limits;
      Into   : out SSL.Versions.Version_Set);

   procedure Read_Client_Versions
     (Data   : Byte_Array;
      Body_Part : in out SSL.Wire.Cursor;
      Bounds : SSL.Limits.Resource_Limits;
      Into   : out SSL.Versions.Version_Set)
   is
      pragma Unreferenced (Bounds);
      List  : SSL.Wire.Cursor;
      Value : Natural;
      Named : SSL.Versions.Protocol_Version;
   begin
      Into := SSL.Versions.No_Versions;
      SSL.Wire.Open_Vector_8 (Data, Body_Part, 254, List);

      while SSL.Wire.Is_Valid (List) and then not SSL.Wire.At_End (List) loop
         SSL.Wire.Get_UInt16 (Data, List, Value);
         exit when not SSL.Wire.Is_Valid (List);

         --  A version this library does not implement is skipped rather than
         --  refused: RFC 8446 section 4.2.1 says a client lists what it
         --  supports and a server picks from the intersection, so an unknown
         --  entry is simply not in the intersection.
         if SSL.Versions.Version_For (SSL.Versions.Version_Value (Value), Named) then
            Into := SSL.Versions.Including (Into, Named);
         end if;
      end loop;
   end Read_Client_Versions;

   procedure Read_Groups
     (Data      : Byte_Array;
      Body_Part : in out SSL.Wire.Cursor;
      Bounds    : SSL.Limits.Resource_Limits;
      Into      : out Groups.Group_List;
      Error     : out SSL.Errors.Error_Information);

   procedure Read_Groups
     (Data      : Byte_Array;
      Body_Part : in out SSL.Wire.Cursor;
      Bounds    : SSL.Limits.Resource_Limits;
      Into      : out Groups.Group_List;
      Error     : out SSL.Errors.Error_Information)
   is
      List  : SSL.Wire.Cursor;
      Value : Natural;
      Named : Groups.Named_Group;
      Count : Natural := 0;
      Done  : Boolean;
   begin
      Into := Groups.No_Groups;
      Error := SSL.Errors.No_Error;
      SSL.Wire.Open_Vector_16
        (Data, Body_Part, 2 * Byte_Index (Bounds.Maximum_Supported_Groups), List);

      while SSL.Wire.Is_Valid (List) and then not SSL.Wire.At_End (List) loop
         SSL.Wire.Get_UInt16 (Data, List, Value);
         exit when not SSL.Wire.Is_Valid (List);

         Count := Count + 1;
         if Count > Bounds.Maximum_Supported_Groups then
            Error := SSL.Errors.Limit_Failure
              (SSL.Limits.Supported_Groups,
               Long_Long_Integer (Bounds.Maximum_Supported_Groups),
               Long_Long_Integer (Count));
            return;
         end if;

         if Groups.Group_For (Groups.Group_Value (Value), Named) then
            Groups.Append (Into, Named, Done);
         end if;
      end loop;
   end Read_Groups;

   procedure Read_Schemes
     (Data      : Byte_Array;
      Body_Part : in out SSL.Wire.Cursor;
      Bounds    : SSL.Limits.Resource_Limits;
      Into      : out Schemes.Scheme_List;
      Error     : out SSL.Errors.Error_Information);

   procedure Read_Schemes
     (Data      : Byte_Array;
      Body_Part : in out SSL.Wire.Cursor;
      Bounds    : SSL.Limits.Resource_Limits;
      Into      : out Schemes.Scheme_List;
      Error     : out SSL.Errors.Error_Information)
   is
      List  : SSL.Wire.Cursor;
      Value : Natural;
      Named : Schemes.Signature_Scheme;
      Count : Natural := 0;
      Done  : Boolean;
   begin
      Into := Schemes.No_Schemes;
      Error := SSL.Errors.No_Error;
      SSL.Wire.Open_Vector_16
        (Data, Body_Part, 2 * Byte_Index (Bounds.Maximum_Signature_Schemes), List);

      while SSL.Wire.Is_Valid (List) and then not SSL.Wire.At_End (List) loop
         SSL.Wire.Get_UInt16 (Data, List, Value);
         exit when not SSL.Wire.Is_Valid (List);

         Count := Count + 1;
         if Count > Bounds.Maximum_Signature_Schemes then
            Error := SSL.Errors.Limit_Failure
              (SSL.Limits.Signature_Schemes,
               Long_Long_Integer (Bounds.Maximum_Signature_Schemes),
               Long_Long_Integer (Count));
            return;
         end if;

         --  A weak or unknown scheme is dropped rather than refused: it simply
         --  will not be in the intersection. Refusing outright would break
         --  against peers that legitimately offer SHA-1 alongside modern
         --  schemes, which many still do.
         if Schemes.Scheme_For (Schemes.Scheme_Value (Value), Named) then
            Schemes.Append (Into, Named, Done);
         end if;
      end loop;
   end Read_Schemes;

   procedure Read_Protocols
     (Data      : Byte_Array;
      Body_Part : in out SSL.Wire.Cursor;
      Bounds    : SSL.Limits.Resource_Limits;
      Into      : out SSL.ALPN.Protocol_List;
      Error     : out SSL.Errors.Error_Information);

   procedure Read_Protocols
     (Data      : Byte_Array;
      Body_Part : in out SSL.Wire.Cursor;
      Bounds    : SSL.Limits.Resource_Limits;
      Into      : out SSL.ALPN.Protocol_List;
      Error     : out SSL.Errors.Error_Information)
   is
      List   : SSL.Wire.Cursor;
      Length : Natural;
      First  : Byte_Index;
      Last   : Byte_Index;
      Count  : Natural := 0;
      Name   : SSL.ALPN.Protocol_Name;
      Done   : Boolean;
   begin
      Into := SSL.ALPN.No_Protocols;
      Error := SSL.Errors.No_Error;
      SSL.Wire.Open_Vector_16 (Data, Body_Part, 65_535, List);

      while SSL.Wire.Is_Valid (List) and then not SSL.Wire.At_End (List) loop
         SSL.Wire.Get_UInt8 (Data, List, Length);
         exit when not SSL.Wire.Is_Valid (List);

         --  RFC 7301 section 3.1: a protocol name is one to 255 octets. A
         --  zero-length name is a protocol violation, not an empty preference.
         if Length = 0 then
            Error := SSL.Errors.Make
              (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
            return;
         end if;

         SSL.Wire.Get_Span (Data, List, Byte_Index (Length), First, Last);
         exit when not SSL.Wire.Is_Valid (List);

         Count := Count + 1;
         if Count > Bounds.Maximum_ALPN_Protocols then
            Error := SSL.Errors.Limit_Failure
              (SSL.Limits.ALPN_Protocols,
               Long_Long_Integer (Bounds.Maximum_ALPN_Protocols),
               Long_Long_Integer (Count));
            return;
         end if;

         if SSL.ALPN.Make (Data (First .. Last), Name) then
            SSL.ALPN.Append (Into, Name, Done);
            if not Done then
               --  A duplicate protocol name. RFC 7301 does not forbid it in so
               --  many words, but a list with a repeat is a list whose
               --  preference order means two different things.
               Error := SSL.Errors.Make
                 (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
               return;
            end if;
         end if;
      end loop;
   end Read_Protocols;

   --  server_name: RFC 6066 section 3. Exactly one host_name entry is meaningful
   --  and every deployed implementation sends exactly one.
   procedure Read_Server_Name
     (Data      : Byte_Array;
      Body_Part : in out SSL.Wire.Cursor;
      Bounds    : SSL.Limits.Resource_Limits;
      Into      : out SSL.Server_Names.DNS_Name;
      Error     : out SSL.Errors.Error_Information);

   procedure Read_Server_Name
     (Data      : Byte_Array;
      Body_Part : in out SSL.Wire.Cursor;
      Bounds    : SSL.Limits.Resource_Limits;
      Into      : out SSL.Server_Names.DNS_Name;
      Error     : out SSL.Errors.Error_Information)
   is
      List    : SSL.Wire.Cursor;
      Kind    : Natural;
      Length  : Natural;
      First   : Byte_Index;
      Last    : Byte_Index;
      Status  : SSL.Server_Names.Name_Status;
   begin
      Into := SSL.Server_Names.No_Name;
      Error := SSL.Errors.No_Error;
      SSL.Wire.Open_Vector_16 (Data, Body_Part, 65_535, List);

      while SSL.Wire.Is_Valid (List) and then not SSL.Wire.At_End (List) loop
         declare
            Entry_Body : SSL.Wire.Cursor;
         begin
            SSL.Wire.Get_UInt8 (Data, List, Kind);
            SSL.Wire.Open_Vector_16
              (Data, List, Byte_Index (Bounds.Maximum_Server_Name_Length), Entry_Body);
            exit when not SSL.Wire.Is_Valid (List);

            --  Only host_name(0) is defined and nothing else has ever been
            --  allocated. An entry of another type is skipped, which opening its
            --  body above has already done.
            if Kind = 0 then
               SSL.Wire.Get_Span (Data, Entry_Body, SSL.Wire.Remaining (Entry_Body), First, Last);
               Length := Natural (Last - First + 1);
               if Length = 0 then
                  Error := SSL.Errors.Make
                    (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
                  return;
               end if;

               declare
                  Text : String (1 .. Length);
               begin
                  for Index in Text'Range loop
                     Text (Index) :=
                       Character'Val (Natural (Data (First + Byte_Index (Index) - 1)));
                  end loop;

                  --  A name that does not parse is not a name this endpoint can
                  --  route on. It is left absent rather than refused, because
                  --  RFC 6066 lets a server that does not recognize a name carry
                  --  on, and this library's unrecognized-name policy decides.
                  SSL.Server_Names.Parse (Text, Into, Status);
                  if Status /= SSL.Server_Names.Ok then
                     Into := SSL.Server_Names.No_Name;
                  end if;
               end;
            end if;
         end;
         exit;
      end loop;
   end Read_Server_Name;

   procedure Read_PSK_Offer
     (Data      : Byte_Array;
      Body_Part : in out SSL.Wire.Cursor;
      Bounds    : SSL.Limits.Resource_Limits;
      Item      : in out Client_Hello_Message;
      Error     : out SSL.Errors.Error_Information)
   is
      --  The shortest hash this library uses is SHA-256, so no binder can be
      --  shorter than that and still be one.
      Minimum_Binder : constant Byte_Index := 32;

      Allowed : constant Natural :=
        Natural'Min (Bounds.Maximum_PSK_Identities, Maximum_Offered_Identities);

      Identities : SSL.Wire.Cursor;
      Binders    : SSL.Wire.Cursor;
      One        : SSL.Wire.Cursor;
      Count      : Natural := 0;
      First      : Byte_Index;
      Last       : Byte_Index;
   begin
      Error := SSL.Errors.No_Error;

      SSL.Wire.Open_Vector_16
        (Data, Body_Part, Byte_Index (Bounds.Maximum_Extension_Body), Identities);
      if not SSL.Wire.Is_Valid (Identities) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      while SSL.Wire.Is_Valid (Identities) and then not SSL.Wire.At_End (Identities) loop
         SSL.Wire.Open_Vector_16
           (Data, Identities, Byte_Index (Bounds.Maximum_Ticket_Size), One);
         exit when not SSL.Wire.Is_Valid (One);

         if SSL.Wire.Remaining (One) = 0 then
            Error := SSL.Errors.Make
              (SSL.Errors.Code_Ticket_Malformed, SSL.Errors.Peer_Message);
            return;
         end if;

         Count := Count + 1;
         if Count > Allowed then
            Error := SSL.Errors.Limit_Failure
              (SSL.Limits.PSK_Identities,
               Long_Long_Integer (Allowed),
               Long_Long_Integer (Count));
            return;
         end if;

         SSL.Wire.Get_Span (Data, One, SSL.Wire.Remaining (One), First, Last);
         Item.Identities (Count).Identity := (Present => True, First => First, Last => Last);
         SSL.Wire.Get_UInt32 (Data, Identities, Item.Identities (Count).Age);
      end loop;

      if not SSL.Wire.Is_Valid (Identities) or else Count = 0 then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      --  Where the binders begin: the cursor is now at their two-octet length
      --  prefix, and everything from here on is outside what they cover.
      Item.Binders_At := Body_Part.Position;

      SSL.Wire.Open_Vector_16
        (Data, Body_Part, Byte_Index (Bounds.Maximum_Extension_Body), Binders);
      if not SSL.Wire.Is_Valid (Binders) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      for Index in 1 .. Count loop
         SSL.Wire.Open_Vector_8 (Data, Binders, 255, One);
         if not SSL.Wire.Is_Valid (One)
           or else SSL.Wire.Remaining (One) < Minimum_Binder
         then
            Error := SSL.Errors.Make
              (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
            return;
         end if;
         SSL.Wire.Get_Span (Data, One, SSL.Wire.Remaining (One), First, Last);
         Item.Identities (Index).Binder := (Present => True, First => First, Last => Last);
      end loop;

      --  One binder per identity and no more. A trailing binder would mean the
      --  two lists disagree about how many offers there are, and matching them
      --  by position would then be matching the wrong things.
      if not SSL.Wire.At_End (Binders) or else not SSL.Wire.At_End (Body_Part) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      Item.Identity_Count := Count;
      Item.Has_PSK := True;
   end Read_PSK_Offer;

   ---------------------------------------------------------------------------
   --  ClientHello
   ---------------------------------------------------------------------------

   function Legacy_Version (Item : Client_Hello_Message) return SSL.Versions.Version_Value
   is (Item.Legacy);
   function Random (Item : Client_Hello_Message) return Random_Bytes is (Item.Random_Value);
   function Session_Id (Item : Client_Hello_Message) return Byte_Array
   is (Item.Id_Value (1 .. Item.Id_Length));
   function Offered_Suites (Item : Client_Hello_Message) return Suites.Suite_List
   is (Item.Suites);
   function Offered_Groups (Item : Client_Hello_Message) return Groups.Group_List
   is (Item.Groups);
   function Offered_Schemes (Item : Client_Hello_Message) return Schemes.Scheme_List
   is (Item.Schemes);
   function Offered_Protocols (Item : Client_Hello_Message) return SSL.ALPN.Protocol_List
   is (Item.Protocols);
   function Offered_Versions (Item : Client_Hello_Message) return SSL.Versions.Version_Set
   is (Item.Versions);
   function Offered_Name (Item : Client_Hello_Message) return SSL.Server_Names.DNS_Name
   is (Item.Name);
   function Extensions_Seen (Item : Client_Hello_Message) return Ext.Seen_Set is (Item.Seen);
   function Requested_Record_Limit (Item : Client_Hello_Message) return Byte_Index
   is (Item.Record_Limit);
   function Requests_Status (Item : Client_Hello_Message) return Boolean is (Item.Status);

   function Key_Share_For
     (Item  : Client_Hello_Message;
      Group : Groups.Named_Group;
      First : out Byte_Index;
      Last  : out Byte_Index) return Boolean
   is
   begin
      First := 1;
      Last := 0;
      for Index in 1 .. Item.Share_Count loop
         if Item.Shares (Index).Group = Group then
            First := Item.Shares (Index).Body_Span.First;
            Last := Item.Shares (Index).Body_Span.Last;
            return True;
         end if;
      end loop;
      return False;
   end Key_Share_For;

   function Key_Share_Groups (Item : Client_Hello_Message) return Groups.Group_List is
      Result : Groups.Group_List := Groups.No_Groups;
      Done   : Boolean;
   begin
      for Index in 1 .. Item.Share_Count loop
         Groups.Append (Result, Item.Shares (Index).Group, Done);
      end loop;
      return Result;
   end Key_Share_Groups;

   function Cookie_Span
     (Item  : Client_Hello_Message;
      First : out Byte_Index;
      Last  : out Byte_Index) return Boolean
   is
   begin
      First := Item.Cookie.First;
      Last := Item.Cookie.Last;
      return Item.Cookie.Present;
   end Cookie_Span;

   function Offers_PSK (Item : Client_Hello_Message) return Boolean is (Item.Has_PSK);

   function PSK_Identity_Count (Item : Client_Hello_Message) return Natural is
     (Item.Identity_Count);

   procedure PSK_Identity_Span
     (Item  : Client_Hello_Message;
      Index : Positive;
      First : out Byte_Index;
      Last  : out Byte_Index)
   is
   begin
      First := Item.Identities (Index).Identity.First;
      Last := Item.Identities (Index).Identity.Last;
   end PSK_Identity_Span;

   function PSK_Obfuscated_Age
     (Item : Client_Hello_Message; Index : Positive) return Interfaces.Unsigned_32
   is (Item.Identities (Index).Age);

   procedure PSK_Binder_Span
     (Item  : Client_Hello_Message;
      Index : Positive;
      First : out Byte_Index;
      Last  : out Byte_Index)
   is
   begin
      First := Item.Identities (Index).Binder.First;
      Last := Item.Identities (Index).Binder.Last;
   end PSK_Binder_Span;

   function PSK_Binders_Offset (Item : Client_Hello_Message) return Byte_Index is
     (Item.Binders_At);

   function Allows_PSK_With_DHE (Item : Client_Hello_Message) return Boolean is
     (Item.PSK_With_DHE);

   function Allows_PSK_Alone (Item : Client_Hello_Message) return Boolean is
     (Item.PSK_Alone);

   procedure Parse_Client_Hello
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out Client_Hello_Message;
      Error  : out SSL.Errors.Error_Information)
   is
      Cursor  : SSL.Wire.Cursor;
      Value   : Natural;
      Length  : Natural;
      First   : Byte_Index;
      Last    : Byte_Index;
      Block   : SSL.Wire.Cursor;
      Reset   : Client_Hello_Message;
   begin
      Item := Reset;
      Error := SSL.Errors.No_Error;

      --  The declared body length must match the octets supplied.
      --
      --  In the assembled protocol the reassembly layer has already collected
      --  exactly this many octets, so this is a second opinion -- but a cheap
      --  one, and it makes the parser self-contained: handed a truncated
      --  message directly, it refuses rather than parsing whatever prefix
      --  happens to be well-formed. A prefix of a ClientHello that stops just
      --  before the extension block is a valid extensionless ClientHello, and
      --  without this check it would parse as one.
      declare
         Kind    : Message_Type;
         Value   : Type_Value;
         Declared : Byte_Index;
      begin
         Parse_Header (Data, Kind, Value, Declared, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;
         if Data'Length /= Header_Length + Declared then
            Error := SSL.Errors.Make
              (Code       => SSL.Errors.Code_Handshake_Message_Malformed,
               Origin     => SSL.Errors.Peer_Message,
               Parameters =>
                 [SSL.Errors.Numeric_Parameter ("declared", Long_Long_Integer (Declared)),
                  SSL.Errors.Numeric_Parameter
                    ("supplied", Long_Long_Integer (Data'Length - Header_Length))]);
            return;
         end if;
      end;

      --  The body starts after the four-octet handshake header.
      Cursor := SSL.Wire.Reader (Data'First + Header_Length, Data'Last);

      SSL.Wire.Get_UInt16 (Data, Cursor, Value);
      Item.Legacy := SSL.Versions.Version_Value (Value);

      SSL.Wire.Get_Bytes (Data, Cursor, Item.Random_Value);

      --  The legacy session identifier, kept verbatim: a TLS 1.3 server must
      --  echo it exactly, and a re-encoding that differed would change the
      --  transcript.
      SSL.Wire.Get_UInt8 (Data, Cursor, Length);
      if Length > Natural (Maximum_Session_Id_Length) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Legacy_Session_Id_Mismatch, SSL.Errors.Peer_Message);
         return;
      end if;
      Item.Id_Length := Byte_Index (Length);
      SSL.Wire.Get_Bytes (Data, Cursor, Item.Id_Value (1 .. Item.Id_Length));

      --  Cipher suites.
      declare
         List  : SSL.Wire.Cursor;
         Count : Natural := 0;
         Suite : Suites.Cipher_Suite;
         Done  : Boolean;
      begin
         SSL.Wire.Open_Vector_16
           (Data, Cursor, 2 * Byte_Index (Bounds.Maximum_Cipher_Suites), List);

         while SSL.Wire.Is_Valid (List) and then not SSL.Wire.At_End (List) loop
            SSL.Wire.Get_UInt16 (Data, List, Value);
            exit when not SSL.Wire.Is_Valid (List);

            Count := Count + 1;
            if Count > Bounds.Maximum_Cipher_Suites then
               Error := SSL.Errors.Limit_Failure
                 (SSL.Limits.Cipher_Suites,
                  Long_Long_Integer (Bounds.Maximum_Cipher_Suites),
                  Long_Long_Integer (Count));
               return;
            end if;

            --  Signalling values are not suites and are not recorded as such.
            --  The fallback sentinel in particular has to reach the state
            --  machine as a downgrade signal, not as an unusable suite.
            if Suites.Suite_For (Suites.Suite_Value (Value), Suite) then
               Suites.Append (Item.Suites, Suite, Done);
            end if;
         end loop;
      end;

      --  Compression methods. TLS 1.3 requires exactly one, null(0); TLS 1.2 as
      --  restricted here requires the same. Anything else is a peer offering
      --  compression, which is a refusal and not a negotiation.
      SSL.Wire.Get_UInt8 (Data, Cursor, Length);
      if Length = 0 then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      SSL.Wire.Get_Span (Data, Cursor, Byte_Index (Length), First, Last);
      if not SSL.Wire.Is_Valid (Cursor) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      for Index in First .. Last loop
         if Data (Index) /= 0 then
            Error := SSL.Errors.Make
              (Code       => SSL.Errors.Code_Legacy_Compression_Offered,
               Origin     => SSL.Errors.Peer_Message,
               Parameters =>
                 [SSL.Errors.Numeric_Parameter ("method", Long_Long_Integer (Data (Index)))]);
            return;
         end if;
      end loop;

      if not SSL.Wire.Is_Valid (Cursor) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      --  A ClientHello with no extension block at all is a TLS 1.2-era hello.
      --  It parses; whether this endpoint can negotiate with it is the state
      --  machine's question.
      if SSL.Wire.At_End (Cursor) then
         return;
      end if;

      Ext.Open_Block (Data, Cursor, Bounds, Block, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      loop
         declare
            Kind      : Ext.Extension_Kind;
            Number    : Ext.Extension_Value;
            Body_Part : SSL.Wire.Cursor;
            Present   : Boolean;
         begin
            Ext.Next (Data, Block, Ext.In_Client_Hello, Bounds, Item.Seen,
                      Kind, Number, Body_Part, Present, Error);
            exit when SSL.Errors.Is_Error (Error) or else not Present;

            --  RFC 8446 section 4.2.11: pre_shared_key must be the last
            --  extension in the block. The binders cover the message up to the
            --  point where they begin, so an extension emitted after them would
            --  be outside everything the binder authenticates -- which is to say
            --  a peer could change it and no binder would notice.
            if Item.Has_PSK then
               Error := SSL.Errors.Make
                 (Code       => SSL.Errors.Code_PSK_Not_Last_Extension,
                  Origin     => SSL.Errors.Peer_Message,
                  Parameters =>
                    [SSL.Errors.Text_Parameter ("followed_by", Ext.Image (Number))]);
               exit;
            end if;

            case Kind is
               when Ext.Supported_Versions =>
                  Read_Client_Versions (Data, Body_Part, Bounds, Item.Versions);

               when Ext.PSK_Key_Exchange_Modes =>
                  declare
                     List : SSL.Wire.Cursor;
                     Mode : Natural;
                  begin
                     SSL.Wire.Open_Vector_8 (Data, Body_Part, 255, List);
                     while SSL.Wire.Is_Valid (List) and then not SSL.Wire.At_End (List) loop
                        SSL.Wire.Get_UInt8 (Data, List, Mode);
                        exit when not SSL.Wire.Is_Valid (List);
                        --  psk_ke(0) and psk_dhe_ke(1) are the two defined
                        --  modes; anything else is skipped rather than refused,
                        --  because a mode this library has not heard of is a
                        --  mode it would not have used.
                        case Mode is
                           when 0 => Item.PSK_Alone := True;
                           when 1 => Item.PSK_With_DHE := True;
                           when others => null;
                        end case;
                     end loop;
                     if not SSL.Wire.Is_Valid (List) or else not SSL.Wire.At_End (Body_Part) then
                        Error := SSL.Errors.Make
                          (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
                     end if;
                  end;

               when Ext.Pre_Shared_Key =>
                  Read_PSK_Offer (Data, Body_Part, Bounds, Item, Error);

               when Ext.Supported_Groups =>
                  Read_Groups (Data, Body_Part, Bounds, Item.Groups, Error);

               when Ext.Signature_Algorithms =>
                  Read_Schemes (Data, Body_Part, Bounds, Item.Schemes, Error);

               when Ext.Application_Layer_Protocol_Negotiation =>
                  Read_Protocols (Data, Body_Part, Bounds, Item.Protocols, Error);

               when Ext.Server_Name =>
                  Read_Server_Name (Data, Body_Part, Bounds, Item.Name, Error);

               when Ext.Status_Request =>
                  Item.Status := True;

               when Ext.Record_Size_Limit =>
                  SSL.Wire.Get_UInt16 (Data, Body_Part, Value);
                  if not SSL.Wire.Is_Valid (Body_Part)
                    or else Value < SSL.Limits.Minimum_Record_Size_Limit
                  then
                     --  RFC 8449 section 4: below 64 the value is illegal, and a
                     --  peer that sends one gets illegal_parameter rather than a
                     --  silently clamped limit.
                     Error := SSL.Errors.Make
                       (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
                  else
                     Item.Record_Limit := Byte_Index (Value);
                  end if;

               when Ext.Cookie =>
                  declare
                     Inner : SSL.Wire.Cursor;
                  begin
                     SSL.Wire.Open_Vector_16
                       (Data, Body_Part, Byte_Index (Bounds.Maximum_Cookie_Length), Inner);
                     if not SSL.Wire.Is_Valid (Body_Part) then
                        Error := SSL.Errors.Make
                          (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
                     else
                        SSL.Wire.Get_Span
                          (Data, Inner, SSL.Wire.Remaining (Inner), First, Last);
                        Item.Cookie := (Present => True, First => First, Last => Last);
                     end if;
                  end;

               when Ext.Key_Share =>
                  declare
                     List  : SSL.Wire.Cursor;
                     Named : Groups.Named_Group;
                  begin
                     SSL.Wire.Open_Vector_16 (Data, Body_Part, 65_535, List);
                     while SSL.Wire.Is_Valid (List) and then not SSL.Wire.At_End (List) loop
                        SSL.Wire.Get_UInt16 (Data, List, Value);
                        SSL.Wire.Get_UInt16 (Data, List, Length);
                        SSL.Wire.Get_Span (Data, List, Byte_Index (Length), First, Last);
                        exit when not SSL.Wire.Is_Valid (List);

                        if Groups.Group_For (Groups.Group_Value (Value), Named)
                          and then Item.Share_Count < Maximum_Recorded_Shares
                        then
                           --  The share's length is checked against the group's
                           --  own width here, before anything downstream sees
                           --  it. A share of the wrong size for the group it was
                           --  offered under never reaches key agreement.
                           if Byte_Index (Length) = Groups.Share_Length (Named) then
                              Item.Share_Count := Item.Share_Count + 1;
                              Item.Shares (Item.Share_Count) :=
                                (Group     => Named,
                                 Body_Span => (Present => True,
                                               First   => First,
                                               Last    => Last));
                           end if;
                        end if;
                     end loop;
                  end;

               when Ext.Early_Data | Ext.Post_Handshake_Auth =>
                  --  Unreachable: Ext.Permitted answers False for both, so
                  --  Ext.Next has already refused. Listed rather than covered by
                  --  an "others" so a change to the context table is a compile
                  --  error here.
                  Error := SSL.Errors.Make
                    (SSL.Errors.Code_Extension_In_Wrong_Context, SSL.Errors.Peer_Message);

               when others =>
                  --  Recognized but not acted on here, or unrecognized. Either
                  --  way the body has been skipped by Ext.Next and the identifier
                  --  recorded in Item.Seen for diagnostics.
                  null;
            end case;

            exit when SSL.Errors.Is_Error (Error);
         end;
      end loop;

      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      if not SSL.Wire.Is_Valid (Cursor) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message);
      end if;
   end Parse_Client_Hello;

   ---------------------------------------------------------------------------
   --  ClientHello encoding
   ---------------------------------------------------------------------------

   procedure Encode_Client_Hello
     (Config       : SSL.Configurations.Client_Configuration;
      Random_Value : Random_Bytes;
      Session_Id   : Byte_Array;
      Shares       : Key_Share_List;
      Share_Count  : Natural;
      Cookie       : Byte_Array;
      Identity     : Byte_Array;
      Obfuscated_Age : Interfaces.Unsigned_32;
      Binder_Length : Byte_Index;
      Legacy_Ticket : Byte_Array := [1 .. 0 => 0];
      Offer_Legacy_Ticket : Boolean := False;
      Into         : out Byte_Array;
      Written      : out Byte_Index;
      Binders_At   : out Byte_Index;
      Error        : out SSL.Errors.Error_Information)
   is
      package Config_Package renames SSL.Configurations;

      Emitter : SSL.Wire.Emitter;

      --  One variable per nesting level, never shared. A deferred length prefix
      --  is a position remembered until the matching close, so two vectors that
      --  are open at the same time cannot share the variable that remembers it:
      --  the inner close leaves the outer position lost, and the outer close
      --  then patches whatever the inner one had recorded. Naming the levels
      --  makes reusing one across a nesting boundary a visible mistake.
      Body_Mark  : Byte_Index;   --  the message body, back-patched last
      Block_Mark : Byte_Index;   --  the extension block
      Ext_Mark   : Byte_Index;   --  the extension currently open
      Inner      : Byte_Index;   --  a vector inside that extension
      Deep       : Byte_Index;   --  a vector inside that vector
   begin
      Written := 0;
      Binders_At := 1;
      if Into'Length > 0 then
         Into := [others => 0];
      end if;
      Error := SSL.Errors.No_Error;

      --  The header length is back-patched once the body is complete, which is
      --  the same deferred-prefix discipline every nested vector here uses. A
      --  two-pass encoder would have to agree with itself about the length.
      Emitter := SSL.Wire.Writer (Into);
      SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Value_Of (Client_Hello)));
      SSL.Wire.Open_Vector_24 (Into, Emitter, Body_Mark);

      --  legacy_version is 0x0303 in every TLS 1.3 ClientHello, whatever is
      --  actually being offered. The real versions are in supported_versions.
      SSL.Wire.Put_UInt16 (Into, Emitter, Natural (SSL.Versions.Legacy_Record_Value));
      SSL.Wire.Put_Bytes (Into, Emitter, Random_Value);

      SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Session_Id'Length));
      SSL.Wire.Put_Bytes (Into, Emitter, Session_Id);

      --  Cipher suites, in the configuration's preference order.
      declare
         Offered : constant Suites.Suite_List := Config_Package.Cipher_Suites (Config);
      begin
         SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
         for Index in 1 .. Suites.Length (Offered) loop
            SSL.Wire.Put_UInt16
              (Into, Emitter, Natural (Suites.Value_Of (Suites.Element (Offered, Index))));
         end loop;
         SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
      end;

      --  Compression: the null method and nothing else, ever.
      SSL.Wire.Put_UInt8 (Into, Emitter, 1);
      SSL.Wire.Put_UInt8 (Into, Emitter, 0);

      SSL.Extensions.Open_Block (Into, Emitter, Block_Mark);

      --  supported_versions first. A server reads this to decide which
      --  protocol it is speaking, and putting it first costs nothing.
      declare
         Values : SSL.Versions.Version_Value_Array;
         Last   : Natural;
      begin
         SSL.Versions.Ordered_Values (Config_Package.Versions (Config), Values, Last);
         SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Supported_Versions, Ext_Mark);
         SSL.Wire.Open_Vector_8 (Into, Emitter, Inner);
         for Index in 1 .. Last loop
            SSL.Wire.Put_UInt16 (Into, Emitter, Natural (Values (Index)));
         end loop;
         SSL.Wire.Close_Vector_8 (Into, Emitter, Inner);
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
      end;

      --  server_name, when there is a routing name to send. An expected IP
      --  address never produces one: RFC 6066 section 3 forbids an address here,
      --  and the configuration has already switched the indication off.
      if Config_Package.Sends_Server_Name (Config) then
         declare
            Name : constant Byte_Array :=
              SSL.Server_Names.Octets (Config_Package.Server_Name_Indication (Config));
         begin
            SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Server_Name, Ext_Mark);
            SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
            SSL.Wire.Put_UInt8 (Into, Emitter, 0);          --  host_name
            SSL.Wire.Open_Vector_16 (Into, Emitter, Deep);
            SSL.Wire.Put_Bytes (Into, Emitter, Name);
            SSL.Wire.Close_Vector_16 (Into, Emitter, Deep);
            SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
            SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
         end;
      end if;

      --  supported_groups.
      declare
         Offered : constant Groups.Group_List := Config_Package.Groups (Config);
      begin
         SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Supported_Groups, Ext_Mark);
         SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
         for Index in 1 .. Groups.Length (Offered) loop
            SSL.Wire.Put_UInt16
              (Into, Emitter, Natural (Groups.Value_Of (Groups.Element (Offered, Index))));
         end loop;
         SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
      end;

      --  signature_algorithms, restricted to what is usable for the highest
      --  version being offered.
      declare
         Offered : constant Schemes.Scheme_List :=
           Config_Package.Signature_Schemes (Config);
      begin
         SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Signature_Algorithms, Ext_Mark);
         SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
         for Index in 1 .. Schemes.Length (Offered) loop
            SSL.Wire.Put_UInt16
              (Into, Emitter, Natural (Schemes.Value_Of (Schemes.Element (Offered, Index))));
         end loop;
         SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
      end;

      --  signature_algorithms_cert, which is a separate list because what may
      --  sign a certificate and what may sign a CertificateVerify are separate
      --  questions -- PKCS#1 v1.5 answers the first and not the second.
      declare
         Offered : constant Schemes.Scheme_List :=
           Config_Package.Certificate_Signature_Schemes (Config);
      begin
         SSL.Extensions.Open_Extension
           (Into, Emitter, SSL.Extensions.Signature_Algorithms_Cert, Ext_Mark);
         SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
         for Index in 1 .. Schemes.Length (Offered) loop
            SSL.Wire.Put_UInt16
              (Into, Emitter, Natural (Schemes.Value_Of (Schemes.Element (Offered, Index))));
         end loop;
         SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
      end;

      --  ALPN, when the policy offers any.
      if Config_Package.ALPN_Requirement (Config) /= SSL.ALPN.Not_Offered then
         declare
            Offered : constant SSL.ALPN.Protocol_List :=
              Config_Package.Application_Protocols (Config);
         begin
            SSL.Extensions.Open_Extension
              (Into, Emitter, SSL.Extensions.Application_Layer_Protocol_Negotiation, Ext_Mark);
            SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
            for Index in 1 .. SSL.ALPN.Length (Offered) loop
               declare
                  Name : constant Byte_Array :=
                    SSL.ALPN.Value_Of (SSL.ALPN.Element (Offered, Index));
               begin
                  SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Name'Length));
                  SSL.Wire.Put_Bytes (Into, Emitter, Name);
               end;
            end loop;
            SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
            SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
         end;
      end if;

      --  status_request, when revocation policy wants a stapled response.
      if Config_Package.Requests_Stapled_Status (Config) then
         SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Status_Request, Ext_Mark);
         SSL.Wire.Put_UInt8 (Into, Emitter, 1);           --  ocsp
         SSL.Wire.Put_UInt16 (Into, Emitter, 0);          --  no responder id list
         SSL.Wire.Put_UInt16 (Into, Emitter, 0);          --  no request extensions
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
      end if;

      --  record_size_limit, when the policy asks for less than the maximum.
      declare
         Limit : constant Byte_Index :=
           Byte_Index (Config_Package.Bounds (Config).Maximum_Plaintext_Record);
      begin
         if Limit < SSL.Limits.Protocol_Plaintext_Record_Limit then
            SSL.Extensions.Open_Extension
              (Into, Emitter, SSL.Extensions.Record_Size_Limit, Ext_Mark);
            SSL.Wire.Put_UInt16 (Into, Emitter, Natural (Limit));
            SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
         end if;
      end;

      --  The three extensions restricted TLS 1.2 needs, emitted whenever the
      --  policy offers TLS 1.2 at all.
      --
      --  They are meaningless to a TLS 1.3 server, which ignores them, and they
      --  are what lets one hello serve both versions: a client that sent a
      --  1.3-only hello and then found the server wanted 1.2 would have to
      --  start again, and the extra round trip is exactly what a downgrade
      --  attacker wants to provoke.
      if SSL.Versions.Contains (Config_Package.Versions (Config), SSL.Versions.TLS_1_2) then
         SSL.Extensions.Open_Extension
           (Into, Emitter, SSL.Extensions.Extended_Master_Secret, Ext_Mark);
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);

         SSL.Extensions.Open_Extension
           (Into, Emitter, SSL.Extensions.Renegotiation_Info, Ext_Mark);
         SSL.Wire.Put_UInt8 (Into, Emitter, 0);
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);

         --  The uncompressed form and nothing else.
         SSL.Extensions.Open_Extension
           (Into, Emitter, SSL.Extensions.EC_Point_Formats, Ext_Mark);
         SSL.Wire.Put_UInt8 (Into, Emitter, 1);
         SSL.Wire.Put_UInt8 (Into, Emitter, 0);
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);

         --  RFC 5077's session_ticket, for the same reason as the three above:
         --  one hello has to serve both versions, and a TLS 1.2 ticket can only
         --  be offered in the hello that a TLS 1.2 server will read. An empty
         --  one asks for a ticket; a full one offers the ticket it holds. A
         --  TLS 1.3 server ignores it, and this client never sends both this
         --  and a `pre_shared_key` for the same session -- a session belongs to
         --  one version and is offered in that version's way.
         if Offer_Legacy_Ticket then
            SSL.Extensions.Open_Extension
              (Into, Emitter, SSL.Extensions.Session_Ticket, Ext_Mark);
            SSL.Wire.Put_Bytes (Into, Emitter, Legacy_Ticket);
            SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
         end if;
      end if;

      --  cookie, echoed exactly as it arrived. RFC 8446 section 4.2.2 says a
      --  client that receives one must send it back unchanged, because it is
      --  the server's own state and the server is the only thing that can read
      --  it.
      if Cookie'Length > 0 then
         SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Cookie, Ext_Mark);
         SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
         SSL.Wire.Put_Bytes (Into, Emitter, Cookie);
         SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
      end if;

      --  key_share last of the ones sent here. pre_shared_key would follow it
      --  and must be the final extension in the block (RFC 8446 section
      --  4.2.11), because the binder covers the message up to that point.
      SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Key_Share, Ext_Mark);
      SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
      for Index in 1 .. Share_Count loop
         SSL.Wire.Put_UInt16
           (Into, Emitter, Natural (Groups.Value_Of (Shares (Index).Group)));
         SSL.Wire.Open_Vector_16 (Into, Emitter, Deep);
         SSL.Wire.Put_Bytes
           (Into, Emitter, Shares (Index).Value (1 .. Shares (Index).Length));
         SSL.Wire.Close_Vector_16 (Into, Emitter, Deep);
      end loop;
      SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
      SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);

      --  psk_key_exchange_modes, whenever a ticket is being offered. RFC 8446
      --  section 4.2.9 makes it mandatory alongside pre_shared_key, and this
      --  library offers exactly one mode: resumption always comes with a fresh
      --  key exchange, so a resumed connection has forward secrecy that a
      --  psk_ke one would not.
      if Identity'Length > 0 then
         SSL.Extensions.Open_Extension
           (Into, Emitter, SSL.Extensions.PSK_Key_Exchange_Modes, Ext_Mark);
         SSL.Wire.Put_UInt8 (Into, Emitter, 1);
         SSL.Wire.Put_UInt8 (Into, Emitter, 1);          --  psk_dhe_ke
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);

         --  pre_shared_key, last of everything. RFC 8446 section 4.2.11
         --  requires it, because the binder covers the message up to the point
         --  where the binders begin and an extension after them would be
         --  outside everything the binder authenticates.
         SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Pre_Shared_Key, Ext_Mark);

         SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
         SSL.Wire.Open_Vector_16 (Into, Emitter, Deep);
         SSL.Wire.Put_Bytes (Into, Emitter, Identity);
         SSL.Wire.Close_Vector_16 (Into, Emitter, Deep);
         SSL.Wire.Put_UInt32 (Into, Emitter, Obfuscated_Age);
         SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);

         --  The binders go out as zeroes and the caller writes the real one
         --  in. It cannot be computed before this point, because it is over
         --  the message up to this point.
         Binders_At := SSL.Wire.Written (Emitter) + Into'First;
         SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
         SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Binder_Length));
         SSL.Wire.Put_Zeroes (Into, Emitter, Binder_Length);
         SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);

         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
      end if;

      SSL.Extensions.Close_Block (Into, Emitter, Block_Mark);

      SSL.Wire.Close_Vector_24 (Into, Emitter, Body_Mark);

      if not SSL.Wire.Is_Valid (Emitter) then
         --  The buffer was too small, or a vector overflowed its prefix. Either
         --  way nothing partial is emitted: a truncated ClientHello would be a
         --  message the transcript hashed and the peer could not parse.
         if Into'Length > 0 then
            Into := [others => 0];
         end if;
         Error := SSL.Errors.Make
           (Code   => SSL.Errors.Code_Handshake_Message_Malformed,
            Origin => SSL.Errors.Local_Implementation);
         return;
      end if;

      Written := SSL.Wire.Written (Emitter);
   end Encode_Client_Hello;

   ---------------------------------------------------------------------------
   --  CertificateVerify content
   ---------------------------------------------------------------------------

   --  RFC 8446 section 4.4.3, written out exactly as the specification gives
   --  them, trailing NUL excluded -- the zero separator is appended separately
   --  so that it is visible as the separator it is.
   Server_Context : constant String := "TLS 1.3, server CertificateVerify";
   Client_Context : constant String := "TLS 1.3, client CertificateVerify";

   function Context_Length (Role : Signing_Role) return Byte_Index is
   begin
      case Role is
         when Server_Signing => return Server_Context'Length;
         when Client_Signing => return Client_Context'Length;
      end case;
   end Context_Length;

   function Certificate_Verify_Content
     (Role            : Signing_Role;
      Transcript_Hash : Byte_Array) return Byte_Array
   is
      Context : constant String :=
        (case Role is
            when Server_Signing => Server_Context,
            when Client_Signing => Client_Context);

      --  Sixty-four octets of 0x20. Their purpose is to make this structure
      --  unable to collide with anything a TLS 1.2 signature covered, so a
      --  signature harvested from an old connection cannot be replayed here.
      Padding : constant Byte_Array (1 .. 64) := [others => 16#20#];

      Result : Byte_Array
        (1 .. 64 + Byte_Index (Context'Length) + 1 + Transcript_Hash'Length);
      Cursor : Byte_Index := 1;
   begin
      Result (Cursor .. Cursor + 63) := Padding;
      Cursor := Cursor + 64;

      for Character_Item of Context loop
         Result (Cursor) := Byte (Character'Pos (Character_Item));
         Cursor := Cursor + 1;
      end loop;

      --  The separator. A single zero octet, which is what keeps the context
      --  string from running into the hash.
      Result (Cursor) := 0;
      Cursor := Cursor + 1;

      if Transcript_Hash'Length > 0 then
         Result (Cursor .. Result'Last) := Transcript_Hash;
      end if;

      return Result;
   end Certificate_Verify_Content;

   ---------------------------------------------------------------------------
   --  ServerHello
   ---------------------------------------------------------------------------

   function Legacy_Version (Item : Server_Hello_Message) return SSL.Versions.Version_Value
   is (Item.Legacy);
   function Random (Item : Server_Hello_Message) return Random_Bytes is (Item.Random_Value);
   function Session_Id (Item : Server_Hello_Message) return Byte_Array
   is (Item.Id_Value (1 .. Item.Id_Length));
   function Selected_Suite (Item : Server_Hello_Message) return Suites.Cipher_Suite
   is (Item.Suite);
   function Selected_Version (Item : Server_Hello_Message) return SSL.Versions.Version_Value
   is (Item.Version);
   function Extensions_Seen (Item : Server_Hello_Message) return Ext.Seen_Set is (Item.Seen);
   function Is_Hello_Retry_Request (Item : Server_Hello_Message) return Boolean is (Item.Retry);

   function Server_Key_Share
     (Item  : Server_Hello_Message;
      Group : out Groups.Named_Group;
      First : out Byte_Index;
      Last  : out Byte_Index) return Boolean
   is
   begin
      Group := Item.Share_Group;
      First := Item.Share_Body.First;
      Last := Item.Share_Body.Last;
      return Item.Has_Share;
   end Server_Key_Share;

   function Retry_Group
     (Item  : Server_Hello_Message;
      Group : out Groups.Named_Group) return Boolean
   is
   begin
      Group := Item.Share_Group;
      return Item.Has_Retry_Group;
   end Retry_Group;

   function Cookie_Span
     (Item  : Server_Hello_Message;
      First : out Byte_Index;
      Last  : out Byte_Index) return Boolean
   is
   begin
      First := Item.Cookie.First;
      Last := Item.Cookie.Last;
      return Item.Cookie.Present;
   end Cookie_Span;

   function Selected_Identity
     (Item  : Server_Hello_Message;
      Index : out Natural) return Boolean
   is
   begin
      Index := Item.Identity;
      return Item.Has_Identity;
   end Selected_Identity;

   procedure Parse_Server_Hello
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out Server_Hello_Message;
      Error  : out SSL.Errors.Error_Information;
      Legacy : Boolean := False)
   is
      Cursor : SSL.Wire.Cursor;
      Value  : Natural;
      Length : Natural;
      Block  : SSL.Wire.Cursor;
      Reset  : Server_Hello_Message;
      Context : Ext.Message_Context;
   begin
      Item := Reset;
      Error := SSL.Errors.No_Error;

      --  The declared body length must match the octets supplied.
      --
      --  In the assembled protocol the reassembly layer has already collected
      --  exactly this many octets, so this is a second opinion -- but a cheap
      --  one, and it makes the parser self-contained: handed a truncated
      --  message directly, it refuses rather than parsing whatever prefix
      --  happens to be well-formed. A prefix of a ClientHello that stops just
      --  before the extension block is a valid extensionless ClientHello, and
      --  without this check it would parse as one.
      declare
         Kind    : Message_Type;
         Value   : Type_Value;
         Declared : Byte_Index;
      begin
         Parse_Header (Data, Kind, Value, Declared, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;
         if Data'Length /= Header_Length + Declared then
            Error := SSL.Errors.Make
              (Code       => SSL.Errors.Code_Handshake_Message_Malformed,
               Origin     => SSL.Errors.Peer_Message,
               Parameters =>
                 [SSL.Errors.Numeric_Parameter ("declared", Long_Long_Integer (Declared)),
                  SSL.Errors.Numeric_Parameter
                    ("supplied", Long_Long_Integer (Data'Length - Header_Length))]);
            return;
         end if;
      end;

      Cursor := SSL.Wire.Reader (Data'First + Header_Length, Data'Last);

      SSL.Wire.Get_UInt16 (Data, Cursor, Value);
      Item.Legacy := SSL.Versions.Version_Value (Value);

      SSL.Wire.Get_Bytes (Data, Cursor, Item.Random_Value);

      --  RFC 8446 section 4.1.3: a ServerHello whose random is exactly the
      --  specified constant is a HelloRetryRequest. There is no other signal,
      --  and the two messages differ in which extensions they may carry, so the
      --  extension context depends on this test.
      Item.Retry := Item.Random_Value = Retry_Random;
      Context :=
        (if Item.Retry then Ext.In_Hello_Retry_Request
         elsif Legacy then Ext.In_Legacy_Server_Hello
         else Ext.In_Server_Hello);

      SSL.Wire.Get_UInt8 (Data, Cursor, Length);
      if Length > Natural (Maximum_Session_Id_Length) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Legacy_Session_Id_Mismatch, SSL.Errors.Peer_Message);
         return;
      end if;
      Item.Id_Length := Byte_Index (Length);
      SSL.Wire.Get_Bytes (Data, Cursor, Item.Id_Value (1 .. Item.Id_Length));

      SSL.Wire.Get_UInt16 (Data, Cursor, Value);
      if not Suites.Suite_For (Suites.Suite_Value (Value), Item.Suite) then
         --  A server selecting a suite this library does not implement cannot
         --  have selected one that was offered, so this is the same failure as
         --  selecting an unoffered suite.
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Selected_Suite_Not_Offered,
            Origin     => SSL.Errors.Peer_Message,
            Parameters =>
              [SSL.Errors.Text_Parameter
                 ("suite", Suites.Image (Suites.Suite_Value (Value)))]);
         return;
      end if;

      --  The compression method. TLS 1.3 fixes it at null and the restricted
      --  TLS 1.2 accepts nothing else.
      SSL.Wire.Get_UInt8 (Data, Cursor, Value);
      if not SSL.Wire.Is_Valid (Cursor) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;
      if Value /= 0 then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Legacy_Compression_Offered, SSL.Errors.Peer_Message);
         return;
      end if;

      if SSL.Wire.At_End (Cursor) then
         --  A TLS 1.2 ServerHello may carry no extensions at all.
         return;
      end if;

      Ext.Open_Block (Data, Cursor, Bounds, Block, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      loop
         declare
            Kind      : Ext.Extension_Kind;
            Number    : Ext.Extension_Value;
            Body_Part : SSL.Wire.Cursor;
            Present   : Boolean;
            First     : Byte_Index;
            Last      : Byte_Index;
         begin
            Ext.Next (Data, Block, Context, Bounds, Item.Seen,
                      Kind, Number, Body_Part, Present, Error);
            exit when SSL.Errors.Is_Error (Error) or else not Present;

            case Kind is
               when Ext.Supported_Versions =>
                  --  In a ServerHello this is a single version, not a list.
                  SSL.Wire.Get_UInt16 (Data, Body_Part, Value);
                  if SSL.Wire.Is_Valid (Body_Part) then
                     Item.Version := SSL.Versions.Version_Value (Value);
                  else
                     Error := SSL.Errors.Make
                       (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
                  end if;

               when Ext.Key_Share =>
                  declare
                     Named : Groups.Named_Group;
                  begin
                     SSL.Wire.Get_UInt16 (Data, Body_Part, Value);
                     if not Groups.Group_For (Groups.Group_Value (Value), Named) then
                        Error := SSL.Errors.Make
                          (Code       => SSL.Errors.Code_Selected_Group_Not_Offered,
                           Origin     => SSL.Errors.Peer_Message,
                           Parameters =>
                             [SSL.Errors.Text_Parameter
                                ("group", Groups.Image (Groups.Group_Value (Value)))]);
                     elsif Item.Retry then
                        --  A HelloRetryRequest carries a bare group and no
                        --  share; a ServerHello carries a share. Which of the
                        --  two arrived is the whole meaning of the message.
                        Item.Share_Group := Named;
                        Item.Has_Retry_Group := True;
                        if not SSL.Wire.At_End (Body_Part) then
                           Error := SSL.Errors.Make
                             (SSL.Errors.Code_Hello_Retry_Invariant_Broken,
                              SSL.Errors.Peer_Message);
                        end if;
                     else
                        SSL.Wire.Get_UInt16 (Data, Body_Part, Length);
                        SSL.Wire.Get_Span (Data, Body_Part, Byte_Index (Length), First, Last);
                        if not SSL.Wire.Is_Valid (Body_Part)
                          or else Byte_Index (Length) /= Groups.Share_Length (Named)
                        then
                           Error := SSL.Errors.Make
                             (SSL.Errors.Code_Key_Exchange_Value_Invalid,
                              SSL.Errors.Peer_Message);
                        else
                           Item.Has_Share := True;
                           Item.Share_Group := Named;
                           Item.Share_Body :=
                             (Present => True, First => First, Last => Last);
                        end if;
                     end if;
                  end;

               when Ext.Cookie =>
                  declare
                     Inner : SSL.Wire.Cursor;
                  begin
                     SSL.Wire.Open_Vector_16
                       (Data, Body_Part, Byte_Index (Bounds.Maximum_Cookie_Length), Inner);
                     if not SSL.Wire.Is_Valid (Body_Part) then
                        Error := SSL.Errors.Make
                          (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
                     else
                        SSL.Wire.Get_Span
                          (Data, Inner, SSL.Wire.Remaining (Inner), First, Last);
                        Item.Cookie := (Present => True, First => First, Last => Last);
                     end if;
                  end;

               when Ext.Pre_Shared_Key =>
                  SSL.Wire.Get_UInt16 (Data, Body_Part, Value);
                  if SSL.Wire.Is_Valid (Body_Part) then
                     Item.Has_Identity := True;
                     Item.Identity := Value;
                  else
                     Error := SSL.Errors.Make
                       (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
                  end if;

               when others =>
                  null;
            end case;

            exit when SSL.Errors.Is_Error (Error);
         end;
      end loop;
   end Parse_Server_Hello;

   ---------------------------------------------------------------------------
   --  Framing shared by the messages below
   ---------------------------------------------------------------------------

   --  Check the header, that it names the expected message, and that the
   --  declared body length equals the octets supplied; then position a cursor
   --  at the body.
   --
   --  Every parser below starts here, so that none of them can be reached with a
   --  message of another type or a truncated one. The type check is not
   --  redundant with the caller's dispatch: it makes each parser correct on its
   --  own, which is what a test can then rely on.
   procedure Begin_Message
     (Data   : Byte_Array;
      Expect : Message_Type;
      Cursor : out SSL.Wire.Cursor;
      Error  : out SSL.Errors.Error_Information);

   procedure Begin_Message
     (Data   : Byte_Array;
      Expect : Message_Type;
      Cursor : out SSL.Wire.Cursor;
      Error  : out SSL.Errors.Error_Information)
   is
      Kind     : Message_Type;
      Raw      : Type_Value;
      Declared : Byte_Index;
   begin
      Cursor := SSL.Wire.Reader (Empty_Bytes);
      Parse_Header (Data, Kind, Raw, Declared, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      if Kind /= Expect then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Unexpected_Handshake_Message,
            Origin     => SSL.Errors.Peer_Message,
            Parameters =>
              [SSL.Errors.Text_Parameter ("expected", Image (Expect)),
               SSL.Errors.Numeric_Parameter ("received", Long_Long_Integer (Raw))]);
         return;
      end if;

      if Data'Length /= Header_Length + Declared then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Handshake_Message_Malformed,
            Origin     => SSL.Errors.Peer_Message,
            Parameters =>
              [SSL.Errors.Numeric_Parameter ("declared", Long_Long_Integer (Declared)),
               SSL.Errors.Numeric_Parameter
                 ("supplied", Long_Long_Integer (Data'Length - Header_Length))]);
         return;
      end if;

      Cursor := SSL.Wire.Reader (Data'First + Header_Length, Data'Last);
   end Begin_Message;

   --  The failure a cursor that ran out of octets produces. One place, so that
   --  every parser below reports a short message the same way.
   function Short_Message return SSL.Errors.Error_Information is
     (SSL.Errors.Make
        (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message));

   --  Finish an encoder: back-patch the body length, or report that the buffer
   --  was too small and emit nothing at all.
   --
   --  Nothing partial is ever emitted. A truncated handshake message is one the
   --  transcript would hash and the peer could not parse, and the two ends would
   --  then disagree about the transcript with no way to find out why.
   procedure Finish_Message
     (Into      : in out Byte_Array;
      Emitter   : in out SSL.Wire.Emitter;
      Body_Mark : Byte_Index;
      Written   : out Byte_Index;
      Error     : out SSL.Errors.Error_Information);

   procedure Finish_Message
     (Into      : in out Byte_Array;
      Emitter   : in out SSL.Wire.Emitter;
      Body_Mark : Byte_Index;
      Written   : out Byte_Index;
      Error     : out SSL.Errors.Error_Information)
   is
   begin
      SSL.Wire.Close_Vector_24 (Into, Emitter, Body_Mark);

      if not SSL.Wire.Is_Valid (Emitter) then
         if Into'Length > 0 then
            Into := [others => 0];
         end if;
         Written := 0;
         Error := SSL.Errors.Make
           (Code   => SSL.Errors.Code_Handshake_Message_Malformed,
            Origin => SSL.Errors.Local_Implementation);
         return;
      end if;

      Written := SSL.Wire.Written (Emitter);
      Error := SSL.Errors.No_Error;
   end Finish_Message;

   --  Open an encoder on a message of a given type, with the body length
   --  prefix reserved.
   procedure Begin_Encoding
     (Kind      : Message_Type;
      Into      : out Byte_Array;
      Emitter   : out SSL.Wire.Emitter;
      Body_Mark : out Byte_Index);

   procedure Begin_Encoding
     (Kind      : Message_Type;
      Into      : out Byte_Array;
      Emitter   : out SSL.Wire.Emitter;
      Body_Mark : out Byte_Index)
   is
   begin
      if Into'Length > 0 then
         Into := [others => 0];
      end if;
      Emitter := SSL.Wire.Writer (Into);
      SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Value_Of (Kind)));
      SSL.Wire.Open_Vector_24 (Into, Emitter, Body_Mark);
   end Begin_Encoding;

   ---------------------------------------------------------------------------
   --  ServerHello and HelloRetryRequest encoding
   ---------------------------------------------------------------------------

   --  The fields the two share, up to and including the compression method.
   procedure Put_Hello_Preamble
     (Into         : in out Byte_Array;
      Emitter      : in out SSL.Wire.Emitter;
      Random_Value : Random_Bytes;
      Session_Id   : Byte_Array;
      Suite        : SSL.Cipher_Suites.Cipher_Suite);

   procedure Put_Hello_Preamble
     (Into         : in out Byte_Array;
      Emitter      : in out SSL.Wire.Emitter;
      Random_Value : Random_Bytes;
      Session_Id   : Byte_Array;
      Suite        : SSL.Cipher_Suites.Cipher_Suite)
   is
   begin
      SSL.Wire.Put_UInt16 (Into, Emitter, Natural (SSL.Versions.Legacy_Record_Value));
      SSL.Wire.Put_Bytes (Into, Emitter, Random_Value);
      SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Session_Id'Length));
      SSL.Wire.Put_Bytes (Into, Emitter, Session_Id);
      SSL.Wire.Put_UInt16 (Into, Emitter, Natural (Suites.Value_Of (Suite)));
      SSL.Wire.Put_UInt8 (Into, Emitter, 0);          --  null compression
   end Put_Hello_Preamble;

   procedure Encode_Server_Hello
     (Random_Value : Random_Bytes;
      Session_Id   : Byte_Array;
      Suite        : SSL.Cipher_Suites.Cipher_Suite;
      Share_Group  : SSL.Supported_Groups.Named_Group;
      Share_Value  : Byte_Array;
      Has_Identity : Boolean;
      Identity     : Natural;
      Into         : out Byte_Array;
      Written      : out Byte_Index;
      Error        : out SSL.Errors.Error_Information)
   is
      Emitter    : SSL.Wire.Emitter;
      Body_Mark  : Byte_Index;
      Block_Mark : Byte_Index;
      Ext_Mark   : Byte_Index;
      Inner      : Byte_Index;
   begin
      Written := 0;
      Error := SSL.Errors.No_Error;

      if Random_Value = Retry_Random then
         --  A ServerHello whose random is the retry constant is a
         --  HelloRetryRequest to every conforming peer, whatever this endpoint
         --  meant by it. Refusing here rather than sending it means the mistake
         --  is a local failure with a name, not a handshake that goes wrong two
         --  messages later.
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Internal_Invariant_Violated, SSL.Errors.Local_Implementation);
         return;
      end if;

      Begin_Encoding (Server_Hello, Into, Emitter, Body_Mark);
      Put_Hello_Preamble (Into, Emitter, Random_Value, Session_Id, Suite);

      SSL.Extensions.Open_Block (Into, Emitter, Block_Mark);

      --  supported_versions, which is what actually selects the protocol: the
      --  legacy_version field above says 1.2 in every TLS 1.3 ServerHello.
      SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Supported_Versions, Ext_Mark);
      SSL.Wire.Put_UInt16 (Into, Emitter, Natural (SSL.Versions.TLS_1_3_Value));
      SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);

      if Share_Value'Length > 0 then
         SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Key_Share, Ext_Mark);
         SSL.Wire.Put_UInt16 (Into, Emitter, Natural (Groups.Value_Of (Share_Group)));
         SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
         SSL.Wire.Put_Bytes (Into, Emitter, Share_Value);
         SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
      end if;

      if Has_Identity then
         SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Pre_Shared_Key, Ext_Mark);
         SSL.Wire.Put_UInt16 (Into, Emitter, Identity);
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
      end if;

      SSL.Extensions.Close_Block (Into, Emitter, Block_Mark);
      Finish_Message (Into, Emitter, Body_Mark, Written, Error);
   end Encode_Server_Hello;

   procedure Encode_Hello_Retry_Request
     (Session_Id : Byte_Array;
      Suite      : SSL.Cipher_Suites.Cipher_Suite;
      Group      : SSL.Supported_Groups.Named_Group;
      Cookie     : Byte_Array;
      Into       : out Byte_Array;
      Written    : out Byte_Index;
      Error      : out SSL.Errors.Error_Information)
   is
      Emitter    : SSL.Wire.Emitter;
      Body_Mark  : Byte_Index;
      Block_Mark : Byte_Index;
      Ext_Mark   : Byte_Index;
      Inner      : Byte_Index;
   begin
      Written := 0;
      Error := SSL.Errors.No_Error;

      Begin_Encoding (Server_Hello, Into, Emitter, Body_Mark);
      Put_Hello_Preamble (Into, Emitter, Retry_Random, Session_Id, Suite);

      SSL.Extensions.Open_Block (Into, Emitter, Block_Mark);

      SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Supported_Versions, Ext_Mark);
      SSL.Wire.Put_UInt16 (Into, Emitter, Natural (SSL.Versions.TLS_1_3_Value));
      SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);

      --  A bare group and no share behind it. That is what makes this key_share
      --  a request rather than an answer, and it is the only form permitted
      --  here.
      SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Key_Share, Ext_Mark);
      SSL.Wire.Put_UInt16 (Into, Emitter, Natural (Groups.Value_Of (Group)));
      SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);

      if Cookie'Length > 0 then
         SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Cookie, Ext_Mark);
         SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
         SSL.Wire.Put_Bytes (Into, Emitter, Cookie);
         SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
      end if;

      SSL.Extensions.Close_Block (Into, Emitter, Block_Mark);
      Finish_Message (Into, Emitter, Body_Mark, Written, Error);
   end Encode_Hello_Retry_Request;

   ---------------------------------------------------------------------------
   --  EncryptedExtensions
   ---------------------------------------------------------------------------

   function Extensions_Seen (Item : Encrypted_Extensions_Message) return SSL.Extensions.Seen_Set is
     (Item.Seen);

   function Selected_Protocol
     (Item     : Encrypted_Extensions_Message;
      Protocol : out SSL.ALPN.Protocol_Name) return Boolean
   is
   begin
      Protocol := Item.Protocol;
      return Item.Has_Protocol;
   end Selected_Protocol;

   function Requested_Record_Limit (Item : Encrypted_Extensions_Message) return Byte_Index is
     (Item.Record_Limit);

   function Acknowledged_Server_Name (Item : Encrypted_Extensions_Message) return Boolean is
     (Item.Name_Acked);

   function Offered_Groups
     (Item : Encrypted_Extensions_Message) return SSL.Supported_Groups.Group_List
   is (Item.Groups);

   procedure Parse_Encrypted_Extensions
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out Encrypted_Extensions_Message;
      Error  : out SSL.Errors.Error_Information)
   is
      Cursor  : SSL.Wire.Cursor;
      Block   : SSL.Wire.Cursor;
      Reset   : Encrypted_Extensions_Message;
      Kind    : Ext.Extension_Kind;
      Value   : Ext.Extension_Value;
      Part    : SSL.Wire.Cursor;
      Present : Boolean;
   begin
      Item := Reset;
      Begin_Message (Data, Encrypted_Extensions, Cursor, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      Ext.Open_Block (Data, Cursor, Bounds, Block, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      loop
         Ext.Next (Data, Block, Ext.In_Encrypted_Extensions, Bounds, Item.Seen,
                   Kind, Value, Part, Present, Error);
         exit when SSL.Errors.Is_Error (Error) or else not Present;

         case Kind is
            when Ext.Application_Layer_Protocol_Negotiation =>
               --  Exactly one protocol. RFC 7301 section 3.1 says the server's
               --  list is one entry, and a list of two would leave the selection
               --  ambiguous at the moment it is supposed to be settled.
               declare
                  List  : SSL.Wire.Cursor;
                  Name  : SSL.Wire.Cursor;
                  First : Byte_Index;
                  Last  : Byte_Index;
                  Ok    : Boolean;
               begin
                  SSL.Wire.Open_Vector_16
                    (Data, Part, Byte_Index (Bounds.Maximum_Extension_Body), List);
                  SSL.Wire.Open_Vector_8 (Data, List, 255, Name);
                  SSL.Wire.Get_Span (Data, Name, SSL.Wire.Remaining (Name), First, Last);
                  if not SSL.Wire.Is_Valid (Name) or else not SSL.Wire.At_End (List) then
                     Error := SSL.Errors.Make
                       (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
                     return;
                  end if;
                  Ok := SSL.ALPN.Make (Data (First .. Last), Item.Protocol);
                  if not Ok then
                     Error := SSL.Errors.Make
                       (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
                     return;
                  end if;
                  Item.Has_Protocol := True;
               end;

            when Ext.Record_Size_Limit =>
               declare
                  Limit : Natural;
               begin
                  SSL.Wire.Get_UInt16 (Data, Part, Limit);
                  if not SSL.Wire.Is_Valid (Part) or else not SSL.Wire.At_End (Part) then
                     Error := SSL.Errors.Make
                       (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
                     return;
                  end if;
                  --  RFC 8449 section 4: below 64 is not a limit, it is a
                  --  malformed extension, because the smallest useful record
                  --  cannot fit.
                  if Limit < 64 then
                     Error := SSL.Errors.Make
                       (SSL.Errors.Code_Record_Size_Limit_Exceeded, SSL.Errors.Peer_Message);
                     return;
                  end if;
                  Item.Record_Limit := Byte_Index (Limit);
               end;

            when Ext.Server_Name =>
               --  RFC 6066 section 3: the server's acknowledgement is an empty
               --  extension. Anything in it is malformed.
               if not SSL.Wire.At_End (Part) then
                  Error := SSL.Errors.Make
                    (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
                  return;
               end if;
               Item.Name_Acked := True;

            when Ext.Supported_Groups =>
               declare
                  List  : SSL.Wire.Cursor;
                  Raw   : Natural;
                  Named : Groups.Named_Group;
                  Ok    : Boolean;
               begin
                  SSL.Wire.Open_Vector_16
                    (Data, Part, Byte_Index (Bounds.Maximum_Extension_Body), List);
                  while SSL.Wire.Is_Valid (List) and then not SSL.Wire.At_End (List) loop
                     SSL.Wire.Get_UInt16 (Data, List, Raw);
                     exit when not SSL.Wire.Is_Valid (List);
                     if Groups.Group_For (Groups.Group_Value (Raw), Named) then
                        Groups.Append (Item.Groups, Named, Ok);
                     end if;
                  end loop;
                  if not SSL.Wire.Is_Valid (List) then
                     Error := SSL.Errors.Make
                       (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
                     return;
                  end if;
               end;

            when Ext.Early_Data =>
               --  Refused rather than ignored: accepting it here would say this
               --  endpoint had offered early data, which it never does.
               Error := SSL.Errors.Make
                 (SSL.Errors.Code_Early_Data_Offered, SSL.Errors.Peer_Message);
               return;

            when others =>
               --  Recorded by Ext.Next and acted on nowhere. An extension the
               --  server sent here that this endpoint did not offer is
               --  unsolicited, which the state machine checks against what it
               --  actually offered -- a check this parser cannot make, because
               --  it has no ClientHello.
               null;
         end case;
      end loop;

      if SSL.Errors.Is_Error (Error) then
         Item := Reset;
      end if;
   end Parse_Encrypted_Extensions;

   procedure Encode_Encrypted_Extensions
     (Protocol         : SSL.ALPN.Protocol_Name;
      Has_Protocol     : Boolean;
      Record_Limit     : Byte_Index;
      Acknowledge_Name : Boolean;
      Into             : out Byte_Array;
      Written          : out Byte_Index;
      Error            : out SSL.Errors.Error_Information)
   is
      Emitter    : SSL.Wire.Emitter;
      Body_Mark  : Byte_Index;
      Block_Mark : Byte_Index;
      Ext_Mark   : Byte_Index;
      Inner      : Byte_Index;
   begin
      Written := 0;
      Error := SSL.Errors.No_Error;

      Begin_Encoding (Encrypted_Extensions, Into, Emitter, Body_Mark);
      SSL.Extensions.Open_Block (Into, Emitter, Block_Mark);

      if Acknowledge_Name then
         SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Server_Name, Ext_Mark);
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
      end if;

      if Has_Protocol then
         declare
            Name : constant Byte_Array := SSL.ALPN.Value_Of (Protocol);
         begin
            SSL.Extensions.Open_Extension
              (Into, Emitter, SSL.Extensions.Application_Layer_Protocol_Negotiation, Ext_Mark);
            SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
            SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Name'Length));
            SSL.Wire.Put_Bytes (Into, Emitter, Name);
            SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
            SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
         end;
      end if;

      if Record_Limit > 0 then
         SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Record_Size_Limit, Ext_Mark);
         SSL.Wire.Put_UInt16 (Into, Emitter, Natural (Record_Limit));
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
      end if;

      SSL.Extensions.Close_Block (Into, Emitter, Block_Mark);
      Finish_Message (Into, Emitter, Body_Mark, Written, Error);
   end Encode_Encrypted_Extensions;

   ---------------------------------------------------------------------------
   --  Certificate
   ---------------------------------------------------------------------------

   function Request_Context_Span
     (Item  : Certificate_Message;
      First : out Byte_Index;
      Last  : out Byte_Index) return Boolean
   is
   begin
      First := Item.Context.First;
      Last := Item.Context.Last;
      return Item.Context.Present;
   end Request_Context_Span;

   function Entry_Count (Item : Certificate_Message) return Natural is (Item.Count);

   procedure Entry_Span
     (Item  : Certificate_Message;
      Index : Positive;
      First : out Byte_Index;
      Last  : out Byte_Index)
   is
   begin
      First := Item.Entries (Index).Body_Span.First;
      Last := Item.Entries (Index).Body_Span.Last;
   end Entry_Span;

   function Entry_Status_Span
     (Item  : Certificate_Message;
      Index : Positive;
      First : out Byte_Index;
      Last  : out Byte_Index) return Boolean
   is
   begin
      First := Item.Entries (Index).Status_Span.First;
      Last := Item.Entries (Index).Status_Span.Last;
      return Item.Entries (Index).Status_Span.Present;
   end Entry_Status_Span;

   procedure Parse_Certificate
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out Certificate_Message;
      Error  : out SSL.Errors.Error_Information)
   is
      Cursor  : SSL.Wire.Cursor;
      List    : SSL.Wire.Cursor;
      Context : SSL.Wire.Cursor;
      Reset   : Certificate_Message;
      Allowed : constant Natural :=
        Natural'Min (Bounds.Maximum_Certificate_Count, Maximum_Chain_Entries);
   begin
      Item := Reset;
      Begin_Message (Data, Certificate, Cursor, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      --  certificate_request_context. A server's is empty; a client's echoes
      --  the request. Kept as a span so the state machine can compare it against
      --  what it sent without this parser knowing which role it is in.
      SSL.Wire.Open_Vector_8 (Data, Cursor, 255, Context);
      if not SSL.Wire.Is_Valid (Context) then
         Error := Short_Message;
         return;
      end if;
      SSL.Wire.Get_Span
        (Data, Context, SSL.Wire.Remaining (Context),
         Item.Context.First, Item.Context.Last);
      Item.Context.Present := True;

      SSL.Wire.Open_Vector_24
        (Data, Cursor, Byte_Index (Bounds.Maximum_Certificate_Message), List);
      if not SSL.Wire.Is_Valid (List) then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Limit_Exceeded,
            Origin     => SSL.Errors.Peer_Message,
            Parameters =>
              [SSL.Errors.Text_Parameter ("limit", "maximum certificate message")]);
         return;
      end if;

      while SSL.Wire.Is_Valid (List) and then not SSL.Wire.At_End (List) loop
         declare
            Der     : SSL.Wire.Cursor;
            Block   : SSL.Wire.Cursor;
            Seen    : Ext.Seen_Set := Ext.Empty_Set;
            Kind    : Ext.Extension_Kind;
            Value   : Ext.Extension_Value;
            Part    : SSL.Wire.Cursor;
            Present : Boolean;
            Index   : Natural;
         begin
            if Item.Count = Allowed then
               --  One certificate past the bound, refused before its length is
               --  used for anything. A chain longer than the configured depth
               --  cannot validate, so reading the rest would be work done for a
               --  message that is already going to be rejected.
               Error := SSL.Errors.Make
                 (Code       => SSL.Errors.Code_Limit_Exceeded,
                  Origin     => SSL.Errors.Peer_Message,
                  Parameters =>
                    [SSL.Errors.Text_Parameter ("limit", "maximum certificate count"),
                     SSL.Errors.Numeric_Parameter ("permitted", Long_Long_Integer (Allowed))]);
               return;
            end if;

            SSL.Wire.Open_Vector_24
              (Data, List, Byte_Index (Bounds.Maximum_Certificate), Der);
            if not SSL.Wire.Is_Valid (Der) then
               Error := SSL.Errors.Make
                 (Code       => SSL.Errors.Code_Limit_Exceeded,
                  Origin     => SSL.Errors.Peer_Message,
                  Parameters =>
                    [SSL.Errors.Text_Parameter ("limit", "maximum certificate")]);
               return;
            end if;
            if SSL.Wire.Remaining (Der) = 0 then
               --  A zero-length entry. cryptolib would refuse it, but refusing
               --  it here keeps an empty span from reaching a DER parser at all.
               Error := SSL.Errors.Make
                 (SSL.Errors.Code_Certificate_Malformed, SSL.Errors.Peer_Message);
               return;
            end if;

            Item.Count := Item.Count + 1;
            Index := Item.Count;
            SSL.Wire.Get_Span
              (Data, Der, SSL.Wire.Remaining (Der),
               Item.Entries (Index).Body_Span.First,
               Item.Entries (Index).Body_Span.Last);
            Item.Entries (Index).Body_Span.Present := True;

            --  Per-entry extensions. TLS 1.3 moved the OCSP staple in here, so
            --  every certificate may carry its own status rather than one being
            --  attached to the message as a whole.
            Ext.Open_Block (Data, List, Bounds, Block, Error);
            if SSL.Errors.Is_Error (Error) then
               return;
            end if;

            loop
               Ext.Next (Data, Block, Ext.In_Certificate, Bounds, Seen,
                         Kind, Value, Part, Present, Error);
               exit when SSL.Errors.Is_Error (Error) or else not Present;

               if Kind = Ext.Status_Request then
                  declare
                     Status : SSL.Wire.Cursor;
                     Kind_Octet : Natural;
                  begin
                     SSL.Wire.Get_UInt8 (Data, Part, Kind_Octet);
                     if not SSL.Wire.Is_Valid (Part) or else Kind_Octet /= 1 then
                        Error := SSL.Errors.Make
                          (SSL.Errors.Code_Stapled_Status_Malformed, SSL.Errors.Peer_Message);
                        return;
                     end if;
                     SSL.Wire.Open_Vector_24
                       (Data, Part, Byte_Index (Bounds.Maximum_OCSP_Response), Status);
                     if not SSL.Wire.Is_Valid (Status)
                       or else SSL.Wire.Remaining (Status) = 0
                     then
                        Error := SSL.Errors.Make
                          (SSL.Errors.Code_Stapled_Status_Malformed, SSL.Errors.Peer_Message);
                        return;
                     end if;
                     SSL.Wire.Get_Span
                       (Data, Status, SSL.Wire.Remaining (Status),
                        Item.Entries (Index).Status_Span.First,
                        Item.Entries (Index).Status_Span.Last);
                     Item.Entries (Index).Status_Span.Present := True;
                  end;
               end if;
            end loop;

            if SSL.Errors.Is_Error (Error) then
               return;
            end if;
         end;
      end loop;

      if not SSL.Wire.Is_Valid (List) or else not SSL.Wire.At_End (Cursor) then
         Error := Short_Message;
         Item := Reset;
      end if;
   end Parse_Certificate;

   procedure Encode_Certificate
     (Chain   : Byte_Array;
      Spans   : Certificate_Span_List;
      Count   : Natural;
      Context : Byte_Array;
      Staple  : Byte_Array;
      Into    : out Byte_Array;
      Written : out Byte_Index;
      Error   : out SSL.Errors.Error_Information)
   is
      Emitter   : SSL.Wire.Emitter;
      Body_Mark : Byte_Index;
      List_Mark : Byte_Index;
      Der_Mark  : Byte_Index;
      Block     : Byte_Index;
      Ext_Mark  : Byte_Index;
      Inner     : Byte_Index;
   begin
      Written := 0;
      Error := SSL.Errors.No_Error;

      Begin_Encoding (Certificate, Into, Emitter, Body_Mark);

      SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Context'Length));
      SSL.Wire.Put_Bytes (Into, Emitter, Context);

      SSL.Wire.Open_Vector_24 (Into, Emitter, List_Mark);
      for Index in 1 .. Count loop
         SSL.Wire.Open_Vector_24 (Into, Emitter, Der_Mark);
         SSL.Wire.Put_Bytes
           (Into, Emitter, Chain (Spans (Index).First .. Spans (Index).Last));
         SSL.Wire.Close_Vector_24 (Into, Emitter, Der_Mark);

         --  The staple goes on the leaf and nowhere else. A responder's answer
         --  is about one certificate, and attaching the leaf's answer to an
         --  intermediate would be a claim nobody made.
         SSL.Extensions.Open_Block (Into, Emitter, Block);
         if Index = 1 and then Staple'Length > 0 then
            SSL.Extensions.Open_Extension (Into, Emitter, SSL.Extensions.Status_Request, Ext_Mark);
            SSL.Wire.Put_UInt8 (Into, Emitter, 1);          --  ocsp
            SSL.Wire.Open_Vector_24 (Into, Emitter, Inner);
            SSL.Wire.Put_Bytes (Into, Emitter, Staple);
            SSL.Wire.Close_Vector_24 (Into, Emitter, Inner);
            SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
         end if;
         SSL.Extensions.Close_Block (Into, Emitter, Block);
      end loop;
      SSL.Wire.Close_Vector_24 (Into, Emitter, List_Mark);

      Finish_Message (Into, Emitter, Body_Mark, Written, Error);
   end Encode_Certificate;

   ---------------------------------------------------------------------------
   --  CertificateRequest
   ---------------------------------------------------------------------------

   function Request_Context_Span
     (Item  : Certificate_Request_Message;
      First : out Byte_Index;
      Last  : out Byte_Index) return Boolean
   is
   begin
      First := Item.Context.First;
      Last := Item.Context.Last;
      return Item.Context.Present;
   end Request_Context_Span;

   function Offered_Schemes
     (Item : Certificate_Request_Message) return SSL.Signature_Schemes.Scheme_List
   is (Item.Schemes);

   function Offered_Certificate_Schemes
     (Item : Certificate_Request_Message) return SSL.Signature_Schemes.Scheme_List
   is (Item.Certificate_Schemes);

   function Extensions_Seen (Item : Certificate_Request_Message) return SSL.Extensions.Seen_Set is
     (Item.Seen);

   function Has_Certificate_Authorities (Item : Certificate_Request_Message) return Boolean is
     (Item.Authorities);

   --  A signature_algorithms-shaped extension body: a two-octet-prefixed list of
   --  two-octet scheme identifiers. Two extensions carry exactly this, and one
   --  reader for both is one place for the bound to be applied.
   procedure Read_Scheme_List
     (Data   : Byte_Array;
      Part   : in out SSL.Wire.Cursor;
      Bounds : SSL.Limits.Resource_Limits;
      Into   : out Schemes.Scheme_List;
      Ok     : out Boolean);

   procedure Read_Scheme_List
     (Data   : Byte_Array;
      Part   : in out SSL.Wire.Cursor;
      Bounds : SSL.Limits.Resource_Limits;
      Into   : out Schemes.Scheme_List;
      Ok     : out Boolean)
   is
      List   : SSL.Wire.Cursor;
      Raw    : Natural;
      Named  : Schemes.Signature_Scheme;
      Placed : Boolean;
   begin
      Into := Schemes.No_Schemes;
      SSL.Wire.Open_Vector_16 (Data, Part, Byte_Index (Bounds.Maximum_Extension_Body), List);

      while SSL.Wire.Is_Valid (List) and then not SSL.Wire.At_End (List) loop
         SSL.Wire.Get_UInt16 (Data, List, Raw);
         exit when not SSL.Wire.Is_Valid (List);
         --  A scheme this library does not implement is not in the intersection,
         --  so it is skipped rather than refused.
         if Schemes.Scheme_For (Schemes.Scheme_Value (Raw), Named) then
            Schemes.Append (Into, Named, Placed);
         end if;
      end loop;

      Ok := SSL.Wire.Is_Valid (List) and then SSL.Wire.At_End (Part);
      if not Ok then
         Into := Schemes.No_Schemes;
      end if;
   end Read_Scheme_List;

   procedure Parse_Certificate_Request
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out Certificate_Request_Message;
      Error  : out SSL.Errors.Error_Information)
   is
      Cursor  : SSL.Wire.Cursor;
      Context : SSL.Wire.Cursor;
      Block   : SSL.Wire.Cursor;
      Reset   : Certificate_Request_Message;
      Kind    : Ext.Extension_Kind;
      Value   : Ext.Extension_Value;
      Part    : SSL.Wire.Cursor;
      Present : Boolean;
      Ok      : Boolean;
   begin
      Item := Reset;
      Begin_Message (Data, Certificate_Request, Cursor, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Wire.Open_Vector_8 (Data, Cursor, 255, Context);
      if not SSL.Wire.Is_Valid (Context) then
         Error := Short_Message;
         return;
      end if;
      SSL.Wire.Get_Span
        (Data, Context, SSL.Wire.Remaining (Context),
         Item.Context.First, Item.Context.Last);
      Item.Context.Present := True;

      Ext.Open_Block (Data, Cursor, Bounds, Block, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      loop
         Ext.Next (Data, Block, Ext.In_Certificate_Request, Bounds, Item.Seen,
                   Kind, Value, Part, Present, Error);
         exit when SSL.Errors.Is_Error (Error) or else not Present;

         case Kind is
            when Ext.Signature_Algorithms =>
               Read_Scheme_List (Data, Part, Bounds, Item.Schemes, Ok);
               if not Ok then
                  Error := SSL.Errors.Make
                    (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
                  return;
               end if;

            when Ext.Signature_Algorithms_Cert =>
               Read_Scheme_List (Data, Part, Bounds, Item.Certificate_Schemes, Ok);
               if not Ok then
                  Error := SSL.Errors.Make
                    (SSL.Errors.Code_Extension_Malformed, SSL.Errors.Peer_Message);
                  return;
               end if;

            when Ext.Certificate_Authorities =>
               --  Recorded as present and not decoded. The contents are DER
               --  distinguished names, and decoding DER in this library is the
               --  boundary violation the architecture exists to prevent.
               Item.Authorities := True;

            when others =>
               null;
         end case;
      end loop;

      if SSL.Errors.Is_Error (Error) then
         Item := Reset;
         return;
      end if;

      --  RFC 8446 section 4.3.2 makes signature_algorithms mandatory here. A
      --  request without it names no scheme a client could sign with, so there
      --  is no way to answer it.
      if not Ext.Contains (Item.Seen, Ext.Signature_Algorithms) then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Missing_Required_Extension,
            Origin     => SSL.Errors.Peer_Message,
            Parameters =>
              [SSL.Errors.Text_Parameter ("extension", "signature_algorithms")]);
         Item := Reset;
      end if;
   end Parse_Certificate_Request;

   procedure Encode_Certificate_Request
     (Context             : Byte_Array;
      Schemes             : SSL.Signature_Schemes.Scheme_List;
      Certificate_Schemes : SSL.Signature_Schemes.Scheme_List;
      Into                : out Byte_Array;
      Written             : out Byte_Index;
      Error               : out SSL.Errors.Error_Information)
   is
      package Scheme_Package renames SSL.Signature_Schemes;

      Emitter    : SSL.Wire.Emitter;
      Body_Mark  : Byte_Index;
      Block_Mark : Byte_Index;
      Ext_Mark   : Byte_Index;
      Inner      : Byte_Index;
   begin
      Written := 0;
      Error := SSL.Errors.No_Error;

      Begin_Encoding (Certificate_Request, Into, Emitter, Body_Mark);

      SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Context'Length));
      SSL.Wire.Put_Bytes (Into, Emitter, Context);

      SSL.Extensions.Open_Block (Into, Emitter, Block_Mark);

      SSL.Extensions.Open_Extension
        (Into, Emitter, SSL.Extensions.Signature_Algorithms, Ext_Mark);
      SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
      for Index in 1 .. Scheme_Package.Length (Schemes) loop
         SSL.Wire.Put_UInt16
           (Into, Emitter,
            Natural (Scheme_Package.Value_Of (Scheme_Package.Element (Schemes, Index))));
      end loop;
      SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
      SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);

      if not Scheme_Package.Is_Empty (Certificate_Schemes) then
         SSL.Extensions.Open_Extension
           (Into, Emitter, SSL.Extensions.Signature_Algorithms_Cert, Ext_Mark);
         SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
         for Index in 1 .. Scheme_Package.Length (Certificate_Schemes) loop
            SSL.Wire.Put_UInt16
              (Into, Emitter,
               Natural (Scheme_Package.Value_Of
                          (Scheme_Package.Element (Certificate_Schemes, Index))));
         end loop;
         SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
         SSL.Extensions.Close_Extension (Into, Emitter, Ext_Mark);
      end if;

      SSL.Extensions.Close_Block (Into, Emitter, Block_Mark);
      Finish_Message (Into, Emitter, Body_Mark, Written, Error);
   end Encode_Certificate_Request;

   ---------------------------------------------------------------------------
   --  CertificateVerify
   ---------------------------------------------------------------------------

   function Scheme
     (Item : Certificate_Verify_Message) return SSL.Signature_Schemes.Signature_Scheme
   is (Item.Named);

   function Scheme_Recognized (Item : Certificate_Verify_Message) return Boolean is
     (Item.Recognized);

   function Scheme_Value
     (Item : Certificate_Verify_Message) return SSL.Signature_Schemes.Scheme_Value
   is (Item.Raw);

   procedure Signature_Span
     (Item  : Certificate_Verify_Message;
      First : out Byte_Index;
      Last  : out Byte_Index)
   is
   begin
      First := Item.Signature.First;
      Last := Item.Signature.Last;
   end Signature_Span;

   procedure Parse_Certificate_Verify
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out Certificate_Verify_Message;
      Error  : out SSL.Errors.Error_Information)
   is
      pragma Unreferenced (Bounds);
      Cursor : SSL.Wire.Cursor;
      Sig    : SSL.Wire.Cursor;
      Reset  : Certificate_Verify_Message;
      Raw    : Natural;
   begin
      Item := Reset;
      Begin_Message (Data, Certificate_Verify, Cursor, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Wire.Get_UInt16 (Data, Cursor, Raw);
      if not SSL.Wire.Is_Valid (Cursor) then
         Error := Short_Message;
         return;
      end if;
      Item.Raw := Schemes.Scheme_Value (Raw);
      Item.Recognized := Schemes.Scheme_For (Item.Raw, Item.Named);

      --  A signature is bounded by the largest key this library will use, which
      --  is what Maximum_Signature_Length in SSL.Credentials states. Bounding it
      --  here as a 16-bit vector is the wire's own bound; the state machine
      --  applies the tighter one when it knows the key.
      SSL.Wire.Open_Vector_16 (Data, Cursor, 65_535, Sig);
      if not SSL.Wire.Is_Valid (Sig) or else SSL.Wire.Remaining (Sig) = 0 then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message);
         Item := Reset;
         return;
      end if;
      SSL.Wire.Get_Span
        (Data, Sig, SSL.Wire.Remaining (Sig),
         Item.Signature.First, Item.Signature.Last);
      Item.Signature.Present := True;

      if not SSL.Wire.At_End (Cursor) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Message_Malformed, SSL.Errors.Peer_Message);
         Item := Reset;
      end if;
   end Parse_Certificate_Verify;

   procedure Encode_Certificate_Verify
     (Scheme    : SSL.Signature_Schemes.Signature_Scheme;
      Signature : Byte_Array;
      Into      : out Byte_Array;
      Written   : out Byte_Index;
      Error     : out SSL.Errors.Error_Information)
   is
      Emitter   : SSL.Wire.Emitter;
      Body_Mark : Byte_Index;
      Inner     : Byte_Index;
   begin
      Written := 0;
      Error := SSL.Errors.No_Error;

      Begin_Encoding (Certificate_Verify, Into, Emitter, Body_Mark);
      SSL.Wire.Put_UInt16 (Into, Emitter, Natural (Schemes.Value_Of (Scheme)));
      SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
      SSL.Wire.Put_Bytes (Into, Emitter, Signature);
      SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);
      Finish_Message (Into, Emitter, Body_Mark, Written, Error);
   end Encode_Certificate_Verify;

   ---------------------------------------------------------------------------
   --  Finished
   ---------------------------------------------------------------------------

   procedure Parse_Finished
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      First  : out Byte_Index;
      Last   : out Byte_Index;
      Error  : out SSL.Errors.Error_Information)
   is
      pragma Unreferenced (Bounds);
      Cursor : SSL.Wire.Cursor;
   begin
      First := 1;
      Last := 0;
      Begin_Message (Data, Finished, Cursor, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      if SSL.Wire.Remaining (Cursor) = 0 then
         Error := Short_Message;
         return;
      end if;
      SSL.Wire.Get_Span (Data, Cursor, SSL.Wire.Remaining (Cursor), First, Last);
   end Parse_Finished;

   procedure Encode_Finished
     (Verify_Data : Byte_Array;
      Into        : out Byte_Array;
      Written     : out Byte_Index;
      Error       : out SSL.Errors.Error_Information)
   is
      Emitter   : SSL.Wire.Emitter;
      Body_Mark : Byte_Index;
   begin
      Written := 0;
      Error := SSL.Errors.No_Error;
      Begin_Encoding (Finished, Into, Emitter, Body_Mark);
      SSL.Wire.Put_Bytes (Into, Emitter, Verify_Data);
      Finish_Message (Into, Emitter, Body_Mark, Written, Error);
   end Encode_Finished;

   ---------------------------------------------------------------------------
   --  NewSessionTicket
   ---------------------------------------------------------------------------

   function Lifetime (Item : New_Session_Ticket_Message) return Interfaces.Unsigned_32 is
     (Item.Ticket_Lifetime);

   function Age_Add (Item : New_Session_Ticket_Message) return Interfaces.Unsigned_32 is
     (Item.Ticket_Age_Add);

   procedure Nonce_Span
     (Item  : New_Session_Ticket_Message;
      First : out Byte_Index;
      Last  : out Byte_Index)
   is
   begin
      First := Item.Nonce.First;
      Last := Item.Nonce.Last;
   end Nonce_Span;

   procedure Ticket_Span
     (Item  : New_Session_Ticket_Message;
      First : out Byte_Index;
      Last  : out Byte_Index)
   is
   begin
      First := Item.Ticket.First;
      Last := Item.Ticket.Last;
   end Ticket_Span;

   function Extensions_Seen (Item : New_Session_Ticket_Message) return SSL.Extensions.Seen_Set is
     (Item.Seen);

   --  RFC 8446 section 4.6.1: seven days, in seconds.
   Maximum_Ticket_Lifetime : constant Interfaces.Unsigned_32 := 604_800;

   procedure Parse_New_Session_Ticket
     (Data   : Byte_Array;
      Bounds : SSL.Limits.Resource_Limits;
      Item   : out New_Session_Ticket_Message;
      Error  : out SSL.Errors.Error_Information)
   is
      use type Interfaces.Unsigned_32;

      Cursor  : SSL.Wire.Cursor;
      Nonce   : SSL.Wire.Cursor;
      Ticket  : SSL.Wire.Cursor;
      Block   : SSL.Wire.Cursor;
      Reset   : New_Session_Ticket_Message;
      Kind    : Ext.Extension_Kind;
      Value   : Ext.Extension_Value;
      Part    : SSL.Wire.Cursor;
      Present : Boolean;
   begin
      Item := Reset;
      Begin_Message (Data, New_Session_Ticket, Cursor, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Wire.Get_UInt32 (Data, Cursor, Item.Ticket_Lifetime);
      SSL.Wire.Get_UInt32 (Data, Cursor, Item.Ticket_Age_Add);
      if not SSL.Wire.Is_Valid (Cursor) then
         Error := Short_Message;
         Item := Reset;
         return;
      end if;

      --  A lifetime past the specified ceiling is refused rather than clamped.
      --  Clamping would leave the two ends disagreeing about when the ticket
      --  died, and the disagreement would surface as a resumption failure with
      --  no cause attached to it.
      if Item.Ticket_Lifetime > Maximum_Ticket_Lifetime then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Ticket_Malformed,
            Origin     => SSL.Errors.Peer_Message,
            Parameters =>
              [SSL.Errors.Numeric_Parameter
                 ("lifetime", Long_Long_Integer (Item.Ticket_Lifetime)),
               SSL.Errors.Numeric_Parameter
                 ("permitted", Long_Long_Integer (Maximum_Ticket_Lifetime))]);
         Item := Reset;
         return;
      end if;

      SSL.Wire.Open_Vector_8 (Data, Cursor, 255, Nonce);
      if not SSL.Wire.Is_Valid (Nonce) then
         Error := Short_Message;
         Item := Reset;
         return;
      end if;
      SSL.Wire.Get_Span
        (Data, Nonce, SSL.Wire.Remaining (Nonce), Item.Nonce.First, Item.Nonce.Last);
      Item.Nonce.Present := True;

      SSL.Wire.Open_Vector_16
        (Data, Cursor, Byte_Index (Bounds.Maximum_Ticket_Size), Ticket);
      if not SSL.Wire.Is_Valid (Ticket) then
         Error := SSL.Errors.Make
           (Code       => SSL.Errors.Code_Limit_Exceeded,
            Origin     => SSL.Errors.Peer_Message,
            Parameters => [SSL.Errors.Text_Parameter ("limit", "maximum ticket size")]);
         Item := Reset;
         return;
      end if;
      if SSL.Wire.Remaining (Ticket) = 0 then
         --  RFC 8446 section 4.6.1 makes the ticket at least one octet, and a
         --  ticket of no octets could not identify anything.
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Ticket_Malformed, SSL.Errors.Peer_Message);
         Item := Reset;
         return;
      end if;
      SSL.Wire.Get_Span
        (Data, Ticket, SSL.Wire.Remaining (Ticket), Item.Ticket.First, Item.Ticket.Last);
      Item.Ticket.Present := True;

      Ext.Open_Block (Data, Cursor, Bounds, Block, Error);
      if SSL.Errors.Is_Error (Error) then
         Item := Reset;
         return;
      end if;

      loop
         Ext.Next (Data, Block, Ext.In_New_Session_Ticket, Bounds, Item.Seen,
                   Kind, Value, Part, Present, Error);
         exit when SSL.Errors.Is_Error (Error) or else not Present;

         if Kind = Ext.Early_Data then
            --  A ticket offering early data is refused outright rather than
            --  accepted with the offer ignored. Accepting it would mean holding
            --  a ticket whose stated terms this library does not honour.
            Error := SSL.Errors.Make
              (SSL.Errors.Code_Early_Data_Offered, SSL.Errors.Peer_Message);
            Item := Reset;
            return;
         end if;
      end loop;

      if SSL.Errors.Is_Error (Error) or else not SSL.Wire.At_End (Cursor) then
         if not SSL.Errors.Is_Error (Error) then
            Error := Short_Message;
         end if;
         Item := Reset;
      end if;
   end Parse_New_Session_Ticket;

   procedure Encode_New_Session_Ticket
     (Lifetime : Interfaces.Unsigned_32;
      Age_Add  : Interfaces.Unsigned_32;
      Nonce    : Byte_Array;
      Ticket   : Byte_Array;
      Into     : out Byte_Array;
      Written  : out Byte_Index;
      Error    : out SSL.Errors.Error_Information)
   is
      use type Interfaces.Unsigned_32;

      Emitter    : SSL.Wire.Emitter;
      Body_Mark  : Byte_Index;
      Block_Mark : Byte_Index;
      Inner      : Byte_Index;
   begin
      Written := 0;
      Error := SSL.Errors.No_Error;

      if Lifetime > Maximum_Ticket_Lifetime then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Internal_Invariant_Violated, SSL.Errors.Local_Implementation);
         return;
      end if;

      Begin_Encoding (New_Session_Ticket, Into, Emitter, Body_Mark);
      SSL.Wire.Put_UInt32 (Into, Emitter, Lifetime);
      SSL.Wire.Put_UInt32 (Into, Emitter, Age_Add);
      SSL.Wire.Put_UInt8 (Into, Emitter, Natural (Nonce'Length));
      SSL.Wire.Put_Bytes (Into, Emitter, Nonce);
      SSL.Wire.Open_Vector_16 (Into, Emitter, Inner);
      SSL.Wire.Put_Bytes (Into, Emitter, Ticket);
      SSL.Wire.Close_Vector_16 (Into, Emitter, Inner);

      --  An empty extension block, not an absent one: RFC 8446 section 4.6.1
      --  puts the field in the message unconditionally.
      SSL.Extensions.Open_Block (Into, Emitter, Block_Mark);
      SSL.Extensions.Close_Block (Into, Emitter, Block_Mark);

      Finish_Message (Into, Emitter, Body_Mark, Written, Error);
   end Encode_New_Session_Ticket;

   ---------------------------------------------------------------------------
   --  KeyUpdate
   ---------------------------------------------------------------------------

   procedure Parse_Key_Update
     (Data    : Byte_Array;
      Request : out Key_Update_Request;
      Error   : out SSL.Errors.Error_Information)
   is
      Cursor : SSL.Wire.Cursor;
      Value  : Natural;
   begin
      Request := Update_Not_Requested;
      Begin_Message (Data, Key_Update, Cursor, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Wire.Get_UInt8 (Data, Cursor, Value);
      if not SSL.Wire.Is_Valid (Cursor) or else not SSL.Wire.At_End (Cursor) then
         Error := Short_Message;
         return;
      end if;

      case Value is
         when 0 => Request := Update_Not_Requested;
         when 1 => Request := Update_Requested;
         when others =>
            --  RFC 8446 section 4.6.3 defines two values and says any other is
            --  an illegal_parameter. There is no third meaning to guess at.
            Error := SSL.Errors.Make
              (Code       => SSL.Errors.Code_Handshake_Message_Malformed,
               Origin     => SSL.Errors.Peer_Message,
               Parameters =>
                 [SSL.Errors.Numeric_Parameter ("request", Long_Long_Integer (Value))]);
      end case;
   end Parse_Key_Update;

   procedure Encode_Key_Update
     (Request : Key_Update_Request;
      Into    : out Byte_Array;
      Written : out Byte_Index;
      Error   : out SSL.Errors.Error_Information)
   is
      Emitter   : SSL.Wire.Emitter;
      Body_Mark : Byte_Index;
   begin
      Written := 0;
      Error := SSL.Errors.No_Error;
      Begin_Encoding (Key_Update, Into, Emitter, Body_Mark);
      SSL.Wire.Put_UInt8
        (Into, Emitter, (case Request is when Update_Not_Requested => 0,
                                         when Update_Requested => 1));
      Finish_Message (Into, Emitter, Body_Mark, Written, Error);
   end Encode_Key_Update;

end SSL.Handshake_Messages;
