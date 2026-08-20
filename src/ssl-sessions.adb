with SSL.Crypto;

package body SSL.Sessions is

   use type SSL.Clocks.Wall_Time;
   use type SSL.Server_Names.DNS_Name;

   ------------------
   -- Is_Live --
   ------------------

   function Is_Live (Item : Session; At_Time : SSL.Clocks.Wall_Time) return Boolean is
   begin
      --  An absent clock makes nothing live. A session whose liveness could not
      --  be established must not be offered: the whole point of the expiry is
      --  that the server will refuse it, and offering one that has run out
      --  wastes a round trip and tells an observer the client is guessing.
      return Item.Present
        and then SSL.Clocks.Is_Present (At_Time)
        and then SSL.Clocks.Is_Present (Item.Expires)
        and then At_Time < Item.Expires;
   end Is_Live;

   ------------------
   -- Matches --
   ------------------

   function Matches
     (Item    : Session;
      Name    : SSL.Server_Names.DNS_Name;
      Context : Security_Context_ID;
      Setup   : Configuration_Fingerprint;
      Anchors : Trust_Fingerprint;
      At_Time : SSL.Clocks.Wall_Time) return Boolean
   is
   begin
      --  Every binding, and a mismatch in any of them means a full handshake.
      --  That is a normal outcome: resumption is an optimization, and declining
      --  it costs a round trip rather than security.
      return Is_Live (Item, At_Time)
        and then Item.Name = Name
        and then Item.Context = Context
        and then Item.Configuration = Setup
        and then Item.Trust = Anchors;
   end Matches;

   ---------------
   -- Wipe --
   ---------------

   procedure Wipe (Item : in out Session) is
   begin
      SSL.Secrets.Wipe (Item.Secret);
      SSL.Crypto.Scrub (Item.Ticket_Bytes);
      SSL.Crypto.Scrub (Item.Nonce_Bytes);
      Item.Ticket_Length := 0;
      Item.Nonce_Length := 0;
      Item.Present := False;
      Item.Authenticated := False;
      Item.Has_A_Protocol := False;
      Item.Issued := SSL.Clocks.No_Wall_Time;
      Item.Expires := SSL.Clocks.No_Wall_Time;
   end Wipe;

   ---------------
   -- Copy --
   ---------------

   procedure Copy (Target : in out Session; Source : Session) is
   begin
      Target.Present := Source.Present;
      Target.Version := Source.Version;
      Target.Suite := Source.Suite;
      Target.Name := Source.Name;
      Target.Has_A_Protocol := Source.Has_A_Protocol;
      Target.Protocol := Source.Protocol;
      Target.Issued := Source.Issued;
      Target.Expires := Source.Expires;
      Target.Context := Source.Context;
      Target.Configuration := Source.Configuration;
      Target.Trust := Source.Trust;
      Target.Authenticated := Source.Authenticated;
      Target.Ticket_Length := Source.Ticket_Length;
      Target.Ticket_Bytes := Source.Ticket_Bytes;
      Target.Offset := Source.Offset;
      Target.Nonce_Length := Source.Nonce_Length;
      Target.Nonce_Bytes := Source.Nonce_Bytes;
      SSL.Secrets.Copy (Target.Secret, Source.Secret);
   end Copy;

   ----------------
   -- Store --
   ----------------

   procedure Store
     (Item          : in out Session;
      Version       : SSL.Versions.Protocol_Version;
      Suite         : SSL.Cipher_Suites.Cipher_Suite;
      Name          : SSL.Server_Names.DNS_Name;
      Protocol      : SSL.ALPN.Protocol_Name;
      Has_Protocol  : Boolean;
      Issued        : SSL.Clocks.Wall_Time;
      Lifetime      : Natural;
      Context       : Security_Context_ID;
      Setup         : Configuration_Fingerprint;
      Anchors       : Trust_Fingerprint;
      Authenticated : Boolean;
      Ticket_Bytes  : Byte_Array;
      Age_Add       : Interfaces.Unsigned_32;
      Nonce_Bytes   : Byte_Array;
      Secret        : Byte_Array;
      Error         : out SSL.Errors.Error_Information)
   is
   begin
      Error := SSL.Errors.No_Error;
      Wipe (Item);

      if Ticket_Bytes'Length = 0 or else Ticket_Bytes'Length > Maximum_Ticket then
         --  Refused rather than truncated. Half a ticket is not a ticket, and
         --  storing one would mean offering something the server cannot open.
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Ticket_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      if Nonce_Bytes'Length > 255 or else Secret'Length = 0 or else Secret'Length > 64 then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Ticket_Malformed, SSL.Errors.Peer_Message);
         return;
      end if;

      if not SSL.Clocks.Is_Present (Issued) then
         --  Without a clock there is no expiry, and without an expiry the
         --  session could be offered forever.
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Ticket_Malformed, SSL.Errors.Local_Policy);
         return;
      end if;

      Item.Version := Version;
      Item.Suite := Suite;
      Item.Name := Name;
      Item.Has_A_Protocol := Has_Protocol;
      Item.Protocol := Protocol;
      Item.Issued := Issued;
      Item.Expires := SSL.Clocks.Advanced (Issued, Lifetime);
      Item.Context := Context;
      Item.Configuration := Setup;
      Item.Trust := Anchors;
      Item.Authenticated := Authenticated;

      Item.Ticket_Length := Ticket_Bytes'Length;
      Item.Ticket_Bytes (1 .. Item.Ticket_Length) := Ticket_Bytes;

      Item.Offset := Age_Add;

      Item.Nonce_Length := Nonce_Bytes'Length;
      if Item.Nonce_Length > 0 then
         Item.Nonce_Bytes (1 .. Item.Nonce_Length) := Nonce_Bytes;
      end if;

      SSL.Secrets.Set (Item.Secret, Secret);
      Item.Present := True;
   end Store;

   ---------------------
   -- Get_Secret --
   ---------------------

   procedure Get_Secret (Item : Session; Into : out Byte_Array; Length : out Byte_Index) is
   begin
      Into := [others => 0];
      Length := SSL.Secrets.Length (Item.Secret);
      if Length > 0 then
         Into (Into'First .. Into'First + Length - 1) := SSL.Secrets.Value (Item.Secret);
      end if;
   end Get_Secret;

   ---------------
   -- Image --
   ---------------

   function Image (Item : Session) return String is
   begin
      if not Item.Present then
         return "no session";
      end if;

      --  Never the ticket and never the secret. What is here is what an
      --  operator needs to see in a log: which host, which suite, when it runs
      --  out.
      return "session for "
        & (if SSL.Server_Names.Is_Present (Item.Name)
           then SSL.Server_Names.Image (Item.Name) else "(no name)")
        & " " & SSL.Cipher_Suites.Image (Item.Suite)
        & (if Item.Has_A_Protocol then " as " & SSL.ALPN.Image (Item.Protocol) else "")
        & " until " & SSL.Clocks.Image (Item.Expires);
   end Image;

end SSL.Sessions;
