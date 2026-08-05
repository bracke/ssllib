with Ada.Text_IO;

with SSL.Limits;
with SSL.Server_Names;

package body Example_Support is

   use type SSL.Transports.Transport_Status;

   Bounds : constant SSL.Limits.Resource_Limits := SSL.Limits.Default_Limits;

   -----------------
   -- Attach --
   -----------------

   procedure Attach
     (Item     : in out Memory_Transport;
      Outgoing : not null access Pipe;
      Incoming : not null access Pipe;
      Name     : String)
   is
   begin
      Item.Outgoing := Outgoing;
      Item.Incoming := Incoming;
      Item.Length := Natural'Min (Name'Length, Name_Limit);
      Item.Name := [others => ' '];
      Item.Name (1 .. Item.Length) := Name (Name'First .. Name'First + Item.Length - 1);
   end Attach;

   procedure Set_Stalling (Item : in out Memory_Transport; Value : Boolean) is
   begin
      Item.Stalling := Value;
   end Set_Stalling;

   ------------------
   -- Receive --
   ------------------

   overriding procedure Receive
     (Item   : in out Memory_Transport;
      Into   : out SSL.Byte_Array;
      Count  : out SSL.Byte_Index;
      Status : out SSL.Transports.Transport_Status)
   is
   begin
      Into := [others => 0];
      Count := 0;

      if Item.Stalling then
         --  What a non-blocking socket does when its receive buffer is empty.
         --  A caller that could not cope with this could not use a real socket.
         Item.Stalled := not Item.Stalled;
         if Item.Stalled then
            Status := SSL.Transports.Would_Block;
            return;
         end if;
      end if;

      if Item.Incoming.Held = 0 then
         Status := SSL.Transports.Would_Block;
         return;
      end if;

      Count := SSL.Byte_Index'Min (Into'Length, Item.Incoming.Held);
      Into (Into'First .. Into'First + Count - 1) := Item.Incoming.Bytes (1 .. Count);
      Item.Incoming.Bytes (1 .. Item.Incoming.Held - Count) :=
        Item.Incoming.Bytes (Count + 1 .. Item.Incoming.Held);
      Item.Incoming.Held := Item.Incoming.Held - Count;
      Status := SSL.Transports.Ok;
   end Receive;

   ---------------
   -- Send --
   ---------------

   overriding procedure Send
     (Item   : in out Memory_Transport;
      Data   : SSL.Byte_Array;
      Count  : out SSL.Byte_Index;
      Status : out SSL.Transports.Transport_Status)
   is
   begin
      Count := 0;

      if Item.Outgoing.Held = Capacity then
         Status := SSL.Transports.Would_Block;
         return;
      end if;

      Count := SSL.Byte_Index'Min (Data'Length, Capacity - Item.Outgoing.Held);
      Item.Outgoing.Bytes (Item.Outgoing.Held + 1 .. Item.Outgoing.Held + Count) :=
        Data (Data'First .. Data'First + Count - 1);
      Item.Outgoing.Held := Item.Outgoing.Held + Count;
      Status := SSL.Transports.Ok;
   end Send;

   overriding function Description (Item : Memory_Transport) return String is
     (Item.Name (1 .. Item.Length));

   ------------------------
   -- Connect_Pipes --
   ------------------------

   procedure Connect_Pipes is
   begin
      To_Server.Held := 0;
      To_Client.Held := 0;
      Attach (Client_Medium, To_Server'Access, To_Client'Access, "client socket");
      Attach (Server_Medium, To_Client'Access, To_Server'Access, "server socket");
   end Connect_Pipes;

   procedure Connect_Second_Pipes is
   begin
      Second_To_Server.Held := 0;
      Second_To_Client.Held := 0;
      Attach (Second_Client_Medium, Second_To_Server'Access, Second_To_Client'Access,
              "client socket");
      Attach (Second_Server_Medium, Second_To_Client'Access, Second_To_Server'Access,
              "server socket");
   end Connect_Second_Pipes;

   ---------------------------------------------------------------------------
   --  Fixtures and configurations
   ---------------------------------------------------------------------------

   function Example_Time return SSL.Clocks.Wall_Time is (SSL.Clocks.UTC (2026, 8, 1));

   procedure Load_Fixtures
     (Anchors    : in out SSL.Trust.Snapshot;
      Credential : in out SSL.Credentials.Credential;
      Now        : SSL.Clocks.Wall_Time;
      Error      : out SSL.Errors.Error_Information)
   is
   begin
      SSL.Trust.Load_Explicit_Anchors (Anchors, Certificate_PEM, Now, Bounds, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      SSL.Credentials.Load_PEM
        (Credential, Certificate_PEM, Private_Key_PEM, Bounds, Error);
   end Load_Fixtures;

   procedure Build_Client
     (Into    : out SSL.Configurations.Client_Configuration;
      Anchors : not null access constant SSL.Trust.Snapshot;
      Error   : out SSL.Errors.Error_Information)
   is
      Builder : SSL.Configurations.Client_Builder;
      Ok      : Boolean;
   begin
      --  Secure defaults first, then only what this example changes. Starting
      --  from the defaults and narrowing is the way round that cannot
      --  accidentally leave something off.
      SSL.Configurations.Secure_Client_Defaults (Builder);
      SSL.Configurations.Set_Expected_Name
        (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
      SSL.Configurations.Set_Anchors (Builder, Anchors, Ok);
      SSL.Configurations.Build (Builder, Into, Error);
   end Build_Client;

   procedure Build_Server
     (Into       : out SSL.Configurations.Server_Configuration;
      Credential : not null access constant SSL.Credentials.Credential;
      Error      : out SSL.Errors.Error_Information)
   is
      Builder : SSL.Configurations.Server_Builder;
      Ok      : Boolean;
   begin
      SSL.Configurations.Secure_Server_Defaults (Builder);
      SSL.Configurations.Add_Credential (Builder, Credential, Ok);
      SSL.Configurations.Build (Builder, Into, Error);
   end Build_Server;

   ---------------------------------------------------------------------------
   --  Driving
   ---------------------------------------------------------------------------

   procedure Run_Handshake
     (Client : in out SSL.Connections.Connection;
      Server : in out SSL.Connections.Connection;
      Error  : out SSL.Errors.Error_Information)
   is
      Moved  : Boolean;
      Rounds : Natural := 0;
   begin
      Error := SSL.Errors.No_Error;

      loop
         Rounds := Rounds + 1;
         if Rounds > 1_000 then
            --  Bounded, because a handshake that does not converge is a failure
            --  rather than something to keep waiting for.
            Error := SSL.Errors.Make
              (SSL.Errors.Code_Deadline_Reached, SSL.Errors.Caller_Request);
            return;
         end if;

         SSL.Connections.Step (Client, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;
         SSL.Connections.Step (Server, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;

         exit when SSL.Connections.Is_Established (Client)
           and then SSL.Connections.Is_Established (Server);
      end loop;
   end Run_Handshake;

   procedure Deliver
     (From  : in out SSL.Connections.Connection;
      To    : in out SSL.Connections.Connection;
      Into  : out SSL.Byte_Array;
      Count : out SSL.Byte_Index;
      Error : out SSL.Errors.Error_Information)
   is
      Moved  : Boolean;
      Rounds : Natural := 0;
   begin
      Into := [others => 0];
      Count := 0;
      Error := SSL.Errors.No_Error;

      while Count = 0 loop
         Rounds := Rounds + 1;
         if Rounds > 1_000 then
            Error := SSL.Errors.Make
              (SSL.Errors.Code_Deadline_Reached, SSL.Errors.Caller_Request);
            return;
         end if;

         SSL.Connections.Step (From, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;
         SSL.Connections.Step (To, Moved, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;

         SSL.Connections.Read_Available (To, Into, Count, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;
      end loop;
   end Deliver;

   ---------------
   -- Report --
   ---------------

   procedure Report (Label : String; Error : SSL.Errors.Error_Information) is
   begin
      Ada.Text_IO.Put_Line (Label & ": " & SSL.Errors.Image (Error));
   end Report;

end Example_Support;
