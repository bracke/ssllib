with Ada.Text_IO;

with SSL;
with SSL.ALPN;
with SSL.Clients;
with SSL.Configurations;
with SSL.Connection_Metadata;
with SSL.Connections;
with SSL.Credentials;
with SSL.Errors;
with SSL.Server_Names;
with SSL.Servers;
with SSL.Trust;

with Example_Support;

--  Negotiating an application protocol, and what happens when there is none in
--  common.
--
--  The second half is the part worth reading. A client that says a protocol is
--  `Required` and finds no overlap gets a failed handshake with a named reason,
--  not a connection that quietly speaks something nobody agreed to.
procedure Alpn_Example is

   package Meta renames SSL.Connection_Metadata;

   Error : SSL.Errors.Error_Information;

   --  The two client policies and the server policy live in Example_Support,
   --  at library level, because a connection holds a reference to the policy it
   --  runs under and the policy must outlive it. `Client_Policy` is the one
   --  that offers h2; `Other_Client_Policy` is the one that insists on spdy/3.

   procedure Build_Client_With
     (Into     : out SSL.Configurations.Client_Configuration;
      Protocol : String;
      Need     : SSL.ALPN.ALPN_Requirement;
      Outcome  : out SSL.Errors.Error_Information);

   procedure Build_Client_With
     (Into     : out SSL.Configurations.Client_Configuration;
      Protocol : String;
      Need     : SSL.ALPN.ALPN_Requirement;
      Outcome  : out SSL.Errors.Error_Information)
   is
      Builder   : SSL.Configurations.Client_Builder;
      Protocols : SSL.ALPN.Protocol_List := SSL.ALPN.No_Protocols;
      Ok        : Boolean;
   begin
      SSL.Configurations.Secure_Client_Defaults (Builder);
      SSL.Configurations.Set_Expected_Name
        (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
      SSL.Configurations.Set_Anchors (Builder, Example_Support.Anchors'Access, Ok);

      SSL.ALPN.Append (Protocols, SSL.ALPN.Protocol (Protocol), Ok);
      SSL.Configurations.Set_Application_Protocols (Builder, Protocols, Need, Ok);

      SSL.Configurations.Build (Builder, Into, Outcome);
   end Build_Client_With;

   procedure Try
     (Label  : String;
      Policy : not null access constant SSL.Configurations.Client_Configuration);

   procedure Try
     (Label  : String;
      Policy : not null access constant SSL.Configurations.Client_Configuration)
   is
      Client : SSL.Connections.Connection;
      Server : SSL.Connections.Connection;
      Result : SSL.Errors.Error_Information;
   begin
      --  A fresh pair of pipes each time, so the second attempt is not reading
      --  what the first one left behind.
      Example_Support.Connect_Pipes;

      SSL.Servers.Accept_Connection
        (Server, Example_Support.Server_Policy'Access, Example_Support.Server_Medium'Access,
         Now => Example_Support.Example_Time, Error => Result);
      SSL.Clients.Connect
        (Client, Policy, Example_Support.Client_Medium'Access,
         Now => Example_Support.Example_Time, Error => Result);

      Example_Support.Run_Handshake (Client, Server, Result);

      if SSL.Errors.Is_Error (Result) then
         Ada.Text_IO.Put_Line (Label & ": refused -- " & SSL.Errors.Image (Result));
      else
         declare
            Chosen : constant Meta.Metadata := SSL.Connections.Metadata_Of (Client);
         begin
            if Meta.Has_Protocol (Chosen) then
               Ada.Text_IO.Put_Line
                 (Label & ": agreed on " & SSL.ALPN.Image (Meta.Protocol (Chosen)));
            else
               Ada.Text_IO.Put_Line (Label & ": connected with no protocol agreed");
            end if;
         end;
      end if;

      SSL.Connections.Wipe (Client);
      SSL.Connections.Wipe (Server);
   end Try;

begin
   Example_Support.Load_Fixtures
     (Example_Support.Anchors, Example_Support.Credential,
      Example_Support.Example_Time, Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("loading the certificate", Error);
      return;
   end if;

   --  The server offers h2 and nothing else.
   declare
      Builder   : SSL.Configurations.Server_Builder;
      Protocols : SSL.ALPN.Protocol_List := SSL.ALPN.No_Protocols;
      Ok        : Boolean;
   begin
      SSL.Configurations.Secure_Server_Defaults (Builder);
      SSL.Configurations.Add_Credential
        (Builder, Example_Support.Credential'Access, Ok);
      SSL.ALPN.Append (Protocols, SSL.ALPN.Protocol ("h2"), Ok);
      SSL.Configurations.Set_Application_Protocols
        (Item        => Builder,
         Value       => Protocols,
         Requirement => SSL.ALPN.Optional,
         Selection   => SSL.ALPN.Server_Order,
         Ok          => Ok);
      SSL.Configurations.Build (Builder, Example_Support.Server_Policy, Error);
      if SSL.Errors.Is_Error (Error) then
         Example_Support.Report ("building the server policy", Error);
         return;
      end if;
   end;

   Build_Client_With
     (Example_Support.Client_Policy, "h2", SSL.ALPN.Required, Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("building the agreeing client", Error);
      return;
   end if;

   Build_Client_With
     (Example_Support.Other_Client_Policy, "spdy/3", SSL.ALPN.Required, Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("building the insisting client", Error);
      return;
   end if;

   Try ("a client offering h2", Example_Support.Client_Policy'Access);

   --  And the case worth having an example for: no overlap, and the client
   --  said it was required. The connection fails with a reason, rather than
   --  succeeding and leaving the two ends to discover later that they are
   --  speaking different protocols down one encrypted pipe.
   Try ("a client insisting on spdy/3", Example_Support.Other_Client_Policy'Access);
end Alpn_Example;
