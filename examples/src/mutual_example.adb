with Ada.Text_IO;

with SSL;
with SSL.Authentication;
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

--  Mutual TLS: the client proves it holds a key too.
--
--  An ordinary TLS connection authenticates one end. The client learns that it
--  is talking to the holder of a particular certificate's key; the server
--  learns nothing about the client except its address. For most of the web that
--  is the right split, because the application authenticates the user inside the
--  tunnel afterwards.
--
--  Mutual TLS moves that authentication into the handshake. It is worth doing
--  when the client is a machine rather than a person -- a service calling a
--  service, an agent reporting to a controller -- because then there is no
--  "afterwards" to put a login in, and a key the client already has to protect
--  is a better credential than a shared secret in a configuration file.
--
--  Three things this example shows that are easy to get wrong:
--
--    * **The server must ask.** A client never volunteers a certificate. The
--      policy is `SSL.Authentication.Required` here; `Requested_Optional` asks
--      and accepts a decline, which is a different deployment and a different
--      risk.
--    * **The client answers only when it can.** If it has no credential, or
--      none matching the schemes the request named, it declines with an empty
--      Certificate rather than sending a chain it cannot then sign for.
--    * **A completed handshake is not the assertion.** What matters is that the
--      server *reports* an authenticated peer, which is checked below. A
--      handshake that finished while the server still considered its peer
--      anonymous would mean the requirement was not enforced.
procedure Mutual_Example is

   Client : SSL.Connections.Connection;
   Server : SSL.Connections.Connection;
   Error  : SSL.Errors.Error_Information;
   Ok     : Boolean;
begin
   Example_Support.Connect_Pipes;

   Example_Support.Load_Fixtures
     (Example_Support.Anchors, Example_Support.Credential,
      Example_Support.Example_Time, Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("loading the fixtures", Error);
      return;
   end if;

   --  The client, with a credential of its own. One fixture serves as both
   --  ends' certificate here because an example with no network has no second
   --  identity to be; a deployment gives each side its own.
   declare
      Builder : SSL.Configurations.Client_Builder;
   begin
      SSL.Configurations.Secure_Client_Defaults (Builder);
      SSL.Configurations.Set_Expected_Name
        (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
      SSL.Configurations.Set_Anchors (Builder, Example_Support.Anchors'Access, Ok);
      SSL.Configurations.Set_Client_Credential
        (Builder, Example_Support.Credential'Access, Ok);
      if not Ok then
         Ada.Text_IO.Put_Line ("the client credential was refused");
         return;
      end if;
      SSL.Configurations.Build (Builder, Example_Support.Client_Policy, Error);
   end;
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("building the client policy", Error);
      return;
   end if;

   --  The server, requiring one. It needs anchors of its own to validate what
   --  the client sends: a server that asked for a certificate and had nothing
   --  to check it against would be asking for a decoration.
   declare
      Builder : SSL.Configurations.Server_Builder;
   begin
      SSL.Configurations.Secure_Server_Defaults (Builder);
      SSL.Configurations.Add_Credential
        (Builder, Example_Support.Credential'Access, Ok);
      SSL.Configurations.Set_Anchors (Builder, Example_Support.Anchors'Access, Ok);
      SSL.Configurations.Set_Client_Authentication
        (Builder, SSL.Authentication.Required);
      SSL.Configurations.Build (Builder, Example_Support.Server_Policy, Error);
   end;
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("building the server policy", Error);
      return;
   end if;

   SSL.Servers.Accept_Connection
     (Server, Example_Support.Server_Policy'Access,
      Example_Support.Server_Medium'Access,
      Now => Example_Support.Example_Time, Error => Error);
   SSL.Clients.Connect
     (Client, Example_Support.Client_Policy'Access,
      Example_Support.Client_Medium'Access,
      Now => Example_Support.Example_Time, Error => Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("starting", Error);
      return;
   end if;

   Example_Support.Run_Handshake (Client, Server, Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("the handshake", Error);
      return;
   end if;

   Ada.Text_IO.Put_Line
     ("the client says its peer is "
      & (if SSL.Connection_Metadata.Peer_Authenticated
              (SSL.Connections.Metadata_Of (Client))
         then "authenticated" else "anonymous"));

   Ada.Text_IO.Put_Line
     ("the server says its peer is "
      & (if SSL.Connection_Metadata.Peer_Authenticated
              (SSL.Connections.Metadata_Of (Server))
         then "authenticated" else "anonymous"));

   if not SSL.Connection_Metadata.Peer_Authenticated
            (SSL.Connections.Metadata_Of (Server))
   then
      Ada.Text_IO.Put_Line
        ("a server that required a certificate and reports an anonymous peer "
         & "did not enforce its own requirement");
      return;
   end if;

   Ada.Text_IO.Put_Line ("both ends authenticated");

   SSL.Connections.Wipe (Client);
   SSL.Connections.Wipe (Server);
end Mutual_Example;
