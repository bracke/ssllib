with Ada.Text_IO;

with SSL;
with SSL.Clients;
with SSL.Configurations;
with SSL.Connections;
with SSL.Credentials;
with SSL.Diagnostics;
with SSL.Errors;
with SSL.Server_Names;
with SSL.Servers;
with SSL.Trust;

with Example_Support;

--  A diagnostic sink, and what the library says through it.
--
--  Two things this example is really about. The first is that nothing appears
--  unless a configuration asks for it: `ssllib` writes nowhere on its own,
--  opens no file, and cannot be switched on by an environment variable. The
--  second is that the level and the redaction are separate settings, because
--  they answer different questions -- how much to say, and how much of what is
--  said may leave the machine.
procedure Diagnostics_Example is

   --  A sink that prints. A real one would enqueue and return: it is called
   --  synchronously, on the task running the handshake.
   type Printing_Sink is limited new SSL.Diagnostics.Sink with record
      Redaction : SSL.Diagnostics.Redaction_Level := SSL.Diagnostics.Operational;
      Prefix    : Character := '?';
   end record;

   overriding procedure Emit
     (Item : in out Printing_Sink; What : SSL.Diagnostics.Event);
   overriding function Description (Item : Printing_Sink) return String;

   overriding procedure Emit
     (Item : in out Printing_Sink; What : SSL.Diagnostics.Event)
   is
   begin
      Ada.Text_IO.Put_Line
        ("  [" & Item.Prefix & "] " & SSL.Diagnostics.Image (What, Item.Redaction));
   end Emit;

   overriding function Description (Item : Printing_Sink) return String is
     ("printing sink " & Item.Prefix);

   --  The sink must outlive every connection built from the configuration it
   --  is attached to, which is why it is not declared inside this procedure:
   --  the same lifetime rule as everything else here, enforced the same way.
   Watcher : aliased Printing_Sink := (Redaction => SSL.Diagnostics.Operational,
                                       Prefix    => 'c');

   Client : SSL.Connections.Connection;
   Server : SSL.Connections.Connection;
   Error  : SSL.Errors.Error_Information;
begin
   Example_Support.Connect_Pipes;

   Example_Support.Load_Fixtures
     (Example_Support.Anchors, Example_Support.Credential,
      Example_Support.Example_Time, Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("loading the certificate", Error);
      return;
   end if;

   --  The client's policy, with diagnostics attached. Everything else is the
   --  secure default.
   declare
      Builder : SSL.Configurations.Client_Builder;
      Ok      : Boolean;
   begin
      SSL.Configurations.Secure_Client_Defaults (Builder);
      SSL.Configurations.Set_Expected_Name
        (Builder, SSL.Server_Names.Name ("www.example.com"), Ok => Ok);
      SSL.Configurations.Set_Anchors (Builder, Example_Support.Anchors'Access, Ok);
      SSL.Configurations.Set_Diagnostics
        (Item      => Builder,
         Value     => Watcher'Unchecked_Access,
         Level     => SSL.Diagnostics.Handshake_Summary,
         Redaction => SSL.Diagnostics.Operational);
      SSL.Configurations.Build (Builder, Example_Support.Client_Policy, Error);
      if SSL.Errors.Is_Error (Error) then
         Example_Support.Report ("building the client policy", Error);
         return;
      end if;
   end;

   Example_Support.Build_Server
     (Example_Support.Server_Policy, Example_Support.Credential'Access, Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("building the server policy", Error);
      return;
   end if;

   Ada.Text_IO.Put_Line ("a connection that works, at Handshake_Summary:");

   SSL.Servers.Accept_Connection
     (Server, Example_Support.Server_Policy'Access, Example_Support.Server_Medium'Access,
      Now => Example_Support.Example_Time, Error => Error);
   SSL.Clients.Connect
     (Client, Example_Support.Client_Policy'Access, Example_Support.Client_Medium'Access,
      Now => Example_Support.Example_Time, Error => Error);

   Example_Support.Run_Handshake (Client, Server, Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("the handshake", Error);
      return;
   end if;

   SSL.Connections.Wipe (Client);
   SSL.Connections.Wipe (Server);

   --  The same events under strict redaction, which is what a deployment
   --  shipping its logs to somebody else would use: the kind and the code, and
   --  none of the facts that say which connection this was.
   Ada.Text_IO.Put_Line ("");
   Ada.Text_IO.Put_Line ("the same events, under Strict redaction:");

   Watcher.Redaction := SSL.Diagnostics.Strict;

   declare
      Again_Client : SSL.Connections.Connection;
      Again_Server : SSL.Connections.Connection;
   begin
      Example_Support.Connect_Second_Pipes;

      SSL.Servers.Accept_Connection
        (Again_Server, Example_Support.Server_Policy'Access,
         Example_Support.Second_Server_Medium'Access,
         Now => Example_Support.Example_Time, Error => Error);
      SSL.Clients.Connect
        (Again_Client, Example_Support.Client_Policy'Access,
         Example_Support.Second_Client_Medium'Access,
         Now => Example_Support.Example_Time, Error => Error);

      Example_Support.Run_Handshake (Again_Client, Again_Server, Error);
      if SSL.Errors.Is_Error (Error) then
         Example_Support.Report ("the second handshake", Error);
         return;
      end if;

      SSL.Connections.Wipe (Again_Client);
      SSL.Connections.Wipe (Again_Server);
   end;
end Diagnostics_Example;
