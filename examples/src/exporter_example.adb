with Ada.Text_IO;

with SSL;
with SSL.Channel_Bindings;
with SSL.Clients;
with SSL.Configurations;
with SSL.Connections;
with SSL.Credentials;
with SSL.Errors;
with SSL.Exporters;
with SSL.Servers;
with SSL.Trust;

with Example_Support;

--  Exported keying material, and a channel binding built from it.
--
--  The use worth understanding: an application that authenticates *inside* the
--  tunnel -- a token, a SASL exchange, an HTTP credential -- is protected from
--  an eavesdropper and not from a proxy that terminates one TLS connection and
--  opens another. The proxy can replay the authentication onto its own
--  connection, because nothing in the authentication says which connection it
--  was for. A channel binding is that missing sentence.
procedure Exporter_Example is

   use type SSL.Byte_Array;

   --  All the long-lived objects live in Example_Support, at library level.
   Client : SSL.Connections.Connection;
   Server : SSL.Connections.Connection;
   Error  : SSL.Errors.Error_Information;

   function Hex (Data : SSL.Byte_Array) return String;

   function Hex (Data : SSL.Byte_Array) return String is
      Digits_Text : constant String := "0123456789abcdef";
      Result : String (1 .. 2 * Natural (Data'Length)) := [others => '0'];
      Cursor : Natural := 0;
   begin
      for Octet of Data loop
         Result (Cursor + 1) := Digits_Text (Natural (Octet) / 16 + 1);
         Result (Cursor + 2) := Digits_Text (Natural (Octet) mod 16 + 1);
         Cursor := Cursor + 2;
      end loop;
      return Result;
   end Hex;

begin
   Example_Support.Connect_Pipes;

   Example_Support.Load_Fixtures
     (Example_Support.Anchors, Example_Support.Credential,
      Example_Support.Example_Time, Error);
   Example_Support.Build_Client
     (Example_Support.Client_Policy, Example_Support.Anchors'Access, Error);
   Example_Support.Build_Server
     (Example_Support.Server_Policy, Example_Support.Credential'Access, Error);
   if SSL.Errors.Is_Error (Error) then
      Example_Support.Report ("setting up", Error);
      return;
   end if;

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

   --  Exported material. Both ends derive it independently and must agree; if
   --  they did not, it would bind nothing.
   declare
      From_Client : SSL.Byte_Array (1 .. 32) := [others => 0];
      From_Server : SSL.Byte_Array (1 .. 32) := [others => 0];
      Different   : SSL.Byte_Array (1 .. 32) := [others => 0];
   begin
      SSL.Exporters.Export (Client, "EXPERIMENTAL-my-application", From_Client, Error);
      SSL.Exporters.Export (Server, "EXPERIMENTAL-my-application", From_Server, Error);
      if SSL.Errors.Is_Error (Error) then
         Example_Support.Report ("exporting", Error);
         return;
      end if;

      Ada.Text_IO.Put_Line ("the two ends agree: "
                            & Boolean'Image (From_Client = From_Server));

      --  A different label gives different material, which is what stops one
      --  caller's key from being another's.
      SSL.Exporters.Export (Client, "EXPERIMENTAL-something-else", Different, Error);
      Ada.Text_IO.Put_Line ("a different label differs: "
                            & Boolean'Image (Different /= From_Client));
   end;

   --  The channel binding itself.
   declare
      Binding : SSL.Byte_Array (1 .. SSL.Channel_Bindings.Exporter_Binding_Length) :=
        [others => 0];
      Peer    : SSL.Byte_Array (1 .. SSL.Channel_Bindings.End_Point_Binding_Length) :=
        [others => 0];
   begin
      SSL.Channel_Bindings.Exporter_Binding (Client, Binding, Error);
      if SSL.Errors.Is_Error (Error) then
         Example_Support.Report ("the tls-exporter binding", Error);
         return;
      end if;
      Ada.Text_IO.Put_Line ("tls-exporter:         " & Hex (Binding));

      SSL.Channel_Bindings.End_Point_Binding (Client, Peer, Error);
      if SSL.Errors.Is_Error (Error) then
         Example_Support.Report ("the tls-server-end-point binding", Error);
         return;
      end if;
      Ada.Text_IO.Put_Line ("tls-server-end-point: " & Hex (Peer));

      --  And from the server's side, where there is no client certificate to
      --  bind to. Refused rather than invented: a binding to something that was
      --  not proved would be worse than none.
      SSL.Channel_Bindings.End_Point_Binding (Server, Peer, Error);
      Ada.Text_IO.Put_Line
        ("the server has no end-point binding, as expected: "
         & Boolean'Image (SSL.Errors.Is_Error (Error)));
   end;

   SSL.Connections.Wipe (Client);
   SSL.Connections.Wipe (Server);
end Exporter_Example;
