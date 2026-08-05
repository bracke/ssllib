with SSL.Configurations;
with SSL.Credentials;
with SSL.Trust;

--  @summary The peer's long-lived objects, at library level.
--
--  A main procedure's own declarations are inside a subprogram, and a
--  configuration holds a reference to its trust snapshot and its credentials
--  while a connection holds one to its configuration. Each must outlive what
--  points at it, and Ada's accessibility rules enforce that rather than trusting
--  anyone to remember it -- so declaring these in the main procedure fails an
--  accessibility check at run time, immediately and loudly.
--
--  A one-package indirection is what a real application would have anyway: the
--  package that owns its configuration.
package SSLLib_Peer_State is

   Anchors      : aliased SSL.Trust.Snapshot;
   Credential   : aliased SSL.Credentials.Credential;

   --  A second credential, for the client role. Separate from the one above
   --  because a peer driving both roles in one run would otherwise have the
   --  server's key where the client's belongs.
   Client_Credential : aliased SSL.Credentials.Credential;
   Client_Setup : aliased SSL.Configurations.Client_Configuration;
   Server_Setup : aliased SSL.Configurations.Server_Configuration;

end SSLLib_Peer_State;
