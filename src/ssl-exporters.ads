with SSL.Connections;
with SSL.Errors;

--  @summary Exported keying material: keys for a protocol layered on top of
--  TLS, derived from the connection and bound to it.
--
--  RFC 5705 and RFC 8446 section 7.5. An application that needs a key which is
--  cryptographically tied to *this* TLS connection -- a token that cannot be
--  replayed onto another connection, a channel binding, a key for a protocol
--  running inside the tunnel -- asks for it here rather than inventing one.
--
--  Three properties this interface is shaped around:
--
--    * **Only after the handshake.** Before it there is no exporter master
--      secret, and anything derived would not be bound to a connection either
--      end had authenticated.
--    * **The label and the context are inputs.** Whether a context was
--      supplied is a separate flag rather than "an empty array means none",
--      because RFC 5705 -- which TLS 1.2 uses -- distinguishes the two. Under
--      TLS 1.3 they give the same output, by RFC 8446 section 7.5's own
--      definition, and this library does not pretend otherwise.
--    * **There is no getter for the secret.** A caller can ask for material
--      derived under a label; nothing can ask for the exporter master secret
--      itself, which is what stops one caller's label from being another's
--      problem.
package SSL.Exporters is

   --  The most a single call will produce. Bounded because an unbounded length
   --  is an unbounded derivation an application can ask for repeatedly, and
   --  because no real use needs more.
   Maximum_Output : constant Byte_Index := 255;

   --  Derive keying material bound to this connection.
   --
   --  @param Item        the connection, which must be established
   --  @param Label       the exporter label, from whatever specification is
   --                     asking for the material. Registered labels avoid
   --                     collisions; an application inventing its own should
   --                     prefix it with something it owns
   --  @param Context     the context octets
   --  @param Has_Context whether a context was supplied at all
   --  @param Into        out: the material; zeroed on failure
   --  @param Error       out: No_Error, or why it could not be derived
   procedure Export
     (Item        : SSL.Connections.Connection;
      Label       : String;
      Context     : Byte_Array;
      Has_Context : Boolean;
      Into        : out Byte_Array;
      Error       : out SSL.Errors.Error_Information)
     with Pre => Label'Length > 0 and then Into'Length in 1 .. Maximum_Output;

   --  Derive with no context at all, which is the common case.
   procedure Export
     (Item  : SSL.Connections.Connection;
      Label : String;
      Into  : out Byte_Array;
      Error : out SSL.Errors.Error_Information)
     with Pre => Label'Length > 0 and then Into'Length in 1 .. Maximum_Output;

end SSL.Exporters;
