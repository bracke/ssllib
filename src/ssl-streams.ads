with Ada.Streams;

with SSL.Clocks;
with SSL.Connections;
with SSL.Errors;

--  @summary An Ada stream over a TLS connection, for code that is written
--  against `Ada.Streams.Root_Stream_Type`.
--
--  This is the one place in the library where a failure is an exception, and it
--  is not a choice: `Read` and `Write` are inherited from
--  `Ada.Streams.Root_Stream_Type` and have no way to report a structured
--  result. That is a real cost. A stream read that fails raises, and the
--  exception carries a rendering of the failure rather than the failure itself,
--  so a caller that needs to act on the failure -- to distinguish a certificate
--  problem from a transport one, say -- must ask the connection afterwards
--  rather than catching a type.
--
--  Because of that, this is a bridge rather than the recommended API. Code that
--  can use `SSL.Blocking` or `SSL.Connections` directly should: it gets the
--  structured failures the rest of this library is built around. This exists so
--  that `Type'Read` and `Type'Write` work over TLS, which is worth having and
--  cannot be had any other way.
package SSL.Streams is

   --  Raised by Read and Write. The message is the failure's operator
   --  rendering: category, code, origin and whatever the disclosure class
   --  permits. Never key material and never plaintext.
   Stream_Failure : exception;

   --  A stream bound to a connection.
   --
   --  Limited and holding a reference: the connection is the application's and
   --  outlives the stream. Two streams over one connection would be two things
   --  reading one queue, which is the concurrency the base connection type
   --  explicitly does not defend against.
   type Connection_Stream
     (Target : not null access SSL.Connections.Connection)
   is limited new Ada.Streams.Root_Stream_Type with private;

   --  The deadline every Read and Write on this stream uses.
   --
   --  Set once, because the inherited operations have nowhere to take one. A
   --  stream with no deadline is a program that can stop responding because a
   --  peer stopped talking, so setting one is worth doing even though it is not
   --  required.
   procedure Set_Deadline (Item : in out Connection_Stream; Value : SSL.Clocks.Deadline);

   --  The failure that ended this stream, when one did. For a caller that
   --  caught Stream_Failure and needs to know what actually happened.
   function Last_Failure (Item : Connection_Stream) return SSL.Errors.Error_Information;

   overriding procedure Read
     (Stream : in out Connection_Stream;
      Item   : out Ada.Streams.Stream_Element_Array;
      Last   : out Ada.Streams.Stream_Element_Offset);

   overriding procedure Write
     (Stream : in out Connection_Stream;
      Item   : Ada.Streams.Stream_Element_Array);

private

   type Connection_Stream
     (Target : not null access SSL.Connections.Connection)
   is limited new Ada.Streams.Root_Stream_Type with record
      Expires_At : SSL.Clocks.Deadline := SSL.Clocks.No_Deadline;
      Failure    : SSL.Errors.Error_Information := SSL.Errors.No_Error;
   end record;

   function Last_Failure (Item : Connection_Stream) return SSL.Errors.Error_Information is
     (Item.Failure);

end SSL.Streams;
