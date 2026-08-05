with SSL;
with SSL.Transports;

--  @summary A pair of in-memory transports wired to each other, deliberately
--  awkward.
--
--  What one writes, the other reads. Nothing here touches a socket, so a whole
--  connection can be driven inside one test with no network, no ports and no
--  timing.
--
--  The awkwardness is the point. A transport that always accepted every write
--  in full and always had data ready would exercise none of the partial-I/O
--  handling that is the hardest part of the connection layer to get right and
--  the easiest to leave untested. So this one:
--
--    * accepts at most `Write_Chunk` octets per send, whatever it is offered;
--    * refuses every other read with `Would_Block`, even when data is waiting;
--    * hands back short reads whenever the pipe holds less than was asked for.
--
--  Every one of those is something a real non-blocking socket does routinely.
package Tests_Pipes is

   use type SSL.Byte_Index;

   Capacity : constant SSL.Byte_Index := 512 * 1024;

   --  How much a single send will take, however much it is offered. Small
   --  enough that a handshake flight takes many writes.
   Write_Chunk : constant SSL.Byte_Index := 97;

   --  One direction: what A wrote and B has not yet read.
   type Pipe is limited private;

   procedure Reset (Item : in out Pipe);

   --  A transport made of two pipes: one to write into, one to read from. Two
   --  of these with the pipes crossed make a connected pair.
   type Pipe_Transport is limited new SSL.Transports.Transport with private;

   procedure Attach
     (Item     : in out Pipe_Transport;
      Outgoing : not null access Pipe;
      Incoming : not null access Pipe;
      Label    : Character);

   overriding procedure Receive
     (Item   : in out Pipe_Transport;
      Into   : out SSL.Byte_Array;
      Count  : out SSL.Byte_Index;
      Status : out SSL.Transports.Transport_Status);

   overriding procedure Send
     (Item   : in out Pipe_Transport;
      Data   : SSL.Byte_Array;
      Count  : out SSL.Byte_Index;
      Status : out SSL.Transports.Transport_Status);

   overriding function Description (Item : Pipe_Transport) return String;

   --  Make the next read report end of stream, for testing truncation.
   procedure Close_Incoming (Item : in out Pipe_Transport);

   --  Make the next operation report a failure, for testing the boundary.
   procedure Break (Item : in out Pipe_Transport);

private

   type Pipe is limited record
      Held  : SSL.Byte_Index := 0;
      Bytes : SSL.Byte_Array (1 .. Capacity) := [others => 0];
   end record;

   type Pipe_Transport is limited new SSL.Transports.Transport with record
      Outgoing : access Pipe;
      Incoming : access Pipe;
      Label    : Character := '?';

      --  Flipped on every read, so that half of them say Would_Block.
      Stall    : Boolean := False;

      Ended    : Boolean := False;
      Broken   : Boolean := False;
   end record;

end Tests_Pipes;
