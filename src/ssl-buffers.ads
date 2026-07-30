private with Ada.Finalization;

--  @summary Fixed-capacity octet storage and octet FIFOs: where every buffer
--  in this library lives.
--
--  Two problems shape this package. The first is that a TLS endpoint needs a
--  handful of buffers a good deal larger than a stack frame -- an input buffer,
--  a ciphertext queue, a plaintext queue, a handshake reassembly area -- so
--  they are heap allocated, once, when the connection is set up, and never
--  resized afterwards. The second is that every one of them has held either
--  key material or plaintext, so releasing one has to scrub it; a buffer
--  returned to the allocator still holding a traffic key is the leak that
--  outlives the connection.
--
--  Capacity is fixed at reservation and is never grown. A queue that is full
--  reports that it is full; it does not allocate. This is the backpressure
--  boundary of the whole library, and it is a boundary precisely because it
--  cannot move under load: a hostile peer can fill a queue but cannot make one
--  bigger.
--
--  Nothing here is public. Callers see bounded copies through the engine API.
private package SSL.Buffers is

   ---------------------------------------------------------------------------
   --  Store: a fixed-capacity octet region
   ---------------------------------------------------------------------------

   --  Heap-backed octet storage, wiped and released when it goes out of scope.
   --  Limited and controlled: a Store cannot be copied, so two owners can
   --  never disagree about when the scrubbing happens.
   type Store is tagged limited private;

   --  Allocate Capacity octets, zeroed. Reserving an already reserved Store
   --  releases the old storage first, so re-reserving is safe and does not
   --  leak.
   --  @param Item     the store to allocate
   --  @param Capacity the number of octets, at least one
   --  @param Ok       out: False when the allocation failed, in which case
   --    Item is left unreserved rather than partly usable
   procedure Reserve (Item : in out Store; Capacity : Byte_Index; Ok : out Boolean)
     with Pre => Capacity > 0;

   --  Has storage been allocated?
   function Is_Reserved (Item : Store) return Boolean;

   --  How many octets the store holds room for; zero when unreserved.
   function Capacity (Item : Store) return Byte_Index;

   --  Overwrite every octet with zero, keeping the storage. For a store that
   --  has held a secret and is about to be reused.
   procedure Wipe (Item : in out Store);

   --  Overwrite and release the storage now rather than at end of scope.
   procedure Release (Item : in out Store);

   --  Copy Data into the store starting at First.
   --  @param Item  the store to write to
   --  @param First the first octet position to write, one-based
   --  @param Data  the octets to copy
   procedure Put
     (Item  : in out Store;
      First : Byte_Index;
      Data  : Byte_Array)
     with Pre => Is_Reserved (Item)
                 and then First >= 1
                 and then First - 1 + Data'Length <= Capacity (Item);

   --  Copy octets out of the store.
   --  @param Item  the store to read from
   --  @param First the first octet position to read, one-based
   --  @param Into  out: receives Into'Length octets
   procedure Get
     (Item  : Store;
      First : Byte_Index;
      Into  : out Byte_Array)
     with Pre => Is_Reserved (Item)
                 and then First >= 1
                 and then First - 1 + Into'Length <= Capacity (Item);

   --  A copy of a range of the store, for the places where a Byte_Array value
   --  is what a CryptoLib entry point takes. Bounded by the caller's range,
   --  which is bounded by the configured limits.
   --  @param Item  the store to read from
   --  @param First the first octet position, one-based
   --  @param Last  the last octet position; a null range gives an empty result
   --  @return the copied octets, indexed from one
   function Slice (Item : Store; First : Byte_Index; Last : Byte_Index) return Byte_Array
     with Pre => Is_Reserved (Item)
                 and then First >= 1
                 and then (Last < First or else Last <= Capacity (Item));

   --  One octet.
   function Element (Item : Store; Index : Byte_Index) return Byte
     with Pre => Is_Reserved (Item) and then Index in 1 .. Capacity (Item);

   ---------------------------------------------------------------------------
   --  Queue: an octet FIFO over a Store
   --
   --  A linear buffer with a read cursor, compacted when the read cursor has
   --  advanced far enough to be worth it. Not a ring buffer, because every
   --  consumer of these octets -- the record parser, the AEAD, the caller's
   --  transport write -- wants a contiguous run, and a ring would have to
   --  either copy at the wrap or hand out two pieces at every call site.
   ---------------------------------------------------------------------------

   type Queue is tagged limited private;

   --  Allocate a queue with room for Capacity octets.
   --  @param Item     the queue to allocate
   --  @param Capacity the number of octets, at least one
   --  @param Ok       out: False when the allocation failed
   procedure Reserve (Item : in out Queue; Capacity : Byte_Index; Ok : out Boolean)
     with Pre => Capacity > 0;

   function Is_Reserved (Item : Queue) return Boolean;

   --  The capacity, in octets.
   function Capacity (Item : Queue) return Byte_Index;

   --  How many octets are queued and not yet consumed.
   function Length (Item : Queue) return Byte_Index
     with Post => Length'Result <= Capacity (Item);

   --  How many more octets can be appended right now. Compaction is accounted
   --  for, so this is the true answer and not a lower bound.
   function Space (Item : Queue) return Byte_Index
     with Post => Space'Result <= Capacity (Item);

   function Is_Empty (Item : Queue) return Boolean;

   --  Append octets. Appends all of Data or none of it: a partial append would
   --  split a record or a handshake message across a backpressure boundary,
   --  and no caller of this wants that.
   --  @param Item the queue to append to
   --  @param Data the octets to append; may be empty
   --  @param Ok   out: False when Space (Item) < Data'Length, queue unchanged
   procedure Append (Item : in out Queue; Data : Byte_Array; Ok : out Boolean);

   --  Append as much of Data as fits, reporting how much was taken. For the
   --  application-write path, where partial acceptance is the documented
   --  behaviour and the caller retries with the remainder.
   --  @param Item     the queue to append to
   --  @param Data     the octets offered
   --  @param Accepted out: how many leading octets of Data were taken
   procedure Append_Partial
     (Item     : in out Queue;
      Data     : Byte_Array;
      Accepted : out Byte_Index)
     with Post => Accepted <= Data'Length;

   --  Copy the front of the queue without consuming it.
   --  @param Item   the queue to read
   --  @param Into   out: receives up to Into'Length octets
   --  @param Copied out: how many octets were written to Into
   procedure Peek (Item : Queue; Into : out Byte_Array; Copied : out Byte_Index)
     with Post => Copied <= Into'Length;

   --  Copy a run from the front of the queue at an offset, for looking at a
   --  record header before deciding whether the whole record has arrived.
   --  @param Item   the queue to read
   --  @param Offset octets to skip from the front, zero-based
   --  @param Into   out: receives Into'Length octets
   --  @param Ok     out: False when fewer than Offset + Into'Length octets are
   --    queued, in which case Into is zeroed
   procedure Peek_At
     (Item   : Queue;
      Offset : Byte_Index;
      Into   : out Byte_Array;
      Ok     : out Boolean);

   --  Discard octets from the front.
   --  @param Item  the queue to consume from
   --  @param Count how many octets to discard
   procedure Consume (Item : in out Queue; Count : Byte_Index)
     with Pre => Count <= Length (Item);

   --  Copy and consume in one step.
   --  @param Item the queue to read from
   --  @param Into out: receives Into'Length octets
   procedure Take (Item : in out Queue; Into : out Byte_Array)
     with Pre => Into'Length <= Length (Item);

   --  A copy of everything queued. Used where a whole message is needed as a
   --  value; bounded by the queue's capacity, which is bounded by policy.
   function Contents (Item : Queue) return Byte_Array
     with Post => Contents'Result'Length = Length (Item);

   --  Discard everything and zero the storage. For a queue that has held
   --  plaintext or a secret.
   procedure Wipe (Item : in out Queue);

   --  Discard everything without scrubbing, for a queue holding only
   --  ciphertext already sent.
   procedure Clear (Item : in out Queue);

   --  Overwrite and release the storage now.
   procedure Release (Item : in out Queue);

private

   type Storage is access Byte_Array;

   type Store is new Ada.Finalization.Limited_Controlled with record
      Data : Storage := null;
   end record;

   overriding procedure Finalize (Item : in out Store);

   type Queue is new Ada.Finalization.Limited_Controlled with record
      Data : Storage := null;

      --  Head is the position of the next octet to be consumed; Tail is one
      --  past the last octet appended. Both are one-based positions into
      --  Data.all. Head = Tail means empty.
      Head : Byte_Index := 1;
      Tail : Byte_Index := 1;
   end record;

   overriding procedure Finalize (Item : in out Queue);

end SSL.Buffers;
