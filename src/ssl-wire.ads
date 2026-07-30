with Interfaces;

--  @summary Explicit octet-by-octet codecs for every TLS wire structure, with
--  bounded cursors that fail rather than raise.
--
--  There is no unchecked conversion of wire octets into an Ada record anywhere
--  in this library, and this package is why there does not need to be. Every
--  integer is assembled from its octets in the order the protocol states, every
--  variable-length vector is read through a sub-cursor that cannot see past its
--  own length prefix, and every read that would go past the end sets a failure
--  flag instead of raising Constraint_Error.
--
--  The failure flag is sticky. A parser can issue a run of reads and check once
--  at the end: after the first failure every subsequent read is a no-op that
--  yields zero, so a partly-parsed structure never carries values read from
--  beyond its bounds. That is what makes incremental parsing at every byte
--  boundary tractable -- the alternative, a check after each read, is the shape
--  of code where one missing check is a buffer overread.
--
--  Cursors carry absolute positions into the caller's array, so a sub-cursor
--  over a slice and a cursor over the whole message index the same octets and
--  no offset arithmetic is duplicated at the call sites.
private package SSL.Wire is

   ---------------------------------------------------------------------------
   --  Reading
   ---------------------------------------------------------------------------

   --  A read position within a Byte_Array, with a sticky validity flag.
   --
   --  Position is the next octet to be read. Last is the last octet this cursor
   --  is allowed to read, which for a sub-cursor is the end of its vector and
   --  not the end of the underlying array.
   type Cursor is record
      Position : Byte_Index := 1;
      Last     : Byte_Index := 0;
      Valid    : Boolean := True;
   end record;

   --  A cursor over the whole of Data.
   --  @param Data the octets to read
   --  @return a valid cursor positioned at the first octet
   function Reader (Data : Byte_Array) return Cursor
     with Post => Is_Valid (Reader'Result);

   --  A cursor over a stated range of Data, for parsing a structure whose
   --  bounds were already established.
   --  @param First the first readable octet
   --  @param Last  the last readable octet; Last < First is an empty cursor
   --  @return a valid cursor
   function Reader (First : Byte_Index; Last : Byte_Index) return Cursor
     with Post => Is_Valid (Reader'Result);

   --  Has every read so far succeeded?
   function Is_Valid (Item : Cursor) return Boolean;

   --  Octets left to read; zero for an invalid cursor.
   function Remaining (Item : Cursor) return Byte_Index;

   --  Is the cursor exactly at the end of its range?
   --
   --  Parsers use this to enforce that a structure is fully consumed: trailing
   --  octets inside a length-prefixed field are a protocol violation, not
   --  padding, and a parser that ignores them accepts messages a conforming
   --  peer would not send.
   function At_End (Item : Cursor) return Boolean;

   --  Mark the cursor failed. For a parser that has read a well-formed field
   --  whose value is not acceptable.
   procedure Fail (Item : in out Cursor)
     with Post => not Is_Valid (Item);

   --  Read one octet as a number in 0 .. 255.
   procedure Get_UInt8 (Data : Byte_Array; Item : in out Cursor; Value : out Natural)
     with Post => Value <= 255;

   --  Read one octet.
   procedure Get_Byte (Data : Byte_Array; Item : in out Cursor; Value : out Byte);

   --  Read two octets, big-endian.
   procedure Get_UInt16 (Data : Byte_Array; Item : in out Cursor; Value : out Natural)
     with Post => Value <= 65_535;

   --  Read three octets, big-endian: the TLS handshake message length and the
   --  certificate list lengths.
   procedure Get_UInt24 (Data : Byte_Array; Item : in out Cursor; Value : out Byte_Index)
     with Post => Value <= 16#FF_FFFF#;

   --  Read four octets, big-endian.
   procedure Get_UInt32
     (Data : Byte_Array; Item : in out Cursor; Value : out Interfaces.Unsigned_32);

   --  Read eight octets, big-endian.
   procedure Get_UInt64
     (Data : Byte_Array; Item : in out Cursor; Value : out Interfaces.Unsigned_64);

   --  Take Count octets, reporting where they are rather than copying them.
   --  First .. Last is the range within Data; a zero Count gives a null range.
   --  @param Data  the octets being read
   --  @param Item  the cursor, advanced past the run
   --  @param Count how many octets to take
   --  @param First out: the first octet of the run
   --  @param Last  out: the last octet of the run
   procedure Get_Span
     (Data  : Byte_Array;
      Item  : in out Cursor;
      Count : Byte_Index;
      First : out Byte_Index;
      Last  : out Byte_Index);

   --  Copy Into'Length octets out.
   procedure Get_Bytes (Data : Byte_Array; Item : in out Cursor; Into : out Byte_Array);

   --  Advance past Count octets without reading them.
   procedure Skip (Data : Byte_Array; Item : in out Cursor; Count : Byte_Index);

   --  Read a length-prefixed vector and hand back a cursor confined to its
   --  body. The outer cursor is advanced past the whole vector, so a caller
   --  that ignores the sub-cursor still parses the rest of the message
   --  correctly.
   --
   --  Limit is the largest body this caller will accept; a longer one fails the
   --  outer cursor rather than being read. That is the check that keeps a
   --  declared length from becoming an allocation: the bound is applied to the
   --  number, before anything is done with it.
   --  @param Data  the octets being read
   --  @param Item  the outer cursor
   --  @param Limit the largest acceptable body length
   --  @param Body_Cursor out: a cursor over the body, invalid if the outer
   --    cursor failed
   procedure Open_Vector_8
     (Data        : Byte_Array;
      Item        : in out Cursor;
      Limit       : Byte_Index;
      Body_Cursor : out Cursor);

   procedure Open_Vector_16
     (Data        : Byte_Array;
      Item        : in out Cursor;
      Limit       : Byte_Index;
      Body_Cursor : out Cursor);

   procedure Open_Vector_24
     (Data        : Byte_Array;
      Item        : in out Cursor;
      Limit       : Byte_Index;
      Body_Cursor : out Cursor);

   ---------------------------------------------------------------------------
   --  Writing
   ---------------------------------------------------------------------------

   --  A write position within a Byte_Array, with a sticky validity flag. A
   --  write that would not fit sets the flag rather than raising, so a message
   --  builder checks once at the end and never emits a truncated structure.
   type Emitter is record
      Origin   : Byte_Index := 1;
      Position : Byte_Index := 1;
      Last     : Byte_Index := 0;
      Valid    : Boolean := True;
   end record;

   --  An emitter over the whole of Data.
   function Writer (Data : Byte_Array) return Emitter
     with Post => Is_Valid (Writer'Result);

   function Is_Valid (Item : Emitter) return Boolean;

   --  How many octets have been written.
   function Written (Item : Emitter) return Byte_Index;

   --  How many octets are still free.
   function Free_Space (Item : Emitter) return Byte_Index;

   --  Mark the emitter failed.
   procedure Fail (Item : in out Emitter)
     with Post => not Is_Valid (Item);

   procedure Put_UInt8 (Data : in out Byte_Array; Item : in out Emitter; Value : Natural)
     with Pre => Value <= 255;

   procedure Put_Byte (Data : in out Byte_Array; Item : in out Emitter; Value : Byte);

   procedure Put_UInt16 (Data : in out Byte_Array; Item : in out Emitter; Value : Natural)
     with Pre => Value <= 65_535;

   procedure Put_UInt24 (Data : in out Byte_Array; Item : in out Emitter; Value : Byte_Index)
     with Pre => Value <= 16#FF_FFFF#;

   procedure Put_UInt32
     (Data : in out Byte_Array; Item : in out Emitter; Value : Interfaces.Unsigned_32);

   procedure Put_UInt64
     (Data : in out Byte_Array; Item : in out Emitter; Value : Interfaces.Unsigned_64);

   procedure Put_Bytes (Data : in out Byte_Array; Item : in out Emitter; Value : Byte_Array);

   --  Write Count zero octets.
   procedure Put_Zeroes (Data : in out Byte_Array; Item : in out Emitter; Count : Byte_Index);

   --  Reserve room for a length prefix and remember where it is. The matching
   --  Close writes the length of everything emitted in between.
   --
   --  Deferred prefixes rather than two passes: a TLS message is a nest of
   --  length-prefixed vectors, and computing every length before emitting
   --  anything means encoding the structure twice and keeping the two
   --  encodings in agreement. One pass with back-patching cannot disagree with
   --  itself.
   --  @param Data the buffer being written
   --  @param Item the emitter
   --  @param Mark out: the position of the reserved prefix
   procedure Open_Vector_8
     (Data : in out Byte_Array; Item : in out Emitter; Mark : out Byte_Index);

   procedure Open_Vector_16
     (Data : in out Byte_Array; Item : in out Emitter; Mark : out Byte_Index);

   procedure Open_Vector_24
     (Data : in out Byte_Array; Item : in out Emitter; Mark : out Byte_Index);

   --  Back-patch the length prefix reserved at Mark. Fails the emitter when
   --  the body turned out longer than the prefix can express, which is how an
   --  over-long structure is refused at encode time rather than sent as a
   --  truncated one.
   procedure Close_Vector_8
     (Data : in out Byte_Array; Item : in out Emitter; Mark : Byte_Index);

   procedure Close_Vector_16
     (Data : in out Byte_Array; Item : in out Emitter; Mark : Byte_Index);

   procedure Close_Vector_24
     (Data : in out Byte_Array; Item : in out Emitter; Mark : Byte_Index);

   ---------------------------------------------------------------------------
   --  Fixed-width integer helpers
   ---------------------------------------------------------------------------

   --  Encode a 64-bit value big-endian into exactly eight octets, for the
   --  record-layer nonce construction.
   --  @param Value the value to encode
   --  @return the eight octets, most significant first
   function Encode_UInt64 (Value : Interfaces.Unsigned_64) return Byte_Array
     with Post => Encode_UInt64'Result'Length = 8;

   --  Encode a 16-bit value big-endian into exactly two octets.
   function Encode_UInt16 (Value : Natural) return Byte_Array
     with Pre => Value <= 65_535, Post => Encode_UInt16'Result'Length = 2;

   --  Decode two octets big-endian.
   function Decode_UInt16 (Data : Byte_Array) return Natural
     with Pre => Data'Length = 2, Post => Decode_UInt16'Result <= 65_535;

   --  Decode three octets big-endian.
   function Decode_UInt24 (Data : Byte_Array) return Byte_Index
     with Pre => Data'Length = 3, Post => Decode_UInt24'Result <= 16#FF_FFFF#;

end SSL.Wire;
