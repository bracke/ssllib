with SSL;

--  @summary A deterministic mutation runner: take a message this library
--  accepts, damage it in every way an attacker might, and require that every
--  result is a structured refusal rather than a crash.
--
--  Not a fuzzer in the usual sense. A fuzzer explores; this enumerates. Given a
--  seed message it produces every single-bit flip, every truncation, every
--  duplicated and reordered extension and every corrupted length, and it does
--  so identically on every machine and every run. That determinism is the point:
--  a failure found here is reproducible from its index alone, and a corpus entry
--  is a number rather than a blob nobody can regenerate.
--
--  What a parser is allowed to do with a damaged message is exactly three
--  things:
--
--    * accept it, when the damage happened to land somewhere that does not
--      change the meaning -- a reserved octet, a field this library ignores;
--    * refuse it with a structured failure;
--    * ask for more input, when the damage made it shorter than a complete
--      message.
--
--  Anything else -- an unhandled exception, an unbounded loop, a partly-filled
--  result treated as complete -- is a bug, and this runner exists to find it.
package Tests_Mutation is

   use type SSL.Byte_Index;

   --  How a seed is damaged.
   type Mutation_Kind is
     (Bit_Flip,
      --  One bit, at one position. The classic, and the one that finds
      --  length fields treated as trusted.

      Truncate,
      --  Cut at one position. Finds parsers that read past what arrived, and
      --  parsers that accept a prefix as a complete shorter message.

      Insert_Octet,
      --  One extra octet, which shifts everything after it. Finds parsers whose
      --  declared lengths and actual lengths are checked in different places.

      Delete_Octet,
      --  One octet removed, the mirror of the above.

      Corrupt_Length,
      --  A declared length replaced with a large one. Finds the difference
      --  between "bounded before allocation" and "bounded after".

      Zero_Length);
      --  A declared length replaced with zero. Finds parsers that assume a
      --  field is non-empty because it always has been.

   function Image (Item : Mutation_Kind) return String;

   --  The largest seed this runner handles.
   Maximum_Seed : constant SSL.Byte_Index := 8_192;

   --  How many mutations a seed of this length produces, for one kind.
   function Case_Count
     (Kind : Mutation_Kind; Length : SSL.Byte_Index) return Natural;

   --  Produce one mutation.
   --
   --  Deterministic in every argument: the same seed, kind and index always
   --  give the same octets, on every machine and every run. A failure is
   --  therefore reproducible from the three numbers, and a corpus entry needs
   --  no stored blob.
   --  @param Seed    the message to damage
   --  @param Kind    how
   --  @param Index   which one, from one to Case_Count
   --  @param Into    out: the damaged message
   --  @param Length  out: how long it is, which may differ from the seed's
   procedure Mutate
     (Seed   : SSL.Byte_Array;
      Kind   : Mutation_Kind;
      Index  : Positive;
      Into   : out SSL.Byte_Array;
      Length : out SSL.Byte_Index)
     with Pre => Seed'Length in 1 .. Maximum_Seed
                 and then Into'Length >= Seed'Length + 1;

end Tests_Mutation;
