package body Tests_Mutation is

   use type SSL.Byte;

   ---------------
   -- Image --
   ---------------

   function Image (Item : Mutation_Kind) return String is
     (case Item is
         when Bit_Flip       => "bit flip",
         when Truncate       => "truncate",
         when Insert_Octet   => "insert octet",
         when Delete_Octet   => "delete octet",
         when Corrupt_Length => "corrupt length",
         when Zero_Length    => "zero length");

   ---------------------
   -- Case_Count --
   ---------------------

   function Case_Count
     (Kind : Mutation_Kind; Length : SSL.Byte_Index) return Natural
   is
   begin
      case Kind is
         when Bit_Flip =>
            --  Every bit of every octet.
            return Natural (Length) * 8;

         when Truncate =>
            --  Every length from zero to one short of complete. A truncation to
            --  the full length is not a mutation.
            return Natural (Length);

         when Insert_Octet | Delete_Octet =>
            return Natural (Length);

         when Corrupt_Length | Zero_Length =>
            --  Every position that could be part of a length field. Which
            --  positions actually are is the parser's business; trying them all
            --  is cheaper than modelling the format here, and it is the same
            --  answer.
            return Natural (Length);
      end case;
   end Case_Count;

   ----------------
   -- Mutate --
   ----------------

   procedure Mutate
     (Seed   : SSL.Byte_Array;
      Kind   : Mutation_Kind;
      Index  : Positive;
      Into   : out SSL.Byte_Array;
      Length : out SSL.Byte_Index)
   is
      use type SSL.Byte_Index;
   begin
      Into := [others => 0];
      Length := 0;

      case Kind is
         when Bit_Flip =>
            declare
               Position : constant SSL.Byte_Index :=
                 SSL.Byte_Index ((Index - 1) / 8) + 1;
               Bit      : constant Natural := (Index - 1) mod 8;
            begin
               if Position > Seed'Length then
                  return;
               end if;
               Into (Into'First .. Into'First + Seed'Length - 1) := Seed;
               Into (Into'First + Position - 1) :=
                 Into (Into'First + Position - 1) xor SSL.Byte (2 ** Bit);
               Length := Seed'Length;
            end;

         when Truncate =>
            declare
               Keep : constant SSL.Byte_Index := SSL.Byte_Index (Index) - 1;
            begin
               if Keep >= Seed'Length then
                  return;
               end if;
               if Keep > 0 then
                  Into (Into'First .. Into'First + Keep - 1) :=
                    Seed (Seed'First .. Seed'First + Keep - 1);
               end if;
               Length := Keep;
            end;

         when Insert_Octet =>
            declare
               At_Position : constant SSL.Byte_Index := SSL.Byte_Index (Index);
            begin
               if At_Position > Seed'Length then
                  return;
               end if;
               Into (Into'First .. Into'First + At_Position - 2) :=
                 Seed (Seed'First .. Seed'First + At_Position - 2);
               --  A value chosen from the index rather than a constant, so that
               --  the inserted octet is not always the same and a parser cannot
               --  pass by ignoring one particular value.
               Into (Into'First + At_Position - 1) := SSL.Byte (Index mod 256);
               Into (Into'First + At_Position .. Into'First + Seed'Length) :=
                 Seed (Seed'First + At_Position - 1 .. Seed'Last);
               Length := Seed'Length + 1;
            end;

         when Delete_Octet =>
            declare
               At_Position : constant SSL.Byte_Index := SSL.Byte_Index (Index);
            begin
               if At_Position > Seed'Length then
                  return;
               end if;
               if At_Position > 1 then
                  Into (Into'First .. Into'First + At_Position - 2) :=
                    Seed (Seed'First .. Seed'First + At_Position - 2);
               end if;
               if At_Position < Seed'Length then
                  Into (Into'First + At_Position - 1
                        .. Into'First + Seed'Length - 2) :=
                    Seed (Seed'First + At_Position .. Seed'Last);
               end if;
               Length := Seed'Length - 1;
            end;

         when Corrupt_Length =>
            declare
               Position : constant SSL.Byte_Index := SSL.Byte_Index (Index);
            begin
               if Position > Seed'Length then
                  return;
               end if;
               Into (Into'First .. Into'First + Seed'Length - 1) := Seed;
               --  0xFF, which makes every length field it lands in as large as
               --  that field can express. A parser that bounds a declared length
               --  before using it refuses; one that allocates first does not.
               Into (Into'First + Position - 1) := 16#FF#;
               Length := Seed'Length;
            end;

         when Zero_Length =>
            declare
               Position : constant SSL.Byte_Index := SSL.Byte_Index (Index);
            begin
               if Position > Seed'Length then
                  return;
               end if;
               Into (Into'First .. Into'First + Seed'Length - 1) := Seed;
               Into (Into'First + Position - 1) := 0;
               Length := Seed'Length;
            end;
      end case;
   end Mutate;

end Tests_Mutation;
