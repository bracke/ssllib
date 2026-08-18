with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Unchecked_Deallocation;

with CryptoLib.PEM;

with Truststores;

with SSL.Crypto;

package body SSL.Trust is

   use type CryptoLib.PEM.Decode_Status;

   procedure Free is new Ada.Unchecked_Deallocation (Span_Array, Span_Storage);
   procedure Free is new Ada.Unchecked_Deallocation (Byte_Array, Octet_Storage);

   -----------
   -- Image --
   -----------

   function Image (Item : Anchor_Source) return String is
   begin
      case Item is
         when Native_System  => return "native_system";
         when NSS_Database   => return "nss_database";
         when Java_Keystore  => return "java_keystore";
         when Explicit_PEM   => return "explicit_pem";
      end case;
   end Image;

   ---------------
   -- Accessors --
   ---------------

   function Is_Built (Item : Snapshot) return Boolean is (Item.Built);
   function Anchor_Count (Item : Snapshot) return Natural is (Item.Count);

   function Anchor_At (Item : Snapshot; Index : Positive) return Byte_Array
   is (Item.Octets (Item.Spans (Index).First .. Item.Spans (Index).Last));

   function Fingerprint (Item : Snapshot) return Trust_Fingerprint is (Item.Digest);
   function Taken_At (Item : Snapshot) return SSL.Clocks.Wall_Time is (Item.Stamp);
   function Includes (Item : Snapshot; Source : Anchor_Source) return Boolean
   is (Item.Sources (Source));

   -------------
   -- Release --
   -------------

   procedure Release (Item : in out Snapshot) is
   begin
      Free (Item.Spans);
      Free (Item.Octets);
      Item.Built := False;
      Item.Count := 0;
      Item.Held := 0;
      Item.Sources := [others => False];
   end Release;

   overriding procedure Finalize (Item : in out Snapshot) is
   begin
      Release (Item);
   end Finalize;

   ---------------------------------------------------------------------------
   --  Loading
   ---------------------------------------------------------------------------

   --  Make room for the anchor index, keeping whatever is already there.
   --
   --  Only the index. The octets are grown to fit by Ensure_Room as each
   --  source is absorbed, because how much a store needs is a property of what
   --  is put in it and nothing here knows that before it arrives.
   procedure Reserve
     (Item   : in out Snapshot;
      Bounds : SSL.Limits.Resource_Limits;
      Ok     : out Boolean);

   procedure Reserve
     (Item   : in out Snapshot;
      Bounds : SSL.Limits.Resource_Limits;
      Ok     : out Boolean)
   is
   begin
      Ok := True;
      if Item.Spans /= null then
         return;
      end if;

      begin
         Item.Spans := new Span_Array (1 .. Bounds.Maximum_Trust_Anchors);
      exception
         when Storage_Error =>
            Free (Item.Spans);
            Ok := False;
      end;
   end Reserve;

   --  Grow the anchor storage so that Needed more octets fit after what is
   --  already held.
   --
   --  This used to be one flat allocation of Maximum_Anchor_Octets -- four
   --  megabytes -- taken before a single certificate had been seen, whatever
   --  the store turned out to hold. A platform store of a hundred-odd anchors
   --  is a few hundred kilobytes, so nearly all of it was never touched, and
   --  every snapshot paid for it. The ceiling is still a ceiling: it bounds
   --  what a store may grow to, rather than what every store costs.
   --
   --  Growth copies. That is deliberate rather than reluctant: absorbing
   --  happens once per source -- system, NSS, Java, explicit -- so a snapshot
   --  reallocates a handful of times over its life and never in a loop.
   --  @param Item   the snapshot
   --  @param Needed how many more octets must fit
   --  @param Ok     out: False when the ceiling is reached or memory ran out
   procedure Ensure_Room
     (Item   : in out Snapshot;
      Needed : Byte_Index;
      Ok     : out Boolean);

   procedure Ensure_Room
     (Item   : in out Snapshot;
      Needed : Byte_Index;
      Ok     : out Boolean)
   is
      Wanted : Byte_Index;
   begin
      Ok := True;

      if Needed = 0 and then Item.Octets /= null then
         return;
      end if;

      Wanted := Byte_Index'Max (Item.Held + Needed, 1);

      if Item.Octets /= null and then Item.Octets'Last >= Wanted then
         return;
      end if;

      if Wanted > Maximum_Anchor_Octets then
         --  The ceiling holds. A store larger than policy allows is refused
         --  rather than truncated, for the same reason the anchor count is.
         Ok := False;
         return;
      end if;

      declare
         Grown : Octet_Storage;
      begin
         Grown := new Byte_Array (1 .. Wanted);
         Grown.all := [others => 0];

         if Item.Octets /= null then
            if Item.Held > 0 then
               Grown (1 .. Item.Held) := Item.Octets (1 .. Item.Held);
            end if;
            Free (Item.Octets);
         end if;

         Item.Octets := Grown;
      exception
         when Storage_Error =>
            Ok := False;
      end;
   end Ensure_Room;

   function Held_Octets (Item : Snapshot) return Byte_Index is (Item.Held);

   function Allocated_Octets (Item : Snapshot) return Byte_Index is
     (if Item.Octets = null then 0 else Item.Octets'Length);

   --  Recompute the fingerprint over every anchor in load order.
   procedure Restamp (Item : in out Snapshot);

   procedure Restamp (Item : in out Snapshot) is
   begin
      --  Over the concatenated DER, in the order the anchors were loaded. Order
      --  matters and is not normalized away: two snapshots holding the same
      --  anchors in a different order are different trust bases as far as
      --  reproducibility is concerned, and pretending otherwise would let a
      --  reordering pass unnoticed.
      if Item.Octets = null or else Item.Held = 0 then
         --  An empty store still has a fingerprint, and it is the digest of
         --  nothing rather than a special value: the storage simply has not
         --  been allocated yet.
         Item.Digest := (Digest => SSL.Crypto.SHA_256 (Empty_Bytes));
      else
         Item.Digest :=
           (Digest => SSL.Crypto.SHA_256 (Item.Octets (1 .. Item.Held)));
      end if;
   end Restamp;

   --  Decode a PEM blob's CERTIFICATE blocks into the snapshot.
   procedure Absorb_PEM
     (Item   : in out Snapshot;
      PEM    : String;
      Source : Anchor_Source;
      Bounds : SSL.Limits.Resource_Limits;
      Added  : out Natural;
      Error  : out SSL.Errors.Error_Information);

   procedure Absorb_PEM
     (Item   : in out Snapshot;
      PEM    : String;
      Source : Anchor_Source;
      Bounds : SSL.Limits.Resource_Limits;
      Added  : out Natural;
      Error  : out SSL.Errors.Error_Information)
   is
      From   : Positive := PEM'First;
      Status : CryptoLib.PEM.Decode_Status;
      Ok     : Boolean;
   begin
      Added := 0;
      Error := SSL.Errors.No_Error;

      Reserve (Item, Bounds, Ok);
      if not Ok then
         Error := SSL.Errors.Make
           (Code   => SSL.Errors.Code_Storage_Exhausted,
            Origin => SSL.Errors.Local_Implementation);
         return;
      end if;

      --  Sized to this text before anything is decoded from it.
      --  Maximum_Decoded_Length is an exact upper bound on what base64 of this
      --  length can produce, so one growth covers every block in it.
      Ensure_Room
        (Item, Byte_Index (CryptoLib.PEM.Maximum_Decoded_Length (PEM)), Ok);
      if not Ok then
         Error := SSL.Errors.Make
           (Code   => SSL.Errors.Code_Storage_Exhausted,
            Origin => SSL.Errors.Local_Policy);
         return;
      end if;

      loop
         exit when From > PEM'Last;

         if Item.Count = Bounds.Maximum_Trust_Anchors then
            --  A trust store larger than policy allows is refused rather than
            --  truncated. A silently shortened trust base is one that rejects
            --  certificates for a reason nobody can see.
            Error := SSL.Errors.Limit_Failure
              (Kind      => SSL.Limits.Trust_Anchors,
               Allowed   => Long_Long_Integer (Bounds.Maximum_Trust_Anchors),
               Requested => Long_Long_Integer (Item.Count) + 1,
               Origin    => SSL.Errors.Local_Policy,
               Stage     => SSL.Errors.Stage_Uninitialized);
            return;
         end if;

         --  Decoded straight into the store, with no temporary at all.
         --
         --  There was one, sized `Maximum_Anchor_Octets - Item.Held` -- the
         --  whole remaining capacity of the store -- to hold a single
         --  certificate, and it was declared inside this loop. That is a
         --  multi-megabyte stack frame per anchor, which overflows any
         --  ordinary task stack: it only ever survived because the one caller
         --  that exercised it ran near the top of an environment task. A
         --  buffer for one certificate never needed to be the size of the
         --  store, and the store's own storage is on the heap already, so the
         --  right size for the temporary turned out to be none.
         declare
            Room : constant Byte_Index := Item.Octets'Last - Item.Held;
            Last : Byte_Index;
         begin
            if Room = 0 then
               --  Full. Refused rather than truncated, for the same reason the
               --  anchor-count limit above is.
               Error := SSL.Errors.Make
                 (Code   => SSL.Errors.Code_Storage_Exhausted,
                  Origin => SSL.Errors.Local_Policy);
               return;
            end if;

            CryptoLib.PEM.Decode_Block
              (Text   => PEM,
               Label  => CryptoLib.PEM.Certificate_Label,
               From   => From,
               Output => Item.Octets (Item.Held + 1 .. Item.Held + Room),
               Last   => Last,
               Status => Status);

            exit when Status = CryptoLib.PEM.No_Block_Found;

            --  `Last` is an index into the slice that was passed, not a
            --  length, and that slice now starts at Item.Held + 1 rather than
            --  at 1. So the certificate occupies Item.Held + 1 .. Last and its
            --  length is Last - Item.Held.
            if Status /= CryptoLib.PEM.Ok then
               --  One malformed block in a trust store is not a reason to
               --  discard the store: system stores accumulate oddities, and an
               --  anchor that cannot be decoded simply is not an anchor. It is
               --  skipped, and Decode_Block has already advanced past it.
               --
               --  Whatever it wrote past Item.Held stays there and is
               --  unreachable: no span covers it, and the next anchor decodes
               --  over it.
               null;
            elsif Last <= Item.Held then
               --  Nothing written, which Decode_Block reports as Output'First
               --  minus one.
               null;
            elsif Last - Item.Held > Byte_Index (Bounds.Maximum_Certificate) then
               null;
            else
               Item.Count := Item.Count + 1;
               Item.Spans (Item.Count) := (First => Item.Held + 1, Last => Last);
               Item.Held := Last;
               Added := Added + 1;
            end if;
         end;
      end loop;

      if Added > 0 then
         Item.Sources (Source) := True;
      end if;
   end Absorb_PEM;

   ----------------------------
   -- Load_System_Anchors --
   ----------------------------

   --  How many certificates a PEM text holds.
   --
   --  By its armour rather than by decoding: what this is for is telling a
   --  caller how large the store it just read is, and a text this endpoint
   --  will not accept should not have to be decoded first to say so.
   function Count_Certificates (Text : String) return Natural;

   function Count_Certificates (Text : String) return Natural is
      Marker : constant String := "-----BEGIN CERTIFICATE-----";
      From   : Positive := Text'First;
      Found  : Natural := 0;
   begin
      loop
         declare
            At_One : constant Natural :=
              Ada.Strings.Fixed.Index (Text, Marker, From);
         begin
            exit when At_One = 0;
            Found := Found + 1;
            exit when At_One + Marker'Length > Text'Last;
            From := At_One + Marker'Length;
         end;
      end loop;

      return Found;
   end Count_Certificates;

   procedure Load_System_Anchors
     (Item    : in out Snapshot;
      At_Time : SSL.Clocks.Wall_Time;
      Bounds  : SSL.Limits.Resource_Limits;
      Error   : out SSL.Errors.Error_Information)
   is
      Added : Natural;
   begin
      Release (Item);
      Item.Stamp := At_Time;

      declare
         --  Where a host keeps its anchors and how they are read is entirely
         --  Truststores'. This library asks and bounds the answer.
         Text : constant String :=
           Ada.Strings.Unbounded.To_String (Truststores.System_Anchors);
      begin
         if Text'Length = 0 then
            Error := SSL.Errors.Make
              (Code     => SSL.Errors.Code_System_Trust_Unavailable,
               Origin   => SSL.Errors.Local_Policy,
               Provider => "truststores returned no system anchor material");
            return;
         end if;

         --  Counted before it is absorbed, so that a store the configuration
         --  cannot hold is said as what it is.
         --
         --  Absorbing answers with a limit failure -- "allowed 512, requested
         --  513" -- which describes the moment it stopped rather than the
         --  situation: this host has 563 roots and these bounds allow 512, and
         --  the store is not going to shrink. A caller reading the first
         --  cannot tell whether to raise a bound or look at its trust source;
         --  a caller reading the second can.
         declare
            Held : constant Natural := Count_Certificates (Text);
         begin
            if Held > Bounds.Maximum_Trust_Anchors then
               Error := SSL.Errors.Make
                 (Code     => SSL.Errors.Code_System_Trust_Exceeds_Bound,
                  Origin   => SSL.Errors.Local_Policy,
                  Provider =>
                    "the system trust store holds"
                    & Natural'Image (Held)
                    & " anchors; these bounds allow"
                    & Natural'Image (Bounds.Maximum_Trust_Anchors));
               return;
            end if;
         end;

         Absorb_PEM (Item, Text, Native_System, Bounds, Added, Error);
         if SSL.Errors.Is_Error (Error) then
            return;
         end if;

         --  An answer with nothing usable in it fails closed. Proceeding with
         --  an empty trust base would turn a misconfiguration into an
         --  unauthenticated connection.
         if Added = 0 then
            Error := SSL.Errors.Make
              (Code     => SSL.Errors.Code_Trust_Source_Empty,
               Origin   => SSL.Errors.Local_Policy,
               Provider => "the system trust store yielded no usable anchor");
            return;
         end if;
      end;

      Restamp (Item);
      Item.Built := True;
      Error := SSL.Errors.No_Error;
   end Load_System_Anchors;

   -------------------------
   -- Add_NSS_Anchors --
   -------------------------

   procedure Add_NSS_Anchors
     (Item   : in out Snapshot;
      Bounds : SSL.Limits.Resource_Limits;
      Error  : out SSL.Errors.Error_Information)
   is
      Added : Natural;
      Text  : constant String :=
        Ada.Strings.Unbounded.To_String (Truststores.NSS_Anchors);
   begin
      if Text'Length = 0 then
         Error := SSL.Errors.Make
           (Code     => SSL.Errors.Code_Trust_Source_Empty,
            Origin   => SSL.Errors.Local_Policy,
            Provider => "the selected NSS database yielded no anchor material");
         return;
      end if;

      Absorb_PEM (Item, Text, NSS_Database, Bounds, Added, Error);
      if not SSL.Errors.Is_Error (Error) then
         Restamp (Item);
      end if;
   end Add_NSS_Anchors;

   --------------------------
   -- Add_Java_Anchors --
   --------------------------

   procedure Add_Java_Anchors
     (Item   : in out Snapshot;
      Bounds : SSL.Limits.Resource_Limits;
      Error  : out SSL.Errors.Error_Information)
   is
      Added : Natural;
      Text  : constant String :=
        Ada.Strings.Unbounded.To_String (Truststores.Java_Anchors);
   begin
      if Text'Length = 0 then
         Error := SSL.Errors.Make
           (Code     => SSL.Errors.Code_Trust_Source_Empty,
            Origin   => SSL.Errors.Local_Policy,
            Provider => "the selected Java keystore yielded no anchor material");
         return;
      end if;

      Absorb_PEM (Item, Text, Java_Keystore, Bounds, Added, Error);
      if not SSL.Errors.Is_Error (Error) then
         Restamp (Item);
      end if;
   end Add_Java_Anchors;

   -------------------------------
   -- Load_Explicit_Anchors --
   -------------------------------

   procedure Load_Explicit_Anchors
     (Item    : in out Snapshot;
      PEM     : String;
      At_Time : SSL.Clocks.Wall_Time;
      Bounds  : SSL.Limits.Resource_Limits;
      Error   : out SSL.Errors.Error_Information)
   is
      Added : Natural;
   begin
      Release (Item);
      Item.Stamp := At_Time;

      Absorb_PEM (Item, PEM, Explicit_PEM, Bounds, Added, Error);
      if SSL.Errors.Is_Error (Error) then
         return;
      end if;

      if Added = 0 then
         Error := SSL.Errors.Make
           (Code     => SSL.Errors.Code_Trust_Source_Empty,
            Origin   => SSL.Errors.Local_Policy,
            Provider => "no usable CERTIFICATE block in the supplied text");
         return;
      end if;

      Restamp (Item);
      Item.Built := True;
      Error := SSL.Errors.No_Error;
   end Load_Explicit_Anchors;

   ------------------------------
   -- Add_Explicit_Anchors --
   ------------------------------

   procedure Add_Explicit_Anchors
     (Item   : in out Snapshot;
      PEM    : String;
      Bounds : SSL.Limits.Resource_Limits;
      Error  : out SSL.Errors.Error_Information)
   is
      Added : Natural;
   begin
      Absorb_PEM (Item, PEM, Explicit_PEM, Bounds, Added, Error);
      if not SSL.Errors.Is_Error (Error) then
         Restamp (Item);
      end if;
   end Add_Explicit_Anchors;

end SSL.Trust;
