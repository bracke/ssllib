package body SSL.Sessions.Client_Caches.Memory is

   use type SSL.Server_Names.DNS_Name;

   --------------------------
   -- Store_Object --
   --------------------------

   protected body Store_Object is

      --  Which slot holds a session for this name and context, or zero.
      function Locate
        (Name : SSL.Server_Names.DNS_Name; Context : Security_Context_ID) return Natural;

      function Locate
        (Name : SSL.Server_Names.DNS_Name; Context : Security_Context_ID) return Natural
      is
      begin
         for Index in Entries'Range loop
            if Entries (Index).Used
              and then Server_Name (Entries (Index).Value) = Name
              and then Security_Context (Entries (Index).Value) = Context
            then
               return Index;
            end if;
         end loop;
         return 0;
      end Locate;

      procedure Look_Up
        (Name    : SSL.Server_Names.DNS_Name;
         Context : Security_Context_ID;
         At_Time : SSL.Clocks.Wall_Time;
         Into    : in out Session;
         Found   : out Boolean)
      is
         Slot : constant Natural := Locate (Name, Context);
      begin
         Found := False;

         if Slot = 0 then
            return;
         end if;

         if not Is_Live (Entries (Slot).Value, At_Time) then
            --  Expired. Dropped here rather than left for the eviction pass,
            --  so that a cache full of dead entries does not evict live ones to
            --  make room.
            Wipe (Entries (Slot).Value);
            Entries (Slot).Used := False;
            return;
         end if;

         --  A TLS 1.3 ticket is single-use: offering one twice is what makes
         --  two connections linkable to an observer, which is the whole reason
         --  the age is obfuscated. So the entry goes as it is handed out.
         Copy (Into, Entries (Slot).Value);
         Wipe (Entries (Slot).Value);
         Entries (Slot).Used := False;
         Found := True;
      end Look_Up;

      procedure Keep (Value : Session; Kept : out Boolean) is
         Slot   : Natural := Locate (Server_Name (Value), Security_Context (Value));
         Oldest : Natural := 0;
      begin
         Kept := False;

         if not Is_Present (Value) then
            return;
         end if;

         if Slot = 0 then
            --  A free slot first.
            for Index in Entries'Range loop
               if not Entries (Index).Used then
                  Slot := Index;
                  exit;
               end if;
            end loop;
         end if;

         if Slot = 0 then
            --  Full. The least recently used goes: evicting the oldest instead
            --  would keep discarding the entry for the host this application
            --  talks to most, because that is the one created first.
            Oldest := Entries'First;
            for Index in Entries'Range loop
               if Entries (Index).Stamp < Entries (Oldest).Stamp then
                  Oldest := Index;
               end if;
            end loop;
            Slot := Oldest;
            Wipe (Entries (Slot).Value);
         end if;

         Ticks := Ticks + 1;
         Copy (Entries (Slot).Value, Value);
         Entries (Slot).Stamp := Ticks;
         Entries (Slot).Used := True;
         Kept := True;
      end Keep;

      procedure Forget (Name : SSL.Server_Names.DNS_Name; Context : Security_Context_ID) is
         Slot : constant Natural := Locate (Name, Context);
      begin
         if Slot /= 0 then
            Wipe (Entries (Slot).Value);
            Entries (Slot).Used := False;
         end if;
      end Forget;

      procedure Clear is
      begin
         for Index in Entries'Range loop
            Wipe (Entries (Index).Value);
            Entries (Index).Used := False;
            Entries (Index).Stamp := 0;
         end loop;
      end Clear;

      function Occupancy return Natural is
         Count : Natural := 0;
      begin
         for Index in Entries'Range loop
            if Entries (Index).Used then
               Count := Count + 1;
            end if;
         end loop;
         return Count;
      end Occupancy;

   end Store_Object;

   ---------------------------------------------------------------------------
   --  The cache itself
   ---------------------------------------------------------------------------

   overriding procedure Look_Up
     (Item    : in out Memory_Cache;
      Name    : SSL.Server_Names.DNS_Name;
      Context : Security_Context_ID;
      At_Time : SSL.Clocks.Wall_Time;
      Into    : in out Session;
      Found   : out Boolean)
   is
   begin
      Item.Held.Look_Up (Name, Context, At_Time, Into, Found);
   end Look_Up;

   overriding procedure Store
     (Item  : in out Memory_Cache;
      Value : Session;
      Kept  : out Boolean)
   is
   begin
      Item.Held.Keep (Value, Kept);
   end Store;

   overriding procedure Discard
     (Item    : in out Memory_Cache;
      Name    : SSL.Server_Names.DNS_Name;
      Context : Security_Context_ID)
   is
   begin
      Item.Held.Forget (Name, Context);
   end Discard;

   overriding function Description (Item : Memory_Cache) return String is
     ("in-memory session cache of" & Positive'Image (Item.Capacity));

   function Occupancy (Item : Memory_Cache) return Natural is (Item.Held.Occupancy);

   procedure Clear (Item : in out Memory_Cache) is
   begin
      Item.Held.Clear;
   end Clear;

end SSL.Sessions.Client_Caches.Memory;
