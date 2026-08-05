--  @summary A bounded, task-safe session cache that lives in memory and goes
--  away with the process.
--
--  What most applications should use. It holds a fixed number of sessions,
--  evicts the least recently used when it is full, and never allocates after
--  it is created.
--
--  **Task-safe, by a protected object.** A client cache is exactly the thing
--  several worker tasks reach at once -- each opening its own outbound
--  connection to the same handful of hosts -- so serializing it here rather
--  than asking every application to do it is the right place for the cost.
--  The operations are short: a bounded scan and a copy.
--
--  **Bounded, and eviction is by use rather than by age.** A cache that evicted
--  the oldest would keep discarding the session for the host it talks to most,
--  because that is the one whose entry was created first. Least-recently-used
--  keeps the working set.
--
--  **Nothing is written anywhere.** Sessions here do not survive the process.
--  Persisting them would need an explicit persistence key -- there is no
--  unencrypted mode and no hidden file I/O -- and that is a separate thing this
--  library does not yet provide.
package SSL.Sessions.Client_Caches.Memory is

   --  How many sessions one cache holds. Fixed at declaration rather than
   --  configurable at run time, so that the storage is reserved once and the
   --  bound is visible where the cache is declared.
   type Memory_Cache (Capacity : Positive) is
     limited new Cache with private;

   overriding procedure Look_Up
     (Item    : in out Memory_Cache;
      Name    : SSL.Server_Names.DNS_Name;
      Context : Security_Context_ID;
      At_Time : SSL.Clocks.Wall_Time;
      Into    : in out Session;
      Found   : out Boolean);

   overriding procedure Store
     (Item  : in out Memory_Cache;
      Value : Session;
      Kept  : out Boolean);

   overriding procedure Discard
     (Item    : in out Memory_Cache;
      Name    : SSL.Server_Names.DNS_Name;
      Context : Security_Context_ID);

   overriding function Description (Item : Memory_Cache) return String;

   --  How many live entries the cache holds. For diagnostics and for a test
   --  that wants to assert eviction happened.
   function Occupancy (Item : Memory_Cache) return Natural;

   --  Forget everything, scrubbing as it goes.
   procedure Clear (Item : in out Memory_Cache);

private

   type Entry_Record is limited record
      Used  : Boolean := False;

      --  When this entry was last looked up or stored, as a counter rather
      --  than a clock. A counter cannot go backwards, and a wall clock that
      --  moved would reorder the eviction queue.
      Stamp : Long_Long_Integer := 0;

      Value : Session;
   end record;

   type Entry_Array is array (Positive range <>) of Entry_Record;

   --  The protected object is where the serialization is, and it holds the
   --  entries directly rather than a reference to them: an application cannot
   --  reach past it to the storage.
   protected type Store_Object (Capacity : Positive) is

      procedure Look_Up
        (Name    : SSL.Server_Names.DNS_Name;
         Context : Security_Context_ID;
         At_Time : SSL.Clocks.Wall_Time;
         Into    : in out Session;
         Found   : out Boolean);

      procedure Keep (Value : Session; Kept : out Boolean);

      procedure Forget (Name : SSL.Server_Names.DNS_Name; Context : Security_Context_ID);

      procedure Clear;

      function Occupancy return Natural;

   private
      Entries : Entry_Array (1 .. Capacity);
      Ticks   : Long_Long_Integer := 0;
   end Store_Object;

   type Memory_Cache (Capacity : Positive) is
     limited new Cache with record
      Held : Store_Object (Capacity);
   end record;

end SSL.Sessions.Client_Caches.Memory;
