with SSL.Clocks;
with SSL.Errors;
with SSL.Sessions;

private with SSL.Secrets;

--  @summary The keys a server protects its session tickets with, and the
--  rotation of them.
--
--  A session ticket is the server's own state, encrypted under a key only the
--  server holds. That key is the most valuable thing a TLS server has after its
--  private key: anyone holding it can decrypt every ticket issued under it, and
--  therefore recover the resumption secret of every session those tickets
--  represent.
--
--  Which is why this is a separate, explicit object rather than something a
--  configuration conjures for itself:
--
--    * **Rotation is the application's decision.** How often, and on what
--      schedule, depends on how long the deployment wants a compromised key to
--      be useful for. This library will not pick a period.
--    * **Nothing is persisted and nothing is distributed.** A deployment
--      running several servers that must accept each other's tickets installs
--      the same key on each, by whatever means it already trusts. This library
--      writes no file and opens no socket to share one.
--    * **Rotation does not invalidate outstanding tickets.** The previous key
--      keeps opening what it issued, until it in turn retires. A rotation that
--      cut off every ticket at once would turn a routine operation into a
--      thundering herd of full handshakes.
package SSL.Ticket_Keys is

   --  A ring of ticket keys. Limited: it holds key material and scrubs it.
   type Ring is limited private;

   --  Is there a key that may issue? A server whose ring has none does not
   --  issue tickets; that is a state, not a failure.
   function Has_Active_Key (Item : Ring) return Boolean;

   function Key_Count (Item : Ring) return Natural;

   --  How long tickets issued under a new key may live, in seconds.
   --
   --  RFC 8446 section 4.6.1 caps a ticket at seven days, and this library
   --  refuses a longer one. The default here is a day, which is short enough
   --  that a stolen key stops being useful quickly and long enough that a
   --  client reconnecting the next morning still resumes.
   Default_Lifetime : constant Natural := 86_400;

   --  Generate a fresh key and make it the one that issues.
   --
   --  Whatever was issuing becomes decrypt-only, so tickets already in clients'
   --  hands keep working.
   --  @param Item     the ring
   --  @param Lifetime how long tickets under this key may live, in seconds
   --  @param Now      the wall clock
   --  @param Error    out: No_Error, or a randomness failure
   procedure Rotate
     (Item     : in out Ring;
      Lifetime : Natural := Default_Lifetime;
      Now      : SSL.Clocks.Wall_Time := SSL.Clocks.Current_UTC;
      Error    : out SSL.Errors.Error_Information)
     with Pre => Lifetime in 1 .. 604_800;

   --  Install a key the application manages itself.
   --
   --  For a deployment where several servers must accept each other's tickets.
   --  The identifier names the key inside every ticket issued under it, so it
   --  must be the same on every server and must differ between keys.
   --  @param Item       the ring
   --  @param Identifier sixteen octets naming the key; not secret
   --  @param Material   thirty-two octets of key; entirely secret
   --  @param Lifetime   how long tickets under it may live, in seconds
   --  @param Now        the wall clock
   --  @param Error      out: No_Error, or why it was refused
   procedure Install
     (Item       : in out Ring;
      Identifier : Byte_Array;
      Material   : Byte_Array;
      Lifetime   : Natural := Default_Lifetime;
      Now        : SSL.Clocks.Wall_Time := SSL.Clocks.Current_UTC;
      Error      : out SSL.Errors.Error_Information)
     with Pre => Identifier'Length = 16
                 and then Material'Length = 32
                 and then Lifetime in 1 .. 604_800;

   --  Scrub every key now rather than at end of scope.
   procedure Wipe (Item : in out Ring);

   --  A reference to a ring, for a configuration to hold.
   type Ring_Reference is access constant Ring;

   ---------------------------------------------------------------------------
   --  The ticket format
   ---------------------------------------------------------------------------

   --  A session ticket is the server's own state, encrypted under a key only
   --  the server holds. The protocol says nothing about what is inside one,
   --  which means every decision here is this library's and every one of them
   --  can be got wrong in a way that costs the security of every resumed
   --  connection. So, explicitly:
   --
   --    * **The ticket is authenticated encryption, and it is authenticated
   --      before it is parsed.** A ticket a server cannot authenticate is a
   --      ticket whose contents it never looks at, which is what keeps chosen
   --      bytes away from the decoder.
   --    * **It is versioned, and the version is authenticated.** A format
   --      change an attacker could roll back would be no change at all.
   --    * **Nothing is persisted as an Ada record.** Every field is written
   --      octet by octet, because a record's layout is a compiler's decision
   --      and a ticket outlives the process that wrote it.
   --    * **An unusable ticket is not an error.** Unknown key, expired,
   --      corrupt, wrong version -- each means "resume is not available", and
   --      each produces the same undifferentiated refusal, so that a peer
   --      probing a server's key rotation learns nothing from which one it got.

   --  The largest a sealed ticket can be.
   Maximum_Ticket : constant Byte_Index := SSL.Sessions.Maximum_Ticket;

   --  Seal a session into a ticket, under the ring's active key.
   --  @param Item    the ring
   --  @param Value   the session to put inside; its own ticket field is ignored
   --  @param Into    out: the sealed ticket
   --  @param Written out: how many octets hold it
   --  @param Error   out: No_Error, or why it could not be sealed
   procedure Seal
     (Item    : Ring;
      Value   : SSL.Sessions.Session;
      Into    : out Byte_Array;
      Written : out Byte_Index;
      Error   : out SSL.Errors.Error_Information)
     with Pre => Into'Length >= Maximum_Ticket;

   --  Open a ticket, if this ring can.
   --
   --  Everything that can go wrong produces `Usable => False` and one
   --  undifferentiated refusal.
   --  @param Item   the ring
   --  @param Ticket the octets as they arrived
   --  @param Now    the wall clock, for the expiry check
   --  @param Into   in out: the recovered session
   --  @param Usable out: True only when everything held
   --  @param Error  out: No_Error, or one undifferentiated refusal
   procedure Open
     (Item   : Ring;
      Ticket : Byte_Array;
      Now    : SSL.Clocks.Wall_Time;
      Into   : in out SSL.Sessions.Session;
      Usable : out Boolean;
      Error  : out SSL.Errors.Error_Information);

private

   --  How a key is named inside a ticket, so that a server with several knows
   --  which to try. Not a secret, and deliberately not a counter: a counter
   --  would tell an observer how many times this server had rotated.
   Identifier_Length : constant Byte_Index := 16;

   --  How many keys a ring holds. Bounded, because retaining every key a
   --  server has ever had would be retaining the means to decrypt every ticket
   --  it has ever issued.
   Maximum_Keys : constant := 4;

   type Key_State is (Active, Decrypt_Only, Retired);

   type Key_Entry is limited record
      State      : Key_State := Retired;
      Identifier : Byte_Array (1 .. Identifier_Length) := [others => 0];
      Material   : SSL.Secrets.Secret (SSL.Secrets.Traffic_Capacity);
      Lifetime   : Natural := 0;
   end record;

   type Key_Array is array (1 .. Maximum_Keys) of Key_Entry;

   type Ring is limited record
      Count : Natural range 0 .. Maximum_Keys := 0;
      Keys  : Key_Array;
   end record;

end SSL.Ticket_Keys;
