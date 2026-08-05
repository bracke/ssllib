private with Ada.Finalization;

--  @summary Bounded controlled secret values: key-schedule secrets, traffic
--  keys, IVs, PSKs, master secrets and the intermediates between them.
--
--  Every value of this type scrubs itself when it goes out of scope, and does
--  so through volatile stores that the optimizer is not allowed to remove. That
--  is the whole reason it exists: a local Byte_Array holding a traffic secret,
--  zeroed by an assignment before return, is a dead store, and -O3 deletes it.
--
--  The type is limited, so a secret cannot be copied into a place that does not
--  scrub. Moving one from a derivation step to the state that owns it is an
--  explicit Set, which copies the octets and leaves the source to be wiped.
--
--  There is deliberately no function returning a secret's octets to a caller
--  outside this library, and no getter for a raw key-schedule secret even
--  inside it. Value is visible only to SSL's own children, which is what a
--  private package means, and the packages that call it are the record layer
--  (which needs the AEAD key) and the key schedule (which needs the previous
--  stage). Nothing else has a reason to see one.
private package SSL.Secrets is

   --  The widest secret this library holds in one of these: an ffdhe4096
   --  shared secret, at 512 octets.
   Maximum_Capacity : constant Byte_Index := 512;

   subtype Secret_Capacity is Byte_Index range 1 .. Maximum_Capacity;
   subtype Secret_Length is Byte_Index range 0 .. Maximum_Capacity;

   --  Capacity is a discriminant rather than one flat maximum, because the
   --  widest secret and the commonest one are two orders of magnitude apart.
   --
   --  Everything in the key schedule is at most 48 octets, an AEAD key at most
   --  32, and an elliptic-curve shared secret at most 66. Only finite-field
   --  Diffie-Hellman is large: an ffdhe4096 shared secret is 512 octets. A
   --  single 512-octet bound would have made a Schedule -- which holds ten of
   --  these -- five kilobytes, and would have made every Wipe of a 32-octet
   --  traffic key a 512-octet memset. Naming the capacity at each declaration
   --  costs one identifier and says how large the thing can be at the point
   --  someone reads it.
   --
   --  There is no default, so a declaration must choose. That is deliberate:
   --  the wrong choice is a compile-time failure at the Set rather than a
   --  silently oversized object.

   --  Key-schedule secrets, Finished keys, PSK binders, resumption PSKs, TLS
   --  1.2 master secrets. Sized for SHA-512's width, above the SHA-384 the
   --  widest suite here actually uses.
   Schedule_Capacity : constant Secret_Capacity := 64;

   --  AEAD traffic keys and static IVs.
   Traffic_Capacity : constant Secret_Capacity := 32;

   --  Key-agreement material: a shared secret or a private exponent, over any
   --  group this library offers. The ffdhe4096 shared secret sets the bound.
   Agreement_Capacity : constant Secret_Capacity := Maximum_Capacity;

   type Secret (Capacity : Secret_Capacity) is tagged limited private;

   --  Copy Data in, replacing whatever was there. The previous contents are
   --  scrubbed first, so overwriting a secret does not leave the old one in the
   --  unused tail.
   --  @param Item the secret to set
   --  @param Data the octets, at most Maximum_Length of them
   procedure Set (Item : in out Secret; Data : Byte_Array)
     with Pre => Data'Length <= Item.Capacity,
          Post => Length (Item) = Data'Length;

   --  Reserve Length octets of zeroes, for a buffer about to be filled in
   --  place by a CryptoLib out parameter.
   --  @param Item   the secret to size
   --  @param Length how many octets
   procedure Set_Length (Item : in out Secret; Length : Secret_Length)
     with Pre => Length <= Item.Capacity,
          Post => SSL.Secrets.Length (Item) = Length;

   --  How many octets the secret holds; zero when it holds nothing.
   function Length (Item : Secret) return Secret_Length
     with Post => Length'Result <= Item.Capacity;

   --  Does the secret hold anything?
   function Is_Present (Item : Secret) return Boolean
     with Post => Is_Present'Result = (Length (Item) > 0);

   --  The octets. Visible only within SSL's own hierarchy, because this
   --  package is private. Returns a copy, which the caller must not retain: the
   --  copy is an ordinary Byte_Array and scrubs nothing.
   --
   --  Callers should pass the result straight into the CryptoLib entry point
   --  that needs it rather than binding it to a named object, so that the copy
   --  lives no longer than the call.
   --  @param Item the secret to read
   --  @return the octets, indexed from one
   function Value (Item : Secret) return Byte_Array
     with Post => Value'Result'Length = Length (Item);

   --  Write the secret's octets into a caller buffer of exactly the right
   --  length, for the CryptoLib entry points that take an out parameter. The
   --  buffer is the caller's to scrub.
   --  @param Item the secret to read
   --  @param Into out: receives exactly Length (Item) octets
   procedure Get (Item : Secret; Into : out Byte_Array)
     with Pre => Into'Length = Length (Item);

   --  Fill the secret's octets from a CryptoLib out parameter that has just
   --  been written, in place, without an intermediate named copy. Length must
   --  already have been set.
   --  @param Item the secret to update
   --  @param Data the octets, exactly Length (Item) of them
   procedure Put (Item : in out Secret; Data : Byte_Array)
     with Pre => Data'Length = Length (Item);

   --  Overwrite with zeroes and forget the length.
   procedure Wipe (Item : in out Secret)
     with Post => Length (Item) = 0;

   --  Compare two secrets in time independent of their contents, for the
   --  places where a secret is what is being verified: a Finished MAC, a PSK
   --  binder, a ticket authentication tag.
   --  @param Left  the first secret
   --  @param Right the second secret
   --  @return True when both hold the same octets
   function Equal (Left : Secret; Right : Secret) return Boolean;

   --  Compare a secret against octets in constant time.
   --  @param Item the secret
   --  @param Data the octets to compare against
   --  @return True when they are the same length and the same octets
   function Equal (Item : Secret; Data : Byte_Array) return Boolean;

   --  Copy Source's octets into Target. Both remain owners of their own
   --  storage and both scrub independently; this is the only way a secret
   --  moves, because the type is limited and cannot be assigned.
   --  @param Target the secret to overwrite
   --  @param Source the secret to copy from
   procedure Copy (Target : in out Secret; Source : Secret)
     with Pre => Length (Source) <= Target.Capacity,
          Post => Length (Target) = Length (Source);

   ---------------------------------------------------------------------------
   --  Watching the wiping happen
   ---------------------------------------------------------------------------

   --  A hook that fires whenever a secret is scrubbed.
   --
   --  **This exists for the test suite and for nothing else.** The
   --  specification asks for secret cleanup to be tested through wipe
   --  observers, and there is no other way to tell "this secret was scrubbed"
   --  from "this secret went out of scope and the storage happened to be
   --  reused": both leave the caller with nothing to look at.
   --
   --  What it is handed is deliberately thin. It receives how many octets were
   --  wiped and nothing else -- not the octets, not the capacity's contents,
   --  not a reference to the secret. An observer that could see what it was
   --  observing would be a hole in exactly the property it exists to check.
   --
   --  Null by default, and nothing in this library ever installs one. A program
   --  that does not call `Observe_Wipes` has a hook that is never read and a
   --  branch the compiler folds away.
   type Wipe_Observer is access procedure (Wiped : Byte_Index);

   --  Install one, or pass null to remove it.
   --
   --  Not task-safe, and not meant to be: it is called once from a test's own
   --  task before anything else runs. Installing an observer while another task
   --  is wiping a secret is a caller mistake this library does not police.
   procedure Observe_Wipes (Sink : Wipe_Observer);

   ---------------------------------------------------------------------------
   --  Secret output for exporters and channel bindings
   --
   --  What an application is allowed to receive: a bounded value it owns and
   --  can scrub, rather than a view into the key schedule. The distinction
   --  matters because an exporter output is a key an application will use for
   --  something else, and it must not be a window onto the secret it came
   --  from.
   ---------------------------------------------------------------------------

   --  The largest exporter or channel-binding output this library will
   --  produce. RFC 8446 puts no ceiling on exporter length; this one is here so
   --  that an application asking for a megabyte of key material meets a
   --  refusal rather than an allocation.
   Maximum_Output_Length : constant Byte_Index := 255;

private

   type Secret (Capacity : Secret_Capacity) is
     new Ada.Finalization.Limited_Controlled with record
      --  The buffer is always the full declared capacity. Only the first Used
      --  octets are the secret; the rest are zero, and Wipe restores that, so a
      --  shorter secret set over a longer one leaves no tail behind.
      Octets : Byte_Array (1 .. Capacity) := [others => 0];
      Used   : Secret_Length := 0;
   end record;

   overriding procedure Finalize (Item : in out Secret);

end SSL.Secrets;
