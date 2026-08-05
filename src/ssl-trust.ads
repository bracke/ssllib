private with Ada.Finalization;

with SSL.Clocks;
with SSL.Errors;
with SSL.Limits;

--  @summary Trust anchors, as an immutable snapshot a configuration holds and
--  connections share.
--
--  A snapshot, not a live view. Anchors are read once, when the snapshot is
--  built, and never re-read; a connection validating a chain against a snapshot
--  is validating against a set that cannot change under it halfway through. If
--  the system store changes, the application builds a new snapshot and a new
--  configuration -- which also gives every session established under the old one
--  a different trust fingerprint, so nothing resumes across the change.
--
--  **Native system trust is the default and the only default.** NSS and Java
--  stores are opt-in and are never merged in silently. An operator who trusts
--  the system store has not thereby agreed to trust whatever a browser profile
--  on the same machine has accumulated, and a library that quietly unioned them
--  would be widening the trust base without anyone deciding to.
--
--  **A required source that is unavailable or empty fails closed.** Building a
--  snapshot from a store that turned out to have no anchors in it produces an
--  error, not an empty snapshot. The alternative turns a misconfiguration into
--  an unauthenticated connection, which is the worst possible ordering of those
--  two outcomes.
--
--  Anchor discovery is entirely `truststores`'. This package chooses which
--  sources to ask, bounds what comes back, and takes the fingerprint; it does
--  not know where a Linux anchor directory lives or how a macOS keychain is
--  read, and it must not learn.
package SSL.Trust is

   ---------------------------------------------------------------------------
   --  Sources
   ---------------------------------------------------------------------------

   type Anchor_Source is
     (Native_System,
      --  Whatever the platform considers its trust store. The default.

      NSS_Database,
      --  An explicitly selected NSS database. Opt-in.

      Java_Keystore,
      --  An explicitly selected Java keystore. Opt-in.

      Explicit_PEM);
      --  Anchors the application supplied directly, as PEM.

   function Image (Item : Anchor_Source) return String;

   ---------------------------------------------------------------------------
   --  Snapshots
   ---------------------------------------------------------------------------

   type Snapshot is limited private;

   --  Has this snapshot been built?
   function Is_Built (Item : Snapshot) return Boolean;

   --  How many anchors it holds.
   function Anchor_Count (Item : Snapshot) return Natural
     with Pre => Is_Built (Item);

   --  One anchor's DER.
   function Anchor_At (Item : Snapshot; Index : Positive) return Byte_Array
     with Pre => Is_Built (Item) and then Index <= Anchor_Count (Item);

   --  The snapshot's identity as a value: SHA-256 over the anchors in the order
   --  they were loaded. Sessions are bound to it, so changing the trust base
   --  invalidates resumption rather than letting a session established under one
   --  set of anchors resume under another.
   --  How many octets the anchors occupy, and how many are allocated for them.
   --
   --  For diagnostics and for the test that checks the store is sized to what
   --  it holds rather than to the ceiling. The two differ only by the slack in
   --  the last growth.
   function Held_Octets (Item : Snapshot) return Byte_Index;
   function Allocated_Octets (Item : Snapshot) return Byte_Index;

   function Fingerprint (Item : Snapshot) return Trust_Fingerprint
     with Pre => Is_Built (Item);

   --  When the snapshot was taken, for diagnostics and for an application with a
   --  policy about how stale its trust base may be.
   function Taken_At (Item : Snapshot) return SSL.Clocks.Wall_Time
     with Pre => Is_Built (Item);

   --  Which sources contributed.
   function Includes (Item : Snapshot; Source : Anchor_Source) return Boolean
     with Pre => Is_Built (Item);

   ---------------------------------------------------------------------------
   --  Building
   ---------------------------------------------------------------------------

   --  Load the platform's own trust anchors.
   --
   --  Fails with Code_System_Trust_Unavailable when the platform will not answer,
   --  and with Code_Trust_Source_Empty when it answers with nothing. Neither
   --  produces a usable empty snapshot.
   --  @param Item    the snapshot to build
   --  @param At_Time the wall time to record as when this was taken
   --  @param Bounds  the limits in force
   --  @param Error   out: No_Error, or why the source could not be used
   procedure Load_System_Anchors
     (Item    : in out Snapshot;
      At_Time : SSL.Clocks.Wall_Time;
      Bounds  : SSL.Limits.Resource_Limits;
      Error   : out SSL.Errors.Error_Information);

   --  Add an explicitly selected NSS database's anchors.
   --
   --  Separate from Load_System_Anchors and never implied by it. See the note at
   --  the top of this package.
   procedure Add_NSS_Anchors
     (Item   : in out Snapshot;
      Bounds : SSL.Limits.Resource_Limits;
      Error  : out SSL.Errors.Error_Information)
     with Pre => Is_Built (Item);

   --  Add an explicitly selected Java keystore's anchors.
   procedure Add_Java_Anchors
     (Item   : in out Snapshot;
      Bounds : SSL.Limits.Resource_Limits;
      Error  : out SSL.Errors.Error_Information)
     with Pre => Is_Built (Item);

   --  Build a snapshot from PEM the application supplies, and from nothing else.
   --
   --  For a private certificate authority, a pinned internal root, or a test
   --  fixture. This is the one way to get a snapshot that does not depend on the
   --  machine, which is what makes a deterministic test of the validation
   --  pipeline possible.
   --  @param Item      the snapshot to build
   --  @param PEM       one or more CERTIFICATE blocks
   --  @param At_Time   the wall time to record
   --  @param Bounds    the limits in force
   --  @param Error     out: No_Error, or why the material could not be used
   procedure Load_Explicit_Anchors
     (Item    : in out Snapshot;
      PEM     : String;
      At_Time : SSL.Clocks.Wall_Time;
      Bounds  : SSL.Limits.Resource_Limits;
      Error   : out SSL.Errors.Error_Information);

   --  Add explicit anchors to a snapshot that already holds some.
   procedure Add_Explicit_Anchors
     (Item   : in out Snapshot;
      PEM    : String;
      Bounds : SSL.Limits.Resource_Limits;
      Error  : out SSL.Errors.Error_Information)
     with Pre => Is_Built (Item);

   --  Release the anchors. A snapshot holds no secret, so this frees storage
   --  rather than scrubbing.
   procedure Release (Item : in out Snapshot);

private

   Maximum_Anchor_Octets : constant Byte_Index := 4 * 1024 * 1024;

   type Span is record
      First : Byte_Index := 1;
      Last  : Byte_Index := 0;
   end record;

   type Span_Array is array (Positive range <>) of Span;
   type Span_Storage is access Span_Array;
   type Octet_Storage is access Byte_Array;

   type Source_Flags is array (Anchor_Source) of Boolean;

   type Snapshot is new Ada.Finalization.Limited_Controlled with record
      Built   : Boolean := False;
      Count   : Natural := 0;
      Held    : Byte_Index := 0;
      Spans   : Span_Storage := null;
      Octets  : Octet_Storage := null;
      Sources : Source_Flags := [others => False];
      Digest  : Trust_Fingerprint;
      Stamp   : SSL.Clocks.Wall_Time := SSL.Clocks.No_Wall_Time;
   end record;

   overriding procedure Finalize (Item : in out Snapshot);

end SSL.Trust;
