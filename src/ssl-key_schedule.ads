private with SSL.Secrets;

with SSL.Cipher_Suites;
with SSL.Errors;

--  @summary The TLS 1.3 key schedule: every secret RFC 8446 section 7.1
--  defines, derived in order, each one tied to the transcript milestone it
--  belongs to.
--
--  CryptoLib provides HKDF-Extract, HKDF-Expand-Label and Derive-Secret, and
--  deliberately provides nothing above them: composing them is protocol work
--  and needs protocol state. This package is that composition, and it owns it
--  entirely.
--
--  The shape of the schedule is three Extract steps with Expand steps hanging
--  off each:
--
--      Early     = Extract(salt = 0,                   ikm = PSK or zeros)
--      Handshake = Extract(salt = Derive(Early, "derived", ""),
--                          ikm = ECDHE shared secret)
--      Master    = Extract(salt = Derive(Handshake, "derived", ""),
--                          ikm = zeros)
--
--  What makes this safe is not the arithmetic but the ordering: each stage is
--  derived from the previous one and from the transcript as it stood at a named
--  point, so a secret cannot be produced early, and a secret produced from the
--  wrong transcript is a different secret. This package enforces the ordering
--  rather than trusting callers to observe it: asking for a handshake traffic
--  secret before the handshake stage has been derived is refused, and each
--  stage can be derived once.
--
--  There is no getter for a raw stage secret. A caller can obtain traffic keys,
--  Finished keys, binder keys, exporter output and a resumption PSK -- the
--  things the protocol uses -- and nothing that would let it derive something
--  the schedule has not sanctioned. That is the difference between a key
--  schedule and a bag of secrets.
private package SSL.Key_Schedule is

   ---------------------------------------------------------------------------
   --  Stages and directions
   ---------------------------------------------------------------------------

   --  Where the schedule has got to. Each stage is entered exactly once, in
   --  this order, and every derivation states which stage it needs.
   type Stage is
     (Unstarted,
      Early_Stage,       --  early secret exists: binder keys available
      Handshake_Stage,   --  handshake traffic secrets exist
      Master_Stage);     --  application traffic, exporter and resumption exist

   --  Which side's secret. Named by role rather than by direction so that the
   --  same code reads correctly in both roles: a client's write key is the
   --  client secret whether it is a client or a server holding the schedule.
   type Party is (Client_Side, Server_Side);

   type Schedule is limited private;

   --  Begin a schedule for a negotiated cipher suite. Discards anything the
   --  schedule held, scrubbing it.
   --  @param Item  the schedule
   --  @param Suite the negotiated suite, which fixes the hash and the AEAD
   procedure Start (Item : in out Schedule; Suite : SSL.Cipher_Suites.Cipher_Suite)
     with Post => Current_Stage (Item) = Unstarted and then Is_Started (Item);

   function Is_Started (Item : Schedule) return Boolean;
   function Current_Stage (Item : Schedule) return Stage;
   function Suite_Of (Item : Schedule) return SSL.Cipher_Suites.Cipher_Suite
     with Pre => Is_Started (Item);

   --  Scrub everything the schedule holds. Called on connection failure and on
   --  finalization; also safe to call at any point.
   procedure Wipe (Item : in out Schedule);

   ---------------------------------------------------------------------------
   --  Stage 1: early secret
   ---------------------------------------------------------------------------

   --  Derive the early secret from a resumption PSK.
   --
   --  The PSK is one this library issued and later recovered from its own
   --  ticket: there are no external PSKs here, so a PSK always came from a
   --  previous handshake's resumption master secret.
   --  @param Item  the schedule
   --  @param PSK   the pre-shared key, the hash's own width
   --  @param Error out: No_Error, or a key-derivation failure
   procedure Derive_Early_From_PSK
     (Item  : in out Schedule;
      PSK   : Byte_Array;
      Error : out SSL.Errors.Error_Information)
     with Pre => Is_Started (Item) and then Current_Stage (Item) = Unstarted;

   --  Derive the early secret with no PSK, which RFC 8446 defines as
   --  Extract(salt = 0, ikm = a string of Hash.length zeroes). Every
   --  full handshake does this, and the stage exists even when nothing is
   --  resumed because the handshake secret is derived from it.
   procedure Derive_Early_Without_PSK
     (Item  : in out Schedule;
      Error : out SSL.Errors.Error_Information)
     with Pre => Is_Started (Item) and then Current_Stage (Item) = Unstarted;

   --  Was a PSK used? Recorded so that the authentication metadata can report a
   --  resumed handshake as resumed rather than as freshly authenticated.
   function Used_PSK (Item : Schedule) return Boolean;

   --  Write the PSK binder for a ClientHello whose binder field is zeroed.
   --
   --  The binder is HMAC, under a key derived from the early secret, over the
   --  transcript of the partial ClientHello up to and including the length of
   --  the binder list -- see RFC 8446 section 4.2.11.2. The caller supplies
   --  that transcript hash; computing which octets it covers is the handshake's
   --  job, not the schedule's.
   --  @param Item            the schedule, at Early_Stage
   --  @param Transcript_Hash the partial-ClientHello transcript hash
   --  @param Is_External     always False here; the parameter exists so that the
   --    resumption label is chosen explicitly rather than by default
   --  @param Into            out: the binder, the hash's own width
   --  @param Error           out: No_Error, or a derivation failure
   procedure Compute_Binder
     (Item            : Schedule;
      Transcript_Hash : Byte_Array;
      Is_External     : Boolean;
      Into            : out Byte_Array;
      Error           : out SSL.Errors.Error_Information)
     with Pre => Current_Stage (Item) >= Early_Stage
                 and then Is_External = False
                 and then Into'Length = Digest_Width (Item);

   ---------------------------------------------------------------------------
   --  Stage 2: handshake secret and handshake traffic keys
   ---------------------------------------------------------------------------

   --  Derive the handshake secret and both handshake traffic secrets.
   --
   --  The transcript hash is taken at the ClientHello..ServerHello milestone,
   --  which is the only point at which these secrets are defined.
   --  @param Item            the schedule, at Early_Stage
   --  @param Shared_Secret   the ECDHE shared secret
   --  @param Transcript_Hash the ClientHello..ServerHello transcript hash
   --  @param Error           out: No_Error, or a derivation failure
   procedure Derive_Handshake
     (Item            : in out Schedule;
      Shared_Secret   : Byte_Array;
      Transcript_Hash : Byte_Array;
      Error           : out SSL.Errors.Error_Information)
     with Pre => Current_Stage (Item) = Early_Stage
                 and then Transcript_Hash'Length = Digest_Width (Item);

   ---------------------------------------------------------------------------
   --  Stage 3: master secret, application traffic keys, exporter, resumption
   ---------------------------------------------------------------------------

   --  Derive the master secret, both application traffic secrets and the
   --  exporter master secret.
   --
   --  Bound to the transcript through the **server's** Finished, which is the
   --  milestone RFC 8446 section 7.1 fixes for these three. That milestone is
   --  reached before the client has said anything in its second flight, which
   --  is what lets a server write application data as soon as its own Finished
   --  is out -- the half-RTT the protocol is designed to allow.
   --
   --  The resumption master secret is *not* derived here, because it is bound
   --  to a different milestone. Deriving both from one call would mean waiting
   --  for the client's Finished before either was available, and a server that
   --  waited could not write early.
   --  @param Item                 the schedule, at Handshake_Stage
   --  @param Server_Finished_Hash the transcript hash after the server Finished
   --  @param Error                out: No_Error, or a derivation failure
   procedure Derive_Master
     (Item                 : in out Schedule;
      Server_Finished_Hash : Byte_Array;
      Error                : out SSL.Errors.Error_Information)
     with Pre => Current_Stage (Item) = Handshake_Stage
                 and then Server_Finished_Hash'Length = Digest_Width (Item);

   --  Derive the resumption master secret.
   --
   --  Bound to the transcript through the **client's** Finished. Passing the
   --  server's hash here instead would produce a ticket that resumes to
   --  nothing, and the two ends would find out one connection later.
   --  @param Item                 the schedule, at Master_Stage
   --  @param Client_Finished_Hash the transcript hash after the client Finished
   --  @param Error                out: No_Error, or a derivation failure
   procedure Derive_Resumption
     (Item                 : in out Schedule;
      Client_Finished_Hash : Byte_Array;
      Error                : out SSL.Errors.Error_Information)
     with Pre => Current_Stage (Item) = Master_Stage
                 and then Client_Finished_Hash'Length = Digest_Width (Item);

   --  Has the resumption master secret been derived? Until it has, no ticket
   --  can be issued and none can be accepted.
   function Has_Resumption (Item : Schedule) return Boolean;

   ---------------------------------------------------------------------------
   --  Products
   ---------------------------------------------------------------------------

   --  Which epoch's traffic keys are wanted.
   type Epoch is (Handshake_Epoch, Application_Epoch);

   --  The traffic key and static IV for one direction and epoch.
   --
   --  RFC 8446 section 7.3: key = Expand-Label(secret, "key", "", key_length),
   --  iv = Expand-Label(secret, "iv", "", iv_length). The AEAD fixes both
   --  lengths.
   --  @param Item  the schedule
   --  @param Which whose secret
   --  @param Which_Epoch handshake or application
   --  @param Key   out: the traffic key, the AEAD's key length
   --  @param IV    out: the static IV, twelve octets
   --  @param Error out: No_Error, or a derivation failure
   procedure Traffic_Key
     (Item        : Schedule;
      Which       : Party;
      Which_Epoch : Epoch;
      Key         : out Byte_Array;
      IV          : out Byte_Array;
      Error       : out SSL.Errors.Error_Information)
     with Pre => (if Which_Epoch = Handshake_Epoch
                  then Current_Stage (Item) >= Handshake_Stage
                  else Current_Stage (Item) >= Master_Stage)
                 and then Key'Length = Key_Width (Item)
                 and then IV'Length = 12;

   --  The Finished key for one party, derived from that party's handshake
   --  traffic secret (RFC 8446 section 4.4.4).
   --  @param Item  the schedule, at Handshake_Stage or later
   --  @param Which whose Finished key
   --  @param Into  out: the key, the hash's own width
   --  @param Error out: No_Error, or a derivation failure
   procedure Finished_Key
     (Item  : Schedule;
      Which : Party;
      Into  : out Byte_Array;
      Error : out SSL.Errors.Error_Information)
     with Pre => Current_Stage (Item) >= Handshake_Stage
                 and then Into'Length = Digest_Width (Item);

   --  Compute a Finished message's verify_data: HMAC, under the Finished key,
   --  over the transcript hash.
   --  @param Item            the schedule
   --  @param Which           whose Finished
   --  @param Transcript_Hash the transcript hash at the Finished milestone
   --  @param Into            out: the verify_data, the hash's own width
   --  @param Error           out: No_Error, or a derivation failure
   procedure Compute_Finished
     (Item            : Schedule;
      Which           : Party;
      Transcript_Hash : Byte_Array;
      Into            : out Byte_Array;
      Error           : out SSL.Errors.Error_Information)
     with Pre => Current_Stage (Item) >= Handshake_Stage
                 and then Transcript_Hash'Length = Digest_Width (Item)
                 and then Into'Length = Digest_Width (Item);

   --  Advance one direction's application traffic secret one generation, which
   --  is what KeyUpdate means (RFC 8446 section 7.2):
   --
   --      next = Expand-Label(current, "traffic upd", "", Hash.length)
   --
   --  The previous secret is scrubbed as part of this: after an update there is
   --  no way to recover the key that has just been retired, which is the
   --  forward secrecy the update exists to provide.
   --  @param Item  the schedule, at Master_Stage
   --  @param Which which direction's secret advances
   --  @param Error out: No_Error, or a derivation failure
   procedure Advance_Traffic_Secret
     (Item  : in out Schedule;
      Which : Party;
      Error : out SSL.Errors.Error_Information)
     with Pre => Current_Stage (Item) = Master_Stage;

   --  How many times a direction's secret has been advanced. Part of the
   --  no-nonce-reuse argument: a generation and a sequence number together
   --  never repeat, because the sequence resets only when the generation
   --  increases.
   function Generation (Item : Schedule; Which : Party) return Natural;

   --  Exporter output (RFC 8446 section 7.5):
   --
   --      Expand-Label(Derive-Secret(exporter_master, label, ""),
   --                   "exporter", Hash(context), length)
   --
   --  The context-presence flag is explicit, and under TLS 1.3 it makes no
   --  difference: RFC 8446 section 7.5 defines an absent context as the empty
   --  string, so both give the same output. It is a parameter because RFC 5705,
   --  which TLS 1.2 uses, does distinguish them, and because a caller writing
   --  `Has_Context => False` is saying something a caller passing an empty
   --  array might not have meant.
   --  @param Item        the schedule, at Master_Stage
   --  @param Label       the exporter label
   --  @param Context     the context octets, ignored when Has_Context is False
   --  @param Has_Context whether a context was supplied at all
   --  @param Into        out: the exported key material
   --  @param Error       out: No_Error, or a derivation failure
   procedure Export
     (Item        : Schedule;
      Label       : String;
      Context     : Byte_Array;
      Has_Context : Boolean;
      Into        : out Byte_Array;
      Error       : out SSL.Errors.Error_Information)
     with Pre => Current_Stage (Item) = Master_Stage
                 and then Into'Length in 1 .. 255
                 and then Label'Length in 1 .. 249;

   --  The PSK a ticket carries, derived from the resumption master secret and
   --  the ticket's nonce (RFC 8446 section 4.6.1):
   --
   --      PSK = Expand-Label(resumption_master, "resumption", nonce, Hash.length)
   --
   --  Each ticket has its own nonce, so several tickets from one connection
   --  yield unrelated PSKs and using one tells an attacker nothing about
   --  another.
   --  @param Item  the schedule, at Master_Stage
   --  @param Nonce the ticket nonce
   --  @param Into  out: the PSK, the hash's own width
   --  @param Error out: No_Error, or a derivation failure
   procedure Resumption_PSK
     (Item  : Schedule;
      Nonce : Byte_Array;
      Into  : out Byte_Array;
      Error : out SSL.Errors.Error_Information)
     with Pre => Current_Stage (Item) = Master_Stage
                 and then Into'Length = Digest_Width (Item);

   ---------------------------------------------------------------------------
   --  Widths
   ---------------------------------------------------------------------------

   --  The hash's digest width, which is the width of every stage secret.
   function Digest_Width (Item : Schedule) return Byte_Index
     with Pre => Is_Started (Item);

   --  The AEAD's key width.
   function Key_Width (Item : Schedule) return Byte_Index
     with Pre => Is_Started (Item);

private

   --  Every secret the schedule holds is at most the hash's digest width, so
   --  all of them are Schedule_Capacity. The key-agreement secret, which may be
   --  512 octets for ffdhe4096, is the caller's and is passed in as octets --
   --  it is never stored here.
   type Party_Secrets is record
      Handshake_Traffic : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
      Application       : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
      Generation        : Natural := 0;
   end record;

   type Party_Array is array (Party) of Party_Secrets;

   type Schedule is limited record
      Started : Boolean := False;
      Reached : Stage := Unstarted;
      Resumption_Ready : Boolean := False;
      Suite   : SSL.Cipher_Suites.Cipher_Suite := SSL.Cipher_Suites.TLS_AES_128_GCM_SHA256;
      With_PSK : Boolean := False;

      Early      : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
      Binder     : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
      Handshake  : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
      Master     : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
      Exporter   : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);
      Resumption : SSL.Secrets.Secret (SSL.Secrets.Schedule_Capacity);

      Sides : Party_Array;
   end record;

end SSL.Key_Schedule;
