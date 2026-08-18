--  @summary Immutable resource bounds. Every count and length a peer can
--  influence is bounded here, and the bound is checked before the storage is
--  reserved rather than after.
--
--  A TLS implementation reads attacker-chosen lengths before it can
--  authenticate anything: the record length, the handshake message length, the
--  certificate list length, the extension block length. Each of those is an
--  invitation to allocate. This package is the single place the answers live,
--  so that a hostile peer meets a refusal of a stated size rather than a
--  memory exhaustion whose size nobody knows.
--
--  The type is a plain immutable record so a configuration can hold one by
--  value and share it between tasks. Build one with Default_Limits and
--  override fields, or use one of the named profiles.
package SSL.Limits is
   pragma Preelaborate;

   --  The plaintext record ceiling TLS itself fixes (RFC 8446 section 5.1).
   --  A larger value is not expressible on the wire, so this is a constant and
   --  not a policy knob; record_size_limit can only lower the effective size.
   Protocol_Plaintext_Record_Limit : constant := 16_384;

   --  The smallest record_size_limit a peer may ask for (RFC 8449 section 4).
   Minimum_Record_Size_Limit : constant := 64;

   type Resource_Limits is record

      ------------------------------------------------------------------------
      --  Record layer
      ------------------------------------------------------------------------

      --  Largest plaintext this endpoint will emit in one record, and the
      --  largest it will accept after removing padding. Never above
      --  Protocol_Plaintext_Record_Limit.
      Maximum_Plaintext_Record : Positive := Protocol_Plaintext_Record_Limit;

      --  Padding octets this endpoint is willing to add to one record. Padding
      --  costs bandwidth and buys traffic-analysis resistance; the default
      --  buys none, because a caller that wants it should say how much.
      Maximum_Record_Padding : Natural := 0;

      --  Consecutive records carrying no plaintext this endpoint will tolerate
      --  before treating the peer as making no progress. RFC 8446 permits
      --  empty application_data records; an unbounded run of them is a denial
      --  of service that costs the sender nothing.
      Maximum_Consecutive_Empty_Records : Positive := 32;

      --  ChangeCipherSpec records accepted in the TLS 1.3 middlebox
      --  compatibility window. Outside that window CCS is a protocol
      --  violation, not a tolerated oddity.
      Maximum_Compatibility_CCS : Natural := 2;

      ------------------------------------------------------------------------
      --  Handshake
      ------------------------------------------------------------------------

      --  Largest single reassembled handshake message other than Certificate.
      Maximum_Handshake_Message : Positive := 1024 * 1024;

      --  Largest Certificate message, and largest single certificate in it.
      Maximum_Certificate_Message : Positive := 4 * 1024 * 1024;
      Maximum_Certificate : Positive := 1024 * 1024;

      --  Certificates accepted in one chain, and links a path build may walk.
      Maximum_Certificate_Count : Positive := 16;
      Maximum_Path_Depth : Positive := 12;

      --  Handshake messages accepted in one flight, so that a peer cannot
      --  drive an unbounded state machine with zero-length messages.
      Maximum_Handshake_Messages : Positive := 64;

      ------------------------------------------------------------------------
      --  Extensions and negotiated lists
      ------------------------------------------------------------------------

      Maximum_Extension_Block : Positive := 64 * 1024;
      Maximum_Extension_Count : Positive := 64;
      Maximum_Extension_Body : Positive := 16 * 1024;

      Maximum_ALPN_Protocols : Positive := 32;
      Maximum_Server_Name_Length : Positive := 253;
      Maximum_Cipher_Suites : Positive := 64;
      Maximum_Supported_Groups : Positive := 32;
      Maximum_Signature_Schemes : Positive := 48;
      Maximum_Key_Shares : Positive := 4;
      Maximum_PSK_Identities : Positive := 4;
      Maximum_Certificate_Authorities : Positive := 32;
      Maximum_Cookie_Length : Positive := 1024;

      ------------------------------------------------------------------------
      --  Queues
      ------------------------------------------------------------------------

      --  Encrypted output queued for the caller to drain, and plaintext
      --  queued for the caller to read. Both are the backpressure boundary:
      --  when the queue is full the engine reports that rather than growing.
      --
      --  These are what the engine reserves, per connection, at the moment it
      --  starts -- so they are a memory decision as much as a backpressure
      --  one, and the defaults are what this library has always reserved
      --  rather than the megabyte that used to stand here and reach nothing.
      --  A megabyte each would have been four times the footprint of every
      --  connection every consumer opens, which is not a change a corrected
      --  number should smuggle in.
      --
      --  Eight protected records of output, because a whole handshake flight
      --  -- EncryptedExtensions through Finished, with a certificate chain in
      --  the middle -- is queued before a transport has taken any of it.
      Maximum_Ciphertext_Queue : Positive :=
        8 * (Protocol_Plaintext_Record_Limit + 256 + 5);

      --  Four plaintext records for the reader to fall behind by.
      Maximum_Plaintext_Queue : Positive :=
        4 * Protocol_Plaintext_Record_Limit;

      --  Encrypted input held while a record is incomplete. One maximum-size
      --  protected record plus its header and expansion is the floor; two, so
      --  that a partially delivered record and the one behind it both fit.
      Maximum_Input_Buffer : Positive :=
        2 * (Protocol_Plaintext_Record_Limit + 256 + 5);

      ------------------------------------------------------------------------
      --  Trust, revocation and pinning
      ------------------------------------------------------------------------

      --  A bound on *hostile* input, so it has to sit above what an honest
      --  host carries -- and 512 did not. A stock Windows runner's
      --  LocalMachine\Root holds 563 root certificates; Linux carries 121 and
      --  macOS 159. Load_System_Anchors refuses a store larger than this
      --  rather than truncating it, which is right -- a silently shortened
      --  trust base rejects certificates for a reason nobody can see -- so on
      --  Windows the whole system store was refused and every TLS connection
      --  from this library failed with no anchors at all.
      --
      --  Raised to a number no real store is near, and still a bound: what it
      --  is defending against is a store somebody handed us, not the one the
      --  operating system ships.
      Maximum_Trust_Anchors : Positive := 4096;
      Maximum_OCSP_Response : Positive := 64 * 1024;
      Maximum_OCSP_Responses : Positive := 8;
      Maximum_CRL_Size : Positive := 1024 * 1024;
      Maximum_CRLs : Positive := 8;
      Maximum_Pins : Positive := 16;

      ------------------------------------------------------------------------
      --  Sessions and tickets
      ------------------------------------------------------------------------

      Maximum_Ticket_Size : Positive := 8 * 1024;
      Maximum_Tickets_Per_Connection : Positive := 8;
      Maximum_Session_Cache_Entries : Positive := 256;
      Maximum_Ticket_Decrypt_Keys : Positive := 4;

      ------------------------------------------------------------------------
      --  Post-handshake traffic management
      ------------------------------------------------------------------------

      --  KeyUpdate messages accepted from the peer per connection. A peer that
      --  asks for more is flooding: each update costs a key schedule step.
      Maximum_Peer_Key_Updates : Positive := 64;

      --  Records and octets this endpoint will protect under one traffic key
      --  before it must update. Well below the AEAD confidentiality and
      --  integrity limits of RFC 8446 appendix B.4 / RFC 9147, so that the
      --  update has room to complete before the hard limit.
      Key_Update_Record_Threshold : Positive := 2 ** 23;
      Key_Update_Octet_Threshold : Long_Long_Integer := 2 ** 34;

      --  The hard ceiling. At this point no further record may be protected
      --  under the current key, and if the update cannot complete the
      --  connection fails closed rather than reusing the key.
      Hard_Record_Limit : Positive := 2 ** 24;
      Hard_Octet_Limit : Long_Long_Integer := 2 ** 36;

      ------------------------------------------------------------------------
      --  Diagnostics and error accumulation
      ------------------------------------------------------------------------

      --  Diagnostic events emitted for one connection. Diagnostics must not
      --  become the denial of service they were added to explain.
      Maximum_Diagnostic_Events : Positive := 1024;

      --  Failures recorded after the first terminal one. The first is
      --  preserved exactly; the rest are counted and bounded.
      Maximum_Secondary_Errors : Positive := 8;
   end record;

   --  The defaults above, as a value.
   Default_Limits : constant Resource_Limits := (others => <>);

   --  Tighter bounds for an endpoint facing the open internet with small
   --  peers: lower queues, fewer certificates, less padding tolerance. Nothing
   --  here weakens verification; it only refuses sooner.
   Constrained_Limits : constant Resource_Limits :=
     (Maximum_Plaintext_Record           => Protocol_Plaintext_Record_Limit,
      Maximum_Handshake_Message          => 128 * 1024,
      Maximum_Certificate_Message        => 512 * 1024,
      Maximum_Certificate                => 128 * 1024,
      Maximum_Certificate_Count          => 8,
      Maximum_Path_Depth                 => 6,
      Maximum_Extension_Block            => 16 * 1024,
      Maximum_Extension_Count            => 32,
      Maximum_Extension_Body             => 8 * 1024,
      Maximum_Ciphertext_Queue           => 128 * 1024,
      Maximum_Plaintext_Queue            => 128 * 1024,
      --  Deliberately below what a desktop host's own store holds: an endpoint
      --  choosing these bounds is one that names its own anchors, and a host
      --  store of several hundred roots is not what it means to trust.
      --
      --  Pairing these bounds with Load_System_Anchors is therefore a
      --  configuration that cannot hold this host, and it is refused as one:
      --  Code_System_Trust_Exceeds_Bound, whose text says how many the store
      --  holds and how many these allow. A Windows host carries 563, which is
      --  over the *default* 4096's predecessor and far over this.
      Maximum_Trust_Anchors              => 256,
      Maximum_Session_Cache_Entries      => 64,
      Maximum_Diagnostic_Events          => 128,
      others                             => <>);

   --  Why a limit refused, as a value a structured error can carry. The name
   --  is the diagnostic: an operator reading "certificate_count" knows which
   --  bound to raise, and a peer learns only that something was too large.
   type Limit_Kind is
     (Plaintext_Record,
      Record_Padding,
      Consecutive_Empty_Records,
      Compatibility_CCS,
      Handshake_Message,
      Certificate_Message,
      Certificate_Size,
      Certificate_Count,
      Path_Depth,
      Handshake_Message_Count,
      Extension_Block,
      Extension_Count,
      Extension_Body,
      ALPN_Protocols,
      Server_Name_Length,
      Cipher_Suites,
      Supported_Groups,
      Signature_Schemes,
      Key_Shares,
      PSK_Identities,
      Certificate_Authorities,
      Cookie_Length,
      Ciphertext_Queue,
      Plaintext_Queue,
      Input_Buffer,
      Trust_Anchors,
      OCSP_Response,
      OCSP_Response_Count,
      CRL_Size,
      CRL_Count,
      Pins,
      Ticket_Size,
      Ticket_Count,
      Session_Cache_Entries,
      Ticket_Decrypt_Keys,
      Peer_Key_Updates,
      Record_Usage,
      Octet_Usage,
      Diagnostic_Events,
      Secondary_Errors);

   --  Short stable text naming a limit, for diagnostics and error parameters.
   --  @param Kind the limit that refused
   --  @return lower-case snake-case text, stable across releases
   function Image (Kind : Limit_Kind) return String;

   --  The configured value of one limit, so a diagnostic can report both what
   --  was asked for and what was allowed.
   --  @param Item the limits in force
   --  @param Kind which limit to read
   --  @return the bound, as a count of octets or of items
   function Value (Item : Resource_Limits; Kind : Limit_Kind) return Long_Long_Integer;

   --  Are these limits internally consistent and usable?
   --
   --  Rejects a plaintext record above what TLS can express, queues too small
   --  to hold one record, a certificate larger than the message containing it,
   --  a soft key-update threshold at or above the hard ceiling, and an input
   --  buffer that cannot hold one maximum-size protected record. A
   --  configuration built on inconsistent limits would deadlock rather than
   --  refuse, which is the failure this check exists to prevent.
   --  @param Item the limits to check
   --  @return True when every bound is usable and mutually consistent
   function Is_Valid (Item : Resource_Limits) return Boolean;

   --  Which rule Is_Valid broke, for a configuration error message.
   --  @param Item the limits to check
   --  @return empty when Is_Valid, otherwise short text naming the rule
   function Invalidity (Item : Resource_Limits) return String;

end SSL.Limits;
