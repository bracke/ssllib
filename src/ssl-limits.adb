package body SSL.Limits is

   --  The largest expansion a protected record adds over its plaintext: the
   --  inner content type octet, this implementation's padding allowance and
   --  the AEAD tag. Used to size the input buffer floor.
   Maximum_Record_Expansion : constant := 1 + 256 + 16;

   -----------
   -- Image --
   -----------

   function Image (Kind : Limit_Kind) return String is
   begin
      case Kind is
         when Plaintext_Record          => return "plaintext_record";
         when Record_Padding            => return "record_padding";
         when Consecutive_Empty_Records => return "consecutive_empty_records";
         when Compatibility_CCS         => return "compatibility_ccs";
         when Handshake_Message         => return "handshake_message";
         when Certificate_Message       => return "certificate_message";
         when Certificate_Size          => return "certificate_size";
         when Certificate_Count         => return "certificate_count";
         when Path_Depth                => return "path_depth";
         when Handshake_Message_Count   => return "handshake_message_count";
         when Extension_Block           => return "extension_block";
         when Extension_Count           => return "extension_count";
         when Extension_Body            => return "extension_body";
         when ALPN_Protocols            => return "alpn_protocols";
         when Server_Name_Length        => return "server_name_length";
         when Cipher_Suites             => return "cipher_suites";
         when Supported_Groups          => return "supported_groups";
         when Signature_Schemes         => return "signature_schemes";
         when Key_Shares                => return "key_shares";
         when PSK_Identities            => return "psk_identities";
         when Certificate_Authorities   => return "certificate_authorities";
         when Cookie_Length             => return "cookie_length";
         when Ciphertext_Queue          => return "ciphertext_queue";
         when Plaintext_Queue           => return "plaintext_queue";
         when Input_Buffer              => return "input_buffer";
         when Trust_Anchors             => return "trust_anchors";
         when OCSP_Response             => return "ocsp_response";
         when OCSP_Response_Count       => return "ocsp_response_count";
         when CRL_Size                  => return "crl_size";
         when CRL_Count                 => return "crl_count";
         when Pins                      => return "pins";
         when Ticket_Size               => return "ticket_size";
         when Ticket_Count              => return "ticket_count";
         when Session_Cache_Entries     => return "session_cache_entries";
         when Ticket_Decrypt_Keys       => return "ticket_decrypt_keys";
         when Peer_Key_Updates          => return "peer_key_updates";
         when Record_Usage              => return "record_usage";
         when Octet_Usage               => return "octet_usage";
         when Diagnostic_Events         => return "diagnostic_events";
         when Secondary_Errors          => return "secondary_errors";
      end case;
   end Image;

   -----------
   -- Value --
   -----------

   function Value (Item : Resource_Limits; Kind : Limit_Kind) return Long_Long_Integer is
   begin
      case Kind is
         when Plaintext_Record          => return Long_Long_Integer (Item.Maximum_Plaintext_Record);
         when Record_Padding            => return Long_Long_Integer (Item.Maximum_Record_Padding);
         when Consecutive_Empty_Records => return Long_Long_Integer (Item.Maximum_Consecutive_Empty_Records);
         when Compatibility_CCS         => return Long_Long_Integer (Item.Maximum_Compatibility_CCS);
         when Handshake_Message         => return Long_Long_Integer (Item.Maximum_Handshake_Message);
         when Certificate_Message       => return Long_Long_Integer (Item.Maximum_Certificate_Message);
         when Certificate_Size          => return Long_Long_Integer (Item.Maximum_Certificate);
         when Certificate_Count         => return Long_Long_Integer (Item.Maximum_Certificate_Count);
         when Path_Depth                => return Long_Long_Integer (Item.Maximum_Path_Depth);
         when Handshake_Message_Count   => return Long_Long_Integer (Item.Maximum_Handshake_Messages);
         when Extension_Block           => return Long_Long_Integer (Item.Maximum_Extension_Block);
         when Extension_Count           => return Long_Long_Integer (Item.Maximum_Extension_Count);
         when Extension_Body            => return Long_Long_Integer (Item.Maximum_Extension_Body);
         when ALPN_Protocols            => return Long_Long_Integer (Item.Maximum_ALPN_Protocols);
         when Server_Name_Length        => return Long_Long_Integer (Item.Maximum_Server_Name_Length);
         when Cipher_Suites             => return Long_Long_Integer (Item.Maximum_Cipher_Suites);
         when Supported_Groups          => return Long_Long_Integer (Item.Maximum_Supported_Groups);
         when Signature_Schemes         => return Long_Long_Integer (Item.Maximum_Signature_Schemes);
         when Key_Shares                => return Long_Long_Integer (Item.Maximum_Key_Shares);
         when PSK_Identities            => return Long_Long_Integer (Item.Maximum_PSK_Identities);
         when Certificate_Authorities   => return Long_Long_Integer (Item.Maximum_Certificate_Authorities);
         when Cookie_Length             => return Long_Long_Integer (Item.Maximum_Cookie_Length);
         when Ciphertext_Queue          => return Long_Long_Integer (Item.Maximum_Ciphertext_Queue);
         when Plaintext_Queue           => return Long_Long_Integer (Item.Maximum_Plaintext_Queue);
         when Input_Buffer              => return Long_Long_Integer (Item.Maximum_Input_Buffer);
         when Trust_Anchors             => return Long_Long_Integer (Item.Maximum_Trust_Anchors);
         when OCSP_Response             => return Long_Long_Integer (Item.Maximum_OCSP_Response);
         when OCSP_Response_Count       => return Long_Long_Integer (Item.Maximum_OCSP_Responses);
         when CRL_Size                  => return Long_Long_Integer (Item.Maximum_CRL_Size);
         when CRL_Count                 => return Long_Long_Integer (Item.Maximum_CRLs);
         when Pins                      => return Long_Long_Integer (Item.Maximum_Pins);
         when Ticket_Size               => return Long_Long_Integer (Item.Maximum_Ticket_Size);
         when Ticket_Count              => return Long_Long_Integer (Item.Maximum_Tickets_Per_Connection);
         when Session_Cache_Entries     => return Long_Long_Integer (Item.Maximum_Session_Cache_Entries);
         when Ticket_Decrypt_Keys       => return Long_Long_Integer (Item.Maximum_Ticket_Decrypt_Keys);
         when Peer_Key_Updates          => return Long_Long_Integer (Item.Maximum_Peer_Key_Updates);
         when Record_Usage              => return Long_Long_Integer (Item.Hard_Record_Limit);
         when Octet_Usage               => return Item.Hard_Octet_Limit;
         when Diagnostic_Events         => return Long_Long_Integer (Item.Maximum_Diagnostic_Events);
         when Secondary_Errors          => return Long_Long_Integer (Item.Maximum_Secondary_Errors);
      end case;
   end Value;

   ----------------
   -- Invalidity --
   ----------------

   function Invalidity (Item : Resource_Limits) return String is
   begin
      if Item.Maximum_Plaintext_Record > Protocol_Plaintext_Record_Limit then
         return "maximum_plaintext_record above the TLS record ceiling";
      end if;

      if Item.Maximum_Plaintext_Record < Minimum_Record_Size_Limit then
         return "maximum_plaintext_record below the smallest expressible record_size_limit";
      end if;

      if Item.Maximum_Record_Padding > Protocol_Plaintext_Record_Limit then
         return "maximum_record_padding above the TLS record ceiling";
      end if;

      if Item.Maximum_Certificate > Item.Maximum_Certificate_Message then
         return "maximum_certificate larger than maximum_certificate_message";
      end if;

      if Item.Maximum_Extension_Body > Item.Maximum_Extension_Block then
         return "maximum_extension_body larger than maximum_extension_block";
      end if;

      --  A queue that cannot hold one maximum-size record can never drain a
      --  full record, so the engine would report backpressure forever.
      if Long_Long_Integer (Item.Maximum_Ciphertext_Queue)
        < Long_Long_Integer (Item.Maximum_Plaintext_Record) + Maximum_Record_Expansion + 5
      then
         return "maximum_ciphertext_queue cannot hold one protected record";
      end if;

      if Item.Maximum_Plaintext_Queue < Item.Maximum_Plaintext_Record then
         return "maximum_plaintext_queue cannot hold one plaintext record";
      end if;

      if Long_Long_Integer (Item.Maximum_Input_Buffer)
        < Long_Long_Integer (Item.Maximum_Plaintext_Record) + Maximum_Record_Expansion + 5
      then
         return "maximum_input_buffer cannot hold one protected record";
      end if;

      --  The soft threshold has to leave room for the update to be queued,
      --  sent and acknowledged by the peer's own switch before the hard limit
      --  forbids any further record.
      if Item.Key_Update_Record_Threshold >= Item.Hard_Record_Limit then
         return "key_update_record_threshold not below hard_record_limit";
      end if;

      if Item.Key_Update_Octet_Threshold >= Item.Hard_Octet_Limit then
         return "key_update_octet_threshold not below hard_octet_limit";
      end if;

      if Item.Maximum_Path_Depth < 2 then
         return "maximum_path_depth below a leaf and one anchor";
      end if;

      --  Maximum_Certificate_Count needs no floor check: the component is
      --  Positive, so one certificate is already the minimum the type allows.

      if Item.Maximum_Server_Name_Length > 253 then
         return "maximum_server_name_length above the DNS name ceiling";
      end if;

      if Item.Maximum_Ticket_Size < 64 then
         return "maximum_ticket_size below the smallest authenticated ticket";
      end if;

      return "";
   end Invalidity;

   --------------
   -- Is_Valid --
   --------------

   function Is_Valid (Item : Resource_Limits) return Boolean is
   begin
      return Invalidity (Item) = "";
   end Is_Valid;

end SSL.Limits;
