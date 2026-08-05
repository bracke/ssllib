with SSL.Connection_Metadata;
with SSL.Exporters;

package body SSL.Channel_Bindings is

   --  RFC 9266 section 2 fixes the label. Written out rather than composed,
   --  because a composed one is a place for a stray character to hide and a
   --  binding that differs by one octet from the peer's is a binding that
   --  silently never matches.
   Exporter_Label : constant String := "EXPORTER-Channel-Binding";

   ---------------------------------
   -- Exporter_Binding --
   ---------------------------------

   procedure Exporter_Binding
     (Item  : SSL.Connections.Connection;
      Into  : out Byte_Array;
      Error : out SSL.Errors.Error_Information)
   is
   begin
      --  An empty context that is *supplied*, which is what RFC 9266 specifies
      --  and is not the same input as no context at all.
      SSL.Exporters.Export
        (Item        => Item,
         Label       => Exporter_Label,
         Context     => Empty_Bytes,
         Has_Context => True,
         Into        => Into,
         Error       => Error);
   end Exporter_Binding;

   ----------------------------------
   -- End_Point_Binding --
   ----------------------------------

   procedure End_Point_Binding
     (Item  : SSL.Connections.Connection;
      Into  : out Byte_Array;
      Error : out SSL.Errors.Error_Information)
   is
      Metadata : constant SSL.Connection_Metadata.Metadata :=
        SSL.Connections.Metadata_Of (Item);
   begin
      Into := [others => 0];
      Error := SSL.Errors.No_Error;

      if not SSL.Connection_Metadata.Is_Established (Metadata) then
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Handshake_Not_Complete, SSL.Errors.Caller_Request);
         return;
      end if;

      if not SSL.Connection_Metadata.Peer_Authenticated (Metadata) then
         --  No certificate was presented, so there is nothing to bind to. A
         --  resumed connection is the usual reason: it proves possession of an
         --  earlier key rather than of a certificate, and returning a binding
         --  derived from an earlier connection's certificate would claim
         --  something this connection did not establish.
         Error := SSL.Errors.Make
           (SSL.Errors.Code_Certificate_Not_Provided, SSL.Errors.Caller_Request);
         return;
      end if;

      declare
         Fingerprint : constant Certificate_Fingerprint :=
           SSL.Connection_Metadata.Peer_Certificate_Fingerprint (Metadata);
      begin
         if not Is_Present (Fingerprint) then
            Error := SSL.Errors.Make
              (SSL.Errors.Code_Certificate_Not_Provided, SSL.Errors.Caller_Request);
            return;
         end if;
         Into := Digest_Of (Fingerprint);
      end;
   end End_Point_Binding;

end SSL.Channel_Bindings;
