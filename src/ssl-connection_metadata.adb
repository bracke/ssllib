package body SSL.Connection_Metadata is

   --------------------
   -- No_Metadata --
   --------------------

   function No_Metadata return Metadata is
      Blank : Metadata;
   begin
      return Blank;
   end No_Metadata;

   -------------------
   -- Establish --
   -------------------

   procedure Establish
     (Item        : out Metadata;
      Identity    : Connection_ID;
      Context     : Security_Context_ID;
      Version     : SSL.Versions.Protocol_Version;
      Suite       : SSL.Cipher_Suites.Cipher_Suite;
      Group       : SSL.Supported_Groups.Named_Group;
      Protocol    : SSL.ALPN.Protocol_Name;
      Has_Protocol : Boolean;
      Name        : SSL.Server_Names.DNS_Name;
      Authenticated : Boolean;
      Scheme      : SSL.Signature_Schemes.Signature_Scheme;
      Leaf        : Certificate_Fingerprint;
      Public_Key  : Certificate_Fingerprint;
      Depth       : Natural;
      Was_Resumed : Boolean)
   is
   begin
      Item :=
        (Established   => True,
         Identity      => Identity,
         Context       => Context,
         Version       => Version,
         Suite         => Suite,
         Group         => Group,
         Protocol      => Protocol,
         Has_Protocol  => Has_Protocol,
         Name          => Name,
         Authenticated => Authenticated,
         Scheme        => Scheme,
         Leaf          => Leaf,
         Public_Key    => Public_Key,
         Depth         => Depth,
         Was_Resumed   => Was_Resumed);
   end Establish;

   ---------------
   -- Image --
   ---------------

   function Image (Item : Metadata) return String is
   begin
      if not Item.Established then
         return "not established";
      end if;

      return SSL.Versions.Image (Item.Version)
        & " " & SSL.Cipher_Suites.Image (Item.Suite)
        & " over " & SSL.Supported_Groups.Image (Item.Group)
        & (if Item.Has_Protocol then " as " & SSL.ALPN.Image (Item.Protocol) else "")
        & (if SSL.Server_Names.Is_Present (Item.Name)
           then " for " & SSL.Server_Names.Image (Item.Name) else "")
        & (if Item.Authenticated
           then ", peer authenticated with "
                & SSL.Signature_Schemes.Image (Item.Scheme)
           else ", peer not authenticated")
        & (if Item.Was_Resumed then ", resumed" else "");
   end Image;

end SSL.Connection_Metadata;
