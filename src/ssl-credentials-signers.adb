package body SSL.Credentials.Signers is

   ------------------------
   -- Sign_Externally --
   ------------------------

   procedure Sign_Externally
     (Item        : in out External_Signer'Class;
      Scheme      : SSL.Signature_Schemes.Signature_Scheme;
      Signed_Data : Byte_Array;
      Signature   : out Byte_Array;
      Length      : out Byte_Index;
      Error       : out SSL.Errors.Error_Information)
   is
   begin
      Signature := [others => 0];
      Length := 0;
      Error := SSL.Errors.No_Error;

      begin
         Item.Sign (Scheme, Signed_Data, Signature, Length);
      exception
         when others =>
            --  The boundary. Application code raised, and it stops here: a
            --  handshake with traffic keys installed and buffers to scrub must
            --  not be unwound through by an exception from a provider.
            --
            --  Deliberately no exception occurrence in the message. It would be
            --  the application's own text, and this failure's rendering reaches
            --  logs that travel.
            Signature := [others => 0];
            Length := 0;
            Error := SSL.Errors.Make
              (Code     => SSL.Errors.Code_Provider_Callback_Raised,
               Origin   => SSL.Errors.External_Provider,
               Provider => Item.Description);
            return;
      end;

      if Length = 0 then
         Signature := [others => 0];
         Error := SSL.Errors.Make
           (Code     => SSL.Errors.Code_Provider_Refused,
            Origin   => SSL.Errors.External_Provider,
            Provider => Item.Description);
         return;
      end if;

      if Length > Signature'Length then
         --  A signer claiming to have written more than it was given a buffer
         --  for. Nothing can be trusted about the result, including the part
         --  that fits.
         Signature := [others => 0];
         Length := 0;
         Error := SSL.Errors.Make
           (Code     => SSL.Errors.Code_Provider_Refused,
            Origin   => SSL.Errors.External_Provider,
            Provider => Item.Description & ": reported an over-long signature");
      end if;
   end Sign_Externally;

   ------------------------
   -- Supports_Safely --
   ------------------------

   function Supports_Safely
     (Item   : External_Signer'Class;
      Scheme : SSL.Signature_Schemes.Signature_Scheme) return Boolean
   is
   begin
      return Item.Supports (Scheme);
   exception
      when others =>
         --  A signer that raises while being asked a question cannot be
         --  selected. Answering False is the safe direction: the connection
         --  falls back to another credential, or fails to negotiate, rather
         --  than committing to a signer that has already misbehaved.
         return False;
   end Supports_Safely;

end SSL.Credentials.Signers;
