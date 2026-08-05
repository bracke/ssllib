package body SSL.Sessions.Client_Caches is

   function Raised
     (Item : Cache'Class) return SSL.Errors.Error_Information
   is (SSL.Errors.Make
         (Code     => SSL.Errors.Code_Application_Callback_Raised,
          Origin   => SSL.Errors.Application_Callback,
          Provider => Item.Description));

   --------------------------
   -- Look_Up_Safely --
   --------------------------

   procedure Look_Up_Safely
     (Item    : in out Cache'Class;
      Name    : SSL.Server_Names.DNS_Name;
      Context : Security_Context_ID;
      At_Time : SSL.Clocks.Wall_Time;
      Into    : in out Session;
      Found   : out Boolean;
      Error   : out SSL.Errors.Error_Information)
   is
   begin
      Found := False;
      Error := SSL.Errors.No_Error;

      begin
         Item.Look_Up (Name, Context, At_Time, Into, Found);
      exception
         when others =>
            --  Deliberately no exception occurrence in the message: it would be
            --  the application's own text, and this failure's rendering reaches
            --  logs that travel.
            Wipe (Into);
            Found := False;
            Error := Raised (Item);
            return;
      end;

      if Found and then not Is_Present (Into) then
         --  A cache claiming to have found something and supplying nothing.
         --  Believing it would mean offering an empty session.
         Found := False;
      end if;
   end Look_Up_Safely;

   ------------------------
   -- Store_Safely --
   ------------------------

   procedure Store_Safely
     (Item  : in out Cache'Class;
      Value : Session;
      Kept  : out Boolean;
      Error : out SSL.Errors.Error_Information)
   is
   begin
      Kept := False;
      Error := SSL.Errors.No_Error;

      begin
         Item.Store (Value, Kept);
      exception
         when others =>
            Kept := False;
            Error := Raised (Item);
      end;
   end Store_Safely;

   --------------------------
   -- Discard_Safely --
   --------------------------

   procedure Discard_Safely
     (Item    : in out Cache'Class;
      Name    : SSL.Server_Names.DNS_Name;
      Context : Security_Context_ID)
   is
   begin
      begin
         Item.Discard (Name, Context);
      exception
         when others =>
            --  Nothing reported. A cache that could not forget a session is a
            --  cache that will offer it again and have it refused again, which
            --  costs a round trip and no security.
            null;
      end;
   end Discard_Safely;

end SSL.Sessions.Client_Caches;
