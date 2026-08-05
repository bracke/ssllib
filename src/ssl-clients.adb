package body SSL.Clients is

   ------------------
   -- Connect --
   ------------------

   procedure Connect
     (Item     : in out SSL.Connections.Connection;
      Config   : not null access constant SSL.Configurations.Client_Configuration;
      Medium   : not null SSL.Transports.Transport_Reference;
      Identity : Connection_ID := No_Connection;
      Now      : SSL.Clocks.Wall_Time := SSL.Clocks.Current_UTC;
      Error    : out SSL.Errors.Error_Information)
   is
   begin
      SSL.Connections.Connect (Item, Config, Medium, Identity, Now, Error);
   end Connect;

end SSL.Clients;
