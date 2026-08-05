package body SSL.Servers is

   ----------------------------
   -- Accept_Connection --
   ----------------------------

   procedure Accept_Connection
     (Item     : in out SSL.Connections.Connection;
      Config   : not null access constant SSL.Configurations.Server_Configuration;
      Medium   : not null SSL.Transports.Transport_Reference;
      Identity : Connection_ID := No_Connection;
      Now      : SSL.Clocks.Wall_Time := SSL.Clocks.Current_UTC;
      Error    : out SSL.Errors.Error_Information)
   is
   begin
      SSL.Connections.Accept_Connection (Item, Config, Medium, Identity, Now, Error);
   end Accept_Connection;

end SSL.Servers;
