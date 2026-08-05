package body SSL.Exporters is

   ----------------
   -- Export --
   ----------------

   procedure Export
     (Item        : SSL.Connections.Connection;
      Label       : String;
      Context     : Byte_Array;
      Has_Context : Boolean;
      Into        : out Byte_Array;
      Error       : out SSL.Errors.Error_Information)
   is
   begin
      SSL.Connections.Export_Keying_Material
        (Item        => Item,
         Label       => Label,
         Context     => Context,
         Has_Context => Has_Context,
         Into        => Into,
         Error       => Error);
   end Export;

   procedure Export
     (Item  : SSL.Connections.Connection;
      Label : String;
      Into  : out Byte_Array;
      Error : out SSL.Errors.Error_Information)
   is
   begin
      --  Has_Context is False, not "an empty context". The two are different
      --  inputs to the derivation, and this overload exists so that a caller
      --  who means the first cannot accidentally write the second.
      Export (Item, Label, Empty_Bytes, Has_Context => False, Into => Into, Error => Error);
   end Export;

end SSL.Exporters;
