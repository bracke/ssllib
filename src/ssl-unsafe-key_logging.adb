with SSL.Crypto;

package body SSL.Unsafe.Key_Logging is

   Hex : constant String := "0123456789abcdef";

   ---------------
   -- Image --
   ---------------

   function Image (Item : Secret_Label) return String is
     (case Item is
         when Client_Handshake_Traffic_Secret => "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
         when Server_Handshake_Traffic_Secret => "SERVER_HANDSHAKE_TRAFFIC_SECRET",
         when Client_Traffic_Secret_0         => "CLIENT_TRAFFIC_SECRET_0",
         when Server_Traffic_Secret_0         => "SERVER_TRAFFIC_SECRET_0",
         when Exporter_Secret                 => "EXPORTER_SECRET",
         when Client_Random_To_Master         => "CLIENT_RANDOM",
         when Early_Traffic_Secret            => "CLIENT_EARLY_TRAFFIC_SECRET");

   --------------
   -- Emit --
   --------------

   procedure Emit
     (Item          : in out Sink'Class;
      Label         : Secret_Label;
      Client_Random : Byte_Array;
      Secret        : Byte_Array;
      Error         : out SSL.Errors.Error_Information)
   is
      Text : constant String := Image (Label);

      --  Label, space, 64 hexadecimal characters, space, up to 128 more.
      Line : String (1 .. Text'Length + 1 + 64 + 1 + 128) := [others => ' '];
      Last : Natural := 0;

      procedure Append_Hex (Data : Byte_Array);

      procedure Append_Hex (Data : Byte_Array) is
      begin
         for Octet of Data loop
            Line (Last + 1) := Hex (Natural (Octet) / 16 + 1);
            Line (Last + 2) := Hex (Natural (Octet) mod 16 + 1);
            Last := Last + 2;
         end loop;
      end Append_Hex;

      --  The buffer holds a traffic secret in hexadecimal, which is a traffic
      --  secret. It is wiped on every path out of this subprogram, including
      --  the one where the sink raised.
      procedure Scrub_Line;

      procedure Scrub_Line is
         Overlay : Byte_Array (1 .. Line'Length)
           with Import, Address => Line'Address;
      begin
         SSL.Crypto.Scrub (Overlay);
      end Scrub_Line;
   begin
      Error := SSL.Errors.No_Error;

      Line (1 .. Text'Length) := Text;
      Last := Text'Length;
      Line (Last + 1) := ' ';
      Last := Last + 1;
      Append_Hex (Client_Random);
      Line (Last + 1) := ' ';
      Last := Last + 1;
      Append_Hex (Secret);

      begin
         Item.Write_Line (Line (1 .. Last));
      exception
         when others =>
            --  Deliberately no exception occurrence in the message: it would be
            --  the application's own text, and this failure's rendering reaches
            --  logs that travel.
            Scrub_Line;
            Error := SSL.Errors.Make
              (Code     => SSL.Errors.Code_Application_Callback_Raised,
               Origin   => SSL.Errors.Application_Callback,
               Provider => Item.Description);
            return;
      end;

      Scrub_Line;
   end Emit;

end SSL.Unsafe.Key_Logging;
