with Ada.Exceptions;

with SSL.Blocking;

package body SSL.Streams is

   -----------------------
   -- Set_Deadline --
   -----------------------

   procedure Set_Deadline (Item : in out Connection_Stream; Value : SSL.Clocks.Deadline) is
   begin
      Item.Expires_At := Value;
   end Set_Deadline;

   ---------------
   -- Read --
   ---------------

   overriding procedure Read
     (Stream : in out Connection_Stream;
      Item   : out Ada.Streams.Stream_Element_Array;
      Last   : out Ada.Streams.Stream_Element_Offset)
   is
      Buffer : Byte_Array (1 .. Byte_Index (Item'Length)) := [others => 0];
      Count  : Byte_Index;
   begin
      Item := [others => 0];
      Last := Item'First - 1;

      if Item'Length = 0 then
         return;
      end if;

      SSL.Blocking.Read_Some
        (Item     => Stream.Target.all,
         Into     => Buffer,
         Count    => Count,
         Until_At => Stream.Expires_At,
         Error    => Stream.Failure);

      if SSL.Errors.Is_Error (Stream.Failure) then
         --  The one place in this library where a failure becomes an exception,
         --  and only because the inherited signature has nowhere to put one.
         --  The message is the operator rendering, which the disclosure rules
         --  have already filtered: it never carries key material or plaintext.
         Ada.Exceptions.Raise_Exception
           (Stream_Failure'Identity, SSL.Errors.Image (Stream.Failure));
      end if;

      --  A zero count with no failure is end of stream, which
      --  Ada.Streams reports as Last < Item'First. That is what
      --  `Type'Read` tests, so an orderly close reads as an orderly close
      --  rather than as an error.
      if Count > 0 then
         Last := Item'First + Ada.Streams.Stream_Element_Offset (Count) - 1;
         Item (Item'First .. Last) := Buffer (1 .. Count);
      end if;
   end Read;

   ----------------
   -- Write --
   ----------------

   overriding procedure Write
     (Stream : in out Connection_Stream;
      Item   : Ada.Streams.Stream_Element_Array)
   is
   begin
      if Item'Length = 0 then
         return;
      end if;

      SSL.Blocking.Write_All
        (Item     => Stream.Target.all,
         Data     => Item,
         Until_At => Stream.Expires_At,
         Error    => Stream.Failure);

      if SSL.Errors.Is_Error (Stream.Failure) then
         Ada.Exceptions.Raise_Exception
           (Stream_Failure'Identity, SSL.Errors.Image (Stream.Failure));
      end if;
   end Write;

end SSL.Streams;
