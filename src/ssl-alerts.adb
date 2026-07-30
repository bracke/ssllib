package body SSL.Alerts is

   ---------------
   -- Value_For --
   ---------------

   --  The two mappings below are each other's inverse, written as case
   --  statements over the closed sets so that the compiler refuses a
   --  description added to the type but not given a wire value.

   function Value_For (Description : Alert_Description) return Alert_Value is
   begin
      case Description is
         when Close_Notify                    => return Close_Notify_Value;
         when Unexpected_Message              => return Unexpected_Message_Value;
         when Bad_Record_MAC                  => return Bad_Record_MAC_Value;
         when Record_Overflow                 => return Record_Overflow_Value;
         when Handshake_Failure               => return Handshake_Failure_Value;
         when Bad_Certificate                 => return Bad_Certificate_Value;
         when Unsupported_Certificate         => return Unsupported_Certificate_Value;
         when Certificate_Revoked             => return Certificate_Revoked_Value;
         when Certificate_Expired             => return Certificate_Expired_Value;
         when Certificate_Unknown             => return Certificate_Unknown_Value;
         when Illegal_Parameter               => return Illegal_Parameter_Value;
         when Unknown_CA                      => return Unknown_CA_Value;
         when Access_Denied                   => return Access_Denied_Value;
         when Decode_Error                    => return Decode_Error_Value;
         when Decrypt_Error                   => return Decrypt_Error_Value;
         when Protocol_Version                => return Protocol_Version_Value;
         when Insufficient_Security           => return Insufficient_Security_Value;
         when Internal_Error                  => return Internal_Error_Value;
         when Inappropriate_Fallback          => return Inappropriate_Fallback_Value;
         when User_Canceled                   => return User_Canceled_Value;
         when Missing_Extension               => return Missing_Extension_Value;
         when Unsupported_Extension           => return Unsupported_Extension_Value;
         when Unrecognized_Name               => return Unrecognized_Name_Value;
         when Bad_Certificate_Status_Response => return Bad_Certificate_Status_Response_Value;
         when Unknown_PSK_Identity            => return Unknown_PSK_Identity_Value;
         when Certificate_Required            => return Certificate_Required_Value;
         when No_Application_Protocol         => return No_Application_Protocol_Value;
         when Unknown_Alert                   => return Internal_Error_Value;
      end case;
   end Value_For;

   ---------------------
   -- Description_For --
   ---------------------

   function Description_For (Item : Alert_Value) return Alert_Description is
   begin
      case Item is
         when Close_Notify_Value                    => return Close_Notify;
         when Unexpected_Message_Value              => return Unexpected_Message;
         when Bad_Record_MAC_Value                  => return Bad_Record_MAC;
         when Record_Overflow_Value                 => return Record_Overflow;
         when Handshake_Failure_Value               => return Handshake_Failure;
         when Bad_Certificate_Value                 => return Bad_Certificate;
         when Unsupported_Certificate_Value         => return Unsupported_Certificate;
         when Certificate_Revoked_Value             => return Certificate_Revoked;
         when Certificate_Expired_Value             => return Certificate_Expired;
         when Certificate_Unknown_Value             => return Certificate_Unknown;
         when Illegal_Parameter_Value               => return Illegal_Parameter;
         when Unknown_CA_Value                      => return Unknown_CA;
         when Access_Denied_Value                   => return Access_Denied;
         when Decode_Error_Value                    => return Decode_Error;
         when Decrypt_Error_Value                   => return Decrypt_Error;
         when Protocol_Version_Value                => return Protocol_Version;
         when Insufficient_Security_Value           => return Insufficient_Security;
         when Internal_Error_Value                  => return Internal_Error;
         when Inappropriate_Fallback_Value          => return Inappropriate_Fallback;
         when User_Canceled_Value                   => return User_Canceled;
         when Missing_Extension_Value               => return Missing_Extension;
         when Unsupported_Extension_Value           => return Unsupported_Extension;
         when Unrecognized_Name_Value               => return Unrecognized_Name;
         when Bad_Certificate_Status_Response_Value => return Bad_Certificate_Status_Response;
         when Unknown_PSK_Identity_Value            => return Unknown_PSK_Identity;
         when Certificate_Required_Value            => return Certificate_Required;
         when No_Application_Protocol_Value         => return No_Application_Protocol;
         when others                                => return Unknown_Alert;
      end case;
   end Description_For;

   --------------
   -- No_Alert --
   --------------

   function No_Alert return Alert is
   begin
      return (Present => False, Description => Unknown_Alert, Value => 0, Level => Fatal_Level);
   end No_Alert;

   ----------------
   -- Is_Present --
   ----------------

   function Is_Present (Item : Alert) return Boolean is
   begin
      return Item.Present;
   end Is_Present;

   -----------------
   -- Local_Alert --
   -----------------

   function Local_Alert (Description : Alert_Description) return Alert is
      --  RFC 8446 section 6: close_notify and user_canceled are the two
      --  warning-level alerts; every other alert this library sends is fatal.
      Level : constant Alert_Level :=
        (if Description in Close_Notify | User_Canceled then Warning_Level else Fatal_Level);
   begin
      return (Present     => True,
              Description => Description,
              Value       => Value_For (Description),
              Level       => Level);
   end Local_Alert;

   ----------------
   -- Peer_Alert --
   ----------------

   function Peer_Alert (Level_Octet : Byte; Description_Octet : Byte) return Alert is
      Value : constant Alert_Value := Alert_Value (Description_Octet);
   begin
      return (Present     => True,
              Description => Description_For (Value),
              Value       => Value,
              Level       =>
                (if Natural (Level_Octet) = Warning_Octet then Warning_Level else Fatal_Level));
   end Peer_Alert;

   --------------------
   -- Description_Of --
   --------------------

   function Description_Of (Item : Alert) return Alert_Description is
   begin
      return Item.Description;
   end Description_Of;

   --------------
   -- Value_Of --
   --------------

   function Value_Of (Item : Alert) return Alert_Value is
   begin
      return Item.Value;
   end Value_Of;

   --------------
   -- Level_Of --
   --------------

   function Level_Of (Item : Alert) return Alert_Level is
   begin
      return Item.Level;
   end Level_Of;

   -----------------
   -- Is_Terminal --
   -----------------

   function Is_Terminal (Item : Alert) return Boolean is
   begin
      if not Item.Present then
         return False;
      end if;

      --  Decided on the description, never on the peer's level octet. An
      --  unrecognized description is treated as terminal, because a peer that
      --  sent an alert this library cannot interpret has said the connection
      --  is in a state this library cannot reason about.
      case Item.Description is
         when Close_Notify | User_Canceled => return False;
         when others                       => return True;
      end case;
   end Is_Terminal;

   ----------------------
   -- Is_Close_Notify --
   ----------------------

   function Is_Close_Notify (Item : Alert) return Boolean is
   begin
      return Item.Present and then Item.Description = Close_Notify;
   end Is_Close_Notify;

   ------------
   -- Encode --
   ------------

   function Encode (Item : Alert) return Byte_Array is
      Level_Value : constant Byte :=
        (if Item.Level = Warning_Level then Byte (Warning_Octet) else Byte (Fatal_Octet));
   begin
      return [1 => Level_Value, 2 => Byte (Item.Value)];
   end Encode;

   -----------
   -- Image --
   -----------

   function Image (Description : Alert_Description) return String is
   begin
      case Description is
         when Close_Notify                    => return "close_notify";
         when Unexpected_Message              => return "unexpected_message";
         when Bad_Record_MAC                  => return "bad_record_mac";
         when Record_Overflow                 => return "record_overflow";
         when Handshake_Failure               => return "handshake_failure";
         when Bad_Certificate                 => return "bad_certificate";
         when Unsupported_Certificate         => return "unsupported_certificate";
         when Certificate_Revoked             => return "certificate_revoked";
         when Certificate_Expired             => return "certificate_expired";
         when Certificate_Unknown             => return "certificate_unknown";
         when Illegal_Parameter               => return "illegal_parameter";
         when Unknown_CA                      => return "unknown_ca";
         when Access_Denied                   => return "access_denied";
         when Decode_Error                    => return "decode_error";
         when Decrypt_Error                   => return "decrypt_error";
         when Protocol_Version                => return "protocol_version";
         when Insufficient_Security           => return "insufficient_security";
         when Internal_Error                  => return "internal_error";
         when Inappropriate_Fallback          => return "inappropriate_fallback";
         when User_Canceled                   => return "user_canceled";
         when Missing_Extension               => return "missing_extension";
         when Unsupported_Extension           => return "unsupported_extension";
         when Unrecognized_Name               => return "unrecognized_name";
         when Bad_Certificate_Status_Response => return "bad_certificate_status_response";
         when Unknown_PSK_Identity            => return "unknown_psk_identity";
         when Certificate_Required            => return "certificate_required";
         when No_Application_Protocol         => return "no_application_protocol";
         when Unknown_Alert                   => return "unknown_alert";
      end case;
   end Image;

   function Image (Item : Alert) return String is
   begin
      if not Item.Present then
         return "none";
      end if;

      if Item.Description /= Unknown_Alert then
         return Image (Item.Description);
      end if;

      --  Preserve the number the peer sent rather than inventing a meaning
      --  for it.
      declare
         Text : constant String := Natural (Item.Value)'Image;
      begin
         return "alert_" & Text (Text'First + 1 .. Text'Last);
      end;
   end Image;

end SSL.Alerts;
