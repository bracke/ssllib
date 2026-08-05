# Alerts

Every alert this library knows, with the wire value it is written down as and whether receiving it ends the connection. Terminality is decided on the description rather than on a peer's level octet, which is why it is a column here rather than something a reader has to infer.

| Alert | Wire value | Terminal |
|---|---|---|
| `close_notify` | 0 | no |
| `unexpected_message` | 10 | yes |
| `bad_record_mac` | 20 | yes |
| `record_overflow` | 22 | yes |
| `handshake_failure` | 40 | yes |
| `bad_certificate` | 42 | yes |
| `unsupported_certificate` | 43 | yes |
| `certificate_revoked` | 44 | yes |
| `certificate_expired` | 45 | yes |
| `certificate_unknown` | 46 | yes |
| `illegal_parameter` | 47 | yes |
| `unknown_ca` | 48 | yes |
| `access_denied` | 49 | yes |
| `decode_error` | 50 | yes |
| `decrypt_error` | 51 | yes |
| `protocol_version` | 70 | yes |
| `insufficient_security` | 71 | yes |
| `internal_error` | 80 | yes |
| `inappropriate_fallback` | 86 | yes |
| `user_canceled` | 90 | no |
| `missing_extension` | 109 | yes |
| `unsupported_extension` | 110 | yes |
| `unrecognized_name` | 112 | yes |
| `bad_certificate_status_response` | 113 | yes |
| `unknown_psk_identity` | 115 | yes |
| `certificate_required` | 116 | yes |
| `no_application_protocol` | 120 | yes |
| `unknown_alert` | -- (a peer's, preserved verbatim) | yes |


