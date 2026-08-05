# Ticket formats

A session ticket is a server's own state under a key only that server holds, and the protocol says nothing about what is inside one. Every decision below is therefore this library's, and every one of them can be got wrong in a way that costs the security of every resumed connection -- so they are written down.

## The sealed ticket

| Field | Width | Authenticated | Encrypted |
|---|---|---|---|
| format version | 1 octet | yes | no |
| key identifier | 16 octets | yes | no |
| nonce | 12 octets | yes | no |
| sealed body | variable | yes | yes |
| authentication tag | 16 octets | -- | -- |

The body is AES-256-GCM, and it is authenticated before it is parsed: a ticket a server cannot authenticate is a ticket whose contents it never looks at, which is what keeps chosen bytes away from the decoder. The format version is inside the authenticated data, because a format change an attacker could roll back would be no change at all.

## Inside the body

| Field | Encoding |
|---|---|
| issued at | 8 octets, seconds since the epoch |
| expires at | 8 octets, seconds since the epoch |
| protocol version | 2 octets, the TLS wire value |
| cipher suite | 2 octets, the TLS wire value |
| configuration fingerprint | 32 octets |
| trust fingerprint | 32 octets |
| security context | 1 octet length, then the label |
| application protocol | 1 octet length, then the name |
| server name | 1 octet length, then the name |
| peer authenticated | 1 octet |
| secret | 1 octet length, then the octets |

Nothing is persisted as an Ada record. Every field is written octet by octet, because a record's layout is a compiler's decision and a ticket outlives the process that wrote it.

The protocol version is in there because it was once assumed. Every sealed session was a TLS 1.3 one, the assumption was not written down, and it stopped being true: a TLS 1.2 session came back out of its own ticket claiming to be TLS 1.3, and the server declined every resumption it had just issued.

## Refusal

Unknown key, expired, corrupt, wrong format version, wrong protocol version, a suite that does not belong to that version -- each produces the same undifferentiated refusal and a full handshake, so that a peer probing a server's key rotation learns nothing from which one it got.

