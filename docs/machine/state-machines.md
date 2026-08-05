# State machines

Four of them, all explicit, all answering with a *plan* rather than performing
input or output. The engine executes the plan; the machines never touch a
socket. That is what lets a whole handshake be run and asserted with no network
involved, and it is why the test suite can drive both ends of a connection
inside one process.

## TLS 1.3 client — `SSL.TLS13.Client`

States are RFC 8446 appendix A's, named for what is being waited for:
`Start`, `Wait_Server_Hello`, `Wait_Encrypted_Extensions`,
`Wait_Certificate_Request_Or_Certificate`, `Wait_Certificate`,
`Wait_Certificate_Verify`, `Wait_Finished`, `Connected`, `Failed`.

A HelloRetryRequest is recognized by the RFC 8446 section 4.1.3 random alone,
which is the only signal there is, and it changes which extensions are
permitted in what follows.

## TLS 1.3 server — `SSL.TLS13.Server`

`Start`, `Received_Client_Hello`, `Wait_End_Of_Early_Data` (never entered: no
0-RTT), `Wait_Certificate`, `Wait_Certificate_Verify`, `Wait_Finished`,
`Connected`, `Failed`.

## TLS 1.2 client — `SSL.TLS12.Client`

`Start`, `Wait_Server_Hello`, `Wait_Certificate`, `Wait_Key_Exchange`,
`Wait_Request_Or_Done`, `Wait_Session_Ticket`, `Wait_Change_Cipher_Spec`,
`Wait_Finished`, `Connected`, `Failed`.

`Wait_Session_Ticket` exists only on the abbreviated handshake, and only when
the server promised a new ticket. The full handshake's NewSessionTicket arrives
while a ChangeCipherSpec is due and needs no state of its own.

## TLS 1.2 server — `SSL.TLS12.Server`

`Start`, `Received_Client_Hello`, `Wait_Client_Key_Exchange`,
`Wait_Client_Change_Cipher_Spec`, `Wait_Client_Finished`, `Connected`, `Failed`.

## Plans

A plan is an ordered list of steps, and the order is the whole point. A key
installation between two messages of one flight means the messages before it go
out under the old key and the ones after it under the new one. A driver that
reordered the steps — or queued every message first and installed afterwards —
would encrypt at least one record under a key the peer will not use.

TLS 1.3's step kinds: `Send_Handshake`, `Install_Write_Keys`,
`Install_Read_Keys`, `Handshake_Complete`.

TLS 1.2 adds `Send_Change_Cipher_Spec`, and that one is the real epoch switch:
the record after it uses the new keys. A driver that treated it as TLS 1.3's
decorative compatibility record would send its Finished in the clear.

## The lifecycle above them

`SSL.Engines.Lifecycle`: `Uninitialized`, `Handshaking`, `Established`,
`Closing`, `Closed`, `Failed`. A connection moves forward only; there is no
transition back into `Handshaking`, which is renegotiation, which this library
does not do.
