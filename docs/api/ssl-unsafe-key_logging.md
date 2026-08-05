# ssl-unsafe-key_logging

Generated from `src/ssl-unsafe-key_logging.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

Key logging in the NSS SSLKEYLOGFILE format, for decrypting one's
own traffic in a packet capture.

**This defeats the encryption.** Anyone holding the log can decrypt every
connection it covers, then and afterwards, including anything already
captured. It exists because debugging a protocol problem inside TLS is
otherwise close to impossible, and the alternative -- developers turning
encryption off to get a capture -- is worse.

Everything about how it is reached is a deliberate obstacle:

* It is off unless a configuration explicitly turns it on. There is no
default that enables it and no build that enables it.
* It cannot be switched on by an environment variable. The reference
implementation's `SSLKEYLOGFILE` is *not* honoured, and that is the
single most important decision in this package: a facility that an
environment variable enables is a facility that anyone who can set
environment variables enables, which on most systems is anyone who can
run a process as that user.
* It never opens a file. The application supplies a sink and owns the
destination, its permissions and its lifetime. A library that created
the file would be choosing the permissions on the file that decrypts
everything.
* The formatting buffers are wiped. A hexadecimal rendering of a secret is
a secret, and leaving one on the stack would be leaving the key where a
later reader could find it.

The labels are the NSS ones, because the whole point is that an existing
capture tool can read the output.

The label a line carries, which says which secret it is.

A closed set. The reference implementation's format is a de facto
standard and inventing a label would produce a line no tool understands.

```ada
type Secret_Label is
  (Client_Handshake_Traffic_Secret,
   Server_Handshake_Traffic_Secret,
   Client_Traffic_Secret_0,
   Server_Traffic_Secret_0,
   Exporter_Secret,
   Client_Random_To_Master,
   --  The TLS 1.2 form, whose label is literally "CLIENT_RANDOM".

   Early_Traffic_Secret);
```

Never emitted by this library, which does not implement 0-RTT. Present
so that the enumeration matches the format rather than this library's
subset, and so that a reader is not left wondering whether it was
forgotten.

The exact text the format uses.

```ada
function Image (Item : Secret_Label) return String;
```

The sink an application supplies.

Receives one complete line, without a trailing newline: label, the
client random as hexadecimal, and the secret as hexadecimal, separated by
single spaces. Whatever the sink does with it -- a file, a pipe, a test
buffer -- is the application's, and so is the responsibility for it.

```ada
type Sink is limited interface;
```

```ada
type Sink_Reference is access all Sink'Class;
```

Receive one line. May raise; it will be caught and the line dropped.

```ada
procedure Write_Line (Item : in out Sink; Line : String) is abstract;
```

Short text naming this sink, for diagnostics.

```ada
function Description (Item : Sink) return String is abstract;
```

Format and emit one secret.

The formatting buffer is wiped before this returns, whether or not the
sink succeeded: a hexadecimal rendering of a traffic secret is a traffic
secret, and leaving one behind would leave the key where a later reader
could find it.
@param Item          the sink
@param Label         which secret this is
@param Client_Random the connection's 32-octet client random, which is
what a capture tool matches lines to connections by
@param Secret        the secret octets
@param Error         out: No_Error, or a provider failure naming the sink

```ada
procedure Emit
  (Item          : in out Sink'Class;
   Label         : Secret_Label;
   Client_Random : Byte_Array;
   Secret        : Byte_Array;
   Error         : out SSL.Errors.Error_Information)
  with Pre => Client_Random'Length = 32 and then Secret'Length in 1 .. 64;
```


