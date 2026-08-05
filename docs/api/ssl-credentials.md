# ssl-credentials

Generated from `src/ssl-credentials.ads` by `ssllib_tools docs`. The prose is the specification's own; nothing here is written twice.

A local certificate chain and the signing capability that goes with
it: what this endpoint presents, and what proves it owns it.

A credential holds a private key, so it is limited and controlled and it
scrubs itself. There is no operation that returns the key, no operation that
returns any parameter of it, and no operation that returns anything from
which it could be reconstructed. What a caller can do is ask what the
credential is capable of and ask it to sign; the key never leaves.

**Everything expensive happens at load time.** Reading a file, decrypting a
PKCS#8 blob, deriving a key from a password, checking that the certificate
and the key belong together, checking the chain hangs together, working out
which signature schemes the key can actually produce -- all of it happens
when the credential is built, and none of it happens during a handshake. A
handshake that had to read a file would be a handshake that could block on a
disk, and one that had to prompt for a password would be one that could
block on a human.

The structural checks are CryptoLib's. `CryptoLib.Identities` answers whether
the key matches the leaf and whether the chain is in the right order, which
are the two configuration mistakes that otherwise surface at the first
handshake against the first peer that cares.

-------------------------------------------------------------------------
What a credential can do
-------------------------------------------------------------------------

The key types this library can hold and present.

```ada
type Key_Kind is (RSA_Key, ECDSA_P256, ECDSA_P384, ECDSA_P521, Ed25519_Key, Ed448_Key);
```

```ada
function Image (Item : Key_Kind) return String;
```

A credential, complete with its chain and its key.

```ada
type Credential is limited private;
```

Has this credential been loaded and checked?

```ada
function Is_Loaded (Item : Credential) return Boolean;
```

What kind of key it holds.

```ada
function Key_Type (Item : Credential) return Key_Kind
  with Pre => Is_Loaded (Item);
```

How many certificates the chain holds, leaf first.

```ada
function Chain_Length (Item : Credential) return Positive
  with Pre => Is_Loaded (Item);
```

One certificate's DER, leaf at index one. Public material; a chain is
sent in the clear in TLS 1.2 and under handshake keys in TLS 1.3, and
either way the peer sees it.

```ada
function Certificate_At (Item : Credential; Index : Positive) return Byte_Array
  with Pre => Is_Loaded (Item) and then Index <= Chain_Length (Item);
```

The leaf's SHA-256 fingerprint, and its SubjectPublicKeyInfo
fingerprint, for pinning and for diagnostics.

```ada
function Leaf_Fingerprint (Item : Credential) return Certificate_Fingerprint
  with Pre => Is_Loaded (Item);
```

```ada
function Public_Key_Fingerprint (Item : Credential) return Certificate_Fingerprint
  with Pre => Is_Loaded (Item);
```

Can this credential produce a signature under this scheme?

Decided at load time from the key type, the key size and, for ECDSA, the
curve -- RFC 8446 section 4.2.3 binds each ECDSA scheme to one curve, so a
P-256 key can produce ecdsa_secp256r1_sha256 and nothing else.

```ada
function Supports
  (Item : Credential; Scheme : SSL.Signature_Schemes.Signature_Scheme) return Boolean
  with Pre => Is_Loaded (Item);
```

The schemes this credential can produce, in this library's preference
order. Empty is impossible for a loaded credential: a key that could sign
nothing is refused at load.

```ada
function Supported_Schemes (Item : Credential) return SSL.Signature_Schemes.Scheme_List
  with Pre => Is_Loaded (Item),
       Post => not SSL.Signature_Schemes.Is_Empty (Supported_Schemes'Result);
```

The identities this credential may be presented for: the leaf's
subjectAltName DNS entries, as a server uses them to route on SNI.

```ada
function Identity_Count (Item : Credential) return Natural
  with Pre => Is_Loaded (Item);
```

```ada
function Identity_At (Item : Credential; Index : Positive) return SSL.Server_Names.DNS_Name
  with Pre => Is_Loaded (Item) and then Index <= Identity_Count (Item);
```

Does this credential cover a name, and how specifically?

Zero means it does not. Higher is more specific, so a server choosing
between several credentials for one SNI name takes the highest -- an exact
match ahead of any wildcard, and a narrower wildcard ahead of a broader
one. See SSL.Server_Names.Match_Specificity.

```ada
function Covers (Item : Credential; Name : SSL.Server_Names.DNS_Name) return Natural
  with Pre => Is_Loaded (Item);
```

-------------------------------------------------------------------------
Loading

No entry point here reads a file. The caller supplies the octets, which
keeps the filesystem the caller's business and makes a credential
loadable from a secret manager, an environment the caller controls, or a
test fixture, with no code path in this library that touches a disk.
-------------------------------------------------------------------------

Load from PEM: a certificate chain, leaf first, and an unencrypted
PKCS#8 private key.
@param Item      the credential to load into
@param Chain_PEM one or more CERTIFICATE blocks, leaf first
@param Key_PEM   one PRIVATE KEY block
@param Bounds    the limits in force
@param Error     out: No_Error, or what is wrong with the material

```ada
procedure Load_PEM
  (Item      : in out Credential;
   Chain_PEM : String;
   Key_PEM   : String;
   Bounds    : SSL.Limits.Resource_Limits;
   Error     : out SSL.Errors.Error_Information);
```

Load from PEM with an encrypted PKCS#8 key.

The password is copied into a scrubbed buffer immediately and the copy is
wiped before this returns. The caller's own copy is the caller's to wipe;
this library cannot do it for them, and says so rather than pretending.
@param Item      the credential to load into
@param Chain_PEM one or more CERTIFICATE blocks, leaf first
@param Key_PEM   one ENCRYPTED PRIVATE KEY block
@param Password  the password, used and wiped here
@param Bounds    the limits in force
@param Error     out: No_Error, or what is wrong

```ada
procedure Load_Encrypted_PEM
  (Item      : in out Credential;
   Chain_PEM : String;
   Key_PEM   : String;
   Password  : String;
   Bounds    : SSL.Limits.Resource_Limits;
   Error     : out SSL.Errors.Error_Information);
```

Scrub the key and release the chain now rather than at end of scope.

```ada
procedure Wipe (Item : in out Credential);
```

-------------------------------------------------------------------------
Signing
-------------------------------------------------------------------------

Sign the exact octets a CertificateVerify covers.

The input is the complete signed structure -- sixty-four spaces, the
context string, a zero separator and the transcript hash -- assembled by
the caller, because only the caller knows the context and the transcript.
Nothing is hashed or wrapped here beyond what the scheme itself does.
Signing does not change the credential: the private key is read and
nothing is recorded. The parameter is a plain `in` for that reason, which
is what lets a server sign through the read-only reference its
configuration hands out -- a configuration is immutable once built, and
a signing operation that needed to mutate it would mean it was not.
@param Item        the credential
@param Scheme      the scheme, which must be one Supports accepts
@param Signed_Data the exact octets to sign
@param Signature   out: the signature in the encoding TLS carries
@param Length      out: how many octets of Signature hold it
@param Error       out: No_Error, or a signing failure

```ada
procedure Sign
  (Item        : Credential;
   Scheme      : SSL.Signature_Schemes.Signature_Scheme;
   Signed_Data : Byte_Array;
   Signature   : out Byte_Array;
   Length      : out Byte_Index;
   Error       : out SSL.Errors.Error_Information)
  with Pre => Is_Loaded (Item) and then Signature'Length >= Maximum_Signature_Length;
```


