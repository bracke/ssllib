--  @summary Committed certificate fixtures, as text.
--
--  A self-signed Ed25519 certificate and its key, generated once and written
--  down here rather than produced at test time. That is what makes the tests
--  deterministic: no key generation, no system randomness, no clock, and the
--  same octets on every machine and every run.
--
--  Embedded as string constants rather than read from `tests/certificates/`
--  because a test that opens a file has a working directory, and a test with a
--  working directory fails differently depending on where it was started from.
--
--  The certificate is self-signed, so it serves as both the leaf a credential
--  presents and the anchor a trust snapshot holds -- which is exactly what a
--  private certificate authority looks like to this library, and lets the
--  validation pipeline be exercised end to end without a chain.
package Tests_Fixtures is

   --  Subject and subjectAltName: CN=www.example.com, with DNS entries
   --  www.example.com and *.example.com. Key usage digitalSignature; extended
   --  key usage serverAuth and clientAuth, so it is usable in both roles.
   --  Basic constraints CA:TRUE, so it can be its own issuer.
   --
   --  Valid from 2026-07-30 to 2126-07-06. The hundred-year window is
   --  deliberate: a fixture that expires is a test suite that starts failing on
   --  a date nobody chose, in a way that looks like a code regression.
   Leaf_Certificate_PEM : constant String :=
     "-----BEGIN CERTIFICATE-----" & ASCII.LF
     & "MIIBpzCCAVmgAwIBAgIUIBiL9TITIQVBhzTergGMWKLOiR8wBQYDK2VwMBoxGDAW" & ASCII.LF
     & "BgNVBAMMD3d3dy5leGFtcGxlLmNvbTAgFw0yNjA3MzAxODAzNTNaGA8yMTI2MDcw" & ASCII.LF
     & "NjE4MDM1M1owGjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCowBQYDK2VwAyEA" & ASCII.LF
     & "tSCd/v8oVcfUyKtkpjhvvKihzuTaZuuGMuxvHe16teijga4wgaswHQYDVR0OBBYE" & ASCII.LF
     & "FJ3vYTfuje2D1uR+srJJDxMzWjFnMB8GA1UdIwQYMBaAFJ3vYTfuje2D1uR+srJJ" & ASCII.LF
     & "DxMzWjFnMA8GA1UdEwEB/wQFMAMBAf8wKQYDVR0RBCIwIIIPd3d3LmV4YW1wbGUu" & ASCII.LF
     & "Y29tgg0qLmV4YW1wbGUuY29tMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggr" & ASCII.LF
     & "BgEFBQcDAQYIKwYBBQUHAwIwBQYDK2VwA0EAHzRbOWV27EsELzrT34OJVQ8xp6d2" & ASCII.LF
     & "B/ju8j65rM9QKEsLYh0n6XDJFLIpg1OfVnAeKVMYbw5KVF8YP4zWpqWKBw==" & ASCII.LF
     & "-----END CERTIFICATE-----" & ASCII.LF;

   --  The matching Ed25519 private key, unencrypted PKCS#8.
   --
   --  A real private key in a source file, which would be indefensible anywhere
   --  else. It is defensible here because it protects nothing: it was generated
   --  for this fixture, it has never been used, and the certificate it belongs
   --  to names a domain reserved by RFC 2606 for exactly this purpose.
   Leaf_Key_PEM : constant String :=
     "-----BEGIN PRIVATE KEY-----" & ASCII.LF
     & "MC4CAQAwBQYDK2VwBCIEINf8wh6nGfnaz8ID+vfApw5tmfpK+UYqxMANsWgMuY++" & ASCII.LF
     & "-----END PRIVATE KEY-----" & ASCII.LF;

   --  The same certificate, used as a trust anchor. Named separately because
   --  the two roles are different even when the octets are not, and a test that
   --  said Leaf_Certificate_PEM where it meant an anchor would read as though
   --  it were pinning the leaf.
   Anchor_PEM : constant String := Leaf_Certificate_PEM;

end Tests_Fixtures;
