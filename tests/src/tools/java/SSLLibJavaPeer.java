//  A peer for the interoperability matrix, on top of Java's own TLS stack.
//
//  This is a driver for an external stack, in the same sense that `openssl
//  s_client` is: nothing in this repository is built with Java, and no part of
//  the build, the test run or the release depends on it. It exists because the
//  only way to find out whether `ssllib` interoperates with JSSE is to run
//  JSSE, and JSSE is reached from Java.
//
//  Run from source with `java SSLLibJavaPeer.java <role> ...`, so that there is
//  no compilation step and no build product to keep in step with anything.
//
//  It prints facts rather than "connected", for the reason the whole matrix
//  exists: a peer that fell back to TLS 1.2, or skipped verification, would
//  have exited zero either way.
//
//    client <port> <ca.pem>
//        Connect to 127.0.0.1:<port>, verifying the server against <ca.pem>
//        alone and against the name www.example.com.
//
//    server <port> <cert.pem> <key.pem>
//        Listen on the loopback address only, present <cert.pem>, accept one
//        connection and report what was negotiated.
//
//  Two rules it holds to, matching the rest of the matrix: the host's trust
//  store is never consulted -- every anchor is the file it was given -- and
//  nothing is ever resolved, the loopback literal being used for the connection
//  and the name being supplied separately for SNI and for verification.

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class SSLLibJavaPeer {

    private static final String EXPECTED_NAME = "www.example.com";

    //  Which protocol to demand. Read from the arguments by scanning for the
    //  literal, because the two roles already differ in what their positional
    //  arguments mean.
    private static String protocol = "TLSv1.3";

    //  Milliseconds. Bounded, because a peer that hangs must not hang the
    //  matrix that is waiting for it.
    private static final int TIMEOUT_MS = 15_000;

    public static void main(String[] args) {
        try {
            if (args.length < 3) {
                say("error=usage: SSLLibJavaPeer client <port> <ca.pem>"
                    + " | server <port> <cert.pem> <key.pem>");
                System.exit(2);
            }

            for (String argument : args) {
                if (argument.equals("tls1.2")) {
                    protocol = "TLSv1.2";
                }
            }

            String role = args[0];
            int port = Integer.parseInt(args[1]);

            if (role.equals("client")) {
                runClient(port, args[2]);
            } else if (role.equals("server")) {
                if (args.length < 4) {
                    say("error=the server role needs a certificate and a key");
                    System.exit(2);
                }
                runServer(port, args[2], args[3]);
            } else {
                say("error=unknown role " + role);
                System.exit(2);
            }
        } catch (Throwable failure) {
            //  A structured line rather than a stack trace: the controller
            //  reads this, and a trace tells it nothing it can act on.
            say("established=no");
            say("error=" + failure);
            System.exit(1);
        }
    }

    // -----------------------------------------------------------------------
    //  Credentials
    // -----------------------------------------------------------------------

    private static X509Certificate loadCertificate(String path)
            throws IOException, GeneralSecurityException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (InputStream in = Files.newInputStream(Path.of(path))) {
            return (X509Certificate) factory.generateCertificate(in);
        }
    }

    //  An unencrypted PKCS#8 key, which is what every issuing tool in this
    //  matrix writes. The algorithms are tried in turn rather than guessed from
    //  the file, because the file does not say and the guess would be wrong on
    //  the first host that issued something else.
    private static PrivateKey loadPrivateKey(String path)
            throws IOException, GeneralSecurityException {
        String text = Files.readString(Path.of(path), StandardCharsets.US_ASCII);
        String base64 = text
            .replaceAll("-----BEGIN [A-Z0-9 ]+-----", "")
            .replaceAll("-----END [A-Z0-9 ]+-----", "")
            .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);

        GeneralSecurityException last = null;
        for (String algorithm : new String[] {"Ed25519", "EC", "RSA"}) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(spec);
            } catch (GeneralSecurityException tried) {
                last = tried;
            }
        }
        throw new GeneralSecurityException(
            "no key factory on this runtime accepted the key", last);
    }

    //  The certificate as the only anchor. Nothing from the host's store: an
    //  interop test that trusted whatever the machine trusts would pass on a
    //  machine that trusts too much.
    private static TrustManagerFactory trustOnly(X509Certificate anchor)
            throws IOException, GeneralSecurityException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setCertificateEntry("peer", anchor);
        TrustManagerFactory factory =
            TrustManagerFactory.getInstance("PKIX");
        factory.init(store);
        return factory;
    }

    private static KeyManagerFactory presentOnly(
            X509Certificate certificate, PrivateKey key)
            throws IOException, GeneralSecurityException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry(
            "self", key, new char[0], new Certificate[] {certificate});
        KeyManagerFactory factory =
            KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        factory.init(store, new char[0]);
        return factory;
    }

    // -----------------------------------------------------------------------
    //  The two roles
    // -----------------------------------------------------------------------

    private static void runClient(int port, String anchorPath) throws Exception {
        SSLContext context = SSLContext.getInstance(protocol);
        context.init(null, trustOnly(loadCertificate(anchorPath)).getTrustManagers(), null);

        //  Connected to the loopback address by number, then wrapped with the
        //  name. The wrapped socket uses the name for SNI and for verification
        //  without ever resolving it, which is how this stays loopback-only and
        //  still checks the name it is supposed to check.
        Socket plain = new Socket();
        plain.connect(
            new InetSocketAddress(InetAddress.getLoopbackAddress(), port),
            TIMEOUT_MS);
        plain.setSoTimeout(TIMEOUT_MS);

        try (SSLSocket socket = (SSLSocket) context.getSocketFactory()
                .createSocket(plain, EXPECTED_NAME, port, true)) {
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setProtocols(new String[] {protocol});
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            parameters.setServerNames(List.of(new SNIHostName(EXPECTED_NAME)));
            socket.setSSLParameters(parameters);

            socket.startHandshake();
            report(socket.getSession(), true);
        }
    }

    private static void runServer(int port, String certificatePath, String keyPath)
            throws Exception {
        X509Certificate certificate = loadCertificate(certificatePath);
        PrivateKey key = loadPrivateKey(keyPath);

        SSLContext context = SSLContext.getInstance(protocol);
        context.init(presentOnly(certificate, key).getKeyManagers(), null, null);

        try (SSLServerSocket listener = (SSLServerSocket) context
                .getServerSocketFactory()
                .createServerSocket(port, 1, InetAddress.getLoopbackAddress())) {
            listener.setEnabledProtocols(new String[] {protocol});
            listener.setSoTimeout(TIMEOUT_MS);

            //  Said on standard output before accepting, so that a controller
            //  waiting for this server has something to wait for.
            say("listening");

            try (SSLSocket socket = (SSLSocket) listener.accept()) {
                socket.setSoTimeout(TIMEOUT_MS);
                socket.startHandshake();
                report(socket.getSession(), false);

                //  Read to the end so that the peer's close is seen rather than
                //  raced: a server that walks away the instant a handshake
                //  finishes gives its peer a truncated connection to report.
                InputStream in = socket.getInputStream();
                byte[] scratch = new byte[512];
                try {
                    while (in.read(scratch) >= 0) {
                        //  Discarded. Nothing here is an application.
                    }
                } catch (IOException ignored) {
                    //  A peer that closed abruptly is not a handshake failure,
                    //  and the handshake is what was being tested.
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    //  Reporting
    // -----------------------------------------------------------------------

    private static void report(SSLSession session, boolean authenticated) {
        say("established=yes");
        say("version=" + session.getProtocol());
        say("suite=" + session.getCipherSuite());
        say("peer=" + (authenticated ? "authenticated" : "anonymous"));
    }

    private static void say(String line) {
        System.out.println(line);
        System.out.flush();
    }
}
