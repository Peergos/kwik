/*
 * Copyright © 2026 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.core;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.server.ApplicationProtocolConnection;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnector;

import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.net.ConnectException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.URI;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Servers requiring clients to authenticate with an X.509 certificate, e.g. a self-signed one as libp2p uses.
 */
class ClientCertificateTest {

    private static final String ALPN = "client-cert-test";
    // Self-signed, generated with openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256
    private static final String EC_CERTIFICATE = "MIIBfzCCASWgAwIBAgIUD1r8tyH1Af6dB1dCowo+CokhaFUwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJY2xpZW50LWVjMCAXDTI2" +
            "MTEwNjEzNDI0MloYDzIxMjYxMDEzMTM0MjQyWjAUMRIwEAYDVQQDDAljbGllbnQtZWMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC" +
            "AATGuWJV0ys2JRi+pWGWFVwkPw8rrrg+ReQPZrr33OET4EsgdOwkqTaVBuxhc+JNOmydBy7gpN/NOaPeOUZ3i2cXo1MwUTAdBgNV" +
            "HQ4EFgQU6kUEhJQwxYlwNyetoNg3YO294ZswHwYDVR0jBBgwFoAU6kUEhJQwxYlwNyetoNg3YO294ZswDwYDVR0TAQH/BAUwAwEB" +
            "/zAKBggqhkjOPQQDAgNIADBFAiEA41amco7ZZepUAJF2A9ruVHvvx4CFNYVKfb0sVKa5Y4ECIE7EpJy5M0mf6zoDioByVtBUVt4a" +
            "MU4n5ySd//+hn90h";
    private static final String EC_PRIVATE_KEY = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxOkbufKilehwtkflTHKGZ8T0dHH7ZygwW2gAdwEk3M2hRANCAATG" +
            "uWJV0ys2JRi+pWGWFVwkPw8rrrg+ReQPZrr33OET4EsgdOwkqTaVBuxhc+JNOmydBy7gpN/NOaPeOUZ3i2cX";

    // Self-signed, generated with openssl req -x509 -newkey ed25519
    private static final String ED25519_CERTIFICATE = "MIIBSDCB+6ADAgECAhR7uIguUS7Xib4NbcypJEgeuRDqNjAFBgMrZXAwGTEXMBUGA1UEAwwOY2xpZW50LWVkMjU1MTkwIBcNMjYx" +
            "MTA2MTM0MjQyWhgPMjEyNjEwMTMxMzQyNDJaMBkxFzAVBgNVBAMMDmNsaWVudC1lZDI1NTE5MCowBQYDK2VwAyEAYafPF9xInZxM" +
            "TqF5K55caje7umKNF4JO9ETplwo8EPyjUzBRMB0GA1UdDgQWBBRe0vojG8fhZxZ3utQVDxflLpgszDAfBgNVHSMEGDAWgBRe0voj" +
            "G8fhZxZ3utQVDxflLpgszDAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANBAOnALJBNajBo/Pqh1Cjnmur2LEORB7Kr4tIIofE7wER/" +
            "kgk9hP75PuqtG1zriKMvCm/ifoRtg1/1CDvqBe4ENgQ=";
    private static final String ED25519_PRIVATE_KEY = "MC4CAQAwBQYDK2VwBCIEIIPRtvAOIwCuZ+BMewHlicaEp2BNX36EVWMGN62csVTD";

    private ServerConnector server;
    private QuicClientConnection client;
    private final CompletableFuture<List<X509Certificate>> chainSeenByServer = new CompletableFuture<>();

    @AfterEach
    void closeAll() {
        if (client != null) {
            client.close();
        }
        if (server != null) {
            server.close();
        }
    }

    @Test
    void acceptedClientCertificateIsAvailableOnTheServerConnection() throws Exception {
        X509Certificate certificate = certificate();
        int port = startServer(true);

        client = clientBuilder(port).clientCertificate(certificate).clientCertificateKey(privateKey()).build();
        client.connect();

        assertThat(chainSeenByServer.get(10, TimeUnit.SECONDS)).containsExactly(certificate);
    }

    @Test
    void ed25519ClientCertificateIsAccepted() throws Exception {
        X509Certificate certificate = certificate(ED25519_CERTIFICATE);
        int port = startServer(true);

        client = clientBuilder(port).clientCertificate(certificate).clientCertificateKey(privateKey("Ed25519", ED25519_PRIVATE_KEY)).build();
        client.connect();

        assertThat(chainSeenByServer.get(10, TimeUnit.SECONDS)).containsExactly(certificate);
    }

    @Test
    void clientCertificateTheTrustManagerRejectsFailsTheConnection() throws Exception {
        int port = startServer(false);

        client = clientBuilder(port).clientCertificate(certificate()).clientCertificateKey(privateKey()).build();
        // In TLS 1.3, the client's handshake completes before the server has checked its certificate, so the
        // rejection comes as the server closing the connection
        connectAndAwaitClose();
        assertThat(chainSeenByServer).isNotDone();
    }

    @Test
    void clientWithoutCertificateIsRefused() throws Exception {
        int port = startServer(true);

        client = clientBuilder(port).build();

        connectAndAwaitClose();
        assertThat(chainSeenByServer).isNotDone();
    }

    @Test
    void rawPublicKeyAndCertificateRequirementsCannotBeCombined() throws Exception {
        assertThatThrownBy(() -> ServerConnector.builder()
                .withSocket(new DatagramSocket(0, InetAddress.getLoopbackAddress()))
                .withCertificate(getClass().getResourceAsStream("server/impl/localhost.pem"),
                        getClass().getResourceAsStream("server/impl/localhost.key"))
                .requireClientRawPublicKey(key -> true)
                .requireClientCertificate(trustManager(true))
                .withLogger(new NullLogger())
                .build())
                .isInstanceOf(IllegalStateException.class);
    }

    private void connectAndAwaitClose() throws Exception {
        try {
            client.connect();
        }
        catch (ConnectException rejectedDuringHandshake) {
            return;
        }
        long deadline = System.currentTimeMillis() + 5000;
        while (client.isConnected() && System.currentTimeMillis() < deadline) {
            Thread.sleep(10);
        }
        assertThat(client.isConnected()).isFalse();
    }

    private int startServer(boolean accept) throws Exception {
        DatagramSocket socket = new DatagramSocket(0, InetAddress.getLoopbackAddress());
        server = ServerConnector.builder()
                .withSocket(socket)
                .withCertificate(getClass().getResourceAsStream("server/impl/localhost.pem"),
                        getClass().getResourceAsStream("server/impl/localhost.key"))
                .withConfiguration(ServerConnectionConfig.builder().maxOpenPeerInitiatedBidirectionalStreams(10).build())
                .requireClientCertificate(trustManager(accept))
                .withLogger(new NullLogger())
                .build();
        server.registerApplicationProtocol(ALPN, new ApplicationProtocolConnectionFactory() {
            @Override
            public ApplicationProtocolConnection createConnection(String protocol, QuicConnection connection) {
                chainSeenByServer.complete(connection.getPeerCertificateChain());
                return new ApplicationProtocolConnection() {};
            }

            @Override
            public int maxConcurrentPeerInitiatedBidirectionalStreams() {
                return 10;
            }
        });
        server.start();
        return socket.getLocalPort();
    }

    private QuicClientConnection.Builder clientBuilder(int port) {
        return QuicClientConnection.newBuilder()
                .uri(URI.create("cc://127.0.0.1:" + port))
                .applicationProtocol(ALPN)
                .noServerCertificateCheck()
                .connectTimeout(Duration.ofSeconds(5))
                .logger(new NullLogger());
    }

    private static X509Certificate certificate() throws Exception {
        return certificate(EC_CERTIFICATE);
    }

    private static X509Certificate certificate(String base64) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(base64)));
    }

    private static PrivateKey privateKey() throws Exception {
        return privateKey("EC", EC_PRIVATE_KEY);
    }

    private static PrivateKey privateKey(String algorithm, String base64) throws Exception {
        return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
    }

    private static X509TrustManager trustManager(boolean accept) {
        return new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                if (!accept) {
                    throw new CertificateException("not this one");
                }
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                throw new IllegalStateException("must not be called");
            }
        };
    }
}
