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
import tech.kwik.core.socket.DatagramEndpoint;
import tech.kwik.core.socket.DatagramSender;
import tech.kwik.core.test.NonBlockingEcho;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Client and server on one executor, connected by an in-memory link instead of sockets: the caller does all I/O, as
 * a Netty datagram channel would. The link can drop and reorder datagrams.
 */
class InMemoryLinkTest {

    private static final String ALPN = "in-memory-test";
    private static final InetSocketAddress SERVER_ADDRESS = new InetSocketAddress("10.0.0.1", 4433);
    private static final InetSocketAddress CLIENT_ADDRESS = new InetSocketAddress("10.0.0.2", 50000);

    private ScheduledExecutorService loop;
    private Thread loopThread;
    private ServerConnector server;
    private QuicClientConnection client;
    private final Random random = new Random(7);
    private volatile double lossRate;
    private volatile int maxDelayMillis;
    private int dropped;
    private boolean shared = true;
    private boolean asyncConnect;
    private Duration connectTimeout = Duration.ofSeconds(20);

    @AfterEach
    void closeAll() throws Exception {
        if (client != null) {
            client.close();
        }
        if (server != null) {
            // Its close waits for the connections, which run on the loop, so it must not run on the loop itself
            server.close();
        }
        loop.shutdownNow();
    }

    @Test
    void handshakeAndEchoWithoutLoss() throws Exception {
        connect();
        byte[] request = randomBytes(1024 * 1024);
        assertThat(echo(request).get(30, TimeUnit.SECONDS)).isEqualTo(request);
    }

    @Test
    void echoSurvivesLossAndReordering() throws Exception {
        lossRate = 0.05;
        maxDelayMillis = 5;
        connect();
        byte[] request = randomBytes(1024 * 1024);
        assertThat(echo(request).get(60, TimeUnit.SECONDS)).isEqualTo(request);
        assertThat(dropped).isGreaterThan(0);
    }

    @Test
    void echoSurvivesLossAndReorderingWithThreadsOfItsOwn() throws Exception {
        // The caller still does the I/O, but kwik runs the connections on threads of their own
        shared = false;
        echoSurvivesLossAndReordering();
    }

    @Test
    void handshakeSurvivesHeavyLoss() throws Exception {
        lossRate = 0.3;
        maxDelayMillis = 2;
        connect();
        byte[] request = randomBytes(1000);
        assertThat(echo(request).get(60, TimeUnit.SECONDS)).isEqualTo(request);
    }

    @Test
    void manyConcurrentStreams() throws Exception {
        maxDelayMillis = 1;
        connect();
        List<byte[]> requests = new ArrayList<>();
        List<CompletableFuture<byte[]>> replies = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            byte[] request = randomBytes(10_000 + i);
            requests.add(request);
            replies.add(echo(request));
        }
        for (int i = 0; i < requests.size(); i++) {
            assertThat(replies.get(i).get(30, TimeUnit.SECONDS)).isEqualTo(requests.get(i));
        }
    }

    @Test
    void kwikStartsNoThreadsOfItsOwn() throws Exception {
        createLoop();
        Set<Thread> before = Thread.getAllStackTraces().keySet();
        connect();
        byte[] request = randomBytes(100_000);
        assertThat(echo(request).get(30, TimeUnit.SECONDS)).isEqualTo(request);

        List<String> started = Thread.getAllStackTraces().keySet().stream()
                .filter(t -> !before.contains(t))
                .map(Thread::getName)
                .collect(Collectors.toList());
        assertThat(started).isEmpty();
    }

    private void createLoop() throws Exception {
        if (loop == null) {
            loop = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread thread = new Thread(r, "test-loop");
                thread.setDaemon(true);
                return thread;
            });
            loopThread = loop.submit(Thread::currentThread).get();
        }
    }

    private void connect() throws Exception {
        createLoop();
        // Filled in once both ends exist
        DatagramEndpoint[] clientEndpoint = new DatagramEndpoint[1];

        ServerConnector.Builder serverBuilder = ServerConnector.builder();
        if (shared) {
            serverBuilder.withConnectionExecutor(loop);
        }
        server = serverBuilder
                .withDatagramSender(new LinkSender(SERVER_ADDRESS, (data, from) -> clientEndpoint[0].receive(data, from)))
                .withCertificate(getClass().getResourceAsStream("server/impl/localhost.pem"),
                        getClass().getResourceAsStream("server/impl/localhost.key"))
                .withConfiguration(ServerConnectionConfig.builder()
                        .maxOpenPeerInitiatedBidirectionalStreams(100)
                        .maxIdleTimeoutInSeconds(30)
                        .retryRequired(false)
                        .build())
                .withLogger(new NullLogger())
                .build();
        server.registerApplicationProtocol(ALPN, new ApplicationProtocolConnectionFactory() {
            @Override
            public ApplicationProtocolConnection createConnection(String protocol, QuicConnection connection) {
                return new ApplicationProtocolConnection() {
                    @Override
                    public void acceptPeerInitiatedStream(QuicStream stream) {
                        stream.setStreamListener(new NonBlockingEcho.Echo(stream));
                    }
                };
            }

            @Override
            public int maxConcurrentPeerInitiatedBidirectionalStreams() {
                return 100;
            }
        });
        server.start();

        clientEndpoint[0] = new DatagramEndpoint(new LinkSender(CLIENT_ADDRESS, (data, from) -> server.receive(data, from)), 8);
        QuicClientConnection.Builder clientBuilder = QuicClientConnection.newBuilder();
        if (shared) {
            clientBuilder.connectionExecutor(loop);
        }
        client = clientBuilder
                .uri(URI.create("mem://" + SERVER_ADDRESS.getHostString() + ":" + SERVER_ADDRESS.getPort()))
                .applicationProtocol(ALPN)
                .noServerCertificateCheck()
                .sharedEndpoint(clientEndpoint[0])
                .connectTimeout(connectTimeout)
                .logger(new NullLogger())
                .build();
        if (asyncConnect) {
            // On the loop, as a Netty channel would; the future completes there too
            loop.submit(() -> client.connectAsync()).get(5, TimeUnit.SECONDS).get(10, TimeUnit.SECONDS);
        }
        else {
            client.connect();
        }
    }

    @Test
    void connectAsyncCompletesOnTheLoopWithoutBlockingIt() throws Exception {
        asyncConnect = true;
        connect();
        byte[] request = randomBytes(1000);
        assertThat(echo(request).get(10, TimeUnit.SECONDS)).isEqualTo(request);
    }

    @Test
    void connectAsyncFailsWhenThePeerDoesNotAnswer() throws Exception {
        asyncConnect = true;
        lossRate = 1.0;
        connectTimeout = Duration.ofMillis(500);
        assertThatThrownBy(this::connect).hasCauseInstanceOf(java.net.ConnectException.class);
    }

    private CompletableFuture<byte[]> echo(byte[] request) throws Exception {
        CompletableFuture<byte[]> reply = new CompletableFuture<>();
        loop.submit(() -> {
            QuicStream stream = client.createStream(true);
            NonBlockingEcho.Exchange exchange = new NonBlockingEcho.Exchange(stream, request, reply);
            stream.setStreamListener(exchange);
            exchange.writeMore();
            return null;
        }).get(10, TimeUnit.SECONDS);
        return reply;
    }

    private byte[] randomBytes(int length) {
        byte[] data = new byte[length];
        random.nextBytes(data);
        return data;
    }

    interface Delivery {
        void deliver(ByteBuffer data, InetSocketAddress from);
    }

    /**
     * One direction of the link: copies the datagram, and delivers it on the loop after a random delay (which reorders),
     * unless it is dropped.
     */
    private class LinkSender implements DatagramSender {
        private final InetSocketAddress local;
        private final Delivery peer;

        LinkSender(InetSocketAddress local, Delivery peer) {
            this.local = local;
            this.peer = peer;
        }

        @Override
        public Instant send(ByteBuffer data, InetSocketAddress destination) {
            byte[] copy = new byte[data.limit()];
            data.duplicate().position(0).get(copy);
            boolean drop;
            int delay;
            synchronized (random) {
                drop = random.nextDouble() < lossRate;
                delay = maxDelayMillis > 0? random.nextInt(maxDelayMillis + 1): 0;
            }
            if (drop) {
                dropped++;
            }
            else {
                Runnable delivery = () -> {
                    assertThat(Thread.currentThread()).isSameAs(loopThread);
                    peer.deliver(ByteBuffer.wrap(copy), local);
                };
                if (delay > 0) {
                    loop.schedule(delivery, delay, TimeUnit.MILLISECONDS);
                }
                else {
                    loop.execute(delivery);
                }
            }
            return Instant.now();
        }

        @Override
        public InetSocketAddress getLocalAddress() {
            return local;
        }
    }
}
