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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.server.ApplicationProtocolConnection;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnector;
import tech.kwik.core.test.NonBlockingEcho;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The non-blocking stream API, with client and server on one shared executor, as on a Netty event loop.
 */
class NonBlockingStreamTest {

    private static final String ALPN = "nonblocking-test";

    private ScheduledExecutorService loop;
    private Thread loopThread;
    private ServerConnector server;
    private QuicClientConnection client;
    private volatile Consumer<QuicStream> serverStreamHandler;

    @BeforeEach
    void startServerAndConnect() throws Exception {
        loop = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "test-loop");
            thread.setDaemon(true);
            return thread;
        });
        loopThread = loop.submit(Thread::currentThread).get();

        DatagramSocket socket = new DatagramSocket(0, InetAddress.getLoopbackAddress());
        server = ServerConnector.builder()
                .withSocket(socket)
                .withCertificate(getClass().getResourceAsStream("server/impl/localhost.pem"),
                        getClass().getResourceAsStream("server/impl/localhost.key"))
                .withConfiguration(ServerConnectionConfig.builder()
                        .maxOpenPeerInitiatedBidirectionalStreams(100)
                        .maxIdleTimeoutInSeconds(30)
                        .build())
                .withConnectionExecutor(loop)
                .withLogger(new NullLogger())
                .build();
        server.registerApplicationProtocol(ALPN, new ApplicationProtocolConnectionFactory() {
            @Override
            public ApplicationProtocolConnection createConnection(String protocol, QuicConnection connection) {
                return new ApplicationProtocolConnection() {
                    @Override
                    public void acceptPeerInitiatedStream(QuicStream stream) {
                        serverStreamHandler.accept(stream);
                    }
                };
            }

            @Override
            public int maxConcurrentPeerInitiatedBidirectionalStreams() {
                return 100;
            }
        });
        server.start();

        client = QuicClientConnection.newBuilder()
                .uri(URI.create("nb://127.0.0.1:" + socket.getLocalPort()))
                .applicationProtocol(ALPN)
                .noServerCertificateCheck()
                .connectionExecutor(loop)
                .connectTimeout(Duration.ofSeconds(10))
                .logger(new NullLogger())
                .build();
        client.connect();
    }

    @AfterEach
    void closeAll() {
        if (client != null) {
            client.close();
        }
        if (server != null) {
            server.close();
        }
        loop.shutdownNow();
    }

    @Test
    void echoesMoreDataThanTheBuffersHold() throws Exception {
        serverStreamHandler = stream -> stream.setStreamListener(new NonBlockingEcho.Echo(stream));
        byte[] request = new byte[3 * 1024 * 1024];
        new Random(1).nextBytes(request);

        CompletableFuture<byte[]> reply = new CompletableFuture<>();
        onLoop(() -> {
            QuicStream stream = client.createStream(true);
            NonBlockingEcho.Exchange exchange = new NonBlockingEcho.Exchange(stream, request, reply);
            stream.setStreamListener(exchange);
            exchange.writeMore();
            return null;
        });

        assertThat(reply.get(30, TimeUnit.SECONDS)).isEqualTo(request);
    }

    @Test
    void resetByPeerIsReportedToTheReaderWithItsErrorCode() throws Exception {
        serverStreamHandler = stream -> stream.resetStream(42);

        CompletableFuture<byte[]> reply = new CompletableFuture<>();
        onLoop(() -> {
            QuicStream stream = client.createStream(true);
            NonBlockingEcho.Exchange exchange = new NonBlockingEcho.Exchange(stream, new byte[10], reply);
            stream.setStreamListener(exchange);
            exchange.writeMore();
            return null;
        });

        assertThatThrownBy(() -> reply.get(10, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .cause().isInstanceOf(StreamResetException.class)
                .extracting(e -> ((StreamResetException) e).getErrorCode()).isEqualTo(42L);
    }

    @Test
    void stopSendingByPeerIsReportedToTheWriterWithItsErrorCode() throws Exception {
        serverStreamHandler = stream -> stream.abortReading(7);

        CompletableFuture<Throwable> writeFailure = new CompletableFuture<>();
        onLoop(() -> {
            QuicStream stream = client.createStream(true);
            // Keep writing without fin, so the stream is still open for writing when the STOP_SENDING arrives
            StreamListener writer = new StreamListener() {
                final ByteBuffer data = ByteBuffer.allocate(16 * 1024);

                @Override
                public void readable(QuicStream s) {
                }

                @Override
                public void writable(QuicStream s) {
                    try {
                        while (true) {
                            data.clear();
                            if (s.write(data, false) == 0) {
                                return;
                            }
                        }
                    }
                    catch (IOException e) {
                        writeFailure.complete(e);
                    }
                }
            };
            stream.setStreamListener(writer);
            writer.writable(stream);
            return null;
        });

        Throwable failure = writeFailure.get(10, TimeUnit.SECONDS);
        assertThat(failure).isInstanceOf(StreamStoppedException.class);
        assertThat(((StreamStoppedException) failure).getErrorCode()).isEqualTo(7L);
    }

    @Test
    void nothingCanBeWrittenAfterFin() throws Exception {
        serverStreamHandler = stream -> stream.setStreamListener(new NonBlockingEcho.Echo(stream));

        int capacityAfterFin = onLoop(() -> {
            QuicStream stream = client.createStream(true);
            assertThat(stream.writeCapacity()).isGreaterThan(0);
            stream.write(ByteBuffer.wrap(new byte[100]), true);
            int capacity = stream.writeCapacity();
            assertThatThrownBy(() -> stream.write(ByteBuffer.wrap(new byte[1]), false)).isInstanceOf(IOException.class);
            return capacity;
        });

        assertThat(capacityAfterFin).isEqualTo(0);
    }

    @Test
    void listenerIsCalledOnTheSharedExecutor() throws Exception {
        CompletableFuture<Thread> notifiedOn = new CompletableFuture<>();
        serverStreamHandler = stream -> stream.setStreamListener(new NonBlockingEcho.Echo(stream));

        onLoop(() -> {
            QuicStream stream = client.createStream(true);
            stream.setStreamListener(new StreamListener() {
                @Override
                public void readable(QuicStream s) {
                    notifiedOn.complete(Thread.currentThread());
                }

                @Override
                public void writable(QuicStream s) {
                }
            });
            stream.write(ByteBuffer.wrap(new byte[100]), true);
            return null;
        });

        assertThat(notifiedOn.get(10, TimeUnit.SECONDS)).isSameAs(loopThread);
    }

    private <T> T onLoop(Callable<T> action) throws Exception {
        try {
            return loop.submit(action).get(10, TimeUnit.SECONDS);
        }
        catch (ExecutionException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            }
            throw e;
        }
    }
}
