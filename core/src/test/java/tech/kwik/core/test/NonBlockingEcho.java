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
package tech.kwik.core.test;

import tech.kwik.core.QuicStream;
import tech.kwik.core.StreamListener;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

/**
 * An echo over the non-blocking stream API, for tests.
 */
public class NonBlockingEcho {

    /**
     * Server side: reads the whole request, then writes it back and ends the stream.
     */
    public static class Echo implements StreamListener {
        private final QuicStream stream;
        private final ByteArrayOutputStream received = new ByteArrayOutputStream();
        private final ByteBuffer readBuffer = ByteBuffer.allocate(16 * 1024);
        private ByteBuffer reply;

        public Echo(QuicStream stream) {
            this.stream = stream;
            // Data may have arrived before the listener was set
            readable(stream);
        }

        @Override
        public void readable(QuicStream s) {
            try {
                int read;
                while (reply == null && (read = stream.read(readBuffer.clear())) != 0) {
                    if (read < 0) {
                        reply = ByteBuffer.wrap(received.toByteArray());
                        writable(s);
                        return;
                    }
                    received.write(readBuffer.array(), 0, read);
                }
            }
            catch (IOException e) {
                stream.resetStream(1);
            }
        }

        @Override
        public void writable(QuicStream s) {
            try {
                if (reply != null && reply.hasRemaining()) {
                    stream.write(reply, true);
                }
            }
            catch (IOException e) {
                stream.resetStream(1);
            }
        }
    }

    /**
     * Client side: writes the request with fin, and collects the reply.
     */
    public static class Exchange implements StreamListener {
        private final QuicStream stream;
        private final ByteBuffer request;
        private final CompletableFuture<byte[]> reply;
        private final ByteArrayOutputStream received = new ByteArrayOutputStream();
        private final ByteBuffer readBuffer = ByteBuffer.allocate(16 * 1024);

        public Exchange(QuicStream stream, byte[] request, CompletableFuture<byte[]> reply) {
            this.stream = stream;
            this.request = ByteBuffer.wrap(request);
            this.reply = reply;
        }

        public void writeMore() throws IOException {
            if (request.hasRemaining()) {
                stream.write(request, true);
            }
        }

        @Override
        public void readable(QuicStream s) {
            try {
                int read;
                while ((read = stream.read(readBuffer.clear())) != 0) {
                    if (read < 0) {
                        reply.complete(received.toByteArray());
                        return;
                    }
                    received.write(readBuffer.array(), 0, read);
                }
            }
            catch (IOException e) {
                reply.completeExceptionally(e);
            }
        }

        @Override
        public void writable(QuicStream s) {
            try {
                writeMore();
            }
            catch (IOException e) {
                reply.completeExceptionally(e);
            }
        }
    }
}
