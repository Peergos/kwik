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
package tech.kwik.core.socket;

import tech.kwik.core.receive.RawPacket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * An endpoint for client connections whose I/O the caller does (e.g. a Netty datagram channel): kwik sends through the
 * given {@link DatagramSender}, and the caller hands received datagrams to {@link #receive}, which routes them to the
 * connection by destination connection ID. Use it with
 * {@link tech.kwik.core.QuicClientConnection.Builder#sharedEndpoint}; the connections then start no receiver threads.
 */
public class DatagramEndpoint implements SharedEndpoint {

    private final DatagramSender sender;
    private final int connectionIdLength;
    private final Map<ByteBuffer, Consumer<RawPacket>> connections = new ConcurrentHashMap<>();

    /**
     * @param connectionIdLength  the length of the connection IDs of the connections using this endpoint: short header
     *                            packets don't carry it, so all must use the same
     */
    public DatagramEndpoint(DatagramSender sender, int connectionIdLength) {
        this.sender = Objects.requireNonNull(sender);
        this.connectionIdLength = connectionIdLength;
    }

    /**
     * Processes a datagram the caller received; the data is copied. When the connections run on a shared executor, call
     * it on that executor.
     * @return whether a connection of this endpoint takes the datagram
     */
    public boolean receive(ByteBuffer datagram, InetSocketAddress source) {
        ByteBuffer destinationId = destinationConnectionId(datagram);
        Consumer<RawPacket> connection = destinationId != null? connections.get(destinationId): null;
        if (connection == null) {
            return false;
        }
        // Copied, because kwik keeps references to received data (e.g. in stream frames) and the caller may reuse its buffer
        byte[] data = new byte[datagram.remaining()];
        datagram.get(data);
        connection.accept(new RawPacket(new DatagramPacket(data, data.length, source), Instant.now(), sender.getLocalAddress()));
        return true;
    }

    private ByteBuffer destinationConnectionId(ByteBuffer datagram) {
        int start = datagram.position();
        if (datagram.remaining() < 1) {
            return null;
        }
        boolean longHeader = (datagram.get(start) & 0x80) != 0;
        int offset, length;
        if (longHeader) {
            // Flags (1), version (4), destination connection ID length (1), destination connection ID
            if (datagram.remaining() < 6) {
                return null;
            }
            length = datagram.get(start + 5) & 0xff;
            offset = start + 6;
        }
        else {
            length = connectionIdLength;
            offset = start + 1;
        }
        if (offset + length > datagram.limit()) {
            return null;
        }
        byte[] id = new byte[length];
        ByteBuffer source = datagram.duplicate();
        source.position(offset);
        source.get(id);
        return ByteBuffer.wrap(id);
    }

    @Override
    public int connectionIdLength() {
        return connectionIdLength;
    }

    @Override
    public InetSocketAddress getLocalAddress() {
        return sender.getLocalAddress();
    }

    @Override
    public Instant send(ByteBuffer data, InetSocketAddress destination) throws IOException {
        return sender.send(data, destination);
    }

    @Override
    public int maxSegments() {
        return sender.maxSegments();
    }

    @Override
    public Instant sendSegmented(byte[] data, int length, int segmentSize, InetSocketAddress destination) throws IOException {
        return sender.sendSegmented(data, length, segmentSize, destination);
    }

    @Override
    public void registerConnectionId(byte[] connectionId, Consumer<RawPacket> receiver) {
        connections.put(ByteBuffer.wrap(connectionId.clone()), receiver);
    }

    @Override
    public void deregisterConnectionId(byte[] connectionId) {
        connections.remove(ByteBuffer.wrap(connectionId));
    }
}
