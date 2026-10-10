/*
 * Copyright © 2023, 2024, 2025, 2026 Peter Doornbosch
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
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.function.Consumer;

/**
 * A datagram endpoint that client connections can share with a server connector, so that all connections, incoming
 * and outgoing, use one local address (as needed for e.g. NAT traversal). Incoming datagrams are routed to client
 * connections by destination connection ID, so client connections must use {@link #connectionIdLength()}.
 */
public interface SharedEndpoint {

    int connectionIdLength();

    InetSocketAddress getLocalAddress();

    Instant send(ByteBuffer data, InetSocketAddress destination) throws IOException;

    default int maxSegments() {
        return 1;
    }

    default Instant sendSegmented(byte[] data, int length, int segmentSize, InetSocketAddress destination) throws IOException {
        throw new UnsupportedOperationException();
    }

    /**
     * Routes datagrams whose destination connection ID equals the given one to the given receiver.
     */
    void registerConnectionId(byte[] connectionId, Consumer<RawPacket> receiver);

    void deregisterConnectionId(byte[] connectionId);
}
