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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * Sends the datagrams of a client connection via a {@link SharedEndpoint}.
 */
public class SharedEndpointSocketManager implements SocketManager {

    private final SharedEndpoint endpoint;
    private final InetSocketAddress serverAddress;

    public SharedEndpointSocketManager(SharedEndpoint endpoint, InetSocketAddress serverAddress) {
        this.endpoint = endpoint;
        this.serverAddress = serverAddress;
    }

    @Override
    public Instant send(ByteBuffer data, InetSocketAddress clientAddress) throws IOException {
        return endpoint.send(data, destination(clientAddress));
    }

    // Packets for the initial path carry the client (local) address; those for other multipath paths carry the
    // peer address of their path.
    private InetSocketAddress destination(InetSocketAddress address) {
        return address == null || address.equals(endpoint.getLocalAddress())? serverAddress: address;
    }

    @Override
    public int maxSegments() {
        return endpoint.maxSegments();
    }

    @Override
    public Instant sendSegmented(byte[] data, int length, int segmentSize, InetSocketAddress clientAddress) throws IOException {
        if (endpoint.maxSegments() <= 1) {
            return SocketManager.super.sendSegmented(data, length, segmentSize, clientAddress);
        }
        return endpoint.sendSegmented(data, length, segmentSize, destination(clientAddress));
    }

    @Override
    public void close() {
        // The endpoint is shared, so it must not be closed here.
    }

    @Override
    public InetSocketAddress getClientAddress() {
        return endpoint.getLocalAddress();
    }
}
