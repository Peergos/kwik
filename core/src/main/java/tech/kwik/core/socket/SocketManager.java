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
 * Abstracts the DatagramSocket used for sending and receiving, so it can hide implementation details related to
 * connection migration and path validation.
 */
public interface SocketManager {

    /**
     * Sends the given data as a UDP datagram to or from the given client address, and returns the time at which it was sent.
     * When used by a client, the client address is the local address from which the datagram is sent.
     * When used by a server, the client address is the remote address to which the datagram is sent.
     * @param data
     * @param clientAddress
     * @return
     * @throws IOException
     */
    Instant send(ByteBuffer data, InetSocketAddress clientAddress) throws IOException;

    /**
     * The maximum number of datagrams {@link #sendSegmented} can send at once; 1 if segmentation is not supported.
     */
    default int maxSegments() {
        return 1;
    }

    /**
     * Sends data[0, length) as datagrams of segmentSize bytes (the last may be shorter).
     */
    default Instant sendSegmented(byte[] data, int length, int segmentSize, InetSocketAddress clientAddress) throws IOException {
        Instant timeSent = null;
        for (int offset = 0; offset < length; offset += segmentSize) {
            byte[] datagram = java.util.Arrays.copyOfRange(data, offset, Math.min(length, offset + segmentSize));
            Instant sent = send(ByteBuffer.wrap(datagram), clientAddress);
            timeSent = timeSent == null ? sent : timeSent;
        }
        return timeSent;
    }

    void close();

    InetSocketAddress getClientAddress();
}
