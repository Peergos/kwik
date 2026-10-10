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
import java.net.DatagramPacket;
import java.net.InetSocketAddress;

/**
 * A socket that can send several equally sized datagrams in one call (e.g. with UDP generic segmentation offload).
 * Every datagram is segmentSize bytes, except the last, which may be shorter.
 */
public interface SegmentedDatagramSocket {

    int maxSegments();

    void sendSegmented(byte[] data, int offset, int length, int segmentSize, InetSocketAddress destination) throws IOException;

    /**
     * Whether more received datagrams are ready after the one the last receive returned, so a receiver can hold its
     * acks until it has processed them.
     */
    default boolean moreReceived() {
        return false;
    }

    /**
     * Receives a datagram without copying it into a caller supplied buffer. The returned packet's data (between its
     * offset and offset + length) belongs to the caller and is not reused by the socket.
     */
    DatagramPacket receive() throws IOException;
}
