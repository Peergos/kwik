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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * Where kwik sends datagrams: a socket, or a caller that does the I/O itself (e.g. a Netty datagram channel), which then
 * also hands received datagrams to kwik.
 */
public interface DatagramSender {

    /**
     * Sends the bytes from position 0 up to the limit of the buffer; must not keep a reference to it after returning.
     * @return the time sent
     */
    Instant send(ByteBuffer data, InetSocketAddress destination) throws IOException;

    InetSocketAddress getLocalAddress();

    default int maxSegments() {
        return 1;
    }

    /**
     * Sends a batch of datagrams of segmentSize bytes each (the last one may be shorter); only called when
     * {@link #maxSegments()} is larger than 1.
     */
    default Instant sendSegmented(byte[] data, int length, int segmentSize, InetSocketAddress destination) throws IOException {
        throw new UnsupportedOperationException();
    }

    static DatagramSender of(DatagramSocket socket) {
        return new DatagramSender() {
            @Override
            public Instant send(ByteBuffer data, InetSocketAddress destination) throws IOException {
                DatagramPacket datagram = new DatagramPacket(data.array(), data.limit(), destination.getAddress(), destination.getPort());
                Instant timeSent = Instant.now();
                socket.send(datagram);
                return timeSent;
            }

            @Override
            public InetSocketAddress getLocalAddress() {
                return (InetSocketAddress) socket.getLocalSocketAddress();
            }

            @Override
            public int maxSegments() {
                return socket instanceof SegmentedDatagramSocket? ((SegmentedDatagramSocket) socket).maxSegments(): 1;
            }

            @Override
            public Instant sendSegmented(byte[] data, int length, int segmentSize, InetSocketAddress destination) throws IOException {
                Instant timeSent = Instant.now();
                ((SegmentedDatagramSocket) socket).sendSegmented(data, 0, length, segmentSize, destination);
                return timeSent;
            }
        };
    }
}
