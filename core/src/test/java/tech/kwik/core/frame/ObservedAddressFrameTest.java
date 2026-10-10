/*
 * Copyright © 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.core.frame;

import org.junit.jupiter.api.Test;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.test.ByteUtils;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;

class ObservedAddressFrameTest {

    @Test
    void ipv4FrameRoundTrips() throws Exception {
        ObservedAddressFrame frame = new ObservedAddressFrame(5, new InetSocketAddress(InetAddress.getByName("203.0.113.7"), 4433));
        ByteBuffer buffer = ByteBuffer.allocate(frame.getFrameLength());
        frame.serialize(buffer);
        // type 0x9f81a6 as a 4-byte varint, seq 5, 4 address bytes, port
        assertThat(tech.kwik.core.util.Bytes.bytesToHex(buffer.array())).isEqualTo("809f81a605cb0071071151");

        buffer.flip();
        ObservedAddressFrame parsed = new ObservedAddressFrame().parse(buffer, new NullLogger());
        assertThat(parsed.getSequenceNumber()).isEqualTo(5);
        assertThat(parsed.getAddress()).isEqualTo(frame.getAddress());
        assertThat(buffer.remaining()).isZero();
    }

    @Test
    void ipv6FrameRoundTrips() throws Exception {
        ObservedAddressFrame frame = new ObservedAddressFrame(300, new InetSocketAddress(InetAddress.getByName("2001:db8::1"), 1));
        ByteBuffer buffer = ByteBuffer.allocate(frame.getFrameLength());
        frame.serialize(buffer);
        assertThat(buffer.remaining()).isZero();
        assertThat(buffer.array()[3]).isEqualTo((byte) 0xa7);

        buffer.flip();
        ObservedAddressFrame parsed = new ObservedAddressFrame().parse(buffer, new NullLogger());
        assertThat(parsed.getSequenceNumber()).isEqualTo(300);
        assertThat(parsed.getAddress()).isEqualTo(frame.getAddress());
    }
}
