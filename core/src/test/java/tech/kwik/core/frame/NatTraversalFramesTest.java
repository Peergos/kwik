/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static tech.kwik.core.util.Bytes.bytesToHex;

class NatTraversalFramesTest {

    @Test
    void addAddressRoundTrips() throws Exception {
        AddAddressFrame frame = new AddAddressFrame(5, new InetSocketAddress(InetAddress.getByName("203.0.113.7"), 4433));
        ByteBuffer buffer = ByteBuffer.allocate(frame.getFrameLength());
        frame.serialize(buffer);
        assertThat(bytesToHex(buffer.array())).isEqualTo("803d7f9005cb0071071151");

        buffer.flip();
        AddAddressFrame parsed = new AddAddressFrame().parse(buffer, new NullLogger());
        assertThat(parsed.getSequenceNumber()).isEqualTo(5);
        assertThat(parsed.getAddress()).isEqualTo(frame.getAddress());
        assertThat(buffer.remaining()).isZero();
    }

    @Test
    void reachOutIpv6RoundTrips() throws Exception {
        ReachOutFrame frame = new ReachOutFrame(2, new InetSocketAddress(InetAddress.getByName("2001:db8::1"), 1));
        ByteBuffer buffer = ByteBuffer.allocate(frame.getFrameLength());
        frame.serialize(buffer);
        assertThat(buffer.remaining()).isZero();
        assertThat(bytesToHex(buffer.array()).substring(0, 10)).isEqualTo("803d7f9302");

        buffer.flip();
        ReachOutFrame parsed = new ReachOutFrame().parse(buffer, new NullLogger());
        assertThat(parsed.getRound()).isEqualTo(2);
        assertThat(parsed.getAddress()).isEqualTo(frame.getAddress());
    }

    @Test
    void removeAddressRoundTrips() throws Exception {
        RemoveAddressFrame frame = new RemoveAddressFrame(70);
        ByteBuffer buffer = ByteBuffer.allocate(frame.getFrameLength());
        frame.serialize(buffer);
        assertThat(bytesToHex(buffer.array())).isEqualTo("803d7f944046");

        buffer.flip();
        assertThat(new RemoveAddressFrame().parse(buffer, new NullLogger()).getSequenceNumber()).isEqualTo(70);
    }
}
