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

import tech.kwik.core.generic.InvalidIntegerEncodingException;
import tech.kwik.core.generic.VariableLengthInteger;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * REACH_OUT frame of iroh's QUIC NAT traversal, as implemented by noq:
 * "{ Type (i) = 0x3d7f92..0x3d7f93, Round (i), IPv4 (32) / IPv6 (128), Port (16) }"
 */
public class ReachOutFrame extends QuicFrame {

    public static final long TYPE_IPV4 = 0x3d7f92L;
    public static final long TYPE_IPV6 = 0x3d7f93L;

    private long round;
    private InetSocketAddress address;

    public ReachOutFrame(long round, InetSocketAddress address) {
        this.round = round;
        this.address = address;
    }

    public ReachOutFrame() {
    }

    public static boolean isType(long type) {
        return type == TYPE_IPV4 || type == TYPE_IPV6;
    }

    public ReachOutFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        long type = VariableLengthInteger.parseLong(buffer);
        round = VariableLengthInteger.parseLong(buffer);
        byte[] ip = new byte[type == TYPE_IPV6? 16: 4];
        buffer.get(ip);
        int port = buffer.getShort() & 0xffff;
        try {
            address = new InetSocketAddress(InetAddress.getByAddress(ip), port);
        }
        catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    private long type() {
        return address.getAddress() instanceof Inet6Address? TYPE_IPV6: TYPE_IPV4;
    }

    @Override
    public int getFrameLength() {
        return VariableLengthInteger.bytesNeeded(type()) + VariableLengthInteger.bytesNeeded(round)
                + address.getAddress().getAddress().length + 2;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        VariableLengthInteger.encode(type(), buffer);
        VariableLengthInteger.encode(round, buffer);
        buffer.put(address.getAddress().getAddress());
        buffer.putShort((short) address.getPort());
    }

    public long getRound() {
        return round;
    }

    public InetSocketAddress getAddress() {
        return address;
    }

    @Override
    public String toString() {
        return "ReachOutFrame[" + round + ":" + address + "]";
    }

    @Override
    public void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
