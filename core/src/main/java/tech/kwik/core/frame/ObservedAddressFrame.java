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
 * OBSERVED_ADDRESS frame of QUIC Address Discovery (draft-ietf-quic-address-discovery), as implemented by noq:
 * "OBSERVED_ADDRESS Frame { Type (i) = 0x9f81a6..0x9f81a7, Sequence Number (i), IPv4 (32) / IPv6 (128), Port (16) }"
 */
public class ObservedAddressFrame extends QuicFrame {

    public static final long TYPE_IPV4 = 0x9f81a6L;
    public static final long TYPE_IPV6 = 0x9f81a7L;

    private long sequenceNumber;
    private InetSocketAddress address;

    public ObservedAddressFrame(long sequenceNumber, InetSocketAddress address) {
        this.sequenceNumber = sequenceNumber;
        this.address = address;
    }

    public ObservedAddressFrame() {
    }

    public static boolean isObservedAddressFrameType(long type) {
        return type == TYPE_IPV4 || type == TYPE_IPV6;
    }

    public ObservedAddressFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        long type = VariableLengthInteger.parseLong(buffer);
        sequenceNumber = VariableLengthInteger.parseLong(buffer);
        byte[] ip = new byte[type == TYPE_IPV6? 16: 4];
        buffer.get(ip);
        int port = buffer.getShort() & 0xffff;
        try {
            address = new InetSocketAddress(InetAddress.getByAddress(ip), port);
        }
        catch (UnknownHostException e) {
            // Impossible with 4 or 16 bytes
            throw new IllegalStateException(e);
        }
        return this;
    }

    private long type() {
        return address.getAddress() instanceof Inet6Address? TYPE_IPV6: TYPE_IPV4;
    }

    @Override
    public int getFrameLength() {
        return VariableLengthInteger.bytesNeeded(type()) + VariableLengthInteger.bytesNeeded(sequenceNumber)
                + address.getAddress().getAddress().length + 2;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        VariableLengthInteger.encode(type(), buffer);
        VariableLengthInteger.encode(sequenceNumber, buffer);
        buffer.put(address.getAddress().getAddress());
        buffer.putShort((short) address.getPort());
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public InetSocketAddress getAddress() {
        return address;
    }

    @Override
    public String toString() {
        return "ObservedAddressFrame[" + sequenceNumber + ":" + address + "]";
    }

    @Override
    public void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
