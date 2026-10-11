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

import java.nio.ByteBuffer;

/**
 * REMOVE_ADDRESS frame of iroh's QUIC NAT traversal: "{ Type (i) = 0x3d7f94, Sequence Number (i) }"
 */
public class RemoveAddressFrame extends QuicFrame {

    public static final long TYPE = 0x3d7f94;

    private long sequenceNumber;

    public RemoveAddressFrame() {
    }

    public RemoveAddressFrame(long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public RemoveAddressFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        VariableLengthInteger.parseLong(buffer);
        sequenceNumber = VariableLengthInteger.parseLong(buffer);
        return this;
    }

    private long type() {
        return TYPE;
    }

    @Override
    public int getFrameLength() {
        return VariableLengthInteger.bytesNeeded(type()) + VariableLengthInteger.bytesNeeded(sequenceNumber);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        VariableLengthInteger.encode(type(), buffer);
        VariableLengthInteger.encode(sequenceNumber, buffer);
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    @Override
    public String toString() {
        return "RemoveAddressFrame[" + sequenceNumber + "]";
    }

    @Override
    public void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
