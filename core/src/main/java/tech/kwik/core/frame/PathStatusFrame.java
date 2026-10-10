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
 * PATH_STATUS_BACKUP and PATH_STATUS_AVAILABLE (draft-ietf-quic-multipath section 4.3).
 */
public class PathStatusFrame extends QuicFrame {

    public static final long TYPE_BACKUP = 0x3e76;
    public static final long TYPE_AVAILABLE = 0x3e77;

    private long pathId;
    private long sequenceNumber;
    private boolean available;

    public PathStatusFrame() {
    }

    public PathStatusFrame(long pathId, long sequenceNumber, boolean available) {
        this.pathId = pathId;
        this.sequenceNumber = sequenceNumber;
        this.available = available;
    }

    public PathStatusFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        available = VariableLengthInteger.parseLong(buffer) == TYPE_AVAILABLE;
        pathId = VariableLengthInteger.parseLong(buffer);
        sequenceNumber = VariableLengthInteger.parseLong(buffer);
        return this;
    }

    private long type() {
        return available? TYPE_AVAILABLE: TYPE_BACKUP;
    }

    @Override
    public int getFrameLength() {
        return VariableLengthInteger.bytesNeeded(type()) + VariableLengthInteger.bytesNeeded(pathId) + VariableLengthInteger.bytesNeeded(sequenceNumber);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        VariableLengthInteger.encode(type(), buffer);
        VariableLengthInteger.encode(pathId, buffer);
        VariableLengthInteger.encode(sequenceNumber, buffer);
    }

    public boolean isAvailable() {
        return available;
    }

    public long getPathId() {
        return pathId;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    @Override
    public String toString() {
        return "PathStatusFrame[" + pathId + "," + sequenceNumber + (available? ",available": ",backup") + "]";
    }

    @Override
    public void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
