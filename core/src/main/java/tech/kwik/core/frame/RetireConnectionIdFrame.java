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
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;

import java.nio.ByteBuffer;

/**
 * Represents a retire connection id frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-retire_connection_id-frames
 */
public class RetireConnectionIdFrame extends QuicFrame {

    public static final long PATH_RETIRE_CONNECTION_ID = 0x3e79;

    // For a PATH_RETIRE_CONNECTION_ID frame (draft-ietf-quic-multipath); -1 for a RETIRE_CONNECTION_ID frame.
    private long pathId = -1;
    private int sequenceNr;

    public RetireConnectionIdFrame(Version quicVersion) {
    }

    public RetireConnectionIdFrame(Version quicVersion, int sequenceNumber) {
        this.sequenceNr = sequenceNumber;
    }

    /**
     * Creates a PATH_RETIRE_CONNECTION_ID frame for the given path.
     */
    public RetireConnectionIdFrame(Version quicVersion, long pathId, int sequenceNumber) {
        this.pathId = pathId;
        this.sequenceNr = sequenceNumber;
    }

    public RetireConnectionIdFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException, TransportError {
        if (VariableLengthInteger.parseLong(buffer) == PATH_RETIRE_CONNECTION_ID) {
            pathId = VariableLengthInteger.parseLong(buffer);
        }
        sequenceNr = parseVariableLengthIntegerLimitedToInt(buffer);  // Kwik does not support sequence numbers larger than max int.
        return this;
    }

    @Override
    public int getFrameLength() {
        return (pathId >= 0? VariableLengthInteger.bytesNeeded(PATH_RETIRE_CONNECTION_ID) + VariableLengthInteger.bytesNeeded(pathId): 1)
                + VariableLengthInteger.bytesNeeded(sequenceNr);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        if (pathId >= 0) {
            VariableLengthInteger.encode(PATH_RETIRE_CONNECTION_ID, buffer);
            VariableLengthInteger.encode(pathId, buffer);
        }
        else {
            buffer.put((byte) 0x19);
        }
        VariableLengthInteger.encode(sequenceNr, buffer);
    }

    @Override
    public String toString() {
        return "RetireConnectionIdFrame[" + (pathId >= 0? "path " + pathId + ",": "") + sequenceNr + "]";
    }

    @Override
    public boolean equals(Object obj) {
        return (obj instanceof RetireConnectionIdFrame) &&
                ((RetireConnectionIdFrame) obj).sequenceNr == this.sequenceNr &&
                ((RetireConnectionIdFrame) obj).pathId == this.pathId;
    }

    @Override
    public int hashCode() {
        return Integer.hashCode(sequenceNr);
    }

    /**
     * The path ID of a PATH_RETIRE_CONNECTION_ID frame, or -1 for a RETIRE_CONNECTION_ID frame.
     */
    public long getPathId() {
        return pathId;
    }

    public int getSequenceNr() {
        return sequenceNr;
    }

    @Override
    public void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
