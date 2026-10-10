/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.core.packet;

import org.junit.jupiter.api.Test;
import tech.kwik.core.frame.*;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.test.ByteUtils;

import java.nio.ByteBuffer;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MultipathFramesTest {

    @Test
    void multipathFramesShouldRoundTripThroughFrameParsing() throws Exception {
        byte[] cid = { 1, 2, 3, 4, 5, 6, 7, 8 };
        List<QuicFrame> sent = List.of(
                new AckFrame(Version.getDefault(), 3, List.of(new Range(5, 9), new Range(1, 2)), 0),
                new NewConnectionIdFrame(Version.getDefault(), 2, 7, 1, cid),
                new RetireConnectionIdFrame(Version.getDefault(), 2, 6),
                new PathAbandonFrame(4, 0x3e76),
                new PathStatusFrame(1, 9, true),
                new PathStatusFrame(1, 10, false),
                new MaxPathIdFrame(17),
                new PathsBlockedFrame(17),
                new PathCidsBlockedFrame(5, 3));
        ByteBuffer buffer = ByteBuffer.allocate(1000);
        int expectedLength = 0;
        for (QuicFrame frame : sent) {
            frame.serialize(buffer);
            expectedLength += frame.getFrameLength();
        }
        assertThat(buffer.position()).isEqualTo(expectedLength);
        buffer.flip();

        ShortHeaderPacket packet = new ShortHeaderPacket(Version.getDefault());
        packet.parseFrames(buffer, new NullLogger());
        List<QuicFrame> parsed = packet.getFrames();

        assertThat(parsed).hasSize(sent.size());
        AckFrame ack = (AckFrame) parsed.get(0);
        assertThat(ack.getPathId()).isEqualTo(3);
        assertThat(ack.getAcknowledgedRanges()).containsExactly(new Range(5, 9), new Range(1, 2));
        NewConnectionIdFrame ncid = (NewConnectionIdFrame) parsed.get(1);
        assertThat(ncid.getPathId()).isEqualTo(2);
        assertThat(ncid.getSequenceNr()).isEqualTo(7);
        assertThat(ncid.getRetirePriorTo()).isEqualTo(1);
        assertThat(ncid.getConnectionId()).isEqualTo(cid);
        assertThat(parsed.get(2)).isEqualTo(new RetireConnectionIdFrame(Version.getDefault(), 2, 6));
        PathAbandonFrame abandon = (PathAbandonFrame) parsed.get(3);
        assertThat(abandon.getPathId()).isEqualTo(4);
        assertThat(abandon.getErrorCode()).isEqualTo(0x3e76);
        assertThat(((PathStatusFrame) parsed.get(4)).isAvailable()).isTrue();
        assertThat(((PathStatusFrame) parsed.get(4)).getSequenceNumber()).isEqualTo(9);
        assertThat(((PathStatusFrame) parsed.get(5)).isAvailable()).isFalse();
        assertThat(((MaxPathIdFrame) parsed.get(6)).getMaxPathId()).isEqualTo(17);
        assertThat(((PathsBlockedFrame) parsed.get(7)).getMaxPathId()).isEqualTo(17);
        assertThat(((PathCidsBlockedFrame) parsed.get(8)).getNextSequenceNumber()).isEqualTo(3);
    }

    @Test
    void nonceShouldIncludePathId() {
        // https://www.ietf.org/archive/id/draft-ietf-quic-multipath-21.html#section-2.4, figure 3
        byte[] iv = ByteUtils.hexToBytes("6b26114b9cba2b63a9e8dd4f");
        assertThat(QuicPacket.nonce(iv, 3, 54321)).isEqualTo(ByteUtils.hexToBytes("6b2611489cba2b63a9e8097e"));
        assertThat(QuicPacket.nonce(iv, 0, 54321)).isEqualTo(ByteUtils.hexToBytes("6b26114b9cba2b63a9e8097e"));
    }

    @Test
    void plainFramesShouldHaveNoPathId() throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        new AckFrame(List.of(new Range(1, 4))).serialize(buffer);
        new RetireConnectionIdFrame(Version.getDefault(), 3).serialize(buffer);
        buffer.flip();

        ShortHeaderPacket packet = new ShortHeaderPacket(Version.getDefault());
        packet.parseFrames(buffer, new NullLogger());

        assertThat(((AckFrame) packet.getFrames().get(0)).getPathId()).isEqualTo(-1);
        assertThat(((RetireConnectionIdFrame) packet.getFrames().get(1)).getPathId()).isEqualTo(-1);
    }

    @Test
    void multipathFramesAreNotAllowedInHandshakePackets() {
        assertThat(FramesCheckFilter.isMultipathFrame(new MaxPathIdFrame(1))).isTrue();
        assertThat(FramesCheckFilter.isMultipathFrame(new AckFrame(List.of(new Range(1, 4))))).isFalse();
        assertThat(FramesCheckFilter.isMultipathFrame(new AckFrame(Version.getDefault(), 0, List.of(new Range(1, 4)), 0))).isTrue();
    }
}
