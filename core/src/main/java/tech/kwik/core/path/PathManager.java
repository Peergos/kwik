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
package tech.kwik.core.path;

import tech.kwik.core.cid.ConnectionIdManager;
import tech.kwik.core.frame.NewConnectionIdFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.frame.RetireConnectionIdFrame;
import tech.kwik.core.impl.Version;
import tech.kwik.core.send.Sender;

import java.nio.ByteBuffer;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;

import static tech.kwik.core.QuicConstants.TransportErrorCode.CONNECTION_ID_LIMIT_ERROR;
import static tech.kwik.core.QuicConstants.TransportErrorCode.FRAME_ENCODING_ERROR;
import static tech.kwik.core.QuicConstants.TransportErrorCode.PROTOCOL_VIOLATION;
import static tech.kwik.core.common.EncryptionLevel.App;

/**
 * Multipath state (draft-ietf-quic-multipath-21) for the path IDs other than 0, whose connection IDs are managed by
 * {@link ConnectionIdManager} as without multipath. Each path ID has its own connection ID sequence numbers, in both
 * directions.
 */
public class PathManager {

    private final Version quicVersion = Version.QUIC_version_1;
    private final ConnectionIdManager connectionIdManager;
    private final Sender sender;
    private final BiConsumer<Integer, String> closeWithError;
    private final long localMaxPathId;
    private volatile long peerMaxPathId;
    private final Map<Long, PathConnectionIds> paths = new ConcurrentHashMap<>();
    private final Map<ByteBuffer, Long> pathIdByConnectionId = new ConcurrentHashMap<>();
    private volatile boolean issuing;

    public PathManager(long localMaxPathId, long peerMaxPathId, ConnectionIdManager connectionIdManager, Sender sender,
                       BiConsumer<Integer, String> closeWithError) {
        this.localMaxPathId = localMaxPathId;
        this.peerMaxPathId = peerMaxPathId;
        this.connectionIdManager = connectionIdManager;
        this.sender = sender;
        this.closeWithError = closeWithError;
    }

    /**
     * Issues connection IDs for every path ID both sides allow, so the peer can open paths
     * (https://www.ietf.org/archive/id/draft-ietf-quic-multipath-21.html#section-3.2.1). Called once 1-RTT packets
     * can be sent.
     */
    public synchronized void startIssuingConnectionIds() {
        issuing = true;
        issueConnectionIds();
    }

    public synchronized void peerMaxPathIdIncreased(long maxPathId) {
        if (maxPathId > peerMaxPathId) {
            peerMaxPathId = maxPathId;
            if (issuing) {
                issueConnectionIds();
            }
        }
    }

    private void issueConnectionIds() {
        long maxPathId = Long.min(localMaxPathId, peerMaxPathId);
        int perPath = Integer.min(connectionIdManager.getMaxConnectionIdsPerPath(), 2);
        for (long pathId = 1; pathId <= maxPathId; pathId++) {
            PathConnectionIds path = path(pathId);
            synchronized (path) {
                if (path.abandoned) {
                    continue;
                }
                while (path.activeLocal() < perPath) {
                    issue(path, 0);
                }
            }
        }
    }

    private void issue(PathConnectionIds path, int retirePriorTo) {
        byte[] connectionId = connectionIdManager.newPathConnectionId();
        int sequenceNr = path.nextLocalSequenceNr++;
        path.local.put(sequenceNr, connectionId);
        pathIdByConnectionId.put(ByteBuffer.wrap(connectionId), path.pathId);
        send(new NewConnectionIdFrame(quicVersion, path.pathId, sequenceNr, retirePriorTo, connectionId));
    }

    private void send(QuicFrame frame) {
        sender.send(frame, App, this::retransmit);
    }

    private void retransmit(QuicFrame frame) {
        if (frame instanceof NewConnectionIdFrame) {
            NewConnectionIdFrame ncid = (NewConnectionIdFrame) frame;
            PathConnectionIds path = paths.get(ncid.getPathId());
            if (path == null || path.abandoned || !path.local.containsKey(ncid.getSequenceNr())) {
                return;
            }
        }
        send(frame);
    }

    private PathConnectionIds path(long pathId) {
        return paths.computeIfAbsent(pathId, PathConnectionIds::new);
    }

    /**
     * The path a received packet belongs to, given its destination connection ID; 0 when the connection ID is not
     * one issued for another path.
     */
    public long resolve(ByteBuffer data, int offset, int length) {
        if (pathIdByConnectionId.isEmpty()) {
            return 0;
        }
        Long pathId = pathIdByConnectionId.get(ByteBuffer.wrap(data.array(), data.arrayOffset() + offset, length));
        return pathId != null? pathId: 0;
    }

    /**
     * Processes a PATH_NEW_CONNECTION_ID frame for a path ID other than 0.
     */
    public void process(NewConnectionIdFrame frame) {
        if (frame.getRetirePriorTo() > frame.getSequenceNr()) {
            closeWithError.accept((int) FRAME_ENCODING_ERROR.value, "retire prior to exceeds sequence number");
            return;
        }
        PathConnectionIds path = path(frame.getPathId());
        synchronized (path) {
            if (path.abandoned) {
                return;
            }
            byte[] existing = path.peer.get(frame.getSequenceNr());
            if (existing != null) {
                if (!java.util.Arrays.equals(existing, frame.getConnectionId())) {
                    closeWithError.accept((int) PROTOCOL_VIOLATION.value, "different connection ids with same sequence number");
                }
                return;
            }
            if (frame.getSequenceNr() < path.peerRetirePriorTo) {
                sendRetire(path.pathId, frame.getSequenceNr());
                return;
            }
            path.peer.put(frame.getSequenceNr(), frame.getConnectionId());
            if (frame.getRetirePriorTo() > path.peerRetirePriorTo) {
                path.peerRetirePriorTo = frame.getRetirePriorTo();
                path.peer.headMap(frame.getRetirePriorTo()).keySet().forEach(sequenceNr -> sendRetire(path.pathId, sequenceNr));
                path.peer.headMap(frame.getRetirePriorTo()).clear();
            }
            if (path.peer.size() > connectionIdManager.getMaxConnectionIdsPerPath()) {
                closeWithError.accept((int) CONNECTION_ID_LIMIT_ERROR.value, "exceeding active connection id limit for path " + path.pathId);
            }
        }
    }

    private void sendRetire(long pathId, int sequenceNr) {
        sender.send(new RetireConnectionIdFrame(quicVersion, pathId, sequenceNr), App, lost -> {
            PathConnectionIds path = paths.get(pathId);
            if (path != null && !path.abandoned) {
                sendRetire(pathId, sequenceNr);
            }
        });
    }

    /**
     * Processes a PATH_RETIRE_CONNECTION_ID frame for a path ID other than 0.
     */
    public void process(RetireConnectionIdFrame frame, byte[] packetDestinationConnectionId) {
        PathConnectionIds path = paths.get(frame.getPathId());
        if (path == null || frame.getSequenceNr() >= path.nextLocalSequenceNr) {
            closeWithError.accept((int) PROTOCOL_VIOLATION.value, "retiring a connection id that was not issued");
            return;
        }
        synchronized (path) {
            byte[] connectionId = path.local.get(frame.getSequenceNr());
            if (connectionId == null) {
                return;
            }
            if (java.util.Arrays.equals(connectionId, packetDestinationConnectionId)) {
                closeWithError.accept((int) PROTOCOL_VIOLATION.value, "cannot retire the connection id the frame was sent to");
                return;
            }
            release(path, frame.getSequenceNr());
            if (!path.abandoned && path.activeLocal() < Integer.min(connectionIdManager.getMaxConnectionIdsPerPath(), 2)) {
                issue(path, 0);
            }
        }
    }

    private void release(PathConnectionIds path, int sequenceNr) {
        byte[] connectionId = path.local.remove(sequenceNr);
        if (connectionId != null) {
            pathIdByConnectionId.remove(ByteBuffer.wrap(connectionId));
            connectionIdManager.releasePathConnectionId(connectionId);
        }
    }

    /**
     * A connection ID the peer issued for the path, or null when there is none.
     */
    public byte[] peerConnectionId(long pathId) {
        PathConnectionIds path = paths.get(pathId);
        if (path == null) {
            return null;
        }
        synchronized (path) {
            return path.peer.isEmpty()? null: path.peer.firstEntry().getValue();
        }
    }

    /**
     * Whether both sides issued connection IDs for the path ID, so a packet can be sent on it.
     */
    public boolean hasConnectionIds(long pathId) {
        PathConnectionIds path = paths.get(pathId);
        if (path == null) {
            return false;
        }
        synchronized (path) {
            return !path.abandoned && !path.local.isEmpty() && !path.peer.isEmpty();
        }
    }

    public long getLocalMaxPathId() {
        return localMaxPathId;
    }

    public long getPeerMaxPathId() {
        return peerMaxPathId;
    }

    private static class PathConnectionIds {
        final long pathId;
        final TreeMap<Integer, byte[]> local = new TreeMap<>();
        int nextLocalSequenceNr;
        final TreeMap<Integer, byte[]> peer = new TreeMap<>();
        int peerRetirePriorTo;
        boolean abandoned;

        PathConnectionIds(long pathId) {
            this.pathId = pathId;
        }

        int activeLocal() {
            return local.size();
        }
    }
}
