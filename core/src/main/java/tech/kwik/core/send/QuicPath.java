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
package tech.kwik.core.send;

import tech.kwik.core.ack.AckGenerator;
import tech.kwik.core.cc.CongestionController;
import tech.kwik.core.cc.NewRenoCongestionController;
import tech.kwik.core.cid.ConnectionIdProvider;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.impl.HandshakeState;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.Logger;
import tech.kwik.core.recovery.RecoveryManager;
import tech.kwik.core.recovery.RttEstimator;

import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * A multipath path other than path 0 (draft-ietf-quic-multipath-21): its own packet number space, acknowledgements,
 * loss recovery, RTT estimate and congestion window. Frames from the shared App queue can go on any path; acks and
 * probes for a path go on that path.
 */
public class QuicPath {

    public enum State { VALIDATING, ACTIVE, ABANDONED }

    private final long id;
    private volatile InetSocketAddress peerAddress;
    private volatile State state;
    private volatile boolean peerPrefersBackup;
    private volatile boolean suspect;
    private volatile boolean carriesData = true;
    private final SendRequestQueue requestQueue;
    private final AckGenerator ackGenerator;
    private final PacketAssembler assembler;
    private final RttEstimator rttEstimator;
    private final CongestionController congestionController;
    private final RecoveryManager recoveryManager;
    private final ConnectionIdProvider connectionIds;
    private volatile int maxPacketSize;
    private volatile byte[] challenge;
    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    QuicPath(long id, InetSocketAddress peerAddress, State state, Clock clock, VersionHolder version, Role role,
         SendRequestQueue sharedAppQueue, ConnectionIdProvider connectionIds, int maxPacketSize, SenderImpl sender, Logger log) {
        this.id = id;
        this.peerAddress = peerAddress;
        this.state = state;
        this.maxPacketSize = maxPacketSize;
        this.connectionIds = connectionIds;
        requestQueue = SendRequestQueue.forPath(clock, sharedAppQueue);
        requestQueue.setSharedEnabled(state == State.ACTIVE);
        PathSender pathSender = new PathSender(sender);
        rttEstimator = new RttEstimator(log);
        congestionController = new NewRenoCongestionController(log, sender);
        recoveryManager = new RecoveryManager(clock, role, rttEstimator, congestionController, pathSender, log);
        recoveryManager.handshakeStateChangedEvent(HandshakeState.Confirmed);
        ackGenerator = new AckGenerator(clock, PnSpace.App, pathSender, rttEstimator, recoveryManager);
        ackGenerator.setPathId(id);
        assembler = new PacketAssembler(version, EncryptionLevel.App, requestQueue, ackGenerator, connectionIds, new PacketNumberGenerator());
        assembler.setPathId(id);
    }

    public long getId() {
        return id;
    }

    public InetSocketAddress getPeerAddress() {
        return peerAddress;
    }

    public void setPeerAddress(InetSocketAddress peerAddress) {
        this.peerAddress = peerAddress;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
        updateSharedEnabled();
    }

    public boolean isSuspect() {
        return suspect;
    }

    void setSuspect(boolean suspect) {
        this.suspect = suspect;
        updateSharedEnabled();
    }

    /**
     * Whether the scheduler has this path carry stream and other shared frames.
     */
    void setCarriesData(boolean carriesData) {
        if (this.carriesData != carriesData) {
            this.carriesData = carriesData;
            updateSharedEnabled();
        }
    }

    private void updateSharedEnabled() {
        requestQueue.setSharedEnabled(state == State.ACTIVE && !suspect && carriesData);
    }

    public boolean peerPrefersBackup() {
        return peerPrefersBackup;
    }

    public void setPeerPrefersBackup(boolean backup) {
        peerPrefersBackup = backup;
    }

    public static byte[] randomChallengeData() {
        byte[] data = new byte[8];
        RANDOM.nextBytes(data);
        return data;
    }

    public byte[] newChallenge() {
        byte[] data = new byte[8];
        RANDOM.nextBytes(data);
        challenge = data;
        return data;
    }

    public boolean isCurrentChallenge(byte[] data) {
        return java.util.Arrays.equals(challenge, data);
    }

    /**
     * Whether a PATH_RESPONSE answers the last PATH_CHALLENGE sent on this path.
     */
    public boolean challengeAnswered(byte[] data) {
        byte[] current = challenge;
        return current != null && java.security.MessageDigest.isEqual(current, data);
    }

    public AckGenerator getAckGenerator() {
        return ackGenerator;
    }

    public RecoveryManager getRecoveryManager() {
        return recoveryManager;
    }

    public RttEstimator getRttEstimator() {
        return rttEstimator;
    }

    public CongestionController getCongestionController() {
        return congestionController;
    }

    public SendRequestQueue getRequestQueue() {
        return requestQueue;
    }

    int getMaxPacketSize() {
        return maxPacketSize;
    }

    /**
     * Queues a frame that must be sent on this path, such as PATH_CHALLENGE or PATH_RESPONSE.
     */
    public void sendOnPath(QuicFrame frame, Consumer<QuicFrame> lostCallback) {
        requestQueue.addPriorityRequestOwn(frame, lostCallback);
    }

    /**
     * Sends the frames to another address than the path's, see {@link SendRequestQueue#addOffPathRequest}.
     */
    public void sendOffPath(java.util.List<QuicFrame> frames, InetSocketAddress destination) {
        requestQueue.addOffPathRequest(frames, destination);
    }

    Optional<SendItem> assemble() {
        if (state == State.ABANDONED || !hasPeerConnectionId()) {
            return Optional.empty();
        }
        return assembler.assemble((int) congestionController.remainingCwnd(), maxPacketSize, peerAddress);
    }

    private boolean hasPeerConnectionId() {
        return connectionIds.getPeerConnectionId(peerAddress) != null;
    }

    Instant nextDelayedSendTime() {
        return requestQueue.nextDelayedSend();
    }

    @Override
    public String toString() {
        return "Path[" + id + "," + peerAddress + "," + state + "]";
    }

    /**
     * The sender as the path's recovery manager and ack generator see it: their acks and probes go on this path.
     */
    private class PathSender implements Sender {
        private final SenderImpl sender;

        PathSender(SenderImpl sender) {
            this.sender = sender;
        }

        @Override
        public void send(QuicFrame frame, EncryptionLevel level) {
            sender.send(frame, level);
        }

        @Override
        public void send(QuicFrame frame, EncryptionLevel level, Consumer<QuicFrame> frameLostCallback) {
            sender.send(frame, level, frameLostCallback);
        }

        @Override
        public void send(Function<Integer, QuicFrame> frameSupplier, int minimumSize, EncryptionLevel level, Consumer<QuicFrame> lostCallback) {
            sender.send(frameSupplier, minimumSize, level, lostCallback);
        }

        @Override
        public void sendAlternateAddress(QuicFrame frame, InetSocketAddress clientAddress) {
            sender.sendAlternateAddress(frame, clientAddress);
        }

        @Override
        public void setInitialToken(byte[] token) {
        }

        @Override
        public void sendAck(PnSpace pnSpace, int maxDelay) {
            sender.sendAck(QuicPath.this, maxDelay);
        }

        @Override
        public void sendProbe(EncryptionLevel level) {
            requestQueue.addProbeRequest();
            sender.flush();
        }

        @Override
        public void sendProbe(List<QuicFrame> frames, EncryptionLevel level) {
            sender.probeTimeout(id);
            requestQueue.addProbeRequest(frames);
            sender.flush();
        }

        @Override
        public void packetProcessed(boolean expectingMore) {
            sender.packetProcessed(expectingMore);
        }

        @Override
        public void datagramProcessed(boolean expectingMore) {
            sender.datagramProcessed(expectingMore);
        }

        @Override
        public void flush() {
            sender.flush();
        }

        @Override
        public Instant lastAckElicitingSent() {
            return sender.lastAckElicitingSent();
        }

        @Override
        public int getPto() {
            return sender.getPto(rttEstimator);
        }
    }
}
