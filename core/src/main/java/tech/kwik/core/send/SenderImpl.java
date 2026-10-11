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

import tech.kwik.core.ack.GlobalAckGenerator;
import tech.kwik.core.cc.CongestionControlEventListener;
import tech.kwik.core.cc.CongestionController;
import tech.kwik.core.cc.NewRenoCongestionController;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.impl.HandshakeStateListener;
import tech.kwik.core.impl.HandshakeState;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.crypto.MissingKeysException;
import tech.kwik.core.frame.Padding;
import tech.kwik.core.frame.PathChallengeFrame;
import tech.kwik.core.frame.PathResponseFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.IdleTimer;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.NullQLog;
import tech.kwik.core.log.QLog;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.packet.ShortHeaderPacket;
import tech.kwik.core.recovery.RecoveryManager;
import tech.kwik.core.recovery.RttEstimator;
import tech.kwik.core.socket.SocketManager;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import tech.kwik.core.cid.ConnectionIdProvider;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Collection;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.lang.Long.max;
import static tech.kwik.core.common.KwikConstants.MAX_SUPPORTED_PACKET_SIZE;

/**
 * Sender implementation that queues frames-to-be-sent and assembles packets "just in time" when conditions allow to
 * send a packet.
 *
 * Sending packets is limited by congestion controller, anti-amplification attack limitations and, for stream frames,
 * flow control. However, ack-only packets are not subject to congestion control and probes are not limited by
 * congestion control (but do count); therefore, such packets have priority when other packets are queued because of
 * congestion control limits. Additionally, delayed ack packets don't have to be send immediately, but they have to
 * within a given time frame.
 * To improve packet and frame coalescing, messages should not be sent immediately when there is the expectation that
 * more will follow in due time.
 *
 * So a sender has to wait for any of the following conditions to become true:
 * - received packet completely processed or batch of packets processed and send requests queued
 * - "spontaneous" request queued (e.g. application initiated stream data)
 * - probe request
 * - delayed ack timeout
 * - congestion controller becoming unblocked due to timer-induced loss detection
 */
public class SenderImpl implements Sender, CongestionControlEventListener, HandshakeStateListener {

    private final Clock clock;
    private volatile int maxPacketSize;
    private final QuicConnectionImpl connection;
    private final SocketManager socketManager;
    private final CongestionController congestionController;
    private final RttEstimator rttEstimater;
    private final Logger log;
    private final QLog qlog;
    private final SendRequestQueue[] sendRequestQueue = new SendRequestQueue[EncryptionLevel.values().length];
    private final GlobalPacketAssembler packetAssembler;
    private final GlobalAckGenerator globalAckGenerator;
    private final RecoveryManager recoveryManager;
    private final IdleTimer idleTimer;
    private final Thread senderThread;
    private final boolean[] discardedSpaces = new boolean[PnSpace.values().length];
    private ConnectionSecrets connectionSecrets;
    private final Object condition = new Object();
    private boolean signalled;

    // Using thread-confinement strategy for concurrency control: only the sender thread created in this class accesses these members
    private volatile boolean running;
    private volatile boolean stopping;
    private volatile boolean stopped;
    private volatile int receiverMaxAckDelay;
    private volatile int datagramsSent;
    private volatile long bytesSent;
    private volatile long dataSent;
    private volatile long packetsSent;
    private AtomicInteger subsequentZeroDelays = new AtomicInteger();
    private volatile boolean lastDelayWasZero = false;
    private volatile int antiAmplificationLimit = -1;
    private volatile Runnable shutdownHook;
    private volatile Instant lastestAckElicitingTime;
    private final byte[] paddingPattern;
    private static final int MAX_BATCH_BYTES = 65000;
    // While received datagrams are queued, the sender is woken once per this many datagrams instead of for each, and
    // immediate acks are held until then, so acks cover more packets. Only accessed by the receiver thread.
    private static final int MAX_DEFERRED_DATAGRAMS = 64;
    private boolean deferWakeUp;
    private int deferredDatagrams;
    private boolean ackHeld;
    private final Set<QuicPath> pathAcksHeld = new HashSet<>();
    // Multipath paths other than path 0, whose state is in this class's fields.
    private final Map<Long, QuicPath> paths = new ConcurrentHashMap<>();
    private final java.util.Queue<Long> probeTimeouts = new java.util.concurrent.ConcurrentLinkedQueue<>();
    private volatile boolean initialPathSuspect;
    private volatile boolean initialPathAbandoned;
    private byte[] batchBuffer;
    private final MtuDiscovery mtuDiscovery;
    private final VersionHolder version;


    public SenderImpl(VersionHolder version, int maxPacketSize, SocketManager socketManager, QuicConnectionImpl connection,
                      String id, Integer initialRtt, Logger log) {
        this(Clock.systemUTC(), version, maxPacketSize, socketManager, connection, id, initialRtt, log);
    }

    public SenderImpl(Clock clock, VersionHolder version, int maxPacketSize, SocketManager socketManager,
                      QuicConnectionImpl connection, String id, Integer initialRtt, Logger log) {
        this.clock = clock;
        this.version = version;
        this.maxPacketSize = maxPacketSize;
        this.socketManager = socketManager;
        this.connection = connection;
        this.log = log;
        this.qlog = log.getQLog();

        Arrays.stream(EncryptionLevel.values()).forEach(level -> {
            int levelIndex = level.ordinal();
            sendRequestQueue[levelIndex] = new SendRequestQueue(clock, level);
        });

        rttEstimater = (initialRtt == null)? new RttEstimator(log): new RttEstimator(log, initialRtt);

        congestionController = new NewRenoCongestionController(log, this);

        recoveryManager = new RecoveryManager(connection.getRole(), rttEstimater, congestionController, this, log);
        connection.addHandshakeStateListener(recoveryManager);
        connection.addAckFrameReceivedListener(recoveryManager);
        mtuDiscovery = new MtuDiscovery(maxPacketSize, Integer.min(MtuDiscovery.DEFAULT_UPPER_BOUND, MAX_SUPPORTED_PACKET_SIZE));
        if (maxPacketSize > 1200) {
            connection.addHandshakeStateListener(this);
        }

        globalAckGenerator = new GlobalAckGenerator(this, rttEstimater, recoveryManager);
        packetAssembler = new GlobalPacketAssembler(version, sendRequestQueue, globalAckGenerator, connection.getConnectionIdManager());

        lastestAckElicitingTime = clock.instant();

        idleTimer = connection.getIdleTimer();

        senderThread = new Thread(() -> sendLoop(), "sender" + (!id.isBlank()? "-" + id: ""));
        senderThread.setDaemon(true);

        String paddingPatternProp = System.getProperty("tech.kwik.padding-pattern");
        if (paddingPatternProp != null && !paddingPatternProp.isEmpty()) {
            paddingPattern = new byte[paddingPatternProp.length() / 2];
            for (int i = 0; i < paddingPattern.length; i++) {
                paddingPattern[i] = (byte) Integer.parseInt(paddingPatternProp.substring(i * 2, i * 2 + 2), 16);
            }
        }
        else {
            paddingPattern = new byte[]{ 0 };
        }
    }

    public void start(ConnectionSecrets secrets) {
        connectionSecrets = secrets;
        senderThread.start();
    }

    @Override
    public void send(QuicFrame frame, EncryptionLevel level) {
        sendRequestQueue[level.ordinal()].addRequest(frame, f -> {});
    }

    @Override
    public void send(QuicFrame frame, EncryptionLevel level, Consumer<QuicFrame> frameLostCallback) {
        sendRequestQueue[level.ordinal()].addRequest(frame, frameLostCallback);
    }

    @Override
    public void send(Function<Integer, QuicFrame> frameSupplier, int minimumSize, EncryptionLevel level, Consumer<QuicFrame> lostCallback) {
        sendRequestQueue[level.ordinal()].addRequest(frameSupplier, minimumSize, lostCallback);
    }

    public void sendWithPriority(QuicFrame frame, EncryptionLevel level, Consumer<QuicFrame> lostCallback) {
        sendRequestQueue[level.ordinal()].addPriorityRequest(frame, lostCallback);
        wakeUpSenderLoop();
    }

    @Override
    public void sendAlternateAddress(QuicFrame frame, InetSocketAddress address) {
        if (! (frame instanceof PathChallengeFrame || frame instanceof PathResponseFrame)) {
            throw new IllegalArgumentException("Only path challenge/response frames can be sent to an alternate address");
        }
        sendRequestQueue[EncryptionLevel.App.ordinal()].addAlternateAddressRequest(frame, address);
        wakeUpSenderLoop();
    }

    @Override
    public void setInitialToken(byte[] token) {
        if (token != null) {
            packetAssembler.setInitialToken(token);
        }
    }

    @Override
    public void sendAck(PnSpace pnSpace, int maxDelay) {
        if (maxDelay == 0 && pnSpace == PnSpace.App && deferWakeUp) {
            ackHeld = true;
            maxDelay = 20;
        }
        sendRequestQueue[pnSpace.relatedEncryptionLevel().ordinal()].addAckRequest(maxDelay);
        if (maxDelay > 0) {
            // Now, the sender loop must use a different wait-period, to ensure it wakes up when the delayed ack
            // must be sent.
            // However, given the current implementation of packetProcessed (i.e. it always wakes up the sender loop),
            // it is not necessary to do this with a ...
            // senderThread.interrupt
            // ... because packetProcessed will ensure the new period is computed.
        }
    }

    void sendAck(QuicPath path, int maxDelay) {
        if (maxDelay == 0 && deferWakeUp) {
            pathAcksHeld.add(path);
            maxDelay = 20;
        }
        path.getRequestQueue().addAckRequest(maxDelay);
    }

    /**
     * Adds a multipath path. Packets for it are assembled by the sender loop once it has frames to send; shared
     * frames only when the path is active.
     */
    public QuicPath addPath(long id, InetSocketAddress peerAddress, ConnectionIdProvider connectionIds, QuicPath.State state) {
        QuicPath path = new QuicPath(id, peerAddress, state, clock, version, connection.getRole(),
                sendRequestQueue[EncryptionLevel.App.ordinal()], connectionIds, Integer.min(maxPacketSize, 1200), this, log);
        paths.put(id, path);
        return path;
    }

    public QuicPath getPath(long id) {
        return paths.get(id);
    }

    public Collection<QuicPath> getPaths() {
        return paths.values();
    }

    /**
     * Stops using the initial path (path 0), which was abandoned while other paths remain: what was in flight on it
     * is retransmitted on the other paths.
     */
    public void abandonInitialPath() {
        initialPathAbandoned = true;
        sendRequestQueue[EncryptionLevel.App.ordinal()].setSharedEnabled(false);
        recoveryManager.declareAllLost(PnSpace.App);
        wakeUpSenderLoop();
    }

    public boolean isInitialPathAbandoned() {
        return initialPathAbandoned;
    }

    /**
     * Whether a path other than path 0 and the given one is active or still being validated.
     */
    public boolean hasOtherPath(long except) {
        return paths.values().stream().anyMatch(p -> p.getId() != except && p.getState() != QuicPath.State.ABANDONED);
    }

    public void removePath(long id) {
        QuicPath path = paths.remove(id);
        if (path != null) {
            path.setState(QuicPath.State.ABANDONED);
            path.getRecoveryManager().abandon();
            if (paths.isEmpty() && !initialPathAbandoned) {
                // Path 0 is the only path again.
                initialPathSuspect = false;
                sendRequestQueue[EncryptionLevel.App.ordinal()].setSharedEnabled(true);
            }
            wakeUpSenderLoop();
        }
    }

    @Override
    public void sendProbe(EncryptionLevel level) {
        synchronized (discardedSpaces) {
            if (! discardedSpaces[level.relatedPnSpace().ordinal()]) {
                sendRequestQueue[level.ordinal()].addProbeRequest();
                wakeUpSenderLoop();
            }
            else {
                log.warn("Attempt to send probe on discarded space (" + level.relatedPnSpace() + ") => ignoring");
            }
        }
    }

    @Override
    public void sendProbe(List<QuicFrame> frames, EncryptionLevel level) {
        if (level == EncryptionLevel.App) {
            probeTimeout(0);
        }
        synchronized (discardedSpaces) {
            if (! discardedSpaces[level.relatedPnSpace().ordinal()]) {
                sendRequestQueue[level.ordinal()].addProbeRequest(frames);
                wakeUpSenderLoop();
            }
            else {
                log.warn("Attempt to send probe on discarded space (" + level.relatedPnSpace() + ") => ignoring");
            }
        }
    }

    @Override
    public void packetProcessed(boolean expectingMore) {
        // If you change this, review this.sendAck()!
        if (deferWakeUp) {
            return;
        }
        if (ackHeld) {
            ackHeld = false;
            sendRequestQueue[EncryptionLevel.App.ordinal()].addAckRequest(0);
        }
        if (!pathAcksHeld.isEmpty()) {
            pathAcksHeld.forEach(path -> path.getRequestQueue().addAckRequest(0));
            pathAcksHeld.clear();
        }
        wakeUpSenderLoop();
    }

    /**
     * Whether wake-ups are being deferred because more received datagrams are queued; receiver thread only.
     */
    public boolean isDeferringWakeUp() {
        return deferWakeUp;
    }

    @Override
    public void endDeferral() {
        if (deferWakeUp) {
            deferWakeUp = false;
            deferredDatagrams = 0;
            packetProcessed(false);
        }
    }

    @Override
    public void moreDatagramsQueued(boolean more) {
        deferWakeUp = more && ++deferredDatagrams < MAX_DEFERRED_DATAGRAMS;
        if (!deferWakeUp) {
            deferredDatagrams = 0;
        }
    }

    @Override
    public void datagramProcessed(boolean expectingMore) {
        // Nothing, current implementation flushes when packet processed
    }

    @Override
    public void flush() {
        wakeUpSenderLoop();
    }
    
    public void discard(PnSpace space, String reason) {
        synchronized (discardedSpaces) {
            if (!discardedSpaces[space.ordinal()]) {
                packetAssembler.stop(space);
                recoveryManager.stopRecovery(space);
                log.recovery("Discarding pn space " + space + " because " + reason);
                globalAckGenerator.discard(space);
                discardedSpaces[space.ordinal()] = true;
            }
        }
    }

    /**
     * Stop sending packets, but don't shutdown yet, so connection close can be sent.
     */
    public void stop() {
        // Stop sending packets, so discard any packet waiting to be send.
        Arrays.stream(sendRequestQueue).forEach(sendRequestQueue -> sendRequestQueue.clear());

        // No more retransmissions either.
        recoveryManager.stopRecovery();

        stopped = true;
    }

    public void shutdown(Runnable postShutdownAction) {
        assert(stopped);  // Stopped should have be called before.
        // Stop cannot be called here (again), because it would drop ConnectionCloseFrame still waiting to be sent.

        shutdownHook = postShutdownAction;
        stopping = true;
        senderThread.interrupt();
    }

    @Override
    public void bytesInFlightIncreased(long bytesInFlight) {
    }

    @Override
    public void bytesInFlightDecreased(long bytesInFlight) {
        wakeUpSenderLoop();
    }

    private void sendLoop() {
        try {
            running = true;
            while (running) {
                doLoopIteration();
            }
        }
        catch (Throwable fatalError) {
            if (running) {
                log.error("Sender thread aborted with exception", fatalError);
                connection.abortConnection(fatalError);
            }
            else {
                log.warn("Ignoring " + fatalError + " because sender is shutting down.");
            }
        }
        if (shutdownHook != null) {
            shutdownHook.run();
        }
    }

    void doLoopIteration() throws IOException {
        synchronized (condition) {
            try {
                if (! signalled) {
                    long timeout = determineMaximumWaitTime();
                    if (timeout > 0) {
                        condition.wait(timeout);
                    }
                }
                signalled = false;
            }
            catch (InterruptedException e) {
                log.debug("Sender thread is interrupted; probably shutting down? " + running);
            }
        }

        // Determine whether this loop must be ended _before_ composing packets, to avoid race conditions with
        // items being queued just after the packet assembler (for that level) has executed.
        if (stopping) {
            running = false;
        }

        sendIfAny();
    }

    @Override
    public void handshakeStateChangedEvent(HandshakeState newState) {
        if (newState == HandshakeState.Confirmed) {
            mtuDiscovery.enable();
            wakeUpSenderLoop();
        }
    }

    private void sendMtuProbeIfDue() throws IOException {
        int size = mtuDiscovery.nextProbe();
        if (size == 0) {
            return;
        }
        Optional<AssembledDatagram> probe = Optional.empty();
        if (congestionController.remainingCwnd() >= size) {
            probe = packetAssembler.assembleMtuProbe(size, socketManager.getClientAddress(),
                    lost -> {
                        mtuDiscovery.probeLost(size);
                        wakeUpSenderLoop();
                    },
                    () -> {
                        maxPacketSize = mtuDiscovery.probeAcked(size);
                        wakeUpSenderLoop();
                    });
        }
        if (probe.isEmpty()) {
            mtuDiscovery.probeLost(-1);
            return;
        }
        send(probe.get(), size);
    }

    /**
     * Notes a probe timeout on a path (0 for the initial path). With multipath, a path that times out while another
     * works is suspected broken: what is in flight on it is retransmitted (on other paths), and it gets no new data
     * until it is acknowledged again.
     */
    void probeTimeout(long pathId) {
        if (!paths.isEmpty()) {
            probeTimeouts.add(pathId);
            wakeUpSenderLoop();
        }
    }

    /**
     * Notes that a path (0 for the initial path) got an acknowledgement, so it is not (or no longer) suspect.
     */
    public void pathAcknowledged(long pathId) {
        if (pathId == 0) {
            if (initialPathSuspect) {
                initialPathSuspect = false;
                sendRequestQueue[EncryptionLevel.App.ordinal()].setSharedEnabled(true);
                wakeUpSenderLoop();
            }
        }
        else {
            QuicPath path = paths.get(pathId);
            if (path != null && path.isSuspect()) {
                path.setSuspect(false);
                wakeUpSenderLoop();
            }
        }
    }

    private void handleProbeTimeouts() {
        Long pathId;
        while ((pathId = probeTimeouts.poll()) != null) {
            long timedOut = pathId;
            boolean otherPathWorks = (timedOut != 0 && !initialPathSuspect)
                    || paths.values().stream().anyMatch(p -> p.getId() != timedOut && p.getState() == QuicPath.State.ACTIVE && !p.isSuspect());
            if (!otherPathWorks) {
                continue;
            }
            if (timedOut == 0) {
                if (!initialPathSuspect) {
                    log.info("Initial path suspected broken; retransmitting on other paths");
                    initialPathSuspect = true;
                    sendRequestQueue[EncryptionLevel.App.ordinal()].setSharedEnabled(false);
                    recoveryManager.declareAllLost(PnSpace.App);
                }
            }
            else {
                QuicPath path = paths.get(timedOut);
                if (path != null && !path.isSuspect()) {
                    log.info("Path " + timedOut + " suspected broken; retransmitting on other paths");
                    path.setSuspect(true);
                    path.getRecoveryManager().declareAllLost(PnSpace.App);
                }
            }
        }
    }

    void sendIfAny() throws IOException {
        if (!probeTimeouts.isEmpty()) {
            handleProbeTimeouts();
        }
        sendMtuProbeIfDue();
        if (socketManager.maxSegments() > 1) {
            sendBatched();
            return;
        }
        AssembledDatagram assembled;
        do {
            assembled = assemblePacket();
            if (!assembled.isEmpty()) {
                send(assembled);
            }
        }
        while (!assembled.isEmpty());
    }

    /**
     * Sends as many datagrams as possible per socket call: consecutive datagrams of the same size to the same address
     * go out as one segmented send (the last may be shorter).
     */
    private void sendBatched() throws IOException {
        int maxSegments = Integer.min(socketManager.maxSegments(), MAX_BATCH_BYTES / maxPacketSize);
        if (batchBuffer == null || batchBuffer.length < maxSegments * maxPacketSize) {
            batchBuffer = new byte[maxSegments * maxPacketSize];
        }
        ByteBuffer buffer = ByteBuffer.wrap(batchBuffer);
        int segmentSize = 0;
        int segments = 0;
        InetSocketAddress destination = null;
        long batchPathId = 0;
        while (true) {
            AssembledDatagram assembled = assemblePacket();
            if (assembled.isEmpty()) {
                break;
            }
            InetSocketAddress address = assembled.getItems().get(0).getClientAddress();
            if (segments > 0 && (!address.equals(destination) || buffer.remaining() < maxPacketSize)) {
                sendSegmented(buffer.position(), segmentSize, destination, batchPathId);
                buffer.clear();
                segments = 0;
            }
            int start = buffer.position();
            int size = encode(assembled, buffer);
            if (size == 0) {
                continue;
            }
            if (segments > 0 && size > segmentSize) {
                // Only the last segment may be shorter, so the longer datagram starts a new batch.
                sendSegmented(start, segmentSize, destination, batchPathId);
                System.arraycopy(batchBuffer, start, batchBuffer, 0, size);
                buffer.position(size);
                segments = 0;
            }
            if (segments == 0) {
                segmentSize = size;
                destination = address;
                batchPathId = assembled.getItems().get(0).getPacket().getPathId();
            }
            segments++;
            registerSent(assembled.getItems(), clock.instant(), size);
            if (size < segmentSize || segments == maxSegments) {
                sendSegmented(buffer.position(), segmentSize, destination, batchPathId);
                buffer.clear();
                segments = 0;
            }
        }
        if (segments > 0) {
            sendSegmented(buffer.position(), segmentSize, destination, batchPathId);
        }
    }

    /**
     * Sends the start of the batch buffer. A failure on a multipath path other than path 0 (e.g. an unreachable
     * address) only makes that path suspect; its packets are retransmitted elsewhere once declared lost.
     */
    private void sendSegmented(int length, int segmentSize, InetSocketAddress destination, long pathId) throws IOException {
        try {
            socketManager.sendSegmented(batchBuffer, length, segmentSize, destination);
        }
        catch (IOException e) {
            if (pathId == 0) {
                throw e;
            }
            log.warn("Sending on path " + pathId + " to " + destination + " failed: " + e);
            probeTimeout(pathId);
        }
    }

    private void wakeUpSenderLoop() {
        synchronized (condition) {
            signalled = true;
            condition.notify();
        }
    }

    /**
     * Determines the maximum wait (sleep) time before the sender must check again if there is something to send.
     * @return
     */
    long determineMaximumWaitTime() {
        Optional<Instant> nextDelayedSendTime = packetAssembler.nextDelayedSendTime();
        for (QuicPath path : paths.values()) {
            Instant pathTime = path.nextDelayedSendTime();
            if (pathTime != null && (nextDelayedSendTime.isEmpty() || pathTime.isBefore(nextDelayedSendTime.get()))) {
                nextDelayedSendTime = Optional.of(pathTime);
            }
        }
        if (nextDelayedSendTime.isPresent()) {
            long delay = max(Duration.between(clock.instant(), nextDelayedSendTime.get()).toMillis(), 0);
            if (delay > 0) {
                subsequentZeroDelays.set(0);
                lastDelayWasZero = false;
                return delay;
            }
            else {
                if (lastDelayWasZero) {
                    int count = subsequentZeroDelays.incrementAndGet();
                    if (count % 20 == 3) {
                        log.error("possible bug: sender is looping in busy wait; got " + count + " iterations");
                    }
                    if (count > 10003) {
                        return 8000;
                    }
                }
                lastDelayWasZero = true;
                // Next time is already in the past, hurry up!
                return 0;
            }
        }

        // No timeout needed, just wait for next action. In theory, infinity should be returned.
        // However, in order to somewhat forgiving for bugs that would lead to deadlocking the sender, use a
        // value that will keep the connection going, but also indicates there is something wrong.
        return 5000;
    }

    void send(AssembledDatagram assembledDatagram) throws IOException {
        send(assembledDatagram, maxPacketSize);
    }

    private void send(AssembledDatagram assembledDatagram, int bufferSize) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(new byte[bufferSize]);
        int size = encode(assembledDatagram, buffer);
        if (size == 0) {
            return;
        }
        buffer.limit(buffer.position());
        long pathId = assembledDatagram.getItems().get(0).getPacket().getPathId();
        Instant timeSent;
        try {
            timeSent = socketManager.send(buffer, assembledDatagram.getItems().get(0).getClientAddress());
        }
        catch (IOException e) {
            if (pathId == 0) {
                throw e;
            }
            log.warn("Sending on path " + pathId + " failed: " + e);
            probeTimeout(pathId);
            timeSent = clock.instant();
        }
        registerSent(assembledDatagram.getItems(), timeSent, size);
    }

    /**
     * Writes the datagram's packets (and external padding) to the buffer, returning the number of bytes written.
     */
    private int encode(AssembledDatagram assembledDatagram, ByteBuffer buffer) {
        List<SendItem> itemsToSend = assembledDatagram.getItems();
        int start = buffer.position();
        try {
            Iterator<SendItem> packetIterator = itemsToSend.iterator();
            while (packetIterator.hasNext()) {
                QuicPacket packet = packetIterator.next().getPacket();
                try {
                    Aead aead = connectionSecrets.getOwnAead(packet.getEncryptionLevel());
                    if (packet instanceof ShortHeaderPacket && buffer.hasArray()) {
                        int packetStart = buffer.position();
                        ((ShortHeaderPacket) packet).generatePacketBytes(aead, buffer);
                        if (log.logRaw()) {
                            log.raw("packet sent, pn: " + packet.getPacketNumber(), Arrays.copyOfRange(buffer.array(), buffer.arrayOffset() + packetStart, buffer.arrayOffset() + buffer.position()));
                        }
                    }
                    else {
                        byte[] packetData = packet.generatePacketBytes(aead);
                        buffer.put(packetData);
                        if (log.logRaw()) {
                            log.raw("packet sent, pn: " + packet.getPacketNumber(), packetData);
                        }
                    }
                }
                catch (MissingKeysException e) {
                    if (e.getMissingKeysCause() == MissingKeysException.Cause.DiscardedKeys) {
                        log.warn("Packet not sent because keys are discarded: " + packet);
                        packetIterator.remove();
                    }
                    else {
                        throw new IllegalStateException(e.getMessage());
                    }
                }
            }
        }
        catch (BufferOverflowException bufferOverflow) {
            log.error("Buffer overflow while generating datagram for " + itemsToSend);
            // rethrow
            throw bufferOverflow;
        }
        if (buffer.position() == start) {
            return 0;
        }
        addExternalPadding(buffer, assembledDatagram.getMinDatagramSize() - (buffer.position() - start));
        return buffer.position() - start;
    }

    private void registerSent(List<SendItem> itemsToSend, Instant timeSent, int size) {
        datagramsSent++;
        packetsSent += itemsToSend.size();
        bytesSent += size;

        boolean ackEliciting = false;
        long data = 0;
        for (SendItem item : itemsToSend) {
            QuicPacket packet = item.getPacket();
            if (packet.getPathId() != 0) {
                QuicPath path = paths.get(packet.getPathId());
                if (path != null) {
                    path.getRecoveryManager().packetSent(packet, timeSent, item.getPacketLostCallback());
                }
            }
            else {
                recoveryManager.packetSent(packet, timeSent, item.getPacketLostCallback());
            }
            idleTimer.packetSent(packet, timeSent);
            ackEliciting |= packet.isAckEliciting();
            data += countDataBytes(packet);
        }
        if (ackEliciting) {
            lastestAckElicitingTime = timeSent;
        }
        dataSent += data;
        if (log.logPackets() || !(qlog instanceof NullQLog)) {
            List<QuicPacket> packetsSent = itemsToSend.stream().map(item -> item.getPacket()).collect(Collectors.toList());
            log.sent(timeSent, packetsSent);
            qlog.emitPacketSentEvent(packetsSent, timeSent);
        }
    }

    private void addExternalPadding(ByteBuffer buffer, int paddingLength) {
        if (paddingLength > 0) {
            byte[] padding = new byte[paddingLength];
            for (int i = 0; i < paddingLength; i++) {
                padding[i] = paddingPattern[i % paddingPattern.length];
            }
            buffer.put(padding);
        }
    }

    private AssembledDatagram assemblePacket() {
        if (paths.isEmpty()) {
            return assembleInitialPath();
        }
        // Suspect paths come last, then those the peer prefers as backup, then lower RTT first. Stream and other shared
        // frames go only on the first (best) usable path, as iroh does, so a slow path (e.g. the relay) does not hold
        // up delivery; acks and probes of a path always go on it.
        List<QuicPath> candidates = new ArrayList<>(paths.size() + 1);
        if (!initialPathAbandoned) {
            candidates.add(null);
        }
        if (candidates.isEmpty() && paths.isEmpty()) {
            return new AssembledDatagram(Collections.emptyList());
        }
        candidates.addAll(paths.values());
        candidates.sort(Comparator.comparing((QuicPath p) -> p == null? initialPathSuspect: !(p.getState() == QuicPath.State.ACTIVE && !p.isSuspect()))
                .thenComparing((QuicPath p) -> p != null && p.peerPrefersBackup())
                .thenComparingInt(p -> p == null? rttEstimater.getSmoothedRtt(): p.getRttEstimator().getSmoothedRtt()));
        QuicPath best = candidates.get(0);
        sendRequestQueue[EncryptionLevel.App.ordinal()].setSharedEnabled(best == null && !initialPathSuspect && !initialPathAbandoned);
        for (QuicPath path : paths.values()) {
            path.setCarriesData(path == best);
        }
        for (QuicPath path : candidates) {
            if (path == null) {
                AssembledDatagram datagram = assembleInitialPath();
                if (!datagram.isEmpty()) {
                    return datagram;
                }
            }
            else {
                Optional<SendItem> item = path.assemble();
                if (item.isPresent()) {
                    padForPathValidation(item.get());
                    return new AssembledDatagram(new ArrayList<>(List.of(item.get())), 0);
                }
            }
        }
        return new AssembledDatagram(Collections.emptyList());
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.1: datagrams with PATH_CHALLENGE are expanded to 1200
    // bytes, as are those with PATH_RESPONSE (section 8.2.2).
    // A 1-RTT packet extends to the end of its datagram, so the padding goes inside the packet.
    private static void padForPathValidation(SendItem item) {
        QuicPacket packet = item.getPacket();
        for (QuicFrame frame : packet.getFrames()) {
            if (frame instanceof PathChallengeFrame || frame instanceof PathResponseFrame) {
                int padding = 1200 - packet.estimateLength(0);
                if (padding > 0) {
                    padding -= packet.estimateLength(padding) - 1200;
                    packet.addFrame(new Padding(padding));
                }
                return;
            }
        }
    }

    private AssembledDatagram assembleInitialPath() {
        int remainingCwnd = (int) congestionController.remainingCwnd();
        int currentMaxPacketSize = maxPacketSize;
        if (antiAmplificationLimit >= 0) {
            if (bytesSent < antiAmplificationLimit) {
                if (antiAmplificationLimit - bytesSent < currentMaxPacketSize) {
                    // Note that when anti-amplification limit is limiting the packet size, it is quite likely that no
                    // packets will be sent at all, because initial packets have a minimum size of 1200 bytes.
                    log.warn(String.format("Sending data may be limited by remaining anti-amplification limit of %d bytes", antiAmplificationLimit - bytesSent));
                }
                currentMaxPacketSize = Integer.min(currentMaxPacketSize, (int) (antiAmplificationLimit - bytesSent));
            }
            else {
                log.warn("Cannot send; anti-amplification limit is reached");
                return new AssembledDatagram(Collections.emptyList());
            }
        }

        return packetAssembler.assemble(remainingCwnd, currentMaxPacketSize, socketManager.getClientAddress());
    }

    @Override
    public Instant lastAckElicitingSent() {
        return lastestAckElicitingTime;
    }

    private Instant earliest(Instant instant1, Instant instant2) {
        if (instant1 == null) {
            return instant2;
        }
        if (instant2 == null) {
            return instant1;
        }
        if (instant1.isBefore(instant2)) {
            return instant1;
        }
        else {
            return instant2;
        }
    }

    private static long countDataBytes(QuicPacket packet) {
        if (!(packet instanceof ShortHeaderPacket)) {
            return 0;
        }
        long count = 0;
        for (QuicFrame frame : packet.getFrames()) {
            if (frame instanceof StreamFrame) {
                count += ((StreamFrame) frame).getLength();
            }
        }
        return count;
    }

    public SendStatistics getStatistics() {
        return new SendStatistics(datagramsSent, packetsSent, bytesSent, dataSent, recoveryManager.getLost(),
                rttEstimater.getSmoothedRtt(), rttEstimater.getRttVar(), rttEstimater.getLatestRtt());
    }

    /**
     * Sender state, for diagnosing stalls.
     */
    public String debugState() {
        return "cwnd=" + congestionController.getWindowSize() + " inFlight=" + congestionController.getBytesInFlight()
                + " appQueueEmpty=" + sendRequestQueue[EncryptionLevel.App.ordinal()].isEmpty(true)
                + " appIdle=" + sendRequestQueue[EncryptionLevel.App.ordinal()].isIdle()
                + " ackElicitingInFlight=" + recoveryManager.waitingForAcknowledgement()
                + " deferWakeUp=" + deferWakeUp + " ackHeld=" + ackHeld + " paths=" + paths.size()
                + " suspect=" + initialPathSuspect + " maxPacketSize=" + maxPacketSize;
    }

    @Override
    public int getPto() {
        return getPto(rttEstimater);
    }

    int getPto(RttEstimator rtt) {
        return rtt.getSmoothedRtt() + 4 * rtt.getRttVar() + receiverMaxAckDelay;
    }

    public CongestionController getCongestionController() {
        return congestionController;
    }

    public void setReceiverMaxAckDelay(int maxAckDelay) {
        this.receiverMaxAckDelay = maxAckDelay;
        rttEstimater.setMaxAckDelay(maxAckDelay);
        recoveryManager.setReceiverMaxAckDelay(maxAckDelay);
    }

    public GlobalAckGenerator getGlobalAckGenerator() {
        return globalAckGenerator;
    }

    public void setAntiAmplificationLimit(int antiAmplificationLimit) {
        this.antiAmplificationLimit = antiAmplificationLimit;
    }

    public void unsetAntiAmplificationLimit() {
        antiAmplificationLimit = -1;
    }

    public void enableAllLevels() {
        packetAssembler.enableAppLevel();
    }

    public void enableAppLevel() {
        packetAssembler.enableAppLevel();
    }

    public void registerMaxUdpPayloadSize(int maxUdpPayloadSize) {
        mtuDiscovery.setUpperBound(maxUdpPayloadSize);
        if (maxUdpPayloadSize < maxPacketSize) {
            maxPacketSize = maxUdpPayloadSize;
        }
    }

    public void resetRecovery(PnSpace pnSpace) {
        recoveryManager.reset(pnSpace);
    }
}

