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
package tech.kwik.core.impl;

import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.ErrorAlert;
import tech.kwik.agent15.engine.TlsEngine;
import tech.kwik.core.*;
import tech.kwik.core.ack.GlobalAckGenerator;
import tech.kwik.core.cid.ConnectionIdManager;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.concurrent.DaemonThreadFactory;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.crypto.CryptoStream;
import tech.kwik.core.frame.*;
import tech.kwik.core.log.Logger;
import tech.kwik.core.common.PnSpace;
import java.util.Optional;
import tech.kwik.core.cid.ConnectionIdProvider;
import tech.kwik.core.send.QuicPath;
import tech.kwik.core.packet.PacketParser;
import tech.kwik.core.path.NatTraversal;
import tech.kwik.core.path.NatTraversalEvent;
import tech.kwik.core.path.PathManager;
import tech.kwik.core.packet.BasePacketFilter;
import tech.kwik.core.packet.PacketFilter;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.recovery.RecoveryManager;
import tech.kwik.core.send.SenderImpl;
import tech.kwik.core.stream.FlowControl;
import tech.kwik.core.stream.StreamManager;
import tech.kwik.core.util.ProgressivelyIncreasingRateLimiter;
import tech.kwik.core.util.RateLimiter;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.function.Function;

import static tech.kwik.core.ConnectionTerminatedEvent.CloseReason;
import static tech.kwik.core.ConnectionTerminatedEvent.CloseReason.ConnectionLost;
import static tech.kwik.core.QuicConstants.TransportErrorCode.*;
import static tech.kwik.core.common.EncryptionLevel.App;
import static tech.kwik.core.common.EncryptionLevel.Handshake;
import static tech.kwik.core.common.EncryptionLevel.Initial;
import static tech.kwik.core.impl.QuicConnectionImpl.ErrorType.APPLICATION_ERROR;
import static tech.kwik.core.impl.QuicConnectionImpl.ErrorType.QUIC_LAYER_ERROR;
import static tech.kwik.core.send.Sender.NO_RETRANSMIT;
import static tech.kwik.core.util.Bytes.bytesToHex;


public abstract class QuicConnectionImpl implements QuicConnection, PacketProcessor, FrameProcessor, PacketFilter {

    // draft-ietf-quic-multipath: the maximum path IDs each side allows; null when it does not support multipath.
    private volatile Long localMaxPathId;
    private volatile Long peerMaxPathId;
    private volatile PathManager pathManager;
    private volatile Consumer<QuicPath> pathListener;
    private volatile Integer localMaxNatTraversalAddresses;
    private volatile NatTraversal natTraversal;
    private volatile Consumer<NatTraversalEvent> natTraversalListener;
    private ScheduledFuture<?> natTraversalRetry;
    // Receiver thread only.
    private final java.util.Set<Runnable> batchEndActions = new java.util.LinkedHashSet<>();
    private volatile Integer addressDiscoveryRole;
    private volatile Integer peerAddressDiscoveryRole;
    private volatile long nextObservedAddressSequenceNumber;
    private volatile long lastObservedAddressSequenceNumber = -1;
    private volatile InetSocketAddress observedAddress;
    private volatile Consumer<InetSocketAddress> observedAddressListener;

    public enum Status {
        Created,
        Handshaking,
        Connected,
        CloseRequested,
        Closing,
        Draining,
        Closed,
        Failed,
        Error;

        /**
         * Returns true if the connection is closing or closed in the broadest sense,
         * i.e. including (handshake) Failed and Error states.
         * @return
         */
        public boolean closingOrDraining() {
            return this == Closing || this == CloseRequested || this == Draining || this == Closed || this == Failed || this == Error;
        }

        public boolean isClosing() {
            return this == Closing;
        }
    }

    protected enum DatagramExtensionStatus {
        Disabled,
        Enable,
        Enabled,
        EnabledReceiveOnly
    }

    public enum VersionNegotiationStatus {
        NotStarted,
        VersionChangeUnconfirmed,
        VersionNegotiated
    }

    protected enum ErrorType {
        QUIC_LAYER_ERROR,
        APPLICATION_ERROR
    }

    // https://www.rfc-editor.org/rfc/rfc9221.html#section-3
    // "For most uses of DATAGRAM frames, it is RECOMMENDED to send a value of 65535 in the max_datagram_frame_size
    //  transport parameter to indicate that this endpoint will accept any DATAGRAM frame that fits inside a QUIC packet."
    protected static final int MAX_DATAGRAM_FRAME_SIZE_TRANSPORT_PARAMETER_VALUE = 65535;

    protected final VersionHolder quicVersion;
    private final Role role;
    protected final Logger log;
    protected final PacketFilter processorChain;
    protected VersionNegotiationStatus versionNegotiationStatus = VersionNegotiationStatus.NotStarted;

    protected final ConnectionSecrets connectionSecrets;
    protected volatile HandshakeState handshakeState = HandshakeState.Initial;
    protected final Object handshakeStateLock = new Object();
    protected List<HandshakeStateListener> handshakeStateListeners = new CopyOnWriteArrayList<>();
    protected volatile EncryptionLevel currentEncryptionLevel;
    protected IdleTimer idleTimer;
    protected final List<Runnable> postProcessingActions = new ArrayList<>();
    protected final List<CryptoStream> cryptoStreams = new ArrayList<>();
    private FrameReceivedListener<AckFrame> recoveryManager;
    // https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    // "If this value is absent, a default value of 3 is assumed (indicating a multiplier of 8)."
    protected volatile int peerAckDelayExponent = 3;
    protected final boolean useStrictSmallestAllowedMaximumDatagramSize;

    protected volatile FlowControl flowController;

    protected volatile Status connectionState;

    private RateLimiter closeFramesSendRateLimiter;
    private volatile ConnectionCloseFrame lastConnectionCloseFrameSent;
    private final ScheduledExecutorService scheduler;
    private ConnectionListener connectionListener;
    protected final ExecutorService callbackThread;

    // https://datatracker.ietf.org/doc/html/rfc9221  Datagram Extension
    protected volatile DatagramExtensionStatus datagramExtensionStatus = DatagramExtensionStatus.Disabled;
    private volatile int maxDatagramFrameSize;

    // https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-07.html  Stream Resets with Partial Delivery
    protected volatile boolean reliableStreamResetEnabled;
    private volatile boolean peerSupportsReliableStreamReset;
    private volatile Consumer<byte[]> datagramHandler;
    private volatile ExecutorService datagramHandlerExecutor;


    protected QuicConnectionImpl(Version originalVersion, Role role, Path secretsFile, ConnectionConfig settings, String id, Logger log) {
        this.quicVersion = new VersionHolder(originalVersion);
        this.role = role;
        this.log = log;
        useStrictSmallestAllowedMaximumDatagramSize = settings != null? settings.useStrictSmallestAllowedMaximumDatagramSize(): false;

        processorChain = createProcessorChain();

        connectionSecrets = new ConnectionSecrets(quicVersion, role, secretsFile, log);

        connectionState = Status.Created;
        closeFramesSendRateLimiter = new ProgressivelyIncreasingRateLimiter();
        scheduler = createScheduler(id);
        ThreadPoolExecutor callbackThreadPoolExecutor = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(), new DaemonThreadFactory("callbacks-" + id),
                new ThreadPoolExecutor.DiscardPolicy());
        callbackThread = callbackThreadPoolExecutor;
        currentEncryptionLevel = Initial;
    }

    public void addHandshakeStateListener(HandshakeStateListener listener) {
        handshakeStateListeners.add(listener);
    }

    /**
     * Queues a frame for sending.
     * As this method does not flush the sender, it should only be called from a context that ensures the sender is
     * flushed, e.g. from a method that processes a received packet (because this class will flush the sender when
     * all frames in a packet have been processed, by calling Sender.packetProcessed()).
     * @param frame  the frame to send
     * @param lostFrameCallback  function called when packet that contains the frame is lost
     */
    public void send(QuicFrame frame, Consumer<QuicFrame> lostFrameCallback) {
        send(frame, lostFrameCallback, false);
    }

    public void send(QuicFrame frame, Consumer<QuicFrame> lostFrameCallback, boolean flush) {
        getSender().send(frame, App, lostFrameCallback);
        if (flush) {
            getSender().flush();
        }
    }

    public void send(QuicFrame frame, EncryptionLevel level, Consumer<QuicFrame> lostFrameCallback, boolean flush) {
        getSender().send(frame, level, lostFrameCallback);
        if (flush) {
            getSender().flush();
        }
    }

    public void send(Function<Integer, QuicFrame> frameSupplier, int minimumSize, EncryptionLevel level, Consumer<QuicFrame> lostCallback) {
        getSender().send(frameSupplier, minimumSize, level, lostCallback);
    }

    public void send(Function<Integer, QuicFrame> frameSupplier, int minimumSize, EncryptionLevel level, Consumer<QuicFrame> lostCallback, boolean flush) {
        getSender().send(frameSupplier, minimumSize, level, lostCallback);
        if (flush) {
            getSender().flush();
        }
    }

    @Override
    public void sendDatagram(byte[] data) {
        if (canSendDatagram()) {
            if (data.length > maxDatagramDataSize()) {
                throw new IllegalArgumentException("Data too large for a single datagram frame");
            }

            // https://www.rfc-editor.org/rfc/rfc9221.html#section-5
            // "When an application sends a datagram over a QUIC connection, QUIC will generate a new DATAGRAM frame and
            //  send it in the first available packet. This frame SHOULD be sent as soon as possible (...)"
            getSender().sendWithPriority(new DatagramFrame(data), App, f -> {});
        }
        else {
            throw new IllegalStateException("Datagram extension is not enabled" +
                    (datagramExtensionStatus == DatagramExtensionStatus.EnabledReceiveOnly? " for sending.":"."));
        }
    }

    @Override
    public int maxDatagramDataSize() {
        // https://www.rfc-editor.org/rfc/rfc9221.html#section-5
        // "Note that while the max_datagram_frame_size transport parameter places a limit on the maximum size of
        //  DATAGRAM frames, that limit can be further reduced by the max_udp_payload_size transport parameter and the
        //  Maximum Transmission Unit (MTU) of the path between endpoints. DATAGRAM frames cannot be fragmented;
        //  therefore, application protocols need to handle cases where the maximum datagram size is limited by other
        //  factors."
        int maxShortHeaderPacketOverhead = getMaxShortHeaderPacketOverhead();
        int maxEffectiveDatagramFrameSize = Integer.min(maxDatagramFrameSize, getMaxPacketSize() - maxShortHeaderPacketOverhead);
        return maxEffectiveDatagramFrameSize - DatagramFrame.getMaxMinimalFrameSize();
    }

    @Override
    public void setDatagramHandler(Consumer<byte[]> handler) {
        DaemonThreadFactory daemonThreadFactory = new DaemonThreadFactory("datagram-frame-handler");
        setDatagramHandler(handler, Executors.newSingleThreadExecutor(daemonThreadFactory));
    }

    @Override
    public void setDatagramHandler(Consumer<byte[]> handler, ExecutorService callbackExecutor) {
        datagramHandlerExecutor = Objects.requireNonNull(callbackExecutor);
        this.datagramHandler = Objects.requireNonNull(handler);
    }

    @Override
    public QuicStream createStream(boolean bidirectional) throws IOException {
        if (connectionState != Status.Connected) {
            throw new IOException("not connected");
        }

        return getStreamManager().createStream(bidirectional);
    }

    public void datagramProcessed() {
        // Processed all packets in the datagram, so not expecting more.
        getSender().packetProcessed(false);
        if (!batchEndActions.isEmpty() && !getSender().isDeferringWakeUp()) {
            runBatchEndActions();
        }

        // Finally, execute actions that need to be executed after all responses and acks are sent.
        runPostProcessingActions();
    }

    /**
     * Runs the action once the current batch of received datagrams is processed (see Sender.moreDatagramsQueued).
     * Only for the receiver thread.
     * @return false when no batch is being processed, in which case the caller acts itself
     */
    public boolean deferToBatchEnd(Runnable action) {
        if (!getSender().isDeferringWakeUp()) {
            return false;
        }
        batchEndActions.add(action);
        return true;
    }

    /**
     * Ends the current batch of received datagrams, e.g. because the receiver found no more after all.
     */
    public void endReceiveBatch() {
        getSender().endDeferral();
        if (!batchEndActions.isEmpty()) {
            runBatchEndActions();
        }
    }

    private void runBatchEndActions() {
        for (Runnable action : batchEndActions) {
            action.run();
        }
        batchEndActions.clear();
    }

    protected void runPostProcessingActions() {
        postProcessingActions.forEach(action -> action.run());
        postProcessingActions.clear();
    }

    protected boolean checkDestinationConnectionId(QuicPacket packet) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-client-packet-handling
        // "Packets that do not match an existing connection -- based on Destination Connection ID or, if this
        //  value is zero length, local IP address and port -- are discarded."
        byte[] cid = packet.getDestinationConnectionId();
        if (getConnectionIdManager().isActiveCid(cid)) {
            return true;
        }
        else {
            log.error(String.format("Dropping packet because dcid %s is not an active connection ID.", bytesToHex(cid)));
            return false;
        }
    }

    protected void processFrames(QuicPacket packet, PacketMetaData metaData) {
        for (QuicFrame frame: packet.getFrames()) {
            frame.accept(this, packet, metaData);
        }
    }

    /**
     * Returns the length of the connection ID's this endpoint uses (and generates).
     * @return  length of the connection ID
     */
    protected abstract int getSourceConnectionIdLength();

    protected void validateTransportParameters(TransportParameters transportParameters) throws TransportError {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4
        // "An endpoint MUST treat receipt of a transport parameter with an invalid value as a connection error
        //  of type TRANSPORT_PARAMETER_ERROR."

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
        // "Values below 1200 are invalid."
        if (transportParameters.getMaxUdpPayloadSize() < 1200) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
        // "Values above 20 are invalid."
        if (transportParameters.getAckDelayExponent() > 20) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
        // "Values of 2^14 or greater are invalid."
        if (transportParameters.getMaxAckDelay() >= 16384) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
        // "The value of the active_connection_id_limit parameter MUST be at least 2."
        if (transportParameters.getActiveConnectionIdLimit() < 2) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }
    }

    /**
     * Process the transport parameters that are common to client and server.
     * @param peerTransportParams  the transport parameters to process
     */
    /**
     * Enables QUIC Address Discovery: whether to report the peer's observed address to it and/or to accept reports
     * of our own. Must be called before the transport parameters are sent.
     */
    public void enableAddressDiscovery(boolean send, boolean receive) {
        addressDiscoveryRole = send && receive? 2: send? 0: receive? 1: null;
    }

    protected Integer getAddressDiscoveryRole() {
        return addressDiscoveryRole;
    }

    private static boolean sends(Integer role) {
        return role != null && (role == 0 || role == 2);
    }

    private static boolean receives(Integer role) {
        return role != null && (role == 1 || role == 2);
    }

    /**
     * Reports the peer's address as observed by this endpoint, when negotiated. Retransmitted when lost, unless a
     * newer report was sent since.
     */
    protected void reportObservedAddress(InetSocketAddress peerAddress) {
        if (sends(addressDiscoveryRole) && receives(peerAddressDiscoveryRole) && peerAddress != null) {
            long sequenceNumber = nextObservedAddressSequenceNumber++;
            sendObservedAddress(new ObservedAddressFrame(sequenceNumber, peerAddress));
        }
    }

    private void sendObservedAddress(ObservedAddressFrame frame) {
        send(frame, lost -> {
            if (frame.getSequenceNumber() == nextObservedAddressSequenceNumber - 1) {
                sendObservedAddress(frame);
            }
        }, true);
    }

    @Override
    public InetSocketAddress getObservedAddress() {
        return observedAddress;
    }

    @Override
    public void setObservedAddressListener(Consumer<InetSocketAddress> listener) {
        observedAddressListener = listener;
    }

    @Override
    public void process(ObservedAddressFrame observedAddressFrame, QuicPacket packet, PacketMetaData metaData) {
        if (!(receives(addressDiscoveryRole) && sends(peerAddressDiscoveryRole))) {
            immediateCloseWithError(PROTOCOL_VIOLATION.value, "OBSERVED_ADDRESS frame received when not negotiated");
            return;
        }
        // Reports can arrive out of order; only a newer one replaces the current address.
        if (observedAddressFrame.getSequenceNumber() > lastObservedAddressSequenceNumber) {
            lastObservedAddressSequenceNumber = observedAddressFrame.getSequenceNumber();
            observedAddress = observedAddressFrame.getAddress();
            Consumer<InetSocketAddress> listener = observedAddressListener;
            if (listener != null) {
                callbackThread.submit(() -> listener.accept(observedAddressFrame.getAddress()));
            }
        }
    }

    /**
     * Offers the multipath extension (draft-ietf-quic-multipath), allowing the peer path IDs up to the given value.
     */
    public void enableMultipath(long maxPathId) {
        if (maxPathId < 0 || maxPathId > 0xffffffffL) {
            throw new IllegalArgumentException("path id must be in 0..2^32-1");
        }
        localMaxPathId = maxPathId;
    }

    /**
     * The highest path ID the peer may use: initially as offered, and raised as paths are abandoned.
     */
    protected Long getLocalMaxPathId() {
        PathManager manager = pathManager;
        return manager != null? Long.valueOf(manager.getLocalMaxPathId()): localMaxPathId;
    }

    /**
     * Whether both endpoints support the multipath extension (draft-ietf-quic-multipath).
     */
    public boolean isMultipathEnabled() {
        return localMaxPathId != null && peerMaxPathId != null;
    }

    /**
     * The multipath state, or null when multipath was not negotiated.
     */
    public PathManager getPathManager() {
        return pathManager;
    }

    /**
     * Offers iroh's QUIC NAT traversal (needs multipath), accepting up to the given number of the peer's addresses.
     */
    public void enableNatTraversal(int maxRemoteAddresses) {
        if (maxRemoteAddresses < 1 || maxRemoteAddresses > 255) {
            throw new IllegalArgumentException("max remote addresses must be in 1..255");
        }
        localMaxNatTraversalAddresses = maxRemoteAddresses;
    }

    protected Integer getLocalMaxNatTraversalAddresses() {
        return localMaxNatTraversalAddresses;
    }

    /**
     * Whether both endpoints support iroh's QUIC NAT traversal (and multipath).
     */
    public boolean isNatTraversalEnabled() {
        return natTraversal != null;
    }

    private NatTraversal requireNatTraversal() {
        NatTraversal nat = natTraversal;
        if (nat == null) {
            throw new IllegalStateException("NAT traversal not negotiated");
        }
        return nat;
    }

    /**
     * Adds an address at which this endpoint may be reachable. A server advertises it to the client (ADD_ADDRESS); a
     * client sends it with its next round (REACH_OUT).
     */
    public void addNatTraversalAddress(InetSocketAddress address) {
        AddAddressFrame frame = requireNatTraversal().addLocalAddress(address);
        if (frame != null) {
            send(frame, this::retransmitAddAddress, true);
        }
    }

    public void removeNatTraversalAddress(InetSocketAddress address) {
        RemoveAddressFrame frame = requireNatTraversal().removeLocalAddress(address);
        if (frame != null) {
            send(frame, this::retransmit, true);
        }
    }

    public List<InetSocketAddress> getLocalNatTraversalAddresses() {
        return requireNatTraversal().localAddresses();
    }

    /**
     * The addresses the server advertised (client only).
     */
    public List<InetSocketAddress> getRemoteNatTraversalAddresses() {
        return requireNatTraversal().remoteAddresses();
    }

    /**
     * Receives the server's ADD_ADDRESS and REMOVE_ADDRESS (client only).
     */
    public void setNatTraversalListener(Consumer<NatTraversalEvent> listener) {
        natTraversalListener = listener;
    }

    /**
     * Starts a NAT traversal round (client only), cancelling the previous one: sends this endpoint's addresses to the
     * server, which probes them, and probes the server's addresses. A path is opened to each that answers.
     * @return the server addresses being probed
     * @throws NatTraversal.NotEnoughAddressesException when no local address was added
     */
    public List<InetSocketAddress> initiateNatTraversalRound() {
        NatTraversal nat = requireNatTraversal();
        if (!nat.isClient()) {
            throw new IllegalStateException("only the client starts NAT traversal rounds");
        }
        if (connectionState != Status.Connected) {
            throw new IllegalStateException("connection not open");
        }
        NatTraversal.Round round = nat.initiateRound();
        round.reachOuts().forEach(frame -> send(frame, this::retransmitReachOut));
        sendProbes(nat);
        scheduleProbeRetry(nat);
        getSender().flush();
        return round.probed();
    }

    private void retransmit(QuicFrame frame) {
        send(frame, this::retransmit);
    }

    private void retransmitAddAddress(QuicFrame frame) {
        NatTraversal nat = natTraversal;
        if (nat != null && nat.isAdvertised((AddAddressFrame) frame)) {
            send(frame, this::retransmitAddAddress, true);
        }
    }

    private void retransmitReachOut(QuicFrame frame) {
        NatTraversal nat = natTraversal;
        if (nat != null && ((ReachOutFrame) frame).getRound() == nat.currentRound()) {
            send(frame, this::retransmitReachOut, true);
        }
    }

    @Override
    public void process(AddAddressFrame addAddressFrame, QuicPacket packet, PacketMetaData metaData) {
        NatTraversal nat = natTraversal;
        if (nat == null || !nat.isClient()) {
            immediateCloseWithError(PROTOCOL_VIOLATION.value, "unexpected ADD_ADDRESS");
            return;
        }
        try {
            InetSocketAddress added = nat.addRemoteAddress(addAddressFrame);
            if (added != null) {
                natTraversalEvent(new NatTraversalEvent(NatTraversalEvent.Type.ADDED, added));
            }
        }
        catch (NatTraversal.TooManyAddressesException e) {
            log.warn("Ignoring " + addAddressFrame + ": too many addresses");
        }
    }

    @Override
    public void process(RemoveAddressFrame removeAddressFrame, QuicPacket packet, PacketMetaData metaData) {
        NatTraversal nat = natTraversal;
        if (nat == null || !nat.isClient()) {
            immediateCloseWithError(PROTOCOL_VIOLATION.value, "unexpected REMOVE_ADDRESS");
            return;
        }
        InetSocketAddress removed = nat.removeRemoteAddress(removeAddressFrame);
        if (removed != null) {
            natTraversalEvent(new NatTraversalEvent(NatTraversalEvent.Type.REMOVED, removed));
        }
    }

    @Override
    public void process(ReachOutFrame reachOutFrame, QuicPacket packet, PacketMetaData metaData) {
        NatTraversal nat = natTraversal;
        if (nat == null || nat.isClient()) {
            immediateCloseWithError(PROTOCOL_VIOLATION.value, "unexpected REACH_OUT");
            return;
        }
        boolean newRound;
        try {
            newRound = nat.handleReachOut(reachOutFrame);
        }
        catch (NatTraversal.TooManyAddressesException e) {
            immediateCloseWithError(PROTOCOL_VIOLATION.value, "too many REACH_OUT addresses");
            return;
        }
        sendProbes(nat);
        if (newRound) {
            scheduleProbeRetry(nat);
        }
    }

    private void natTraversalEvent(NatTraversalEvent event) {
        Consumer<NatTraversalEvent> listener = natTraversalListener;
        if (listener != null) {
            callbackThread.submit(() -> listener.accept(event));
        }
    }

    // noq's default initial RTT, from which the probe retry backoff starts.
    private static final long NAT_TRAVERSAL_INITIAL_RTT_MILLIS = 333;

    private synchronized void scheduleProbeRetry(NatTraversal nat) {
        if (natTraversalRetry != null) {
            natTraversalRetry.cancel(false);
            natTraversalRetry = null;
        }
        long delay = nat.retryDelayMillis(NAT_TRAVERSAL_INITIAL_RTT_MILLIS);
        if (delay < 0 || connectionState.closingOrDraining()) {
            return;
        }
        try {
            natTraversalRetry = scheduler.schedule(() -> {
                nat.queueRetries();
                sendProbes(nat);
                getSender().flush();
                scheduleProbeRetry(nat);
            }, delay, TimeUnit.MILLISECONDS);
        }
        catch (RejectedExecutionException closed) {
        }
    }

    /**
     * Sends a PATH_CHALLENGE to each address due a probe, off-path: on a validated path, but to that address.
     */
    private void sendProbes(NatTraversal nat) {
        for (InetSocketAddress address : nat.takePendingProbes()) {
            byte[] data = QuicPath.randomChallengeData();
            if (sendOffPath(-1, List.of(new PathChallengeFrame(quicVersion.getVersion(), data)), address)) {
                nat.probeSent(address, challengeValue(data));
            }
        }
    }

    /**
     * Answers a PATH_CHALLENGE that came from another address than its path's: back to that address, on the same
     * path, without migrating. A client adds its own challenge, so the server's probe also validates the address for
     * the client (which then opens a path to it).
     */
    private void respondOffPath(NatTraversal nat, PathResponseFrame response, long pathId, InetSocketAddress source) {
        List<QuicFrame> frames = new ArrayList<>(List.of(response));
        long challenge = 0;
        boolean challenging = nat.isClient() && !hasValidatedPathTo(source);
        if (challenging) {
            byte[] data = QuicPath.randomChallengeData();
            frames.add(new PathChallengeFrame(quicVersion.getVersion(), data));
            challenge = challengeValue(data);
        }
        if (sendOffPath(pathId, frames, source) && challenging) {
            nat.probeSent(source, challenge);
        }
    }

    /**
     * Whether the PATH_RESPONSE answers a NAT traversal probe; a client then opens a path to its source address.
     */
    protected boolean natTraversalResponse(PathResponseFrame frame, PacketMetaData metaData) {
        NatTraversal nat = natTraversal;
        if (nat == null || !nat.handlePathResponse(metaData.sourceAddress(), challengeValue(frame.getData()))) {
            return false;
        }
        log.info("NAT traversal probe to " + metaData.sourceAddress() + " answered");
        openNatTraversedPaths();
        return true;
    }

    private void openNatTraversedPaths() {
        NatTraversal nat = natTraversal;
        if (nat == null || !nat.isClient()) {
            return;
        }
        InetSocketAddress address;
        while ((address = nat.pollPathToOpen()) != null) {
            if (hasPathTo(address)) {
                continue;
            }
            Optional<QuicPath> path = openPath(address);
            if (path.isEmpty()) {
                // No path ID or connection IDs yet: retried on MAX_PATH_ID or PATH_NEW_CONNECTION_ID.
                nat.pushPathToOpen(address);
                return;
            }
            log.info("Opened path " + path.get().getId() + " to NAT traversed address " + address);
        }
    }

    /**
     * Sends the frames in a packet of their own to the given address, with the packet numbers and connection ID of
     * the given path, or of any validated path when -1, outside loss recovery and congestion control.
     */
    private boolean sendOffPath(long pathId, List<QuicFrame> frames, InetSocketAddress destination) {
        if (pathId == 0 || (pathId < 0 && !getSender().isInitialPathAbandoned())) {
            getSender().sendOffPath(frames, destination);
            return true;
        }
        QuicPath path = pathId > 0? getSender().getPath(pathId): getSender().getPaths().stream()
                .filter(p -> p.getState() == QuicPath.State.ACTIVE)
                .findFirst().orElse(null);
        if (path == null || path.getState() == QuicPath.State.ABANDONED) {
            return false;
        }
        path.sendOffPath(frames, destination);
        getSender().flush();
        return true;
    }

    private boolean isOnPath(long pathId, InetSocketAddress source) {
        InetSocketAddress pathAddress = pathId == 0? initialPathPeerAddress(): Optional.ofNullable(getSender().getPath(pathId)).map(QuicPath::getPeerAddress).orElse(null);
        return pathAddress == null || NatTraversal.canonical(pathAddress).equals(NatTraversal.canonical(source));
    }

    /**
     * Whether the initial path, if not abandoned, or a validated multipath path goes to a peer address that matches.
     */
    public boolean hasActivePath(java.util.function.Predicate<InetSocketAddress> peerAddress) {
        if (!getSender().isInitialPathAbandoned() && peerAddress.test(initialPathPeerAddress())) {
            return true;
        }
        return getSender().getPaths().stream()
                .anyMatch(p -> p.getState() == QuicPath.State.ACTIVE && peerAddress.test(p.getPeerAddress()));
    }

    private boolean hasValidatedPathTo(InetSocketAddress address) {
        InetSocketAddress canonical = NatTraversal.canonical(address);
        if (!getSender().isInitialPathAbandoned() && NatTraversal.canonical(initialPathPeerAddress()).equals(canonical)) {
            return true;
        }
        return getSender().getPaths().stream()
                .anyMatch(p -> p.getState() == QuicPath.State.ACTIVE && NatTraversal.canonical(p.getPeerAddress()).equals(canonical));
    }

    private boolean hasPathTo(InetSocketAddress address) {
        InetSocketAddress canonical = NatTraversal.canonical(address);
        if (!getSender().isInitialPathAbandoned() && NatTraversal.canonical(initialPathPeerAddress()).equals(canonical)) {
            return true;
        }
        return getSender().getPaths().stream()
                .anyMatch(p -> p.getState() != QuicPath.State.ABANDONED && NatTraversal.canonical(p.getPeerAddress()).equals(canonical));
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.1: only these frames make a packet a probing packet.
    private static boolean isProbing(QuicPacket packet) {
        for (QuicFrame frame : packet.getFrames()) {
            if (!(frame instanceof Padding || frame instanceof PathChallengeFrame || frame instanceof PathResponseFrame
                    || frame instanceof NewConnectionIdFrame || frame instanceof ObservedAddressFrame)) {
                return false;
            }
        }
        return true;
    }

    private static long challengeValue(byte[] data) {
        return java.nio.ByteBuffer.wrap(data).getLong();
    }

    /**
     * The peer's address on the initial path (path 0).
     */
    protected abstract InetSocketAddress initialPathPeerAddress();

    /**
     * Opens a new multipath path to the given peer address, on the lowest path ID for which both sides issued
     * connection IDs. The path carries data once validated (see {@link #setPathListener}).
     * @return the new path, or empty when there is no usable path ID
     */
    public synchronized Optional<QuicPath> openPath(InetSocketAddress peerAddress) {
        PathManager manager = pathManager;
        if (manager == null) {
            return Optional.empty();
        }
        for (long pathId = 1; pathId <= Long.min(getLocalMaxPathId(), peerMaxPathId); pathId++) {
            if (getSender().getPath(pathId) == null && !manager.isAbandoned(pathId) && manager.hasConnectionIds(pathId)) {
                QuicPath path = getSender().addPath(pathId, peerAddress, pathConnectionIds(pathId), QuicPath.State.VALIDATING);
                challenge(path);
                abandonUnlessValidated(path);
                return Optional.of(path);
            }
        }
        return Optional.empty();
    }

    /**
     * Abandons a multipath path other than path 0: tells the peer with PATH_ABANDON and stops using the path; what
     * was in flight on it is retransmitted on other paths.
     */
    public void abandonPath(long pathId, long errorCode) {
        PathManager manager = pathManager;
        if (manager == null || manager.isAbandoned(pathId)) {
            return;
        }
        if (pathId == 0) {
            if (getSender().hasOtherPath(0)) {
                abandonInitialPath();
            }
            return;
        }
        // Local connection IDs stay registered for three PTOs, so late packets on the path are not answered with
        // stateless resets (section 3.4.2).
        manager.abandon(pathId, scheduler, 3L * getSender().getPto());
        send(new PathAbandonFrame(pathId, errorCode), this::retransmitPathAbandon);
        getSender().removePath(pathId);
        getSender().flush();
        if (getSender().isInitialPathAbandoned() && getSender().getPaths().isEmpty()) {
            immediateCloseWithError(NO_ERROR.value, "all paths abandoned");
        }
    }

    /**
     * Abandons the initial path while other paths remain: PATH_ABANDON (once) and no more packets on path 0.
     */
    private synchronized void abandonInitialPath() {
        if (getSender().isInitialPathAbandoned()) {
            return;
        }
        pathManager.abandon(0, null, 0);
        getSender().abandonInitialPath();
        send(new PathAbandonFrame(0, NO_ERROR.value), this::retransmitPathAbandon);
        getSender().flush();
        log.info("Initial path abandoned; continuing on the other paths");
    }

    private void retransmitPathAbandon(QuicFrame frame) {
        send(frame, this::retransmitPathAbandon);
    }

    public String debugState() {
        return getSender().debugState() + " flowControl=" + getStreamManager().debugState();
    }

    /**
     * The multipath paths other than path 0.
     */
    public java.util.Collection<QuicPath> getPaths() {
        return getSender().getPaths();
    }

    /**
     * Receives a notification whenever a multipath path becomes active.
     */
    public void setPathListener(Consumer<QuicPath> listener) {
        pathListener = listener;
    }

    private void pathEvent(QuicPath path) {
        Consumer<QuicPath> listener = pathListener;
        if (listener != null) {
            callbackThread.submit(() -> listener.accept(path));
        }
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.4: "A value of three times the larger of the current
    // PTO or the PTO for the new path (using kInitialRtt, as defined in [QUIC-RECOVERY]) is RECOMMENDED."
    private void abandonUnlessValidated(QuicPath path) {
        long timeout = 3L * Long.max(getSender().getPto(), 2 * 333);
        scheduler.schedule(() -> {
            if (path.getState() == QuicPath.State.VALIDATING) {
                log.info("Path " + path.getId() + " to " + path.getPeerAddress() + " not validated; abandoning it");
                abandonPath(path.getId(), NO_ERROR.value);
            }
        }, timeout, TimeUnit.MILLISECONDS);
    }

    private void challenge(QuicPath path) {
        byte[] data = path.newChallenge();
        path.sendOnPath(new PathChallengeFrame(quicVersion.getVersion(), data), lost -> {
            if (path.getState() == QuicPath.State.VALIDATING && path.isCurrentChallenge(data)) {
                challenge(path);
            }
        });
        getSender().flush();
    }

    /**
     * The path of a received packet for a path ID other than 0. A path the peer opened is added, and validated by
     * this endpoint (https://www.ietf.org/archive/id/draft-ietf-quic-multipath-21.html#section-3.1).
     */
    private QuicPath receivedOnPath(QuicPacket packet, PacketMetaData metaData) {
        QuicPath path = getSender().getPath(packet.getPathId());
        if (path == null) {
            PathManager manager = pathManager;
            if (manager == null || manager.isAbandoned(packet.getPathId())) {
                return null;
            }
            path = getSender().addPath(packet.getPathId(), metaData.sourceAddress(), pathConnectionIds(packet.getPathId()), QuicPath.State.VALIDATING);
            log.info("Peer opened path " + path.getId() + " from " + metaData.sourceAddress());
            challenge(path);
            abandonUnlessValidated(path);
        }
        else if (!metaData.sourceAddress().equals(path.getPeerAddress()) && !(natTraversal != null && isProbing(packet))) {
            // https://www.ietf.org/archive/id/draft-ietf-quic-multipath-21.html#section-3.1.2: migration of that path.
            // With NAT traversal, probing packets from other addresses are off-path probes and do not migrate.
            path.setPeerAddress(metaData.sourceAddress());
            if (path.getState() != QuicPath.State.ABANDONED) {
                path.setState(QuicPath.State.VALIDATING);
                challenge(path);
            }
        }
        return path;
    }

    private ConnectionIdProvider pathConnectionIds(long pathId) {
        return new ConnectionIdProvider() {
            @Override
            public byte[] getInitialConnectionId() {
                return getConnectionIdManager().getInitialConnectionId();
            }

            @Override
            public byte[] getPeerConnectionId(InetSocketAddress clientAddress) {
                return pathManager.peerConnectionId(pathId);
            }

            @Override
            public void registerClientAddress(InetSocketAddress clientAddress) {
            }

            @Override
            public boolean unusedPeerConnectionIdAvailable() {
                return false;
            }

            @Override
            public boolean peerUsesZeroLengthConnectionId() {
                return false;
            }

            @Override
            public void addressNoLongerInUse(InetSocketAddress previousAddress) {
            }
        };
    }

    /**
     * Resolves the paths of received 1-RTT packets once multipath is negotiated.
     */
    protected PacketParser.PathResolver pathResolver() {
        return (data, offset, length) -> {
            PathManager manager = pathManager;
            return manager != null? manager.resolve(data, offset, length): 0;
        };
    }

    /**
     * Checks the path ID of a received multipath frame; returns whether the frame applies to the initial path (path
     * ID 0), which is the only one used so far. Other path IDs are ignored, or close the connection when invalid.
     */
    protected boolean forInitialPath(long pathId) {
        if (pathId < 0) {
            return true;
        }
        if (!isMultipathEnabled()) {
            immediateCloseWithError(PROTOCOL_VIOLATION.value, "multipath frame received without multipath negotiated");
            return false;
        }
        if (pathId > getLocalMaxPathId()) {
            immediateCloseWithError(PROTOCOL_VIOLATION.value, "path id " + pathId + " exceeds maximum path id " + getLocalMaxPathId());
            return false;
        }
        return pathId == 0;
    }

    @Override
    public void process(PathAbandonFrame pathAbandonFrame, QuicPacket packet, PacketMetaData metaData) {
        long pathId = pathAbandonFrame.getPathId();
        if (pathId > 0 && isMultipathEnabled() && pathId <= getLocalMaxPathId()) {
            // https://www.ietf.org/archive/id/draft-ietf-quic-multipath-21.html#section-3.4
            // "When an endpoint receives a PATH_ABANDON frame, it MUST send a corresponding PATH_ABANDON frame, if it
            //  has not already done so"
            abandonPath(pathId, NO_ERROR.value);
            return;
        }
        if (forInitialPath(pathId)) {
            if (isMultipathEnabled() && getSender().hasOtherPath(0)) {
                abandonInitialPath();
            }
            else {
                // https://www.ietf.org/archive/id/draft-ietf-quic-multipath-21.html#section-3.4
                // "If a PATH_ABANDON frame is received for the only open path of a QUIC connection, the receiving peer
                //  SHOULD send a CONNECTION_CLOSE frame and enter the closing state."
                immediateCloseWithError(NO_ERROR.value, "peer abandoned the only path");
            }
        }
    }

    @Override
    public void process(PathStatusFrame pathStatusFrame, QuicPacket packet, PacketMetaData metaData) {
        forInitialPath(pathStatusFrame.getPathId());
    }

    @Override
    public void process(MaxPathIdFrame maxPathIdFrame, QuicPacket packet, PacketMetaData metaData) {
        if (!isMultipathEnabled()) {
            immediateCloseWithError(PROTOCOL_VIOLATION.value, "multipath frame received without multipath negotiated");
            return;
        }
        if (maxPathIdFrame.getMaxPathId() > 0xffffffffL) {
            immediateCloseWithError(PROTOCOL_VIOLATION.value, "invalid maximum path id");
            return;
        }
        if (maxPathIdFrame.getMaxPathId() > peerMaxPathId) {
            peerMaxPathId = maxPathIdFrame.getMaxPathId();
            pathManager.peerMaxPathIdIncreased(maxPathIdFrame.getMaxPathId());
            openNatTraversedPaths();
        }
    }

    @Override
    public void process(PathsBlockedFrame pathsBlockedFrame, QuicPacket packet, PacketMetaData metaData) {
        if (!isMultipathEnabled() || pathsBlockedFrame.getMaxPathId() > getLocalMaxPathId()) {
            immediateCloseWithError(PROTOCOL_VIOLATION.value, "invalid PATHS_BLOCKED frame");
        }
    }

    @Override
    public void process(PathCidsBlockedFrame pathCidsBlockedFrame, QuicPacket packet, PacketMetaData metaData) {
        forInitialPath(pathCidsBlockedFrame.getPathId());
    }

    protected void processCommonTransportParameters(TransportParameters peerTransportParams) {
        peerAddressDiscoveryRole = peerTransportParams.getAddressDiscoveryRole();
        peerMaxPathId = peerTransportParams.getInitialMaxPathId();
        Integer peerMaxNatTraversalAddresses = peerTransportParams.getMaxRemoteNatTraversalAddresses();
        if (localMaxNatTraversalAddresses != null && peerMaxNatTraversalAddresses != null && isMultipathEnabled()) {
            natTraversal = new NatTraversal(role == Role.Client, localMaxNatTraversalAddresses, peerMaxNatTraversalAddresses);
        }
        if (isMultipathEnabled()) {
            PathManager manager = new PathManager(localMaxPathId, peerMaxPathId, getConnectionIdManager(), getSender(),
                    (error, reason) -> immediateCloseWithError(error, reason));
            pathManager = manager;
            addHandshakeStateListener(state -> {
                if (state == HandshakeState.Confirmed) {
                    manager.startIssuingConnectionIds();
                }
            });
        }
        getStreamManager().setInitialMaxStreamsBidi(peerTransportParams.getInitialMaxStreamsBidi());
        getStreamManager().setInitialMaxStreamsUni(peerTransportParams.getInitialMaxStreamsUni());

        peerAckDelayExponent = peerTransportParams.getAckDelayExponent();
        getSender().setReceiverMaxAckDelay(peerTransportParams.getMaxAckDelay());

        getSender().registerMaxUdpPayloadSize(peerTransportParams.getMaxUdpPayloadSize());

        updateDatagramExtensionStatus(peerTransportParams);

        // https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-07.html#section-3
        // "Support for receiving RESET_STREAM_AT frames is advertised by sending the reset_stream_at (...) transport parameter"
        peerSupportsReliableStreamReset = peerTransportParams.isResetStreamAtSupported();
    }

    private void updateDatagramExtensionStatus(TransportParameters peerTransportParams) {
        // https://www.rfc-editor.org/rfc/rfc9221.html#section-3
        // "The max_datagram_frame_size transport parameter is a unidirectional limit and indication of support of
        //  DATAGRAM frames. Application protocols that use DATAGRAM frames MAY choose to only negotiate and use them
        //  in a single direction."
        if (peerTransportParams.getMaxDatagramFrameSize() > 0) {
            if (datagramExtensionStatus == DatagramExtensionStatus.Enable) {
                datagramExtensionStatus = DatagramExtensionStatus.Enabled;
                maxDatagramFrameSize = (int) Long.min(65535, peerTransportParams.getMaxDatagramFrameSize());  // Value larger than 65535 is useless
            }
        }
        else if (datagramExtensionStatus == DatagramExtensionStatus.Enable) {
            datagramExtensionStatus = DatagramExtensionStatus.EnabledReceiveOnly;
        }
    }

    @Override
    public boolean canSendDatagram() {
        return datagramExtensionStatus == DatagramExtensionStatus.Enabled;
    }

    @Override
    public boolean canReceiveDatagram() {
        return datagramExtensionStatus == DatagramExtensionStatus.Enabled || datagramExtensionStatus == DatagramExtensionStatus.EnabledReceiveOnly;
    }

    @Override
    public boolean isDatagramExtensionEnabled() {
        return datagramExtensionStatus == DatagramExtensionStatus.Enabled;
    }

    /**
     * Returns the value of the max_datagram_frame_size transport parameter.
     * Note that this value does not indicate the real maximum size of a datagram frame.
     * @return
     */
    protected int getMaxDatagramFrameSize() {
        return maxDatagramFrameSize;
    }

    @Override
    public void processPacket(QuicPacket packet, PacketMetaData metaData) {
        QuicPath path = null;
        if (packet.getPathId() != 0) {
            path = receivedOnPath(packet, metaData);
            if (path == null) {
                return;
            }
        }
        ProcessResult result = packet.accept(this, metaData);
        if (result == ProcessResult.Abort) {
            return;
        }
        if (path != null) {
            path.getAckGenerator().packetReceived(packet);
            idleTimer.packetProcessed();
            return;
        }

        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-13.1
        // "A packet MUST NOT be acknowledged until packet protection has been successfully removed and all frames
        //  contained in the packet have been processed."
        // "Once the packet has been fully processed, a receiver acknowledges receipt by sending one or more ACK
        //  frames containing the packet number of the received packet."
        getAckGenerator().packetReceived(packet);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
        // "An endpoint restarts its idle timer when a packet from its peer is received and processed successfully."
        idleTimer.packetProcessed();
    }

    @Override
    public void process(AckFrame ackFrame, QuicPacket packet, PacketMetaData metaData) {
        if (!forInitialPath(ackFrame.getPathId())) {
            QuicPath path = isMultipathEnabled()? getSender().getPath(ackFrame.getPathId()): null;
            if (path != null) {
                ackFrame.setDelayExponent(peerAckDelayExponent);
                getSender().pathAcknowledged(path.getId());
                path.getAckGenerator().process(ackFrame);
                path.getRecoveryManager().received(ackFrame, PnSpace.App, metaData.timeReceived());
            }
            return;
        }
        ackFrame.setDelayExponent(peerAckDelayExponent);
        if (packet.getPnSpace() == PnSpace.App) {
            getSender().pathAcknowledged(0);
        }
        getAckGenerator().received(ackFrame, packet.getPnSpace(), metaData.timeReceived());
        recoveryManager.received(ackFrame, packet.getPnSpace(), metaData.timeReceived());
    }

    @Override
    public void process(CryptoFrame cryptoFrame, QuicPacket packet, PacketMetaData metaData) {
        try {
            getCryptoStream(packet.getEncryptionLevel()).add(cryptoFrame);
            postProcessCrypto(cryptoFrame, packet, metaData.timeReceived());
            log.receivedPacketInfo(getCryptoStream(packet.getEncryptionLevel()).toStringReceived());
        }
        catch (TlsProtocolException e) {
            cryptoProcessingErrorOcurred(e);
            immediateCloseWithError(quicError(e), e.getMessage());
        }
        catch (TransportError e) {
            cryptoProcessingErrorOcurred(e);
            immediateCloseWithError(e.getTransportErrorCode().value, "");
        }
    }

    protected void postProcessCrypto(CryptoFrame cryptoFrame, QuicPacket packet, Instant timeReceived) throws TlsProtocolException {}

    protected abstract void cryptoProcessingErrorOcurred(Exception exception);

    @Override
    public void process(ConnectionCloseFrame connectionCloseFrame, QuicPacket packet, PacketMetaData metaData) {
        handlePeerClosing(connectionCloseFrame, packet.getEncryptionLevel());
    }

    @Override
    public void process(DataBlockedFrame dataBlockedFrame, QuicPacket packet, PacketMetaData metaData) {
        log.warn("Received " + dataBlockedFrame);
    }

    @Override
    public void process(DatagramFrame datagramFrame, QuicPacket packet, PacketMetaData metaData) {
        // https://www.rfc-editor.org/rfc/rfc9221.html#section-3
        // "An endpoint that receives a DATAGRAM frame when it has not indicated support via the transport parameter
        //  MUST terminate the connection with an error of type PROTOCOL_VIOLATION."
        if (!canReceiveDatagram()) {
            immediateCloseWithError(PROTOCOL_VIOLATION.value, "Datagram frame received, but datagram extension is not enabled");
            return;
        }
        if (datagramHandler != null) {
            datagramHandlerExecutor.submit(() -> datagramHandler.accept(datagramFrame.getData()));
        }
        else {
            log.warn("Received datagram frame, but no handler is set");
        }
    }

    @Override
    public void process(MaxDataFrame maxDataFrame, QuicPacket packet, PacketMetaData metaData) {
        flowController.process(maxDataFrame);
    }

    @Override
    public void process(MaxStreamDataFrame maxStreamDataFrame, QuicPacket packet, PacketMetaData metaData) {
        try {
            flowController.process(maxStreamDataFrame);
        } catch (TransportError transportError) {
            immediateCloseWithError(transportError.getTransportErrorCode().value, null);
        }
    }
    @Override
    public void process(MaxStreamsFrame maxStreamsFrame, QuicPacket packet, PacketMetaData metaData) {
        getStreamManager().process(maxStreamsFrame);
    }

    @Override
    public void process(NewConnectionIdFrame newConnectionIdFrame, QuicPacket packet, PacketMetaData metaData) {
        if (!forInitialPath(newConnectionIdFrame.getPathId())) {
            if (isMultipathEnabled() && newConnectionIdFrame.getPathId() > 0 && newConnectionIdFrame.getPathId() <= getLocalMaxPathId()) {
                pathManager.process(newConnectionIdFrame);
                openNatTraversedPaths();
            }
            return;
        }
        getConnectionIdManager().process(newConnectionIdFrame);
    }

    @Override
    public void process(Padding paddingFrame, QuicPacket packet, PacketMetaData metaData) {
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-path_challenge-frames
    // "The recipient of this frame MUST generate a PATH_RESPONSE frame (...) containing the same Data value."
    @Override
    public void process(PathChallengeFrame pathChallengeFrame, QuicPacket packet, PacketMetaData metaData) {
        PathResponseFrame response = new PathResponseFrame(quicVersion.getVersion(), pathChallengeFrame.getData());
        NatTraversal nat = natTraversal;
        if (nat != null && !isOnPath(packet.getPathId(), metaData.sourceAddress())) {
            respondOffPath(nat, response, packet.getPathId(), metaData.sourceAddress());
            return;
        }
        if (packet.getPathId() != 0) {
            // https://www.ietf.org/archive/id/draft-ietf-quic-multipath-21.html#section-3.1
            // "If an endpoint sends a PATH_RESPONSE (...), it MUST be sent on the same path as used by the packet that
            //  contained the PATH_CHALLENGE frame"
            QuicPath path = getSender().getPath(packet.getPathId());
            if (path != null) {
                path.sendOnPath(response, f -> {});
                getSender().flush();
            }
            return;
        }
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-retransmission-of-informati
        // "Responses to path validation using PATH_RESPONSE frames are sent just once."
        send(response, f -> {});
    }

    @Override
    public void process(PathResponseFrame pathResponseFrame, QuicPacket packet, PacketMetaData metaData) {
        if (natTraversalResponse(pathResponseFrame, metaData)) {
            return;
        }
        QuicPath path = getSender().getPath(packet.getPathId());
        if (path != null && path.getState() == QuicPath.State.VALIDATING && path.challengeAnswered(pathResponseFrame.getData())) {
            path.setState(QuicPath.State.ACTIVE);
            log.info("Path " + path.getId() + " to " + path.getPeerAddress() + " validated");
            pathEvent(path);
            getSender().flush();
        }
    }

    @Override
    public void process(PingFrame pingFrame, QuicPacket packet, PacketMetaData metaData) {
        // Intentionally left empty (nothing to do on receiving ping: will be acknowledged like any other ack-eliciting frame)
    }

    @Override
    public void process(ResetStreamFrame resetStreamFrame, QuicPacket packet, PacketMetaData metaData) {
        try {
            getStreamManager().process(resetStreamFrame);
        }
        catch (TransportError transportError) {
            immediateCloseWithError(transportError.getTransportErrorCode().value, null);
        }
    }

    @Override
    public void process(ResetStreamAtFrame resetStreamAtFrame, QuicPacket packet, PacketMetaData metaData) {
        if (!reliableStreamResetEnabled) {
            immediateCloseWithError(PROTOCOL_VIOLATION.value, "RESET_STREAM_AT frame received, but reliable stream reset extension is not enabled");
            return;
        }
        try {
            getStreamManager().process(resetStreamAtFrame);
        }
        catch (TransportError transportError) {
            immediateCloseWithError(transportError.getTransportErrorCode().value, null);
        }
    }

    @Override
    public void process(StopSendingFrame stopSendingFrame, QuicPacket packet, PacketMetaData metaData) {
        getStreamManager().process(stopSendingFrame);
    }

    @Override
    public void process(StreamFrame streamFrame, QuicPacket packet, PacketMetaData metaData) {
        try {
            getStreamManager().process(streamFrame);
        }
        catch (TransportError transportError) {
            immediateCloseWithError(transportError.getTransportErrorCode().value, null);
        }
    }

    @Override
    public void process(StreamDataBlockedFrame streamDataBlockedFrame, QuicPacket packet, PacketMetaData metaData) {
        log.warn("Received " + streamDataBlockedFrame);
    }

    @Override
    public void process(StreamsBlockedFrame streamsBlockedFrame, QuicPacket packet, PacketMetaData metaData) {
        log.warn("Received " + streamsBlockedFrame);
    }

    protected CryptoStream getCryptoStream(EncryptionLevel encryptionLevel) {
        // Ensure the list is long enough to set the crypto stream at the correct index.
        while (cryptoStreams.size() <= encryptionLevel.ordinal()) {
            cryptoStreams.add(null);
        }
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.6
        // "There is a separate flow of cryptographic handshake data in each encryption level"
        if (cryptoStreams.get(encryptionLevel.ordinal()) == null) {
            cryptoStreams.set(encryptionLevel.ordinal(), new CryptoStream(quicVersion, encryptionLevel, role, getTlsEngine(), log, getSender()));
        }
        return cryptoStreams.get(encryptionLevel.ordinal());
    }

    protected void determineIdleTimeout(long maxIdleTimout, long peerMaxIdleTimeout) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
        // "If a max_idle_timeout is specified by either peer in its transport parameters (Section 18.2), the
        //  connection is silently closed and its state is discarded when it remains idle for longer than the minimum
        //  of both peers max_idle_timeout values."
        long idleTimeout = Long.min(maxIdleTimout, peerMaxIdleTimeout);
        if (idleTimeout == 0) {
            // Value of 0 is the same as not specified.
            idleTimeout = Long.max(maxIdleTimout, peerMaxIdleTimeout);
        }
        if (idleTimeout != 0) {
            log.debug("Effective idle timeout is " + idleTimeout);
            // Initialise the idle timer that will take care of (silently) closing connection if idle longer than idle timeout
            idleTimer.setIdleTimeout(idleTimeout);
        }
        else {
            // Both or 0 or not set:
            // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-18.2
            // "Idle timeout is disabled when both endpoints omit this transport parameter or specify a value of 0."
        }
    }

    protected void silentlyCloseConnection(long idleTime) {
        if (connectionState.closingOrDraining()) {
            return;
        }
        log.error("Idle timeout after " + idleTime + " ms; closing the connection");
        connectionState = Status.Closing;

        emit(new ConnectionTerminatedEvent(this, idleTimer.isTailLoss()? ConnectionLost: CloseReason.IdleTimeout, false));

        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.1
        // "If a max_idle_timeout is specified by either peer (...), the connection is silently closed and its state is
        //  discarded when it remains idle for longer than the minimum of both peers max_idle_timeout values."
        getStreamManager().abortAll();
        getSender().stop();
        log.getQLog().emitConnectionClosedEvent(Instant.now());
        terminate();
    }

    protected void immediateClose() {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2
        immediateCloseWithError(NO_ERROR.value, QUIC_LAYER_ERROR, null);
    }

    /**
     * Immediately closes the connection with a QUIC layer error and enters the "closing state".
     * Connection close frame with indicated error (or "NO_ERROR") is sent to peer and after 3 x PTO, the closing state
     * is ended and all connection state is discarded.
     * If this method is called outside received-message-processing, post-processing actions (including flushing the
     * sender) should be performed by the caller.
     *
     * @param error       The error code, see https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1
     * @param errorReason
     */
    protected void immediateCloseWithError(QuicConstants.TransportErrorCode error, String errorReason) {
        immediateCloseWithError(error.value, QUIC_LAYER_ERROR, errorReason);
    }

    /**
     * Immediately closes the connection (with or without a QUIC layer error) and enters the "closing state".
     * Connection close frame with indicated error (or "NO_ERROR") is sent to peer and after 3 x PTO, the closing state
     * is ended and all connection state is discarded.
     * If this method is called outside received-message-processing, post-processing actions (including flushing the
     * sender) should be performed by the caller.
     *
     * @param error       The error code, see https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1
     * @param errorReason
     */
    protected void immediateCloseWithError(long error, String errorReason) {
        immediateCloseWithError(error, QUIC_LAYER_ERROR, errorReason);
    }
    
    /**
     * Immediately closes the connection (with or without error) and enters the "closing state".
     * Connection close frame with indicated error (or "NO_ERROR") is sent to peer and after 3 x PTO, the closing state
     * is ended and all connection state is discarded.
     * If this method is called outside received-message-processing, post-processing actions (including flushing the
     * sender) should be performed by the caller.
     *
     * @param error       The error code, see https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-20.1.
     * @param errorType   whether the error is at the QUIC layer or an application error
     * @param errorReason
     */
    protected void immediateCloseWithError(long error, ErrorType errorType, String errorReason) {
        if (connectionState.closingOrDraining()){
            log.debug("Immediate close ignored because already closing");
            return;
        }
        connectionState = Status.CloseRequested;
        if (error != NO_ERROR.value || errorType == APPLICATION_ERROR) {
            log.error("Closing connection with " + (errorType == APPLICATION_ERROR? "application ": "") + "error " + error
                    + (errorReason != null? ": " + errorReason: ""));
        }

        emit(new ConnectionTerminatedEvent(this, CloseReason.ImmediateClose, false,
                errorType == QUIC_LAYER_ERROR? error: null,
                errorType == APPLICATION_ERROR? error: null, errorReason));

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2
        // "An endpoint sends a CONNECTION_CLOSE frame (Section 19.19) to terminate the connection immediately."
        getSender().stop();
        sendConnectionClose(error, errorType, errorReason);
        // "After sending a CONNECTION_CLOSE frame, an endpoint immediately enters the closing state;"
        connectionState = Status.Closing;

        getStreamManager().abortAll();

        if (currentEncryptionLevel != Initial) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2
            // "The closing and draining connection states exist to ensure that connections close cleanly and that
            //  delayed or reordered packets are properly discarded. These states SHOULD persist for at least three
            //  times the current PTO interval as defined in [QUIC-RECOVERY]."
            int pto = getSender().getPto();
            schedule(() -> terminate(), 3 * pto, TimeUnit.MILLISECONDS);
        }
        else {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.3
            // "An endpoint that has not established state, such as a server that detects an error in an Initial packet,
            //  does not enter the closing state."
            postProcessingActions.add(() -> terminate());
        }

        log.getQLog().emitConnectionClosedEvent(Instant.now(), error, errorReason);
    }

    private void sendConnectionClose(long error, ErrorType errorType, String errorReason) {
        if (errorType == APPLICATION_ERROR && currentEncryptionLevel != App) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.3
            // "Sending a CONNECTION_CLOSE of type 0x1d in an Initial or Handshake packet could expose application state
            // or be used to alter application state. A CONNECTION_CLOSE of type 0x1d MUST be replaced by a
            // CONNECTION_CLOSE of type 0x1c when sending the frame in Initial or Handshake packets."
            sendConnectionClose(QuicConstants.TransportErrorCode.APPLICATION_ERROR.value, QUIC_LAYER_ERROR, "");
        }
        else {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.3
            // "However, prior to confirming the handshake, it is possible that more advanced packet protection keys are
            //  not available to the peer, so another CONNECTION_CLOSE frame MAY be sent in a packet that uses a lower
            //  packet protection level."
            ConnectionCloseFrame closeFrame = new ConnectionCloseFrame(quicVersion.getVersion(), error, errorType == QUIC_LAYER_ERROR, errorReason);
            switch (currentEncryptionLevel) {
                case Initial:
                    getSender().send(closeFrame, Initial);
                    break;
                case Handshake:
                    getSender().send(closeFrame, Initial);
                    getSender().send(closeFrame, Handshake);
                    break;
                case App:
                    getSender().send(closeFrame, App);
                    break;
            }
            lastConnectionCloseFrameSent = closeFrame;
        }
    }

    /**
     * Handle connection error that did not occur during processing of a received packet.
     * @param cause
     */
    protected void connectionError(TransportError cause) {
        immediateCloseWithError(cause.getTransportErrorCode().value, cause.getMessage());
        getSender().flush();
        runPostProcessingActions();
    }

    protected void handlePacketInClosingState(QuicPacket packet) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.2
        // "An endpoint MAY enter the draining state from the closing state if it receives a CONNECTION_CLOSE frame,
        //  which indicates that the peer is also closing or draining."
        if (packet.getFrames().stream().filter(frame -> frame instanceof ConnectionCloseFrame).findAny().isPresent()) {
            connectionState = Status.Draining;
        }
        else {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.1
            // "An endpoint in the closing state sends a packet containing a CONNECTION_CLOSE frame in response to any
            //  incoming packet that it attributes to the connection."
            // "An endpoint SHOULD limit the rate at which it generates packets in the closing state."
            assert lastConnectionCloseFrameSent != null;
            closeFramesSendRateLimiter.execute(() -> send(lastConnectionCloseFrameSent, packet.getEncryptionLevel(), NO_RETRANSMIT, false));  // No flush necessary, as this method is called while processing a received packet.
        }
    }

    protected void handlePeerClosing(ConnectionCloseFrame closing, EncryptionLevel encryptionLevel) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.2
        // "The draining state is entered once an endpoint receives a CONNECTION_CLOSE frame, which indicates that its
        //  peer is closing or draining."
        if (!connectionState.closingOrDraining()) {  // Can occur due to race condition (both peers closing simultaneously)
            emit(new ConnectionTerminatedEvent(this, CloseReason.ImmediateClose, true,
                    closing.hasTransportError()? closing.getErrorCode(): null,
                    closing.hasApplicationProtocolError()? closing.getErrorCode(): null, closing.getReasonPhrase()));

            if (closing.hasError()) {
                log.error("Peer closed the connection: " + closing);
                peerClosedWithError(closing);
            }
            getSender().stop();

            getStreamManager().abortAll();

            // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.2
            // "An endpoint that receives a CONNECTION_CLOSE frame MAY send a single packet containing a CONNECTION_CLOSE
            //  frame before entering the draining state, using a CONNECTION_CLOSE frame and a NO_ERROR code if appropriate.
            //  An endpoint MUST NOT send further packets."
            send(new ConnectionCloseFrame(quicVersion.getVersion()), encryptionLevel, NO_RETRANSMIT, false);  // No flush necessary, as this method is called while processing a received packet.

            drain();
        }
    }

    protected void peerClosedWithError(ConnectionCloseFrame closeFrame) {
    }

    private void drain() {
        connectionState = Status.Draining;
        /// https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2
        // "The closing and draining connection states exist to ensure that connections close cleanly and that delayed
        //  or reordered packets are properly discarded. These states SHOULD persist for at least three times the
        //  current Probe Timeout (PTO) interval"
        int pto = getSender().getPto();
        schedule(() -> terminate(), 3 * pto, TimeUnit.MILLISECONDS);
    }

    protected boolean enterDrainingState() {
        if (!connectionState.closingOrDraining()) {
            getSender().stop();
            getStreamManager().abortAll();
            drain();
            return true;
        }
        else {
            return false;
        }
    }

    protected void emit(ConnectionTerminatedEvent connectionDisconnectEvent) {
        if (connectionListener != null) {
            callbackThread.submit(() -> connectionListener.disconnected(connectionDisconnectEvent));
        }
        String logMessage = (connectionDisconnectEvent.closedByPeer()? "Peer is closing ": "Closing ") +
                this +
                (connectionDisconnectEvent.hasError()?
                        " with error " + connectionDisconnectEvent.errorDescription():
                        " (reason: " + connectionDisconnectEvent.closeReason() + ")");
        log.info(logMessage);
    }

    protected void emit(ConnectionEstablishedEvent connectionEstablishedEvent) {
        if (connectionListener != null) {
            callbackThread.submit(() -> connectionListener.connected(connectionEstablishedEvent));
        }
    }

    protected String determineClosingErrorMessage(ConnectionCloseFrame closing) {
        if (closing.hasTransportError()) {
            if (closing.hasTlsError()) {
                return "TLS error " + closing.getTlsError() + (closing.hasReasonPhrase()? ": " + closing.getReasonPhrase():"");
            }
            else {
                return "transport error " + closing.getErrorCode() + (closing.hasReasonPhrase()? ": " + closing.getReasonPhrase():"");
            }
        }
        else if (closing.hasApplicationProtocolError()) {
            return "application protocol error " + closing.getErrorCode() + (closing.hasReasonPhrase()? ": " + closing.getReasonPhrase():"");
        }
        else {
            return "";
        }
    }

    /**
     * Closes the connection by discarding all connection state. Do not call directly, should be called after
     * closing state or draining state ends.
     */
    protected final void terminate() {
        preTerminateHook();
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2
        // "Once its closing or draining state ends, an endpoint SHOULD discard all connection state."
        idleTimer.shutdown();
        getSender().shutdown(this::postTerminateHook);
        connectionState = Status.Closed;
        scheduler.shutdown();
    }

    protected void preTerminateHook() {}

    /**
     * Called on sender thread after the sender is shut down (and for example, connection close frame is sent).
     */
    protected void postTerminateHook() {
        callbackThread.shutdown();
    }

    protected int quicError(TlsProtocolException tlsError) {
        if (tlsError instanceof ErrorAlert) {
            return 0x100 + ((ErrorAlert) tlsError).alertDescription().value;
        }
        else if (tlsError.getCause() instanceof TransportError) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1
            return ((TransportError) tlsError.getCause()).getTransportErrorCode().value;
        }
        else {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1
            // "INTERNAL_ERROR (0x1): The endpoint encountered an internal error and cannot continue with the connection."
            return INTERNAL_ERROR.value;
        }
    }

    /**
     * Abort connection due to a local fatal error. No message is sent to peer; just inform application it's all over.
     * @param error  the exception that caused the trouble
     */
    public abstract void abortConnection(Throwable error);

    public int getMaxPacketSize() {
        if (useStrictSmallestAllowedMaximumDatagramSize) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-14.2
            // "An endpoint SHOULD use DPLPMTUD (Section 14.3) or PMTUD (Section 14.2.1) to determine whether the path
            //  to a destination will support a desired maximum datagram size without fragmentation. In the absence of
            //  these mechanisms, QUIC endpoints SHOULD NOT send datagrams larger than the smallest allowed maximum
            //  datagram size."
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.1, https://www.rfc-editor.org/rfc/rfc9000.html#section-14
            // "... the smallest allowed maximum datagram size of 1200 bytes"
            return 1200;
        }
        else {
            // Draft versions of the QUIC specification (e.g. https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-28)
            // allowed a minimum of 1252 bytes for IPv4 and 1232 bytes for IPv6
            // https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-28#section-14.1
            // "In the absence of these mechanisms, QUIC endpoints SHOULD NOT send IP packets larger than 1280 bytes.
            //  Assuming the minimum IP header size, this results in a QUIC maximum packet size of 1232 bytes for IPv6
            //  and 1252 bytes for IPv4."
            // and this is what several implementations still use.
            // The RFC still mentions this maximum minimum size in the context of path MTU discovery:
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-14
            // "QUIC assumes a minimum IP packet size of at least 1280 bytes. This is the IPv6 minimum size [IPv6] and is
            //  also supported by most modern IPv4 networks. Assuming the minimum IP header size of 40 bytes for IPv6 and
            //  20 bytes for IPv4 and a UDP header size of 8 bytes, this results in a maximum datagram size of 1232 bytes
            //  for IPv6 and 1252 bytes for IPv4. Thus, modern IPv4 and all IPv6 network paths are expected to be able
            //  to support QUIC."
            if (usingIPv4()) {
                return 1252;
            }
            else {
                return 1232;
            }
        }
    }

    @Override
    public void close() {
        immediateClose();
        // Because this method is not called in the context of processing received messages,
        // sender flush must be called explicitly.
        getSender().flush();
    }

    @Override
    public void closeAndWait() {
        // After 3 PTO, connection should have been terminated anyway, so no use in waiting longer.
        closeAndWait(Duration.ofMillis(4L * getSender().getPto()));
    }

    @Override
    public void closeAndWait(Duration maxWait) {
        close();

        long maxWaitMillis = Long.min(maxWait.toMillis(), 4L * getSender().getPto());
        long waitedMillis = 0;

        try {
            // Busy wait is not ideal, but this method will only be used by a client that is waiting to shutdown JVM, so don't bother.
            while (connectionState != Status.Closed && waitedMillis < maxWaitMillis) {
                Thread.sleep(1);
                waitedMillis++;
            }
        } catch (InterruptedException e) {}
    }

    @Override
    public void close(QuicConstants.TransportErrorCode applicationError, String errorReason) {
        immediateCloseWithError(applicationError.value, QUIC_LAYER_ERROR, errorReason);
        // Because this method is not called in the context of processing received messages,
        // sender flush must be called explicitly.
        getSender().flush();
    }

    @Override
    public void close(long applicationError, String errorReason) {
        immediateCloseWithError(applicationError, APPLICATION_ERROR, errorReason);
        // Because this method is not called in the context of processing received messages,
        // sender flush must be called explicitly.
        getSender().flush();
    }

    private static ScheduledExecutorService createScheduler(String id) {
        ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1, new DaemonThreadFactory("scheduler" + id));
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
        return executor;
    }

    private void schedule(Runnable command, int delay, TimeUnit unit) {
        try {
            scheduler.schedule(command, delay, unit);
        }
        catch (RejectedExecutionException rejected) {
            // Can happen when already terminated; don't bother
        }
    }

    @Override
    public Statistics getStats() {
        return new Statistics(getSender().getStatistics());
    }

    @Override
    public QuicVersion getQuicVersion() {
        return quicVersion.getVersion().toQuicVersion();
    }

    @Override
    public void setConnectionListener(ConnectionListener connectionListener) {
        this.connectionListener = connectionListener;
    }

    protected abstract boolean usingIPv4();

    protected abstract PacketFilter createProcessorChain();
    
    protected abstract SenderImpl getSender();

    protected abstract TlsEngine getTlsEngine();

    protected abstract GlobalAckGenerator getAckGenerator();

    protected abstract StreamManager getStreamManager();

    public abstract ConnectionIdManager getConnectionIdManager();

    @Deprecated
    public abstract long getInitialMaxStreamData();

    int getMaxShortHeaderPacketOverhead() {
        return 1  // flag byte
                + getConnectionIdManager().getCurrentPeerConnectionIdLength()
                + 4  // max packet number size, in practice this will be mostly 1
                + 16 // encryption overhead
                ;
    }

    /**
     * Returns the connection ID of this connection. During handshake, this is a fixed ID, that is generated by this
     * endpoint. After handshaking, this is one of the active connection ID's; if there are multiple active connection
     * ID's, which one is returned is not determined (but this method should always return the same until it is not
     * active anymore). Note that after handshaking, the connection ID (of this endpoint) is not used for sending
     * packets (short header packets only contain the destination connection ID), only for routing received packets.
     * @return
     */
    public abstract byte[] getSourceConnectionId();

    public IdleTimer getIdleTimer() {
        return idleTimer;
    }

    public Role getRole() {
        return role;
    }

    public PacketFilter getPacketProcessorChain() {
        return processorChain;
    }

    public void addAckFrameReceivedListener(FrameReceivedListener<AckFrame> recoveryManager) {
        this.recoveryManager = recoveryManager;
    }

    public void enableDatagramExtension() {
        if (datagramExtensionStatus != DatagramExtensionStatus.Disabled) {
            throw new IllegalStateException("Datagram extension can only be disable once and before connection is established.");
        }
        if (datagramExtensionStatus == DatagramExtensionStatus.Disabled) {
            datagramExtensionStatus = DatagramExtensionStatus.Enable;
        }
    }

    public void enableReliableStreamReset() {
        reliableStreamResetEnabled = true;
    }

    @Override
    public boolean canUseReliableStreamReset() {
        return peerSupportsReliableStreamReset;
    }

    protected class CheckDestinationFilter extends BasePacketFilter {

        public CheckDestinationFilter(PacketFilter next) {
            super(next);
        }

        @Override
        public void processPacket(QuicPacket packet, PacketMetaData metaData) throws TransportError {
            if (checkDestinationConnectionId(packet)) {
                next(packet, metaData);
            }
            else {
                discard(packet, "with unknown destination connection ID");
            }
        }
    }

    protected class ClosingOrDrainingFilter extends BasePacketFilter {

        public ClosingOrDrainingFilter(PacketFilter next, Logger log) {
            super(next, log);
        }

        @Override
        public void processPacket(QuicPacket packet, PacketMetaData metaData) throws TransportError {
            if (connectionState.closingOrDraining()) {
                if (connectionState.isClosing()) {
                    // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.2.1
                    // "An endpoint in the closing state sends a packet containing a CONNECTION_CLOSE frame in response
                    //  to any incoming packet that it attributes to the connection."
                    handlePacketInClosingState(packet);
                }
                else {
                    discard(packet, "in draining state");
                }
            }
            else {
                next(packet, metaData);
            }
        }
    }

    protected class PostProcessingFilter extends BasePacketFilter {

            public PostProcessingFilter(PacketFilter next) {
                super(next);
            }

            @Override
            public void processPacket(QuicPacket packet, PacketMetaData metaData) throws TransportError {
                next(packet, metaData);
                getSender().packetProcessed(metaData.moreDataInDatagram());
            }
    }
}
