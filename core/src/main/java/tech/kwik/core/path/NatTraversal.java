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
package tech.kwik.core.path;

import tech.kwik.core.frame.AddAddressFrame;
import tech.kwik.core.frame.ReachOutFrame;
import tech.kwik.core.frame.RemoveAddressFrame;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * State of iroh's QUIC NAT traversal (QNT), as implemented by noq (n0_nat_traversal.rs). The server advertises its
 * candidate addresses with ADD_ADDRESS; the client starts a round by sending its own candidates in REACH_OUT frames,
 * and then both sides send off-path PATH_CHALLENGE probes to the other's candidates. When a probe is answered the
 * client opens a multipath path to that address.
 */
public class NatTraversal {

    // A round's probes stop when a new round starts, a probe succeeds, or this many attempts were made: with the
    // backoff of retryDelay, about 4 s with the default initial RTT.
    public static final int MAX_PROBE_ATTEMPTS = 9;
    private static final int MAX_BACKOFF_EXPONENT = 8;
    private static final long MAX_RETRY_INTERVAL_MILLIS = 2000;

    public static class TooManyAddressesException extends IllegalStateException {
        public TooManyAddressesException() {
            super("too many NAT traversal addresses");
        }
    }

    public static class NotEnoughAddressesException extends IllegalStateException {
        public NotEnoughAddressesException() {
            super("no local NAT traversal addresses");
        }
    }

    public static final class Round {
        private final List<ReachOutFrame> reachOuts;
        private final List<InetSocketAddress> probed;

        Round(List<ReachOutFrame> reachOuts, List<InetSocketAddress> probed) {
            this.reachOuts = reachOuts;
            this.probed = probed;
        }

        public List<ReachOutFrame> reachOuts() {
            return reachOuts;
        }

        public List<InetSocketAddress> probed() {
            return probed;
        }
    }

    private static final class Probe {
        int remaining;
        boolean succeeded;

        Probe(int remaining) {
            this.remaining = remaining;
        }

        int remaining() {
            return succeeded? 0: remaining;
        }
    }

    private static final class Remote {
        private final InetSocketAddress address;
        private final Probe probe;

        Remote(InetSocketAddress address, Probe probe) {
            this.address = address;
            this.probe = probe;
        }

        InetSocketAddress address() {
            return address;
        }

        Probe probe() {
            return probe;
        }
    }

    private final boolean client;
    // Set by this endpoint.
    private final int maxRemoteAddresses;
    // Set by the peer.
    private final int maxLocalAddresses;

    // Client: the server's candidates by ADD_ADDRESS sequence number, and our own, sent in REACH_OUT.
    private final Map<Long, Remote> remoteAddresses = new LinkedHashMap<>();
    private final Set<InetSocketAddress> clientLocalAddresses = new LinkedHashSet<>();
    private final Deque<InetSocketAddress> pathsToOpen = new ArrayDeque<>();
    // Server: our candidates with their sequence numbers, and the client's candidates of the current round.
    private final Map<InetSocketAddress, Long> serverLocalAddresses = new LinkedHashMap<>();
    private long nextLocalSequenceNumber;
    private final Map<InetSocketAddress, Probe> roundRemotes = new LinkedHashMap<>();

    private long round;
    private int attempt;
    private final Map<Long, InetSocketAddress> sentChallenges = new HashMap<>();
    private final Set<InetSocketAddress> pendingProbes = new LinkedHashSet<>();

    public NatTraversal(boolean client, int maxRemoteAddresses, int maxLocalAddresses) {
        this.client = client;
        this.maxRemoteAddresses = maxRemoteAddresses;
        this.maxLocalAddresses = maxLocalAddresses;
    }

    public boolean isClient() {
        return client;
    }

    /**
     * Canonical form: IPv4-mapped IPv6 addresses as IPv4, and no host names.
     */
    public static InetSocketAddress canonical(InetSocketAddress address) {
        byte[] ip = address.getAddress().getAddress();
        try {
            return new InetSocketAddress(InetAddress.getByAddress(ip), address.getPort());
        }
        catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Adds a candidate address of this endpoint. A server advertises it with the returned ADD_ADDRESS frame (null when
     * already advertised); a client sends it in the REACH_OUT frames of the next round.
     */
    public synchronized AddAddressFrame addLocalAddress(InetSocketAddress address) {
        address = canonical(address);
        if (client) {
            if (!clientLocalAddresses.contains(address) && clientLocalAddresses.size() >= maxLocalAddresses) {
                throw new TooManyAddressesException();
            }
            clientLocalAddresses.add(address);
            return null;
        }
        if (serverLocalAddresses.containsKey(address)) {
            return null;
        }
        if (serverLocalAddresses.size() >= maxLocalAddresses) {
            throw new TooManyAddressesException();
        }
        long sequenceNumber = nextLocalSequenceNumber++;
        serverLocalAddresses.put(address, sequenceNumber);
        return new AddAddressFrame(sequenceNumber, address);
    }

    /**
     * Removes a candidate address of this endpoint; for a server, returns the REMOVE_ADDRESS frame to send.
     */
    public synchronized RemoveAddressFrame removeLocalAddress(InetSocketAddress address) {
        address = canonical(address);
        if (client) {
            clientLocalAddresses.remove(address);
            return null;
        }
        Long sequenceNumber = serverLocalAddresses.remove(address);
        return sequenceNumber == null? null: new RemoveAddressFrame(sequenceNumber);
    }

    /**
     * Whether the server still advertises the address of the given ADD_ADDRESS frame (so a lost frame is resent).
     */
    public synchronized boolean isAdvertised(AddAddressFrame frame) {
        Long sequenceNumber = serverLocalAddresses.get(frame.getAddress());
        return sequenceNumber != null && sequenceNumber == frame.getSequenceNumber();
    }

    public synchronized List<InetSocketAddress> localAddresses() {
        return new ArrayList<>(client? clientLocalAddresses: serverLocalAddresses.keySet());
    }

    /**
     * Client: starts a new round, cancelling the previous one: probes every candidate of the server, and returns the
     * REACH_OUT frames asking the server to probe ours.
     */
    public synchronized Round initiateRound() {
        if (clientLocalAddresses.isEmpty()) {
            throw new NotEnoughAddressesException();
        }
        round++;
        attempt = 0;
        sentChallenges.clear();
        pendingProbes.clear();
        for (Remote remote : remoteAddresses.values()) {
            pendingProbes.add(remote.address());
            remote.probe().remaining = MAX_PROBE_ATTEMPTS - 1;
            remote.probe().succeeded = false;
        }
        List<ReachOutFrame> reachOuts = new ArrayList<>();
        for (InetSocketAddress local : clientLocalAddresses) {
            reachOuts.add(new ReachOutFrame(round, local));
        }
        return new Round(reachOuts, new ArrayList<>(pendingProbes));
    }

    public synchronized long currentRound() {
        return round;
    }

    /**
     * Server: handles a REACH_OUT frame; returns whether it started a new round.
     */
    public synchronized boolean handleReachOut(ReachOutFrame frame) {
        if (frame.getRound() < round) {
            return false;
        }
        InetSocketAddress address = canonical(frame.getAddress());
        boolean newRound = frame.getRound() > round;
        if (newRound) {
            round = frame.getRound();
            attempt = 0;
            roundRemotes.clear();
            sentChallenges.clear();
            pendingProbes.clear();
        }
        else if (roundRemotes.containsKey(address)) {
            return false;
        }
        else if (roundRemotes.size() >= maxRemoteAddresses) {
            throw new TooManyAddressesException();
        }
        roundRemotes.put(address, new Probe(MAX_PROBE_ATTEMPTS - 1));
        pendingProbes.add(address);
        return newRound;
    }

    /**
     * Client: handles ADD_ADDRESS; returns the address when it is new to the set.
     */
    public synchronized InetSocketAddress addRemoteAddress(AddAddressFrame frame) {
        InetSocketAddress address = canonical(frame.getAddress());
        Remote existing = remoteAddresses.get(frame.getSequenceNumber());
        if (existing != null) {
            if (existing.address().equals(address)) {
                return null;
            }
        }
        else if (remoteAddresses.size() >= maxRemoteAddresses) {
            throw new TooManyAddressesException();
        }
        remoteAddresses.put(frame.getSequenceNumber(), new Remote(address, new Probe(MAX_PROBE_ATTEMPTS)));
        return address;
    }

    /**
     * Client: handles REMOVE_ADDRESS; returns the removed address, if it was known.
     */
    public synchronized InetSocketAddress removeRemoteAddress(RemoveAddressFrame frame) {
        Remote removed = remoteAddresses.remove(frame.getSequenceNumber());
        return removed == null? null: removed.address();
    }

    public synchronized List<InetSocketAddress> remoteAddresses() {
        return remoteAddresses.values().stream().map(Remote::address).collect(Collectors.toList());
    }

    /**
     * Queues the next attempt of each probe that has not succeeded and has attempts left.
     */
    public synchronized void queueRetries() {
        attempt++;
        if (client) {
            remoteAddresses.values().forEach(remote -> retry(remote.address(), remote.probe()));
        }
        else {
            roundRemotes.forEach(this::retry);
        }
    }

    private void retry(InetSocketAddress address, Probe probe) {
        if (probe.remaining() > 0) {
            probe.remaining--;
            pendingProbes.add(address);
        }
    }

    private Iterable<Probe> probes() {
        return client? remoteAddresses.values().stream().map(Remote::probe).collect(Collectors.toList()): roundRemotes.values();
    }

    /**
     * The addresses to probe now; each probe sent must be reported with {@link #probeSent}.
     */
    public synchronized List<InetSocketAddress> takePendingProbes() {
        List<InetSocketAddress> probes = new ArrayList<>(pendingProbes);
        pendingProbes.clear();
        return probes;
    }

    public synchronized void probeSent(InetSocketAddress address, long challenge) {
        sentChallenges.put(challenge, canonical(address));
    }

    /**
     * Whether the PATH_RESPONSE answers a probe sent to the address it came from. For a client, the address is then
     * returned by {@link #pollPathToOpen}.
     */
    public synchronized boolean handlePathResponse(InetSocketAddress source, long challenge) {
        InetSocketAddress expected = sentChallenges.get(challenge);
        if (expected == null) {
            return false;
        }
        source = canonical(source);
        if (!expected.equals(source)) {
            return false;
        }
        sentChallenges.remove(challenge);
        if (client) {
            pathsToOpen.add(source);
            for (Remote remote : remoteAddresses.values()) {
                if (remote.address().equals(source)) {
                    remote.probe().succeeded = true;
                }
            }
        }
        else {
            Probe probe = roundRemotes.get(source);
            if (probe != null) {
                probe.succeeded = true;
            }
        }
        return true;
    }

    public synchronized InetSocketAddress pollPathToOpen() {
        return pathsToOpen.poll();
    }

    public synchronized void pushPathToOpen(InetSocketAddress address) {
        pathsToOpen.addFirst(address);
    }

    /**
     * The delay until the next retry of the probes, or -1 when none has attempts left: exponential backoff from a
     * tenth of the initial RTT, capped at 2 s.
     */
    public synchronized long retryDelayMillis(long initialRttMillis) {
        boolean any = false;
        for (Probe probe : probes()) {
            any |= probe.remaining() > 0;
        }
        if (!any) {
            return -1;
        }
        double base = initialRttMillis / 10.0;
        int exponent = Integer.min(attempt, MAX_BACKOFF_EXPONENT);
        double interval = exponent == 0? base: base * (1L << exponent) - base * (1L << (exponent - 1));
        return (long) Math.min(Math.ceil(interval), MAX_RETRY_INTERVAL_MILLIS);
    }
}
