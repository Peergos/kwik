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

import org.junit.jupiter.api.Test;
import tech.kwik.core.frame.AddAddressFrame;
import tech.kwik.core.frame.ReachOutFrame;
import tech.kwik.core.frame.RemoveAddressFrame;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NatTraversalTest {

    private static InetSocketAddress address(String ip, int port) throws Exception {
        return new InetSocketAddress(InetAddress.getByName(ip), port);
    }

    @Test
    void serverProbesEachReachOutAddressUpToTheMaximumAttempts() throws Exception {
        NatTraversal server = new NatTraversal(false, 2, 2);
        assertThat(server.handleReachOut(new ReachOutFrame(1, address("127.0.0.1", 1)))).isTrue();
        assertThat(server.handleReachOut(new ReachOutFrame(1, address("1.1.1.1", 2)))).isFalse();

        long challenge = 0;
        for (int attempt = 0; attempt < NatTraversal.MAX_PROBE_ATTEMPTS; attempt++) {
            if (attempt > 0) {
                server.queueRetries();
            }
            List<InetSocketAddress> probes = server.takePendingProbes();
            assertThat(probes).hasSize(2);
            for (InetSocketAddress probe : probes) {
                server.probeSent(probe, ++challenge);
            }
            assertThat(server.takePendingProbes()).isEmpty();
        }
        server.queueRetries();
        assertThat(server.takePendingProbes()).isEmpty();
        assertThat(server.retryDelayMillis(333)).isEqualTo(-1);
    }

    @Test
    void serverRejectsTooManyAddressesInARound() throws Exception {
        NatTraversal server = new NatTraversal(false, 1, 1);
        server.handleReachOut(new ReachOutFrame(1, address("10.0.0.1", 1)));
        assertThatThrownBy(() -> server.handleReachOut(new ReachOutFrame(1, address("10.0.0.2", 1))))
                .isInstanceOf(NatTraversal.TooManyAddressesException.class);
        // A new round starts afresh, and older rounds are ignored.
        assertThat(server.handleReachOut(new ReachOutFrame(2, address("10.0.0.2", 1)))).isTrue();
        assertThat(server.handleReachOut(new ReachOutFrame(1, address("10.0.0.3", 1)))).isFalse();
        assertThat(server.takePendingProbes()).containsExactly(address("10.0.0.2", 1));
    }

    @Test
    void retryDelayBacksOffExponentiallyUntilAProbeIsAnswered() throws Exception {
        InetSocketAddress remote = address("::2", 2);
        NatTraversal client = new NatTraversal(true, 8, 8);
        client.addLocalAddress(address("::3", 3));
        client.addRemoteAddress(new AddAddressFrame(1, remote));
        client.initiateRound();
        client.probeSent(remote, 0);
        assertThat(client.retryDelayMillis(333)).isEqualTo(34);

        long[] delays = { 34, 67, 134, 267, 533, 1066, 2000 };
        for (int i = 0; i < delays.length; i++) {
            client.queueRetries();
            assertThat(client.takePendingProbes()).containsExactly(remote);
            client.probeSent(remote, i + 1);
            assertThat(client.retryDelayMillis(333)).isEqualTo(delays[i]);
        }

        assertThat(client.handlePathResponse(address("::3", 2), 7)).isFalse();
        assertThat(client.handlePathResponse(remote, 7)).isTrue();
        assertThat(client.pollPathToOpen()).isEqualTo(remote);
        assertThat(client.retryDelayMillis(333)).isEqualTo(-1);
        // A late response to an earlier probe of the round still counts; one of a previous round does not.
        assertThat(client.handlePathResponse(remote, 3)).isTrue();
        client.initiateRound();
        assertThat(client.handlePathResponse(remote, 4)).isFalse();
    }

    @Test
    void clientRoundSendsItsAddressesAndProbesTheServers() throws Exception {
        NatTraversal client = new NatTraversal(true, 4, 2);
        assertThatThrownBy(client::initiateRound).isInstanceOf(NatTraversal.NotEnoughAddressesException.class);
        assertThat(client.addLocalAddress(address("192.168.1.2", 1000))).isNull();
        client.addLocalAddress(address("::ffff:203.0.113.9", 2000));
        assertThatThrownBy(() -> client.addLocalAddress(address("10.1.1.1", 1)))
                .isInstanceOf(NatTraversal.TooManyAddressesException.class);

        assertThat(client.addRemoteAddress(new AddAddressFrame(0, address("198.51.100.1", 4433)))).isEqualTo(address("198.51.100.1", 4433));
        assertThat(client.addRemoteAddress(new AddAddressFrame(0, address("198.51.100.1", 4433)))).isNull();
        client.addRemoteAddress(new AddAddressFrame(1, address("198.51.100.2", 4433)));
        assertThat(client.removeRemoteAddress(new RemoveAddressFrame(1))).isEqualTo(address("198.51.100.2", 4433));

        NatTraversal.Round round = client.initiateRound();
        assertThat(round.probed()).containsExactly(address("198.51.100.1", 4433));
        assertThat(round.reachOuts()).extracting(ReachOutFrame::getRound).containsOnly(1L);
        // IPv4-mapped addresses are sent as IPv4.
        assertThat(round.reachOuts()).extracting(ReachOutFrame::getAddress)
                .containsExactly(address("192.168.1.2", 1000), address("203.0.113.9", 2000));
        assertThat(client.initiateRound().reachOuts()).extracting(ReachOutFrame::getRound).containsOnly(2L);
    }

    @Test
    void serverAdvertisesEachAddressOnce() throws Exception {
        NatTraversal server = new NatTraversal(false, 4, 2);
        AddAddressFrame first = server.addLocalAddress(address("203.0.113.1", 1));
        assertThat(first.getSequenceNumber()).isEqualTo(0);
        assertThat(server.addLocalAddress(address("203.0.113.1", 1))).isNull();
        assertThat(server.addLocalAddress(address("203.0.113.2", 1)).getSequenceNumber()).isEqualTo(1);
        assertThat(server.isAdvertised(first)).isTrue();
        assertThat(server.removeLocalAddress(address("203.0.113.1", 1)).getSequenceNumber()).isEqualTo(0);
        assertThat(server.isAdvertised(first)).isFalse();
        assertThat(server.addLocalAddress(address("203.0.113.1", 1)).getSequenceNumber()).isEqualTo(2);
    }
}
