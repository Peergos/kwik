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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MtuDiscoveryTest {

    @Test
    void doesNotProbeBeforeEnabled() {
        MtuDiscovery discovery = new MtuDiscovery(1252, 1452);
        assertThat(discovery.nextProbe()).isEqualTo(0);
    }

    @Test
    void ackedUpperBoundEndsTheSearch() {
        MtuDiscovery discovery = new MtuDiscovery(1252, 1452);
        discovery.enable();
        assertThat(discovery.nextProbe()).isEqualTo(1452);
        assertThat(discovery.nextProbe()).isEqualTo(0);
        assertThat(discovery.probeAcked(1452)).isEqualTo(1452);
        assertThat(discovery.nextProbe()).isEqualTo(0);
    }

    @Test
    void sizeIsGivenUpAfterRepeatedLossAndSearchContinuesBelow() {
        MtuDiscovery discovery = new MtuDiscovery(1252, 1452);
        discovery.enable();
        for (int i = 0; i < MtuDiscovery.MAX_PROBES; i++) {
            assertThat(discovery.nextProbe()).isEqualTo(1452);
            discovery.probeLost(1452);
        }
        assertThat(discovery.nextProbe()).isEqualTo(1352);
        assertThat(discovery.probeAcked(1352)).isEqualTo(1352);
        assertThat(discovery.nextProbe()).isEqualTo(1402);
        discovery.probeAcked(1402);
        assertThat(discovery.nextProbe()).isEqualTo(1427);
        for (int i = 0; i < MtuDiscovery.MAX_PROBES; i++) {
            discovery.nextProbe();
            discovery.probeLost(1427);
        }
        assertThat(discovery.nextProbe()).isEqualTo(1414);
        discovery.probeAcked(1414);
        assertThat(discovery.nextProbe()).isEqualTo(0);
        assertThat(discovery.confirmedSize()).isEqualTo(1414);
    }

    @Test
    void upperBoundIsCappedByPeerLimit() {
        MtuDiscovery discovery = new MtuDiscovery(1252, 1452);
        discovery.setUpperBound(1400);
        discovery.enable();
        assertThat(discovery.nextProbe()).isEqualTo(1400);
    }
}
