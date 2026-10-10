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

/**
 * Datagram packetization layer path MTU discovery (RFC 8899, RFC 9000 section 14.3): searches between the size known
 * to work and an upper bound with PING+PADDING probes, trying the upper bound first. A size is given up after
 * MAX_PROBES lost probes.
 */
public class MtuDiscovery {

    public static final int DEFAULT_UPPER_BOUND = 1452;
    static final int MAX_PROBES = 3;
    // Stop searching when the remaining range is smaller than this.
    static final int MIN_STEP = 20;

    private int confirmed;
    private int upper;
    private int candidate;
    private int lostProbes;
    private boolean enabled;
    private boolean probeInFlight;

    public MtuDiscovery(int base, int upperBound) {
        confirmed = base;
        upper = upperBound;
        candidate = upperBound;
    }

    public synchronized void enable() {
        enabled = true;
    }

    public synchronized void setUpperBound(int upperBound) {
        upper = Integer.min(upper, upperBound);
        candidate = Integer.min(candidate, upper);
    }

    public synchronized int confirmedSize() {
        return confirmed;
    }

    /**
     * Returns the size of the probe to send now, or 0. The caller must report the probe's fate with probeAcked or
     * probeLost.
     */
    public synchronized int nextProbe() {
        if (!enabled || probeInFlight || candidate <= confirmed) {
            return 0;
        }
        probeInFlight = true;
        return candidate;
    }

    /**
     * @return the new confirmed size
     */
    public synchronized int probeAcked(int size) {
        probeInFlight = false;
        lostProbes = 0;
        if (size > confirmed) {
            confirmed = size;
        }
        nextCandidate();
        return confirmed;
    }

    public synchronized void probeLost(int size) {
        probeInFlight = false;
        if (size != candidate) {
            return;
        }
        if (++lostProbes >= MAX_PROBES) {
            lostProbes = 0;
            upper = size - 1;
            nextCandidate();
        }
    }

    private void nextCandidate() {
        candidate = upper - confirmed < MIN_STEP ? confirmed : (confirmed + upper + 1) / 2;
    }
}
