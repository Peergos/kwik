/*
 * Copyright © 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.core.receive;

import tech.kwik.core.log.Logger;

import java.util.function.Predicate;

/**
 * Receiver that does not read from a socket itself, but is fed with datagrams by someone that does (e.g. a
 * {@link tech.kwik.core.socket.SharedEndpoint}).
 */
public class QueueReceiver extends AbstractReceiver {

    private final Predicate<RawPacket> filter;

    public QueueReceiver(Logger log, Predicate<RawPacket> filter) {
        super(log, p -> true, e -> {});
        this.filter = filter;
    }

    public void deliver(RawPacket packet) {
        if (!isClosing && filter.test(packet)) {
            receivedPacketsQueue.add(packet);
        }
    }

    @Override
    public void start() {
    }

    @Override
    public void shutdown() {
        isClosing = true;
    }
}
