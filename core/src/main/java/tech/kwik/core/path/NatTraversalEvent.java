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

import java.net.InetSocketAddress;

/**
 * The server advertised (ADD_ADDRESS) or withdrew (REMOVE_ADDRESS) a NAT traversal address.
 */
public final class NatTraversalEvent {

    public enum Type { ADDED, REMOVED }

    private final Type type;
    private final InetSocketAddress address;

    public NatTraversalEvent(Type type, InetSocketAddress address) {
        this.type = type;
        this.address = address;
    }

    public Type type() {
        return type;
    }

    public InetSocketAddress address() {
        return address;
    }

    @Override
    public String toString() {
        return type + " " + address;
    }
}
