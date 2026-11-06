/*
 * Copyright © 2026 Peter Doornbosch
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
package tech.kwik.core;

/**
 * Notified about a stream for its non-blocking API ({@link QuicStream#read(java.nio.ByteBuffer)},
 * {@link QuicStream#write(java.nio.ByteBuffer, boolean)}). Called on the connection's callback executor, which is the
 * shared executor when the connection runs on one; implementations must not block. Notifications are coalesced: one
 * call can stand for several events, so read or write until there is nothing (more) to do.
 */
public interface StreamListener {

    /**
     * Something new can be read: data, the end of the stream, or a reset by the peer (which a read then reports).
     */
    void readable(QuicStream stream);

    /**
     * After a write did not take all data: space in the send buffer became available, or the stream can no longer be
     * written to (which a write then reports).
     */
    void writable(QuicStream stream);
}
