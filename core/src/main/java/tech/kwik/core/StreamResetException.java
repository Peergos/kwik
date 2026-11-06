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
 * The peer reset the stream (RESET_STREAM), so no more data can be read from it.
 */
public class StreamResetException extends StreamClosedException {

    private final long errorCode;

    public StreamResetException(long errorCode) {
        super("Stream reset by peer with error code " + errorCode);
        this.errorCode = errorCode;
    }

    public long getErrorCode() {
        return errorCode;
    }
}
