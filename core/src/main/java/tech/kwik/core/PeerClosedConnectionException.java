/*
 * Copyright © 2025, 2026 Peter Doornbosch
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

import java.net.ConnectException;

/**
 * The peer closed the connection during the handshake.
 */
public class PeerClosedConnectionException extends ConnectException {

    private final boolean applicationError;
    private final long errorCode;
    private final String reason;

    public PeerClosedConnectionException(String message, boolean applicationError, long errorCode, String reason) {
        super(message);
        this.applicationError = applicationError;
        this.errorCode = errorCode;
        this.reason = reason;
    }

    public boolean isApplicationError() {
        return applicationError;
    }

    /**
     * @return the error code of the peer's CONNECTION_CLOSE frame; a TLS alert is 0x100 plus the alert
     */
    public long errorCode() {
        return errorCode;
    }

    public String reason() {
        return reason;
    }
}
