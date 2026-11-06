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
package tech.kwik.core.socket;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * Controls how the (shared) server socket is used to send datagrams to the client associated with one particular QUIC connection.
 */
public class ServerConnectionSocketManager implements SocketManager {

    private final DatagramSender sender;
    private volatile InetSocketAddress clientAddress;

    public ServerConnectionSocketManager(DatagramSocket serverSocket, InetSocketAddress initialClientAddress) {
        this(DatagramSender.of(serverSocket), initialClientAddress);
    }

    public ServerConnectionSocketManager(DatagramSender sender, InetSocketAddress initialClientAddress) {
        this.sender = sender;
        this.clientAddress = initialClientAddress;
    }

    public Instant send(ByteBuffer data) throws IOException {
        return send(data, clientAddress);
    }

    @Override
    public Instant send(ByteBuffer data, InetSocketAddress clientAddress) throws IOException {
        return sender.send(data, clientAddress);
    }

    @Override
    public int maxSegments() {
        return sender.maxSegments();
    }

    @Override
    public Instant sendSegmented(byte[] data, int length, int segmentSize, InetSocketAddress clientAddress) throws IOException {
        if (sender.maxSegments() <= 1) {
            return SocketManager.super.sendSegmented(data, length, segmentSize, clientAddress);
        }
        return sender.sendSegmented(data, length, segmentSize, clientAddress);
    }

    @Override
    public void close() {
        // Note that the serverSocket must not be closed here, as it is used for all server connections ;-)
    }

    @Override
    public InetSocketAddress getClientAddress() {
        return clientAddress;
    }

    public void changeClientAddress(InetSocketAddress clientAddress) {
        this.clientAddress = clientAddress;
    }
}
