/*
 * Copyright © 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.core.stream;

import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.Version;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Buffer for data to be sent on a stream. The buffer has a maximum size, and writing to it will block if the buffer is
 * full. The buffer is thread-safe for concurrent writes and reads, not for concurrent writes or concurrent reads.
 */
public class SendBuffer {

    // Send queue contains stream bytes to send in order. The position of the first byte buffer in the queue determines the next byte(s) to send.
    private final Queue<ByteBuffer> sendQueue;
    private final ByteBuffer END_OF_STREAM_MARKER = ByteBuffer.allocate(0);
    private final int maxBufferSize;
    private final AtomicInteger bufferedBytes;
    private final ReentrantLock bufferLock;
    private final Condition notFull;
    private volatile Thread blockingWriterThread;
    // The free space a blocked writer waits for: at least half the buffer, so it isn't woken for every frame sent.
    private volatile int awaitedSpace;


    public SendBuffer(Integer sendBufferSize) {
        sendQueue = new ConcurrentLinkedQueue<>();
        if (sendBufferSize != null && sendBufferSize > 0) {
            maxBufferSize = sendBufferSize;
        }
        else {
            maxBufferSize = 50 * 1024;
        }
        bufferedBytes = new AtomicInteger();
        bufferLock = new ReentrantLock();
        notFull = bufferLock.newCondition();
    }

    /**
     * Writes data to the buffer. If the buffer is full, the method will block until there is enough space in the buffer.
     * This method makes defensive copies of the data.
     * @param data
     * @param off
     * @param len
     * @throws IOException
     * @throws InterruptedException
     */
    public void write(byte[] data, int off, int len) throws IOException, InterruptedException {
        int availableBufferSpace = maxBufferSize - bufferedBytes.get();
        if (len > availableBufferSpace) {
            // Wait for enough buffer space to become available
            bufferLock.lock();
            awaitedSpace = Integer.min(maxBufferSize, Integer.max(len, maxBufferSize / 2));
            blockingWriterThread = Thread.currentThread();
            try {
                while (maxBufferSize - bufferedBytes.get() < awaitedSpace) {
                    if (Thread.currentThread().isInterrupted()) {
                        throw new InterruptedException();
                    }
                    // Might throw InterruptedException, must be handled by caller
                    notFull.await();
                }
                if (Thread.currentThread().isInterrupted()) {
                    // When an interrupt races with a signal, await() can return normally with the interrupt status set
                    // (instead of throwing InterruptedException); the interrupted write must not complete.
                    throw new InterruptedException();
                }
            }
            finally {
                blockingWriterThread = null;
                bufferLock.unlock();
            }
        }

        sendQueue.add(ByteBuffer.wrap(Arrays.copyOfRange(data, off, off + len)));
        bufferedBytes.getAndAdd(len);
    }

    public StreamFrame getStreamFrame(Version quicVersion, int streamId, long currentOffset, int maxBytesToSend) {
        ByteBuffer first = sendQueue.peek();
        if (first != null && first != END_OF_STREAM_MARKER && first.remaining() >= maxBytesToSend && maxBytesToSend > 0) {
            // The frame comes from one buffered chunk, which never changes once written: reference it, no copy.
            int start = first.arrayOffset() + first.position();
            first.position(first.position() + maxBytesToSend);
            if (!first.hasRemaining()) {
                sendQueue.poll();
            }
            boolean fin = sendQueue.peek() == END_OF_STREAM_MARKER;
            if (fin) {
                sendQueue.poll();
            }
            dataTaken(maxBytesToSend);
            return StreamFrame.referencing(quicVersion, streamId, currentOffset, first.array(), start, maxBytesToSend, fin);
        }
        int nrOfBytes = 0;
        byte[] dataToSend = new byte[maxBytesToSend];
        boolean finalFrame = false;
        ByteBuffer buffer;
        while (nrOfBytes < maxBytesToSend && (buffer = sendQueue.peek()) != null && buffer != END_OF_STREAM_MARKER) {
            int position = nrOfBytes;
            if (buffer.remaining() <= maxBytesToSend - nrOfBytes) {
                // All bytes remaining in buffer will fit in stream frame
                nrOfBytes += buffer.remaining();
                buffer.get(dataToSend, position, buffer.remaining());
                sendQueue.poll();
            }
            else {
                // Just part of the buffer will fit in (and will fill up) the stream frame
                buffer.get(dataToSend, position, maxBytesToSend - nrOfBytes);
                nrOfBytes = maxBytesToSend;  // Short form of: nrOfBytes += (maxBytesToSend - nrOfBytes)
            }
        }

        if (sendQueue.peek() == END_OF_STREAM_MARKER) {
            finalFrame = true;
            sendQueue.poll();
        }
        if (nrOfBytes == 0 && !finalFrame) {
            // Nothing to send really
            return null;
        }

        dataTaken(nrOfBytes);
        if (nrOfBytes < maxBytesToSend) {
            // This can happen when not enough data is buffer to fill a stream frame, or length field is 1 byte (instead of 2 that was counted for)
            dataToSend = Arrays.copyOfRange(dataToSend, 0, nrOfBytes);
        }
        StreamFrame streamFrame = new StreamFrame(quicVersion, streamId, currentOffset, dataToSend, finalFrame);
        return streamFrame;
    }

    private void dataTaken(int bytes) {
        int buffered = bufferedBytes.addAndGet(-1 * bytes);
        if (blockingWriterThread != null && maxBufferSize - buffered >= awaitedSpace) {
            bufferLock.lock();
            try {
                notFull.signal();
            }
            finally {
                bufferLock.unlock();
            }
        }
    }

    public int getAvailableBytes() {
        return bufferedBytes.get();
    }

    public boolean isEmpty() {
        return sendQueue.isEmpty();
    }

    public void close() {
        sendQueue.add(END_OF_STREAM_MARKER);
    }

    public void clear() {
        sendQueue.clear();
        bufferedBytes.set(0);
        bufferLock.lock();
        try {
            notFull.signal();
        }
        finally {
            bufferLock.unlock();
        }
    }

    public void interruptBlockedWriter() {
        Thread blocking = blockingWriterThread;
        if (blocking != null) {
            blocking.interrupt();
        }
    }

    public int getMaxSize() {
        return maxBufferSize;
    }

    public boolean hasData() {
        return !sendQueue.isEmpty();
    }
}
