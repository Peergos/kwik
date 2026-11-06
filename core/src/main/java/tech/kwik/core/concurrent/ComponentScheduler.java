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
package tech.kwik.core.concurrent;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Delayed;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * One component's view of a shared executor. {@link #shutdown()} cancels this component's pending tasks and discards
 * any submitted later, as the components' own executors do with their discard policy, but leaves the shared executor
 * running.
 */
public final class ComponentScheduler extends AbstractExecutorService implements ScheduledExecutorService {

    private static final int PURGE_THRESHOLD = 32;

    private final ScheduledExecutorService shared;
    private final Set<Future<?>> pending = ConcurrentHashMap.newKeySet();
    private volatile boolean shutdown;

    public ComponentScheduler(ScheduledExecutorService shared) {
        this.shared = shared;
    }

    @Override
    public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
        if (shutdown) {
            return CancelledFuture.INSTANCE;
        }
        return track(shared.schedule(guard(command), delay, unit));
    }

    @Override
    public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) {
        if (shutdown) {
            return CancelledFuture.instance();
        }
        return track(shared.schedule(() -> shutdown? null: callable.call(), delay, unit));
    }

    @Override
    public ScheduledFuture<?> scheduleAtFixedRate(Runnable command, long initialDelay, long period, TimeUnit unit) {
        if (shutdown) {
            return CancelledFuture.INSTANCE;
        }
        return track(shared.scheduleAtFixedRate(guard(command), initialDelay, period, unit));
    }

    @Override
    public ScheduledFuture<?> scheduleWithFixedDelay(Runnable command, long initialDelay, long delay, TimeUnit unit) {
        if (shutdown) {
            return CancelledFuture.INSTANCE;
        }
        return track(shared.scheduleWithFixedDelay(guard(command), initialDelay, delay, unit));
    }

    @Override
    public void execute(Runnable command) {
        if (! shutdown) {
            shared.execute(guard(command));
        }
    }

    @Override
    public void shutdown() {
        shutdown = true;
        for (Future<?> future : pending) {
            future.cancel(false);
        }
        pending.clear();
    }

    @Override
    public List<Runnable> shutdownNow() {
        shutdown();
        return Collections.emptyList();
    }

    @Override
    public boolean isShutdown() {
        return shutdown;
    }

    @Override
    public boolean isTerminated() {
        return shutdown;
    }

    @Override
    public boolean awaitTermination(long timeout, TimeUnit unit) {
        return shutdown;
    }

    /** A task already handed to the shared executor must not run once this component is shut down. */
    private Runnable guard(Runnable command) {
        return () -> {
            if (! shutdown) {
                command.run();
            }
        };
    }

    private <F extends Future<?>> F track(F future) {
        if (pending.size() >= PURGE_THRESHOLD) {
            pending.removeIf(Future::isDone);
        }
        pending.add(future);
        if (shutdown) {
            // Lost a race with shutdown()
            future.cancel(false);
            pending.remove(future);
        }
        return future;
    }

    private static final class CancelledFuture<V> implements ScheduledFuture<V> {

        static final CancelledFuture<Object> INSTANCE = new CancelledFuture<>();

        @SuppressWarnings("unchecked")
        static <V> CancelledFuture<V> instance() {
            return (CancelledFuture<V>) INSTANCE;
        }

        @Override
        public long getDelay(TimeUnit unit) {
            return 0;
        }

        @Override
        public int compareTo(Delayed other) {
            return Long.compare(0, other.getDelay(TimeUnit.NANOSECONDS));
        }

        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            return false;
        }

        @Override
        public boolean isCancelled() {
            return true;
        }

        @Override
        public boolean isDone() {
            return true;
        }

        @Override
        public V get() throws ExecutionException {
            throw new java.util.concurrent.CancellationException();
        }

        @Override
        public V get(long timeout, TimeUnit unit) throws ExecutionException {
            throw new java.util.concurrent.CancellationException();
        }
    }
}
