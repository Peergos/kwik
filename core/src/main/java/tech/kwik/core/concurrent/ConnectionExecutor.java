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

import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Supplier;

/**
 * Where a connection's timers and callbacks run. Threaded (the default), each component creates its own executor
 * thread. Shared, all of them run on one executor, e.g. a Netty event loop, and creating a connection starts no threads
 * for them. Each component then gets its own {@link ComponentScheduler} view, so that shutting a component down cancels
 * only its own tasks.
 */
public final class ConnectionExecutor {

    private static final ConnectionExecutor THREADED = new ConnectionExecutor(null);

    private final ScheduledExecutorService shared;

    private ConnectionExecutor(ScheduledExecutorService shared) {
        this.shared = shared;
    }

    public static ConnectionExecutor threaded() {
        return THREADED;
    }

    public static ConnectionExecutor shared(ScheduledExecutorService executor) {
        return new ConnectionExecutor(Objects.requireNonNull(executor));
    }

    public boolean isShared() {
        return shared != null;
    }

    /**
     * A new component view of the shared executor, for components that have no thread of their own to fall back on.
     * @throws IllegalStateException when not shared
     */
    public ScheduledExecutorService sharedScheduler() {
        if (shared == null) {
            throw new IllegalStateException("not shared");
        }
        return new ComponentScheduler(shared);
    }

    /**
     * @param own  creates the component's own executor, used when not shared
     */
    public ScheduledExecutorService scheduler(Supplier<? extends ScheduledExecutorService> own) {
        return shared == null? own.get(): new ComponentScheduler(shared);
    }

    /**
     * @param own  creates the component's own executor, used when not shared
     */
    public ExecutorService executor(Supplier<? extends ExecutorService> own) {
        return shared == null? own.get(): new ComponentScheduler(shared);
    }
}
