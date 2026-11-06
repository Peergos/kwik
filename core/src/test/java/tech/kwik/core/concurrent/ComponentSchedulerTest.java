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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class ComponentSchedulerTest {

    private ScheduledExecutorService shared;

    @BeforeEach
    void createSharedExecutor() {
        shared = Executors.newSingleThreadScheduledExecutor();
    }

    @AfterEach
    void shutdownSharedExecutor() {
        shared.shutdownNow();
    }

    @Test
    void tasksRunOnTheSharedExecutor() throws Exception {
        ComponentScheduler scheduler = new ComponentScheduler(shared);
        Thread sharedThread = shared.submit(Thread::currentThread).get();
        Thread[] ranOn = new Thread[2];
        CountDownLatch done = new CountDownLatch(2);

        scheduler.execute(() -> { ranOn[0] = Thread.currentThread(); done.countDown(); });
        scheduler.schedule(() -> { ranOn[1] = Thread.currentThread(); done.countDown(); }, 1, TimeUnit.MILLISECONDS);

        assertThat(done.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(ranOn).containsOnly(sharedThread);
    }

    @Test
    void shutdownCancelsOnlyThisComponentsTasks() throws Exception {
        ComponentScheduler first = new ComponentScheduler(shared);
        ComponentScheduler second = new ComponentScheduler(shared);
        AtomicInteger firstRuns = new AtomicInteger();
        CountDownLatch secondRan = new CountDownLatch(1);

        ScheduledFuture<?> pending = first.schedule(firstRuns::incrementAndGet, 50, TimeUnit.MILLISECONDS);
        second.schedule(secondRan::countDown, 50, TimeUnit.MILLISECONDS);
        first.shutdown();

        assertThat(secondRan.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(pending.isCancelled()).isTrue();
        assertThat(firstRuns.get()).isEqualTo(0);
        assertThat(shared.isShutdown()).isFalse();
    }

    @Test
    void shutdownStopsRepeatingTasks() throws Exception {
        ComponentScheduler scheduler = new ComponentScheduler(shared);
        AtomicInteger runs = new AtomicInteger();
        CountDownLatch ranTwice = new CountDownLatch(2);

        scheduler.scheduleAtFixedRate(() -> { runs.incrementAndGet(); ranTwice.countDown(); }, 0, 5, TimeUnit.MILLISECONDS);
        assertThat(ranTwice.await(5, TimeUnit.SECONDS)).isTrue();
        scheduler.shutdown();
        // Let a run that was already started finish
        shared.submit(() -> {}).get();
        int afterShutdown = runs.get();
        Thread.sleep(50);

        assertThat(runs.get()).isEqualTo(afterShutdown);
    }

    @Test
    void tasksSubmittedAfterShutdownAreDiscarded() throws Exception {
        ComponentScheduler scheduler = new ComponentScheduler(shared);
        AtomicInteger runs = new AtomicInteger();
        scheduler.shutdown();

        scheduler.execute(runs::incrementAndGet);
        ScheduledFuture<?> scheduled = scheduler.schedule(runs::incrementAndGet, 0, TimeUnit.MILLISECONDS);
        shared.schedule(() -> {}, 20, TimeUnit.MILLISECONDS).get();

        assertThat(runs.get()).isEqualTo(0);
        assertThat(scheduled.isCancelled()).isTrue();
        assertThat(scheduler.isShutdown()).isTrue();
    }

    @Test
    void taskAlreadyQueuedOnSharedExecutorDoesNotRunAfterShutdown() throws Exception {
        ComponentScheduler scheduler = new ComponentScheduler(shared);
        AtomicInteger runs = new AtomicInteger();
        CountDownLatch blockShared = new CountDownLatch(1);

        shared.execute(() -> { try { blockShared.await(); } catch (InterruptedException e) {} });
        scheduler.execute(runs::incrementAndGet);
        scheduler.shutdown();
        blockShared.countDown();
        shared.submit(() -> {}).get();

        assertThat(runs.get()).isEqualTo(0);
    }

    @Test
    void threadedModeUsesTheComponentsOwnExecutor() {
        ScheduledExecutorService own = Executors.newSingleThreadScheduledExecutor();
        try {
            assertThat(ConnectionExecutor.threaded().scheduler(() -> own)).isSameAs(own);
            assertThat(ConnectionExecutor.shared(shared).scheduler(() -> own)).isInstanceOf(ComponentScheduler.class);
        }
        finally {
            own.shutdownNow();
        }
    }
}
