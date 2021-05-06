// Copyright 2021, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Can be removed when instrumentations are added to keystore.
#![allow(dead_code)]

//! This module implements a watchdog thread.

use std::{
    cmp::min,
    collections::HashMap,
    sync::Arc,
    sync::{Condvar, Mutex, MutexGuard},
    thread,
};
use std::{
    marker::PhantomData,
    time::{Duration, Instant},
};

/// Represents a Watchdog record. It can be created with `Watchdog::watch` or
/// `Watchdog::watch_with`. It disarms the record when dropped.
pub struct WatchPoint {
    id: &'static str,
    wd: Arc<Watchdog>,
    not_send: PhantomData<*mut ()>, // WatchPoint must not be Send.
}

impl Drop for WatchPoint {
    fn drop(&mut self) {
        self.wd.disarm(self.id)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    NotRunning,
    Running,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct Index {
    tid: thread::ThreadId,
    id: &'static str,
}

struct Record {
    started: Instant,
    deadline: Instant,
    callback: Option<Box<dyn Fn() -> String + Send + 'static>>,
}

struct WatchdogState {
    state: State,
    thread: Option<thread::JoinHandle<()>>,
    timeout: Duration,
    records: HashMap<Index, Record>,
    has_overdue: bool,
}

impl WatchdogState {
    fn update_overdue_and_find_next_timeout(&mut self) -> Option<Duration> {
        let now = Instant::now();
        let mut next_timeout: Option<Duration> = None;
        self.has_overdue = false;
        for (_, r) in self.records.iter() {
            let timeout = r.deadline.saturating_duration_since(now);
            if timeout == Duration::new(0, 0) {
                self.has_overdue = true;
                continue;
            }
            next_timeout = match next_timeout {
                Some(nt) => {
                    if timeout < nt {
                        Some(timeout)
                    } else {
                        Some(nt)
                    }
                }
                None => Some(timeout),
            };
        }
        next_timeout
    }

    fn log_report(&self) -> bool {
        if !self.has_overdue {
            return false;
        }
        log::warn!("Keystore Watchdog report:");
        log::warn!("Overdue records:");
        let now = Instant::now();
        for (i, r) in self.records.iter() {
            if r.deadline.saturating_duration_since(now) == Duration::new(0, 0) {
                match &r.callback {
                    Some(cb) => {
                        log::warn!(
                            "{:?} {} Pending: {:?} Overdue {:?}: {}",
                            i.tid,
                            i.id,
                            r.started.elapsed(),
                            r.deadline.elapsed(),
                            (cb)()
                        );
                    }
                    None => {
                        log::warn!(
                            "{:?} {} Pending: {:?} Overdue {:?}",
                            i.tid,
                            i.id,
                            r.started.elapsed(),
                            r.deadline.elapsed()
                        );
                    }
                }
            }
        }
        true
    }

    fn disarm(&mut self, index: Index) {
        self.records.remove(&index);
    }

    fn arm(&mut self, index: Index, record: Record) {
        if self.records.insert(index.clone(), record).is_some() {
            log::warn!("Recursive watchdog record at \"{:?}\" replaces previous record.", index);
        }
    }
}

/// Watchdog spawns a thread that logs records of all overdue watch points when a deadline
/// is missed and at least every second as long as overdue watch points exist.
/// The thread terminates when idle for a given period of time.
pub struct Watchdog {
    state: Arc<(Condvar, Mutex<WatchdogState>)>,
}

impl Watchdog {
    /// If we have overdue records, we want to be noisy about it and log a report
    /// at least every `NOISY_REPORT_TIMEOUT` interval.
    const NOISY_REPORT_TIMEOUT: Duration = Duration::from_secs(1);

    /// Construct a [`Watchdog`]. When `timeout` has elapsed since the watchdog thread became
    /// idle, i.e., there are no more active or overdue watch points, the watchdog thread
    /// terminates.
    pub fn new(timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new((
                Condvar::new(),
                Mutex::new(WatchdogState {
                    state: State::NotRunning,
                    thread: None,
                    timeout,
                    records: HashMap::new(),
                    has_overdue: false,
                }),
            )),
        })
    }

    fn watch_with_optional(
        wd: &Arc<Self>,
        callback: Option<Box<dyn Fn() -> String + Send + 'static>>,
        id: &'static str,
        timeout: Duration,
    ) -> Option<WatchPoint> {
        let deadline = Instant::now().checked_add(timeout);
        if deadline.is_none() {
            log::warn!("Deadline computation failed for WatchPoint \"{}\"", id);
            log::warn!("WatchPoint not armed.");
            return None;
        }
        wd.arm(callback, id, deadline.unwrap());
        Some(WatchPoint { id, wd: wd.clone(), not_send: Default::default() })
    }

    /// Create a new watch point. If the WatchPoint is not dropped before the timeout
    /// expires, a report is logged at least every second, which includes the id string
    /// and whatever string the callback returns.
    pub fn watch_with(
        wd: &Arc<Self>,
        id: &'static str,
        timeout: Duration,
        callback: impl Fn() -> String + Send + 'static,
    ) -> Option<WatchPoint> {
        Self::watch_with_optional(wd, Some(Box::new(callback)), id, timeout)
    }

    /// Like `watch_with`, but without a callback.
    pub fn watch(wd: &Arc<Self>, id: &'static str, timeout: Duration) -> Option<WatchPoint> {
        Self::watch_with_optional(wd, None, id, timeout)
    }

    fn arm(
        &self,
        callback: Option<Box<dyn Fn() -> String + Send + 'static>>,
        id: &'static str,
        deadline: Instant,
    ) {
        let tid = thread::current().id();
        let index = Index { tid, id };
        let record = Record { started: Instant::now(), deadline, callback };

        let (ref condvar, ref state) = *self.state;

        let mut state = state.lock().unwrap();
        state.arm(index, record);

        if state.state != State::Running {
            self.spawn_thread(&mut state);
        }
        drop(state);
        condvar.notify_all();
    }

    fn disarm(&self, id: &'static str) {
        let tid = thread::current().id();
        let index = Index { tid, id };
        let (_, ref state) = *self.state;

        let mut state = state.lock().unwrap();
        state.disarm(index);
        // There is no need to notify condvar. There is no action required for the
        // watchdog thread before the next deadline.
    }

    fn spawn_thread(&self, state: &mut MutexGuard<WatchdogState>) {
        if let Some(t) = state.thread.take() {
            t.join().expect("Watchdog thread panicked.");
        }

        let cloned_state = self.state.clone();

        state.thread = Some(thread::spawn(move || {
            let (ref condvar, ref state) = *cloned_state;

            let mut state = state.lock().unwrap();

            loop {
                let next_timeout = state.update_overdue_and_find_next_timeout();
                let has_overdue = state.log_report();
                let (next_timeout, idle) = match (has_overdue, next_timeout) {
                    (true, Some(next_timeout)) => {
                        (min(next_timeout, Self::NOISY_REPORT_TIMEOUT), false)
                    }
                    (false, Some(next_timeout)) => (next_timeout, false),
                    (true, None) => (Self::NOISY_REPORT_TIMEOUT, false),
                    (false, None) => (state.timeout, true),
                };

                let (s, timeout) = condvar.wait_timeout(state, next_timeout).unwrap();
                state = s;

                if idle && timeout.timed_out() && state.records.is_empty() {
                    state.state = State::NotRunning;
                    break;
                }
            }
        }));
        state.state = State::Running;
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::sync::atomic;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_watchdog() {
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("keystore2_watchdog_tests")
                .with_min_level(log::Level::Debug),
        );

        let wd = Watchdog::new(Watchdog::NOISY_REPORT_TIMEOUT.checked_mul(3).unwrap());
        let hit_count = Arc::new(atomic::AtomicU8::new(0));
        let hit_count_clone = hit_count.clone();
        let wp =
            Watchdog::watch_with(&wd, "test_watchdog", Duration::from_millis(100), move || {
                format!("hit_count: {}", hit_count_clone.fetch_add(1, atomic::Ordering::Relaxed))
            });
        assert_eq!(0, hit_count.load(atomic::Ordering::Relaxed));
        thread::sleep(Duration::from_millis(500));
        assert_eq!(1, hit_count.load(atomic::Ordering::Relaxed));
        thread::sleep(Watchdog::NOISY_REPORT_TIMEOUT);
        assert_eq!(2, hit_count.load(atomic::Ordering::Relaxed));
        drop(wp);
        thread::sleep(Watchdog::NOISY_REPORT_TIMEOUT.checked_mul(4).unwrap());
        assert_eq!(2, hit_count.load(atomic::Ordering::Relaxed));
        let (_, ref state) = *wd.state;
        let state = state.lock().unwrap();
        assert_eq!(state.state, State::NotRunning);
    }
}
