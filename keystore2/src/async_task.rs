// Copyright 2020, The Android Open Source Project
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

//! This module implements the handling of async tasks.
//! The worker thread has a high priority and a low priority queue. Adding a job to either
//! will cause one thread to be spawned if none exists. As a compromise between performance
//! and resource consumption, the thread will linger for about 30 seconds after it has
//! processed all tasks before it terminates.
//! Note that low priority tasks are processed only when the high priority queue is empty.

use std::time::Duration;
use std::{
    collections::VecDeque,
    sync::Arc,
    sync::{Condvar, Mutex, MutexGuard},
    thread,
};

#[derive(Debug, PartialEq, Eq)]
enum State {
    Exiting,
    Running,
}

struct AsyncTaskState {
    state: State,
    thread: Option<thread::JoinHandle<()>>,
    hi_prio_req: VecDeque<Box<dyn FnOnce() + Send>>,
    lo_prio_req: VecDeque<Box<dyn FnOnce() + Send>>,
}

/// AsyncTask spawns one worker thread on demand to process jobs inserted into
/// a low and a high priority work queue.
pub struct AsyncTask {
    state: Arc<(Condvar, Mutex<AsyncTaskState>)>,
}

impl Default for AsyncTask {
    fn default() -> Self {
        Self {
            state: Arc::new((
                Condvar::new(),
                Mutex::new(AsyncTaskState {
                    state: State::Exiting,
                    thread: None,
                    hi_prio_req: VecDeque::new(),
                    lo_prio_req: VecDeque::new(),
                }),
            )),
        }
    }
}

impl AsyncTask {
    /// Adds a job to the high priority queue. High priority jobs are completed before
    /// low priority jobs and can also overtake low priority jobs. But they cannot
    /// preempt them.
    pub fn queue_hi<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.queue(f, true)
    }

    /// Adds a job to the low priority queue. Low priority jobs are completed after
    /// high priority. And they are not executed as long as high priority jobs are
    /// present. Jobs always run to completion and are never preempted by high
    /// priority jobs.
    pub fn queue_lo<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.queue(f, false)
    }

    fn queue<F>(&self, f: F, hi_prio: bool)
    where
        F: FnOnce() + Send + 'static,
    {
        let (ref condvar, ref state) = *self.state;
        let mut state = state.lock().unwrap();
        if hi_prio {
            state.hi_prio_req.push_back(Box::new(f));
        } else {
            state.lo_prio_req.push_back(Box::new(f));
        }

        if state.state != State::Running {
            self.spawn_thread(&mut state);
        }
        drop(state);
        condvar.notify_all();
    }

    fn spawn_thread(&self, state: &mut MutexGuard<AsyncTaskState>) {
        if let Some(t) = state.thread.take() {
            t.join().expect("AsyncTask panicked.");
        }

        let cloned_state = self.state.clone();

        state.thread = Some(thread::spawn(move || {
            let (ref condvar, ref state) = *cloned_state;
            loop {
                if let Some(f) = {
                    let (mut state, timeout) = condvar
                        .wait_timeout_while(
                            state.lock().unwrap(),
                            Duration::from_secs(30),
                            |state| state.hi_prio_req.is_empty() && state.lo_prio_req.is_empty(),
                        )
                        .unwrap();
                    match (
                        state.hi_prio_req.pop_front(),
                        state.lo_prio_req.is_empty(),
                        timeout.timed_out(),
                    ) {
                        (Some(f), _, _) => Some(f),
                        (None, false, _) => state.lo_prio_req.pop_front(),
                        (None, true, true) => {
                            state.state = State::Exiting;
                            break;
                        }
                        (None, true, false) => None,
                    }
                } {
                    f()
                }
            }
        }));
        state.state = State::Running;
    }
}
