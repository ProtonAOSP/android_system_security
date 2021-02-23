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

use std::{any::Any, any::TypeId, time::Duration};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    sync::{Condvar, Mutex, MutexGuard},
    thread,
};

#[derive(Debug, PartialEq, Eq)]
enum State {
    Exiting,
    Running,
}

/// The Shelf allows async tasks to store state across invocations.
/// Note: Store elves at your own peril ;-).
#[derive(Debug, Default)]
pub struct Shelf(HashMap<TypeId, Box<dyn Any + Send>>);

impl Shelf {
    /// Get a reference to the shelved data of type T. Returns Some if the data exists.
    pub fn get_downcast_ref<T: Any + Send>(&self) -> Option<&T> {
        self.0.get(&TypeId::of::<T>()).and_then(|v| v.downcast_ref::<T>())
    }

    /// Get a mutable reference to the shelved data of type T. If a T was inserted using put,
    /// get_mut, or get_or_put_with.
    pub fn get_downcast_mut<T: Any + Send>(&mut self) -> Option<&mut T> {
        self.0.get_mut(&TypeId::of::<T>()).and_then(|v| v.downcast_mut::<T>())
    }

    /// Remove the entry of the given type and returns the stored data if it existed.
    pub fn remove_downcast_ref<T: Any + Send>(&mut self) -> Option<T> {
        self.0.remove(&TypeId::of::<T>()).and_then(|v| v.downcast::<T>().ok().map(|b| *b))
    }

    /// Puts data `v` on the shelf. If there already was an entry of type T it is returned.
    pub fn put<T: Any + Send>(&mut self, v: T) -> Option<T> {
        self.0
            .insert(TypeId::of::<T>(), Box::new(v) as Box<dyn Any + Send>)
            .and_then(|v| v.downcast::<T>().ok().map(|b| *b))
    }

    /// Gets a mutable reference to the entry of the given type and default creates it if necessary.
    /// The type must implement Default.
    pub fn get_mut<T: Any + Send + Default>(&mut self) -> &mut T {
        self.0
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Box::new(T::default()) as Box<dyn Any + Send>)
            .downcast_mut::<T>()
            .unwrap()
    }

    /// Gets a mutable reference to the entry of the given type or creates it using the init
    /// function. Init is not executed if the entry already existed.
    pub fn get_or_put_with<T: Any + Send, F>(&mut self, init: F) -> &mut T
    where
        F: FnOnce() -> T,
    {
        self.0
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Box::new(init()) as Box<dyn Any + Send>)
            .downcast_mut::<T>()
            .unwrap()
    }
}

struct AsyncTaskState {
    state: State,
    thread: Option<thread::JoinHandle<()>>,
    hi_prio_req: VecDeque<Box<dyn FnOnce(&mut Shelf) + Send>>,
    lo_prio_req: VecDeque<Box<dyn FnOnce(&mut Shelf) + Send>>,
    /// The store allows tasks to store state across invocations. It is passed to each invocation
    /// of each task. Tasks need to cooperate on the ids they use for storing state.
    shelf: Option<Shelf>,
}

/// AsyncTask spawns one worker thread on demand to process jobs inserted into
/// a low and a high priority work queue. The queues are processed FIFO, and low
/// priority queue is processed if the high priority queue is empty.
/// Note: Because there is only one worker thread at a time for a given AsyncTask instance,
/// all scheduled requests are guaranteed to be serialized with respect to one another.
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
                    shelf: None,
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
        F: for<'r> FnOnce(&'r mut Shelf) + Send + 'static,
    {
        self.queue(f, true)
    }

    /// Adds a job to the low priority queue. Low priority jobs are completed after
    /// high priority. And they are not executed as long as high priority jobs are
    /// present. Jobs always run to completion and are never preempted by high
    /// priority jobs.
    pub fn queue_lo<F>(&self, f: F)
    where
        F: FnOnce(&mut Shelf) + Send + 'static,
    {
        self.queue(f, false)
    }

    fn queue<F>(&self, f: F, hi_prio: bool)
    where
        F: for<'r> FnOnce(&'r mut Shelf) + Send + 'static,
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
            // When the worker starts, it takes the shelf and puts it on the stack.
            let mut shelf = state.lock().unwrap().shelf.take().unwrap_or_default();
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
                            // When the worker exits it puts the shelf back into the shared
                            // state for the next worker to use. So state is preserved not
                            // only across invocations but also across worker thread shut down.
                            state.shelf = Some(shelf);
                            state.state = State::Exiting;
                            break;
                        }
                        (None, true, false) => None,
                    }
                } {
                    f(&mut shelf)
                }
            }
        }));
        state.state = State::Running;
    }
}

#[cfg(test)]
mod tests {
    use super::{AsyncTask, Shelf};
    use std::sync::mpsc::channel;

    #[test]
    fn test_shelf() {
        let mut shelf = Shelf::default();

        let s = "A string".to_string();
        assert_eq!(shelf.put(s), None);

        let s2 = "Another string".to_string();
        assert_eq!(shelf.put(s2), Some("A string".to_string()));

        // Put something of a different type on the shelf.
        #[derive(Debug, PartialEq, Eq)]
        struct Elf {
            pub name: String,
        }
        let e1 = Elf { name: "Glorfindel".to_string() };
        assert_eq!(shelf.put(e1), None);

        // The String value is still on the shelf.
        let s3 = shelf.get_downcast_ref::<String>().unwrap();
        assert_eq!(s3, "Another string");

        // As is the Elf.
        {
            let e2 = shelf.get_downcast_mut::<Elf>().unwrap();
            assert_eq!(e2.name, "Glorfindel");
            e2.name = "Celeborn".to_string();
        }

        // Take the Elf off the shelf.
        let e3 = shelf.remove_downcast_ref::<Elf>().unwrap();
        assert_eq!(e3.name, "Celeborn");

        assert_eq!(shelf.remove_downcast_ref::<Elf>(), None);

        // No u64 value has been put on the shelf, so getting one gives the default value.
        {
            let i = shelf.get_mut::<u64>();
            assert_eq!(*i, 0);
            *i = 42;
        }
        let i2 = shelf.get_downcast_ref::<u64>().unwrap();
        assert_eq!(*i2, 42);

        // No i32 value has ever been seen near the shelf.
        assert_eq!(shelf.get_downcast_ref::<i32>(), None);
        assert_eq!(shelf.get_downcast_mut::<i32>(), None);
        assert_eq!(shelf.remove_downcast_ref::<i32>(), None);
    }

    #[test]
    fn test_async_task() {
        let at = AsyncTask::default();

        // First queue up a job that blocks until we release it, to avoid
        // unpredictable synchronization.
        let (start_sender, start_receiver) = channel();
        at.queue_hi(move |shelf| {
            start_receiver.recv().unwrap();
            // Put a trace vector on the shelf
            shelf.put(Vec::<String>::new());
        });

        // Queue up some high-priority and low-priority jobs.
        for i in 0..3 {
            let j = i;
            at.queue_lo(move |shelf| {
                let trace = shelf.get_mut::<Vec<String>>();
                trace.push(format!("L{}", j));
            });
            let j = i;
            at.queue_hi(move |shelf| {
                let trace = shelf.get_mut::<Vec<String>>();
                trace.push(format!("H{}", j));
            });
        }

        // Finally queue up a low priority job that emits the trace.
        let (trace_sender, trace_receiver) = channel();
        at.queue_lo(move |shelf| {
            let trace = shelf.get_downcast_ref::<Vec<String>>().unwrap();
            trace_sender.send(trace.clone()).unwrap();
        });

        // Ready, set, go.
        start_sender.send(()).unwrap();
        let trace = trace_receiver.recv().unwrap();

        assert_eq!(trace, vec!["H0", "H1", "H2", "L0", "L1", "L2"]);
    }

    #[test]
    #[should_panic]
    fn test_async_task_panic() {
        let at = AsyncTask::default();
        at.queue_hi(|_shelf| {
            panic!("Panic from queued job");
        });
        // Queue another job afterwards to ensure that the async thread gets joined.
        let (done_sender, done_receiver) = channel();
        at.queue_hi(move |_shelf| {
            done_sender.send(()).unwrap();
        });
        done_receiver.recv().unwrap();
    }
}
