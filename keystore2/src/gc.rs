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

//! This module implements the key garbage collector.
//! The key garbage collector has one public function `notify_gc()`. This will create
//! a thread on demand which will query the database for unreferenced key entries,
//! optionally dispose of sensitive key material appropriately, and then delete
//! the key entry from the database.

use crate::{
    async_task,
    database::{KeystoreDB, Uuid},
    super_key::SuperKeyManager,
};
use anyhow::{Context, Result};
use async_task::AsyncTask;
use std::sync::Arc;

pub struct Gc {
    async_task: Arc<AsyncTask>,
}

impl Gc {
    /// Creates a garbage collector using the given async_task.
    /// The garbage collector needs a function to invalidate key blobs and a database connection.
    /// Both are obtained from the init function. The function is only called if this is first
    /// time a garbage collector was initialized with the given AsyncTask instance.
    pub fn new_init_with<F>(async_task: Arc<AsyncTask>, init: F) -> Self
    where
        F: FnOnce() -> (
                Box<dyn Fn(&Uuid, &[u8]) -> Result<()> + Send + 'static>,
                KeystoreDB,
                Arc<SuperKeyManager>,
            ) + Send
            + 'static,
    {
        let weak_at = Arc::downgrade(&async_task);
        // Initialize the task's shelf.
        async_task.queue_hi(move |shelf| {
            let (invalidate_key, db, super_key) = init();
            shelf.get_or_put_with(|| GcInternal {
                blob_id_to_delete: None,
                invalidate_key,
                db,
                async_task: weak_at,
                super_key,
            });
        });
        Self { async_task }
    }

    /// Notifies the key garbage collector to iterate through orphaned and superseded blobs and
    /// attempts their deletion. We only process one key at a time and then schedule another
    /// attempt by queueing it in the async_task (low priority) queue.
    pub fn notify_gc(&self) {
        self.async_task.queue_lo(|shelf| shelf.get_downcast_mut::<GcInternal>().unwrap().step())
    }
}

struct GcInternal {
    blob_id_to_delete: Option<i64>,
    invalidate_key: Box<dyn Fn(&Uuid, &[u8]) -> Result<()> + Send + 'static>,
    db: KeystoreDB,
    async_task: std::sync::Weak<AsyncTask>,
    super_key: Arc<SuperKeyManager>,
}

impl GcInternal {
    /// Attempts to process one blob from the database.
    /// We process one key at a time, because deleting a key is a time consuming process which
    /// may involve calling into the KeyMint backend and we don't want to hog neither the backend
    /// nor the database for extended periods of time.
    fn process_one_key(&mut self) -> Result<()> {
        if let Some((blob_id, blob, blob_metadata)) = self
            .db
            .handle_next_superseded_blob(self.blob_id_to_delete.take())
            .context("In process_one_key: Trying to handle superseded blob.")?
        {
            // Set the blob_id as the next to be deleted blob. So it will be
            // removed from the database regardless of whether the following
            // succeeds or not.
            self.blob_id_to_delete = Some(blob_id);

            // If the key has a km_uuid we try to get the corresponding device
            // and delete the key, unwrapping if necessary and possible.
            // (At this time keys may get deleted without having the super encryption
            // key in this case we can only delete the key from the database.)
            if let Some(uuid) = blob_metadata.km_uuid() {
                let blob = self
                    .super_key
                    .unwrap_key_if_required(&blob_metadata, &blob)
                    .context("In process_one_key: Trying to unwrap to-be-deleted blob.")?;
                (self.invalidate_key)(&uuid, &*blob)
                    .context("In process_one_key: Trying to invalidate key.")?;
            }
        }
        Ok(())
    }

    /// Processes one key and then schedules another attempt until it runs out of blobs to delete.
    fn step(&mut self) {
        if let Err(e) = self.process_one_key() {
            log::error!("Error trying to delete blob entry. {:?}", e);
        }
        // Schedule the next step. This gives high priority requests a chance to interleave.
        if self.blob_id_to_delete.is_some() {
            if let Some(at) = self.async_task.upgrade() {
                at.queue_lo(move |shelf| shelf.get_downcast_mut::<GcInternal>().unwrap().step());
            }
        }
    }
}
