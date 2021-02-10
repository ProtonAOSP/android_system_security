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

use crate::globals::{get_keymint_dev_by_uuid, DB};
use crate::{error::map_km_error, globals::ASYNC_TASK};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::IKeyMintDevice::IKeyMintDevice;
use android_hardware_security_keymint::binder::Strong;
use anyhow::Result;

#[derive(Clone, Copy)]
pub struct Gc {
    remaining_tries: u32,
}

impl Gc {
    const MAX_ERROR_RETRIES: u32 = 3u32;

    /// Attempts to process one unreferenced key from the database.
    /// Returns Ok(true) if a key was deleted and Ok(false) if there were no more keys to process.
    /// We process one key at a time, because deleting a key is a time consuming process which
    /// may involve calling into the KeyMint backend and we don't want to hog neither the backend
    /// nor the database for extended periods of time.
    fn process_one_key() -> Result<bool> {
        DB.with(|db| {
            let mut db = db.borrow_mut();
            if let Some((key_id, mut key_entry)) = db.get_unreferenced_key()? {
                if let Some(blob) = key_entry.take_km_blob() {
                    let km_dev: Strong<dyn IKeyMintDevice> =
                        get_keymint_dev_by_uuid(key_entry.km_uuid())
                            .map(|(dev, _)| dev)?
                            .get_interface()?;
                    if let Err(e) = map_km_error(km_dev.deleteKey(&blob)) {
                        // Log but ignore error.
                        log::error!("Error trying to delete key. {:?}", e);
                    }
                }
                db.purge_key_entry(key_id)?;
                return Ok(true);
            }
            Ok(false)
        })
    }

    /// Processes one key and then schedules another attempt until it runs out of tries or keys
    /// to delete.
    fn process_all(mut self) {
        match Self::process_one_key() {
            // We successfully removed a key.
            Ok(true) => self.remaining_tries = Self::MAX_ERROR_RETRIES,
            // There were no more keys to remove. We may exit.
            Ok(false) => self.remaining_tries = 0,
            // An error occurred. We retry in case the error was transient, but
            // we also count down the number of tries so that we don't spin
            // indefinitely.
            Err(e) => {
                self.remaining_tries -= 1;
                log::error!(
                    concat!(
                        "Failed to delete key. Retrying in case this error was transient. ",
                        "(Tries remaining {}) {:?}"
                    ),
                    self.remaining_tries,
                    e
                )
            }
        }
        if self.remaining_tries != 0 {
            ASYNC_TASK.queue_lo(move || {
                self.process_all();
            })
        }
    }

    /// Notifies the key garbage collector to iterate through unreferenced keys and attempt
    /// their deletion. We only process one key at a time and then schedule another
    /// attempt by queueing it in the async_task (low priority) queue.
    pub fn notify_gc() {
        ASYNC_TASK.queue_lo(|| Self { remaining_tries: Self::MAX_ERROR_RETRIES }.process_all())
    }
}
