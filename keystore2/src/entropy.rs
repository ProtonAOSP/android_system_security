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

//! This module holds functionality for retrieving and distributing entropy.

use anyhow::{Context, Result};
use log::error;
use std::time::{Duration, Instant};

static ENTROPY_SIZE: usize = 64;
static MIN_FEED_INTERVAL_SECS: u64 = 30;

#[derive(Default)]
struct FeederInfo {
    last_feed: Option<Instant>,
}

/// Register the entropy feeder as an idle callback.
pub fn register_feeder() {
    crate::globals::ASYNC_TASK.add_idle(|shelf| {
        let mut info = shelf.get_mut::<FeederInfo>();
        let now = Instant::now();
        let feed_needed = match info.last_feed {
            None => true,
            Some(last) => now.duration_since(last) > Duration::from_secs(MIN_FEED_INTERVAL_SECS),
        };
        if feed_needed {
            info.last_feed = Some(now);
            feed_devices();
        }
    });
}

fn get_entropy(size: usize) -> Result<Vec<u8>> {
    keystore2_crypto::generate_random_data(size).context("Retrieving entropy for KeyMint device")
}

/// Feed entropy to all known KeyMint devices.
pub fn feed_devices() {
    let km_devs = crate::globals::get_keymint_devices();
    if km_devs.is_empty() {
        return;
    }
    let data = match get_entropy(km_devs.len() * ENTROPY_SIZE) {
        Ok(data) => data,
        Err(e) => {
            error!(
                "Failed to retrieve {}*{} bytes of entropy: {:?}",
                km_devs.len(),
                ENTROPY_SIZE,
                e
            );
            return;
        }
    };
    for (i, km_dev) in km_devs.iter().enumerate() {
        let offset = i * ENTROPY_SIZE;
        let sub_data = &data[offset..(offset + ENTROPY_SIZE)];
        if let Err(e) = km_dev.addRngEntropy(sub_data) {
            error!("Failed to feed entropy to KeyMint device: {:?}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_entropy_size() {
        for size in &[0, 1, 4, 8, 256, 4096] {
            let data = get_entropy(*size).expect("failed to get entropy");
            assert_eq!(data.len(), *size);
        }
    }
    #[test]
    fn test_entropy_uniqueness() {
        let count = 10;
        let mut seen = HashSet::new();
        for _i in 0..count {
            let data = get_entropy(16).expect("failed to get entropy");
            seen.insert(data);
        }
        assert_eq!(seen.len(), count);
    }
}
