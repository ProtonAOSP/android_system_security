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

//TODO: remove this after implementing the methods.
#![allow(dead_code)]

//! This is the Keystore 2.0 Enforcements module.
// TODO: more description to follow.
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::HardwareAuthToken::HardwareAuthToken;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Enforcements data structure
pub struct Enforcements {
    // This hash set contains the user ids for whom the device is currently unlocked. If a user id
    // is not in the set, it implies that the device is locked for the user.
    device_unlocked_set: Mutex<HashSet<i32>>,
    // This maps the operation challenge to an optional auth token, to maintain op-auth tokens
    // in-memory, until they are picked up and given to the operation by authorise_update_finish().
    op_auth_map: Mutex<HashMap<i64, Option<HardwareAuthToken>>>,
}

impl Enforcements {
    /// Creates an enforcement object with the two data structures it holds.
    pub fn new() -> Self {
        Enforcements {
            device_unlocked_set: Mutex::new(HashSet::new()),
            op_auth_map: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for Enforcements {
    fn default() -> Self {
        Self::new()
    }
}

//TODO: Add tests to enforcement module (b/175578618).
