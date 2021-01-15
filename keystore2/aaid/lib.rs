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

//! Rust binding for getting the attestation application id.

use keystore2_aaid_bindgen::{
    aaid_keystore_attestation_id, KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE,
};

/// Returns the attestation application id for the given uid or an error code
/// corresponding to ::android::status_t.
pub fn get_aaid(uid: u32) -> Result<Vec<u8>, u32> {
    let mut buffer = [0u8; KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE];
    let mut size = KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE;
    // Safety:
    // aaid_keystore_attestation_id expects a buffer of exactly
    // KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE bytes and returns the number of bytes written
    // in the second pointer argument.
    let status = unsafe { aaid_keystore_attestation_id(uid, buffer.as_mut_ptr(), &mut size) };
    match status {
        0 => Ok(buffer[0..size as usize].to_vec()),
        status => Err(status),
    }
}
