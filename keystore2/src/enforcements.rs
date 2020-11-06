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
use crate::auth_token_handler::AuthTokenHandler;
use crate::database::AuthTokenEntry;
use crate::error::Error as KeystoreError;
use crate::key_parameter::{KeyParameter, KeyParameterValue};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    ErrorCode::ErrorCode as Ec, HardwareAuthToken::HardwareAuthToken,
    HardwareAuthenticatorType::HardwareAuthenticatorType,
};
use android_system_keystore2::aidl::android::system::keystore2::OperationChallenge::OperationChallenge;
use anyhow::{Context, Result};
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

    /// Checks if update or finish calls are authorized. If the operation is based on per-op key,
    /// try to receive the auth token from the op_auth_map. We assume that by the time update/finish
    /// is called, the auth token has been delivered to keystore. Therefore, we do not wait for it
    /// and if the auth token is not found in the map, an error is returned.
    pub fn authorize_update_or_finish(
        &self,
        key_params: &[KeyParameter],
        op_challenge: Option<OperationChallenge>,
    ) -> Result<AuthTokenHandler> {
        let mut user_auth_type: Option<HardwareAuthenticatorType> = None;
        let mut user_secure_ids = Vec::<i64>::new();
        let mut is_timeout_key = false;

        for key_param in key_params.iter() {
            match key_param.key_parameter_value() {
                KeyParameterValue::NoAuthRequired => {
                    // unlike in authorize_create, we do not check if both NoAuthRequired and user
                    // secure id are present, because that is already checked in authorize_create.
                    return Ok(AuthTokenHandler::NoAuthRequired);
                }
                KeyParameterValue::AuthTimeout(_) => {
                    is_timeout_key = true;
                }
                KeyParameterValue::HardwareAuthenticatorType(a) => {
                    user_auth_type = Some(*a);
                }
                KeyParameterValue::UserSecureID(u) => {
                    user_secure_ids.push(*u);
                }
                _ => {}
            }
        }

        // If either of auth_type or secure_id is present and the other is not present,
        // authorize_create would have already returned error.
        // At this point, if UserSecureID is present and AuthTimeout is not present in
        // key parameters, per-op auth is required.
        // Obtain and validate the auth token.
        if !is_timeout_key && !user_secure_ids.is_empty() {
            let challenge =
                op_challenge.ok_or(KeystoreError::Km(Ec::KEY_USER_NOT_AUTHENTICATED)).context(
                    "In authorize_update_or_finish: Auth required, but operation challenge is not
                    present.",
                )?;
            let auth_type =
                user_auth_type.ok_or(KeystoreError::Km(Ec::KEY_USER_NOT_AUTHENTICATED)).context(
                    "In authorize_update_or_finish: Auth required, but authenticator type is not
                    present.",
                )?;
            // It is ok to unwrap here, because there is no way this lock can get poisoned and
            // and there is no way to recover if it is poisoned.
            let mut op_auth_map_guard = self.op_auth_map.lock().unwrap();
            let auth_entry = op_auth_map_guard.remove(&(challenge.challenge));

            match auth_entry {
                Some(Some(auth_token)) => {
                    if AuthTokenEntry::satisfies_auth(&auth_token, &user_secure_ids, auth_type) {
                        return Ok(AuthTokenHandler::Token(auth_token, None));
                    } else {
                        return Err(KeystoreError::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
                            .context("In authorize_update_or_finish: Auth token does not match.");
                    }
                }
                _ => {
                    // there was no auth token
                    return Err(KeystoreError::Km(Ec::KEY_USER_NOT_AUTHENTICATED)).context(
                        "In authorize_update_or_finish: Auth required, but an auth token
                        is not found for the given operation challenge, in the op_auth_map.",
                    );
                }
            }
        }

        // If we don't find HardwareAuthenticatorType and UserSecureID, we assume that
        // authentication is not required, because in legacy keys, authentication related
        // key parameters may not present.
        // TODO: METRICS: count how many times (if any) this code path is executed, in order
        // to identify if any such keys are in use
        Ok(AuthTokenHandler::NoAuthRequired)
    }
}

impl Default for Enforcements {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: Add tests to enforcement module (b/175578618).
