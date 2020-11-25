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

//! This is the Keystore 2.0 Enforcements module.
// TODO: more description to follow.
use crate::auth_token_handler::AuthTokenHandler;
use crate::background_task_handler::Message;
use crate::database::AuthTokenEntry;
use crate::error::Error as KeystoreError;
use crate::globals::DB;
use crate::key_parameter::{KeyParameter, KeyParameterValue};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, ErrorCode::ErrorCode as Ec, HardwareAuthToken::HardwareAuthToken,
    HardwareAuthenticatorType::HardwareAuthenticatorType, KeyPurpose::KeyPurpose,
    SecurityLevel::SecurityLevel, Tag::Tag, Timestamp::Timestamp,
    VerificationToken::VerificationToken,
};
use android_system_keystore2::aidl::android::system::keystore2::OperationChallenge::OperationChallenge;
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{channel, Sender};
use std::sync::Mutex;
use std::time::SystemTime;

/// Enforcements data structure
pub struct Enforcements {
    // This hash set contains the user ids for whom the device is currently unlocked. If a user id
    // is not in the set, it implies that the device is locked for the user.
    device_unlocked_set: Mutex<HashSet<i32>>,
    // This maps the operation challenge to an optional auth token, to maintain op-auth tokens
    // in-memory, until they are picked up and given to the operation by authorise_update_finish().
    op_auth_map: Mutex<HashMap<i64, Option<HardwareAuthToken>>>,
    // sender end of the channel via which the enforcement module communicates with the
    // background task handler (bth). This is of type Mutex in an Option because it is initialized
    // after the global enforcement object is created.
    sender_to_bth: Mutex<Option<Sender<Message>>>,
}

impl Enforcements {
    /// Creates an enforcement object with the two data structures it holds and the sender as None.
    pub fn new() -> Self {
        Enforcements {
            device_unlocked_set: Mutex::new(HashSet::new()),
            op_auth_map: Mutex::new(HashMap::new()),
            sender_to_bth: Mutex::new(None),
        }
    }

    /// Initialize the sender_to_bth field, using the given sender end of a channel.
    pub fn set_sender_to_bth(&self, sender: Sender<Message>) {
        // It is ok to unwrap here because there is no chance of poisoning this mutex.
        let mut sender_guard = self.sender_to_bth.lock().unwrap();
        *sender_guard = Some(sender);
    }

    /// Checks if update or finish calls are authorized. If the operation is based on per-op key,
    /// try to receive the auth token from the op_auth_map. We assume that by the time update/finish
    /// is called, the auth token has been delivered to keystore. Therefore, we do not wait for it
    /// and if the auth token is not found in the map, an error is returned.
    /// This method is called only during the first call to update or if finish is called right
    /// after create operation, because the operation caches the authorization decisions and tokens
    /// from previous calls to enforcement module.
    pub fn authorize_update_or_finish(
        &self,
        key_params: &[KeyParameter],
        op_challenge: Option<&OperationChallenge>,
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

    /// Checks if a create call is authorized, given key parameters and operation parameters.
    /// With regard to auth tokens, the following steps are taken:
    /// If the key is time-bound, find a matching auth token from the database.
    /// If the above step is successful, and if the security level is STRONGBOX, return a
    /// VerificationRequired variant of the AuthTokenHandler with the found auth token to signal
    /// the operation that it may need to obtain a verification token from TEE KeyMint.
    /// If the security level is not STRONGBOX, return a Token variant of the AuthTokenHandler with
    /// the found auth token to signal the operation that no more authorization required.
    /// If the key is per-op, return an OpAuthRequired variant of the AuthTokenHandler to signal
    /// create_operation() that it needs to add the operation challenge to the op_auth_map, once it
    /// is received from the keymint, and that operation needs to be authorized before update/finish
    /// is called.
    pub fn authorize_create(
        &self,
        purpose: KeyPurpose,
        key_params: &[KeyParameter],
        op_params: &[KeyParameter],
        security_level: SecurityLevel,
    ) -> Result<AuthTokenHandler> {
        match purpose {
            // Allow SIGN, DECRYPT for both symmetric and asymmetric keys.
            KeyPurpose::SIGN | KeyPurpose::DECRYPT => {}
            // Rule out WRAP_KEY purpose
            KeyPurpose::WRAP_KEY => {
                return Err(KeystoreError::Km(Ec::INCOMPATIBLE_PURPOSE))
                    .context("In authorize_create: WRAP_KEY purpose is not allowed here.");
            }
            KeyPurpose::VERIFY | KeyPurpose::ENCRYPT => {
                // We do not support ENCRYPT and VERIFY (the remaining two options of purpose) for
                // asymmetric keys.
                for kp in key_params.iter() {
                    match *kp.key_parameter_value() {
                        KeyParameterValue::Algorithm(Algorithm::RSA)
                        | KeyParameterValue::Algorithm(Algorithm::EC) => {
                            return Err(KeystoreError::Km(Ec::UNSUPPORTED_PURPOSE)).context(
                                "In authorize_create: public operations on asymmetric keys are not
                                 supported.",
                            );
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                return Err(KeystoreError::Km(Ec::UNSUPPORTED_PURPOSE))
                    .context("In authorize_create: specified purpose is not supported.");
            }
        }
        // The following variables are to record information from key parameters to be used in
        // enforcements, when two or more such pieces of information are required for enforcements.
        // There is only one additional variable than what legacy keystore has, but this helps
        // reduce the number of for loops on key parameters from 3 to 1, compared to legacy keystore
        let mut key_purpose_authorized: bool = false;
        let mut is_time_out_key: bool = false;
        let mut user_auth_type: Option<HardwareAuthenticatorType> = None;
        let mut no_auth_required: bool = false;
        let mut caller_nonce_allowed = false;
        let mut user_id: i32 = -1;
        let mut user_secure_ids = Vec::<i64>::new();
        let mut key_time_out: Option<i64> = None;
        let mut allow_while_on_body = false;

        // iterate through key parameters, recording information we need for authorization
        // enforcements later, or enforcing authorizations in place, where applicable
        for key_param in key_params.iter() {
            match key_param.key_parameter_value() {
                KeyParameterValue::NoAuthRequired => {
                    no_auth_required = true;
                }
                KeyParameterValue::AuthTimeout(t) => {
                    is_time_out_key = true;
                    key_time_out = Some(*t as i64);
                }
                KeyParameterValue::HardwareAuthenticatorType(a) => {
                    user_auth_type = Some(*a);
                }
                KeyParameterValue::KeyPurpose(p) => {
                    // Note: if there can be multiple KeyPurpose key parameters (TODO: confirm this),
                    // following check has the effect of key_params.contains(purpose)
                    // Also, authorizing purpose can not be completed here, if there can be multiple
                    // key parameters for KeyPurpose
                    if !key_purpose_authorized && *p == purpose {
                        key_purpose_authorized = true;
                    }
                }
                KeyParameterValue::CallerNonce => {
                    caller_nonce_allowed = true;
                }
                KeyParameterValue::ActiveDateTime(a) => {
                    if !Enforcements::is_given_time_passed(*a, true) {
                        return Err(KeystoreError::Km(Ec::KEY_NOT_YET_VALID))
                            .context("In authorize_create: key is not yet active.");
                    }
                }
                KeyParameterValue::OriginationExpireDateTime(o) => {
                    if (purpose == KeyPurpose::ENCRYPT || purpose == KeyPurpose::SIGN)
                        && Enforcements::is_given_time_passed(*o, false)
                    {
                        return Err(KeystoreError::Km(Ec::KEY_EXPIRED))
                            .context("In authorize_create: key is expired.");
                    }
                }
                KeyParameterValue::UsageExpireDateTime(u) => {
                    if (purpose == KeyPurpose::DECRYPT || purpose == KeyPurpose::VERIFY)
                        && Enforcements::is_given_time_passed(*u, false)
                    {
                        return Err(KeystoreError::Km(Ec::KEY_EXPIRED))
                            .context("In authorize_create: key is expired.");
                    }
                }
                KeyParameterValue::UserSecureID(s) => {
                    user_secure_ids.push(*s);
                }
                KeyParameterValue::UserID(u) => {
                    user_id = *u;
                }
                KeyParameterValue::UnlockedDeviceRequired => {
                    // check the device locked status. If locked, operations on the key are not
                    // allowed.
                    if self.is_device_locked(user_id) {
                        return Err(KeystoreError::Km(Ec::DEVICE_LOCKED))
                            .context("In authorize_create: device is locked.");
                    }
                }
                KeyParameterValue::AllowWhileOnBody => {
                    allow_while_on_body = true;
                }
                // NOTE: as per offline discussion, sanitizing key parameters and rejecting
                // create operation if any non-allowed tags are present, is not done in
                // authorize_create (unlike in legacy keystore where AuthorizeBegin is rejected if
                // a subset of non-allowed tags are present). Because santizing key parameters
                // should have been done during generate/import key, by KeyMint.
                _ => { /*Do nothing on all the other key parameters, as in legacy keystore*/ }
            }
        }

        // authorize the purpose
        if !key_purpose_authorized {
            return Err(KeystoreError::Km(Ec::INCOMPATIBLE_PURPOSE))
                .context("In authorize_create: the purpose is not authorized.");
        }

        // if both NO_AUTH_REQUIRED and USER_SECURE_ID tags are present, return error
        if !user_secure_ids.is_empty() && no_auth_required {
            return Err(KeystoreError::Km(Ec::INVALID_KEY_BLOB)).context(
                "In authorize_create: key has both NO_AUTH_REQUIRED
                and USER_SECURE_ID tags.",
            );
        }

        // if either of auth_type or secure_id is present and the other is not present, return error
        if (user_auth_type.is_some() && user_secure_ids.is_empty())
            || (user_auth_type.is_none() && !user_secure_ids.is_empty())
        {
            return Err(KeystoreError::Km(Ec::KEY_USER_NOT_AUTHENTICATED)).context(
                "In authorize_create: Auth required, but either auth type or secure ids
                are not present.",
            );
        }
        // validate caller nonce for origination purposes
        if (purpose == KeyPurpose::ENCRYPT || purpose == KeyPurpose::SIGN)
            && !caller_nonce_allowed
            && op_params.iter().any(|kp| kp.get_tag() == Tag::NONCE)
        {
            return Err(KeystoreError::Km(Ec::CALLER_NONCE_PROHIBITED)).context(
                "In authorize_create, NONCE is present,
                    although CALLER_NONCE is not present",
            );
        }

        if !user_secure_ids.is_empty() {
            // key requiring authentication per operation
            if !is_time_out_key {
                return Ok(AuthTokenHandler::OpAuthRequired);
            } else {
                // key requiring time-out based authentication
                let auth_token = DB
                    .with::<_, Result<HardwareAuthToken>>(|db| {
                        let mut db = db.borrow_mut();
                        match (user_auth_type, key_time_out) {
                            (Some(auth_type), Some(key_time_out)) => {
                                let matching_entry = db
                                    .find_timed_auth_token_entry(
                                        &user_secure_ids,
                                        auth_type,
                                        key_time_out,
                                        allow_while_on_body,
                                    )
                                    .context("Failed to find timed auth token.")?;
                                Ok(matching_entry.get_auth_token())
                            }
                            (_, _) => Err(KeystoreError::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
                                .context("Authenticator type and/or key time out is not given."),
                        }
                    })
                    .context("In authorize_create.")?;

                if security_level == SecurityLevel::STRONGBOX {
                    return Ok(AuthTokenHandler::VerificationRequired(auth_token));
                } else {
                    return Ok(AuthTokenHandler::Token(auth_token, None));
                }
            }
        }

        // If we reach here, all authorization enforcements have passed and no auth token required.
        Ok(AuthTokenHandler::NoAuthRequired)
    }

    /// Checks if the time now since epoch is greater than (or equal, if is_given_time_inclusive is
    /// set) the given time (in milliseconds)
    fn is_given_time_passed(given_time: i64, is_given_time_inclusive: bool) -> bool {
        let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);

        let time_since_epoch = match duration_since_epoch {
            Ok(duration) => duration.as_millis(),
            Err(_) => return false,
        };

        if is_given_time_inclusive {
            time_since_epoch >= (given_time as u128)
        } else {
            time_since_epoch > (given_time as u128)
        }
    }

    /// Check if the device is locked for the given user. If there's no entry yet for the user,
    /// we assume that the device is locked
    fn is_device_locked(&self, user_id: i32) -> bool {
        // unwrap here because there's no way this mutex guard can be poisoned and
        // because there's no way to recover, even if it is poisoned.
        let set = self.device_unlocked_set.lock().unwrap();
        !set.contains(&user_id)
    }

    /// Sets the device locked status for the user. This method is called externally.
    pub fn set_device_locked(&self, user_id: i32, device_locked_status: bool) {
        // unwrap here because there's no way this mutex guard can be poisoned and
        // because there's no way to recover, even if it is poisoned.
        let mut set = self.device_unlocked_set.lock().unwrap();
        if device_locked_status {
            set.remove(&user_id);
        } else {
            set.insert(user_id);
        }
    }

    /// Add this auth token to the database.
    /// Then check if there is an entry in the op_auth_map, indexed by the challenge of this
    /// auth token (which could have been inserted during create_operation of an operation on a
    /// per-op-auth key). If so, add a copy of this auth token to the map indexed by the
    /// challenge.
    pub fn add_auth_token(&self, auth_token: HardwareAuthToken) -> Result<()> {
        //it is ok to unwrap here, because there is no way this lock can get poisoned and
        //and there is no way to recover if it is poisoned.
        let mut op_auth_map_guard = self.op_auth_map.lock().unwrap();

        if op_auth_map_guard.contains_key(&auth_token.challenge) {
            let auth_token_copy = HardwareAuthToken {
                challenge: auth_token.challenge,
                userId: auth_token.userId,
                authenticatorId: auth_token.authenticatorId,
                authenticatorType: HardwareAuthenticatorType(auth_token.authenticatorType.0),
                timestamp: Timestamp { milliSeconds: auth_token.timestamp.milliSeconds },
                mac: auth_token.mac.clone(),
            };
            op_auth_map_guard.insert(auth_token.challenge, Some(auth_token_copy));
        }

        DB.with(|db| db.borrow_mut().insert_auth_token(&auth_token))
            .context("In add_auth_token.")?;
        Ok(())
    }

    /// This allows adding an entry to the op_auth_map, indexed by the operation challenge.
    /// This is to be called by create_operation, once it has received the operation challenge
    /// from keymint for an operation whose authorization decision is OpAuthRequired, as signalled
    /// by the AuthTokenHandler.
    pub fn insert_to_op_auth_map(&self, op_challenge: i64) {
        let mut op_auth_map_guard = self.op_auth_map.lock().unwrap();
        op_auth_map_guard.insert(op_challenge, None);
    }

    /// Requests a verification token from the background task handler which will retrieve it from
    /// Timestamp Service or TEE KeyMint.
    /// Once the create_operation receives an operation challenge from KeyMint, if it has
    /// previously received a VerificationRequired variant of AuthTokenHandler during
    /// authorize_create_operation, it calls this method to obtain a VerificationToken.
    pub fn request_verification_token(
        &self,
        auth_token: HardwareAuthToken,
        op_challenge: OperationChallenge,
    ) -> Result<AuthTokenHandler> {
        // create a channel for this particular operation
        let (op_sender, op_receiver) = channel::<(HardwareAuthToken, VerificationToken)>();
        // it is ok to unwrap here because there is no way this mutex gets poisoned.
        let sender_guard = self.sender_to_bth.lock().unwrap();
        if let Some(sender) = &*sender_guard {
            let sender_cloned = sender.clone();
            drop(sender_guard);
            sender_cloned
                .send(Message::Inputs((auth_token, op_challenge, op_sender)))
                .map_err(|_| KeystoreError::sys())
                .context(
                    "In request_verification_token. Sending a request for a verification token
             failed.",
                )?;
        }
        Ok(AuthTokenHandler::Channel(op_receiver))
    }
}

impl Default for Enforcements {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Enforcements {
    fn drop(&mut self) {
        let sender_guard = self.sender_to_bth.lock().unwrap();
        if let Some(sender) = &*sender_guard {
            let sender_cloned = sender.clone();
            drop(sender_guard);
            // TODO: Verify how best to handle the error in this case.
            sender_cloned.send(Message::Shutdown).unwrap_or_else(|e| {
                panic!(
                    "Failed to send shutdown message to background task handler because of {:?}.",
                    e
                );
            });
        }
    }
}

// TODO: Add tests to enforcement module (b/175578618).
