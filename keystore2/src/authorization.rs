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

//! This module implements IKeyAuthorization AIDL interface.

use crate::error::map_or_log_err;
use crate::globals::ENFORCEMENTS;
use crate::permission::KeystorePerm;
use crate::utils::check_keystore_permission;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
    Timestamp::Timestamp,
};
use android_security_authorization::binder::{Interface, Result as BinderResult};
use android_security_authorization:: aidl::android::security::authorization::IKeystoreAuthorization::{
        BnKeystoreAuthorization, IKeystoreAuthorization,
};
use anyhow::{Context, Result};
use binder::IBinder;

/// This struct is defined to implement the aforementioned AIDL interface.
/// As of now, it is an empty struct.
pub struct AuthorizationManager;

impl AuthorizationManager {
    /// Create a new instance of Keystore Authorization service.
    pub fn new_native_binder() -> Result<impl IKeystoreAuthorization> {
        let result = BnKeystoreAuthorization::new_binder(Self);
        result.as_binder().set_requesting_sid(true);
        Ok(result)
    }

    fn add_auth_token(&self, auth_token: &HardwareAuthToken) -> Result<()> {
        //check keystore permission
        check_keystore_permission(KeystorePerm::add_auth()).context("In add_auth_token.")?;

        //TODO: Keymint's HardwareAuthToken aidl needs to implement Copy/Clone
        let auth_token_copy = HardwareAuthToken {
            challenge: auth_token.challenge,
            userId: auth_token.userId,
            authenticatorId: auth_token.authenticatorId,
            authenticatorType: HardwareAuthenticatorType(auth_token.authenticatorType.0),
            timestamp: Timestamp { milliSeconds: auth_token.timestamp.milliSeconds },
            mac: auth_token.mac.clone(),
        };
        ENFORCEMENTS.add_auth_token(auth_token_copy)?;
        Ok(())
    }
}

impl Interface for AuthorizationManager {}

impl IKeystoreAuthorization for AuthorizationManager {
    fn addAuthToken(&self, auth_token: &HardwareAuthToken) -> BinderResult<()> {
        map_or_log_err(self.add_auth_token(auth_token), Ok)
    }
}
