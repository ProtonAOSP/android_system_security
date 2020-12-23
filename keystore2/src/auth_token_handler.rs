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

//! This module defines the AuthTokenHandler enum and its methods. AuthTokenHandler enum represents
//! the different states an auth token and an associated verification token can be expressed during
//! the operation life cycle.
use crate::error::Error as KeystoreError;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, VerificationToken::VerificationToken,
};
use anyhow::{Context, Result};
use std::sync::mpsc::Receiver;

/// AuthTokenHandler enum has five different variants which are described by the comments above
// each variant.
pub enum AuthTokenHandler {
    /// Used when an operation does not require an auth token for authorization.
    NoAuthRequired,
    /// Used to represent the intermediate state between the time the operation is found to be
    /// requiring per-op auth and the time the auth token for the operation is found.
    OpAuthRequired,
    /// Used to represent the intermediate state between the time the operation is found to be
    /// using a time_out key with STRONGBOX keymint, and the time a verficiation token is requested
    /// from the worker thread which obtains verification tokens from the TEE KeyMint.
    VerificationRequired(HardwareAuthToken),
    /// Used to represent the intermediate state between the time a verification token is requested
    /// from the worker thread which obtains verification tokens from the TEE KeyMint and the time
    /// the verification token is received from the worker thread.
    Channel(Receiver<(HardwareAuthToken, VerificationToken)>),
    /// Used to represent the final state for all operations requiring an auth token for
    /// authorization, after the matching auth token (and the associated verification token if
    /// required) is found.
    Token(HardwareAuthToken, Option<VerificationToken>),
}

impl AuthTokenHandler {
    /// Retrieve auth token and verification token from the Token variant of an AuthTokenHandler
    /// instance
    pub fn get_auth_and_verification_tokens(
        &self,
    ) -> Option<(&HardwareAuthToken, &VerificationToken)> {
        if let AuthTokenHandler::Token(auth_token, Some(verification_token)) = self {
            Some((auth_token, verification_token))
        } else {
            None
        }
    }

    /// Retrieve auth token from the Token variant of an AuthTokenHandler instance
    pub fn get_auth_token(&self) -> Option<&HardwareAuthToken> {
        if let AuthTokenHandler::Token(auth_token, _) = self {
            Some(auth_token)
        } else {
            None
        }
    }

    /// If Channel variant, block on it until the verification token is sent by the
    /// keystore2 worker thread which obtains verification tokens from TEE Keymint
    pub fn receive_verification_token(&mut self) -> Result<()> {
        if let AuthTokenHandler::Channel(recv) = self {
            let (auth_token, verification_token) =
                recv.recv().context("In receive_verification_token: sender disconnected.")?;
            *self = AuthTokenHandler::Token(auth_token, Some(verification_token));
            Ok(())
        } else {
            Err(KeystoreError::sys()).context(
                "In receive_verification_token: Wrong variant found in the authorization object.",
            )
        }
    }
}
