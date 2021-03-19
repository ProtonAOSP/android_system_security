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

//! This module implements the Android Protected Confirmation (APC) service as defined
//! in the android.security.apc AIDL spec.

use std::{
    cmp::PartialEq,
    collections::HashMap,
    sync::{mpsc::Sender, Arc, Mutex},
};

use crate::utils::{compat_2_response_code, ui_opts_2_compat};
use android_security_apc::aidl::android::security::apc::{
    IConfirmationCallback::IConfirmationCallback,
    IProtectedConfirmation::{BnProtectedConfirmation, IProtectedConfirmation},
    ResponseCode::ResponseCode,
};
use android_security_apc::binder::{
    ExceptionCode, Interface, Result as BinderResult, SpIBinder, Status as BinderStatus, Strong,
};
use anyhow::{Context, Result};
use binder::{IBinderInternal, ThreadState};
use keystore2_apc_compat::ApcHal;
use keystore2_selinux as selinux;
use std::time::{Duration, Instant};

/// This is the main APC error type, it wraps binder exceptions and the
/// APC ResponseCode.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    /// Wraps an Android Protected Confirmation (APC) response code as defined by the
    /// android.security.apc AIDL interface specification.
    #[error("Error::Rc({0:?})")]
    Rc(ResponseCode),
    /// Wraps a Binder exception code other than a service specific exception.
    #[error("Binder exception code {0:?}, {1:?}")]
    Binder(ExceptionCode, i32),
}

impl Error {
    /// Short hand for `Error::Rc(ResponseCode::SYSTEM_ERROR)`
    pub fn sys() -> Self {
        Error::Rc(ResponseCode::SYSTEM_ERROR)
    }

    /// Short hand for `Error::Rc(ResponseCode::OPERATION_PENDING)`
    pub fn pending() -> Self {
        Error::Rc(ResponseCode::OPERATION_PENDING)
    }

    /// Short hand for `Error::Rc(ResponseCode::CANCELLED)`
    pub fn cancelled() -> Self {
        Error::Rc(ResponseCode::CANCELLED)
    }

    /// Short hand for `Error::Rc(ResponseCode::ABORTED)`
    pub fn aborted() -> Self {
        Error::Rc(ResponseCode::ABORTED)
    }

    /// Short hand for `Error::Rc(ResponseCode::IGNORED)`
    pub fn ignored() -> Self {
        Error::Rc(ResponseCode::IGNORED)
    }

    /// Short hand for `Error::Rc(ResponseCode::UNIMPLEMENTED)`
    pub fn unimplemented() -> Self {
        Error::Rc(ResponseCode::UNIMPLEMENTED)
    }
}

/// This function should be used by confirmation service calls to translate error conditions
/// into service specific exceptions.
///
/// All error conditions get logged by this function.
///
/// `Error::Rc(x)` variants get mapped onto a service specific error code of `x`.
/// `selinux::Error::perm()` is mapped on `ResponseCode::PERMISSION_DENIED`.
///
/// All non `Error` error conditions get mapped onto ResponseCode::SYSTEM_ERROR`.
///
/// `handle_ok` will be called if `result` is `Ok(value)` where `value` will be passed
/// as argument to `handle_ok`. `handle_ok` must generate a `BinderResult<T>`, but it
/// typically returns Ok(value).
pub fn map_or_log_err<T, U, F>(result: Result<U>, handle_ok: F) -> BinderResult<T>
where
    F: FnOnce(U) -> BinderResult<T>,
{
    result.map_or_else(
        |e| {
            log::error!("{:#?}", e);
            let root_cause = e.root_cause();
            let rc = match root_cause.downcast_ref::<Error>() {
                Some(Error::Rc(rcode)) => rcode.0,
                Some(Error::Binder(_, _)) => ResponseCode::SYSTEM_ERROR.0,
                None => match root_cause.downcast_ref::<selinux::Error>() {
                    Some(selinux::Error::PermissionDenied) => ResponseCode::PERMISSION_DENIED.0,
                    _ => ResponseCode::SYSTEM_ERROR.0,
                },
            };
            Err(BinderStatus::new_service_specific_error(rc, None))
        },
        handle_ok,
    )
}

/// Rate info records how many failed attempts a client has made to display a protected
/// confirmation prompt. Clients are penalized for attempts that get declined by the user
/// or attempts that get aborted by the client itself.
///
/// After the third failed attempt the client has to cool down for 30 seconds before it
/// it can retry. After the sixth failed attempt, the time doubles with every failed attempt
/// until it goes into saturation at 24h.
///
/// A successful user prompt resets the counter.
#[derive(Debug, Clone)]
struct RateInfo {
    counter: u32,
    timestamp: Instant,
}

impl RateInfo {
    const ONE_DAY: Duration = Duration::from_secs(60u64 * 60u64 * 24u64);

    fn get_remaining_back_off(&self) -> Option<Duration> {
        let back_off = match self.counter {
            // The first three attempts come without penalty.
            0..=2 => return None,
            // The next three attempts are are penalized with 30 seconds back off time.
            3..=5 => Duration::from_secs(30),
            // After that we double the back off time the with every additional attempt
            // until we reach 1024m (~17h).
            6..=16 => Duration::from_secs(60)
                .checked_mul(1u32 << (self.counter - 6))
                .unwrap_or(Self::ONE_DAY),
            // After that we cap of at 24h between attempts.
            _ => Self::ONE_DAY,
        };
        let elapsed = self.timestamp.elapsed();
        // This does exactly what we want.
        // `back_off - elapsed` is the remaining back off duration or None if elapsed is larger
        // than back_off. Also, this operation cannot overflow as long as elapsed is less than
        // back_off, which is all that we care about.
        back_off.checked_sub(elapsed)
    }
}

impl Default for RateInfo {
    fn default() -> Self {
        Self { counter: 0u32, timestamp: Instant::now() }
    }
}

/// The APC session state represents the state of an APC session.
struct ApcSessionState {
    /// A reference to the APC HAL backend.
    hal: Arc<ApcHal>,
    /// The client callback object.
    cb: SpIBinder,
    /// The uid of the owner of this APC session.
    uid: u32,
    /// The time when this session was started.
    start: Instant,
    /// This is set when the client calls abort.
    /// This is used by the rate limiting logic to determine
    /// if the client needs to be penalized for this attempt.
    client_aborted: bool,
}

struct ApcState {
    session: Option<ApcSessionState>,
    rate_limiting: HashMap<u32, RateInfo>,
    confirmation_token_sender: Sender<Vec<u8>>,
}

impl ApcState {
    fn new(confirmation_token_sender: Sender<Vec<u8>>) -> Self {
        Self { session: None, rate_limiting: Default::default(), confirmation_token_sender }
    }
}

/// Implementation of the APC service.
pub struct ApcManager {
    state: Arc<Mutex<ApcState>>,
}

impl Interface for ApcManager {}

impl ApcManager {
    /// Create a new instance of the Android Protected Confirmation service.
    pub fn new_native_binder(
        confirmation_token_sender: Sender<Vec<u8>>,
    ) -> Result<Strong<dyn IProtectedConfirmation>> {
        let result = BnProtectedConfirmation::new_binder(Self {
            state: Arc::new(Mutex::new(ApcState::new(confirmation_token_sender))),
        });
        result.as_binder().set_requesting_sid(true);
        Ok(result)
    }

    fn result(
        state: Arc<Mutex<ApcState>>,
        rc: u32,
        data_confirmed: Option<&[u8]>,
        confirmation_token: Option<&[u8]>,
    ) {
        let mut state = state.lock().unwrap();
        let (callback, uid, start, client_aborted) = match state.session.take() {
            None => return, // Nothing to do
            Some(ApcSessionState { cb: callback, uid, start, client_aborted, .. }) => {
                (callback, uid, start, client_aborted)
            }
        };

        let rc = compat_2_response_code(rc);

        // Update rate limiting information.
        match (rc, client_aborted, confirmation_token) {
            // If the user confirmed the dialog.
            (ResponseCode::OK, _, Some(confirmation_token)) => {
                // Reset counter.
                state.rate_limiting.remove(&uid);
                // Send confirmation token to the enforcement module.
                if let Err(e) = state.confirmation_token_sender.send(confirmation_token.to_vec()) {
                    log::error!("Got confirmation token, but receiver would not have it. {:?}", e);
                }
            }
            // If cancelled by the user or if aborted by the client.
            (ResponseCode::CANCELLED, _, _) | (ResponseCode::ABORTED, true, _) => {
                // Penalize.
                let mut rate_info = state.rate_limiting.entry(uid).or_default();
                rate_info.counter += 1;
                rate_info.timestamp = start;
            }
            (ResponseCode::OK, _, None) => {
                log::error!(
                    "Confirmation prompt was successful but no confirmation token was returned."
                );
            }
            // In any other case this try does not count at all.
            _ => {}
        }
        drop(state);

        if let Ok(listener) = callback.into_interface::<dyn IConfirmationCallback>() {
            if let Err(e) = listener.onCompleted(rc, data_confirmed) {
                log::error!(
                    "In ApcManagerCallback::result: Reporting completion to client failed {:?}",
                    e
                )
            }
        } else {
            log::error!("In ApcManagerCallback::result: SpIBinder is not a IConfirmationCallback.");
        }
    }

    fn present_prompt(
        &self,
        listener: &dyn IConfirmationCallback,
        prompt_text: &str,
        extra_data: &[u8],
        locale: &str,
        ui_option_flags: i32,
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.session.is_some() {
            return Err(Error::pending())
                .context("In ApcManager::present_prompt: Session pending.");
        }

        // Perform rate limiting.
        let uid = ThreadState::get_calling_uid();
        match state.rate_limiting.get(&uid) {
            None => {}
            Some(rate_info) => {
                if let Some(back_off) = rate_info.get_remaining_back_off() {
                    return Err(Error::sys()).context(format!(
                        "In ApcManager::present_prompt: Cooling down. Remaining back-off: {}s",
                        back_off.as_secs()
                    ));
                }
            }
        }

        let hal = ApcHal::try_get_service();
        let hal = match hal {
            None => {
                return Err(Error::unimplemented())
                    .context("In ApcManager::present_prompt: APC not supported.")
            }
            Some(h) => Arc::new(h),
        };

        let ui_opts = ui_opts_2_compat(ui_option_flags);

        let state_clone = self.state.clone();
        hal.prompt_user_confirmation(
            prompt_text,
            extra_data,
            locale,
            ui_opts,
            move |rc, data_confirmed, confirmation_token| {
                Self::result(state_clone, rc, data_confirmed, confirmation_token)
            },
        )
        .map_err(|rc| Error::Rc(compat_2_response_code(rc)))
        .context("In present_prompt: Failed to present prompt.")?;
        state.session = Some(ApcSessionState {
            hal,
            cb: listener.as_binder(),
            uid,
            start: Instant::now(),
            client_aborted: false,
        });
        Ok(())
    }

    fn cancel_prompt(&self, listener: &dyn IConfirmationCallback) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let hal = match &mut state.session {
            None => {
                return Err(Error::ignored())
                    .context("In cancel_prompt: Attempt to cancel non existing session. Ignoring.")
            }
            Some(session) => {
                if session.cb != listener.as_binder() {
                    return Err(Error::ignored()).context(concat!(
                        "In cancel_prompt: Attempt to cancel session not belonging to caller. ",
                        "Ignoring."
                    ));
                }
                session.client_aborted = true;
                session.hal.clone()
            }
        };
        drop(state);
        hal.abort();
        Ok(())
    }

    fn is_supported() -> Result<bool> {
        Ok(ApcHal::try_get_service().is_some())
    }
}

impl IProtectedConfirmation for ApcManager {
    fn presentPrompt(
        &self,
        listener: &dyn IConfirmationCallback,
        prompt_text: &str,
        extra_data: &[u8],
        locale: &str,
        ui_option_flags: i32,
    ) -> BinderResult<()> {
        map_or_log_err(
            self.present_prompt(listener, prompt_text, extra_data, locale, ui_option_flags),
            Ok,
        )
    }
    fn cancelPrompt(&self, listener: &dyn IConfirmationCallback) -> BinderResult<()> {
        map_or_log_err(self.cancel_prompt(listener), Ok)
    }
    fn isSupported(&self) -> BinderResult<bool> {
        map_or_log_err(Self::is_supported(), Ok)
    }
}
