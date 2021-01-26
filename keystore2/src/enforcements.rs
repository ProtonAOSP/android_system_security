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
use crate::database::{AuthTokenEntry, MonotonicRawTime};
use crate::error::{map_binder_status, Error, ErrorCode};
use crate::globals::{get_timestamp_service, ASYNC_TASK, DB, ENFORCEMENTS};
use crate::key_parameter::{KeyParameter, KeyParameterValue};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, ErrorCode::ErrorCode as Ec, HardwareAuthToken::HardwareAuthToken,
    HardwareAuthenticatorType::HardwareAuthenticatorType,
    KeyParameter::KeyParameter as KmKeyParameter, KeyPurpose::KeyPurpose, Tag::Tag,
};
use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
    ISecureClock::ISecureClock, TimeStampToken::TimeStampToken,
};
use android_system_keystore2::aidl::android::system::keystore2::OperationChallenge::OperationChallenge;
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::sync::{
    mpsc::{channel, Receiver, Sender},
    Arc, Mutex, Weak,
};
use std::time::SystemTime;

#[derive(Debug)]
enum AuthRequestState {
    /// An outstanding per operation authorization request.
    OpAuth,
    /// An outstanding request for per operation authorization and secure timestamp.
    TimeStampedOpAuth(Receiver<Result<TimeStampToken, Error>>),
    /// An outstanding request for a timestamp token.
    TimeStamp(Receiver<Result<TimeStampToken, Error>>),
}

#[derive(Debug)]
struct AuthRequest {
    state: AuthRequestState,
    /// This need to be set to Some to fulfill a AuthRequestState::OpAuth or
    /// AuthRequestState::TimeStampedOpAuth.
    hat: Option<HardwareAuthToken>,
}

impl AuthRequest {
    fn op_auth() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self { state: AuthRequestState::OpAuth, hat: None }))
    }

    fn timestamped_op_auth(receiver: Receiver<Result<TimeStampToken, Error>>) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            state: AuthRequestState::TimeStampedOpAuth(receiver),
            hat: None,
        }))
    }

    fn timestamp(
        hat: HardwareAuthToken,
        receiver: Receiver<Result<TimeStampToken, Error>>,
    ) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self { state: AuthRequestState::TimeStamp(receiver), hat: Some(hat) }))
    }

    fn add_auth_token(&mut self, hat: HardwareAuthToken) {
        self.hat = Some(hat)
    }

    fn get_auth_tokens(&mut self) -> Result<(HardwareAuthToken, Option<TimeStampToken>)> {
        match (&self.state, self.hat.is_some()) {
            (AuthRequestState::OpAuth, true) => Ok((self.hat.take().unwrap(), None)),
            (AuthRequestState::TimeStampedOpAuth(recv), true)
            | (AuthRequestState::TimeStamp(recv), true) => {
                let result = recv.recv().context("In get_auth_tokens: Sender disconnected.")?;
                let tst = result.context(concat!(
                    "In get_auth_tokens: Worker responded with error ",
                    "from generating timestamp token."
                ))?;
                Ok((self.hat.take().unwrap(), Some(tst)))
            }
            (_, false) => Err(Error::Km(ErrorCode::KEY_USER_NOT_AUTHENTICATED))
                .context("In get_auth_tokens: No operation auth token received."),
        }
    }
}

/// DeferredAuthState describes how auth tokens and timestamp tokens need to be provided when
/// updating and finishing an operation.
#[derive(Debug)]
enum DeferredAuthState {
    /// Used when an operation does not require further authorization.
    NoAuthRequired,
    /// Indicates that the operation requires an operation specific token. This means we have
    /// to return an operation challenge to the client which should reward us with an
    /// operation specific auth token. If it is not provided before the client calls update
    /// or finish, the operation fails as not authorized.
    OpAuthRequired,
    /// Indicates that the operation requires a time stamp token. The auth token was already
    /// loaded from the database, but it has to be accompanied by a time stamp token to inform
    /// the target KM with a different clock about the time on the authenticators.
    TimeStampRequired(HardwareAuthToken),
    /// Indicates that both an operation bound auth token and a verification token are
    /// before the operation can commence.
    TimeStampedOpAuthRequired,
    /// In this state the auth info is waiting for the deferred authorizations to come in.
    /// We block on timestamp tokens, because we can always make progress on these requests.
    /// The per-op auth tokens might never come, which means we fail if the client calls
    /// update or finish before we got a per-op auth token.
    Waiting(Arc<Mutex<AuthRequest>>),
    /// In this state we have gotten all of the required tokens, we just cache them to
    /// be used when the operation progresses.
    Token(HardwareAuthToken, Option<TimeStampToken>),
}

/// Auth info hold all of the authorization related information of an operation. It is stored
/// in and owned by the operation. It is constructed by authorize_create and stays with the
/// operation until it completes.
#[derive(Debug)]
pub struct AuthInfo {
    state: DeferredAuthState,
}

struct TokenReceiverMap {
    /// The map maps an outstanding challenge to a TokenReceiver. If an incoming Hardware Auth
    /// Token (HAT) has the map key in its challenge field, it gets passed to the TokenReceiver
    /// and the entry is removed from the map. In the case where no HAT is received before the
    /// corresponding operation gets dropped, the entry goes stale. So every time the cleanup
    /// counter (second field in the tuple) turns 0, the map is cleaned from stale entries.
    /// The cleanup counter is decremented every time a new receiver is added.
    /// and reset to TokenReceiverMap::CLEANUP_PERIOD + 1 after each cleanup.
    map_and_cleanup_counter: Mutex<(HashMap<i64, TokenReceiver>, u8)>,
}

impl Default for TokenReceiverMap {
    fn default() -> Self {
        Self { map_and_cleanup_counter: Mutex::new((HashMap::new(), Self::CLEANUP_PERIOD + 1)) }
    }
}

impl TokenReceiverMap {
    /// There is a chance that receivers may become stale because their operation is dropped
    /// without ever being authorized. So occasionally we iterate through the map and throw
    /// out obsolete entries.
    /// This is the number of calls to add_receiver between cleanups.
    const CLEANUP_PERIOD: u8 = 25;

    pub fn add_auth_token(&self, hat: HardwareAuthToken) {
        let mut map = self.map_and_cleanup_counter.lock().unwrap();
        let (ref mut map, _) = *map;
        if let Some((_, recv)) = map.remove_entry(&hat.challenge) {
            recv.add_auth_token(hat);
        }
    }

    pub fn add_receiver(&self, challenge: i64, recv: TokenReceiver) {
        let mut map = self.map_and_cleanup_counter.lock().unwrap();
        let (ref mut map, ref mut cleanup_counter) = *map;
        map.insert(challenge, recv);

        *cleanup_counter -= 1;
        if *cleanup_counter == 0 {
            map.retain(|_, v| !v.is_obsolete());
            map.shrink_to_fit();
            *cleanup_counter = Self::CLEANUP_PERIOD + 1;
        }
    }
}

#[derive(Debug)]
struct TokenReceiver(Weak<Mutex<AuthRequest>>);

impl TokenReceiver {
    fn is_obsolete(&self) -> bool {
        self.0.upgrade().is_none()
    }

    fn add_auth_token(&self, hat: HardwareAuthToken) {
        if let Some(state_arc) = self.0.upgrade() {
            let mut state = state_arc.lock().unwrap();
            state.add_auth_token(hat);
        }
    }
}

fn get_timestamp_token(challenge: i64) -> Result<TimeStampToken, Error> {
    let dev: Box<dyn ISecureClock> = get_timestamp_service()
        .expect(concat!(
            "Secure Clock service must be present ",
            "if TimeStampTokens are required."
        ))
        .get_interface()
        .expect("Fatal: Timestamp service does not implement ISecureClock.");
    map_binder_status(dev.generateTimeStamp(challenge))
}

fn timestamp_token_request(challenge: i64, sender: Sender<Result<TimeStampToken, Error>>) {
    if let Err(e) = sender.send(get_timestamp_token(challenge)) {
        log::info!(
            concat!(
                "In timestamp_token_request: Operation hung up ",
                "before timestamp token could be delivered. {:?}"
            ),
            e
        );
    }
}

impl AuthInfo {
    /// This function gets called after an operation was successfully created.
    /// It makes all the preparations required, so that the operation has all the authentication
    /// related artifacts to advance on update and finish.
    pub fn finalize_create_authorization(&mut self, challenge: i64) -> Option<OperationChallenge> {
        match &self.state {
            DeferredAuthState::OpAuthRequired => {
                let auth_request = AuthRequest::op_auth();
                let token_receiver = TokenReceiver(Arc::downgrade(&auth_request));
                ENFORCEMENTS.register_op_auth_receiver(challenge, token_receiver);

                self.state = DeferredAuthState::Waiting(auth_request);
                Some(OperationChallenge { challenge })
            }
            DeferredAuthState::TimeStampedOpAuthRequired => {
                let (sender, receiver) = channel::<Result<TimeStampToken, Error>>();
                let auth_request = AuthRequest::timestamped_op_auth(receiver);
                let token_receiver = TokenReceiver(Arc::downgrade(&auth_request));
                ENFORCEMENTS.register_op_auth_receiver(challenge, token_receiver);

                ASYNC_TASK.queue_hi(move || timestamp_token_request(challenge, sender));
                self.state = DeferredAuthState::Waiting(auth_request);
                Some(OperationChallenge { challenge })
            }
            DeferredAuthState::TimeStampRequired(hat) => {
                let hat = (*hat).clone();
                let (sender, receiver) = channel::<Result<TimeStampToken, Error>>();
                let auth_request = AuthRequest::timestamp(hat, receiver);
                ASYNC_TASK.queue_hi(move || timestamp_token_request(challenge, sender));
                self.state = DeferredAuthState::Waiting(auth_request);
                None
            }
            _ => None,
        }
    }

    /// This function returns the auth tokens as needed by the ongoing operation or fails
    /// with ErrorCode::KEY_USER_NOT_AUTHENTICATED. If this was called for the first time
    /// after a deferred authorization was requested by finalize_create_authorization, this
    /// function may block on the generation of a time stamp token. It then moves the
    /// tokens into the DeferredAuthState::Token state for future use.
    pub fn get_auth_tokens(
        &mut self,
    ) -> Result<(Option<HardwareAuthToken>, Option<TimeStampToken>)> {
        let deferred_tokens = if let DeferredAuthState::Waiting(ref auth_request) = self.state {
            let mut state = auth_request.lock().unwrap();
            Some(state.get_auth_tokens().context("In AuthInfo::get_auth_tokens.")?)
        } else {
            None
        };

        if let Some((hat, tst)) = deferred_tokens {
            self.state = DeferredAuthState::Token(hat, tst);
        }

        match &self.state {
            DeferredAuthState::NoAuthRequired => Ok((None, None)),
            DeferredAuthState::Token(hat, tst) => Ok((Some((*hat).clone()), (*tst).clone())),
            DeferredAuthState::OpAuthRequired
            | DeferredAuthState::TimeStampedOpAuthRequired
            | DeferredAuthState::TimeStampRequired(_) => {
                Err(Error::Km(ErrorCode::KEY_USER_NOT_AUTHENTICATED)).context(concat!(
                    "In AuthInfo::get_auth_tokens: No operation auth token requested??? ",
                    "This should not happen."
                ))
            }
            // This should not be reachable, because it should have been handled above.
            DeferredAuthState::Waiting(_) => {
                Err(Error::sys()).context("In AuthInfo::get_auth_tokens: Cannot be reached.")
            }
        }
    }
}

/// Enforcements data structure
pub struct Enforcements {
    /// This hash set contains the user ids for whom the device is currently unlocked. If a user id
    /// is not in the set, it implies that the device is locked for the user.
    device_unlocked_set: Mutex<HashSet<i32>>,
    /// This field maps outstanding auth challenges to their operations. When an auth token
    /// with the right challenge is received it is passed to the map using
    /// TokenReceiverMap::add_auth_token() which removes the entry from the map. If an entry goes
    /// stale, because the operation gets dropped before an auth token is received, the map
    /// is cleaned up in regular intervals.
    op_auth_map: TokenReceiverMap,
}

impl Enforcements {
    /// Creates an enforcement object with the two data structures it holds and the sender as None.
    pub fn new() -> Self {
        Enforcements {
            device_unlocked_set: Mutex::new(HashSet::new()),
            op_auth_map: Default::default(),
        }
    }

    /// Checks if a create call is authorized, given key parameters and operation parameters.
    /// It returns an optional immediate auth token which can be presented to begin, and an
    /// AuthInfo object which stays with the authorized operation and is used to obtain
    /// auth tokens and timestamp tokens as required by the operation.
    /// With regard to auth tokens, the following steps are taken:
    ///
    /// If no key parameters are given (typically when the client is self managed
    /// (see Domain.Blob)) nothing is enforced.
    /// If the key is time-bound, find a matching auth token from the database.
    /// If the above step is successful, and if requires_timestamp is given, the returned
    /// AuthInfo will provide a Timestamp token as appropriate.
    pub fn authorize_create(
        &self,
        purpose: KeyPurpose,
        key_params: Option<&[KeyParameter]>,
        op_params: &[KmKeyParameter],
        requires_timestamp: bool,
    ) -> Result<(Option<HardwareAuthToken>, AuthInfo)> {
        let key_params = if let Some(k) = key_params {
            k
        } else {
            return Ok((None, AuthInfo { state: DeferredAuthState::NoAuthRequired }));
        };

        match purpose {
            // Allow SIGN, DECRYPT for both symmetric and asymmetric keys.
            KeyPurpose::SIGN | KeyPurpose::DECRYPT => {}
            // Rule out WRAP_KEY purpose
            KeyPurpose::WRAP_KEY => {
                return Err(Error::Km(Ec::INCOMPATIBLE_PURPOSE))
                    .context("In authorize_create: WRAP_KEY purpose is not allowed here.");
            }
            KeyPurpose::VERIFY | KeyPurpose::ENCRYPT => {
                // We do not support ENCRYPT and VERIFY (the remaining two options of purpose) for
                // asymmetric keys.
                for kp in key_params.iter() {
                    match *kp.key_parameter_value() {
                        KeyParameterValue::Algorithm(Algorithm::RSA)
                        | KeyParameterValue::Algorithm(Algorithm::EC) => {
                            return Err(Error::Km(Ec::UNSUPPORTED_PURPOSE)).context(
                                "In authorize_create: public operations on asymmetric keys are not
                                 supported.",
                            );
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                return Err(Error::Km(Ec::UNSUPPORTED_PURPOSE))
                    .context("In authorize_create: specified purpose is not supported.");
            }
        }
        // The following variables are to record information from key parameters to be used in
        // enforcements, when two or more such pieces of information are required for enforcements.
        // There is only one additional variable than what legacy keystore has, but this helps
        // reduce the number of for loops on key parameters from 3 to 1, compared to legacy keystore
        let mut key_purpose_authorized: bool = false;
        let mut user_auth_type: Option<HardwareAuthenticatorType> = None;
        let mut no_auth_required: bool = false;
        let mut caller_nonce_allowed = false;
        let mut user_id: i32 = -1;
        let mut user_secure_ids = Vec::<i64>::new();
        let mut key_time_out: Option<i64> = None;
        let mut allow_while_on_body = false;
        let mut unlocked_device_required = false;

        // iterate through key parameters, recording information we need for authorization
        // enforcements later, or enforcing authorizations in place, where applicable
        for key_param in key_params.iter() {
            match key_param.key_parameter_value() {
                KeyParameterValue::NoAuthRequired => {
                    no_auth_required = true;
                }
                KeyParameterValue::AuthTimeout(t) => {
                    key_time_out = Some(*t as i64);
                }
                KeyParameterValue::HardwareAuthenticatorType(a) => {
                    user_auth_type = Some(*a);
                }
                KeyParameterValue::KeyPurpose(p) => {
                    // The following check has the effect of key_params.contains(purpose)
                    // Also, authorizing purpose can not be completed here, if there can be multiple
                    // key parameters for KeyPurpose.
                    key_purpose_authorized = key_purpose_authorized || *p == purpose;
                }
                KeyParameterValue::CallerNonce => {
                    caller_nonce_allowed = true;
                }
                KeyParameterValue::ActiveDateTime(a) => {
                    if !Enforcements::is_given_time_passed(*a, true) {
                        return Err(Error::Km(Ec::KEY_NOT_YET_VALID))
                            .context("In authorize_create: key is not yet active.");
                    }
                }
                KeyParameterValue::OriginationExpireDateTime(o) => {
                    if (purpose == KeyPurpose::ENCRYPT || purpose == KeyPurpose::SIGN)
                        && Enforcements::is_given_time_passed(*o, false)
                    {
                        return Err(Error::Km(Ec::KEY_EXPIRED))
                            .context("In authorize_create: key is expired.");
                    }
                }
                KeyParameterValue::UsageExpireDateTime(u) => {
                    if (purpose == KeyPurpose::DECRYPT || purpose == KeyPurpose::VERIFY)
                        && Enforcements::is_given_time_passed(*u, false)
                    {
                        return Err(Error::Km(Ec::KEY_EXPIRED))
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
                    unlocked_device_required = true;
                }
                KeyParameterValue::AllowWhileOnBody => {
                    allow_while_on_body = true;
                }
                // NOTE: as per offline discussion, sanitizing key parameters and rejecting
                // create operation if any non-allowed tags are present, is not done in
                // authorize_create (unlike in legacy keystore where AuthorizeBegin is rejected if
                // a subset of non-allowed tags are present). Because sanitizing key parameters
                // should have been done during generate/import key, by KeyMint.
                _ => { /*Do nothing on all the other key parameters, as in legacy keystore*/ }
            }
        }

        // authorize the purpose
        if !key_purpose_authorized {
            return Err(Error::Km(Ec::INCOMPATIBLE_PURPOSE))
                .context("In authorize_create: the purpose is not authorized.");
        }

        // if both NO_AUTH_REQUIRED and USER_SECURE_ID tags are present, return error
        if !user_secure_ids.is_empty() && no_auth_required {
            return Err(Error::Km(Ec::INVALID_KEY_BLOB)).context(
                "In authorize_create: key has both NO_AUTH_REQUIRED
                and USER_SECURE_ID tags.",
            );
        }

        // if either of auth_type or secure_id is present and the other is not present, return error
        if (user_auth_type.is_some() && user_secure_ids.is_empty())
            || (user_auth_type.is_none() && !user_secure_ids.is_empty())
        {
            return Err(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED)).context(
                "In authorize_create: Auth required, but either auth type or secure ids
                are not present.",
            );
        }

        // validate caller nonce for origination purposes
        if (purpose == KeyPurpose::ENCRYPT || purpose == KeyPurpose::SIGN)
            && !caller_nonce_allowed
            && op_params.iter().any(|kp| kp.tag == Tag::NONCE)
        {
            return Err(Error::Km(Ec::CALLER_NONCE_PROHIBITED)).context(
                "In authorize_create, NONCE is present,
                    although CALLER_NONCE is not present",
            );
        }

        if unlocked_device_required {
            // check the device locked status. If locked, operations on the key are not
            // allowed.
            if self.is_device_locked(user_id) {
                return Err(Error::Km(Ec::DEVICE_LOCKED))
                    .context("In authorize_create: device is locked.");
            }
        }

        if !unlocked_device_required && no_auth_required {
            return Ok((None, AuthInfo { state: DeferredAuthState::NoAuthRequired }));
        }

        let has_sids = !user_secure_ids.is_empty();

        let timeout_bound = key_time_out.is_some() && has_sids;

        let per_op_bound = key_time_out.is_none() && has_sids;

        let need_auth_token = timeout_bound || unlocked_device_required;

        let hat_and_last_off_body = if need_auth_token {
            let hat_and_last_off_body = Self::find_auth_token(|hat: &AuthTokenEntry| {
                if let (Some(auth_type), true) = (user_auth_type, has_sids) {
                    hat.satisfies(&user_secure_ids, auth_type)
                } else {
                    unlocked_device_required
                }
            })
            .context("In authorize_create: Trying to get required auth token.")?;
            Some(
                hat_and_last_off_body
                    .ok_or(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
                    .context("In authorize_create: No suitable auth token found.")?,
            )
        } else {
            None
        };

        // Now check the validity of the auth token if the key is timeout bound.
        let hat = match (hat_and_last_off_body, key_time_out) {
            (Some((hat, last_off_body)), Some(key_time_out)) => {
                let now = MonotonicRawTime::now();
                let token_age = now
                    .checked_sub(&hat.time_received())
                    .ok_or_else(Error::sys)
                    .context(concat!(
                        "In authorize_create: Overflow while computing Auth token validity. ",
                        "Validity cannot be established."
                    ))?;

                let on_body_extended = allow_while_on_body && last_off_body < hat.time_received();

                if token_age.seconds() > key_time_out && !on_body_extended {
                    return Err(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
                        .context("In authorize_create: matching auth token is expired.");
                }
                Some(hat)
            }
            (Some((hat, _)), None) => Some(hat),
            // If timeout_bound is true, above code must have retrieved a HAT or returned with
            // KEY_USER_NOT_AUTHENTICATED. This arm should not be reachable.
            (None, Some(_)) => panic!("Logical error."),
            _ => None,
        };

        Ok(match (hat, requires_timestamp, per_op_bound) {
            // Per-op-bound and Some(hat) can only happen if we are both per-op bound and unlocked
            // device required. In addition, this KM instance needs a timestamp token.
            // So the HAT cannot be presented on create. So on update/finish we present both
            // an per-op-bound auth token and a timestamp token.
            (Some(_), true, true) => (None, DeferredAuthState::TimeStampedOpAuthRequired),
            (Some(hat), true, false) => {
                (None, DeferredAuthState::TimeStampRequired(hat.take_auth_token()))
            }
            (Some(hat), false, true) => {
                (Some(hat.take_auth_token()), DeferredAuthState::OpAuthRequired)
            }
            (Some(hat), false, false) => {
                (Some(hat.take_auth_token()), DeferredAuthState::NoAuthRequired)
            }
            (None, _, true) => (None, DeferredAuthState::OpAuthRequired),
            (None, _, false) => (None, DeferredAuthState::NoAuthRequired),
        })
        .map(|(hat, state)| (hat, AuthInfo { state }))
    }

    fn find_auth_token<F>(p: F) -> Result<Option<(AuthTokenEntry, MonotonicRawTime)>>
    where
        F: Fn(&AuthTokenEntry) -> bool,
    {
        DB.with(|db| {
            let mut db = db.borrow_mut();
            db.find_auth_token_entry(p).context("Trying to find auth token.")
        })
        .context("In find_auth_token.")
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
    /// Then present the auth token to the op auth map. If an operation is waiting for this
    /// auth token this fulfills the request and removes the receiver from the map.
    pub fn add_auth_token(&self, hat: HardwareAuthToken) -> Result<()> {
        DB.with(|db| db.borrow_mut().insert_auth_token(&hat)).context("In add_auth_token.")?;

        self.op_auth_map.add_auth_token(hat);
        Ok(())
    }

    /// This allows adding an entry to the op_auth_map, indexed by the operation challenge.
    /// This is to be called by create_operation, once it has received the operation challenge
    /// from keymint for an operation whose authorization decision is OpAuthRequired, as signalled
    /// by the DeferredAuthState.
    fn register_op_auth_receiver(&self, challenge: i64, recv: TokenReceiver) {
        self.op_auth_map.add_receiver(challenge, recv);
    }
}

impl Default for Enforcements {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: Add tests to enforcement module (b/175578618).
