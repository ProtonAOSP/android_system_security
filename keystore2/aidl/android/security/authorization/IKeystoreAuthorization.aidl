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

package android.security.authorization;

import android.hardware.security.keymint.HardwareAuthToken;
import android.security.authorization.LockScreenEvent;
import android.security.authorization.AuthorizationTokens;

// TODO: mark the interface with @SensitiveData when the annotation is ready (b/176110256).

/**
 * IKeystoreAuthorization interface exposes the methods for other system components to
 * provide keystore with the information required to enforce authorizations on key usage.
 * @hide
 */
interface IKeystoreAuthorization {

    /**
     * Allows the Android authenticators to hand over an auth token to Keystore.
     * Callers require 'AddAuth' permission.
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the callers do not have the 'AddAuth' permission.
     * `ResponseCode::SYSTEM_ERROR` - if failed to store the auth token in the database or if failed
     * to add the auth token to the operation, if it is a per-op auth token.
     *
     * @param authToken The auth token created by an authenticator, upon user authentication.
     */
    void addAuthToken(in HardwareAuthToken authToken);

    /**
     * Unlocks the keystore for the given user id.
     * Callers require 'Unlock' permission.
     * If a password was set, a password must be given on unlock or the operation fails.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the callers do not have the 'Unlock' permission.
     * `ResponseCode::SYSTEM_ERROR` - if failed to perform lock/unlock operations due to various
     * `ResponseCode::VALUE_CORRUPTED` - if the super key can not be decrypted.
     * `ResponseCode::KEY_NOT_FOUND` - if the super key is not found.
     *
     * @lockScreenEvent - Indicates what happened.
     *                    * LockScreenEvent.UNLOCK if the screen was unlocked.
     *                    * LockScreenEvent.LOCK if the screen was locked.
     *
     * @param userId - Android user id
     *
     * @param password - synthetic password derived by the user denoted by the user id
     */
    void onLockScreenEvent(in LockScreenEvent lockScreenEvent, in int userId,
                           in @nullable byte[] password);

    /**
     * Allows Credstore to retrieve a HardwareAuthToken and a TimestampToken.
     * Identity Credential Trusted App can run either in the TEE or in other secure Hardware.
     * So, credstore always need to retrieve a TimestampToken along with a HardwareAuthToken.
     *
     * The passed in |challenge| parameter must always be non-zero.
     *
     * The returned TimestampToken will always have its |challenge| field set to
     * the |challenge| parameter.
     *
     * This method looks through auth-tokens cached by keystore which match
     * the passed-in |secureUserId|.
     * The most recent matching auth token which has a |challenge| field which matches
     * the passed-in |challenge| parameter is returned.
     * In this case the |authTokenMaxAgeMillis| parameter is not used.
     *
     * Otherwise, the most recent matching auth token which is younger
     * than |authTokenMaxAgeMillis| is returned.
     *
     * This method is called by credstore (and only credstore).
     *
     * The caller requires 'get_auth_token' permission.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the caller does not have the 'get_auth_token'
     *                                     permission.
     * `ResponseCode::SYSTEM_ERROR` - if failed to obtain an authtoken from the database.
     * `ResponseCode::NO_AUTH_TOKEN_FOUND` - a matching auth token is not found.
     * `ResponseCode::INVALID_ARGUMENT` - if the passed-in |challenge| parameter is zero.
     */
    AuthorizationTokens getAuthTokensForCredStore(in long challenge, in long secureUserId,
     in long authTokenMaxAgeMillis);
}
