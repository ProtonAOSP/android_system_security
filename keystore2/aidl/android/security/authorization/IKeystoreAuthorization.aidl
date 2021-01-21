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

// TODO: mark the interface with @SensitiveData when the annotation is ready (b/176110256).

/**
 * IKeystoreAuthorization interface exposes the methods for other system components to
 * provide keystore with the information required to enforce authorizations on key usage.
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
}
