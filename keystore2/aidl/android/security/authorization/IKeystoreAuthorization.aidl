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

/**
* IKeystoreAuthorization interface exposes the methods for other system components to
* provide keystore with the information required to enforce authorizations on key usage.
*/
interface IKeystoreAuthorization {

    /**
    * Allows the Android authenticators to hand over an auth token to Keystore.
    * Callers require 'AddAuth' permission.
    * ## Error conditions:
    * `ResponseCode::SYSTEM_ERROR` - if failed to store the auth token in the database or if failed
    * to add the auth token to the operation, if it is a per-op auth token.
    *
    * @param authToken The auth token created by an authenticator, upon user authentication.
    */
    void addAuthToken(in HardwareAuthToken authToken);
}
