// Copyright 2021, The Android Open Source Project
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

package android.security.usermanager;

// TODO: mark the interface with @SensitiveData when the annotation is ready (b/176110256).

/**
 * IKeystoreUserManager interface exposes the methods for adding/removing users and changing the
 * user's password.
 */
interface IKeystoreUserManager {

    /**
     * Allows LockSettingsService to inform keystore about adding a new user.
     * Callers require 'AddUser' permission.
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the callers do not have the 'AddUser' permission.
     * `ResponseCode::SYSTEM_ERROR` - if failed to delete the keys of an existing user with the same
     * user id.
     *
     * @param userId - Android user id
     */
    void onUserAdded(in int userId);

    /**
     * Allows LockSettingsService to inform keystore about removing a user.
     * Callers require 'RemoveUser' permission.
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the callers do not have the 'RemoveUser' permission.
     * `ResponseCode::SYSTEM_ERROR` - if failed to delete the keys of the user being deleted.
     *
     * @param userId - Android user id
     */
    void onUserRemoved(in int userId);

    /**
     * Allows LockSettingsService to inform keystore about password change of a user.
     * Callers require 'ChangePassword' permission.
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the callers do not have the 'ChangePassword'
     *                                     permission.
     * `ResponseCode::SYSTEM_ERROR` - if failed to delete the super encrypted keys of the user.
     * `ResponseCode::Locked' -  if the keystore is locked for the given user.
     *
     * @param userId - Android user id
     * @param password - a secret derived from the synthetic password of the user
     */
    void onUserPasswordChanged(in int userId, in @nullable byte[] password);
}
