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

package android.security.maintenance;

import android.system.keystore2.Domain;
import android.system.keystore2.KeyDescriptor;
import android.security.maintenance.UserState;

/**
 * IKeystoreMaintenance interface exposes the methods for adding/removing users and changing the
 * user's password.
 * @hide
 */
 @SensitiveData
interface IKeystoreMaintenance {

    /**
     * Allows LockSettingsService to inform keystore about adding a new user.
     * Callers require 'AddUser' permission.
     *
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
     *
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
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the callers does not have the 'ChangePassword'
     *                                     permission.
     * `ResponseCode::SYSTEM_ERROR` - if failed to delete the super encrypted keys of the user.
     * `ResponseCode::Locked' -  if the keystore is locked for the given user.
     *
     * @param userId - Android user id
     * @param password - a secret derived from the synthetic password of the user
     */
    void onUserPasswordChanged(in int userId, in @nullable byte[] password);

    /**
     * This function deletes all keys within a namespace. It mainly gets called when an app gets
     * removed and all resources of this app need to be cleaned up.
     *
     * @param domain - One of Domain.APP or Domain.SELINUX.
     * @param nspace - The UID of the app that is to be cleared if domain is Domain.APP or
     *                 the SEPolicy namespace if domain is Domain.SELINUX.
     */
    void clearNamespace(Domain domain, long nspace);

    /**
     * Allows querying user state, given user id.
     * Callers require 'GetState' permission.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the callers do not have the 'GetState'
     *                                     permission.
     * `ResponseCode::SYSTEM_ERROR` - if an error occurred when querying the user state.
     *
     * @param userId - Android user id
     */
    UserState getState(in int userId);

    /**
     * This function notifies the Keymint device of the specified securityLevel that
     * early boot has ended, so that they no longer allow early boot keys to be used.
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the caller does not have the 'EarlyBootEnded'
     *                                     permission.
     * A KeyMint ErrorCode may be returned indicating a backend diagnosed error.
     */
     void earlyBootEnded();

    /**
     * Informs Keystore 2.0 that the an off body event was detected.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the caller does not have the `ReportOffBody`
     *                                     permission.
     * `ResponseCode::SYSTEM_ERROR` - if an unexpected error occurred.
     */
    void onDeviceOffBody();

    /**
     * Migrate a key from one namespace to another. The caller must have use, grant, and delete
     * permissions on the source namespace and rebind permissions on the destination namespace.
     * The source may be specified by Domain::APP, Domain::SELINUX, or Domain::KEY_ID. The target
     * may be specified by Domain::APP or Domain::SELINUX.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - If the caller lacks any of the required permissions.
     * `ResponseCode::KEY_NOT_FOUND` - If the source did not exist.
     * `ResponseCode::INVALID_ARGUMENT` - If the target exists or if any of the above mentioned
     *                                    requirements for the domain parameter are not met.
     * `ResponseCode::SYSTEM_ERROR` - An unexpected system error occurred.
     */
    void migrateKeyNamespace(in KeyDescriptor source, in KeyDescriptor destination);
}
