/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KEYSTORE_KEYSTORE_SERVICE_H_
#define KEYSTORE_KEYSTORE_SERVICE_H_

#include <keystore/IKeystoreService.h>

#include <keystore/authorization_set.h>

#include "auth_token_table.h"
#include "keystore.h"
#include "keystore_keymaster_enforcement.h"
#include "operation.h"
#include "permissions.h"

namespace keystore {

class KeyStoreService : public android::BnKeystoreService, public android::IBinder::DeathRecipient {
    typedef ::android::sp<::android::hardware::keymaster::V3_0::IKeymasterDevice> km_device_t;

  public:
    explicit KeyStoreService(KeyStore* keyStore) : mKeyStore(keyStore), mOperationMap(this) {}

    void binderDied(const android::wp<android::IBinder>& who);

    KeyStoreServiceReturnCode getState(int32_t userId) override;

    KeyStoreServiceReturnCode get(const android::String16& name, int32_t uid,
                                  hidl_vec<uint8_t>* item) override;
    KeyStoreServiceReturnCode insert(const android::String16& name, const hidl_vec<uint8_t>& item,
                                     int targetUid, int32_t flags) override;
    KeyStoreServiceReturnCode del(const android::String16& name, int targetUid) override;
    KeyStoreServiceReturnCode exist(const android::String16& name, int targetUid) override;
    KeyStoreServiceReturnCode list(const android::String16& prefix, int targetUid,
                                   android::Vector<android::String16>* matches) override;

    KeyStoreServiceReturnCode reset() override;

    KeyStoreServiceReturnCode onUserPasswordChanged(int32_t userId,
                                                    const android::String16& password) override;
    KeyStoreServiceReturnCode onUserAdded(int32_t userId, int32_t parentId) override;
    KeyStoreServiceReturnCode onUserRemoved(int32_t userId) override;

    KeyStoreServiceReturnCode lock(int32_t userId) override;
    KeyStoreServiceReturnCode unlock(int32_t userId, const android::String16& pw) override;

    bool isEmpty(int32_t userId) override;

    KeyStoreServiceReturnCode
    generate(const android::String16& name, int32_t targetUid, int32_t keyType, int32_t keySize,
             int32_t flags, android::Vector<android::sp<android::KeystoreArg>>* args) override;
    KeyStoreServiceReturnCode import(const android::String16& name, const hidl_vec<uint8_t>& data,
                                     int targetUid, int32_t flags) override;
    KeyStoreServiceReturnCode sign(const android::String16& name, const hidl_vec<uint8_t>& data,
                                   hidl_vec<uint8_t>* out) override;
    KeyStoreServiceReturnCode verify(const android::String16& name, const hidl_vec<uint8_t>& data,
                                     const hidl_vec<uint8_t>& signature) override;

    /*
     * TODO: The abstraction between things stored in hardware and regular blobs
     * of data stored on the filesystem should be moved down to keystore itself.
     * Unfortunately the Java code that calls this has naming conventions that it
     * knows about. Ideally keystore shouldn't be used to store random blobs of
     * data.
     *
     * Until that happens, it's necessary to have a separate "get_pubkey" and
     * "del_key" since the Java code doesn't really communicate what it's
     * intentions are.
     */
    KeyStoreServiceReturnCode get_pubkey(const android::String16& name,
                                         hidl_vec<uint8_t>* pubKey) override;

    android::String16 grant(const android::String16& name, int32_t granteeUid) override;
    KeyStoreServiceReturnCode ungrant(const android::String16& name, int32_t granteeUid) override;

    int64_t getmtime(const android::String16& name, int32_t uid) override;

    KeyStoreServiceReturnCode duplicate(const android::String16& srcKey, int32_t srcUid,
                                        const android::String16& destKey, int32_t destUid) override;

    int32_t is_hardware_backed(const android::String16& keyType) override;

    KeyStoreServiceReturnCode clear_uid(int64_t targetUid64) override;

    KeyStoreServiceReturnCode addRngEntropy(const hidl_vec<uint8_t>& entropy) override;
    KeyStoreServiceReturnCode generateKey(const android::String16& name,
                                          const hidl_vec<KeyParameter>& params,
                                          const hidl_vec<uint8_t>& entropy, int uid, int flags,
                                          KeyCharacteristics* outCharacteristics) override;
    KeyStoreServiceReturnCode
    getKeyCharacteristics(const android::String16& name, const hidl_vec<uint8_t>& clientId,
                          const hidl_vec<uint8_t>& appData, int32_t uid,
                          KeyCharacteristics* outCharacteristics) override;
    KeyStoreServiceReturnCode importKey(const android::String16& name,
                                        const hidl_vec<KeyParameter>& params, KeyFormat format,
                                        const hidl_vec<uint8_t>& keyData, int uid, int flags,
                                        KeyCharacteristics* outCharacteristics) override;
    void exportKey(const android::String16& name, KeyFormat format,
                   const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, int32_t uid,
                   android::ExportResult* result) override;
    void begin(const sp<android::IBinder>& appToken, const android::String16& name,
               KeyPurpose purpose, bool pruneable, const hidl_vec<KeyParameter>& params,
               const hidl_vec<uint8_t>& entropy, int32_t uid,
               android::OperationResult* result) override;
    void update(const sp<android::IBinder>& token, const hidl_vec<KeyParameter>& params,
                const hidl_vec<uint8_t>& data, android::OperationResult* result) override;
    void finish(const sp<android::IBinder>& token, const hidl_vec<KeyParameter>& params,
                const hidl_vec<uint8_t>& signature, const hidl_vec<uint8_t>& entropy,
                android::OperationResult* result) override;
    KeyStoreServiceReturnCode abort(const sp<android::IBinder>& token) override;

    bool isOperationAuthorized(const sp<android::IBinder>& token) override;

    KeyStoreServiceReturnCode addAuthToken(const uint8_t* token, size_t length) override;

    KeyStoreServiceReturnCode attestKey(const android::String16& name,
                                        const hidl_vec<KeyParameter>& params,
                                        hidl_vec<hidl_vec<uint8_t>>* outChain) override;

    KeyStoreServiceReturnCode attestDeviceIds(const hidl_vec<KeyParameter>& params,
                                              hidl_vec<hidl_vec<uint8_t>>* outChain) override;

    KeyStoreServiceReturnCode onDeviceOffBody() override;

  private:
    static const int32_t UID_SELF = -1;

    /**
     * Prune the oldest pruneable operation.
     */
    bool pruneOperation();

    /**
     * Get the effective target uid for a binder operation that takes an
     * optional uid as the target.
     */
    uid_t getEffectiveUid(int32_t targetUid);

    /**
     * Check if the caller of the current binder method has the required
     * permission and if acting on other uids the grants to do so.
     */
    bool checkBinderPermission(perm_t permission, int32_t targetUid = UID_SELF);

    /**
     * Check if the caller of the current binder method has the required
     * permission and the target uid is the caller or the caller is system.
     */
    bool checkBinderPermissionSelfOrSystem(perm_t permission, int32_t targetUid);

    /**
     * Check if the caller of the current binder method has the required
     * permission or the target of the operation is the caller's uid. This is
     * for operation where the permission is only for cross-uid activity and all
     * uids are allowed to act on their own (ie: clearing all entries for a
     * given uid).
     */
    bool checkBinderPermissionOrSelfTarget(perm_t permission, int32_t targetUid);

    /**
     * Helper method to check that the caller has the required permission as
     * well as the keystore is in the unlocked state if checkUnlocked is true.
     *
     * Returns NO_ERROR on success, PERMISSION_DENIED on a permission error and
     * otherwise the state of keystore when not unlocked and checkUnlocked is
     * true.
     */
    KeyStoreServiceReturnCode checkBinderPermissionAndKeystoreState(perm_t permission,
                                                                    int32_t targetUid = -1,
                                                                    bool checkUnlocked = true);

    bool isKeystoreUnlocked(State state);

    /**
     * Check that all keymaster_key_param_t's provided by the application are
     * allowed. Any parameter that keystore adds itself should be disallowed here.
     */
    bool checkAllowedOperationParams(const hidl_vec<KeyParameter>& params);

    ErrorCode getOperationCharacteristics(const hidl_vec<uint8_t>& key, km_device_t* dev,
                                          const AuthorizationSet& params, KeyCharacteristics* out);

    /**
     * Get the auth token for this operation from the auth token table.
     *
     * Returns ::NO_ERROR if the auth token was set or none was required.
     *         ::OP_AUTH_NEEDED if it is a per op authorization, no
     *         authorization token exists for that operation and
     *         failOnTokenMissing is false.
     *         KM_ERROR_KEY_USER_NOT_AUTHENTICATED if there is no valid auth
     *         token for the operation
     */
    KeyStoreServiceReturnCode getAuthToken(const KeyCharacteristics& characteristics,
                                           uint64_t handle, KeyPurpose purpose,
                                           const HardwareAuthToken** authToken,
                                           bool failOnTokenMissing = true);

    /**
     * Add the auth token for the operation to the param list if the operation
     * requires authorization. Uses the cached result in the OperationMap if available
     * otherwise gets the token from the AuthTokenTable and caches the result.
     *
     * Returns ::NO_ERROR if the auth token was added or not needed.
     *         KM_ERROR_KEY_USER_NOT_AUTHENTICATED if the operation is not
     *         authenticated.
     *         KM_ERROR_INVALID_OPERATION_HANDLE if token is not a valid
     *         operation token.
     */
    KeyStoreServiceReturnCode addOperationAuthTokenIfNeeded(const sp<android::IBinder>& token,
                                                            AuthorizationSet* params);

    /**
     * Translate a result value to a legacy return value. All keystore errors are
     * preserved and keymaster errors become SYSTEM_ERRORs
     */
    KeyStoreServiceReturnCode translateResultToLegacyResult(int32_t result);

    void addLegacyBeginParams(const android::String16& name, AuthorizationSet* params);

    KeyStoreServiceReturnCode doLegacySignVerify(const android::String16& name,
                                                 const hidl_vec<uint8_t>& data,
                                                 hidl_vec<uint8_t>* out,
                                                 const hidl_vec<uint8_t>& signature,
                                                 KeyPurpose purpose);

    /**
     * Upgrade a key blob under alias "name", returning the new blob in "blob".  If "blob"
     * previously contained data, it will be overwritten.
     *
     * Returns ::NO_ERROR if the key was upgraded successfully.
     *         KM_ERROR_VERSION_MISMATCH if called on a key whose patch level is greater than or
     *         equal to the current system patch level.
     */
    KeyStoreServiceReturnCode upgradeKeyBlob(const android::String16& name, uid_t targetUid,
                                             const AuthorizationSet& params, Blob* blob);

    ::KeyStore* mKeyStore;

    /**
     * This mutex locks keystore operations from concurrent execution.
     * The keystore service has always been conceptually single threaded. Even with the introduction
     * of keymaster workers, it was assumed that the dispatcher thread executes exclusively on
     * certain code paths. With the introduction of wifi Keystore service in the keystore process
     * this assumption no longer holds as the hwbinder thread servicing this interface makes
     * functions (rather than IPC) calls into keystore. This mutex protects the keystore logic
     * from concurrent execution.
     */
    std::recursive_mutex keystoreServiceMutex_;
    OperationMap mOperationMap;
    keystore::AuthTokenTable mAuthTokenTable;
    KeystoreKeymasterEnforcement enforcement_policy;
};

};  // namespace keystore

#endif  // KEYSTORE_KEYSTORE_SERVICE_H_
