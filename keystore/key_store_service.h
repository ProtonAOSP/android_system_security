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

#include <keymaster/authorization_set.h>

#include "auth_token_table.h"
#include "keystore.h"
#include "keystore_keymaster_enforcement.h"
#include "operation.h"
#include "permissions.h"

namespace android {

class KeyStoreService : public BnKeystoreService, public IBinder::DeathRecipient {
  public:
    KeyStoreService(KeyStore* keyStore) : mKeyStore(keyStore), mOperationMap(this) {}

    void binderDied(const wp<IBinder>& who);

    int32_t getState(int32_t userId);

    int32_t get(const String16& name, int32_t uid, uint8_t** item, size_t* itemLength);
    int32_t insert(const String16& name, const uint8_t* item, size_t itemLength, int targetUid,
                   int32_t flags);
    int32_t del(const String16& name, int targetUid);
    int32_t exist(const String16& name, int targetUid);
    int32_t list(const String16& prefix, int targetUid, Vector<String16>* matches);

    int32_t reset();

    int32_t onUserPasswordChanged(int32_t userId, const String16& password);
    int32_t onUserAdded(int32_t userId, int32_t parentId);
    int32_t onUserRemoved(int32_t userId);

    int32_t lock(int32_t userId);
    int32_t unlock(int32_t userId, const String16& pw);

    bool isEmpty(int32_t userId);

    int32_t generate(const String16& name, int32_t targetUid, int32_t keyType, int32_t keySize,
                     int32_t flags, Vector<sp<KeystoreArg>>* args);
    int32_t import(const String16& name, const uint8_t* data, size_t length, int targetUid,
                   int32_t flags);
    int32_t sign(const String16& name, const uint8_t* data, size_t length, uint8_t** out,
                 size_t* outLength);
    int32_t verify(const String16& name, const uint8_t* data, size_t dataLength,
                   const uint8_t* signature, size_t signatureLength);

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
    int32_t get_pubkey(const String16& name, uint8_t** pubkey, size_t* pubkeyLength);

    int32_t grant(const String16& name, int32_t granteeUid);
    int32_t ungrant(const String16& name, int32_t granteeUid);

    int64_t getmtime(const String16& name, int32_t uid);

    int32_t duplicate(const String16& srcKey, int32_t srcUid, const String16& destKey,
                      int32_t destUid);

    int32_t is_hardware_backed(const String16& keyType);

    int32_t clear_uid(int64_t targetUid64);

    int32_t addRngEntropy(const uint8_t* data, size_t dataLength);
    int32_t generateKey(const String16& name, const KeymasterArguments& params,
                        const uint8_t* entropy, size_t entropyLength, int uid, int flags,
                        KeyCharacteristics* outCharacteristics);
    int32_t getKeyCharacteristics(const String16& name, const keymaster_blob_t* clientId,
                                  const keymaster_blob_t* appData, int32_t uid,
                                  KeyCharacteristics* outCharacteristics);
    int32_t importKey(const String16& name, const KeymasterArguments& params,
                      keymaster_key_format_t format, const uint8_t* keyData, size_t keyLength,
                      int uid, int flags, KeyCharacteristics* outCharacteristics);
    void exportKey(const String16& name, keymaster_key_format_t format,
                   const keymaster_blob_t* clientId, const keymaster_blob_t* appData, int32_t uid,
                   ExportResult* result);
    void begin(const sp<IBinder>& appToken, const String16& name, keymaster_purpose_t purpose,
               bool pruneable, const KeymasterArguments& params, const uint8_t* entropy,
               size_t entropyLength, int32_t uid, OperationResult* result);
    void update(const sp<IBinder>& token, const KeymasterArguments& params, const uint8_t* data,
                size_t dataLength, OperationResult* result);
    void finish(const sp<IBinder>& token, const KeymasterArguments& params,
                const uint8_t* signature, size_t signatureLength, const uint8_t* entropy,
                size_t entropyLength, OperationResult* result);
    int32_t abort(const sp<IBinder>& token);

    bool isOperationAuthorized(const sp<IBinder>& token);

    int32_t addAuthToken(const uint8_t* token, size_t length);

    int32_t attestKey(const String16& name, const KeymasterArguments& params,
                      KeymasterCertificateChain* outChain) override;

    int32_t onDeviceOffBody();

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
    int32_t checkBinderPermissionAndKeystoreState(perm_t permission, int32_t targetUid = -1,
                                                  bool checkUnlocked = true);

    bool isKeystoreUnlocked(State state);

    bool isKeyTypeSupported(const keymaster2_device_t* device, keymaster_keypair_t keyType);

    /**
     * Check that all keymaster_key_param_t's provided by the application are
     * allowed. Any parameter that keystore adds itself should be disallowed here.
     */
    bool checkAllowedOperationParams(const std::vector<keymaster_key_param_t>& params);

    keymaster_error_t getOperationCharacteristics(const keymaster_key_blob_t& key,
                                                  const keymaster2_device_t* dev,
                                                  const std::vector<keymaster_key_param_t>& params,
                                                  keymaster_key_characteristics_t* out);

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
    int32_t getAuthToken(const keymaster_key_characteristics_t* characteristics,
                         keymaster_operation_handle_t handle, keymaster_purpose_t purpose,
                         const hw_auth_token_t** authToken, bool failOnTokenMissing = true);

    void addAuthToParams(std::vector<keymaster_key_param_t>* params, const hw_auth_token_t* token);

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
    int32_t addOperationAuthTokenIfNeeded(sp<IBinder> token,
                                          std::vector<keymaster_key_param_t>* params);

    /**
     * Translate a result value to a legacy return value. All keystore errors are
     * preserved and keymaster errors become SYSTEM_ERRORs
     */
    int32_t translateResultToLegacyResult(int32_t result);

    keymaster_key_param_t* getKeyAlgorithm(keymaster_key_characteristics_t* characteristics);

    void addLegacyBeginParams(const String16& name, std::vector<keymaster_key_param_t>& params);

    int32_t doLegacySignVerify(const String16& name, const uint8_t* data, size_t length,
                               uint8_t** out, size_t* outLength, const uint8_t* signature,
                               size_t signatureLength, keymaster_purpose_t purpose);

    /**
     * Upgrade a key blob under alias "name", returning the new blob in "blob".  If "blob"
     * previously contained data, it will be overwritten.
     *
     * Returns ::NO_ERROR if the key was upgraded successfully.
     *         KM_ERROR_VERSION_MISMATCH if called on a key whose patch level is greater than or
     *         equal to the current system patch level.
     */
    int32_t upgradeKeyBlob(const String16& name, uid_t targetUid,
                           const keymaster::AuthorizationSet& params, Blob* blob);

    ::KeyStore* mKeyStore;
    OperationMap mOperationMap;
    keymaster::AuthTokenTable mAuthTokenTable;
    KeystoreKeymasterEnforcement enforcement_policy;
};

};  // namespace android

#endif  // KEYSTORE_KEYSTORE_SERVICE_H_
