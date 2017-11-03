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

#define LOG_TAG "keystore"

#include "key_store_service.h"

#include <fcntl.h>
#include <sys/stat.h>

#include <sstream>

#include <binder/IPCThreadState.h>

#include <private/android_filesystem_config.h>

#include <hardware/keymaster_defs.h>

#include "defaults.h"
#include "keystore_utils.h"

using keymaster::AuthorizationSet;
using keymaster::AuthorizationSetBuilder;
using keymaster::TAG_APPLICATION_DATA;
using keymaster::TAG_APPLICATION_ID;

namespace android {

const size_t MAX_OPERATIONS = 15;

struct BIGNUM_Delete {
    void operator()(BIGNUM* p) const { BN_free(p); }
};
typedef UniquePtr<BIGNUM, BIGNUM_Delete> Unique_BIGNUM;

struct Malloc_Delete {
    void operator()(uint8_t* p) const { free(p); }
};

void KeyStoreService::binderDied(const wp<IBinder>& who) {
    auto operations = mOperationMap.getOperationsForToken(who.unsafe_get());
    for (auto token : operations) {
        abort(token);
    }
}

int32_t KeyStoreService::getState(int32_t userId) {
    if (!checkBinderPermission(P_GET_STATE)) {
        return ::PERMISSION_DENIED;
    }

    return mKeyStore->getState(userId);
}

int32_t KeyStoreService::get(const String16& name, int32_t uid, uint8_t** item,
                             size_t* itemLength) {
    uid_t targetUid = getEffectiveUid(uid);
    if (!checkBinderPermission(P_GET, targetUid)) {
        return ::PERMISSION_DENIED;
    }

    String8 name8(name);
    Blob keyBlob;

    ResponseCode responseCode = mKeyStore->getKeyForName(&keyBlob, name8, targetUid, TYPE_GENERIC);
    if (responseCode != ::NO_ERROR) {
        *item = NULL;
        *itemLength = 0;
        return responseCode;
    }

    *item = (uint8_t*)malloc(keyBlob.getLength());
    memcpy(*item, keyBlob.getValue(), keyBlob.getLength());
    *itemLength = keyBlob.getLength();

    return ::NO_ERROR;
}

int32_t KeyStoreService::insert(const String16& name, const uint8_t* item, size_t itemLength,
                                int targetUid, int32_t flags) {
    targetUid = getEffectiveUid(targetUid);
    int32_t result =
        checkBinderPermissionAndKeystoreState(P_INSERT, targetUid, flags & KEYSTORE_FLAG_ENCRYPTED);
    if (result != ::NO_ERROR) {
        return result;
    }

    String8 name8(name);
    String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, targetUid, ::TYPE_GENERIC));

    Blob keyBlob(item, itemLength, NULL, 0, ::TYPE_GENERIC);
    keyBlob.setEncrypted(flags & KEYSTORE_FLAG_ENCRYPTED);

    return mKeyStore->put(filename.string(), &keyBlob, get_user_id(targetUid));
}

int32_t KeyStoreService::del(const String16& name, int targetUid) {
    targetUid = getEffectiveUid(targetUid);
    if (!checkBinderPermission(P_DELETE, targetUid)) {
        return ::PERMISSION_DENIED;
    }
    String8 name8(name);
    String8 filename = mKeyStore->getBlobFileNameIfExists(name8, targetUid, ::TYPE_ANY);
    if (filename.isEmpty()) return ResponseCode::KEY_NOT_FOUND;

    ResponseCode result = mKeyStore->del(filename.string(), ::TYPE_ANY,
            get_user_id(targetUid));
    if (result != ResponseCode::NO_ERROR) {
        return result;
    }

    filename = mKeyStore->getBlobFileNameIfExists(name8, targetUid, ::TYPE_KEY_CHARACTERISTICS);
    if (!filename.isEmpty()) {
        return mKeyStore->del(filename.string(), ::TYPE_KEY_CHARACTERISTICS,
                get_user_id(targetUid));
    }
    return ResponseCode::NO_ERROR;
}

int32_t KeyStoreService::exist(const String16& name, int targetUid) {
    targetUid = getEffectiveUid(targetUid);
    if (!checkBinderPermission(P_EXIST, targetUid)) {
        return ::PERMISSION_DENIED;
    }

    String8 filename = mKeyStore->getBlobFileNameIfExists(String8(name), targetUid,  ::TYPE_ANY);
    return (!filename.isEmpty()) ? ResponseCode::NO_ERROR : ResponseCode::KEY_NOT_FOUND;
}

int32_t KeyStoreService::list(const String16& prefix, int targetUid, Vector<String16>* matches) {
    targetUid = getEffectiveUid(targetUid);
    if (!checkBinderPermission(P_LIST, targetUid)) {
        return ::PERMISSION_DENIED;
    }
    const String8 prefix8(prefix);
    String8 filename(mKeyStore->getKeyNameForUid(prefix8, targetUid, TYPE_ANY));

    if (mKeyStore->list(filename, matches, get_user_id(targetUid)) != ::NO_ERROR) {
        return ::SYSTEM_ERROR;
    }
    return ::NO_ERROR;
}

int32_t KeyStoreService::reset() {
    if (!checkBinderPermission(P_RESET)) {
        return ::PERMISSION_DENIED;
    }

    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    mKeyStore->resetUser(get_user_id(callingUid), false);
    return ::NO_ERROR;
}

int32_t KeyStoreService::onUserPasswordChanged(int32_t userId, const String16& password) {
    if (!checkBinderPermission(P_PASSWORD)) {
        return ::PERMISSION_DENIED;
    }

    const String8 password8(password);
    // Flush the auth token table to prevent stale tokens from sticking
    // around.
    mAuthTokenTable.Clear();

    if (password.size() == 0) {
        ALOGI("Secure lockscreen for user %d removed, deleting encrypted entries", userId);
        mKeyStore->resetUser(userId, true);
        return ::NO_ERROR;
    } else {
        switch (mKeyStore->getState(userId)) {
        case ::STATE_UNINITIALIZED: {
            // generate master key, encrypt with password, write to file,
            // initialize mMasterKey*.
            return mKeyStore->initializeUser(password8, userId);
        }
        case ::STATE_NO_ERROR: {
            // rewrite master key with new password.
            return mKeyStore->writeMasterKey(password8, userId);
        }
        case ::STATE_LOCKED: {
            ALOGE("Changing user %d's password while locked, clearing old encryption", userId);
            mKeyStore->resetUser(userId, true);
            return mKeyStore->initializeUser(password8, userId);
        }
        }
        return ::SYSTEM_ERROR;
    }
}

int32_t KeyStoreService::onUserAdded(int32_t userId, int32_t parentId) {
    if (!checkBinderPermission(P_USER_CHANGED)) {
        return ::PERMISSION_DENIED;
    }

    // Sanity check that the new user has an empty keystore.
    if (!mKeyStore->isEmpty(userId)) {
        ALOGW("New user %d's keystore not empty. Clearing old entries.", userId);
    }
    // Unconditionally clear the keystore, just to be safe.
    mKeyStore->resetUser(userId, false);
    if (parentId != -1) {
        // This profile must share the same master key password as the parent profile. Because the
        // password of the parent profile is not known here, the best we can do is copy the parent's
        // master key and master key file. This makes this profile use the same master key as the
        // parent profile, forever.
        return mKeyStore->copyMasterKey(parentId, userId);
    } else {
        return ::NO_ERROR;
    }
}

int32_t KeyStoreService::onUserRemoved(int32_t userId) {
    if (!checkBinderPermission(P_USER_CHANGED)) {
        return ::PERMISSION_DENIED;
    }

    mKeyStore->resetUser(userId, false);
    return ::NO_ERROR;
}

int32_t KeyStoreService::lock(int32_t userId) {
    if (!checkBinderPermission(P_LOCK)) {
        return ::PERMISSION_DENIED;
    }

    State state = mKeyStore->getState(userId);
    if (state != ::STATE_NO_ERROR) {
        ALOGD("calling lock in state: %d", state);
        return state;
    }

    mKeyStore->lock(userId);
    return ::NO_ERROR;
}

int32_t KeyStoreService::unlock(int32_t userId, const String16& pw) {
    if (!checkBinderPermission(P_UNLOCK)) {
        return ::PERMISSION_DENIED;
    }

    State state = mKeyStore->getState(userId);
    if (state != ::STATE_LOCKED) {
        switch (state) {
        case ::STATE_NO_ERROR:
            ALOGI("calling unlock when already unlocked, ignoring.");
            break;
        case ::STATE_UNINITIALIZED:
            ALOGE("unlock called on uninitialized keystore.");
            break;
        default:
            ALOGE("unlock called on keystore in unknown state: %d", state);
            break;
        }
        return state;
    }

    const String8 password8(pw);
    // read master key, decrypt with password, initialize mMasterKey*.
    return mKeyStore->readMasterKey(password8, userId);
}

bool KeyStoreService::isEmpty(int32_t userId) {
    if (!checkBinderPermission(P_IS_EMPTY)) {
        return false;
    }

    return mKeyStore->isEmpty(userId);
}

int32_t KeyStoreService::generate(const String16& name, int32_t targetUid, int32_t keyType,
                                  int32_t keySize, int32_t flags, Vector<sp<KeystoreArg>>* args) {
    targetUid = getEffectiveUid(targetUid);
    int32_t result =
        checkBinderPermissionAndKeystoreState(P_INSERT, targetUid, flags & KEYSTORE_FLAG_ENCRYPTED);
    if (result != ::NO_ERROR) {
        return result;
    }

    KeymasterArguments params;
    add_legacy_key_authorizations(keyType, &params.params);

    switch (keyType) {
    case EVP_PKEY_EC: {
        params.params.push_back(keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_EC));
        if (keySize == -1) {
            keySize = EC_DEFAULT_KEY_SIZE;
        } else if (keySize < EC_MIN_KEY_SIZE || keySize > EC_MAX_KEY_SIZE) {
            ALOGI("invalid key size %d", keySize);
            return ::SYSTEM_ERROR;
        }
        params.params.push_back(keymaster_param_int(KM_TAG_KEY_SIZE, keySize));
        break;
    }
    case EVP_PKEY_RSA: {
        params.params.push_back(keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA));
        if (keySize == -1) {
            keySize = RSA_DEFAULT_KEY_SIZE;
        } else if (keySize < RSA_MIN_KEY_SIZE || keySize > RSA_MAX_KEY_SIZE) {
            ALOGI("invalid key size %d", keySize);
            return ::SYSTEM_ERROR;
        }
        params.params.push_back(keymaster_param_int(KM_TAG_KEY_SIZE, keySize));
        unsigned long exponent = RSA_DEFAULT_EXPONENT;
        if (args->size() > 1) {
            ALOGI("invalid number of arguments: %zu", args->size());
            return ::SYSTEM_ERROR;
        } else if (args->size() == 1) {
            sp<KeystoreArg> expArg = args->itemAt(0);
            if (expArg != NULL) {
                Unique_BIGNUM pubExpBn(BN_bin2bn(
                    reinterpret_cast<const unsigned char*>(expArg->data()), expArg->size(), NULL));
                if (pubExpBn.get() == NULL) {
                    ALOGI("Could not convert public exponent to BN");
                    return ::SYSTEM_ERROR;
                }
                exponent = BN_get_word(pubExpBn.get());
                if (exponent == 0xFFFFFFFFL) {
                    ALOGW("cannot represent public exponent as a long value");
                    return ::SYSTEM_ERROR;
                }
            } else {
                ALOGW("public exponent not read");
                return ::SYSTEM_ERROR;
            }
        }
        params.params.push_back(keymaster_param_long(KM_TAG_RSA_PUBLIC_EXPONENT, exponent));
        break;
    }
    default: {
        ALOGW("Unsupported key type %d", keyType);
        return ::SYSTEM_ERROR;
    }
    }

    int32_t rc = generateKey(name, params, NULL, 0, targetUid, flags,
                             /*outCharacteristics*/ NULL);
    if (rc != ::NO_ERROR) {
        ALOGW("generate failed: %d", rc);
    }
    return translateResultToLegacyResult(rc);
}

int32_t KeyStoreService::import(const String16& name, const uint8_t* data, size_t length,
                                int targetUid, int32_t flags) {
    const uint8_t* ptr = data;

    Unique_PKCS8_PRIV_KEY_INFO pkcs8(d2i_PKCS8_PRIV_KEY_INFO(NULL, &ptr, length));
    if (!pkcs8.get()) {
        return ::SYSTEM_ERROR;
    }
    Unique_EVP_PKEY pkey(EVP_PKCS82PKEY(pkcs8.get()));
    if (!pkey.get()) {
        return ::SYSTEM_ERROR;
    }
    int type = EVP_PKEY_type(pkey->type);
    KeymasterArguments params;
    add_legacy_key_authorizations(type, &params.params);
    switch (type) {
    case EVP_PKEY_RSA:
        params.params.push_back(keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA));
        break;
    case EVP_PKEY_EC:
        params.params.push_back(keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_EC));
        break;
    default:
        ALOGW("Unsupported key type %d", type);
        return ::SYSTEM_ERROR;
    }
    int32_t rc = importKey(name, params, KM_KEY_FORMAT_PKCS8, data, length, targetUid, flags,
                           /*outCharacteristics*/ NULL);
    if (rc != ::NO_ERROR) {
        ALOGW("importKey failed: %d", rc);
    }
    return translateResultToLegacyResult(rc);
}

int32_t KeyStoreService::sign(const String16& name, const uint8_t* data, size_t length,
                              uint8_t** out, size_t* outLength) {
    if (!checkBinderPermission(P_SIGN)) {
        return ::PERMISSION_DENIED;
    }
    return doLegacySignVerify(name, data, length, out, outLength, NULL, 0, KM_PURPOSE_SIGN);
}

int32_t KeyStoreService::verify(const String16& name, const uint8_t* data, size_t dataLength,
                                const uint8_t* signature, size_t signatureLength) {
    if (!checkBinderPermission(P_VERIFY)) {
        return ::PERMISSION_DENIED;
    }
    return doLegacySignVerify(name, data, dataLength, NULL, NULL, signature, signatureLength,
                              KM_PURPOSE_VERIFY);
}

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
int32_t KeyStoreService::get_pubkey(const String16& name, uint8_t** pubkey, size_t* pubkeyLength) {
    ExportResult result;
    exportKey(name, KM_KEY_FORMAT_X509, NULL, NULL, UID_SELF, &result);
    if (result.resultCode != ::NO_ERROR) {
        ALOGW("export failed: %d", result.resultCode);
        return translateResultToLegacyResult(result.resultCode);
    }

    *pubkey = result.exportData.release();
    *pubkeyLength = result.dataLength;
    return ::NO_ERROR;
}

int32_t KeyStoreService::grant(const String16& name, int32_t granteeUid) {
    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    int32_t result = checkBinderPermissionAndKeystoreState(P_GRANT);
    if (result != ::NO_ERROR) {
        return result;
    }

    String8 name8(name);
    String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, callingUid, ::TYPE_ANY));

    if (access(filename.string(), R_OK) == -1) {
        return (errno != ENOENT) ? ::SYSTEM_ERROR : ::KEY_NOT_FOUND;
    }

    mKeyStore->addGrant(filename.string(), granteeUid);
    return ::NO_ERROR;
}

int32_t KeyStoreService::ungrant(const String16& name, int32_t granteeUid) {
    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    int32_t result = checkBinderPermissionAndKeystoreState(P_GRANT);
    if (result != ::NO_ERROR) {
        return result;
    }

    String8 name8(name);
    String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, callingUid, ::TYPE_ANY));

    if (access(filename.string(), R_OK) == -1) {
        return (errno != ENOENT) ? ::SYSTEM_ERROR : ::KEY_NOT_FOUND;
    }

    return mKeyStore->removeGrant(filename.string(), granteeUid) ? ::NO_ERROR : ::KEY_NOT_FOUND;
}

int64_t KeyStoreService::getmtime(const String16& name, int32_t uid) {
    uid_t targetUid = getEffectiveUid(uid);
    if (!checkBinderPermission(P_GET, targetUid)) {
        ALOGW("permission denied for %d: getmtime", targetUid);
        return -1L;
    }

    String8 filename = mKeyStore->getBlobFileNameIfExists(String8(name), targetUid, ::TYPE_ANY);

    if (filename.isEmpty()) {
        ALOGW("could not access %s for getmtime", filename.string());
        return -1L;
    }

    int fd = TEMP_FAILURE_RETRY(open(filename.string(), O_NOFOLLOW, O_RDONLY));
    if (fd < 0) {
        ALOGW("could not open %s for getmtime", filename.string());
        return -1L;
    }

    struct stat s;
    int ret = fstat(fd, &s);
    close(fd);
    if (ret == -1) {
        ALOGW("could not stat %s for getmtime", filename.string());
        return -1L;
    }

    return static_cast<int64_t>(s.st_mtime);
}

// TODO(tuckeris): This is dead code, remove it.  Don't bother copying over key characteristics here
int32_t KeyStoreService::duplicate(const String16& srcKey, int32_t srcUid, const String16& destKey,
                                   int32_t destUid) {
    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    pid_t spid = IPCThreadState::self()->getCallingPid();
    if (!has_permission(callingUid, P_DUPLICATE, spid)) {
        ALOGW("permission denied for %d: duplicate", callingUid);
        return -1L;
    }

    State state = mKeyStore->getState(get_user_id(callingUid));
    if (!isKeystoreUnlocked(state)) {
        ALOGD("calling duplicate in state: %d", state);
        return state;
    }

    if (srcUid == -1 || static_cast<uid_t>(srcUid) == callingUid) {
        srcUid = callingUid;
    } else if (!is_granted_to(callingUid, srcUid)) {
        ALOGD("migrate not granted from source: %d -> %d", callingUid, srcUid);
        return ::PERMISSION_DENIED;
    }

    if (destUid == -1) {
        destUid = callingUid;
    }

    if (srcUid != destUid) {
        if (static_cast<uid_t>(srcUid) != callingUid) {
            ALOGD("can only duplicate from caller to other or to same uid: "
                  "calling=%d, srcUid=%d, destUid=%d",
                  callingUid, srcUid, destUid);
            return ::PERMISSION_DENIED;
        }

        if (!is_granted_to(callingUid, destUid)) {
            ALOGD("duplicate not granted to dest: %d -> %d", callingUid, destUid);
            return ::PERMISSION_DENIED;
        }
    }

    String8 source8(srcKey);
    String8 sourceFile(mKeyStore->getKeyNameForUidWithDir(source8, srcUid, ::TYPE_ANY));

    String8 target8(destKey);
    String8 targetFile(mKeyStore->getKeyNameForUidWithDir(target8, destUid, ::TYPE_ANY));

    if (access(targetFile.string(), W_OK) != -1 || errno != ENOENT) {
        ALOGD("destination already exists: %s", targetFile.string());
        return ::SYSTEM_ERROR;
    }

    Blob keyBlob;
    ResponseCode responseCode =
        mKeyStore->get(sourceFile.string(), &keyBlob, TYPE_ANY, get_user_id(srcUid));
    if (responseCode != ::NO_ERROR) {
        return responseCode;
    }

    return mKeyStore->put(targetFile.string(), &keyBlob, get_user_id(destUid));
}

int32_t KeyStoreService::is_hardware_backed(const String16& keyType) {
    return mKeyStore->isHardwareBacked(keyType) ? 1 : 0;
}

int32_t KeyStoreService::clear_uid(int64_t targetUid64) {
    uid_t targetUid = getEffectiveUid(targetUid64);
    if (!checkBinderPermissionSelfOrSystem(P_CLEAR_UID, targetUid)) {
        return ::PERMISSION_DENIED;
    }

    String8 prefix = String8::format("%u_", targetUid);
    Vector<String16> aliases;
    if (mKeyStore->list(prefix, &aliases, get_user_id(targetUid)) != ::NO_ERROR) {
        return ::SYSTEM_ERROR;
    }

    for (uint32_t i = 0; i < aliases.size(); i++) {
        String8 name8(aliases[i]);
        String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, targetUid, ::TYPE_ANY));
        mKeyStore->del(filename.string(), ::TYPE_ANY, get_user_id(targetUid));

        // del() will fail silently if no cached characteristics are present for this alias.
        String8 chr_filename(mKeyStore->getKeyNameForUidWithDir(name8, targetUid,
            ::TYPE_KEY_CHARACTERISTICS));
        mKeyStore->del(chr_filename.string(), ::TYPE_KEY_CHARACTERISTICS, get_user_id(targetUid));
    }
    return ::NO_ERROR;
}

int32_t KeyStoreService::addRngEntropy(const uint8_t* data, size_t dataLength) {
    const auto* device = mKeyStore->getDevice();
    const auto* fallback = mKeyStore->getFallbackDevice();
    int32_t devResult = KM_ERROR_UNIMPLEMENTED;
    int32_t fallbackResult = KM_ERROR_UNIMPLEMENTED;
    if (device->common.module->module_api_version >= KEYMASTER_MODULE_API_VERSION_1_0 &&
        device->add_rng_entropy != NULL) {
        devResult = device->add_rng_entropy(device, data, dataLength);
    }
    if (fallback->add_rng_entropy) {
        fallbackResult = fallback->add_rng_entropy(fallback, data, dataLength);
    }
    if (devResult) {
        return devResult;
    }
    if (fallbackResult) {
        return fallbackResult;
    }
    return ::NO_ERROR;
}

int32_t KeyStoreService::generateKey(const String16& name, const KeymasterArguments& params,
                                     const uint8_t* entropy, size_t entropyLength, int uid,
                                     int flags, KeyCharacteristics* outCharacteristics) {
    uid = getEffectiveUid(uid);
    int rc = checkBinderPermissionAndKeystoreState(P_INSERT, uid, flags & KEYSTORE_FLAG_ENCRYPTED);
    if (rc != ::NO_ERROR) {
        return rc;
    }

    rc = KM_ERROR_UNIMPLEMENTED;
    bool isFallback = false;
    keymaster_key_blob_t blob;
    keymaster_key_characteristics_t out = {{nullptr, 0}, {nullptr, 0}};

    const auto* device = mKeyStore->getDevice();
    const auto* fallback = mKeyStore->getFallbackDevice();
    std::vector<keymaster_key_param_t> opParams(params.params);
    const keymaster_key_param_set_t inParams = {opParams.data(), opParams.size()};
    if (device == NULL) {
        return ::SYSTEM_ERROR;
    }

    // Capture characteristics before they're potentially stripped by the device
    AuthorizationSet keyCharacteristics(opParams.data(), opParams.size());
    if (keyCharacteristics.is_valid() != AuthorizationSet::Error::OK) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    UniquePtr<uint8_t[]> kc_buf;
    kc_buf.reset(new (std::nothrow) uint8_t[keyCharacteristics.SerializedSize()]);
    if (!kc_buf.get()) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    keyCharacteristics.Serialize(kc_buf.get(), kc_buf.get() + keyCharacteristics.SerializedSize());

    // TODO: Seed from Linux RNG before this.
    if (device->common.module->module_api_version >= KEYMASTER_MODULE_API_VERSION_1_0 &&
        device->generate_key != NULL) {
        if (!entropy) {
            rc = KM_ERROR_OK;
        } else if (device->add_rng_entropy) {
            rc = device->add_rng_entropy(device, entropy, entropyLength);
        } else {
            rc = KM_ERROR_UNIMPLEMENTED;
        }
        if (rc == KM_ERROR_OK) {
            rc =
                device->generate_key(device, &inParams, &blob, outCharacteristics ? &out : nullptr);
        }
    }
    // If the HW device didn't support generate_key or generate_key failed
    // fall back to the software implementation.
    if (rc && fallback->generate_key != NULL) {
        ALOGW("Primary keymaster device failed to generate key, falling back to SW.");
        isFallback = true;
        if (!entropy) {
            rc = KM_ERROR_OK;
        } else if (fallback->add_rng_entropy) {
            rc = fallback->add_rng_entropy(fallback, entropy, entropyLength);
        } else {
            rc = KM_ERROR_UNIMPLEMENTED;
        }
        if (rc == KM_ERROR_OK) {
            rc = fallback->generate_key(fallback, &inParams, &blob,
                                        outCharacteristics ? &out : nullptr);
        }
    }

    if (outCharacteristics) {
        outCharacteristics->characteristics = out;
    }

    if (rc) {
        return rc;
    }

    // Write the key:
    String8 name8(name);
    String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, uid, ::TYPE_KEYMASTER_10));

    Blob keyBlob(blob.key_material, blob.key_material_size, NULL, 0, ::TYPE_KEYMASTER_10);
    keyBlob.setFallback(isFallback);
    keyBlob.setEncrypted(flags & KEYSTORE_FLAG_ENCRYPTED);

    free(const_cast<uint8_t*>(blob.key_material));
    rc = mKeyStore->put(filename.string(), &keyBlob, get_user_id(uid));

    if (rc != ::NO_ERROR) {
        return rc;
    }

    // Write the characteristics:
    String8 cFilename(mKeyStore->getKeyNameForUidWithDir(name8, uid, ::TYPE_KEY_CHARACTERISTICS));

    Blob charBlob(kc_buf.get(), keyCharacteristics.SerializedSize(),
        NULL, 0, ::TYPE_KEY_CHARACTERISTICS);
    charBlob.setFallback(isFallback);
    charBlob.setEncrypted(flags & KEYSTORE_FLAG_ENCRYPTED);

    return mKeyStore->put(cFilename.string(), &charBlob, get_user_id(uid));
}

int32_t KeyStoreService::getKeyCharacteristics(const String16& name,
                                               const keymaster_blob_t* clientId,
                                               const keymaster_blob_t* appData, int32_t uid,
                                               KeyCharacteristics* outCharacteristics) {
    if (!outCharacteristics) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }

    uid_t targetUid = getEffectiveUid(uid);
    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    if (!is_granted_to(callingUid, targetUid)) {
        ALOGW("uid %d not permitted to act for uid %d in getKeyCharacteristics", callingUid,
              targetUid);
        return ::PERMISSION_DENIED;
    }

    Blob keyBlob;
    String8 name8(name);
    int rc;

    ResponseCode responseCode =
        mKeyStore->getKeyForName(&keyBlob, name8, targetUid, TYPE_KEYMASTER_10);
    if (responseCode != ::NO_ERROR) {
        return responseCode;
    }
    keymaster_key_blob_t key = {keyBlob.getValue(), static_cast<size_t>(keyBlob.getLength())};
    auto* dev = mKeyStore->getDeviceForBlob(keyBlob);
    keymaster_key_characteristics_t out = {};
    if (!dev->get_key_characteristics) {
        ALOGE("device does not implement get_key_characteristics");
        return KM_ERROR_UNIMPLEMENTED;
    }
    rc = dev->get_key_characteristics(dev, &key, clientId, appData, &out);
    if (rc == KM_ERROR_KEY_REQUIRES_UPGRADE) {
        AuthorizationSet upgradeParams;
        if (clientId && clientId->data && clientId->data_length) {
            upgradeParams.push_back(TAG_APPLICATION_ID, *clientId);
        }
        if (appData && appData->data && appData->data_length) {
            upgradeParams.push_back(TAG_APPLICATION_DATA, *appData);
        }
        rc = upgradeKeyBlob(name, targetUid, upgradeParams, &keyBlob);
        if (rc != ::NO_ERROR) {
            return rc;
        }
        key = {keyBlob.getValue(), static_cast<size_t>(keyBlob.getLength())};
        rc = dev->get_key_characteristics(dev, &key, clientId, appData, &out);
    }
    if (rc != KM_ERROR_OK) {
        return rc;
    }

    outCharacteristics->characteristics = out;
    return ::NO_ERROR;
}

int32_t KeyStoreService::importKey(const String16& name, const KeymasterArguments& params,
                                   keymaster_key_format_t format, const uint8_t* keyData,
                                   size_t keyLength, int uid, int flags,
                                   KeyCharacteristics* outCharacteristics) {
    uid = getEffectiveUid(uid);
    int rc = checkBinderPermissionAndKeystoreState(P_INSERT, uid, flags & KEYSTORE_FLAG_ENCRYPTED);
    if (rc != ::NO_ERROR) {
        return rc;
    }

    rc = KM_ERROR_UNIMPLEMENTED;
    bool isFallback = false;
    keymaster_key_blob_t blob;
    keymaster_key_characteristics_t out = {{nullptr, 0}, {nullptr, 0}};

    const auto* device = mKeyStore->getDevice();
    const auto* fallback = mKeyStore->getFallbackDevice();
    std::vector<keymaster_key_param_t> opParams(params.params);
    const keymaster_key_param_set_t inParams = {opParams.data(), opParams.size()};
    const keymaster_blob_t input = {keyData, keyLength};
    if (device == NULL) {
        return ::SYSTEM_ERROR;
    }

    // Capture characteristics before they're potentially stripped
    AuthorizationSet keyCharacteristics(opParams.data(), opParams.size());
    if (keyCharacteristics.is_valid() != AuthorizationSet::Error::OK) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    UniquePtr<uint8_t[]> kc_buf;
    kc_buf.reset(new (std::nothrow) uint8_t[keyCharacteristics.SerializedSize()]);
    if (!kc_buf.get()) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    keyCharacteristics.Serialize(kc_buf.get(), kc_buf.get() + keyCharacteristics.SerializedSize());

    if (device->common.module->module_api_version >= KEYMASTER_MODULE_API_VERSION_1_0 &&
        device->import_key != NULL) {
        rc = device->import_key(device, &inParams, format, &input, &blob,
                                outCharacteristics ? &out : nullptr);
    }
    if (rc && fallback->import_key != NULL) {
        ALOGW("Primary keymaster device failed to import key, falling back to SW.");
        isFallback = true;
        rc = fallback->import_key(fallback, &inParams, format, &input, &blob,
                                  outCharacteristics ? &out : nullptr);
    }
    if (outCharacteristics) {
        outCharacteristics->characteristics = out;
    }

    if (rc) {
        return rc;
    }

    // Write the key:
    String8 name8(name);
    String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, uid, ::TYPE_KEYMASTER_10));

    Blob keyBlob(blob.key_material, blob.key_material_size, NULL, 0, ::TYPE_KEYMASTER_10);
    keyBlob.setFallback(isFallback);
    keyBlob.setEncrypted(flags & KEYSTORE_FLAG_ENCRYPTED);

    free(const_cast<uint8_t*>(blob.key_material));
    rc = mKeyStore->put(filename.string(), &keyBlob, get_user_id(uid));

    if (rc != ::NO_ERROR) {
        return rc;
    }

    // Write the characteristics:
    String8 cFilename(mKeyStore->getKeyNameForUidWithDir(name8, uid, ::TYPE_KEY_CHARACTERISTICS));

    Blob charBlob(kc_buf.get(), keyCharacteristics.SerializedSize(),
        NULL, 0, ::TYPE_KEY_CHARACTERISTICS);
    charBlob.setFallback(isFallback);
    charBlob.setEncrypted(flags & KEYSTORE_FLAG_ENCRYPTED);

    return mKeyStore->put(cFilename.string(), &charBlob, get_user_id(uid));
}

void KeyStoreService::exportKey(const String16& name, keymaster_key_format_t format,
                                const keymaster_blob_t* clientId, const keymaster_blob_t* appData,
                                int32_t uid, ExportResult* result) {

    uid_t targetUid = getEffectiveUid(uid);
    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    if (!is_granted_to(callingUid, targetUid)) {
        ALOGW("uid %d not permitted to act for uid %d in exportKey", callingUid, targetUid);
        result->resultCode = ::PERMISSION_DENIED;
        return;
    }

    Blob keyBlob;
    String8 name8(name);
    int rc;

    ResponseCode responseCode =
        mKeyStore->getKeyForName(&keyBlob, name8, targetUid, TYPE_KEYMASTER_10);
    if (responseCode != ::NO_ERROR) {
        result->resultCode = responseCode;
        return;
    }
    keymaster_key_blob_t key;
    key.key_material_size = keyBlob.getLength();
    key.key_material = keyBlob.getValue();
    auto* dev = mKeyStore->getDeviceForBlob(keyBlob);
    if (!dev->export_key) {
        result->resultCode = KM_ERROR_UNIMPLEMENTED;
        return;
    }
    keymaster_blob_t output = {NULL, 0};
    rc = dev->export_key(dev, format, &key, clientId, appData, &output);
    result->exportData.reset(const_cast<uint8_t*>(output.data));
    result->dataLength = output.data_length;
    result->resultCode = rc ? rc : ::NO_ERROR;
}

void KeyStoreService::begin(const sp<IBinder>& appToken, const String16& name,
                            keymaster_purpose_t purpose, bool pruneable,
                            const KeymasterArguments& params, const uint8_t* entropy,
                            size_t entropyLength, int32_t uid, OperationResult* result) {
    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    uid_t targetUid = getEffectiveUid(uid);
    if (!is_granted_to(callingUid, targetUid)) {
        ALOGW("uid %d not permitted to act for uid %d in begin", callingUid, targetUid);
        result->resultCode = ::PERMISSION_DENIED;
        return;
    }
    if (!pruneable && get_app_id(callingUid) != AID_SYSTEM) {
        ALOGE("Non-system uid %d trying to start non-pruneable operation", callingUid);
        result->resultCode = ::PERMISSION_DENIED;
        return;
    }
    if (!checkAllowedOperationParams(params.params)) {
        result->resultCode = KM_ERROR_INVALID_ARGUMENT;
        return;
    }
    Blob keyBlob;
    String8 name8(name);
    ResponseCode responseCode =
        mKeyStore->getKeyForName(&keyBlob, name8, targetUid, TYPE_KEYMASTER_10);
    if (responseCode != ::NO_ERROR) {
        result->resultCode = responseCode;
        return;
    }
    keymaster_key_blob_t key;
    key.key_material_size = keyBlob.getLength();
    key.key_material = keyBlob.getValue();
    keymaster_operation_handle_t handle;
    auto* dev = mKeyStore->getDeviceForBlob(keyBlob);
    keymaster_error_t err = KM_ERROR_UNIMPLEMENTED;
    std::vector<keymaster_key_param_t> opParams(params.params);
    Unique_keymaster_key_characteristics characteristics;
    characteristics.reset(new keymaster_key_characteristics_t);
    err = getOperationCharacteristics(key, dev, opParams, characteristics.get());
    if (err == KM_ERROR_KEY_REQUIRES_UPGRADE) {
        int32_t rc = upgradeKeyBlob(name, targetUid,
                                    AuthorizationSet(opParams.data(), opParams.size()), &keyBlob);
        if (rc != ::NO_ERROR) {
            result->resultCode = rc;
            return;
        }
        key = {keyBlob.getValue(), static_cast<size_t>(keyBlob.getLength())};
        err = getOperationCharacteristics(key, dev, opParams, characteristics.get());
    }
    if (err) {
        result->resultCode = err;
        return;
    }
    const hw_auth_token_t* authToken = NULL;

    // Merge these characteristics with the ones cached when the key was generated or imported
    Blob charBlob;
    AuthorizationSet persistedCharacteristics;
    responseCode = mKeyStore->getKeyForName(&charBlob, name8, targetUid, TYPE_KEY_CHARACTERISTICS);
    if (responseCode == ::NO_ERROR) {
        const uint8_t* serializedCharacteristics = charBlob.getValue();
        persistedCharacteristics.Deserialize(&serializedCharacteristics,
            serializedCharacteristics + charBlob.getLength());
    } else {
        ALOGD("Unable to read cached characteristics for key");
    }

    // Replace the sw_enforced set with those persisted to disk, minus hw_enforced
    persistedCharacteristics.Union(characteristics.get()->sw_enforced);
    persistedCharacteristics.Difference(characteristics.get()->hw_enforced);
    persistedCharacteristics.CopyToParamSet(&characteristics.get()->sw_enforced);

    int32_t authResult = getAuthToken(characteristics.get(), 0, purpose, &authToken,
                                      /*failOnTokenMissing*/ false);
    // If per-operation auth is needed we need to begin the operation and
    // the client will need to authorize that operation before calling
    // update. Any other auth issues stop here.
    if (authResult != ::NO_ERROR && authResult != ::OP_AUTH_NEEDED) {
        result->resultCode = authResult;
        return;
    }
    addAuthToParams(&opParams, authToken);
    // Add entropy to the device first.
    if (entropy) {
        if (dev->add_rng_entropy) {
            err = dev->add_rng_entropy(dev, entropy, entropyLength);
        } else {
            err = KM_ERROR_UNIMPLEMENTED;
        }
        if (err) {
            result->resultCode = err;
            return;
        }
    }
    keymaster_key_param_set_t inParams = {opParams.data(), opParams.size()};

    // Create a keyid for this key.
    keymaster::km_id_t keyid;
    if (!enforcement_policy.CreateKeyId(key, &keyid)) {
        ALOGE("Failed to create a key ID for authorization checking.");
        result->resultCode = KM_ERROR_UNKNOWN_ERROR;
        return;
    }

    // Check that all key authorization policy requirements are met.
    keymaster::AuthorizationSet key_auths(characteristics->hw_enforced);
    key_auths.push_back(characteristics->sw_enforced);
    keymaster::AuthorizationSet operation_params(inParams);
    err = enforcement_policy.AuthorizeOperation(purpose, keyid, key_auths, operation_params,
                                                0 /* op_handle */, true /* is_begin_operation */);
    if (err) {
        result->resultCode = err;
        return;
    }

    keymaster_key_param_set_t outParams = {NULL, 0};

    // If there are more than MAX_OPERATIONS, abort the oldest operation that was started as
    // pruneable.
    while (mOperationMap.getOperationCount() >= MAX_OPERATIONS) {
        ALOGD("Reached or exceeded concurrent operations limit");
        if (!pruneOperation()) {
            break;
        }
    }

    err = dev->begin(dev, purpose, &key, &inParams, &outParams, &handle);
    if (err != KM_ERROR_OK) {
        ALOGE("Got error %d from begin()", err);
    }

    // If there are too many operations abort the oldest operation that was
    // started as pruneable and try again.
    while (err == KM_ERROR_TOO_MANY_OPERATIONS && mOperationMap.hasPruneableOperation()) {
        ALOGE("Ran out of operation handles");
        if (!pruneOperation()) {
            break;
        }
        err = dev->begin(dev, purpose, &key, &inParams, &outParams, &handle);
    }
    if (err) {
        result->resultCode = err;
        return;
    }

    sp<IBinder> operationToken = mOperationMap.addOperation(handle, keyid, purpose, dev, appToken,
                                                            characteristics.release(), pruneable);
    if (authToken) {
        mOperationMap.setOperationAuthToken(operationToken, authToken);
    }
    // Return the authentication lookup result. If this is a per operation
    // auth'd key then the resultCode will be ::OP_AUTH_NEEDED and the
    // application should get an auth token using the handle before the
    // first call to update, which will fail if keystore hasn't received the
    // auth token.
    result->resultCode = authResult;
    result->token = operationToken;
    result->handle = handle;
    if (outParams.params) {
        result->outParams.params.assign(outParams.params, outParams.params + outParams.length);
        free(outParams.params);
    }
}

void KeyStoreService::update(const sp<IBinder>& token, const KeymasterArguments& params,
                             const uint8_t* data, size_t dataLength, OperationResult* result) {
    if (!checkAllowedOperationParams(params.params)) {
        result->resultCode = KM_ERROR_INVALID_ARGUMENT;
        return;
    }
    const keymaster2_device_t* dev;
    keymaster_operation_handle_t handle;
    keymaster_purpose_t purpose;
    keymaster::km_id_t keyid;
    const keymaster_key_characteristics_t* characteristics;
    if (!mOperationMap.getOperation(token, &handle, &keyid, &purpose, &dev, &characteristics)) {
        result->resultCode = KM_ERROR_INVALID_OPERATION_HANDLE;
        return;
    }
    std::vector<keymaster_key_param_t> opParams(params.params);
    int32_t authResult = addOperationAuthTokenIfNeeded(token, &opParams);
    if (authResult != ::NO_ERROR) {
        result->resultCode = authResult;
        return;
    }
    keymaster_key_param_set_t inParams = {opParams.data(), opParams.size()};
    keymaster_blob_t input = {data, dataLength};
    size_t consumed = 0;
    keymaster_blob_t output = {NULL, 0};
    keymaster_key_param_set_t outParams = {NULL, 0};

    // Check that all key authorization policy requirements are met.
    keymaster::AuthorizationSet key_auths(characteristics->hw_enforced);
    key_auths.push_back(characteristics->sw_enforced);
    keymaster::AuthorizationSet operation_params(inParams);
    result->resultCode = enforcement_policy.AuthorizeOperation(
        purpose, keyid, key_auths, operation_params, handle, false /* is_begin_operation */);
    if (result->resultCode) {
        return;
    }

    keymaster_error_t err =
        dev->update(dev, handle, &inParams, &input, &consumed, &outParams, &output);
    result->data.reset(const_cast<uint8_t*>(output.data));
    result->dataLength = output.data_length;
    result->inputConsumed = consumed;
    result->resultCode = err ? (int32_t)err : ::NO_ERROR;
    if (outParams.params) {
        result->outParams.params.assign(outParams.params, outParams.params + outParams.length);
        free(outParams.params);
    }
}

void KeyStoreService::finish(const sp<IBinder>& token, const KeymasterArguments& params,
                             const uint8_t* signature, size_t signatureLength,
                             const uint8_t* entropy, size_t entropyLength,
                             OperationResult* result) {
    if (!checkAllowedOperationParams(params.params)) {
        result->resultCode = KM_ERROR_INVALID_ARGUMENT;
        return;
    }
    const keymaster2_device_t* dev;
    keymaster_operation_handle_t handle;
    keymaster_purpose_t purpose;
    keymaster::km_id_t keyid;
    const keymaster_key_characteristics_t* characteristics;
    if (!mOperationMap.getOperation(token, &handle, &keyid, &purpose, &dev, &characteristics)) {
        result->resultCode = KM_ERROR_INVALID_OPERATION_HANDLE;
        return;
    }
    std::vector<keymaster_key_param_t> opParams(params.params);
    int32_t authResult = addOperationAuthTokenIfNeeded(token, &opParams);
    if (authResult != ::NO_ERROR) {
        result->resultCode = authResult;
        return;
    }
    keymaster_error_t err;
    if (entropy) {
        if (dev->add_rng_entropy) {
            err = dev->add_rng_entropy(dev, entropy, entropyLength);
        } else {
            err = KM_ERROR_UNIMPLEMENTED;
        }
        if (err) {
            result->resultCode = err;
            return;
        }
    }

    keymaster_key_param_set_t inParams = {opParams.data(), opParams.size()};
    keymaster_blob_t input = {nullptr, 0};
    keymaster_blob_t sig = {signature, signatureLength};
    keymaster_blob_t output = {nullptr, 0};
    keymaster_key_param_set_t outParams = {nullptr, 0};

    // Check that all key authorization policy requirements are met.
    keymaster::AuthorizationSet key_auths(characteristics->hw_enforced);
    key_auths.push_back(characteristics->sw_enforced);
    keymaster::AuthorizationSet operation_params(inParams);
    err = enforcement_policy.AuthorizeOperation(purpose, keyid, key_auths, operation_params, handle,
                                                false /* is_begin_operation */);
    if (err) {
        result->resultCode = err;
        return;
    }

    err =
        dev->finish(dev, handle, &inParams, &input /* TODO(swillden): wire up input to finish() */,
                    &sig, &outParams, &output);
    // Remove the operation regardless of the result
    mOperationMap.removeOperation(token);
    mAuthTokenTable.MarkCompleted(handle);

    result->data.reset(const_cast<uint8_t*>(output.data));
    result->dataLength = output.data_length;
    result->resultCode = err ? (int32_t)err : ::NO_ERROR;
    if (outParams.params) {
        result->outParams.params.assign(outParams.params, outParams.params + outParams.length);
        free(outParams.params);
    }
}

int32_t KeyStoreService::abort(const sp<IBinder>& token) {
    const keymaster2_device_t* dev;
    keymaster_operation_handle_t handle;
    keymaster_purpose_t purpose;
    keymaster::km_id_t keyid;
    if (!mOperationMap.getOperation(token, &handle, &keyid, &purpose, &dev, NULL)) {
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    }
    mOperationMap.removeOperation(token);
    int32_t rc;
    if (!dev->abort) {
        rc = KM_ERROR_UNIMPLEMENTED;
    } else {
        rc = dev->abort(dev, handle);
    }
    mAuthTokenTable.MarkCompleted(handle);
    if (rc) {
        return rc;
    }
    return ::NO_ERROR;
}

bool KeyStoreService::isOperationAuthorized(const sp<IBinder>& token) {
    const keymaster2_device_t* dev;
    keymaster_operation_handle_t handle;
    const keymaster_key_characteristics_t* characteristics;
    keymaster_purpose_t purpose;
    keymaster::km_id_t keyid;
    if (!mOperationMap.getOperation(token, &handle, &keyid, &purpose, &dev, &characteristics)) {
        return false;
    }
    const hw_auth_token_t* authToken = NULL;
    mOperationMap.getOperationAuthToken(token, &authToken);
    std::vector<keymaster_key_param_t> ignored;
    int32_t authResult = addOperationAuthTokenIfNeeded(token, &ignored);
    return authResult == ::NO_ERROR;
}

int32_t KeyStoreService::addAuthToken(const uint8_t* token, size_t length) {
    if (!checkBinderPermission(P_ADD_AUTH)) {
        ALOGW("addAuthToken: permission denied for %d", IPCThreadState::self()->getCallingUid());
        return ::PERMISSION_DENIED;
    }
    if (length != sizeof(hw_auth_token_t)) {
        return KM_ERROR_INVALID_ARGUMENT;
    }
    hw_auth_token_t* authToken = new hw_auth_token_t;
    memcpy(reinterpret_cast<void*>(authToken), token, sizeof(hw_auth_token_t));
    // The table takes ownership of authToken.
    mAuthTokenTable.AddAuthenticationToken(authToken);
    return ::NO_ERROR;
}

int32_t KeyStoreService::attestKey(const String16& name, const KeymasterArguments& params,
                                   KeymasterCertificateChain* outChain) {
    if (!outChain)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    if (!checkAllowedOperationParams(params.params)) {
        return KM_ERROR_INVALID_ARGUMENT;
    }

    uid_t callingUid = IPCThreadState::self()->getCallingUid();

    Blob keyBlob;
    String8 name8(name);
    ResponseCode responseCode =
        mKeyStore->getKeyForName(&keyBlob, name8, callingUid, TYPE_KEYMASTER_10);
    if (responseCode != ::NO_ERROR) {
        return responseCode;
    }

    keymaster_key_blob_t key = {keyBlob.getValue(),
                                static_cast<size_t>(std::max(0, keyBlob.getLength()))};
    auto* dev = mKeyStore->getDeviceForBlob(keyBlob);
    if (!dev->attest_key)
        return KM_ERROR_UNIMPLEMENTED;

    const keymaster_key_param_set_t in_params = {
        const_cast<keymaster_key_param_t*>(params.params.data()), params.params.size()};
    outChain->chain = {nullptr, 0};
    int32_t rc = dev->attest_key(dev, &key, &in_params, &outChain->chain);
    if (rc)
        return rc;
    return ::NO_ERROR;
}

int32_t KeyStoreService::onDeviceOffBody() {
    // TODO(tuckeris): add permission check.  This should be callable from ClockworkHome only.
    mAuthTokenTable.onDeviceOffBody();
    return ::NO_ERROR;
}

/**
 * Prune the oldest pruneable operation.
 */
bool KeyStoreService::pruneOperation() {
    sp<IBinder> oldest = mOperationMap.getOldestPruneableOperation();
    ALOGD("Trying to prune operation %p", oldest.get());
    size_t op_count_before_abort = mOperationMap.getOperationCount();
    // We mostly ignore errors from abort() because all we care about is whether at least
    // one operation has been removed.
    int abort_error = abort(oldest);
    if (mOperationMap.getOperationCount() >= op_count_before_abort) {
        ALOGE("Failed to abort pruneable operation %p, error: %d", oldest.get(), abort_error);
        return false;
    }
    return true;
}

/**
 * Get the effective target uid for a binder operation that takes an
 * optional uid as the target.
 */
uid_t KeyStoreService::getEffectiveUid(int32_t targetUid) {
    if (targetUid == UID_SELF) {
        return IPCThreadState::self()->getCallingUid();
    }
    return static_cast<uid_t>(targetUid);
}

/**
 * Check if the caller of the current binder method has the required
 * permission and if acting on other uids the grants to do so.
 */
bool KeyStoreService::checkBinderPermission(perm_t permission, int32_t targetUid) {
    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    pid_t spid = IPCThreadState::self()->getCallingPid();
    if (!has_permission(callingUid, permission, spid)) {
        ALOGW("permission %s denied for %d", get_perm_label(permission), callingUid);
        return false;
    }
    if (!is_granted_to(callingUid, getEffectiveUid(targetUid))) {
        ALOGW("uid %d not granted to act for %d", callingUid, targetUid);
        return false;
    }
    return true;
}

/**
 * Check if the caller of the current binder method has the required
 * permission and the target uid is the caller or the caller is system.
 */
bool KeyStoreService::checkBinderPermissionSelfOrSystem(perm_t permission, int32_t targetUid) {
    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    pid_t spid = IPCThreadState::self()->getCallingPid();
    if (!has_permission(callingUid, permission, spid)) {
        ALOGW("permission %s denied for %d", get_perm_label(permission), callingUid);
        return false;
    }
    return getEffectiveUid(targetUid) == callingUid || callingUid == AID_SYSTEM;
}

/**
 * Check if the caller of the current binder method has the required
 * permission or the target of the operation is the caller's uid. This is
 * for operation where the permission is only for cross-uid activity and all
 * uids are allowed to act on their own (ie: clearing all entries for a
 * given uid).
 */
bool KeyStoreService::checkBinderPermissionOrSelfTarget(perm_t permission, int32_t targetUid) {
    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    if (getEffectiveUid(targetUid) == callingUid) {
        return true;
    } else {
        return checkBinderPermission(permission, targetUid);
    }
}

/**
 * Helper method to check that the caller has the required permission as
 * well as the keystore is in the unlocked state if checkUnlocked is true.
 *
 * Returns NO_ERROR on success, PERMISSION_DENIED on a permission error and
 * otherwise the state of keystore when not unlocked and checkUnlocked is
 * true.
 */
int32_t KeyStoreService::checkBinderPermissionAndKeystoreState(perm_t permission, int32_t targetUid,
                                                               bool checkUnlocked) {
    if (!checkBinderPermission(permission, targetUid)) {
        return ::PERMISSION_DENIED;
    }
    State state = mKeyStore->getState(get_user_id(getEffectiveUid(targetUid)));
    if (checkUnlocked && !isKeystoreUnlocked(state)) {
        return state;
    }

    return ::NO_ERROR;
}

bool KeyStoreService::isKeystoreUnlocked(State state) {
    switch (state) {
    case ::STATE_NO_ERROR:
        return true;
    case ::STATE_UNINITIALIZED:
    case ::STATE_LOCKED:
        return false;
    }
    return false;
}

bool KeyStoreService::isKeyTypeSupported(const keymaster2_device_t* device,
                                         keymaster_keypair_t keyType) {
    const int32_t device_api = device->common.module->module_api_version;
    if (device_api == KEYMASTER_MODULE_API_VERSION_0_2) {
        switch (keyType) {
        case TYPE_RSA:
        case TYPE_DSA:
        case TYPE_EC:
            return true;
        default:
            return false;
        }
    } else if (device_api >= KEYMASTER_MODULE_API_VERSION_0_3) {
        switch (keyType) {
        case TYPE_RSA:
            return true;
        case TYPE_DSA:
            return device->flags & KEYMASTER_SUPPORTS_DSA;
        case TYPE_EC:
            return device->flags & KEYMASTER_SUPPORTS_EC;
        default:
            return false;
        }
    } else {
        return keyType == TYPE_RSA;
    }
}

/**
 * Check that all keymaster_key_param_t's provided by the application are
 * allowed. Any parameter that keystore adds itself should be disallowed here.
 */
bool KeyStoreService::checkAllowedOperationParams(
    const std::vector<keymaster_key_param_t>& params) {
    for (auto param : params) {
        switch (param.tag) {
        case KM_TAG_AUTH_TOKEN:
            return false;
        default:
            break;
        }
    }
    return true;
}

keymaster_error_t KeyStoreService::getOperationCharacteristics(
    const keymaster_key_blob_t& key, const keymaster2_device_t* dev,
    const std::vector<keymaster_key_param_t>& params, keymaster_key_characteristics_t* out) {
    UniquePtr<keymaster_blob_t> appId;
    UniquePtr<keymaster_blob_t> appData;
    for (auto param : params) {
        if (param.tag == KM_TAG_APPLICATION_ID) {
            appId.reset(new keymaster_blob_t);
            appId->data = param.blob.data;
            appId->data_length = param.blob.data_length;
        } else if (param.tag == KM_TAG_APPLICATION_DATA) {
            appData.reset(new keymaster_blob_t);
            appData->data = param.blob.data;
            appData->data_length = param.blob.data_length;
        }
    }
    keymaster_key_characteristics_t result = {{nullptr, 0}, {nullptr, 0}};
    if (!dev->get_key_characteristics) {
        return KM_ERROR_UNIMPLEMENTED;
    }
    keymaster_error_t error =
        dev->get_key_characteristics(dev, &key, appId.get(), appData.get(), &result);
    if (error == KM_ERROR_OK) {
        *out = result;
    }
    return error;
}

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
int32_t KeyStoreService::getAuthToken(const keymaster_key_characteristics_t* characteristics,
                                      keymaster_operation_handle_t handle,
                                      keymaster_purpose_t purpose,
                                      const hw_auth_token_t** authToken, bool failOnTokenMissing) {

    std::vector<keymaster_key_param_t> allCharacteristics;
    for (size_t i = 0; i < characteristics->sw_enforced.length; i++) {
        allCharacteristics.push_back(characteristics->sw_enforced.params[i]);
    }
    for (size_t i = 0; i < characteristics->hw_enforced.length; i++) {
        allCharacteristics.push_back(characteristics->hw_enforced.params[i]);
    }
    keymaster::AuthTokenTable::Error err = mAuthTokenTable.FindAuthorization(
        allCharacteristics.data(), allCharacteristics.size(), purpose, handle, authToken);
    switch (err) {
    case keymaster::AuthTokenTable::OK:
    case keymaster::AuthTokenTable::AUTH_NOT_REQUIRED:
        return ::NO_ERROR;
    case keymaster::AuthTokenTable::AUTH_TOKEN_NOT_FOUND:
    case keymaster::AuthTokenTable::AUTH_TOKEN_EXPIRED:
    case keymaster::AuthTokenTable::AUTH_TOKEN_WRONG_SID:
        return KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
    case keymaster::AuthTokenTable::OP_HANDLE_REQUIRED:
        return failOnTokenMissing ? (int32_t)KM_ERROR_KEY_USER_NOT_AUTHENTICATED
                                  : (int32_t)::OP_AUTH_NEEDED;
    default:
        ALOGE("Unexpected FindAuthorization return value %d", err);
        return KM_ERROR_INVALID_ARGUMENT;
    }
}

inline void KeyStoreService::addAuthToParams(std::vector<keymaster_key_param_t>* params,
                                             const hw_auth_token_t* token) {
    if (token) {
        params->push_back(keymaster_param_blob(
            KM_TAG_AUTH_TOKEN, reinterpret_cast<const uint8_t*>(token), sizeof(hw_auth_token_t)));
    }
}

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
int32_t KeyStoreService::addOperationAuthTokenIfNeeded(sp<IBinder> token,
                                                       std::vector<keymaster_key_param_t>* params) {
    const hw_auth_token_t* authToken = NULL;
    mOperationMap.getOperationAuthToken(token, &authToken);
    if (!authToken) {
        const keymaster2_device_t* dev;
        keymaster_operation_handle_t handle;
        const keymaster_key_characteristics_t* characteristics = NULL;
        keymaster_purpose_t purpose;
        keymaster::km_id_t keyid;
        if (!mOperationMap.getOperation(token, &handle, &keyid, &purpose, &dev, &characteristics)) {
            return KM_ERROR_INVALID_OPERATION_HANDLE;
        }
        int32_t result = getAuthToken(characteristics, handle, purpose, &authToken);
        if (result != ::NO_ERROR) {
            return result;
        }
        if (authToken) {
            mOperationMap.setOperationAuthToken(token, authToken);
        }
    }
    addAuthToParams(params, authToken);
    return ::NO_ERROR;
}

/**
 * Translate a result value to a legacy return value. All keystore errors are
 * preserved and keymaster errors become SYSTEM_ERRORs
 */
int32_t KeyStoreService::translateResultToLegacyResult(int32_t result) {
    if (result > 0) {
        return result;
    }
    return ::SYSTEM_ERROR;
}

keymaster_key_param_t*
KeyStoreService::getKeyAlgorithm(keymaster_key_characteristics_t* characteristics) {
    for (size_t i = 0; i < characteristics->hw_enforced.length; i++) {
        if (characteristics->hw_enforced.params[i].tag == KM_TAG_ALGORITHM) {
            return &characteristics->hw_enforced.params[i];
        }
    }
    for (size_t i = 0; i < characteristics->sw_enforced.length; i++) {
        if (characteristics->sw_enforced.params[i].tag == KM_TAG_ALGORITHM) {
            return &characteristics->sw_enforced.params[i];
        }
    }
    return NULL;
}

void KeyStoreService::addLegacyBeginParams(const String16& name,
                                           std::vector<keymaster_key_param_t>& params) {
    // All legacy keys are DIGEST_NONE/PAD_NONE.
    params.push_back(keymaster_param_enum(KM_TAG_DIGEST, KM_DIGEST_NONE));
    params.push_back(keymaster_param_enum(KM_TAG_PADDING, KM_PAD_NONE));

    // Look up the algorithm of the key.
    KeyCharacteristics characteristics;
    int32_t rc = getKeyCharacteristics(name, NULL, NULL, UID_SELF, &characteristics);
    if (rc != ::NO_ERROR) {
        ALOGE("Failed to get key characteristics");
        return;
    }
    keymaster_key_param_t* algorithm = getKeyAlgorithm(&characteristics.characteristics);
    if (!algorithm) {
        ALOGE("getKeyCharacteristics did not include KM_TAG_ALGORITHM");
        return;
    }
    params.push_back(*algorithm);
}

int32_t KeyStoreService::doLegacySignVerify(const String16& name, const uint8_t* data,
                                            size_t length, uint8_t** out, size_t* outLength,
                                            const uint8_t* signature, size_t signatureLength,
                                            keymaster_purpose_t purpose) {

    std::basic_stringstream<uint8_t> outBuffer;
    OperationResult result;
    KeymasterArguments inArgs;
    addLegacyBeginParams(name, inArgs.params);
    sp<IBinder> appToken(new BBinder);
    sp<IBinder> token;

    begin(appToken, name, purpose, true, inArgs, NULL, 0, UID_SELF, &result);
    if (result.resultCode != ResponseCode::NO_ERROR) {
        if (result.resultCode == ::KEY_NOT_FOUND) {
            ALOGW("Key not found");
        } else {
            ALOGW("Error in begin: %d", result.resultCode);
        }
        return translateResultToLegacyResult(result.resultCode);
    }
    inArgs.params.clear();
    token = result.token;
    size_t consumed = 0;
    size_t lastConsumed = 0;
    do {
        update(token, inArgs, data + consumed, length - consumed, &result);
        if (result.resultCode != ResponseCode::NO_ERROR) {
            ALOGW("Error in update: %d", result.resultCode);
            return translateResultToLegacyResult(result.resultCode);
        }
        if (out) {
            outBuffer.write(result.data.get(), result.dataLength);
        }
        lastConsumed = result.inputConsumed;
        consumed += lastConsumed;
    } while (consumed < length && lastConsumed > 0);

    if (consumed != length) {
        ALOGW("Not all data consumed. Consumed %zu of %zu", consumed, length);
        return ::SYSTEM_ERROR;
    }

    finish(token, inArgs, signature, signatureLength, NULL, 0, &result);
    if (result.resultCode != ResponseCode::NO_ERROR) {
        ALOGW("Error in finish: %d", result.resultCode);
        return translateResultToLegacyResult(result.resultCode);
    }
    if (out) {
        outBuffer.write(result.data.get(), result.dataLength);
    }

    if (out) {
        auto buf = outBuffer.str();
        *out = new uint8_t[buf.size()];
        memcpy(*out, buf.c_str(), buf.size());
        *outLength = buf.size();
    }

    return ::NO_ERROR;
}

int32_t KeyStoreService::upgradeKeyBlob(const String16& name, uid_t uid,
                                        const AuthorizationSet& params, Blob* blob) {
    // Read the blob rather than assuming the caller provided the right name/uid/blob triplet.
    String8 name8(name);
    ResponseCode responseCode = mKeyStore->getKeyForName(blob, name8, uid, TYPE_KEYMASTER_10);
    if (responseCode != ::NO_ERROR) {
        return responseCode;
    }

    keymaster_key_blob_t key = {blob->getValue(), static_cast<size_t>(blob->getLength())};
    auto* dev = mKeyStore->getDeviceForBlob(*blob);
    keymaster_key_blob_t upgraded_key;
    int32_t rc = dev->upgrade_key(dev, &key, &params, &upgraded_key);
    if (rc != KM_ERROR_OK) {
        return rc;
    }
    UniquePtr<uint8_t, Malloc_Delete> upgraded_key_deleter(
        const_cast<uint8_t*>(upgraded_key.key_material));

    String8 filename = mKeyStore->getBlobFileNameIfExists(name8, uid, ::TYPE_KEYMASTER_10);
    if (filename.isEmpty()) {
        ALOGI("trying to upgrade a non existing blob");
        return KEY_NOT_FOUND;
    }
    rc = mKeyStore->del(filename.string(), ::TYPE_ANY, get_user_id(uid));
    if (rc != ::NO_ERROR) {
        ALOGI("upgradeKeyBlob keystore->del failed %d", rc);
        return rc;
    }

    Blob newBlob(upgraded_key.key_material, upgraded_key.key_material_size, nullptr /* info */,
                 0 /* infoLength */, ::TYPE_KEYMASTER_10);
    newBlob.setFallback(blob->isFallback());
    newBlob.setEncrypted(blob->isEncrypted());

    rc = mKeyStore->put(filename.string(), &newBlob, get_user_id(uid));

    // Re-read blob for caller.  We can't use newBlob because writing it modified it.
    responseCode = mKeyStore->getKeyForName(blob, name8, uid, TYPE_KEYMASTER_10);
    if (responseCode != ::NO_ERROR) {
        return responseCode;
    }

    return rc;
}

}  // namespace android
