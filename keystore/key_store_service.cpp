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
#include "include/keystore/KeystoreArg.h"

#include <fcntl.h>
#include <sys/stat.h>

#include <algorithm>
#include <atomic>
#include <sstream>

#include <android-base/scopeguard.h>
#include <binder/IInterface.h>
#include <binder/IPCThreadState.h>
#include <binder/IPermissionController.h>
#include <binder/IServiceManager.h>
#include <cutils/multiuser.h>
#include <log/log_event_list.h>

#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#include <android/hardware/confirmationui/1.0/IConfirmationUI.h>
#include <android/hardware/keymaster/3.0/IHwKeymasterDevice.h>

#include "defaults.h"
#include "key_proto_handler.h"
#include "keystore_attestation_id.h"
#include "keystore_keymaster_enforcement.h"
#include "keystore_utils.h"
#include <keystore/keystore_hidl_support.h>
#include <keystore/keystore_return_types.h>

#include <hardware/hw_auth_token.h>

namespace keystore {

using namespace android;

namespace {

using ::android::binder::Status;
using android::security::KeystoreArg;
using android::security::keymaster::ExportResult;
using android::security::keymaster::KeymasterArguments;
using android::security::keymaster::KeymasterBlob;
using android::security::keymaster::KeymasterCertificateChain;
using android::security::keymaster::operationFailed;
using android::security::keymaster::OperationResult;
using ConfirmationResponseCode = android::hardware::confirmationui::V1_0::ResponseCode;

constexpr double kIdRotationPeriod = 30 * 24 * 60 * 60; /* Thirty days, in seconds */
const char* kTimestampFilePath = "timestamp";
const int ID_ATTESTATION_REQUEST_GENERIC_INFO = 1 << 0;
const int ID_ATTESTATION_REQUEST_UNIQUE_DEVICE_ID = 1 << 1;

struct BIGNUM_Delete {
    void operator()(BIGNUM* p) const { BN_free(p); }
};
typedef std::unique_ptr<BIGNUM, BIGNUM_Delete> Unique_BIGNUM;

bool containsTag(const hidl_vec<KeyParameter>& params, Tag tag) {
    return params.end() !=
           std::find_if(params.begin(), params.end(),
                        [&](const KeyParameter& param) { return param.tag == tag; });
}

std::pair<KeyStoreServiceReturnCode, bool> hadFactoryResetSinceIdRotation() {
    struct stat sbuf;
    if (stat(kTimestampFilePath, &sbuf) == 0) {
        double diff_secs = difftime(time(nullptr), sbuf.st_ctime);
        return {ResponseCode::NO_ERROR, diff_secs < kIdRotationPeriod};
    }

    if (errno != ENOENT) {
        ALOGE("Failed to stat \"timestamp\" file, with error %d", errno);
        return {ResponseCode::SYSTEM_ERROR, false /* don't care */};
    }

    int fd = creat(kTimestampFilePath, 0600);
    if (fd < 0) {
        ALOGE("Couldn't create \"timestamp\" file, with error %d", errno);
        return {ResponseCode::SYSTEM_ERROR, false /* don't care */};
    }

    if (close(fd)) {
        ALOGE("Couldn't close \"timestamp\" file, with error %d", errno);
        return {ResponseCode::SYSTEM_ERROR, false /* don't care */};
    }

    return {ResponseCode::NO_ERROR, true};
}

using ::android::security::KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE;

KeyStoreServiceReturnCode updateParamsForAttestation(uid_t callingUid, AuthorizationSet* params) {
    KeyStoreServiceReturnCode responseCode;
    bool factoryResetSinceIdRotation;
    std::tie(responseCode, factoryResetSinceIdRotation) = hadFactoryResetSinceIdRotation();

    if (!responseCode.isOk()) return responseCode;
    if (factoryResetSinceIdRotation) params->push_back(TAG_RESET_SINCE_ID_ROTATION);

    auto asn1_attestation_id_result = security::gather_attestation_application_id(callingUid);
    if (!asn1_attestation_id_result.isOk()) {
        ALOGE("failed to gather attestation_id");
        return ErrorCode::ATTESTATION_APPLICATION_ID_MISSING;
    }
    std::vector<uint8_t>& asn1_attestation_id = asn1_attestation_id_result;

    /*
     * The attestation application ID must not be longer than
     * KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE, error out if gather_attestation_application_id
     * returned such an invalid vector.
     */
    if (asn1_attestation_id.size() > KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE) {
        ALOGE("BUG: Gathered Attestation Application ID is too big (%d)",
              static_cast<int32_t>(asn1_attestation_id.size()));
        return ErrorCode::CANNOT_ATTEST_IDS;
    }

    params->push_back(TAG_ATTESTATION_APPLICATION_ID, asn1_attestation_id);

    return ResponseCode::NO_ERROR;
}

}  // anonymous namespace

Status KeyStoreService::getState(int32_t userId, int32_t* aidl_return) {
    if (!checkBinderPermission(P_GET_STATE)) {
        *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
        return Status::ok();
    }
    *aidl_return = mKeyStore->getState(userId);
    return Status::ok();
}

Status KeyStoreService::get(const String16& name, int32_t uid, ::std::vector<uint8_t>* item) {
    uid_t targetUid = getEffectiveUid(uid);
    if (!checkBinderPermission(P_GET, targetUid)) {
        // see keystore/keystore.h
        return Status::fromServiceSpecificError(
            static_cast<int32_t>(ResponseCode::PERMISSION_DENIED));
    }

    String8 name8(name);
    ResponseCode rc;
    Blob keyBlob;
    Blob charBlob;
    LockedKeyBlobEntry lockedEntry;

    std::tie(rc, keyBlob, charBlob, lockedEntry) =
        mKeyStore->getKeyForName(name8, targetUid, TYPE_GENERIC);
    if (rc != ResponseCode::NO_ERROR) {
        *item = ::std::vector<uint8_t>();
        // Return empty array if key is not found
        // TODO: consider having returned value nullable or parse exception on the client.
        return Status::fromServiceSpecificError(static_cast<int32_t>(rc));
    }
    auto resultBlob = blob2hidlVec(keyBlob);
    // The static_cast here is needed to prevent a move, forcing a deep copy.
    if (item) *item = static_cast<const hidl_vec<uint8_t>&>(blob2hidlVec(keyBlob));
    return Status::ok();
}

Status KeyStoreService::insert(const String16& name, const ::std::vector<uint8_t>& item,
                               int targetUid, int32_t flags, int32_t* aidl_return) {
    targetUid = getEffectiveUid(targetUid);
    KeyStoreServiceReturnCode result =
        checkBinderPermissionAndKeystoreState(P_INSERT, targetUid, flags & KEYSTORE_FLAG_ENCRYPTED);
    if (!result.isOk()) {
        *aidl_return = static_cast<int32_t>(result);
        return Status::ok();
    }

    String8 name8(name);
    auto lockedEntry = mKeyStore->getLockedBlobEntryIfNotExists(name8.string(), targetUid);

    if (!lockedEntry) {
        ALOGE("failed to grab lock on blob entry %u_%s", targetUid, name8.string());
        *aidl_return = static_cast<int32_t>(ResponseCode::KEY_ALREADY_EXISTS);
        return Status::ok();
    }

    Blob keyBlob(&item[0], item.size(), nullptr, 0, ::TYPE_GENERIC);
    keyBlob.setEncrypted(flags & KEYSTORE_FLAG_ENCRYPTED);

    *aidl_return = static_cast<int32_t>(mKeyStore->put(lockedEntry, keyBlob, {}));
    return Status::ok();
}

Status KeyStoreService::del(const String16& name, int targetUid, int32_t* aidl_return) {
    targetUid = getEffectiveUid(targetUid);
    if (!checkBinderPermission(P_DELETE, targetUid)) {
        *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
        return Status::ok();
    }
    String8 name8(name);
    ALOGI("del %s %d", name8.string(), targetUid);
    auto lockedEntry = mKeyStore->getLockedBlobEntryIfExists(name8.string(), targetUid);
    if (!lockedEntry) {
        *aidl_return = static_cast<int32_t>(ResponseCode::KEY_NOT_FOUND);
        return Status::ok();
    }

    ResponseCode result = mKeyStore->del(lockedEntry);

    *aidl_return = static_cast<int32_t>(result);
    return Status::ok();
}

Status KeyStoreService::exist(const String16& name, int targetUid, int32_t* aidl_return) {
    targetUid = getEffectiveUid(targetUid);
    if (!checkBinderPermission(P_EXIST, targetUid)) {
        *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
        return Status::ok();
    }

    LockedKeyBlobEntry lockedEntry =
        mKeyStore->getLockedBlobEntryIfExists(String8(name).string(), targetUid);
    *aidl_return =
        static_cast<int32_t>(lockedEntry ? ResponseCode::NO_ERROR : ResponseCode::KEY_NOT_FOUND);
    return Status::ok();
}

Status KeyStoreService::list(const String16& prefix, int32_t targetUid,
                             ::std::vector<::android::String16>* matches) {
    targetUid = getEffectiveUid(targetUid);
    if (!checkBinderPermission(P_LIST, targetUid)) {
        return Status::fromServiceSpecificError(
            static_cast<int32_t>(ResponseCode::PERMISSION_DENIED));
    }
    const String8 prefix8(prefix);
    const std::string stdPrefix(prefix8.string());

    ResponseCode rc;
    std::list<LockedKeyBlobEntry> internal_matches;

    std::tie(rc, internal_matches) = LockedKeyBlobEntry::list(
        mKeyStore->getUserStateDB().getUserStateByUid(targetUid)->getUserDirName(),
        [&](uid_t uid, const std::string& alias) {
            std::mismatch(stdPrefix.begin(), stdPrefix.end(), alias.begin(), alias.end());
            return uid == static_cast<uid_t>(targetUid) &&
                   std::mismatch(stdPrefix.begin(), stdPrefix.end(), alias.begin(), alias.end())
                           .first == stdPrefix.end();
        });

    if (rc != ResponseCode::NO_ERROR) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(rc));
    }

    for (LockedKeyBlobEntry& entry : internal_matches) {
        matches->push_back(String16(entry->alias().substr(prefix8.size()).c_str()));
    }
    return Status::ok();
}

Status KeyStoreService::reset(int32_t* aidl_return) {
    if (!checkBinderPermission(P_RESET)) {
        *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
        return Status::ok();
    }

    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    mKeyStore->resetUser(get_user_id(callingUid), false);
    *aidl_return = static_cast<int32_t>(ResponseCode::NO_ERROR);
    return Status::ok();
}

Status KeyStoreService::onUserPasswordChanged(int32_t userId, const String16& password,
                                              int32_t* aidl_return) {
    if (!checkBinderPermission(P_PASSWORD)) {
        *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
        return Status::ok();
    }

    const String8 password8(password);
    // Flush the auth token table to prevent stale tokens from sticking
    // around.
    mKeyStore->getAuthTokenTable().Clear();

    if (password.size() == 0) {
        ALOGI("Secure lockscreen for user %d removed, deleting encrypted entries", userId);
        mKeyStore->resetUser(userId, true);
        *aidl_return = static_cast<int32_t>(ResponseCode::NO_ERROR);
        return Status::ok();
    } else {
        switch (mKeyStore->getState(userId)) {
        case ::STATE_UNINITIALIZED: {
            // generate master key, encrypt with password, write to file,
            // initialize mMasterKey*.
            *aidl_return = static_cast<int32_t>(mKeyStore->initializeUser(password8, userId));
            return Status::ok();
        }
        case ::STATE_NO_ERROR: {
            // rewrite master key with new password.
            *aidl_return = static_cast<int32_t>(mKeyStore->writeMasterKey(password8, userId));
            return Status::ok();
        }
        case ::STATE_LOCKED: {
            ALOGE("Changing user %d's password while locked, clearing old encryption", userId);
            mKeyStore->resetUser(userId, true);
            *aidl_return = static_cast<int32_t>(mKeyStore->initializeUser(password8, userId));
            return Status::ok();
        }
        }
        *aidl_return = static_cast<int32_t>(ResponseCode::SYSTEM_ERROR);
        return Status::ok();
    }
}

Status KeyStoreService::onUserAdded(int32_t userId, int32_t parentId, int32_t* aidl_return) {
    if (!checkBinderPermission(P_USER_CHANGED)) {
        *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
        return Status::ok();
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
        *aidl_return = static_cast<int32_t>(mKeyStore->copyMasterKey(parentId, userId));
        return Status::ok();
    } else {
        *aidl_return = static_cast<int32_t>(ResponseCode::NO_ERROR);
        return Status::ok();
    }
}

Status KeyStoreService::onUserRemoved(int32_t userId, int32_t* aidl_return) {
    if (!checkBinderPermission(P_USER_CHANGED)) {
        *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
        return Status::ok();
    }

    mKeyStore->resetUser(userId, false);
    *aidl_return = static_cast<int32_t>(ResponseCode::NO_ERROR);
    return Status::ok();
}

Status KeyStoreService::lock(int32_t userId, int32_t* aidl_return) {
    if (!checkBinderPermission(P_LOCK)) {
        *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
        return Status::ok();
    }

    State state = mKeyStore->getState(userId);
    if (state != ::STATE_NO_ERROR) {
        ALOGD("calling lock in state: %d", state);
        *aidl_return = static_cast<int32_t>(ResponseCode(state));
        return Status::ok();
    }

    mKeyStore->getEnforcementPolicy().set_device_locked(true, userId);
    mKeyStore->lock(userId);
    *aidl_return = static_cast<int32_t>(ResponseCode::NO_ERROR);
    return Status::ok();
}

Status KeyStoreService::unlock(int32_t userId, const String16& pw, int32_t* aidl_return) {
    if (!checkBinderPermission(P_UNLOCK)) {
        *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
        return Status::ok();
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
        *aidl_return = static_cast<int32_t>(ResponseCode(state));
        return Status::ok();
    }

    mKeyStore->getEnforcementPolicy().set_device_locked(false, userId);
    const String8 password8(pw);
    // read master key, decrypt with password, initialize mMasterKey*.
    *aidl_return = static_cast<int32_t>(mKeyStore->readMasterKey(password8, userId));
    return Status::ok();
}

Status KeyStoreService::isEmpty(int32_t userId, int32_t* aidl_return) {
    if (!checkBinderPermission(P_IS_EMPTY)) {
        *aidl_return = static_cast<int32_t>(false);
        return Status::ok();
    }

    *aidl_return = static_cast<int32_t>(mKeyStore->isEmpty(userId));
    return Status::ok();
}

Status KeyStoreService::grant(const String16& name, int32_t granteeUid,
                              ::android::String16* aidl_return) {
    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    auto result =
        checkBinderPermissionAndKeystoreState(P_GRANT, /*targetUid=*/-1, /*checkUnlocked=*/false);
    if (!result.isOk()) {
        *aidl_return = String16();
        return Status::ok();
    }

    String8 name8(name);
    auto lockedEntry = mKeyStore->getLockedBlobEntryIfExists(name8.string(), callingUid);
    if (!lockedEntry) {
        *aidl_return = String16();
        return Status::ok();
    }

    *aidl_return = String16(mKeyStore->addGrant(lockedEntry, granteeUid).c_str());
    return Status::ok();
}

Status KeyStoreService::ungrant(const String16& name, int32_t granteeUid, int32_t* aidl_return) {
    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    KeyStoreServiceReturnCode result =
        checkBinderPermissionAndKeystoreState(P_GRANT, /*targetUid=*/-1, /*checkUnlocked=*/false);
    if (!result.isOk()) {
        *aidl_return = static_cast<int32_t>(result);
        return Status::ok();
    }

    String8 name8(name);

    auto lockedEntry = mKeyStore->getLockedBlobEntryIfExists(name8.string(), callingUid);
    if (!lockedEntry) {
        *aidl_return = static_cast<int32_t>(ResponseCode::KEY_NOT_FOUND);
    }

    *aidl_return = mKeyStore->removeGrant(lockedEntry, granteeUid);
    return Status::ok();
}

Status KeyStoreService::getmtime(const String16& name, int32_t uid, int64_t* time) {
    uid_t targetUid = getEffectiveUid(uid);
    if (!checkBinderPermission(P_GET, targetUid)) {
        ALOGW("permission denied for %d: getmtime", targetUid);
        *time = -1L;
        return Status::ok();
    }
    String8 name8(name);

    auto lockedEntry = mKeyStore->getLockedBlobEntryIfExists(name8.string(), targetUid);
    if (!lockedEntry) {
        ALOGW("could not access key with alias %s for getmtime", name8.string());
        *time = -1L;
        return Status::ok();
    }

    std::string filename = lockedEntry->getKeyBlobPath();

    int fd = TEMP_FAILURE_RETRY(open(filename.c_str(), O_NOFOLLOW, O_RDONLY));
    if (fd < 0) {
        ALOGW("could not open %s for getmtime", filename.c_str());
        *time = -1L;
        return Status::ok();
    }

    struct stat s;
    int ret = fstat(fd, &s);
    close(fd);
    if (ret == -1) {
        ALOGW("could not stat %s for getmtime", filename.c_str());
        *time = -1L;
        return Status::ok();
    }

    *time = static_cast<int64_t>(s.st_mtime);
    return Status::ok();
}

Status KeyStoreService::is_hardware_backed(const String16& keyType, int32_t* aidl_return) {
    *aidl_return = static_cast<int32_t>(mKeyStore->isHardwareBacked(keyType) ? 1 : 0);
    return Status::ok();
}

Status KeyStoreService::clear_uid(int64_t targetUid64, int32_t* aidl_return) {
    uid_t targetUid = getEffectiveUid(targetUid64);
    if (!checkBinderPermissionSelfOrSystem(P_CLEAR_UID, targetUid)) {
        *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
        return Status::ok();
    }
    ALOGI("clear_uid %" PRId64, targetUid64);

    mKeyStore->removeAllGrantsToUid(targetUid);

    ResponseCode rc;
    std::list<LockedKeyBlobEntry> entries;

    // list has a fence making sure no workers are modifying blob files before iterating the
    // data base. All returned entries are locked.
    std::tie(rc, entries) = LockedKeyBlobEntry::list(
        mKeyStore->getUserStateDB().getUserStateByUid(targetUid)->getUserDirName(),
        [&](uid_t uid, const std::string&) -> bool { return uid == targetUid; });

    if (rc != ResponseCode::NO_ERROR) {
        *aidl_return = static_cast<int32_t>(rc);
        return Status::ok();
    }

    for (LockedKeyBlobEntry& lockedEntry : entries) {
        if (get_app_id(targetUid) == AID_SYSTEM) {
            Blob keyBlob;
            Blob charBlob;
            std::tie(rc, keyBlob, charBlob) = mKeyStore->get(lockedEntry);
            if (rc == ResponseCode::NO_ERROR && keyBlob.isCriticalToDeviceEncryption()) {
                // Do not clear keys critical to device encryption under system uid.
                continue;
            }
        }
        mKeyStore->del(lockedEntry);
    }
    *aidl_return = static_cast<int32_t>(ResponseCode::NO_ERROR);
    return Status::ok();
}

Status KeyStoreService::addRngEntropy(const ::std::vector<uint8_t>& entropy, int32_t flags,
                                      int32_t* aidl_return) {
    auto device = mKeyStore->getDevice(flagsToSecurityLevel(flags));
    if (!device) {
        *aidl_return = static_cast<int32_t>(ErrorCode::HARDWARE_TYPE_UNAVAILABLE);
        return Status::ok();
    }
    std::promise<KeyStoreServiceReturnCode> resultPromise;
    auto resultFuture = resultPromise.get_future();

    device->addRngEntropy(
        entropy, [&](Return<ErrorCode> rc) { resultPromise.set_value(KS_HANDLE_HIDL_ERROR(rc)); });
    resultFuture.wait();
    *aidl_return = int32_t(resultFuture.get());
    return Status::ok();
}

Status
KeyStoreService::generateKey(const String16& name, const KeymasterArguments& params,
                             const ::std::vector<uint8_t>& entropy, int uid, int flags,
                             android::security::keymaster::KeyCharacteristics* outCharacteristics,
                             int32_t* aidl_return) {
    // TODO(jbires): remove this getCallingUid call upon implementation of b/25646100
    uid_t originalUid = IPCThreadState::self()->getCallingUid();
    uid = getEffectiveUid(uid);
    auto logOnScopeExit = android::base::make_scope_guard([&] {
        if (__android_log_security()) {
            android_log_event_list(SEC_TAG_AUTH_KEY_GENERATED)
                << int32_t(*aidl_return == static_cast<int32_t>(ResponseCode::NO_ERROR))
                << String8(name) << int32_t(uid) << LOG_ID_SECURITY;
        }
    });
    KeyStoreServiceReturnCode rc =
        checkBinderPermissionAndKeystoreState(P_INSERT, uid, flags & KEYSTORE_FLAG_ENCRYPTED);
    if (!rc.isOk()) {
        *aidl_return = static_cast<int32_t>(rc);
        return Status::ok();
    }
    if ((flags & KEYSTORE_FLAG_CRITICAL_TO_DEVICE_ENCRYPTION) && get_app_id(uid) != AID_SYSTEM) {
        ALOGE("Non-system uid %d cannot set FLAG_CRITICAL_TO_DEVICE_ENCRYPTION", uid);
        *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
        return Status::ok();
    }

    if (containsTag(params.getParameters(), Tag::INCLUDE_UNIQUE_ID)) {
        // TODO(jbires): remove uid checking upon implementation of b/25646100
        if (!checkBinderPermission(P_GEN_UNIQUE_ID) ||
            originalUid != IPCThreadState::self()->getCallingUid()) {
            *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
            return Status::ok();
        }
    }

    SecurityLevel securityLevel = flagsToSecurityLevel(flags);
    auto dev = mKeyStore->getDevice(securityLevel);
    if (!dev) {
        *aidl_return = static_cast<int32_t>(ErrorCode::HARDWARE_TYPE_UNAVAILABLE);
        return Status::ok();
    }

    String8 name8(name);
    auto lockedEntry = mKeyStore->getLockedBlobEntryIfNotExists(name8.string(), uid);
    if (!lockedEntry) {
        *aidl_return = static_cast<int32_t>(ResponseCode::KEY_ALREADY_EXISTS);
        return Status::ok();
    }

    logOnScopeExit.Disable();

    std::promise<KeyStoreServiceReturnCode> resultPromise;
    auto resultFuture = resultPromise.get_future();

    dev->generateKey(std::move(lockedEntry), params.getParameters(), entropy, flags,
                     [&, uid](KeyStoreServiceReturnCode rc, KeyCharacteristics keyCharacteristics) {
                         if (outCharacteristics && rc.isOk()) {
                             *outCharacteristics = android::security::keymaster::KeyCharacteristics(
                                 keyCharacteristics);
                         }
                         if (__android_log_security()) {
                             android_log_event_list(SEC_TAG_AUTH_KEY_GENERATED)
                                 << rc.isOk() << String8(name) << int32_t(uid) << LOG_ID_SECURITY;
                         }
                         resultPromise.set_value(rc);
                     });

    resultFuture.wait();
    *aidl_return = int32_t(resultFuture.get());
    return Status::ok();
}

Status KeyStoreService::getKeyCharacteristics(
    const String16& name, const ::android::security::keymaster::KeymasterBlob& clientId,
    const ::android::security::keymaster::KeymasterBlob& appData, int32_t uid,
    ::android::security::keymaster::KeyCharacteristics* outCharacteristics, int32_t* aidl_return) {
    if (!outCharacteristics) {
        *aidl_return =
            static_cast<int32_t>(KeyStoreServiceReturnCode(ErrorCode::UNEXPECTED_NULL_POINTER));
        return Status::ok();
    }

    uid_t targetUid = getEffectiveUid(uid);
    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    if (!is_granted_to(callingUid, targetUid)) {
        ALOGW("uid %d not permitted to act for uid %d in getKeyCharacteristics", callingUid,
              targetUid);
        *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
        return Status::ok();
    }

    String8 name8(name);

    ResponseCode rc;
    Blob keyBlob;
    Blob charBlob;
    LockedKeyBlobEntry lockedEntry;

    std::tie(rc, keyBlob, charBlob, lockedEntry) =
        mKeyStore->getKeyForName(name8, targetUid, TYPE_KEYMASTER_10);

    if (rc != ResponseCode::NO_ERROR) {
        *aidl_return = static_cast<int32_t>(rc);
        return Status::ok();
    }

    auto dev = mKeyStore->getDevice(keyBlob);
    if (!dev) {
        *aidl_return = static_cast<int32_t>(ResponseCode::SYSTEM_ERROR);
        return Status::ok();
    }

    // If the charBlob is up to date, it simply moves the argument blobs to the returned blobs
    // and extracts the characteristics on the way. Otherwise it updates the cache file with data
    // from keymaster. It may also upgrade the key blob.
    std::promise<KeyStoreServiceReturnCode> resultPromise;
    auto resultFuture = resultPromise.get_future();

    dev->getKeyCharacteristics(
        std::move(lockedEntry), clientId.getData(), appData.getData(), std::move(keyBlob),
        std::move(charBlob),
        [&](KeyStoreServiceReturnCode rc, KeyCharacteristics keyCharacteristics) {
            if (outCharacteristics && rc.isOk()) {
                *outCharacteristics = std::move(keyCharacteristics);
            }
            resultPromise.set_value(rc);
        });

    resultFuture.wait();
    *aidl_return = int32_t(resultFuture.get());
    return Status::ok();
}

Status
KeyStoreService::importKey(const String16& name, const KeymasterArguments& params, int32_t format,
                           const ::std::vector<uint8_t>& keyData, int uid, int flags,
                           ::android::security::keymaster::KeyCharacteristics* outCharacteristics,
                           int32_t* aidl_return) {
    uid = getEffectiveUid(uid);
    auto logOnScopeExit = android::base::make_scope_guard([&] {
        if (__android_log_security()) {
            android_log_event_list(SEC_TAG_KEY_IMPORTED)
                << int32_t(*aidl_return == static_cast<int32_t>(ResponseCode::NO_ERROR))
                << String8(name) << int32_t(uid) << LOG_ID_SECURITY;
        }
    });
    KeyStoreServiceReturnCode rc =
        checkBinderPermissionAndKeystoreState(P_INSERT, uid, flags & KEYSTORE_FLAG_ENCRYPTED);
    if (!rc.isOk()) {
        LOG(ERROR) << "permissission denied";
        *aidl_return = static_cast<int32_t>(rc);
        return Status::ok();
    }
    if ((flags & KEYSTORE_FLAG_CRITICAL_TO_DEVICE_ENCRYPTION) && get_app_id(uid) != AID_SYSTEM) {
        ALOGE("Non-system uid %d cannot set FLAG_CRITICAL_TO_DEVICE_ENCRYPTION", uid);
        *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
        return Status::ok();
    }

    SecurityLevel securityLevel = flagsToSecurityLevel(flags);
    auto dev = mKeyStore->getDevice(securityLevel);
    if (!dev) {
        LOG(ERROR) << "importKey - cound not get keymaster device";
        *aidl_return = static_cast<int32_t>(ErrorCode::HARDWARE_TYPE_UNAVAILABLE);
        return Status::ok();
    }

    String8 name8(name);
    auto lockedEntry = mKeyStore->getLockedBlobEntryIfNotExists(name8.string(), uid);
    if (!lockedEntry) {
        LOG(ERROR) << "importKey - key: " << name8.string() << " " << int(uid)
                   << " already exists.";
        *aidl_return = static_cast<int32_t>(ResponseCode::KEY_ALREADY_EXISTS);
        return Status::ok();
    }

    logOnScopeExit.Disable();

    std::promise<KeyStoreServiceReturnCode> resultPromise;
    auto resultFuture = resultPromise.get_future();

    dev->importKey(std::move(lockedEntry), params.getParameters(), KeyFormat(format), keyData,
                   flags,
                   [&, uid](KeyStoreServiceReturnCode rc, KeyCharacteristics keyCharacteristics) {
                       if (outCharacteristics && rc.isOk()) {
                           *outCharacteristics = std::move(keyCharacteristics);
                       }
                       if (__android_log_security()) {
                           android_log_event_list(SEC_TAG_KEY_IMPORTED)
                               << rc.isOk() << String8(name) << int32_t(uid) << LOG_ID_SECURITY;
                       }
                       resultPromise.set_value(rc);
                   });

    resultFuture.wait();
    *aidl_return = int32_t(resultFuture.get());
    return Status::ok();
}

Status KeyStoreService::exportKey(const String16& name, int32_t format,
                                  const ::android::security::keymaster::KeymasterBlob& clientId,
                                  const ::android::security::keymaster::KeymasterBlob& appData,
                                  int32_t uid, ExportResult* result) {

    uid_t targetUid = getEffectiveUid(uid);
    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    if (!is_granted_to(callingUid, targetUid)) {
        ALOGW("uid %d not permitted to act for uid %d in exportKey", callingUid, targetUid);
        result->resultCode = ResponseCode::PERMISSION_DENIED;
        return Status::ok();
    }

    String8 name8(name);

    KeyStoreServiceReturnCode rc;
    Blob keyBlob;
    Blob charBlob;
    LockedKeyBlobEntry lockedEntry;

    std::tie(rc, keyBlob, charBlob, lockedEntry) =
        mKeyStore->getKeyForName(name8, targetUid, TYPE_KEYMASTER_10);
    if (!rc) {
        result->resultCode = rc;
        return Status::ok();
    }

    auto dev = mKeyStore->getDevice(keyBlob);
    std::promise<void> resultPromise;
    auto resultFuture = resultPromise.get_future();

    dev->exportKey(std::move(lockedEntry), KeyFormat(format), clientId.getData(), appData.getData(),
                   std::move(keyBlob), std::move(charBlob), [&](ExportResult exportResult) {
                       *result = std::move(exportResult);
                       resultPromise.set_value();
                   });

    resultFuture.wait();
    return Status::ok();
}

Status KeyStoreService::begin(const sp<IBinder>& appToken, const String16& name, int32_t purpose,
                              bool pruneable, const KeymasterArguments& params,
                              const ::std::vector<uint8_t>& entropy, int32_t uid,
                              OperationResult* result) {
    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    uid_t targetUid = getEffectiveUid(uid);
    if (!is_granted_to(callingUid, targetUid)) {
        ALOGW("uid %d not permitted to act for uid %d in begin", callingUid, targetUid);
        result->resultCode = ResponseCode::PERMISSION_DENIED;
        return Status::ok();
    }
    if (!pruneable && get_app_id(callingUid) != AID_SYSTEM) {
        ALOGE("Non-system uid %d trying to start non-pruneable operation", callingUid);
        result->resultCode = ResponseCode::PERMISSION_DENIED;
        return Status::ok();
    }
    if (!checkAllowedOperationParams(params.getParameters())) {
        result->resultCode = ErrorCode::INVALID_ARGUMENT;
        return Status::ok();
    }

    String8 name8(name);
    Blob keyBlob;
    Blob charBlob;
    LockedKeyBlobEntry lockedEntry;
    ResponseCode rc;

    std::tie(rc, keyBlob, charBlob, lockedEntry) =
        mKeyStore->getKeyForName(name8, targetUid, TYPE_KEYMASTER_10);

    if (rc == ResponseCode::LOCKED && keyBlob.isSuperEncrypted()) {
        return result->resultCode = ErrorCode::KEY_USER_NOT_AUTHENTICATED, Status::ok();
    }
    if (rc != ResponseCode::NO_ERROR) return result->resultCode = rc, Status::ok();

    auto dev = mKeyStore->getDevice(keyBlob);
    AuthorizationSet opParams = params.getParameters();
    KeyCharacteristics characteristics;

    std::promise<void> resultPromise;
    auto resultFuture = resultPromise.get_future();

    dev->begin(std::move(lockedEntry), appToken, std::move(keyBlob), std::move(charBlob), pruneable,
               static_cast<KeyPurpose>(purpose), std::move(opParams), entropy,
               [&, this](OperationResult result_) {
                   if (result_.resultCode.isOk() ||
                       result_.resultCode == ResponseCode::OP_AUTH_NEEDED) {
                       addOperationDevice(result_.token, dev);
                   }
                   if (result) *result = std::move(result_);
                   resultPromise.set_value();
               });

    resultFuture.wait();
    return Status::ok();
}

Status KeyStoreService::update(const sp<IBinder>& token, const KeymasterArguments& params,
                               const ::std::vector<uint8_t>& data, OperationResult* result) {
    if (!checkAllowedOperationParams(params.getParameters())) {
        result->resultCode = ErrorCode::INVALID_ARGUMENT;
        return Status::ok();
    }

    std::promise<void> resultPromise;
    auto resultFuture = resultPromise.get_future();

    auto dev = getOperationDevice(token);
    if (!dev) {
        *result = operationFailed(ErrorCode::INVALID_OPERATION_HANDLE);
        return Status::ok();
    }

    dev->update(token, params.getParameters(), data, [&](OperationResult result_) {
        if (!result_.resultCode.isOk()) {
            removeOperationDevice(token);
        }
        if (result) *result = std::move(result_);
        resultPromise.set_value();
    });

    resultFuture.wait();
    return Status::ok();
}

Status KeyStoreService::finish(const sp<IBinder>& token, const KeymasterArguments& params,
                               const ::std::vector<uint8_t>& signature,
                               const ::std::vector<uint8_t>& entropy, OperationResult* result) {
    if (!checkAllowedOperationParams(params.getParameters())) {
        result->resultCode = ErrorCode::INVALID_ARGUMENT;
        return Status::ok();
    }

    std::promise<void> resultPromise;
    auto resultFuture = resultPromise.get_future();

    auto dev = getOperationDevice(token);
    if (!dev) {
        *result = operationFailed(ErrorCode::INVALID_OPERATION_HANDLE);
        return Status::ok();
    }

    dev->finish(token, params.getParameters(), {}, signature, entropy,
                [&](OperationResult result_) {
                    if (!result_.resultCode.isOk()) {
                        removeOperationDevice(token);
                    }
                    if (result) *result = std::move(result_);
                    resultPromise.set_value();
                });

    resultFuture.wait();
    return Status::ok();
}

Status KeyStoreService::abort(const sp<IBinder>& token, int32_t* aidl_return) {
    auto dev = getOperationDevice(token);
    if (!dev) {
        *aidl_return = static_cast<int32_t>(ErrorCode::INVALID_OPERATION_HANDLE);
        return Status::ok();
    }
    std::promise<KeyStoreServiceReturnCode> resultPromise;
    auto resultFuture = resultPromise.get_future();

    dev->abort(token, [&](KeyStoreServiceReturnCode rc) { resultPromise.set_value(rc); });

    resultFuture.wait();
    *aidl_return = int32_t(resultFuture.get());
    return Status::ok();
}

Status KeyStoreService::addAuthToken(const ::std::vector<uint8_t>& authTokenAsVector,
                                     int32_t* aidl_return) {

    // TODO(swillden): When gatekeeper and fingerprint are ready, this should be updated to
    // receive a HardwareAuthToken, rather than an opaque byte array.

    if (!checkBinderPermission(P_ADD_AUTH)) {
        ALOGW("addAuthToken: permission denied for %d", IPCThreadState::self()->getCallingUid());
        *aidl_return = static_cast<int32_t>(ResponseCode::PERMISSION_DENIED);
        return Status::ok();
    }
    if (authTokenAsVector.size() != sizeof(hw_auth_token_t)) {
        *aidl_return = static_cast<int32_t>(KeyStoreServiceReturnCode(ErrorCode::INVALID_ARGUMENT));
        return Status::ok();
    }

    hw_auth_token_t authToken;
    memcpy(reinterpret_cast<void*>(&authToken), authTokenAsVector.data(), sizeof(hw_auth_token_t));
    if (authToken.version != 0) {
        *aidl_return = static_cast<int32_t>(KeyStoreServiceReturnCode(ErrorCode::INVALID_ARGUMENT));
        return Status::ok();
    }

    mKeyStore->getAuthTokenTable().AddAuthenticationToken(
        hidlVec2AuthToken(hidl_vec<uint8_t>(authTokenAsVector)));
    *aidl_return = static_cast<int32_t>(ResponseCode::NO_ERROR);
    return Status::ok();
}

int isDeviceIdAttestationRequested(const KeymasterArguments& params) {
    const hardware::hidl_vec<KeyParameter>& paramsVec = params.getParameters();
    int result = 0;
    for (size_t i = 0; i < paramsVec.size(); ++i) {
        switch (paramsVec[i].tag) {
        case Tag::ATTESTATION_ID_BRAND:
        case Tag::ATTESTATION_ID_DEVICE:
        case Tag::ATTESTATION_ID_MANUFACTURER:
        case Tag::ATTESTATION_ID_MODEL:
        case Tag::ATTESTATION_ID_PRODUCT:
            result |= ID_ATTESTATION_REQUEST_GENERIC_INFO;
            break;
        case Tag::ATTESTATION_ID_IMEI:
        case Tag::ATTESTATION_ID_MEID:
        case Tag::ATTESTATION_ID_SERIAL:
            result |= ID_ATTESTATION_REQUEST_UNIQUE_DEVICE_ID;
            break;
        default:
            continue;
        }
    }
    return result;
}

Status KeyStoreService::attestKey(const String16& name, const KeymasterArguments& params,
                                  ::android::security::keymaster::KeymasterCertificateChain* chain,
                                  int32_t* aidl_return) {
    // check null output if method signature is updated and return ErrorCode::OUTPUT_PARAMETER_NULL
    if (!checkAllowedOperationParams(params.getParameters())) {
        *aidl_return = static_cast<int32_t>(KeyStoreServiceReturnCode(ErrorCode::INVALID_ARGUMENT));
        return Status::ok();
    }

    uid_t callingUid = IPCThreadState::self()->getCallingUid();

    int needsIdAttestation = isDeviceIdAttestationRequested(params);
    bool needsUniqueIdAttestation = needsIdAttestation & ID_ATTESTATION_REQUEST_UNIQUE_DEVICE_ID;
    bool isPrimaryUserSystemUid = (callingUid == AID_SYSTEM);
    bool isSomeUserSystemUid = (get_app_id(callingUid) == AID_SYSTEM);
    // Allow system context from any user to request attestation with basic device information,
    // while only allow system context from user 0 (device owner) to request attestation with
    // unique device ID.
    if ((needsIdAttestation && !isSomeUserSystemUid) ||
        (needsUniqueIdAttestation && !isPrimaryUserSystemUid)) {
        *aidl_return = static_cast<int32_t>(KeyStoreServiceReturnCode(ErrorCode::INVALID_ARGUMENT));
        return Status::ok();
    }

    AuthorizationSet mutableParams = params.getParameters();
    KeyStoreServiceReturnCode rc = updateParamsForAttestation(callingUid, &mutableParams);
    if (!rc.isOk()) {
        *aidl_return = static_cast<int32_t>(rc);
        return Status::ok();
    }

    String8 name8(name);
    Blob keyBlob;
    Blob charBlob;
    LockedKeyBlobEntry lockedEntry;

    std::tie(rc, keyBlob, charBlob, lockedEntry) =
        mKeyStore->getKeyForName(name8, callingUid, TYPE_KEYMASTER_10);

    std::promise<KeyStoreServiceReturnCode> resultPromise;
    auto resultFuture = resultPromise.get_future();

    auto worker_cb = [&](Return<void> rc,
                         std::tuple<ErrorCode, hidl_vec<hidl_vec<uint8_t>>>&& hidlResult) {
        auto& [ret, certChain] = hidlResult;
        if (!rc.isOk()) {
            resultPromise.set_value(ResponseCode::SYSTEM_ERROR);
            return;
        }
        if (ret == ErrorCode::OK && chain) {
            *chain = KeymasterCertificateChain(certChain);
        }
        resultPromise.set_value(ret);
    };
    auto dev = mKeyStore->getDevice(keyBlob);
    auto hidlKey = blob2hidlVec(keyBlob);
    dev->attestKey(std::move(hidlKey), mutableParams.hidl_data(), worker_cb);

    resultFuture.wait();
    *aidl_return = static_cast<int32_t>(resultFuture.get());
    return Status::ok();
}

Status
KeyStoreService::attestDeviceIds(const KeymasterArguments& params,
                                 ::android::security::keymaster::KeymasterCertificateChain* chain,
                                 int32_t* aidl_return) {
    // check null output if method signature is updated and return ErrorCode::OUTPUT_PARAMETER_NULL

    if (!checkAllowedOperationParams(params.getParameters())) {
        *aidl_return = static_cast<int32_t>(KeyStoreServiceReturnCode(ErrorCode::INVALID_ARGUMENT));
        return Status::ok();
    }

    if (!isDeviceIdAttestationRequested(params)) {
        // There is an attestKey() method for attesting keys without device ID attestation.
        *aidl_return = static_cast<int32_t>(KeyStoreServiceReturnCode(ErrorCode::INVALID_ARGUMENT));
        return Status::ok();
    }

    uid_t callingUid = IPCThreadState::self()->getCallingUid();
    sp<IBinder> binder = defaultServiceManager()->getService(String16("permission"));
    if (binder == nullptr) {
        *aidl_return =
            static_cast<int32_t>(KeyStoreServiceReturnCode(ErrorCode::CANNOT_ATTEST_IDS));
        return Status::ok();
    }
    if (!interface_cast<IPermissionController>(binder)->checkPermission(
            String16("android.permission.READ_PRIVILEGED_PHONE_STATE"),
            IPCThreadState::self()->getCallingPid(), callingUid)) {
        *aidl_return =
            static_cast<int32_t>(KeyStoreServiceReturnCode(ErrorCode::CANNOT_ATTEST_IDS));
        return Status::ok();
    }

    AuthorizationSet mutableParams = params.getParameters();
    KeyStoreServiceReturnCode rc = updateParamsForAttestation(callingUid, &mutableParams);
    if (!rc.isOk()) {
        *aidl_return = static_cast<int32_t>(rc);
        return Status::ok();
    }

    // Generate temporary key.
    auto dev = mKeyStore->getDevice(SecurityLevel::TRUSTED_ENVIRONMENT);

    if (!dev) {
        *aidl_return = static_cast<int32_t>(ResponseCode::SYSTEM_ERROR);
        return Status::ok();
    }


    AuthorizationSet keyCharacteristics;
    keyCharacteristics.push_back(TAG_PURPOSE, KeyPurpose::VERIFY);
    keyCharacteristics.push_back(TAG_ALGORITHM, Algorithm::EC);
    keyCharacteristics.push_back(TAG_DIGEST, Digest::SHA_2_256);
    keyCharacteristics.push_back(TAG_NO_AUTH_REQUIRED);
    keyCharacteristics.push_back(TAG_EC_CURVE, EcCurve::P_256);

    std::promise<KeyStoreServiceReturnCode> resultPromise;
    auto resultFuture = resultPromise.get_future();

    dev->generateKey(
        keyCharacteristics.hidl_data(),
        [&, dev](Return<void> rc,
                 std::tuple<ErrorCode, ::std::vector<uint8_t>, KeyCharacteristics>&& hidlResult) {
            auto& [ret, hidlKeyBlob_, dummyCharacteristics] = hidlResult;
            auto hidlKeyBlob = std::move(hidlKeyBlob_);
            if (!rc.isOk()) {
                resultPromise.set_value(ResponseCode::SYSTEM_ERROR);
                return;
            }
            if (ret != ErrorCode::OK) {
                resultPromise.set_value(ret);
                return;
            }
            dev->attestKey(
                hidlKeyBlob, mutableParams.hidl_data(),
                [&, dev,
                 hidlKeyBlob](Return<void> rc,
                              std::tuple<ErrorCode, hidl_vec<hidl_vec<uint8_t>>>&& hidlResult) {
                    auto& [ret, certChain] = hidlResult;
                    // shedule temp key for deletion
                    dev->deleteKey(std::move(hidlKeyBlob), [](Return<ErrorCode> rc) {
                        // log error but don't return an error
                        KS_HANDLE_HIDL_ERROR(rc);
                    });
                    if (!rc.isOk()) {
                        resultPromise.set_value(ResponseCode::SYSTEM_ERROR);
                        return;
                    }
                    if (ret == ErrorCode::OK && chain) {
                        *chain =
                            ::android::security::keymaster::KeymasterCertificateChain(certChain);
                    }
                    resultPromise.set_value(ret);
                });
        });

    resultFuture.wait();
    *aidl_return = static_cast<int32_t>(resultFuture.get());
    return Status::ok();
}

Status KeyStoreService::onDeviceOffBody(int32_t* aidl_return) {
    // TODO(tuckeris): add permission check.  This should be callable from ClockworkHome only.
    mKeyStore->getAuthTokenTable().onDeviceOffBody();
    *aidl_return = static_cast<int32_t>(ResponseCode::NO_ERROR);
    return Status::ok();
}

#define AIDL_RETURN(rc)                                                                            \
    (*_aidl_return = static_cast<int32_t>(KeyStoreServiceReturnCode(rc)), Status::ok())

Status KeyStoreService::importWrappedKey(
    const ::android::String16& wrappedKeyAlias, const ::std::vector<uint8_t>& wrappedKey,
    const ::android::String16& wrappingKeyAlias, const ::std::vector<uint8_t>& maskingKey,
    const KeymasterArguments& params, int64_t rootSid, int64_t fingerprintSid,
    ::android::security::keymaster::KeyCharacteristics* outCharacteristics, int32_t* _aidl_return) {

    uid_t callingUid = IPCThreadState::self()->getCallingUid();

    if (!checkBinderPermission(P_INSERT, callingUid)) {
        return AIDL_RETURN(ResponseCode::PERMISSION_DENIED);
    }

    String8 wrappingKeyName8(wrappingKeyAlias);

    KeyStoreServiceReturnCode rc;
    Blob wrappingKeyBlob;
    Blob wrappingCharBlob;
    LockedKeyBlobEntry wrappingLockedEntry;

    std::tie(rc, wrappingKeyBlob, wrappingCharBlob, wrappingLockedEntry) =
        mKeyStore->getKeyForName(wrappingKeyName8, callingUid, TYPE_KEYMASTER_10);
    if (!rc) {
        return AIDL_RETURN(rc);
    }

    String8 wrappedKeyName8(wrappedKeyAlias);
    auto wrappedLockedEntry =
        mKeyStore->getLockedBlobEntryIfNotExists(wrappedKeyName8.string(), callingUid);
    if (!wrappedLockedEntry) {
        return AIDL_RETURN(ResponseCode::KEY_ALREADY_EXISTS);
    }

    SecurityLevel securityLevel = wrappingKeyBlob.getSecurityLevel();
    auto dev = mKeyStore->getDevice(securityLevel);
    if (!dev) {
        return AIDL_RETURN(ErrorCode::HARDWARE_TYPE_UNAVAILABLE);
    }

    std::promise<KeyStoreServiceReturnCode> resultPromise;
    auto resultFuture = resultPromise.get_future();

    dev->importWrappedKey(
        std::move(wrappingLockedEntry), std::move(wrappedLockedEntry), wrappedKey, maskingKey,
        params.getParameters(), std::move(wrappingKeyBlob), std::move(wrappingCharBlob), rootSid,
        fingerprintSid, [&](KeyStoreServiceReturnCode rc, KeyCharacteristics keyCharacteristics) {
            if (rc.isOk() && outCharacteristics) {
                *outCharacteristics =
                    ::android::security::keymaster::KeyCharacteristics(keyCharacteristics);
            }
            resultPromise.set_value(rc);
        });

    resultFuture.wait();
    return AIDL_RETURN(resultFuture.get());
}

Status KeyStoreService::presentConfirmationPrompt(const sp<IBinder>& listener,
                                                  const String16& promptText,
                                                  const ::std::vector<uint8_t>& extraData,
                                                  const String16& locale, int32_t uiOptionsAsFlags,
                                                  int32_t* aidl_return) {
    return mKeyStore->getConfirmationManager().presentConfirmationPrompt(
        listener, promptText, extraData, locale, uiOptionsAsFlags, aidl_return);
}

Status KeyStoreService::cancelConfirmationPrompt(const sp<IBinder>& listener,
                                                 int32_t* aidl_return) {
    return mKeyStore->getConfirmationManager().cancelConfirmationPrompt(listener, aidl_return);
}

Status KeyStoreService::isConfirmationPromptSupported(bool* aidl_return) {
    return mKeyStore->getConfirmationManager().isConfirmationPromptSupported(aidl_return);
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
KeyStoreServiceReturnCode
KeyStoreService::checkBinderPermissionAndKeystoreState(perm_t permission, int32_t targetUid,
                                                       bool checkUnlocked) {
    if (!checkBinderPermission(permission, targetUid)) {
        return ResponseCode::PERMISSION_DENIED;
    }
    State state = mKeyStore->getState(get_user_id(getEffectiveUid(targetUid)));
    if (checkUnlocked && !isKeystoreUnlocked(state)) {
        // All State values coincide with ResponseCodes
        return static_cast<ResponseCode>(state);
    }

    return ResponseCode::NO_ERROR;
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

/**
 * Check that all KeyParameters provided by the application are allowed. Any parameter that keystore
 * adds itself should be disallowed here.
 */
bool KeyStoreService::checkAllowedOperationParams(const hidl_vec<KeyParameter>& params) {
    for (size_t i = 0; i < params.size(); ++i) {
        switch (params[i].tag) {
        case Tag::ATTESTATION_APPLICATION_ID:
        case Tag::RESET_SINCE_ID_ROTATION:
            return false;
        default:
            break;
        }
    }
    return true;
}

Status KeyStoreService::onKeyguardVisibilityChanged(bool isShowing, int32_t userId,
                                                    int32_t* aidl_return) {
    mKeyStore->getEnforcementPolicy().set_device_locked(isShowing, userId);
    *aidl_return = static_cast<int32_t>(ResponseCode::NO_ERROR);

    return Status::ok();
}

}  // namespace keystore
