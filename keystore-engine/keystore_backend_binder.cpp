/* Copyright 2017 The Android Open Source Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#include "keystore_backend_binder.h"

#include <android-base/logging.h>
#include <android/security/IKeystoreService.h>
#include <binder/IServiceManager.h>
#include <keystore/KeyCharacteristics.h>
#include <keystore/KeymasterArguments.h>
#include <keystore/KeymasterBlob.h>
#include <keystore/OperationResult.h>
#include <keystore/keymaster_types.h>
#include <keystore/keystore.h>
#include <keystore/keystore_hidl_support.h>
#include <keystore/keystore_return_types.h>

using android::security::IKeystoreService;
using namespace android;
using keystore::hidl_vec;

using android::hardware::keymaster::V4_0::Algorithm;
using android::hardware::keymaster::V4_0::authorizationValue;
using android::hardware::keymaster::V4_0::Digest;
using android::hardware::keymaster::V4_0::KeyFormat;
using android::hardware::keymaster::V4_0::KeyParameter;
using android::hardware::keymaster::V4_0::KeyPurpose;
using android::hardware::keymaster::V4_0::NullOr;
using android::hardware::keymaster::V4_0::PaddingMode;
using android::hardware::keymaster::V4_0::TAG_ALGORITHM;
using android::hardware::keymaster::V4_0::TAG_DIGEST;
using android::hardware::keymaster::V4_0::TAG_PADDING;
using android::security::keymaster::ExportResult;
using android::security::keymaster::KeyCharacteristics;
using android::security::keymaster::KeymasterArguments;
using android::security::keymaster::KeymasterBlob;
using android::security::keymaster::OperationResult;

using KSReturn = keystore::KeyStoreNativeReturnCode;

namespace {
const char keystore_service_name[] = "android.security.keystore";
constexpr int32_t UID_SELF = -1;
};

#define AT __func__ << ":" << __LINE__ << " "

static NullOr<const Algorithm&> getKeyAlgoritmFromKeyCharacteristics(
    const ::android::security::keymaster::KeyCharacteristics& characteristics) {
    for (const auto& param : characteristics.hardwareEnforced.getParameters()) {
        auto algo = authorizationValue(TAG_ALGORITHM, param);
        if (algo.isOk()) return algo;
    }
    for (const auto& param : characteristics.softwareEnforced.getParameters()) {
        auto algo = authorizationValue(TAG_ALGORITHM, param);
        if (algo.isOk()) return algo;
    }
    return {};
}

int32_t KeystoreBackendBinder::sign(const char* key_id, const uint8_t* in, size_t len,
                                    uint8_t** reply, size_t* reply_len) {
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16(keystore_service_name));
    sp<IKeystoreService> service = interface_cast<IKeystoreService>(binder);

    if (service == nullptr) {
        LOG(ERROR) << AT << "could not contact keystore";
        return -1;
    }

    KeyCharacteristics keyCharacteristics;
    String16 key_name16(key_id);
    int32_t aidl_result;
    auto binder_result = service->getKeyCharacteristics(
        key_name16, KeymasterBlob(), KeymasterBlob(), UID_SELF, &keyCharacteristics, &aidl_result);
    if (!binder_result.isOk()) {
        LOG(ERROR) << AT << "communication error while calling keystore";
        return -1;
    }
    if (KSReturn(aidl_result).isOk()) {
        LOG(ERROR) << AT << "getKeyCharacteristics failed: " << aidl_result;
    }

    auto algorithm = getKeyAlgoritmFromKeyCharacteristics(keyCharacteristics);
    if (!algorithm.isOk()) {
        LOG(ERROR) << AT << "could not get algorithm from key characteristics";
        return -1;
    }

    hidl_vec<KeyParameter> params(3);
    params[0] = Authorization(TAG_DIGEST, Digest::NONE);
    params[1] = Authorization(TAG_PADDING, PaddingMode::NONE);
    params[2] = Authorization(TAG_ALGORITHM, algorithm.value());

    android::sp<android::IBinder> token(new android::BBinder);
    OperationResult result;
    binder_result = service->begin(token, key_name16, (int)KeyPurpose::SIGN, true /*pruneable*/,
                                   KeymasterArguments(params), std::vector<uint8_t>() /* entropy */,
                                   UID_SELF, &result);
    if (!binder_result.isOk()) {
        LOG(ERROR) << AT << "communication error while calling keystore";
        return -1;
    }
    if (!result.resultCode.isOk()) {
        LOG(ERROR) << AT << "begin failed: " << int32_t(result.resultCode);
        return -1;
    }
    auto handle = std::move(result.token);

    do {
        binder_result = service->update(handle, KeymasterArguments(params),
                                        std::vector<uint8_t>(in, in + len), &result);
        if (!binder_result.isOk()) {
            LOG(ERROR) << AT << "communication error while calling keystore";
            return -1;
        }
        if (!result.resultCode.isOk()) {
            LOG(ERROR) << AT << "update failed: " << int32_t(result.resultCode);
            return -1;
        }
        if (result.inputConsumed > len) {
            LOG(ERROR) << AT << "update consumed more data than provided";
            service->abort(handle, &aidl_result);
            return -1;
        }
        len -= result.inputConsumed;
        in += result.inputConsumed;
    } while (len > 0);

    binder_result =
        service->finish(handle, KeymasterArguments(params), std::vector<uint8_t>() /* signature */,
                        std::vector<uint8_t>() /* entropy */, &result);
    if (!binder_result.isOk()) {
        LOG(ERROR) << AT << "communication error while calling keystore";
        return -1;
    }
    if (!result.resultCode.isOk()) {
        LOG(ERROR) << AT << "finish failed: " << int32_t(result.resultCode);
        return -1;
    }

    hidl_vec<uint8_t> reply_hidl(result.data);
    if (reply_len) {
        *reply_len = reply_hidl.size();
    }
    if (reply) {
        *reply = reply_hidl.releaseData();
    }
    return 0;
}

int32_t KeystoreBackendBinder::get_pubkey(const char* key_id, uint8_t** pubkey,
                                          size_t* pubkey_len) {
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16(keystore_service_name));
    sp<IKeystoreService> service = interface_cast<IKeystoreService>(binder);

    if (service == nullptr) {
        LOG(ERROR) << AT << "could not contact keystore";
        return -1;
    }

    ExportResult result;
    auto binder_result = service->exportKey(String16(key_id), static_cast<int32_t>(KeyFormat::X509),
                                            KeymasterBlob() /* clientId */,
                                            KeymasterBlob() /* appData */, UID_SELF, &result);
    if (!binder_result.isOk()) {
        LOG(ERROR) << AT << "communication error while calling keystore";
        return -1;
    }
    if (!result.resultCode.isOk()) {
        LOG(ERROR) << AT << "exportKey failed: " << int32_t(result.resultCode);
        return -1;
    }

    hidl_vec<uint8_t> reply_hidl(result.exportData);
    if (pubkey_len) {
        *pubkey_len = reply_hidl.size();
    }
    if (pubkey) {
        *pubkey = reply_hidl.releaseData();
    }
    return 0;
}
