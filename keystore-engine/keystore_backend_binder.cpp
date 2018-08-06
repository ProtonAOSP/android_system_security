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

#include <android/security/IKeystoreService.h>
#include <binder/IServiceManager.h>
#include <keystore/keystore.h>
#include <keystore/keystore_hidl_support.h>

using android::security::IKeystoreService;
using namespace android;
using keystore::blob2hidlVec;
using keystore::hidl_vec;

namespace {
const char keystore_service_name[] = "android.security.keystore";
};

int32_t KeystoreBackendBinder::sign(const char* key_id, const uint8_t* in, size_t len,
                                    uint8_t** reply, size_t* reply_len) {
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16(keystore_service_name));
    sp<IKeystoreService> service = interface_cast<IKeystoreService>(binder);

    if (service == nullptr) {
        ALOGE("could not contact keystore");
        return -1;
    }

    auto inBlob = blob2hidlVec(in, len);
    std::vector<uint8_t> reply_vec;
    auto ret = service->sign(String16(key_id), inBlob, &reply_vec);
    if (!ret.isOk()) {
        return -1;
    }

    hidl_vec<uint8_t> reply_hidl(reply_vec);  // makes copy
    *reply = reply_hidl.releaseData();
    *reply_len = reply_vec.size();
    return 0;
}

int32_t KeystoreBackendBinder::get_pubkey(const char* key_id, uint8_t** pubkey,
                                          size_t* pubkey_len) {
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16(keystore_service_name));
    sp<IKeystoreService> service = interface_cast<IKeystoreService>(binder);

    if (service == nullptr) {
        ALOGE("could not contact keystore");
        return -1;
    }

    std::vector<uint8_t> pubkey_vec;
    auto ret = service->get_pubkey(String16(key_id), &pubkey_vec);
    if (!ret.isOk()) {
        return -1;
    }

    hidl_vec<uint8_t> hidl_pubkey(pubkey_vec);  // makes copy
    *pubkey = hidl_pubkey.releaseData();        // caller should clean up memory.
    *pubkey_len = pubkey_vec.size();
    return 0;
}
