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
#include "keystore_attestation_id.h"

#define LOG_TAG "keystore_att_id"

#include <cutils/log.h>

#include <memory>
#include <string>
#include <vector>

#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <binder/PersistableBundle.h>

#include <android/security/keymaster/BpKeyAttestationApplicationIdProvider.h>
#include <android/security/keymaster/IKeyAttestationApplicationIdProvider.h>
#include <keystore/KeyAttestationApplicationId.h>
#include <keystore/KeyAttestationPackageInfo.h>
#include <keystore/Signature.h>

#include <openssl/asn1t.h>
#include <openssl/sha.h>

#include <utils/String8.h>

namespace android {

namespace {

static std::vector<uint8_t> signature2SHA256(const content::pm::Signature& sig) {
    std::vector<uint8_t> digest_buffer(SHA256_DIGEST_LENGTH);
    SHA256(sig.data().data(), sig.data().size(), digest_buffer.data());
    return digest_buffer;
}

using ::android::security::keymaster::BpKeyAttestationApplicationIdProvider;

class KeyAttestationApplicationIdProvider : public BpKeyAttestationApplicationIdProvider {
  public:
    KeyAttestationApplicationIdProvider();

    static KeyAttestationApplicationIdProvider& get();

  private:
    android::sp<android::IServiceManager> service_manager_;
};

KeyAttestationApplicationIdProvider& KeyAttestationApplicationIdProvider::get() {
    static KeyAttestationApplicationIdProvider mpm;
    return mpm;
}

KeyAttestationApplicationIdProvider::KeyAttestationApplicationIdProvider()
    : BpKeyAttestationApplicationIdProvider(
          android::defaultServiceManager()->getService(String16("sec_key_att_app_id_provider"))) {}

DECLARE_STACK_OF(ASN1_OCTET_STRING);

typedef struct km_attestation_package_info {
    ASN1_OCTET_STRING* package_name;
    ASN1_INTEGER* version;
    STACK_OF(ASN1_OCTET_STRING) * signature_digests;
} KM_ATTESTATION_PACKAGE_INFO;

ASN1_SEQUENCE(KM_ATTESTATION_PACKAGE_INFO) = {
    ASN1_SIMPLE(KM_ATTESTATION_PACKAGE_INFO, package_name, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KM_ATTESTATION_PACKAGE_INFO, version, ASN1_INTEGER),
    ASN1_SET_OF(KM_ATTESTATION_PACKAGE_INFO, signature_digests, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(KM_ATTESTATION_PACKAGE_INFO);
IMPLEMENT_ASN1_FUNCTIONS(KM_ATTESTATION_PACKAGE_INFO);

DECLARE_STACK_OF(KM_ATTESTATION_PACKAGE_INFO);

typedef struct km_attestation_application_id {
    STACK_OF(KM_ATTESTATION_PACKAGE_INFO) * package_infos;
} KM_ATTESTATION_APPLICATION_ID;

ASN1_SEQUENCE(KM_ATTESTATION_APPLICATION_ID) = {
    ASN1_SET_OF(KM_ATTESTATION_APPLICATION_ID, package_infos, KM_ATTESTATION_PACKAGE_INFO),
} ASN1_SEQUENCE_END(KM_ATTESTATION_APPLICATION_ID);
IMPLEMENT_ASN1_FUNCTIONS(KM_ATTESTATION_APPLICATION_ID);
}

}  // namespace android

namespace std {
template <> struct default_delete<android::KM_ATTESTATION_PACKAGE_INFO> {
    void operator()(android::KM_ATTESTATION_PACKAGE_INFO* p) {
        android::KM_ATTESTATION_PACKAGE_INFO_free(p);
    }
};
template <> struct default_delete<ASN1_OCTET_STRING> {
    void operator()(ASN1_OCTET_STRING* p) { ASN1_OCTET_STRING_free(p); }
};
template <> struct default_delete<android::KM_ATTESTATION_APPLICATION_ID> {
    void operator()(android::KM_ATTESTATION_APPLICATION_ID* p) {
        android::KM_ATTESTATION_APPLICATION_ID_free(p);
    }
};
}  // namespace std

namespace android {
namespace security {
namespace {

using ::android::security::keymaster::KeyAttestationApplicationId;
using ::android::security::keymaster::KeyAttestationPackageInfo;

status_t build_attestation_package_info(
    const std::string& pkg_name, const uint32_t pkg_version,
    const std::vector<std::vector<uint8_t>>& signature_digests,
    std::unique_ptr<KM_ATTESTATION_PACKAGE_INFO>* attestation_package_info_ptr) {

    if (!attestation_package_info_ptr) return BAD_VALUE;
    auto& attestation_package_info = *attestation_package_info_ptr;

    attestation_package_info.reset(KM_ATTESTATION_PACKAGE_INFO_new());
    if (!attestation_package_info.get()) return NO_MEMORY;

    if (!ASN1_OCTET_STRING_set(attestation_package_info->package_name,
                               reinterpret_cast<const unsigned char*>(pkg_name.data()),
                               pkg_name.size())) {
        return UNKNOWN_ERROR;
    }

    auto signature_digest_stack =
        reinterpret_cast<_STACK*>(attestation_package_info->signature_digests);

    assert(signature_digest_stack != nullptr);

    for (auto si : signature_digests) {
        auto asn1_item = std::unique_ptr<ASN1_OCTET_STRING>(ASN1_OCTET_STRING_new());
        if (!asn1_item) return NO_MEMORY;
        if (!ASN1_OCTET_STRING_set(asn1_item.get(), si.data(), si.size())) {
            return UNKNOWN_ERROR;
        }
        if (!sk_push(signature_digest_stack, asn1_item.get())) {
            return NO_MEMORY;
        }
        asn1_item.release();  // if push succeeded, the stack takes ownership
    }

    if (!ASN1_INTEGER_set(attestation_package_info->version, pkg_version)) {
        return UNKNOWN_ERROR;
    }

    return NO_ERROR;
}

inline std::pair<std::vector<uint8_t>, status_t> wraperror(const status_t status) {
    return std::pair<std::vector<uint8_t>, status_t>(std::vector<uint8_t>(), status);
}

std::pair<std::vector<uint8_t>, status_t>
build_attestation_application_id(const KeyAttestationApplicationId& key_attestation_id) {
    auto attestation_id =
        std::unique_ptr<KM_ATTESTATION_APPLICATION_ID>(KM_ATTESTATION_APPLICATION_ID_new());

    auto attestation_pinfo_stack = reinterpret_cast<_STACK*>(attestation_id->package_infos);

    for (auto pinfo = key_attestation_id.pinfos_begin(); pinfo != key_attestation_id.pinfos_end();
         ++pinfo) {
        std::vector<std::vector<uint8_t>> signature_digests;

        for (auto sig = pinfo->sigs_begin(); sig != pinfo->sigs_end(); ++sig) {
            signature_digests.push_back(signature2SHA256(*sig));
        }

        if (!pinfo->package_name()) {
            ALOGE("Key attestation package info lacks package name");
            return wraperror(BAD_VALUE);
        }
        std::string package_name(String8(*pinfo->package_name()).string());
        std::unique_ptr<KM_ATTESTATION_PACKAGE_INFO> attestation_package_info;
        auto rc = build_attestation_package_info(package_name, pinfo->version_code(),
                                                 signature_digests, &attestation_package_info);
        if (rc != NO_ERROR) {
            ALOGE("Building DER attestation package info failed %d", rc);
            return wraperror(rc);
        }
        if (!sk_push(attestation_pinfo_stack, attestation_package_info.get())) {
            return wraperror(NO_MEMORY);
        }
        // if push succeeded, the stack takes ownership
        attestation_package_info.release();
    }

    int len = i2d_KM_ATTESTATION_APPLICATION_ID(attestation_id.get(), nullptr);
    if (len < 0) return wraperror(UNKNOWN_ERROR);
    auto result = std::make_pair(std::vector<uint8_t>(len), NO_ERROR);
    uint8_t* p = result.first.data();
    len = i2d_KM_ATTESTATION_APPLICATION_ID(attestation_id.get(), &p);
    if (len < 0) return wraperror(UNKNOWN_ERROR);

    return result;
}

/* The following function are not used. They are mentioned here to silence
 * warnings about them not being used.
 */
void unused_functions_silencer() __attribute__((unused));
void unused_functions_silencer() {
    i2d_KM_ATTESTATION_PACKAGE_INFO(nullptr, nullptr);
    d2i_KM_ATTESTATION_APPLICATION_ID(nullptr, nullptr, 0);
    d2i_KM_ATTESTATION_PACKAGE_INFO(nullptr, nullptr, 0);
}

}  // namespace

std::pair<std::vector<uint8_t>, status_t> gather_attestation_application_id(uid_t uid) {
    auto& pm = KeyAttestationApplicationIdProvider::get();

    /* Get the attestation application ID from package manager */
    KeyAttestationApplicationId key_attestation_id;
    auto status = pm.getKeyAttestationApplicationId(uid, &key_attestation_id);
    if (!status.isOk()) {
        ALOGE("package manager request for key attestation ID failed with: %s",
              status.exceptionMessage().string());
        return wraperror(FAILED_TRANSACTION);
    }

    /* DER encode the attestation application ID */
    return build_attestation_application_id(key_attestation_id);
}

}  // namespace security
}  // namespace android
