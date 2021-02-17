/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "km_compat.h"
#include <keymint_support/keymint_tags.h>

#include <aidl/android/hardware/security/keymint/Algorithm.h>
#include <aidl/android/hardware/security/keymint/BlockMode.h>
#include <aidl/android/hardware/security/keymint/Digest.h>
#include <aidl/android/hardware/security/keymint/PaddingMode.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#define DEFINE_OPENSSL_OBJECT_POINTER(name) using name##_Ptr = bssl::UniquePtr<name>

DEFINE_OPENSSL_OBJECT_POINTER(EVP_PKEY);
DEFINE_OPENSSL_OBJECT_POINTER(X509);

using ::aidl::android::hardware::security::keymint::Algorithm;
using ::aidl::android::hardware::security::keymint::BlockMode;
using ::aidl::android::hardware::security::keymint::Certificate;
using ::aidl::android::hardware::security::keymint::Digest;
using ::aidl::android::hardware::security::keymint::PaddingMode;
using ::aidl::android::hardware::security::keymint::SecurityLevel;
using ::aidl::android::hardware::security::keymint::Tag;

namespace KMV1 = ::aidl::android::hardware::security::keymint;

static std::variant<std::vector<Certificate>, ScopedAStatus>
getCertificate(const std::vector<KeyParameter>& keyParams) {
    static std::shared_ptr<KeyMintDevice> device =
        KeyMintDevice::createKeyMintDevice(SecurityLevel::TRUSTED_ENVIRONMENT);
    if (!device) {
        return ScopedAStatus::fromStatus(STATUS_NAME_NOT_FOUND);
    }
    KeyCreationResult creationResult;
    auto status = device->generateKey(keyParams, std::nullopt /* attest_key */, &creationResult);
    if (!status.isOk()) {
        return status;
    }
    return creationResult.certificateChain;
}

static void ensureCertChainSize(const std::variant<std::vector<Certificate>, ScopedAStatus>& result,
                                uint32_t size) {
    ASSERT_TRUE(std::holds_alternative<std::vector<Certificate>>(result));
    auto certChain = std::get<std::vector<Certificate>>(result);
    ASSERT_EQ(certChain.size(), size);
}

static void verify(const Certificate& certificate) {
    const uint8_t* p = certificate.encodedCertificate.data();
    X509_Ptr decoded_cert(d2i_X509(nullptr, &p, (long)certificate.encodedCertificate.size()));
    EVP_PKEY_Ptr decoded_pkey(X509_get_pubkey(decoded_cert.get()));
    ASSERT_TRUE(X509_verify(decoded_cert.get(), decoded_pkey.get()));
}

static std::vector<KeyParameter> getRSAKeyParams(const std::vector<KeyParameter>& extraParams) {
    auto keyParams = std::vector<KeyParameter>({
        KMV1::makeKeyParameter(KMV1::TAG_ALGORITHM, Algorithm::RSA),
        KMV1::makeKeyParameter(KMV1::TAG_KEY_SIZE, 2048),
        KMV1::makeKeyParameter(KMV1::TAG_RSA_PUBLIC_EXPONENT, 65537),
    });
    keyParams.insert(keyParams.end(), extraParams.begin(), extraParams.end());
    return keyParams;
}

TEST(CertificateTest, TestRSAKeygen) {
    auto keyParams = getRSAKeyParams({
        KMV1::makeKeyParameter(KMV1::TAG_DIGEST, Digest::SHA_2_256),
        KMV1::makeKeyParameter(KMV1::TAG_PADDING, PaddingMode::RSA_PSS),
        KMV1::makeKeyParameter(KMV1::TAG_NO_AUTH_REQUIRED),
        KMV1::makeKeyParameter(KMV1::TAG_PURPOSE, KeyPurpose::SIGN),
        KMV1::makeKeyParameter(KMV1::TAG_PURPOSE, KeyPurpose::ENCRYPT),
    });
    auto result = getCertificate(keyParams);
    ensureCertChainSize(result, 1);
}

TEST(CertificateTest, TestAES) {
    auto keyParams = {
        KMV1::makeKeyParameter(KMV1::TAG_ALGORITHM, Algorithm::AES),
        KMV1::makeKeyParameter(KMV1::TAG_KEY_SIZE, 128),
        KMV1::makeKeyParameter(KMV1::TAG_BLOCK_MODE, BlockMode::CBC),
        KMV1::makeKeyParameter(KMV1::TAG_PADDING, PaddingMode::NONE),
        KMV1::makeKeyParameter(KMV1::TAG_PURPOSE, KeyPurpose::ENCRYPT),
    };
    auto result = getCertificate(keyParams);
    ensureCertChainSize(result, 0);
}

TEST(CertificateTest, TestAttestation) {
    auto keyParams = getRSAKeyParams({
        KMV1::makeKeyParameter(KMV1::TAG_PURPOSE, KeyPurpose::SIGN),
        KMV1::makeKeyParameter(KMV1::TAG_ATTESTATION_CHALLENGE, 42),
        KMV1::makeKeyParameter(KMV1::TAG_ATTESTATION_APPLICATION_ID, 42),
    });
    auto result = getCertificate(keyParams);
    ensureCertChainSize(result, 3);
    verify(std::get<std::vector<Certificate>>(result).back());
}

TEST(CertificateTest, TestRSAKeygenNoEncryptNoAuthRequired) {
    auto keyParams = getRSAKeyParams({
        KMV1::makeKeyParameter(KMV1::TAG_DIGEST, Digest::SHA_2_256),
        KMV1::makeKeyParameter(KMV1::TAG_PADDING, PaddingMode::RSA_PSS),
        KMV1::makeKeyParameter(KMV1::TAG_NO_AUTH_REQUIRED, true),
        KMV1::makeKeyParameter(KMV1::TAG_PURPOSE, KeyPurpose::SIGN),
    });
    auto result = getCertificate(keyParams);
    ensureCertChainSize(result, 1);
    verify(std::get<std::vector<Certificate>>(result)[0]);
}

TEST(CertificateTest, TestRSAKeygenNoEncryptAuthRequired) {
    auto keyParams = getRSAKeyParams({
        KMV1::makeKeyParameter(KMV1::TAG_DIGEST, Digest::SHA_2_256),
        KMV1::makeKeyParameter(KMV1::TAG_PADDING, PaddingMode::RSA_PSS),
        KMV1::makeKeyParameter(KMV1::TAG_PURPOSE, KeyPurpose::SIGN),
    });
    auto result = getCertificate(keyParams);
    ensureCertChainSize(result, 1);
}
