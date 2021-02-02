/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <aidl/android/hardware/security/keymint/ErrorCode.h>
#include <keymasterV4_1/keymaster_tags.h>
#include <keymint_support/keymint_tags.h>

namespace V4_0 = ::android::hardware::keymaster::V4_0;
namespace V4_1 = ::android::hardware::keymaster::V4_1;
namespace KMV1 = ::aidl::android::hardware::security::keymint;

static KMV1::ErrorCode convert(V4_0::ErrorCode error) {
    switch (error) {
    case V4_0::ErrorCode::OK:
        return KMV1::ErrorCode::OK;
    case V4_0::ErrorCode::ROOT_OF_TRUST_ALREADY_SET:
        return KMV1::ErrorCode::ROOT_OF_TRUST_ALREADY_SET;
    case V4_0::ErrorCode::UNSUPPORTED_PURPOSE:
        return KMV1::ErrorCode::UNSUPPORTED_PURPOSE;
    case V4_0::ErrorCode::INCOMPATIBLE_PURPOSE:
        return KMV1::ErrorCode::INCOMPATIBLE_PURPOSE;
    case V4_0::ErrorCode::UNSUPPORTED_ALGORITHM:
        return KMV1::ErrorCode::UNSUPPORTED_ALGORITHM;
    case V4_0::ErrorCode::INCOMPATIBLE_ALGORITHM:
        return KMV1::ErrorCode::INCOMPATIBLE_ALGORITHM;
    case V4_0::ErrorCode::UNSUPPORTED_KEY_SIZE:
        return KMV1::ErrorCode::UNSUPPORTED_KEY_SIZE;
    case V4_0::ErrorCode::UNSUPPORTED_BLOCK_MODE:
        return KMV1::ErrorCode::UNSUPPORTED_BLOCK_MODE;
    case V4_0::ErrorCode::INCOMPATIBLE_BLOCK_MODE:
        return KMV1::ErrorCode::INCOMPATIBLE_BLOCK_MODE;
    case V4_0::ErrorCode::UNSUPPORTED_MAC_LENGTH:
        return KMV1::ErrorCode::UNSUPPORTED_MAC_LENGTH;
    case V4_0::ErrorCode::UNSUPPORTED_PADDING_MODE:
        return KMV1::ErrorCode::UNSUPPORTED_PADDING_MODE;
    case V4_0::ErrorCode::INCOMPATIBLE_PADDING_MODE:
        return KMV1::ErrorCode::INCOMPATIBLE_PADDING_MODE;
    case V4_0::ErrorCode::UNSUPPORTED_DIGEST:
        return KMV1::ErrorCode::UNSUPPORTED_DIGEST;
    case V4_0::ErrorCode::INCOMPATIBLE_DIGEST:
        return KMV1::ErrorCode::INCOMPATIBLE_DIGEST;
    case V4_0::ErrorCode::INVALID_EXPIRATION_TIME:
        return KMV1::ErrorCode::INVALID_EXPIRATION_TIME;
    case V4_0::ErrorCode::INVALID_USER_ID:
        return KMV1::ErrorCode::INVALID_USER_ID;
    case V4_0::ErrorCode::INVALID_AUTHORIZATION_TIMEOUT:
        return KMV1::ErrorCode::INVALID_AUTHORIZATION_TIMEOUT;
    case V4_0::ErrorCode::UNSUPPORTED_KEY_FORMAT:
        return KMV1::ErrorCode::UNSUPPORTED_KEY_FORMAT;
    case V4_0::ErrorCode::INCOMPATIBLE_KEY_FORMAT:
        return KMV1::ErrorCode::INCOMPATIBLE_KEY_FORMAT;
    case V4_0::ErrorCode::UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM:
        return KMV1::ErrorCode::UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
    case V4_0::ErrorCode::UNSUPPORTED_KEY_VERIFICATION_ALGORITHM:
        return KMV1::ErrorCode::UNSUPPORTED_KEY_VERIFICATION_ALGORITHM;
    case V4_0::ErrorCode::INVALID_INPUT_LENGTH:
        return KMV1::ErrorCode::INVALID_INPUT_LENGTH;
    case V4_0::ErrorCode::KEY_EXPORT_OPTIONS_INVALID:
        return KMV1::ErrorCode::KEY_EXPORT_OPTIONS_INVALID;
    case V4_0::ErrorCode::DELEGATION_NOT_ALLOWED:
        return KMV1::ErrorCode::DELEGATION_NOT_ALLOWED;
    case V4_0::ErrorCode::KEY_NOT_YET_VALID:
        return KMV1::ErrorCode::KEY_NOT_YET_VALID;
    case V4_0::ErrorCode::KEY_EXPIRED:
        return KMV1::ErrorCode::KEY_EXPIRED;
    case V4_0::ErrorCode::KEY_USER_NOT_AUTHENTICATED:
        return KMV1::ErrorCode::KEY_USER_NOT_AUTHENTICATED;
    case V4_0::ErrorCode::OUTPUT_PARAMETER_NULL:
        return KMV1::ErrorCode::OUTPUT_PARAMETER_NULL;
    case V4_0::ErrorCode::INVALID_OPERATION_HANDLE:
        return KMV1::ErrorCode::INVALID_OPERATION_HANDLE;
    case V4_0::ErrorCode::INSUFFICIENT_BUFFER_SPACE:
        return KMV1::ErrorCode::INSUFFICIENT_BUFFER_SPACE;
    case V4_0::ErrorCode::VERIFICATION_FAILED:
        return KMV1::ErrorCode::VERIFICATION_FAILED;
    case V4_0::ErrorCode::TOO_MANY_OPERATIONS:
        return KMV1::ErrorCode::TOO_MANY_OPERATIONS;
    case V4_0::ErrorCode::UNEXPECTED_NULL_POINTER:
        return KMV1::ErrorCode::UNEXPECTED_NULL_POINTER;
    case V4_0::ErrorCode::INVALID_KEY_BLOB:
        return KMV1::ErrorCode::INVALID_KEY_BLOB;
    case V4_0::ErrorCode::IMPORTED_KEY_NOT_ENCRYPTED:
        return KMV1::ErrorCode::IMPORTED_KEY_NOT_ENCRYPTED;
    case V4_0::ErrorCode::IMPORTED_KEY_DECRYPTION_FAILED:
        return KMV1::ErrorCode::IMPORTED_KEY_DECRYPTION_FAILED;
    case V4_0::ErrorCode::IMPORTED_KEY_NOT_SIGNED:
        return KMV1::ErrorCode::IMPORTED_KEY_NOT_SIGNED;
    case V4_0::ErrorCode::IMPORTED_KEY_VERIFICATION_FAILED:
        return KMV1::ErrorCode::IMPORTED_KEY_VERIFICATION_FAILED;
    case V4_0::ErrorCode::INVALID_ARGUMENT:
        return KMV1::ErrorCode::INVALID_ARGUMENT;
    case V4_0::ErrorCode::UNSUPPORTED_TAG:
        return KMV1::ErrorCode::UNSUPPORTED_TAG;
    case V4_0::ErrorCode::INVALID_TAG:
        return KMV1::ErrorCode::INVALID_TAG;
    case V4_0::ErrorCode::MEMORY_ALLOCATION_FAILED:
        return KMV1::ErrorCode::MEMORY_ALLOCATION_FAILED;
    case V4_0::ErrorCode::IMPORT_PARAMETER_MISMATCH:
        return KMV1::ErrorCode::IMPORT_PARAMETER_MISMATCH;
    case V4_0::ErrorCode::SECURE_HW_ACCESS_DENIED:
        return KMV1::ErrorCode::SECURE_HW_ACCESS_DENIED;
    case V4_0::ErrorCode::OPERATION_CANCELLED:
        return KMV1::ErrorCode::OPERATION_CANCELLED;
    case V4_0::ErrorCode::CONCURRENT_ACCESS_CONFLICT:
        return KMV1::ErrorCode::CONCURRENT_ACCESS_CONFLICT;
    case V4_0::ErrorCode::SECURE_HW_BUSY:
        return KMV1::ErrorCode::SECURE_HW_BUSY;
    case V4_0::ErrorCode::SECURE_HW_COMMUNICATION_FAILED:
        return KMV1::ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    case V4_0::ErrorCode::UNSUPPORTED_EC_FIELD:
        return KMV1::ErrorCode::UNSUPPORTED_EC_FIELD;
    case V4_0::ErrorCode::MISSING_NONCE:
        return KMV1::ErrorCode::MISSING_NONCE;
    case V4_0::ErrorCode::INVALID_NONCE:
        return KMV1::ErrorCode::INVALID_NONCE;
    case V4_0::ErrorCode::MISSING_MAC_LENGTH:
        return KMV1::ErrorCode::MISSING_MAC_LENGTH;
    case V4_0::ErrorCode::KEY_RATE_LIMIT_EXCEEDED:
        return KMV1::ErrorCode::KEY_RATE_LIMIT_EXCEEDED;
    case V4_0::ErrorCode::CALLER_NONCE_PROHIBITED:
        return KMV1::ErrorCode::CALLER_NONCE_PROHIBITED;
    case V4_0::ErrorCode::KEY_MAX_OPS_EXCEEDED:
        return KMV1::ErrorCode::KEY_MAX_OPS_EXCEEDED;
    case V4_0::ErrorCode::INVALID_MAC_LENGTH:
        return KMV1::ErrorCode::INVALID_MAC_LENGTH;
    case V4_0::ErrorCode::MISSING_MIN_MAC_LENGTH:
        return KMV1::ErrorCode::MISSING_MIN_MAC_LENGTH;
    case V4_0::ErrorCode::UNSUPPORTED_MIN_MAC_LENGTH:
        return KMV1::ErrorCode::UNSUPPORTED_MIN_MAC_LENGTH;
    case V4_0::ErrorCode::UNSUPPORTED_KDF:
        return KMV1::ErrorCode::UNSUPPORTED_KDF;
    case V4_0::ErrorCode::UNSUPPORTED_EC_CURVE:
        return KMV1::ErrorCode::UNSUPPORTED_EC_CURVE;
    case V4_0::ErrorCode::KEY_REQUIRES_UPGRADE:
        return KMV1::ErrorCode::KEY_REQUIRES_UPGRADE;
    case V4_0::ErrorCode::ATTESTATION_CHALLENGE_MISSING:
        return KMV1::ErrorCode::ATTESTATION_CHALLENGE_MISSING;
    case V4_0::ErrorCode::KEYMASTER_NOT_CONFIGURED:
        return KMV1::ErrorCode::KEYMINT_NOT_CONFIGURED;
    case V4_0::ErrorCode::ATTESTATION_APPLICATION_ID_MISSING:
        return KMV1::ErrorCode::ATTESTATION_APPLICATION_ID_MISSING;
    case V4_0::ErrorCode::CANNOT_ATTEST_IDS:
        return KMV1::ErrorCode::CANNOT_ATTEST_IDS;
    case V4_0::ErrorCode::ROLLBACK_RESISTANCE_UNAVAILABLE:
        return KMV1::ErrorCode::ROLLBACK_RESISTANCE_UNAVAILABLE;
    case V4_0::ErrorCode::HARDWARE_TYPE_UNAVAILABLE:
        return KMV1::ErrorCode::HARDWARE_TYPE_UNAVAILABLE;
    case V4_0::ErrorCode::PROOF_OF_PRESENCE_REQUIRED:
        return KMV1::ErrorCode::PROOF_OF_PRESENCE_REQUIRED;
    case V4_0::ErrorCode::CONCURRENT_PROOF_OF_PRESENCE_REQUESTED:
        return KMV1::ErrorCode::CONCURRENT_PROOF_OF_PRESENCE_REQUESTED;
    case V4_0::ErrorCode::NO_USER_CONFIRMATION:
        return KMV1::ErrorCode::NO_USER_CONFIRMATION;
    case V4_0::ErrorCode::DEVICE_LOCKED:
        return KMV1::ErrorCode::DEVICE_LOCKED;
    case V4_0::ErrorCode::UNIMPLEMENTED:
        return KMV1::ErrorCode::UNIMPLEMENTED;
    case V4_0::ErrorCode::VERSION_MISMATCH:
        return KMV1::ErrorCode::VERSION_MISMATCH;
    case V4_0::ErrorCode::UNKNOWN_ERROR:
        return KMV1::ErrorCode::UNKNOWN_ERROR;
    }
}

static std::optional<V4_0::KeyPurpose> convert(KMV1::KeyPurpose p) {
    switch (p) {
    case KMV1::KeyPurpose::ENCRYPT:
        return V4_0::KeyPurpose::ENCRYPT;
    case KMV1::KeyPurpose::DECRYPT:
        return V4_0::KeyPurpose::DECRYPT;
    case KMV1::KeyPurpose::SIGN:
        return V4_0::KeyPurpose::SIGN;
    case KMV1::KeyPurpose::VERIFY:
        return V4_0::KeyPurpose::VERIFY;
    case KMV1::KeyPurpose::WRAP_KEY:
        return V4_0::KeyPurpose::WRAP_KEY;
    default:
        // Can end up here because KeyMint may have KeyPurpose values not in KM4.
        return {};
    }
}

static KMV1::KeyPurpose convert(V4_0::KeyPurpose p) {
    switch (p) {
    case V4_0::KeyPurpose::ENCRYPT:
        return KMV1::KeyPurpose::ENCRYPT;
    case V4_0::KeyPurpose::DECRYPT:
        return KMV1::KeyPurpose::DECRYPT;
    case V4_0::KeyPurpose::SIGN:
        return KMV1::KeyPurpose::SIGN;
    case V4_0::KeyPurpose::VERIFY:
        return KMV1::KeyPurpose::VERIFY;
    case V4_0::KeyPurpose::WRAP_KEY:
        return KMV1::KeyPurpose::WRAP_KEY;
    }
}

static V4_0::Algorithm convert(KMV1::Algorithm a) {
    switch (a) {
    case KMV1::Algorithm::RSA:
        return V4_0::Algorithm::RSA;
    case KMV1::Algorithm::EC:
        return V4_0::Algorithm::EC;
    case KMV1::Algorithm::AES:
        return V4_0::Algorithm::AES;
    case KMV1::Algorithm::TRIPLE_DES:
        return V4_0::Algorithm::TRIPLE_DES;
    case KMV1::Algorithm::HMAC:
        return V4_0::Algorithm::HMAC;
    }
}

static KMV1::Algorithm convert(V4_0::Algorithm a) {
    switch (a) {
    case V4_0::Algorithm::RSA:
        return KMV1::Algorithm::RSA;
    case V4_0::Algorithm::EC:
        return KMV1::Algorithm::EC;
    case V4_0::Algorithm::AES:
        return KMV1::Algorithm::AES;
    case V4_0::Algorithm::TRIPLE_DES:
        return KMV1::Algorithm::TRIPLE_DES;
    case V4_0::Algorithm::HMAC:
        return KMV1::Algorithm::HMAC;
    }
}

static V4_0::Digest convert(KMV1::Digest d) {
    switch (d) {
    case KMV1::Digest::NONE:
        return V4_0::Digest::NONE;
    case KMV1::Digest::MD5:
        return V4_0::Digest::MD5;
    case KMV1::Digest::SHA1:
        return V4_0::Digest::SHA1;
    case KMV1::Digest::SHA_2_224:
        return V4_0::Digest::SHA_2_224;
    case KMV1::Digest::SHA_2_256:
        return V4_0::Digest::SHA_2_256;
    case KMV1::Digest::SHA_2_384:
        return V4_0::Digest::SHA_2_384;
    case KMV1::Digest::SHA_2_512:
        return V4_0::Digest::SHA_2_512;
    }
}

static KMV1::Digest convert(V4_0::Digest d) {
    switch (d) {
    case V4_0::Digest::NONE:
        return KMV1::Digest::NONE;
    case V4_0::Digest::MD5:
        return KMV1::Digest::MD5;
    case V4_0::Digest::SHA1:
        return KMV1::Digest::SHA1;
    case V4_0::Digest::SHA_2_224:
        return KMV1::Digest::SHA_2_224;
    case V4_0::Digest::SHA_2_256:
        return KMV1::Digest::SHA_2_256;
    case V4_0::Digest::SHA_2_384:
        return KMV1::Digest::SHA_2_384;
    case V4_0::Digest::SHA_2_512:
        return KMV1::Digest::SHA_2_512;
    }
}

static V4_0::EcCurve convert(KMV1::EcCurve e) {
    switch (e) {
    case KMV1::EcCurve::P_224:
        return V4_0::EcCurve::P_224;
    case KMV1::EcCurve::P_256:
        return V4_0::EcCurve::P_256;
    case KMV1::EcCurve::P_384:
        return V4_0::EcCurve::P_384;
    case KMV1::EcCurve::P_521:
        return V4_0::EcCurve::P_521;
    }
}

static KMV1::EcCurve convert(V4_0::EcCurve e) {
    switch (e) {
    case V4_0::EcCurve::P_224:
        return KMV1::EcCurve::P_224;
    case V4_0::EcCurve::P_256:
        return KMV1::EcCurve::P_256;
    case V4_0::EcCurve::P_384:
        return KMV1::EcCurve::P_384;
    case V4_0::EcCurve::P_521:
        return KMV1::EcCurve::P_521;
    }
}

static V4_0::BlockMode convert(KMV1::BlockMode b) {
    switch (b) {
    case KMV1::BlockMode::ECB:
        return V4_0::BlockMode::ECB;
    case KMV1::BlockMode::CBC:
        return V4_0::BlockMode::CBC;
    case KMV1::BlockMode::CTR:
        return V4_0::BlockMode::CTR;
    case KMV1::BlockMode::GCM:
        return V4_0::BlockMode::GCM;
    }
}

static KMV1::BlockMode convert(V4_0::BlockMode b) {
    switch (b) {
    case V4_0::BlockMode::ECB:
        return KMV1::BlockMode::ECB;
    case V4_0::BlockMode::CBC:
        return KMV1::BlockMode::CBC;
    case V4_0::BlockMode::CTR:
        return KMV1::BlockMode::CTR;
    case V4_0::BlockMode::GCM:
        return KMV1::BlockMode::GCM;
    }
}

static V4_0::PaddingMode convert(KMV1::PaddingMode p) {
    switch (p) {
    case KMV1::PaddingMode::NONE:
        return V4_0::PaddingMode::NONE;
    case KMV1::PaddingMode::RSA_OAEP:
        return V4_0::PaddingMode::RSA_OAEP;
    case KMV1::PaddingMode::RSA_PSS:
        return V4_0::PaddingMode::RSA_PSS;
    case KMV1::PaddingMode::RSA_PKCS1_1_5_ENCRYPT:
        return V4_0::PaddingMode::RSA_PKCS1_1_5_ENCRYPT;
    case KMV1::PaddingMode::RSA_PKCS1_1_5_SIGN:
        return V4_0::PaddingMode::RSA_PKCS1_1_5_SIGN;
    case KMV1::PaddingMode::PKCS7:
        return V4_0::PaddingMode::PKCS7;
    }
}

static KMV1::PaddingMode convert(V4_0::PaddingMode p) {
    switch (p) {
    case V4_0::PaddingMode::NONE:
        return KMV1::PaddingMode::NONE;
    case V4_0::PaddingMode::RSA_OAEP:
        return KMV1::PaddingMode::RSA_OAEP;
    case V4_0::PaddingMode::RSA_PSS:
        return KMV1::PaddingMode::RSA_PSS;
    case V4_0::PaddingMode::RSA_PKCS1_1_5_ENCRYPT:
        return KMV1::PaddingMode::RSA_PKCS1_1_5_ENCRYPT;
    case V4_0::PaddingMode::RSA_PKCS1_1_5_SIGN:
        return KMV1::PaddingMode::RSA_PKCS1_1_5_SIGN;
    case V4_0::PaddingMode::PKCS7:
        return KMV1::PaddingMode::PKCS7;
    }
}

static V4_0::HardwareAuthenticatorType convert(KMV1::HardwareAuthenticatorType h) {
    uint32_t result = 0;
    uint32_t hat = static_cast<uint32_t>(h);
    if (hat & static_cast<uint32_t>(KMV1::HardwareAuthenticatorType::PASSWORD)) {
        result |= static_cast<uint32_t>(V4_0::HardwareAuthenticatorType::PASSWORD);
    }
    if (hat & static_cast<uint32_t>(KMV1::HardwareAuthenticatorType::FINGERPRINT)) {
        result |= static_cast<uint32_t>(V4_0::HardwareAuthenticatorType::FINGERPRINT);
    }
    return static_cast<V4_0::HardwareAuthenticatorType>(result);
}

static KMV1::HardwareAuthenticatorType convert(V4_0::HardwareAuthenticatorType h) {
    uint32_t result = 0;
    if ((uint32_t)h & (uint32_t)V4_0::HardwareAuthenticatorType::PASSWORD) {
        result |= (uint32_t)KMV1::HardwareAuthenticatorType::PASSWORD;
    }
    if ((uint32_t)h & (uint32_t)V4_0::HardwareAuthenticatorType::FINGERPRINT) {
        result |= (uint32_t)KMV1::HardwareAuthenticatorType::FINGERPRINT;
    }
    return static_cast<KMV1::HardwareAuthenticatorType>(result);
}

static V4_0::SecurityLevel convert(KMV1::SecurityLevel s) {
    switch (s) {
    case KMV1::SecurityLevel::SOFTWARE:
        return V4_0::SecurityLevel::SOFTWARE;
    case KMV1::SecurityLevel::TRUSTED_ENVIRONMENT:
        return V4_0::SecurityLevel::TRUSTED_ENVIRONMENT;
    case KMV1::SecurityLevel::STRONGBOX:
        return V4_0::SecurityLevel::STRONGBOX;
    case KMV1::SecurityLevel::KEYSTORE:
        return V4_0::SecurityLevel::SOFTWARE;
    }
}

static KMV1::SecurityLevel convert(V4_0::SecurityLevel s) {
    switch (s) {
    case V4_0::SecurityLevel::SOFTWARE:
        return KMV1::SecurityLevel::SOFTWARE;
    case V4_0::SecurityLevel::TRUSTED_ENVIRONMENT:
        return KMV1::SecurityLevel::TRUSTED_ENVIRONMENT;
    case V4_0::SecurityLevel::STRONGBOX:
        return KMV1::SecurityLevel::STRONGBOX;
    }
}

static V4_0::KeyOrigin convert(KMV1::KeyOrigin o) {
    switch (o) {
    case KMV1::KeyOrigin::GENERATED:
        return V4_0::KeyOrigin::GENERATED;
    case KMV1::KeyOrigin::DERIVED:
        return V4_0::KeyOrigin::DERIVED;
    case KMV1::KeyOrigin::IMPORTED:
        return V4_0::KeyOrigin::IMPORTED;
    case KMV1::KeyOrigin::RESERVED:
        return V4_0::KeyOrigin::UNKNOWN;
    case KMV1::KeyOrigin::SECURELY_IMPORTED:
        return V4_0::KeyOrigin::SECURELY_IMPORTED;
    }
}

static KMV1::KeyOrigin convert(V4_0::KeyOrigin o) {
    switch (o) {
    case V4_0::KeyOrigin::GENERATED:
        return KMV1::KeyOrigin::GENERATED;
    case V4_0::KeyOrigin::DERIVED:
        return KMV1::KeyOrigin::DERIVED;
    case V4_0::KeyOrigin::IMPORTED:
        return KMV1::KeyOrigin::IMPORTED;
    case V4_0::KeyOrigin::UNKNOWN:
        return KMV1::KeyOrigin::RESERVED;
    case V4_0::KeyOrigin::SECURELY_IMPORTED:
        return KMV1::KeyOrigin::SECURELY_IMPORTED;
    }
}

static V4_0::KeyParameter convertKeyParameterToLegacy(const KMV1::KeyParameter& kp) {
    switch (kp.tag) {
    case KMV1::Tag::INVALID:
        break;
    case KMV1::Tag::PURPOSE:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_PURPOSE, kp)) {
            std::optional<V4_0::KeyPurpose> purpose = convert(v->get());
            if (purpose) {
                return V4_0::makeKeyParameter(V4_0::TAG_PURPOSE, purpose.value());
            }
        }
        break;
    case KMV1::Tag::ALGORITHM:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ALGORITHM, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ALGORITHM, convert(v->get()));
        }
        break;
    case KMV1::Tag::KEY_SIZE:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_KEY_SIZE, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_KEY_SIZE, v->get());
        }
        break;
    case KMV1::Tag::BLOCK_MODE:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_BLOCK_MODE, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_BLOCK_MODE, convert(v->get()));
        }
        break;
    case KMV1::Tag::DIGEST:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_DIGEST, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_DIGEST, convert(v->get()));
        }
        break;
    case KMV1::Tag::PADDING:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_PADDING, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_PADDING, convert(v->get()));
        }
        break;
    case KMV1::Tag::CALLER_NONCE:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_CALLER_NONCE, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_CALLER_NONCE, v->get());
        }
        break;
    case KMV1::Tag::MIN_MAC_LENGTH:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_MIN_MAC_LENGTH, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_MIN_MAC_LENGTH, v->get());
        }
        break;
    case KMV1::Tag::EC_CURVE:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_EC_CURVE, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_EC_CURVE, convert(v->get()));
        }
        break;
    case KMV1::Tag::RSA_PUBLIC_EXPONENT:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_RSA_PUBLIC_EXPONENT, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_RSA_PUBLIC_EXPONENT, v->get());
        }
        break;
    case KMV1::Tag::INCLUDE_UNIQUE_ID:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_INCLUDE_UNIQUE_ID, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_INCLUDE_UNIQUE_ID, v->get());
        }
        break;
    case KMV1::Tag::BLOB_USAGE_REQUIREMENTS:
        // This tag has been removed. Mapped on invalid.
        break;
    case KMV1::Tag::BOOTLOADER_ONLY:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_BOOTLOADER_ONLY, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_BOOTLOADER_ONLY, v->get());
        }
        break;
    case KMV1::Tag::ROLLBACK_RESISTANCE:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ROLLBACK_RESISTANCE, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ROLLBACK_RESISTANCE, v->get());
        }
        break;
    case KMV1::Tag::HARDWARE_TYPE:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_HARDWARE_TYPE, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_HARDWARE_TYPE, convert(v->get()));
        }
        break;
    case KMV1::Tag::EARLY_BOOT_ONLY:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_EARLY_BOOT_ONLY, kp)) {
            return V4_0::makeKeyParameter(V4_1::TAG_EARLY_BOOT_ONLY, v->get());
        }
        break;
    case KMV1::Tag::ACTIVE_DATETIME:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ACTIVE_DATETIME, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ACTIVE_DATETIME, v->get());
        }
        break;
    case KMV1::Tag::ORIGINATION_EXPIRE_DATETIME:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ORIGINATION_EXPIRE_DATETIME, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ORIGINATION_EXPIRE_DATETIME, v->get());
        }
        break;
    case KMV1::Tag::USAGE_EXPIRE_DATETIME:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_USAGE_EXPIRE_DATETIME, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_USAGE_EXPIRE_DATETIME, v->get());
        }
        break;
    case KMV1::Tag::MIN_SECONDS_BETWEEN_OPS:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_MIN_SECONDS_BETWEEN_OPS, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_MIN_SECONDS_BETWEEN_OPS, v->get());
        }
        break;
    case KMV1::Tag::MAX_USES_PER_BOOT:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_MAX_USES_PER_BOOT, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_MAX_USES_PER_BOOT, v->get());
        }
        break;
    case KMV1::Tag::USAGE_COUNT_LIMIT:
        // Does not exist in KM < KeyMint 1.0.
        break;
    case KMV1::Tag::USER_ID:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_USER_ID, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_USER_ID, v->get());
        }
        break;
    case KMV1::Tag::USER_SECURE_ID:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_USER_SECURE_ID, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_USER_SECURE_ID, v->get());
        }
        break;
    case KMV1::Tag::NO_AUTH_REQUIRED:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_NO_AUTH_REQUIRED, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_NO_AUTH_REQUIRED, v->get());
        }
        break;
    case KMV1::Tag::USER_AUTH_TYPE:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_USER_AUTH_TYPE, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_USER_AUTH_TYPE, convert(v->get()));
        }
        break;
    case KMV1::Tag::AUTH_TIMEOUT:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_AUTH_TIMEOUT, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_AUTH_TIMEOUT, v->get());
        }
        break;
    case KMV1::Tag::ALLOW_WHILE_ON_BODY:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ALLOW_WHILE_ON_BODY, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ALLOW_WHILE_ON_BODY, v->get());
        }
        break;
    case KMV1::Tag::TRUSTED_USER_PRESENCE_REQUIRED:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_TRUSTED_USER_PRESENCE_REQUIRED, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_TRUSTED_USER_PRESENCE_REQUIRED, v->get());
        }
        break;
    case KMV1::Tag::TRUSTED_CONFIRMATION_REQUIRED:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_TRUSTED_CONFIRMATION_REQUIRED, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_TRUSTED_CONFIRMATION_REQUIRED, v->get());
        }
        break;
    case KMV1::Tag::UNLOCKED_DEVICE_REQUIRED:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_UNLOCKED_DEVICE_REQUIRED, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_UNLOCKED_DEVICE_REQUIRED, v->get());
        }
        break;
    case KMV1::Tag::APPLICATION_ID:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_APPLICATION_ID, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_APPLICATION_ID, v->get());
        }
        break;
    case KMV1::Tag::APPLICATION_DATA:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_APPLICATION_DATA, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_APPLICATION_DATA, v->get());
        }
        break;
    case KMV1::Tag::CREATION_DATETIME:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_CREATION_DATETIME, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_CREATION_DATETIME, v->get());
        }
        break;
    case KMV1::Tag::ORIGIN:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ORIGIN, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ORIGIN, convert(v->get()));
        }
        break;
    case KMV1::Tag::ROOT_OF_TRUST:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ROOT_OF_TRUST, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ROOT_OF_TRUST, v->get());
        }
        break;
    case KMV1::Tag::OS_VERSION:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_OS_VERSION, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_OS_VERSION, v->get());
        }
        break;
    case KMV1::Tag::OS_PATCHLEVEL:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_OS_PATCHLEVEL, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_OS_PATCHLEVEL, v->get());
        }
        break;
    case KMV1::Tag::UNIQUE_ID:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_UNIQUE_ID, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_UNIQUE_ID, v->get());
        }
        break;
    case KMV1::Tag::ATTESTATION_CHALLENGE:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ATTESTATION_CHALLENGE, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ATTESTATION_CHALLENGE, v->get());
        }
        break;
    case KMV1::Tag::ATTESTATION_APPLICATION_ID:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ATTESTATION_APPLICATION_ID, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ATTESTATION_APPLICATION_ID, v->get());
        }
        break;
    case KMV1::Tag::ATTESTATION_ID_BRAND:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ATTESTATION_ID_BRAND, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ATTESTATION_ID_BRAND, v->get());
        }
        break;
    case KMV1::Tag::ATTESTATION_ID_DEVICE:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ATTESTATION_ID_DEVICE, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ATTESTATION_ID_DEVICE, v->get());
        }
        break;
    case KMV1::Tag::ATTESTATION_ID_PRODUCT:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ATTESTATION_ID_PRODUCT, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ATTESTATION_ID_PRODUCT, v->get());
        }
        break;
    case KMV1::Tag::ATTESTATION_ID_SERIAL:
        // TODO This tag is missing from 4.0 keymaster_tags.h
        break;
    case KMV1::Tag::ATTESTATION_ID_IMEI:
        // TODO This tag is missing from 4.0 keymaster_tags.h
        break;
    case KMV1::Tag::ATTESTATION_ID_MEID:
        // TODO This tag is missing from 4.0 keymaster_tags.h
        break;
    case KMV1::Tag::ATTESTATION_ID_MANUFACTURER:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ATTESTATION_ID_MANUFACTURER, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ATTESTATION_ID_MANUFACTURER, v->get());
        }
        break;
    case KMV1::Tag::ATTESTATION_ID_MODEL:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ATTESTATION_ID_MODEL, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ATTESTATION_ID_MODEL, v->get());
        }
        break;
    case KMV1::Tag::VENDOR_PATCHLEVEL:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_VENDOR_PATCHLEVEL, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_VENDOR_PATCHLEVEL, v->get());
        }
        break;
    case KMV1::Tag::BOOT_PATCHLEVEL:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_BOOT_PATCHLEVEL, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_BOOT_PATCHLEVEL, v->get());
        }
        break;
    case KMV1::Tag::DEVICE_UNIQUE_ATTESTATION:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_DEVICE_UNIQUE_ATTESTATION, kp)) {
            return V4_0::makeKeyParameter(V4_1::TAG_DEVICE_UNIQUE_ATTESTATION, v->get());
        }
        break;
    case KMV1::Tag::IDENTITY_CREDENTIAL_KEY:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_IDENTITY_CREDENTIAL_KEY, kp)) {
            return V4_0::makeKeyParameter(V4_1::TAG_IDENTITY_CREDENTIAL_KEY, v->get());
        }
        break;
    case KMV1::Tag::STORAGE_KEY:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_STORAGE_KEY, kp)) {
            return V4_0::makeKeyParameter(V4_1::TAG_STORAGE_KEY, v->get());
        }
        break;
    case KMV1::Tag::ASSOCIATED_DATA:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_ASSOCIATED_DATA, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_ASSOCIATED_DATA, v->get());
        }
        break;
    case KMV1::Tag::NONCE:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_NONCE, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_NONCE, v->get());
        }
        break;
    case KMV1::Tag::MAC_LENGTH:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_MAC_LENGTH, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_MAC_LENGTH, v->get());
        }
        break;
    case KMV1::Tag::RESET_SINCE_ID_ROTATION:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_RESET_SINCE_ID_ROTATION, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_RESET_SINCE_ID_ROTATION, v->get());
        }
        break;
    case KMV1::Tag::CONFIRMATION_TOKEN:
        if (auto v = KMV1::authorizationValue(KMV1::TAG_CONFIRMATION_TOKEN, kp)) {
            return V4_0::makeKeyParameter(V4_0::TAG_CONFIRMATION_TOKEN, v->get());
        }
        break;
    case KMV1::Tag::RSA_OAEP_MGF_DIGEST:
        // Does not exist in KM < KeyMint 1.0.
        break;
    }
    return V4_0::KeyParameter{.tag = V4_0::Tag::INVALID};
}

static KMV1::KeyParameter convertKeyParameterFromLegacy(const V4_0::KeyParameter& kp) {
    auto unwrapper = [](auto v) -> auto {
        if (v.isOk()) {
            return std::optional(std::reference_wrapper(v.value()));
        } else {
            return std::optional<decltype(std::reference_wrapper(v.value()))>{};
        }
    };
    switch (kp.tag) {
    case V4_0::Tag::INVALID:
        break;
    case V4_0::Tag::PURPOSE:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_PURPOSE, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_PURPOSE, convert(v->get()));
        }
        break;
    case V4_0::Tag::ALGORITHM:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_ALGORITHM, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ALGORITHM, convert(v->get()));
        }
        break;
    case V4_0::Tag::KEY_SIZE:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_KEY_SIZE, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_KEY_SIZE, v->get());
        }
        break;
    case V4_0::Tag::BLOCK_MODE:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_BLOCK_MODE, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_BLOCK_MODE, convert(v->get()));
        }
        break;
    case V4_0::Tag::DIGEST:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_DIGEST, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_DIGEST, convert(v->get()));
        }
        break;
    case V4_0::Tag::PADDING:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_PADDING, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_PADDING, convert(v->get()));
        }
        break;
    case V4_0::Tag::CALLER_NONCE:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_CALLER_NONCE, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_CALLER_NONCE, v->get());
        }
        break;
    case V4_0::Tag::MIN_MAC_LENGTH:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_MIN_MAC_LENGTH, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_MIN_MAC_LENGTH, v->get());
        }
        break;
    case V4_0::Tag::EC_CURVE:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_EC_CURVE, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_EC_CURVE, convert(v->get()));
        }
        break;
    case V4_0::Tag::RSA_PUBLIC_EXPONENT:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_RSA_PUBLIC_EXPONENT, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_RSA_PUBLIC_EXPONENT, v->get());
        }
        break;
    case V4_0::Tag::INCLUDE_UNIQUE_ID:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_INCLUDE_UNIQUE_ID, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_INCLUDE_UNIQUE_ID, v->get());
        }
        break;
    case V4_0::Tag::BLOB_USAGE_REQUIREMENTS:
        // This tag has been removed. Mapped on invalid.
        break;
    case V4_0::Tag::BOOTLOADER_ONLY:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_BOOTLOADER_ONLY, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_BOOTLOADER_ONLY, v->get());
        }
        break;
    case V4_0::Tag::ROLLBACK_RESISTANCE:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_ROLLBACK_RESISTANCE, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ROLLBACK_RESISTANCE, v->get());
        }
        break;
    case V4_0::Tag::HARDWARE_TYPE:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_HARDWARE_TYPE, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_HARDWARE_TYPE, convert(v->get()));
        }
        break;
    case V4_0::Tag::ACTIVE_DATETIME:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_ACTIVE_DATETIME, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ACTIVE_DATETIME, v->get());
        }
        break;
    case V4_0::Tag::ORIGINATION_EXPIRE_DATETIME:
        if (auto v =
                unwrapper(V4_0::authorizationValue(V4_0::TAG_ORIGINATION_EXPIRE_DATETIME, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ORIGINATION_EXPIRE_DATETIME, v->get());
        }
        break;
    case V4_0::Tag::USAGE_EXPIRE_DATETIME:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_USAGE_EXPIRE_DATETIME, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_USAGE_EXPIRE_DATETIME, v->get());
        }
        break;
    case V4_0::Tag::MIN_SECONDS_BETWEEN_OPS:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_MIN_SECONDS_BETWEEN_OPS, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_MIN_SECONDS_BETWEEN_OPS, v->get());
        }
        break;
    case V4_0::Tag::MAX_USES_PER_BOOT:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_MAX_USES_PER_BOOT, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_MAX_USES_PER_BOOT, v->get());
        }
        break;
    case V4_0::Tag::USER_ID:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_USER_ID, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_USER_ID, v->get());
        }
        break;
    case V4_0::Tag::USER_SECURE_ID:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_USER_SECURE_ID, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_USER_SECURE_ID, v->get());
        }
        break;
    case V4_0::Tag::NO_AUTH_REQUIRED:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_NO_AUTH_REQUIRED, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_NO_AUTH_REQUIRED, v->get());
        }
        break;
    case V4_0::Tag::USER_AUTH_TYPE:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_USER_AUTH_TYPE, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_USER_AUTH_TYPE, convert(v->get()));
        }
        break;
    case V4_0::Tag::AUTH_TIMEOUT:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_AUTH_TIMEOUT, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_AUTH_TIMEOUT, v->get());
        }
        break;
    case V4_0::Tag::ALLOW_WHILE_ON_BODY:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_ALLOW_WHILE_ON_BODY, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ALLOW_WHILE_ON_BODY, v->get());
        }
        break;
    case V4_0::Tag::TRUSTED_USER_PRESENCE_REQUIRED:
        if (auto v =
                unwrapper(V4_0::authorizationValue(V4_0::TAG_TRUSTED_USER_PRESENCE_REQUIRED, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_TRUSTED_USER_PRESENCE_REQUIRED, v->get());
        }
        break;
    case V4_0::Tag::TRUSTED_CONFIRMATION_REQUIRED:
        if (auto v =
                unwrapper(V4_0::authorizationValue(V4_0::TAG_TRUSTED_CONFIRMATION_REQUIRED, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_TRUSTED_CONFIRMATION_REQUIRED, v->get());
        }
        break;
    case V4_0::Tag::UNLOCKED_DEVICE_REQUIRED:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_UNLOCKED_DEVICE_REQUIRED, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_UNLOCKED_DEVICE_REQUIRED, v->get());
        }
        break;
    case V4_0::Tag::APPLICATION_ID:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_APPLICATION_ID, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_APPLICATION_ID, v->get());
        }
        break;
    case V4_0::Tag::APPLICATION_DATA:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_APPLICATION_DATA, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_APPLICATION_DATA, v->get());
        }
        break;
    case V4_0::Tag::CREATION_DATETIME:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_CREATION_DATETIME, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_CREATION_DATETIME, v->get());
        }
        break;
    case V4_0::Tag::ORIGIN:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_ORIGIN, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ORIGIN, convert(v->get()));
        }
        break;
    case V4_0::Tag::ROOT_OF_TRUST:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_ROOT_OF_TRUST, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ROOT_OF_TRUST, v->get());
        }
        break;
    case V4_0::Tag::OS_VERSION:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_OS_VERSION, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_OS_VERSION, v->get());
        }
        break;
    case V4_0::Tag::OS_PATCHLEVEL:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_OS_PATCHLEVEL, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_OS_PATCHLEVEL, v->get());
        }
        break;
    case V4_0::Tag::UNIQUE_ID:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_UNIQUE_ID, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_UNIQUE_ID, v->get());
        }
        break;
    case V4_0::Tag::ATTESTATION_CHALLENGE:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_ATTESTATION_CHALLENGE, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ATTESTATION_CHALLENGE, v->get());
        }
        break;
    case V4_0::Tag::ATTESTATION_APPLICATION_ID:
        if (auto v =
                unwrapper(V4_0::authorizationValue(V4_0::TAG_ATTESTATION_APPLICATION_ID, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ATTESTATION_APPLICATION_ID, v->get());
        }
        break;
    case V4_0::Tag::ATTESTATION_ID_BRAND:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_ATTESTATION_ID_BRAND, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ATTESTATION_ID_BRAND, v->get());
        }
        break;
    case V4_0::Tag::ATTESTATION_ID_DEVICE:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_ATTESTATION_ID_DEVICE, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ATTESTATION_ID_DEVICE, v->get());
        }
        break;
    case V4_0::Tag::ATTESTATION_ID_PRODUCT:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_ATTESTATION_ID_PRODUCT, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ATTESTATION_ID_PRODUCT, v->get());
        }
        break;
    case V4_0::Tag::ATTESTATION_ID_SERIAL:
        // TODO This tag is missing from 4.0 keymaster_tags.h
        break;
    case V4_0::Tag::ATTESTATION_ID_IMEI:
        // TODO This tag is missing from 4.0 keymaster_tags.h
        break;
    case V4_0::Tag::ATTESTATION_ID_MEID:
        // TODO This tag is missing from 4.0 keymaster_tags.h
        break;
    case V4_0::Tag::ATTESTATION_ID_MANUFACTURER:
        if (auto v =
                unwrapper(V4_0::authorizationValue(V4_0::TAG_ATTESTATION_ID_MANUFACTURER, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ATTESTATION_ID_MANUFACTURER, v->get());
        }
        break;
    case V4_0::Tag::ATTESTATION_ID_MODEL:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_ATTESTATION_ID_MODEL, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ATTESTATION_ID_MODEL, v->get());
        }
        break;
    case V4_0::Tag::VENDOR_PATCHLEVEL:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_VENDOR_PATCHLEVEL, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_VENDOR_PATCHLEVEL, v->get());
        }
        break;
    case V4_0::Tag::BOOT_PATCHLEVEL:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_BOOT_PATCHLEVEL, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_BOOT_PATCHLEVEL, v->get());
        }
        break;
    case V4_0::Tag::ASSOCIATED_DATA:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_ASSOCIATED_DATA, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_ASSOCIATED_DATA, v->get());
        }
        break;
    case V4_0::Tag::NONCE:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_NONCE, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_NONCE, v->get());
        }
        break;
    case V4_0::Tag::MAC_LENGTH:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_MAC_LENGTH, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_MAC_LENGTH, v->get());
        }
        break;
    case V4_0::Tag::RESET_SINCE_ID_ROTATION:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_RESET_SINCE_ID_ROTATION, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_RESET_SINCE_ID_ROTATION, v->get());
        }
        break;
    case V4_0::Tag::CONFIRMATION_TOKEN:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_0::TAG_CONFIRMATION_TOKEN, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_CONFIRMATION_TOKEN, v->get());
        }
        break;
    default:
        break;
    }

    switch (static_cast<V4_1::Tag>(kp.tag)) {
    case V4_1::Tag::EARLY_BOOT_ONLY:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_1::TAG_EARLY_BOOT_ONLY, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_EARLY_BOOT_ONLY, v->get());
        }
        break;
    case V4_1::Tag::DEVICE_UNIQUE_ATTESTATION:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_1::TAG_DEVICE_UNIQUE_ATTESTATION, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_DEVICE_UNIQUE_ATTESTATION, v->get());
        }
        break;
    case V4_1::Tag::IDENTITY_CREDENTIAL_KEY:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_1::TAG_IDENTITY_CREDENTIAL_KEY, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_IDENTITY_CREDENTIAL_KEY, v->get());
        }
        break;
    case V4_1::Tag::STORAGE_KEY:
        if (auto v = unwrapper(V4_0::authorizationValue(V4_1::TAG_STORAGE_KEY, kp))) {
            return KMV1::makeKeyParameter(KMV1::TAG_STORAGE_KEY, v->get());
        }
        break;
    default:
        break;
    }

    return KMV1::makeKeyParameter(KMV1::TAG_INVALID);
}
