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

#include "km_compat.h"

#include "km_compat_type_conversion.h"
#include <aidl/android/hardware/security/keymint/Algorithm.h>
#include <aidl/android/hardware/security/keymint/Digest.h>
#include <aidl/android/hardware/security/keymint/ErrorCode.h>
#include <aidl/android/hardware/security/keymint/PaddingMode.h>
#include <aidl/android/system/keystore2/ResponseCode.h>
#include <android-base/logging.h>
#include <android/hidl/manager/1.2/IServiceManager.h>
#include <binder/IServiceManager.h>
#include <hardware/keymaster_defs.h>
#include <keymasterV4_1/Keymaster.h>
#include <keymasterV4_1/Keymaster3.h>
#include <keymasterV4_1/Keymaster4.h>

#include <chrono>

#include "certificate_utils.h"

using ::aidl::android::hardware::security::keymint::Algorithm;
using ::aidl::android::hardware::security::keymint::Digest;
using ::aidl::android::hardware::security::keymint::PaddingMode;
using ::aidl::android::hardware::security::keymint::Tag;
using ::aidl::android::system::keystore2::ResponseCode;
using ::android::hardware::hidl_vec;
using ::android::hardware::keymaster::V4_0::TagType;
using ::android::hidl::manager::V1_2::IServiceManager;
using V4_0_HardwareAuthToken = ::android::hardware::keymaster::V4_0::HardwareAuthToken;
using V4_0_HmacSharingParameters = ::android::hardware::keymaster::V4_0::HmacSharingParameters;
using V4_0_KeyCharacteristics = ::android::hardware::keymaster::V4_0::KeyCharacteristics;
using V4_0_KeyFormat = ::android::hardware::keymaster::V4_0::KeyFormat;
using V4_0_KeyParameter = ::android::hardware::keymaster::V4_0::KeyParameter;
using V4_0_VerificationToken = ::android::hardware::keymaster::V4_0::VerificationToken;
namespace V4_0 = ::android::hardware::keymaster::V4_0;
namespace V4_1 = ::android::hardware::keymaster::V4_1;
namespace KMV1 = ::aidl::android::hardware::security::keymint;

using namespace std::chrono_literals;
using std::chrono::duration_cast;

// Utility functions

// Returns true if this parameter may be passed to attestKey.
bool isAttestationParameter(const KMV1::KeyParameter& param) {
    switch (param.tag) {
    case Tag::APPLICATION_ID:
    case Tag::APPLICATION_DATA:
    case Tag::ATTESTATION_CHALLENGE:
    case Tag::ATTESTATION_APPLICATION_ID:
    case Tag::ATTESTATION_ID_BRAND:
    case Tag::ATTESTATION_ID_DEVICE:
    case Tag::ATTESTATION_ID_PRODUCT:
    case Tag::ATTESTATION_ID_SERIAL:
    case Tag::ATTESTATION_ID_IMEI:
    case Tag::ATTESTATION_ID_MEID:
    case Tag::ATTESTATION_ID_MANUFACTURER:
    case Tag::ATTESTATION_ID_MODEL:
    case Tag::CERTIFICATE_SERIAL:
    case Tag::CERTIFICATE_SUBJECT:
    case Tag::CERTIFICATE_NOT_BEFORE:
    case Tag::CERTIFICATE_NOT_AFTER:
    case Tag::INCLUDE_UNIQUE_ID:
    case Tag::DEVICE_UNIQUE_ATTESTATION:
        return true;
    default:
        return false;
    }
}

// Returns true if this parameter may be passed to generate/importKey.
bool isKeyCreationParameter(const KMV1::KeyParameter& param) {
    switch (param.tag) {
    case Tag::APPLICATION_ID:
    case Tag::APPLICATION_DATA:
    case Tag::CERTIFICATE_SERIAL:
    case Tag::CERTIFICATE_SUBJECT:
    case Tag::CERTIFICATE_NOT_BEFORE:
    case Tag::CERTIFICATE_NOT_AFTER:
    case Tag::PURPOSE:
    case Tag::ALGORITHM:
    case Tag::KEY_SIZE:
    case Tag::BLOCK_MODE:
    case Tag::DIGEST:
    case Tag::PADDING:
    case Tag::CALLER_NONCE:
    case Tag::MIN_MAC_LENGTH:
    case Tag::EC_CURVE:
    case Tag::RSA_PUBLIC_EXPONENT:
    case Tag::RSA_OAEP_MGF_DIGEST:
    case Tag::BLOB_USAGE_REQUIREMENTS:
    case Tag::BOOTLOADER_ONLY:
    case Tag::ROLLBACK_RESISTANCE:
    case Tag::EARLY_BOOT_ONLY:
    case Tag::ACTIVE_DATETIME:
    case Tag::ORIGINATION_EXPIRE_DATETIME:
    case Tag::USAGE_EXPIRE_DATETIME:
    case Tag::MIN_SECONDS_BETWEEN_OPS:
    case Tag::MAX_USES_PER_BOOT:
    case Tag::USAGE_COUNT_LIMIT:
    case Tag::USER_ID:
    case Tag::USER_SECURE_ID:
    case Tag::NO_AUTH_REQUIRED:
    case Tag::USER_AUTH_TYPE:
    case Tag::AUTH_TIMEOUT:
    case Tag::ALLOW_WHILE_ON_BODY:
    case Tag::TRUSTED_USER_PRESENCE_REQUIRED:
    case Tag::TRUSTED_CONFIRMATION_REQUIRED:
    case Tag::UNLOCKED_DEVICE_REQUIRED:
    case Tag::CREATION_DATETIME:
    case Tag::UNIQUE_ID:
    case Tag::IDENTITY_CREDENTIAL_KEY:
    case Tag::STORAGE_KEY:
    case Tag::MAC_LENGTH:
        return true;
    default:
        return false;
    }
}

/*
 * Returns true if the parameter is not understood by KM 4.1 and older but can be enforced by
 * Keystore. These parameters need to be included in the returned KeyCharacteristics, but will not
 * be passed to the legacy backend.
 */
bool isNewAndKeystoreEnforceable(const KMV1::KeyParameter& param) {
    switch (param.tag) {
    case KMV1::Tag::USAGE_COUNT_LIMIT:
        return true;
    default:
        return false;
    }
}

std::vector<KMV1::KeyParameter>
extractGenerationParams(const std::vector<KMV1::KeyParameter>& params) {
    std::vector<KMV1::KeyParameter> result;
    std::copy_if(params.begin(), params.end(), std::back_inserter(result), isKeyCreationParameter);
    return result;
}

std::vector<KMV1::KeyParameter>
extractAttestationParams(const std::vector<KMV1::KeyParameter>& params) {
    std::vector<KMV1::KeyParameter> result;
    std::copy_if(params.begin(), params.end(), std::back_inserter(result), isAttestationParameter);
    return result;
}

std::vector<KMV1::KeyParameter>
extractNewAndKeystoreEnforceableParams(const std::vector<KMV1::KeyParameter>& params) {
    std::vector<KMV1::KeyParameter> result;
    std::copy_if(params.begin(), params.end(), std::back_inserter(result),
                 isNewAndKeystoreEnforceable);
    return result;
}

ScopedAStatus convertErrorCode(KMV1::ErrorCode result) {
    if (result == KMV1::ErrorCode::OK) {
        return ScopedAStatus::ok();
    }
    return ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(result));
}

// Converts a V4 error code into a ScopedAStatus
ScopedAStatus convertErrorCode(V4_0_ErrorCode result) {
    return convertErrorCode(convert(result));
}

static KMV1::ErrorCode toErrorCode(const ScopedAStatus& status) {
    if (status.getExceptionCode() == EX_SERVICE_SPECIFIC) {
        return static_cast<KMV1::ErrorCode>(status.getServiceSpecificError());
    } else {
        return KMV1::ErrorCode::UNKNOWN_ERROR;
    }
}

static std::vector<V4_0::KeyParameter>
convertKeyParametersToLegacy(const std::vector<KeyParameter>& kps) {
    std::vector<V4_0::KeyParameter> legacyKps;
    legacyKps.reserve(kps.size());
    for (const auto& kp : kps) {
        auto p = convertKeyParameterToLegacy(kp);
        if (p.tag != V4_0::Tag::INVALID) {
            legacyKps.push_back(std::move(p));
        }
    }
    return legacyKps;
}

static std::vector<KeyParameter>
convertKeyParametersFromLegacy(const std::vector<V4_0_KeyParameter>& legacyKps) {
    std::vector<KeyParameter> kps(legacyKps.size());
    std::transform(legacyKps.begin(), legacyKps.end(), kps.begin(), convertKeyParameterFromLegacy);
    return kps;
}

static std::vector<KeyCharacteristics>
processLegacyCharacteristics(KeyMintSecurityLevel securityLevel,
                             const std::vector<KeyParameter>& genParams,
                             const V4_0_KeyCharacteristics& legacyKc) {

    KeyCharacteristics keystoreEnforced{KeyMintSecurityLevel::KEYSTORE,
                                        convertKeyParametersFromLegacy(legacyKc.softwareEnforced)};

    // Add all parameters that we know can be enforced by keystore but not by the legacy backend.
    auto unsupported_requested = extractNewAndKeystoreEnforceableParams(genParams);
    std::copy(unsupported_requested.begin(), unsupported_requested.end(),
              std::back_insert_iterator(keystoreEnforced.authorizations));

    if (securityLevel == KeyMintSecurityLevel::SOFTWARE) {
        // If the security level of the backend is `software` we expect the hardware enforced list
        // to be empty. Log a warning otherwise.
        CHECK(legacyKc.hardwareEnforced.size() == 0);
        return {keystoreEnforced};
    }

    KeyCharacteristics hwEnforced{securityLevel,
                                  convertKeyParametersFromLegacy(legacyKc.hardwareEnforced)};
    return {hwEnforced, keystoreEnforced};
}

static V4_0_KeyFormat convertKeyFormatToLegacy(const KeyFormat& kf) {
    return static_cast<V4_0_KeyFormat>(kf);
}

static V4_0_HardwareAuthToken convertAuthTokenToLegacy(const HardwareAuthToken& at) {
    V4_0_HardwareAuthToken legacyAt;
    legacyAt.challenge = at.challenge;
    legacyAt.userId = at.userId;
    legacyAt.authenticatorId = at.authenticatorId;
    legacyAt.authenticatorType =
        static_cast<::android::hardware::keymaster::V4_0::HardwareAuthenticatorType>(
            at.authenticatorType);
    legacyAt.timestamp = at.timestamp.milliSeconds;
    legacyAt.mac = at.mac;
    return legacyAt;
}

static V4_0_VerificationToken convertTimestampTokenToLegacy(const TimeStampToken& tst) {
    V4_0_VerificationToken legacyVt;
    legacyVt.challenge = tst.challenge;
    legacyVt.timestamp = tst.timestamp.milliSeconds;
    // Legacy verification tokens were always minted by TEE.
    legacyVt.securityLevel = V4_0::SecurityLevel::TRUSTED_ENVIRONMENT;
    legacyVt.mac = tst.mac;
    return legacyVt;
}

static V4_0_HmacSharingParameters
convertSharedSecretParameterToLegacy(const SharedSecretParameters& ssp) {
    V4_0_HmacSharingParameters legacyHsp;
    legacyHsp.seed = ssp.seed;
    std::copy(ssp.nonce.begin(), ssp.nonce.end(), legacyHsp.nonce.data());
    return legacyHsp;
}

static std::vector<V4_0_HmacSharingParameters>
convertSharedSecretParametersToLegacy(const std::vector<SharedSecretParameters>& legacySsps) {
    std::vector<V4_0_HmacSharingParameters> ssps(legacySsps.size());
    std::transform(legacySsps.begin(), legacySsps.end(), ssps.begin(),
                   convertSharedSecretParameterToLegacy);
    return ssps;
}

void OperationSlots::setNumFreeSlots(uint8_t numFreeSlots) {
    std::lock_guard<std::mutex> lock(mNumFreeSlotsMutex);
    mNumFreeSlots = numFreeSlots;
}

bool OperationSlots::claimSlot() {
    std::lock_guard<std::mutex> lock(mNumFreeSlotsMutex);
    if (mNumFreeSlots > 0) {
        mNumFreeSlots--;
        return true;
    }
    return false;
}

void OperationSlots::freeSlot() {
    std::lock_guard<std::mutex> lock(mNumFreeSlotsMutex);
    mNumFreeSlots++;
}

void OperationSlot::freeSlot() {
    if (mIsActive) {
        mOperationSlots->freeSlot();
        mIsActive = false;
    }
}

// KeyMintDevice implementation

ScopedAStatus KeyMintDevice::getHardwareInfo(KeyMintHardwareInfo* _aidl_return) {
    // TODO: What do I do about the version number?  Is it the version of the device I get?
    auto result = mDevice->getHardwareInfo([&](auto securityLevel, const auto& keymasterName,
                                               const auto& keymasterAuthorName) {
        securityLevel_ =
            static_cast<::aidl::android::hardware::security::keymint::SecurityLevel>(securityLevel);

        _aidl_return->securityLevel = securityLevel_;
        _aidl_return->keyMintName = keymasterName;
        _aidl_return->keyMintAuthorName = keymasterAuthorName;
    });
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        return convertErrorCode(KMV1::ErrorCode::UNKNOWN_ERROR);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus KeyMintDevice::addRngEntropy(const std::vector<uint8_t>& in_data) {
    auto result = mDevice->addRngEntropy(in_data);
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        return convertErrorCode(KMV1::ErrorCode::UNKNOWN_ERROR);
    }
    return convertErrorCode(result);
}

ScopedAStatus KeyMintDevice::generateKey(const std::vector<KeyParameter>& inKeyParams,
                                         KeyCreationResult* out_creationResult) {
    auto legacyKeyGenParams = convertKeyParametersToLegacy(extractGenerationParams(inKeyParams));
    KMV1::ErrorCode errorCode;
    auto result = mDevice->generateKey(
        legacyKeyGenParams, [&](V4_0_ErrorCode error, const hidl_vec<uint8_t>& keyBlob,
                                const V4_0_KeyCharacteristics& keyCharacteristics) {
            errorCode = convert(error);
            out_creationResult->keyBlob = keyBlob;
            out_creationResult->keyCharacteristics =
                processLegacyCharacteristics(securityLevel_, inKeyParams, keyCharacteristics);
        });
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        return convertErrorCode(KMV1::ErrorCode::UNKNOWN_ERROR);
    }
    if (errorCode == KMV1::ErrorCode::OK) {
        auto cert = getCertificate(inKeyParams, out_creationResult->keyBlob);
        if (std::holds_alternative<KMV1::ErrorCode>(cert)) {
            auto code = std::get<KMV1::ErrorCode>(cert);
            // We return OK in successful cases that do not generate a certificate.
            if (code != KMV1::ErrorCode::OK) {
                errorCode = code;
                deleteKey(out_creationResult->keyBlob);
            }
        } else {
            out_creationResult->certificateChain = std::get<std::vector<Certificate>>(cert);
        }
    }
    return convertErrorCode(errorCode);
}

ScopedAStatus KeyMintDevice::importKey(const std::vector<KeyParameter>& inKeyParams,
                                       KeyFormat in_inKeyFormat,
                                       const std::vector<uint8_t>& in_inKeyData,
                                       KeyCreationResult* out_creationResult) {
    auto legacyKeyGENParams = convertKeyParametersToLegacy(extractGenerationParams(inKeyParams));
    auto legacyKeyFormat = convertKeyFormatToLegacy(in_inKeyFormat);
    KMV1::ErrorCode errorCode;
    auto result = mDevice->importKey(legacyKeyGENParams, legacyKeyFormat, in_inKeyData,
                                     [&](V4_0_ErrorCode error, const hidl_vec<uint8_t>& keyBlob,
                                         const V4_0_KeyCharacteristics& keyCharacteristics) {
                                         errorCode = convert(error);
                                         out_creationResult->keyBlob = keyBlob;
                                         out_creationResult->keyCharacteristics =
                                             processLegacyCharacteristics(
                                                 securityLevel_, inKeyParams, keyCharacteristics);
                                     });
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        return convertErrorCode(KMV1::ErrorCode::UNKNOWN_ERROR);
    }
    if (errorCode == KMV1::ErrorCode::OK) {
        auto cert = getCertificate(inKeyParams, out_creationResult->keyBlob);
        if (std::holds_alternative<KMV1::ErrorCode>(cert)) {
            auto code = std::get<KMV1::ErrorCode>(cert);
            // We return OK in successful cases that do not generate a certificate.
            if (code != KMV1::ErrorCode::OK) {
                errorCode = code;
                deleteKey(out_creationResult->keyBlob);
            }
        } else {
            out_creationResult->certificateChain = std::get<std::vector<Certificate>>(cert);
        }
    }
    return convertErrorCode(errorCode);
}

ScopedAStatus KeyMintDevice::importWrappedKey(
    const std::vector<uint8_t>& in_inWrappedKeyData,
    const std::vector<uint8_t>& in_inWrappingKeyBlob, const std::vector<uint8_t>& in_inMaskingKey,
    const std::vector<KeyParameter>& in_inUnwrappingParams, int64_t in_inPasswordSid,
    int64_t in_inBiometricSid, KeyCreationResult* out_creationResult) {
    auto legacyUnwrappingParams = convertKeyParametersToLegacy(in_inUnwrappingParams);
    KMV1::ErrorCode errorCode;
    auto result = mDevice->importWrappedKey(
        in_inWrappedKeyData, in_inWrappingKeyBlob, in_inMaskingKey, legacyUnwrappingParams,
        in_inPasswordSid, in_inBiometricSid,
        [&](V4_0_ErrorCode error, const hidl_vec<uint8_t>& keyBlob,
            const V4_0_KeyCharacteristics& keyCharacteristics) {
            errorCode = convert(error);
            out_creationResult->keyBlob = keyBlob;
            out_creationResult->keyCharacteristics =
                processLegacyCharacteristics(securityLevel_, {}, keyCharacteristics);
        });
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        return convertErrorCode(KMV1::ErrorCode::UNKNOWN_ERROR);
    }
    return convertErrorCode(errorCode);
}

ScopedAStatus KeyMintDevice::upgradeKey(const std::vector<uint8_t>& in_inKeyBlobToUpgrade,
                                        const std::vector<KeyParameter>& in_inUpgradeParams,
                                        std::vector<uint8_t>* _aidl_return) {
    auto legacyUpgradeParams = convertKeyParametersToLegacy(in_inUpgradeParams);
    V4_0_ErrorCode errorCode;
    auto result =
        mDevice->upgradeKey(in_inKeyBlobToUpgrade, legacyUpgradeParams,
                            [&](V4_0_ErrorCode error, const hidl_vec<uint8_t>& upgradedKeyBlob) {
                                errorCode = error;
                                *_aidl_return = upgradedKeyBlob;
                            });
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        return convertErrorCode(KMV1::ErrorCode::UNKNOWN_ERROR);
    }
    return convertErrorCode(errorCode);
}

ScopedAStatus KeyMintDevice::deleteKey(const std::vector<uint8_t>& in_inKeyBlob) {
    auto result = mDevice->deleteKey(in_inKeyBlob);
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        return convertErrorCode(KMV1::ErrorCode::UNKNOWN_ERROR);
    }
    return convertErrorCode(result);
}

ScopedAStatus KeyMintDevice::deleteAllKeys() {
    auto result = mDevice->deleteAllKeys();
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        return convertErrorCode(KMV1::ErrorCode::UNKNOWN_ERROR);
    }
    return convertErrorCode(result);
}

// We're not implementing this.
ScopedAStatus KeyMintDevice::destroyAttestationIds() {
    return ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(V4_0_ErrorCode::UNIMPLEMENTED));
}

ScopedAStatus KeyMintDevice::begin(KeyPurpose in_inPurpose,
                                   const std::vector<uint8_t>& in_inKeyBlob,
                                   const std::vector<KeyParameter>& in_inParams,
                                   const HardwareAuthToken& in_inAuthToken,
                                   BeginResult* _aidl_return) {
    if (!mOperationSlots.claimSlot()) {
        return convertErrorCode(V4_0_ErrorCode::TOO_MANY_OPERATIONS);
    }
    auto legacyPurpose =
        static_cast<::android::hardware::keymaster::V4_0::KeyPurpose>(in_inPurpose);
    auto legacyParams = convertKeyParametersToLegacy(in_inParams);
    auto legacyAuthToken = convertAuthTokenToLegacy(in_inAuthToken);
    KMV1::ErrorCode errorCode;
    auto result = mDevice->begin(
        legacyPurpose, in_inKeyBlob, legacyParams, legacyAuthToken,
        [&](V4_0_ErrorCode error, const hidl_vec<V4_0_KeyParameter>& outParams,
            uint64_t operationHandle) {
            errorCode = convert(error);
            _aidl_return->challenge = operationHandle;
            _aidl_return->params = convertKeyParametersFromLegacy(outParams);
            _aidl_return->operation = ndk::SharedRefBase::make<KeyMintOperation>(
                mDevice, operationHandle, &mOperationSlots, error == V4_0_ErrorCode::OK);
        });
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        errorCode = KMV1::ErrorCode::UNKNOWN_ERROR;
    }
    if (errorCode != KMV1::ErrorCode::OK) {
        mOperationSlots.freeSlot();
    }
    return convertErrorCode(errorCode);
}

ScopedAStatus KeyMintOperation::update(const std::optional<KeyParameterArray>& in_inParams,
                                       const std::optional<std::vector<uint8_t>>& in_input,
                                       const std::optional<HardwareAuthToken>& in_inAuthToken,
                                       const std::optional<TimeStampToken>& in_inTimeStampToken,
                                       std::optional<KeyParameterArray>* out_outParams,
                                       std::optional<ByteArray>* out_output,
                                       int32_t* _aidl_return) {
    std::vector<V4_0_KeyParameter> legacyParams;
    if (in_inParams.has_value()) {
        legacyParams = convertKeyParametersToLegacy(in_inParams.value().params);
    }
    auto input = in_input.value_or(std::vector<uint8_t>());
    V4_0_HardwareAuthToken authToken;
    if (in_inAuthToken.has_value()) {
        authToken = convertAuthTokenToLegacy(in_inAuthToken.value());
    }
    V4_0_VerificationToken verificationToken;
    if (in_inTimeStampToken.has_value()) {
        verificationToken = convertTimestampTokenToLegacy(in_inTimeStampToken.value());
    }

    KMV1::ErrorCode errorCode;
    auto result = mDevice->update(
        mOperationHandle, legacyParams, input, authToken, verificationToken,
        [&](V4_0_ErrorCode error, uint32_t inputConsumed,
            const hidl_vec<V4_0_KeyParameter>& outParams, const hidl_vec<uint8_t>& output) {
            errorCode = convert(error);
            out_outParams->emplace();
            out_outParams->value().params = convertKeyParametersFromLegacy(outParams);
            out_output->emplace();
            out_output->value().data = output;
            *_aidl_return = inputConsumed;
        });

    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        errorCode = KMV1::ErrorCode::UNKNOWN_ERROR;
    }
    if (errorCode != KMV1::ErrorCode::OK) {
        mOperationSlot.freeSlot();
    }
    return convertErrorCode(errorCode);
}

ScopedAStatus KeyMintOperation::finish(const std::optional<KeyParameterArray>& in_inParams,
                                       const std::optional<std::vector<uint8_t>>& in_input,
                                       const std::optional<std::vector<uint8_t>>& in_inSignature,
                                       const std::optional<HardwareAuthToken>& in_authToken,
                                       const std::optional<TimeStampToken>& in_inTimeStampToken,
                                       std::optional<KeyParameterArray>* out_outParams,
                                       std::vector<uint8_t>* _aidl_return) {
    KMV1::ErrorCode errorCode;
    std::vector<V4_0_KeyParameter> legacyParams;
    if (in_inParams.has_value()) {
        legacyParams = convertKeyParametersToLegacy(in_inParams.value().params);
    }
    auto input = in_input.value_or(std::vector<uint8_t>());
    auto signature = in_inSignature.value_or(std::vector<uint8_t>());
    V4_0_HardwareAuthToken authToken;
    if (in_authToken.has_value()) {
        authToken = convertAuthTokenToLegacy(in_authToken.value());
    }
    V4_0_VerificationToken verificationToken;
    if (in_inTimeStampToken.has_value()) {
        verificationToken = convertTimestampTokenToLegacy(in_inTimeStampToken.value());
    }
    auto result = mDevice->finish(
        mOperationHandle, legacyParams, input, signature, authToken, verificationToken,
        [&](V4_0_ErrorCode error, const hidl_vec<V4_0_KeyParameter>& outParams,
            const hidl_vec<uint8_t>& output) {
            errorCode = convert(error);
            out_outParams->emplace();
            out_outParams->value().params = convertKeyParametersFromLegacy(outParams);
            *_aidl_return = output;
        });
    mOperationSlot.freeSlot();
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        errorCode = KMV1::ErrorCode::UNKNOWN_ERROR;
    }
    return convertErrorCode(errorCode);
}

ScopedAStatus KeyMintOperation::abort() {
    auto result = mDevice->abort(mOperationHandle);
    mOperationSlot.freeSlot();
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        return convertErrorCode(KMV1::ErrorCode::UNKNOWN_ERROR);
    }
    return convertErrorCode(result);
}

KeyMintOperation::~KeyMintOperation() {
    if (mOperationSlot.hasSlot()) {
        auto error = abort();
        if (!error.isOk()) {
            LOG(WARNING) << "Error calling abort in ~KeyMintOperation: " << error.getMessage();
        }
    }
}

// SecureClock implementation

ScopedAStatus SecureClock::generateTimeStamp(int64_t in_challenge, TimeStampToken* _aidl_return) {
    KMV1::ErrorCode errorCode;
    auto result = mDevice->verifyAuthorization(
        in_challenge, {}, V4_0_HardwareAuthToken(),
        [&](V4_0_ErrorCode error, const V4_0_VerificationToken& token) {
            errorCode = convert(error);
            _aidl_return->challenge = token.challenge;
            _aidl_return->timestamp.milliSeconds = token.timestamp;
            _aidl_return->mac = token.mac;
        });
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        errorCode = KMV1::ErrorCode::UNKNOWN_ERROR;
    }
    return convertErrorCode(errorCode);
}

// SharedSecret implementation

ScopedAStatus SharedSecret::getSharedSecretParameters(SharedSecretParameters* _aidl_return) {
    KMV1::ErrorCode errorCode;
    auto result = mDevice->getHmacSharingParameters(
        [&](V4_0_ErrorCode error, const V4_0_HmacSharingParameters& params) {
            errorCode = convert(error);
            _aidl_return->seed = params.seed;
            std::copy(params.nonce.data(), params.nonce.data() + params.nonce.elementCount(),
                      std::back_inserter(_aidl_return->nonce));
        });
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        errorCode = KMV1::ErrorCode::UNKNOWN_ERROR;
    }
    return convertErrorCode(errorCode);
}

ScopedAStatus
SharedSecret::computeSharedSecret(const std::vector<SharedSecretParameters>& in_params,
                                  std::vector<uint8_t>* _aidl_return) {
    KMV1::ErrorCode errorCode;
    auto legacyParams = convertSharedSecretParametersToLegacy(in_params);
    auto result = mDevice->computeSharedHmac(
        legacyParams, [&](V4_0_ErrorCode error, const hidl_vec<uint8_t>& sharingCheck) {
            errorCode = convert(error);
            *_aidl_return = sharingCheck;
        });
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " transaction failed. " << result.description();
        errorCode = KMV1::ErrorCode::UNKNOWN_ERROR;
    }
    return convertErrorCode(errorCode);
}

// Certificate implementation

template <KMV1::Tag tag, KMV1::TagType type>
static auto getParam(const std::vector<KeyParameter>& keyParams, KMV1::TypedTag<type, tag> ttag)
    -> decltype(authorizationValue(ttag, KeyParameter())) {
    for (const auto& p : keyParams) {

        if (auto v = authorizationValue(ttag, p)) {
            return v;
        }
    }
    return {};
}

template <typename T>
static bool containsParam(const std::vector<KeyParameter>& keyParams, T ttag) {
    return static_cast<bool>(getParam(keyParams, ttag));
}

// Prefer the smallest.
// If no options are found, return the first.
template <typename T>
static typename KMV1::TypedTag2ValueType<T>::type
getMaximum(const std::vector<KeyParameter>& keyParams, T tag,
           std::vector<typename KMV1::TypedTag2ValueType<T>::type> sortedOptions) {
    auto bestSoFar = sortedOptions.end();
    for (const KeyParameter& kp : keyParams) {
        if (auto value = authorizationValue(tag, kp)) {
            auto candidate = std::find(sortedOptions.begin(), sortedOptions.end(), *value);
            // sortedOptions is sorted from best to worst. `std::distance(first, last)` counts the
            // hops from `first` to `last`. So a better `candidate` yields a positive distance to
            // `bestSoFar`.
            if (std::distance(candidate, bestSoFar) > 0) {
                bestSoFar = candidate;
            }
        }
    }
    if (bestSoFar == sortedOptions.end()) {
        return sortedOptions[0];
    }
    return *bestSoFar;
}

static std::variant<keystore::X509_Ptr, KMV1::ErrorCode>
makeCert(::android::sp<Keymaster> mDevice, const std::vector<KeyParameter>& keyParams,
         const std::vector<uint8_t>& keyBlob) {
    // Start generating the certificate.
    // Get public key for makeCert.
    KMV1::ErrorCode errorCode;
    std::vector<uint8_t> key;
    static std::vector<uint8_t> empty_vector;
    auto unwrapBlob = [&](auto b) -> const std::vector<uint8_t>& {
        if (b)
            return *b;
        else
            return empty_vector;
    };
    auto result = mDevice->exportKey(
        V4_0_KeyFormat::X509, keyBlob, unwrapBlob(getParam(keyParams, KMV1::TAG_APPLICATION_ID)),
        unwrapBlob(getParam(keyParams, KMV1::TAG_APPLICATION_DATA)),
        [&](V4_0_ErrorCode error, const hidl_vec<uint8_t>& keyMaterial) {
            errorCode = convert(error);
            key = keyMaterial;
        });
    if (!result.isOk()) {
        LOG(ERROR) << __func__ << " exportKey transaction failed. " << result.description();
        return KMV1::ErrorCode::UNKNOWN_ERROR;
    }
    if (errorCode != KMV1::ErrorCode::OK) {
        return errorCode;
    }
    // Get pkey for makeCert.
    CBS cbs;
    CBS_init(&cbs, key.data(), key.size());
    auto pkey = EVP_parse_public_key(&cbs);

    // makeCert
    std::optional<std::reference_wrapper<const std::vector<uint8_t>>> subject;
    if (auto blob = getParam(keyParams, KMV1::TAG_CERTIFICATE_SUBJECT)) {
        subject = *blob;
    }

    std::optional<std::reference_wrapper<const std::vector<uint8_t>>> serial;
    if (auto blob = getParam(keyParams, KMV1::TAG_CERTIFICATE_SERIAL)) {
        serial = *blob;
    }

    int64_t activation;
    if (auto date = getParam(keyParams, KMV1::TAG_CERTIFICATE_NOT_BEFORE)) {
        activation = static_cast<int64_t>(*date);
    } else {
        return KMV1::ErrorCode::MISSING_NOT_BEFORE;
    }

    int64_t expiration;
    if (auto date = getParam(keyParams, KMV1::TAG_CERTIFICATE_NOT_AFTER)) {
        expiration = static_cast<int64_t>(*date);
    } else {
        return KMV1::ErrorCode::MISSING_NOT_AFTER;
    }

    auto certOrError = keystore::makeCert(
        pkey, serial, subject, activation, expiration, false /* intentionally left blank */,
        std::nullopt /* intentionally left blank */, std::nullopt /* intentionally left blank */);
    if (std::holds_alternative<keystore::CertUtilsError>(certOrError)) {
        LOG(ERROR) << __func__ << ": Failed to make certificate";
        return KMV1::ErrorCode::UNKNOWN_ERROR;
    }
    return std::move(std::get<keystore::X509_Ptr>(certOrError));
}

static std::variant<keystore::Algo, KMV1::ErrorCode> getKeystoreAlgorithm(Algorithm algorithm) {
    switch (algorithm) {
    case Algorithm::RSA:
        return keystore::Algo::RSA;
    case Algorithm::EC:
        return keystore::Algo::ECDSA;
    default:
        LOG(ERROR) << __func__ << ": This should not be called with symmetric algorithm.";
        return KMV1::ErrorCode::UNKNOWN_ERROR;
    }
}

static std::variant<keystore::Padding, KMV1::ErrorCode> getKeystorePadding(PaddingMode padding) {
    switch (padding) {
    case PaddingMode::RSA_PKCS1_1_5_SIGN:
        return keystore::Padding::PKCS1_5;
    case PaddingMode::RSA_PSS:
        return keystore::Padding::PSS;
    default:
        return keystore::Padding::Ignored;
    }
}

static std::variant<keystore::Digest, KMV1::ErrorCode> getKeystoreDigest(Digest digest) {
    switch (digest) {
    case Digest::SHA1:
        return keystore::Digest::SHA1;
    case Digest::SHA_2_224:
        return keystore::Digest::SHA224;
    case Digest::SHA_2_256:
    case Digest::NONE:
        return keystore::Digest::SHA256;
    case Digest::SHA_2_384:
        return keystore::Digest::SHA384;
    case Digest::SHA_2_512:
        return keystore::Digest::SHA512;
    default:
        LOG(ERROR) << __func__ << ": Unknown digest.";
        return KMV1::ErrorCode::UNKNOWN_ERROR;
    }
}

std::optional<KMV1::ErrorCode>
KeyMintDevice::signCertificate(const std::vector<KeyParameter>& keyParams,
                               const std::vector<uint8_t>& keyBlob, X509* cert) {
    auto algorithm = getParam(keyParams, KMV1::TAG_ALGORITHM);
    auto algoOrError = getKeystoreAlgorithm(*algorithm);
    if (std::holds_alternative<KMV1::ErrorCode>(algoOrError)) {
        return std::get<KMV1::ErrorCode>(algoOrError);
    }
    auto algo = std::get<keystore::Algo>(algoOrError);
    auto origPadding = getMaximum(keyParams, KMV1::TAG_PADDING,
                                  {PaddingMode::RSA_PSS, PaddingMode::RSA_PKCS1_1_5_SIGN});
    auto paddingOrError = getKeystorePadding(origPadding);
    if (std::holds_alternative<KMV1::ErrorCode>(paddingOrError)) {
        return std::get<KMV1::ErrorCode>(paddingOrError);
    }
    auto padding = std::get<keystore::Padding>(paddingOrError);
    auto origDigest = getMaximum(keyParams, KMV1::TAG_DIGEST,
                                 {Digest::SHA_2_256, Digest::SHA_2_512, Digest::SHA_2_384,
                                  Digest::SHA_2_224, Digest::SHA1, Digest::NONE});
    auto digestOrError = getKeystoreDigest(origDigest);
    if (std::holds_alternative<KMV1::ErrorCode>(digestOrError)) {
        return std::get<KMV1::ErrorCode>(digestOrError);
    }
    auto digest = std::get<keystore::Digest>(digestOrError);

    KMV1::ErrorCode errorCode = KMV1::ErrorCode::OK;
    auto error = keystore::signCertWith(
        &*cert,
        [&](const uint8_t* data, size_t len) {
            std::vector<uint8_t> dataVec(data, data + len);
            std::vector<KeyParameter> kps = {
                KMV1::makeKeyParameter(KMV1::TAG_DIGEST, origDigest),
            };
            if (algorithm == KMV1::Algorithm::RSA) {
                kps.push_back(KMV1::makeKeyParameter(KMV1::TAG_PADDING, origPadding));
            }
            BeginResult beginResult;
            auto error = begin(KeyPurpose::SIGN, keyBlob, kps, HardwareAuthToken(), &beginResult);
            if (!error.isOk()) {
                errorCode = toErrorCode(error);
                return std::vector<uint8_t>();
            }
            std::optional<KeyParameterArray> outParams;
            std::optional<ByteArray> outByte;
            int32_t status;
            error = beginResult.operation->update(std::nullopt, dataVec, std::nullopt, std::nullopt,
                                                  &outParams, &outByte, &status);
            if (!error.isOk()) {
                errorCode = toErrorCode(error);
                return std::vector<uint8_t>();
            }
            std::vector<uint8_t> result;
            error = beginResult.operation->finish(std::nullopt, std::nullopt, std::nullopt,
                                                  std::nullopt, std::nullopt, &outParams, &result);
            if (!error.isOk()) {
                errorCode = toErrorCode(error);
                return std::vector<uint8_t>();
            }
            return result;
        },
        algo, padding, digest);
    if (error) {
        LOG(ERROR) << __func__
                   << ": signCertWith failed. (Callback diagnosed: " << toString(errorCode) << ")";
        return KMV1::ErrorCode::UNKNOWN_ERROR;
    }
    if (errorCode != KMV1::ErrorCode::OK) {
        return errorCode;
    }
    return std::nullopt;
}

std::variant<std::vector<Certificate>, KMV1::ErrorCode>
KeyMintDevice::getCertificate(const std::vector<KeyParameter>& keyParams,
                              const std::vector<uint8_t>& keyBlob) {
    // There are no certificates for symmetric keys.
    auto algorithm = getParam(keyParams, KMV1::TAG_ALGORITHM);
    if (!algorithm) {
        LOG(ERROR) << __func__ << ": Unable to determine key algorithm.";
        return KMV1::ErrorCode::UNKNOWN_ERROR;
    }
    switch (*algorithm) {
    case Algorithm::RSA:
    case Algorithm::EC:
        break;
    default:
        return KMV1::ErrorCode::OK;
    }

    // If attestation was requested, call and use attestKey.
    if (containsParam(keyParams, KMV1::TAG_ATTESTATION_CHALLENGE)) {
        auto legacyParams = convertKeyParametersToLegacy(extractAttestationParams(keyParams));
        std::vector<Certificate> certs;
        KMV1::ErrorCode errorCode = KMV1::ErrorCode::OK;
        auto result = mDevice->attestKey(
            keyBlob, legacyParams,
            [&](V4_0::ErrorCode error, const hidl_vec<hidl_vec<uint8_t>>& certChain) {
                errorCode = convert(error);
                for (const auto& cert : certChain) {
                    Certificate certificate;
                    certificate.encodedCertificate = cert;
                    certs.push_back(certificate);
                }
            });
        if (!result.isOk()) {
            LOG(ERROR) << __func__ << ": Call to attestKey failed.";
            return KMV1::ErrorCode::UNKNOWN_ERROR;
        }
        if (errorCode != KMV1::ErrorCode::OK) {
            return errorCode;
        }
        return certs;
    }

    // makeCert
    auto certOrError = makeCert(mDevice, keyParams, keyBlob);
    if (std::holds_alternative<KMV1::ErrorCode>(certOrError)) {
        return std::get<KMV1::ErrorCode>(certOrError);
    }
    auto cert = std::move(std::get<keystore::X509_Ptr>(certOrError));

    // setIssuer
    auto error = keystore::setIssuer(&*cert, &*cert, false);
    if (error) {
        LOG(ERROR) << __func__ << ": Set issuer failed.";
        return KMV1::ErrorCode::UNKNOWN_ERROR;
    }

    // Signing
    auto canSelfSign =
        std::find_if(keyParams.begin(), keyParams.end(), [&](const KeyParameter& kp) {
            if (auto v = KMV1::authorizationValue(KMV1::TAG_PURPOSE, kp)) {
                return *v == KeyPurpose::SIGN;
            }
            return false;
        }) != keyParams.end();
    auto noAuthRequired = containsParam(keyParams, KMV1::TAG_NO_AUTH_REQUIRED);
    // If we cannot sign because of purpose or authorization requirement,
    if (!(canSelfSign && noAuthRequired)
        // or if self signing fails for any other reason,
        || signCertificate(keyParams, keyBlob, &*cert).has_value()) {
        // we sign with ephemeral key.
        keystore::EVP_PKEY_CTX_Ptr pkey_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));
        EVP_PKEY_keygen_init(pkey_ctx.get());
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx.get(), NID_X9_62_prime256v1);
        EVP_PKEY* pkey_ptr = nullptr;
        EVP_PKEY_keygen(pkey_ctx.get(), &pkey_ptr);
        error = keystore::signCert(&*cert, pkey_ptr);
        if (error) {
            LOG(ERROR) << __func__ << ": signCert failed.";
            return KMV1::ErrorCode::UNKNOWN_ERROR;
        }
    }

    // encodeCert
    auto encodedCertOrError = keystore::encodeCert(&*cert);
    if (std::holds_alternative<keystore::CertUtilsError>(encodedCertOrError)) {
        LOG(ERROR) << __func__ << ": encodeCert failed.";
        return KMV1::ErrorCode::UNKNOWN_ERROR;
    }

    Certificate certificate{.encodedCertificate =
                                std::get<std::vector<uint8_t>>(encodedCertOrError)};
    std::vector certificates = {certificate};
    return certificates;
}

// Code to find the Keymaster devices (copied from existing code).

// Copied from system/security/keystore/include/keystore/keymaster_types.h.

// Changing this namespace alias will change the keymaster version.
namespace keymaster = ::android::hardware::keymaster::V4_1;

using keymaster::SecurityLevel;

// Copied from system/security/keystore/KeyStore.h.

using ::android::sp;
using keymaster::support::Keymaster;

template <typename T, size_t count> class Devices : public std::array<T, count> {
  public:
    T& operator[](SecurityLevel secLevel) {
        static_assert(uint32_t(SecurityLevel::SOFTWARE) == 0 &&
                          uint32_t(SecurityLevel::TRUSTED_ENVIRONMENT) == 1 &&
                          uint32_t(SecurityLevel::STRONGBOX) == 2,
                      "Numeric values of security levels have changed");
        return std::array<T, count>::at(static_cast<uint32_t>(secLevel));
    }
    T operator[](SecurityLevel secLevel) const {
        if (static_cast<uint32_t>(secLevel) > static_cast<uint32_t>(SecurityLevel::STRONGBOX)) {
            LOG(ERROR) << "Invalid security level requested";
            return {};
        }
        return (*const_cast<Devices*>(this))[secLevel];
    }
};

using KeymasterDevices = Devices<sp<Keymaster>, 3>;

// Copied from system/security/keystore/keystore_main.cpp.

using ::android::hardware::hidl_string;
using keymaster::support::Keymaster3;
using keymaster::support::Keymaster4;

template <typename Wrapper>
KeymasterDevices enumerateKeymasterDevices(IServiceManager* serviceManager) {
    KeymasterDevices result;
    serviceManager->listManifestByInterface(
        Wrapper::WrappedIKeymasterDevice::descriptor, [&](const hidl_vec<hidl_string>& names) {
            auto try_get_device = [&](const auto& name, bool fail_silent) {
                auto device = Wrapper::WrappedIKeymasterDevice::getService(name);
                if (fail_silent && !device) return;
                CHECK(device) << "Failed to get service for \""
                              << Wrapper::WrappedIKeymasterDevice::descriptor
                              << "\" with interface name \"" << name << "\"";

                sp<Keymaster> kmDevice(new Wrapper(device, name));
                auto halVersion = kmDevice->halVersion();
                SecurityLevel securityLevel = halVersion.securityLevel;
                LOG(INFO) << "found " << Wrapper::WrappedIKeymasterDevice::descriptor
                          << " with interface name " << name << " and seclevel "
                          << toString(securityLevel);
                CHECK(static_cast<uint32_t>(securityLevel) < result.size())
                    << "Security level of \"" << Wrapper::WrappedIKeymasterDevice::descriptor
                    << "\" with interface name \"" << name << "\" out of range";
                auto& deviceSlot = result[securityLevel];
                if (deviceSlot) {
                    if (!fail_silent) {
                        LOG(WARNING) << "Implementation of \""
                                     << Wrapper::WrappedIKeymasterDevice::descriptor
                                     << "\" with interface name \"" << name
                                     << "\" and security level: " << toString(securityLevel)
                                     << " Masked by other implementation of Keymaster";
                    }
                } else {
                    deviceSlot = kmDevice;
                }
            };
            bool has_default = false;
            for (auto& n : names) {
                try_get_device(n, false);
                if (n == "default") has_default = true;
            }
            // Make sure that we always check the default device. If we enumerate only what is
            // known to hwservicemanager, we miss a possible passthrough HAL.
            if (!has_default) {
                try_get_device("default", true /* fail_silent */);
            }
        });
    return result;
}

KeymasterDevices initializeKeymasters() {
    auto serviceManager = IServiceManager::getService();
    CHECK(serviceManager.get()) << "Failed to get ServiceManager";
    auto result = enumerateKeymasterDevices<Keymaster4>(serviceManager.get());
    auto softKeymaster = result[SecurityLevel::SOFTWARE];
    if (!result[SecurityLevel::TRUSTED_ENVIRONMENT]) {
        result = enumerateKeymasterDevices<Keymaster3>(serviceManager.get());
    }
    if (softKeymaster) result[SecurityLevel::SOFTWARE] = softKeymaster;
    if (result[SecurityLevel::SOFTWARE] && !result[SecurityLevel::TRUSTED_ENVIRONMENT]) {
        LOG(WARNING) << "No secure Keymaster implementation found, but device offers insecure"
                        " Keymaster HAL. Using as default.";
        result[SecurityLevel::TRUSTED_ENVIRONMENT] = result[SecurityLevel::SOFTWARE];
        result[SecurityLevel::SOFTWARE] = nullptr;
    }
    // The software bit was removed since we do not need it.
    return result;
}

void KeyMintDevice::setNumFreeSlots(uint8_t numFreeSlots) {
    mOperationSlots.setNumFreeSlots(numFreeSlots);
}

// Constructors and helpers.

KeyMintDevice::KeyMintDevice(sp<Keymaster> device, KeyMintSecurityLevel securityLevel)
    : mDevice(device) {
    if (securityLevel == KeyMintSecurityLevel::STRONGBOX) {
        mOperationSlots.setNumFreeSlots(3);
    } else {
        mOperationSlots.setNumFreeSlots(15);
    }
}

sp<Keymaster> getDevice(KeyMintSecurityLevel securityLevel) {
    static std::mutex mutex;
    static sp<Keymaster> teeDevice;
    static sp<Keymaster> sbDevice;
    std::lock_guard<std::mutex> lock(mutex);
    if (!teeDevice) {
        auto devices = initializeKeymasters();
        teeDevice = devices[V4_0::SecurityLevel::TRUSTED_ENVIRONMENT];
        sbDevice = devices[V4_0::SecurityLevel::STRONGBOX];
    }
    switch (securityLevel) {
    case KeyMintSecurityLevel::TRUSTED_ENVIRONMENT:
        return teeDevice;
    case KeyMintSecurityLevel::STRONGBOX:
        return sbDevice;
    default:
        return {};
    }
}

std::shared_ptr<KeyMintDevice>
KeyMintDevice::createKeyMintDevice(KeyMintSecurityLevel securityLevel) {
    if (auto dev = getDevice(securityLevel)) {
        return ndk::SharedRefBase::make<KeyMintDevice>(std::move(dev), securityLevel);
    }
    return {};
}

std::shared_ptr<SharedSecret> SharedSecret::createSharedSecret(KeyMintSecurityLevel securityLevel) {
    auto device = getDevice(securityLevel);
    if (!device) {
        return {};
    }
    return ndk::SharedRefBase::make<SharedSecret>(std::move(device));
}

std::shared_ptr<SecureClock> SecureClock::createSecureClock(KeyMintSecurityLevel securityLevel) {
    auto device = getDevice(securityLevel);
    if (!device) {
        return {};
    }
    return ndk::SharedRefBase::make<SecureClock>(std::move(device));
}

ScopedAStatus
KeystoreCompatService::getKeyMintDevice(KeyMintSecurityLevel in_securityLevel,
                                        std::shared_ptr<IKeyMintDevice>* _aidl_return) {
    auto i = mDeviceCache.find(in_securityLevel);
    if (i == mDeviceCache.end()) {
        auto device = KeyMintDevice::createKeyMintDevice(in_securityLevel);
        if (!device) {
            return ScopedAStatus::fromStatus(STATUS_NAME_NOT_FOUND);
        }
        bool inserted = false;
        std::tie(i, inserted) = mDeviceCache.insert({in_securityLevel, std::move(device)});
    }
    *_aidl_return = i->second;
    return ScopedAStatus::ok();
}

ScopedAStatus KeystoreCompatService::getSharedSecret(KeyMintSecurityLevel in_securityLevel,
                                                     std::shared_ptr<ISharedSecret>* _aidl_return) {
    if (!mSharedSecret) {
        auto secret = SharedSecret::createSharedSecret(in_securityLevel);
        if (!secret) {
            return ScopedAStatus::fromStatus(STATUS_NAME_NOT_FOUND);
        }
        mSharedSecret = std::move(secret);
    }
    *_aidl_return = mSharedSecret;
    return ScopedAStatus::ok();
}

ScopedAStatus KeystoreCompatService::getSecureClock(std::shared_ptr<ISecureClock>* _aidl_return) {
    if (!mSharedSecret) {
        // The legacy verification service was always provided by the TEE variant.
        auto clock = SecureClock::createSecureClock(KeyMintSecurityLevel::TRUSTED_ENVIRONMENT);
        if (!clock) {
            return ScopedAStatus::fromStatus(STATUS_NAME_NOT_FOUND);
        }
        mSecureClock = std::move(clock);
    }
    *_aidl_return = mSecureClock;
    return ScopedAStatus::ok();
}
