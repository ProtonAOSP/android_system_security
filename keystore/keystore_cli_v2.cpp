// Copyright 2015 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <chrono>
#include <cstdio>
#include <future>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

#include <aidl/android/security/apc/BnConfirmationCallback.h>
#include <aidl/android/security/apc/IProtectedConfirmation.h>
#include <aidl/android/system/keystore2/IKeystoreService.h>
#include <aidl/android/system/keystore2/ResponseCode.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <keymint_support/authorization_set.h>

#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/x509.h>

#include "keystore_client.pb.h"

namespace apc = ::aidl::android::security::apc;
namespace keymint = ::aidl::android::hardware::security::keymint;
namespace ks2 = ::aidl::android::system::keystore2;

using base::CommandLine;
using keystore::EncryptedData;

namespace {

struct TestCase {
    std::string name;
    bool required_for_brillo_pts;
    keymint::AuthorizationSet parameters;
};

constexpr const char keystore2_service_name[] = "android.system.keystore2";

int unwrapError(const ndk::ScopedAStatus& status) {
    if (status.isOk()) return 0;
    if (status.getExceptionCode() == EX_SERVICE_SPECIFIC) {
        return status.getServiceSpecificError();
    } else {
        return static_cast<int>(ks2::ResponseCode::SYSTEM_ERROR);
    }
}

ks2::KeyDescriptor keyDescriptor(const std::string& alias) {
    return {
        .domain = ks2::Domain::APP,
        .nspace = -1,  // ignored - should be -1.
        .alias = alias,
        .blob = {},
    };
}

void PrintUsageAndExit() {
    printf("Usage: keystore_client_v2 <command> [options]\n");
    printf("Commands: brillo-platform-test [--prefix=<test_name_prefix>] [--test_for_0_3]\n"
           "          list-brillo-tests\n"
           "          add-entropy --input=<entropy> [--seclevel=software|strongbox|tee(default)]\n"
           "          generate --name=<key_name> [--seclevel=software|strongbox|tee(default)]\n"
           "          get-chars --name=<key_name>\n"
           "          export --name=<key_name>\n"
           "          delete --name=<key_name>\n"
           "          delete-all\n"
           "          exists --name=<key_name>\n"
           "          list [--prefix=<key_name_prefix>]\n"
           "          list-apps-with-keys\n"
           "          sign-verify --name=<key_name>\n"
           "          [en|de]crypt --name=<key_name> --in=<file> --out=<file>\n"
           "                       [--seclevel=software|strongbox|tee(default)]\n"
           "          confirmation --prompt_text=<PromptText> --extra_data=<hex>\n"
           "                       --locale=<locale> [--ui_options=<list_of_ints>]\n"
           "                       --cancel_after=<seconds>\n");
    exit(1);
}

std::shared_ptr<ks2::IKeystoreService> CreateKeystoreInstance() {
    ::ndk::SpAIBinder keystoreBinder(AServiceManager_checkService(keystore2_service_name));
    auto result = ks2::IKeystoreService::fromBinder(keystoreBinder);
    if (result) return result;
    std::cerr << "Unable to connect to Keystore.";
    exit(-1);
}

std::shared_ptr<ks2::IKeystoreSecurityLevel>
GetSecurityLevelInterface(std::shared_ptr<ks2::IKeystoreService> keystore,
                          keymint::SecurityLevel securitylevel) {
    std::shared_ptr<ks2::IKeystoreSecurityLevel> sec_level;
    auto rc = keystore->getSecurityLevel(securitylevel, &sec_level);
    if (rc.isOk()) return sec_level;
    std::cerr << "Unable to get security level interface from Keystore: " << rc.getDescription();
    exit(-1);
}

bool isHardwareEnforced(const ks2::Authorization& a) {
    return !(a.securityLevel == keymint::SecurityLevel::SOFTWARE ||
             a.securityLevel == keymint::SecurityLevel::KEYSTORE);
}

void PrintTags(const std::vector<ks2::Authorization>& characteristics, bool printHardwareEnforced) {
    for (const auto& a : characteristics) {
        if (isHardwareEnforced(a) == printHardwareEnforced) {
            std::cout << toString(a.keyParameter.tag) << "\n";
        }
    }
}

void PrintKeyCharacteristics(const std::vector<ks2::Authorization>& characteristics) {
    printf("Hardware:\n");
    PrintTags(characteristics, true /* printHardwareEnforced */);
    printf("Software:\n");
    PrintTags(characteristics, false /* printHardwareEnforced */);
}

const char kEncryptSuffix[] = "_ENC";
const char kAuthenticateSuffix[] = "_AUTH";
constexpr uint32_t kAESKeySize = 256;      // bits
constexpr uint32_t kHMACKeySize = 256;     // bits
constexpr uint32_t kHMACOutputSize = 256;  // bits

bool verifyEncryptionKeyAttributes(const std::vector<ks2::Authorization> authorizations) {
    bool verified = true;
    verified =
        verified &&
        std::any_of(authorizations.begin(), authorizations.end(), [&](const ks2::Authorization& a) {
            return a.keyParameter.tag == keymint::Tag::ALGORITHM &&
                   a.keyParameter.value ==
                       keymint::KeyParameterValue::make<keymint::KeyParameterValue::algorithm>(
                           keymint::Algorithm::AES);
        });

    verified =
        verified &&
        std::any_of(authorizations.begin(), authorizations.end(), [&](const ks2::Authorization& a) {
            return a.keyParameter.tag == keymint::Tag::KEY_SIZE &&
                   a.keyParameter.value ==
                       keymint::KeyParameterValue::make<keymint::KeyParameterValue::integer>(
                           kAESKeySize);
        });

    verified =
        verified &&
        std::any_of(authorizations.begin(), authorizations.end(), [&](const ks2::Authorization& a) {
            return a.keyParameter.tag == keymint::Tag::BLOCK_MODE &&
                   a.keyParameter.value ==
                       keymint::KeyParameterValue::make<keymint::KeyParameterValue::blockMode>(
                           keymint::BlockMode::CBC);
        });

    verified =
        verified &&
        std::any_of(authorizations.begin(), authorizations.end(), [&](const ks2::Authorization& a) {
            return a.keyParameter.tag == keymint::Tag::PADDING &&
                   a.keyParameter.value ==
                       keymint::KeyParameterValue::make<keymint::KeyParameterValue::paddingMode>(
                           keymint::PaddingMode::PKCS7);
        });

    return verified;
}

bool verifyAuthenticationKeyAttributes(const std::vector<ks2::Authorization> authorizations) {
    bool verified = true;
    verified =
        verified &&
        std::any_of(authorizations.begin(), authorizations.end(), [&](const ks2::Authorization& a) {
            return a.keyParameter.tag == keymint::Tag::ALGORITHM &&
                   a.keyParameter.value ==
                       keymint::KeyParameterValue::make<keymint::KeyParameterValue::algorithm>(
                           keymint::Algorithm::HMAC);
        });

    verified =
        verified &&
        std::any_of(authorizations.begin(), authorizations.end(), [&](const ks2::Authorization& a) {
            return a.keyParameter.tag == keymint::Tag::KEY_SIZE &&
                   a.keyParameter.value ==
                       keymint::KeyParameterValue::make<keymint::KeyParameterValue::integer>(
                           kHMACKeySize);
        });

    verified =
        verified &&
        std::any_of(authorizations.begin(), authorizations.end(), [&](const ks2::Authorization& a) {
            return a.keyParameter.tag == keymint::Tag::MIN_MAC_LENGTH &&
                   a.keyParameter.value ==
                       keymint::KeyParameterValue::make<keymint::KeyParameterValue::integer>(
                           kHMACOutputSize);
        });

    verified =
        verified &&
        std::any_of(authorizations.begin(), authorizations.end(), [&](const ks2::Authorization& a) {
            return a.keyParameter.tag == keymint::Tag::DIGEST &&
                   a.keyParameter.value ==
                       keymint::KeyParameterValue::make<keymint::KeyParameterValue::digest>(
                           keymint::Digest::SHA_2_256);
        });
    return verified;
}

std::variant<int, ks2::KeyEntryResponse>
loadOrCreateAndVerifyEncryptionKey(const std::string& name, keymint::SecurityLevel securityLevel,
                                   bool create) {
    auto keystore = CreateKeystoreInstance();

    ks2::KeyEntryResponse keyEntryResponse;

    bool foundKey = true;
    auto rc = keystore->getKeyEntry(keyDescriptor(name), &keyEntryResponse);
    if (!rc.isOk()) {
        auto error = unwrapError(rc);
        if (ks2::ResponseCode(error) == ks2::ResponseCode::KEY_NOT_FOUND && create) {
            foundKey = false;
        } else {
            std::cerr << "Failed to get key entry: " << rc.getDescription() << std::endl;
            return error;
        }
    }

    if (!foundKey) {
        auto sec_level = GetSecurityLevelInterface(keystore, securityLevel);
        auto params = keymint::AuthorizationSetBuilder()
                          .AesEncryptionKey(kAESKeySize)
                          .Padding(keymint::PaddingMode::PKCS7)
                          .Authorization(keymint::TAG_BLOCK_MODE, keymint::BlockMode::CBC)
                          .Authorization(keymint::TAG_NO_AUTH_REQUIRED);

        ks2::KeyMetadata keyMetadata;

        rc = sec_level->generateKey(keyDescriptor(name), {} /* attestationKey */,
                                    params.vector_data(), 0 /* flags */, {} /* entropy */,
                                    &keyMetadata);
        if (!rc.isOk()) {
            std::cerr << "Failed to generate key: " << rc.getDescription() << std::endl;
            return unwrapError(rc);
        }

        rc = keystore->getKeyEntry(keyDescriptor(name), &keyEntryResponse);
        if (!rc.isOk()) {
            std::cerr << "Failed to get key entry (second try): " << rc.getDescription()
                      << std::endl;
            return unwrapError(rc);
        }
    }

    if (!verifyEncryptionKeyAttributes(keyEntryResponse.metadata.authorizations)) {
        std::cerr << "Key has wrong set of parameters." << std::endl;
        return static_cast<int>(ks2::ResponseCode::INVALID_ARGUMENT);
    }

    return keyEntryResponse;
}

std::variant<int, ks2::KeyEntryResponse>
loadOrCreateAndVerifyAuthenticationKey(const std::string& name,
                                       keymint::SecurityLevel securityLevel, bool create) {
    auto keystore = CreateKeystoreInstance();

    ks2::KeyEntryResponse keyEntryResponse;

    bool foundKey = true;
    auto rc = keystore->getKeyEntry(keyDescriptor(name), &keyEntryResponse);
    if (!rc.isOk()) {
        auto error = unwrapError(rc);
        if (ks2::ResponseCode(error) == ks2::ResponseCode::KEY_NOT_FOUND && create) {
            foundKey = false;
        } else {
            std::cerr << "Failed to get HMAC key entry: " << rc.getDescription() << std::endl;
            return error;
        }
    }

    if (!foundKey) {
        auto sec_level = GetSecurityLevelInterface(keystore, securityLevel);
        auto params = keymint::AuthorizationSetBuilder()
                          .HmacKey(kHMACKeySize)
                          .Digest(keymint::Digest::SHA_2_256)
                          .Authorization(keymint::TAG_MIN_MAC_LENGTH, kHMACOutputSize)
                          .Authorization(keymint::TAG_NO_AUTH_REQUIRED);

        ks2::KeyMetadata keyMetadata;

        rc = sec_level->generateKey(keyDescriptor(name), {} /* attestationKey */,
                                    params.vector_data(), 0 /* flags */, {} /* entropy */,
                                    &keyMetadata);
        if (!rc.isOk()) {
            std::cerr << "Failed to generate HMAC key: " << rc.getDescription() << std::endl;
            return unwrapError(rc);
        }

        rc = keystore->getKeyEntry(keyDescriptor(name), &keyEntryResponse);
        if (!rc.isOk()) {
            std::cerr << "Failed to get HMAC key entry (second try): " << rc.getDescription()
                      << std::endl;
            return unwrapError(rc);
        }
    }

    if (!verifyAuthenticationKeyAttributes(keyEntryResponse.metadata.authorizations)) {
        std::cerr << "Key has wrong set of parameters." << std::endl;
        return static_cast<int>(ks2::ResponseCode::INVALID_ARGUMENT);
    }

    return keyEntryResponse;
}

std::variant<int, std::vector<uint8_t>>
encryptWithAuthentication(const std::string& name, const std::vector<uint8_t>& data,
                          keymint::SecurityLevel securityLevel) {
    // The encryption algorithm is AES-256-CBC with PKCS #7 padding and a random
    // IV. The authentication algorithm is HMAC-SHA256 and is computed over the
    // cipher-text (i.e. Encrypt-then-MAC approach). This was chosen over AES-GCM
    // because hardware support for GCM is not mandatory for all Brillo devices.
    std::string encryption_key_name = name + kEncryptSuffix;
    auto encryption_key_result =
        loadOrCreateAndVerifyEncryptionKey(encryption_key_name, securityLevel, true /* create */);
    if (auto error = std::get_if<int>(&encryption_key_result)) {
        return *error;
    }
    auto encryption_key = std::get<ks2::KeyEntryResponse>(encryption_key_result);

    std::string authentication_key_name = name + kAuthenticateSuffix;
    auto authentication_key_result = loadOrCreateAndVerifyAuthenticationKey(
        authentication_key_name, securityLevel, true /* create */);
    if (auto error = std::get_if<int>(&authentication_key_result)) {
        return *error;
    }
    auto authentication_key = std::get<ks2::KeyEntryResponse>(authentication_key_result);

    ks2::CreateOperationResponse encOperationResponse;
    auto encrypt_params = keymint::AuthorizationSetBuilder()
                              .Authorization(keymint::TAG_PURPOSE, keymint::KeyPurpose::ENCRYPT)
                              .Padding(keymint::PaddingMode::PKCS7)
                              .Authorization(keymint::TAG_BLOCK_MODE, keymint::BlockMode::CBC);

    auto rc = encryption_key.iSecurityLevel->createOperation(
        encryption_key.metadata.key, encrypt_params.vector_data(), false /* forced */,
        &encOperationResponse);
    if (!rc.isOk()) {
        std::cerr << "Failed to begin encryption operation: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }

    std::optional<std::vector<uint8_t>> optCiphertext;

    rc = encOperationResponse.iOperation->finish(data, {}, &optCiphertext);
    if (!rc.isOk()) {
        std::cerr << "Failed to finish encryption operation: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }

    std::vector<uint8_t> initVector;
    if (auto params = encOperationResponse.parameters) {
        for (auto& p : params->keyParameter) {
            if (auto iv = keymint::authorizationValue(keymint::TAG_NONCE, p)) {
                initVector = std::move(iv->get());
                break;
            }
        }
        if (initVector.empty()) {
            std::cerr << "Encryption operation did not return an IV." << std::endl;
            return static_cast<int>(ks2::ResponseCode::SYSTEM_ERROR);
        }
    }

    if (!optCiphertext) {
        std::cerr << "Encryption succeeded but no ciphertext returned." << std::endl;
        return static_cast<int>(ks2::ResponseCode::SYSTEM_ERROR);
    }

    auto ciphertext = std::move(*optCiphertext);
    auto toBeSigned = initVector;
    toBeSigned.insert(toBeSigned.end(), ciphertext.begin(), ciphertext.end());

    ks2::CreateOperationResponse signOperationResponse;
    auto sign_params = keymint::AuthorizationSetBuilder()
                           .Authorization(keymint::TAG_PURPOSE, keymint::KeyPurpose::SIGN)
                           .Digest(keymint::Digest::SHA_2_256)
                           .Authorization(keymint::TAG_MAC_LENGTH, kHMACOutputSize);

    rc = authentication_key.iSecurityLevel->createOperation(
        authentication_key.metadata.key, sign_params.vector_data(), false /* forced */,
        &signOperationResponse);
    if (!rc.isOk()) {
        std::cerr << "Failed to begin signing operation: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }

    std::optional<std::vector<uint8_t>> optMac;

    rc = signOperationResponse.iOperation->finish(toBeSigned, {}, &optMac);
    if (!rc.isOk()) {
        std::cerr << "Failed to finish encryption operation: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }

    if (!optMac) {
        std::cerr << "Signing succeeded but no MAC returned." << std::endl;
        return static_cast<int>(ks2::ResponseCode::SYSTEM_ERROR);
    }

    auto mac = std::move(*optMac);

    EncryptedData protobuf;
    protobuf.set_init_vector(initVector.data(), initVector.size());
    protobuf.set_authentication_data(mac.data(), mac.size());
    protobuf.set_encrypted_data(ciphertext.data(), ciphertext.size());
    std::string resultString;
    if (!protobuf.SerializeToString(&resultString)) {
        std::cerr << "Encrypt: Failed to serialize EncryptedData protobuf.";
        return static_cast<int>(ks2::ResponseCode::SYSTEM_ERROR);
    }

    std::vector<uint8_t> result(reinterpret_cast<const uint8_t*>(resultString.data()),
                                reinterpret_cast<const uint8_t*>(resultString.data()) +
                                    resultString.size());
    return result;
}

std::variant<int, std::vector<uint8_t>>
decryptWithAuthentication(const std::string& name, const std::vector<uint8_t>& data) {

    // Decode encrypted data
    EncryptedData protobuf;
    if (!protobuf.ParseFromArray(data.data(), data.size())) {
        std::cerr << "Decrypt: Failed to parse EncryptedData protobuf." << std::endl;
        return static_cast<int>(ks2::ResponseCode::SYSTEM_ERROR);
    }

    // Load encryption and authentication keys.
    std::string encryption_key_name = name + kEncryptSuffix;
    auto encryption_key_result = loadOrCreateAndVerifyEncryptionKey(
        encryption_key_name, keymint::SecurityLevel::KEYSTORE /* ignored */, false /* create */);
    if (auto error = std::get_if<int>(&encryption_key_result)) {
        return *error;
    }
    auto encryption_key = std::get<ks2::KeyEntryResponse>(encryption_key_result);

    std::string authentication_key_name = name + kAuthenticateSuffix;
    auto authentication_key_result = loadOrCreateAndVerifyAuthenticationKey(
        authentication_key_name, keymint::SecurityLevel::KEYSTORE /* ignored */,
        false /* create */);
    if (auto error = std::get_if<int>(&authentication_key_result)) {
        return *error;
    }
    auto authentication_key = std::get<ks2::KeyEntryResponse>(authentication_key_result);

    // Begin authentication operation
    ks2::CreateOperationResponse signOperationResponse;
    auto sign_params = keymint::AuthorizationSetBuilder()
                           .Authorization(keymint::TAG_PURPOSE, keymint::KeyPurpose::VERIFY)
                           .Digest(keymint::Digest::SHA_2_256)
                           .Authorization(keymint::TAG_MAC_LENGTH, kHMACOutputSize);

    auto rc = authentication_key.iSecurityLevel->createOperation(
        authentication_key.metadata.key, sign_params.vector_data(), false /* forced */,
        &signOperationResponse);
    if (!rc.isOk()) {
        std::cerr << "Failed to begin verify operation: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }

    const uint8_t* p = reinterpret_cast<const uint8_t*>(protobuf.init_vector().data());
    std::vector<uint8_t> toBeVerified(p, p + protobuf.init_vector().size());

    p = reinterpret_cast<const uint8_t*>(protobuf.encrypted_data().data());
    toBeVerified.insert(toBeVerified.end(), p, p + protobuf.encrypted_data().size());

    p = reinterpret_cast<const uint8_t*>(protobuf.authentication_data().data());
    std::vector<uint8_t> signature(p, p + protobuf.authentication_data().size());

    std::optional<std::vector<uint8_t>> optOut;
    rc = signOperationResponse.iOperation->finish(toBeVerified, signature, &optOut);
    if (!rc.isOk()) {
        std::cerr << "Decrypt: HMAC verification failed: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }

    // Begin decryption operation
    ks2::CreateOperationResponse encOperationResponse;
    auto encrypt_params = keymint::AuthorizationSetBuilder()
                              .Authorization(keymint::TAG_PURPOSE, keymint::KeyPurpose::DECRYPT)
                              .Authorization(keymint::TAG_NONCE, protobuf.init_vector().data(),
                                             protobuf.init_vector().size())
                              .Padding(keymint::PaddingMode::PKCS7)
                              .Authorization(keymint::TAG_BLOCK_MODE, keymint::BlockMode::CBC);

    rc = encryption_key.iSecurityLevel->createOperation(encryption_key.metadata.key,
                                                        encrypt_params.vector_data(),
                                                        false /* forced */, &encOperationResponse);
    if (!rc.isOk()) {
        std::cerr << "Failed to begin encryption operation: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }

    std::optional<std::vector<uint8_t>> optPlaintext;

    p = reinterpret_cast<const uint8_t*>(protobuf.encrypted_data().data());
    std::vector<uint8_t> cyphertext(p, p + protobuf.encrypted_data().size());

    rc = encOperationResponse.iOperation->finish(cyphertext, {}, &optPlaintext);
    if (!rc.isOk()) {
        std::cerr << "Failed to finish encryption operation: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }

    if (!optPlaintext) {
        std::cerr << "Decryption succeeded but no plaintext returned." << std::endl;
        return static_cast<int>(ks2::ResponseCode::SYSTEM_ERROR);
    }

    return *optPlaintext;
}

bool TestKey(const std::string& name, bool required,
             const std::vector<keymint::KeyParameter>& parameters) {
    auto keystore = CreateKeystoreInstance();
    auto sec_level =
        GetSecurityLevelInterface(keystore, keymint::SecurityLevel::TRUSTED_ENVIRONMENT);

    ks2::KeyDescriptor keyDescriptor = {
        .domain = ks2::Domain::APP,
        .nspace = -1,
        .alias = "tmp",
        .blob = {},
    };

    ks2::KeyMetadata keyMetadata;

    auto rc = sec_level->generateKey(keyDescriptor, {} /* attestationKey */, parameters,
                                     0 /* flags */, {} /* entropy */, &keyMetadata);
    const char kBoldRedAbort[] = "\033[1;31mABORT\033[0m";
    if (!rc.isOk()) {
        LOG(ERROR) << "Failed to generate key: " << rc.getDescription();
        printf("[%s] %s\n", kBoldRedAbort, name.c_str());
        return false;
    }

    rc = keystore->deleteKey(keyDescriptor);
    if (!rc.isOk()) {
        LOG(ERROR) << "Failed to delete key: " << rc.getDescription();
        printf("[%s] %s\n", kBoldRedAbort, name.c_str());
        return false;
    }
    printf("===============================================================\n");
    printf("%s Key Characteristics:\n", name.c_str());
    PrintKeyCharacteristics(keyMetadata.authorizations);
    bool hardware_backed = std::any_of(keyMetadata.authorizations.begin(),
                                       keyMetadata.authorizations.end(), isHardwareEnforced);
    if (std::any_of(keyMetadata.authorizations.begin(), keyMetadata.authorizations.end(),
                    [&](const auto& a) {
                        return !isHardwareEnforced(a) &&
                               (a.keyParameter.tag == keymint::Tag::ALGORITHM ||
                                a.keyParameter.tag == keymint::Tag::KEY_SIZE ||
                                a.keyParameter.tag == keymint::Tag::RSA_PUBLIC_EXPONENT);
                    })) {
        VLOG(1) << "Hardware-backed key but required characteristics enforced in software.";
        hardware_backed = false;
    }
    const char kBoldRedFail[] = "\033[1;31mFAIL\033[0m";
    const char kBoldGreenPass[] = "\033[1;32mPASS\033[0m";
    const char kBoldYellowWarn[] = "\033[1;33mWARN\033[0m";
    printf("[%s] %s\n",
           hardware_backed ? kBoldGreenPass : (required ? kBoldRedFail : kBoldYellowWarn),
           name.c_str());

    return (hardware_backed || !required);
}

keymint::AuthorizationSet GetRSASignParameters(uint32_t key_size, bool sha256_only) {
    keymint::AuthorizationSetBuilder parameters;
    parameters.RsaSigningKey(key_size, 65537)
        .Digest(keymint::Digest::SHA_2_256)
        .Padding(keymint::PaddingMode::RSA_PKCS1_1_5_SIGN)
        .Padding(keymint::PaddingMode::RSA_PSS)
        .Authorization(keymint::TAG_NO_AUTH_REQUIRED);
    if (!sha256_only) {
        parameters.Digest(keymint::Digest::SHA_2_224)
            .Digest(keymint::Digest::SHA_2_384)
            .Digest(keymint::Digest::SHA_2_512);
    }
    return std::move(parameters);
}

keymint::AuthorizationSet GetRSAEncryptParameters(uint32_t key_size) {
    keymint::AuthorizationSetBuilder parameters;
    parameters.RsaEncryptionKey(key_size, 65537)
        .Padding(keymint::PaddingMode::RSA_PKCS1_1_5_ENCRYPT)
        .Padding(keymint::PaddingMode::RSA_OAEP)
        .Authorization(keymint::TAG_NO_AUTH_REQUIRED);
    return std::move(parameters);
}

keymint::AuthorizationSet GetECDSAParameters(uint32_t key_size, bool sha256_only) {
    keymint::AuthorizationSetBuilder parameters;
    parameters.EcdsaSigningKey(key_size)
        .Digest(keymint::Digest::SHA_2_256)
        .Authorization(keymint::TAG_NO_AUTH_REQUIRED);
    if (!sha256_only) {
        parameters.Digest(keymint::Digest::SHA_2_224)
            .Digest(keymint::Digest::SHA_2_384)
            .Digest(keymint::Digest::SHA_2_512);
    }
    return std::move(parameters);
}

keymint::AuthorizationSet GetAESParameters(uint32_t key_size, bool with_gcm_mode) {
    keymint::AuthorizationSetBuilder parameters;
    parameters.AesEncryptionKey(key_size).Authorization(keymint::TAG_NO_AUTH_REQUIRED);
    if (with_gcm_mode) {
        parameters.Authorization(keymint::TAG_BLOCK_MODE, keymint::BlockMode::GCM)
            .Authorization(keymint::TAG_MIN_MAC_LENGTH, 128);
    } else {
        parameters.Authorization(keymint::TAG_BLOCK_MODE, keymint::BlockMode::ECB);
        parameters.Authorization(keymint::TAG_BLOCK_MODE, keymint::BlockMode::CBC);
        parameters.Authorization(keymint::TAG_BLOCK_MODE, keymint::BlockMode::CTR);
        parameters.Padding(keymint::PaddingMode::NONE);
    }
    return std::move(parameters);
}

keymint::AuthorizationSet GetHMACParameters(uint32_t key_size, keymint::Digest digest) {
    keymint::AuthorizationSetBuilder parameters;
    parameters.HmacKey(key_size)
        .Digest(digest)
        .Authorization(keymint::TAG_MIN_MAC_LENGTH, 224)
        .Authorization(keymint::TAG_NO_AUTH_REQUIRED);
    return std::move(parameters);
}

std::vector<TestCase> GetTestCases() {
    TestCase test_cases[] = {
        {"RSA-2048 Sign", true, GetRSASignParameters(2048, true)},
        {"RSA-2048 Sign (more digests)", false, GetRSASignParameters(2048, false)},
        {"RSA-3072 Sign", false, GetRSASignParameters(3072, false)},
        {"RSA-4096 Sign", false, GetRSASignParameters(4096, false)},
        {"RSA-2048 Encrypt", true, GetRSAEncryptParameters(2048)},
        {"RSA-3072 Encrypt", false, GetRSAEncryptParameters(3072)},
        {"RSA-4096 Encrypt", false, GetRSAEncryptParameters(4096)},
        {"ECDSA-P256 Sign", true, GetECDSAParameters(256, true)},
        {"ECDSA-P256 Sign (more digests)", false, GetECDSAParameters(256, false)},
        {"ECDSA-P224 Sign", false, GetECDSAParameters(224, false)},
        {"ECDSA-P384 Sign", false, GetECDSAParameters(384, false)},
        {"ECDSA-P521 Sign", false, GetECDSAParameters(521, false)},
        {"AES-128", true, GetAESParameters(128, false)},
        {"AES-256", true, GetAESParameters(256, false)},
        {"AES-128-GCM", false, GetAESParameters(128, true)},
        {"AES-256-GCM", false, GetAESParameters(256, true)},
        {"HMAC-SHA256-16", true, GetHMACParameters(16, keymint::Digest::SHA_2_256)},
        {"HMAC-SHA256-32", true, GetHMACParameters(32, keymint::Digest::SHA_2_256)},
        {"HMAC-SHA256-64", false, GetHMACParameters(64, keymint::Digest::SHA_2_256)},
        {"HMAC-SHA224-32", false, GetHMACParameters(32, keymint::Digest::SHA_2_224)},
        {"HMAC-SHA384-32", false, GetHMACParameters(32, keymint::Digest::SHA_2_384)},
        {"HMAC-SHA512-32", false, GetHMACParameters(32, keymint::Digest::SHA_2_512)},
    };
    return std::vector<TestCase>(&test_cases[0], &test_cases[arraysize(test_cases)]);
}

int BrilloPlatformTest(const std::string& prefix, bool test_for_0_3) {
    const char kBoldYellowWarning[] = "\033[1;33mWARNING\033[0m";
    if (test_for_0_3) {
        printf("%s: Testing for keymaster v0.3. "
               "This does not meet Brillo requirements.\n",
               kBoldYellowWarning);
    }
    int test_count = 0;
    int fail_count = 0;
    std::vector<TestCase> test_cases = GetTestCases();
    for (const auto& test_case : test_cases) {
        if (!prefix.empty() &&
            !base::StartsWith(test_case.name, prefix, base::CompareCase::SENSITIVE)) {
            continue;
        }
        if (test_for_0_3 &&
            (base::StartsWith(test_case.name, "AES", base::CompareCase::SENSITIVE) ||
             base::StartsWith(test_case.name, "HMAC", base::CompareCase::SENSITIVE))) {
            continue;
        }
        ++test_count;
        if (!TestKey(test_case.name, test_case.required_for_brillo_pts,
                     test_case.parameters.vector_data())) {
            VLOG(1) << "Test failed: " << test_case.name;
            ++fail_count;
        }
    }
    return fail_count;
}

int ListTestCases() {
    const char kBoldGreenRequired[] = "\033[1;32mREQUIRED\033[0m";
    const char kBoldYellowRecommended[] = "\033[1;33mRECOMMENDED\033[0m";
    std::vector<TestCase> test_cases = GetTestCases();
    for (const auto& test_case : test_cases) {
        printf("%s : %s\n", test_case.name.c_str(),
               test_case.required_for_brillo_pts ? kBoldGreenRequired : kBoldYellowRecommended);
    }
    return 0;
}

std::vector<uint8_t> ReadFile(const std::string& filename) {
    std::string content;
    base::FilePath path(filename);
    if (!base::ReadFileToString(path, &content)) {
        printf("Failed to read file: %s\n", filename.c_str());
        exit(1);
    }
    std::vector<uint8_t> buffer(reinterpret_cast<const uint8_t*>(content.data()),
                                reinterpret_cast<const uint8_t*>(content.data()) + content.size());
    return buffer;
}

void WriteFile(const std::string& filename, const std::vector<uint8_t>& content) {
    base::FilePath path(filename);
    int size = content.size();
    if (base::WriteFile(path, reinterpret_cast<const char*>(content.data()), size) != size) {
        printf("Failed to write file: %s\n", filename.c_str());
        exit(1);
    }
}

// Note: auth_bound keys created with this tool will not be usable.
int GenerateKey(const std::string& name, keymint::SecurityLevel securityLevel, bool auth_bound) {
    auto keystore = CreateKeystoreInstance();
    auto sec_level = GetSecurityLevelInterface(keystore, securityLevel);
    keymint::AuthorizationSetBuilder params;
    params.RsaSigningKey(2048, 65537)
        .Digest(keymint::Digest::SHA_2_224)
        .Digest(keymint::Digest::SHA_2_256)
        .Digest(keymint::Digest::SHA_2_384)
        .Digest(keymint::Digest::SHA_2_512)
        .Padding(keymint::PaddingMode::RSA_PKCS1_1_5_SIGN)
        .Padding(keymint::PaddingMode::RSA_PSS);
    if (auth_bound) {
        // Gatekeeper normally generates the secure user id.
        // Using zero allows the key to be created, but it will not be usuable.
        params.Authorization(keymint::TAG_USER_SECURE_ID, 0);
    } else {
        params.Authorization(keymint::TAG_NO_AUTH_REQUIRED);
    }

    ks2::KeyMetadata keyMetadata;

    auto rc =
        sec_level->generateKey(keyDescriptor(name), {} /* attestationKey */, params.vector_data(),
                               0 /* flags */, {} /* entropy */, &keyMetadata);

    if (rc.isOk()) {
        std::cerr << "GenerateKey failed: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }
    std::cout << "GenerateKey: success" << std::endl;
    PrintKeyCharacteristics(keyMetadata.authorizations);
    return 0;
}

int GetCharacteristics(const std::string& name) {
    auto keystore = CreateKeystoreInstance();

    ks2::KeyEntryResponse keyEntryResponse;

    auto rc = keystore->getKeyEntry(keyDescriptor(name), &keyEntryResponse);
    if (!rc.isOk()) {
        std::cerr << "Failed to get key entry: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }

    std::cout << "GetCharacteristics: success" << std::endl;
    PrintKeyCharacteristics(keyEntryResponse.metadata.authorizations);
    return 0;
}

int ExportKey(const std::string& name) {
    auto keystore = CreateKeystoreInstance();

    ks2::KeyEntryResponse keyEntryResponse;

    auto rc = keystore->getKeyEntry(keyDescriptor(name), &keyEntryResponse);
    if (!rc.isOk()) {
        std::cerr << "Failed to get key entry: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }

    if (auto cert = keyEntryResponse.metadata.certificate) {
        std::cout << "ExportKey: Got certificate of length (" << cert->size() << ")" << std::endl;
    } else {
        std::cout << "ExportKey: Key entry does not have a public component.\n";
        std::cout << "Possibly a symmetric key?" << std::endl;
    }
    return 0;
}

int DeleteKey(const std::string& name) {
    auto keystore = CreateKeystoreInstance();

    auto rc = keystore->deleteKey(keyDescriptor(name));
    if (!rc.isOk()) {
        std::cerr << "Failed to delete key: " << rc.getDescription();
        return unwrapError(rc);
    }
    std::cout << "Successfully deleted key." << std::endl;
    return 0;
}

int DoesKeyExist(const std::string& name) {
    auto keystore = CreateKeystoreInstance();
    ks2::KeyEntryResponse keyEntryResponse;

    bool keyExists = true;
    auto rc = keystore->getKeyEntry(keyDescriptor(name), &keyEntryResponse);
    if (!rc.isOk()) {
        auto responseCode = unwrapError(rc);
        if (ks2::ResponseCode(responseCode) == ks2::ResponseCode::KEY_NOT_FOUND) {
            keyExists = false;
        } else {
            std::cerr << "Failed to get key entry: " << rc.getDescription() << std::endl;
            return unwrapError(rc);
        }
    }
    std::cout << "DoesKeyExists: " << (keyExists ? "yes" : "no") << std::endl;
    return 0;
}

int List() {
    auto keystore = CreateKeystoreInstance();
    std::vector<ks2::KeyDescriptor> key_list;
    auto rc = keystore->listEntries(ks2::Domain::APP, -1 /* nspace ignored */, &key_list);
    if (!rc.isOk()) {
        std::cerr << "ListKeys failed: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }
    std::cout << "Keys:\n";
    for (const auto& key : key_list) {
        std::cout << "  "
                  << (key.alias ? *key.alias : "Whoopsi - no alias, this should not happen.")
                  << std::endl;
    }
    return 0;
}

int SignAndVerify(const std::string& name) {
    auto keystore = CreateKeystoreInstance();
    auto sign_params = keymint::AuthorizationSetBuilder()
                           .Authorization(keymint::TAG_PURPOSE, keymint::KeyPurpose::SIGN)
                           .Padding(keymint::PaddingMode::RSA_PKCS1_1_5_SIGN)
                           .Digest(keymint::Digest::SHA_2_256);

    keymint::AuthorizationSet output_params;

    ks2::KeyEntryResponse keyEntryResponse;

    auto rc = keystore->getKeyEntry(keyDescriptor(name), &keyEntryResponse);
    if (!rc.isOk()) {
        std::cerr << "Failed to get key entry: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }

    ks2::CreateOperationResponse operationResponse;

    rc = keyEntryResponse.iSecurityLevel->createOperation(keyEntryResponse.metadata.key,
                                                          sign_params.vector_data(),
                                                          false /* forced */, &operationResponse);
    if (!rc.isOk()) {
        std::cerr << "Failed to create operation: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }

    const std::vector<uint8_t> data_to_sign{0x64, 0x61, 0x74, 0x61, 0x5f, 0x74,
                                            0x6f, 0x5f, 0x73, 0x69, 0x67, 0x6e};
    std::optional<std::vector<uint8_t>> output_data;
    rc = operationResponse.iOperation->finish(data_to_sign, {}, &output_data);
    if (!rc.isOk()) {
        std::cerr << "Failed to finalize operation: " << rc.getDescription() << std::endl;
        return unwrapError(rc);
    }

    if (!output_data) {
        std::cerr << "Odd signing succeeded but no signature was returned." << std::endl;
        return static_cast<int>(ks2::ResponseCode::SYSTEM_ERROR);
    }
    auto signature = std::move(*output_data);

    std::cout << "Sign: " << signature.size() << " bytes." << std::endl;

    if (auto cert = keyEntryResponse.metadata.certificate) {
        const uint8_t* p = cert->data();
        bssl::UniquePtr<X509> decoded_cert(d2i_X509(nullptr, &p, (long)cert->size()));
        bssl::UniquePtr<EVP_PKEY> decoded_pkey(X509_get_pubkey(decoded_cert.get()));
        bssl::UniquePtr<EVP_MD_CTX> ctx(EVP_MD_CTX_new());
        if (!ctx) {
            std::cerr << "Failed to created EVP_MD context. << std::endl";
            return static_cast<int>(ks2::ResponseCode::SYSTEM_ERROR);
        }

        if (!EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, decoded_pkey.get()) ||
            !EVP_DigestVerifyUpdate(ctx.get(), data_to_sign.data(), data_to_sign.size()) ||
            EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size()) != 1) {
            std::cerr << "Failed to verify signature." << std::endl;
            return static_cast<int>(ks2::ResponseCode::SYSTEM_ERROR);
        }
    } else {
        std::cerr << "No public key to check signature against." << std::endl;
        return static_cast<int>(ks2::ResponseCode::SYSTEM_ERROR);
    }

    std::cout << "Verify: OK" << std::endl;
    return 0;
}

int Encrypt(const std::string& key_name, const std::string& input_filename,
            const std::string& output_filename, keymint::SecurityLevel securityLevel) {
    auto input = ReadFile(input_filename);
    auto result = encryptWithAuthentication(key_name, input, securityLevel);
    if (auto error = std::get_if<int>(&result)) {
        std::cerr << "EncryptWithAuthentication failed." << std::endl;
        return *error;
    }
    WriteFile(output_filename, std::get<std::vector<uint8_t>>(result));
    return 0;
}

int Decrypt(const std::string& key_name, const std::string& input_filename,
            const std::string& output_filename) {
    auto input = ReadFile(input_filename);
    auto result = decryptWithAuthentication(key_name, input);
    if (auto error = std::get_if<int>(&result)) {
        std::cerr << "DecryptWithAuthentication failed." << std::endl;
        return *error;
    }
    WriteFile(output_filename, std::get<std::vector<uint8_t>>(result));
    return 0;
}

keymint::SecurityLevel securityLevelOption2SecurlityLevel(const CommandLine& cmd) {
    if (cmd.HasSwitch("seclevel")) {
        auto str = cmd.GetSwitchValueASCII("seclevel");
        if (str == "strongbox") {
            return keymint::SecurityLevel::STRONGBOX;
        } else if (str == "tee") {
            return keymint::SecurityLevel::TRUSTED_ENVIRONMENT;
        }
        std::cerr << "Unknown Security level: " << str << std::endl;
        std::cerr << "Supported security levels: \"strongbox\" or \"tee\" (default)" << std::endl;
    }
    return keymint::SecurityLevel::TRUSTED_ENVIRONMENT;
}

class ConfirmationListener
    : public apc::BnConfirmationCallback,
      public std::promise<std::tuple<apc::ResponseCode, std::optional<std::vector<uint8_t>>>> {
  public:
    ConfirmationListener() {}

    virtual ::ndk::ScopedAStatus
    onCompleted(::aidl::android::security::apc::ResponseCode result,
                const std::optional<std::vector<uint8_t>>& dataConfirmed) override {
        this->set_value({result, dataConfirmed});
        return ::ndk::ScopedAStatus::ok();
    };
};

int Confirmation(const std::string& promptText, const std::string& extraDataHex,
                 const std::string& locale, const std::string& uiOptionsStr,
                 const std::string& cancelAfter) {
    ::ndk::SpAIBinder apcBinder(AServiceManager_getService("android.security.apc"));
    auto apcService = apc::IProtectedConfirmation::fromBinder(apcBinder);
    if (!apcService) {
        std::cerr << "Error: could not connect to apc service." << std::endl;
        return 1;
    }

    if (promptText.size() == 0) {
        printf("The --prompt_text parameter cannot be empty.\n");
        return 1;
    }

    std::vector<uint8_t> extraData;
    if (!base::HexStringToBytes(extraDataHex, &extraData)) {
        printf("The --extra_data parameter does not appear to be valid hexadecimal.\n");
        return 1;
    }

    std::vector<std::string> pieces =
        base::SplitString(uiOptionsStr, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    int uiOptionsAsFlags = 0;
    for (auto& p : pieces) {
        int value;
        if (!base::StringToInt(p, &value)) {
            printf("Error parsing %s in --ui_options parameter as a number.\n", p.c_str());
            return 1;
        }
        uiOptionsAsFlags |= (1 << value);
    }

    double cancelAfterValue = 0.0;

    if (cancelAfter.size() > 0 && !base::StringToDouble(cancelAfter, &cancelAfterValue)) {
        printf("Error parsing %s in --cancel_after parameter as a double.\n", cancelAfter.c_str());
        return 1;
    }

    auto listener = std::make_shared<ConfirmationListener>();

    auto future = listener->get_future();
    auto rc = apcService->presentPrompt(listener, promptText, extraData, locale, uiOptionsAsFlags);

    if (!rc.isOk()) {
        std::cerr << "Presenting confirmation prompt failed: " << rc.getDescription() << std::endl;
        return 1;
    }

    std::cerr << "Waiting for prompt to complete - use Ctrl+C to abort..." << std::endl;

    if (cancelAfterValue > 0.0) {
        std::cerr << "Sleeping " << cancelAfterValue << " seconds before canceling prompt..."
                  << std::endl;
        auto fstatus =
            future.wait_for(std::chrono::milliseconds(uint64_t(cancelAfterValue * 1000)));
        if (fstatus == std::future_status::timeout) {
            rc = apcService->cancelPrompt(listener);
            if (!rc.isOk()) {
                std::cerr << "Canceling confirmation prompt failed: " << rc.getDescription()
                          << std::endl;
                return 1;
            }
        }
    }

    future.wait();

    auto [responseCode, dataThatWasConfirmed] = future.get();

    std::cerr << "Confirmation prompt completed\n"
              << "responseCode = " << toString(responseCode);
    size_t newLineCountDown = 16;
    bool hasPrinted = false;
    if (dataThatWasConfirmed) {
        std::cerr << "dataThatWasConfirmed[" << dataThatWasConfirmed->size() << "] = {";
        for (uint8_t element : *dataThatWasConfirmed) {
            if (hasPrinted) {
                std::cerr << ", ";
            }
            if (newLineCountDown == 0) {
                std::cerr << "\n  ";
                newLineCountDown = 32;
            }
            std::cerr << "0x" << std::hex << std::setw(2) << std::setfill('0') << (unsigned)element;

            hasPrinted = true;
        }
    }
    std::cerr << std::endl;
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    CommandLine::Init(argc, argv);
    CommandLine* command_line = CommandLine::ForCurrentProcess();
    CommandLine::StringVector args = command_line->GetArgs();

    ABinderProcess_startThreadPool();

    if (args.empty()) {
        PrintUsageAndExit();
    }
    if (args[0] == "brillo-platform-test") {
        return BrilloPlatformTest(command_line->GetSwitchValueASCII("prefix"),
                                  command_line->HasSwitch("test_for_0_3"));
    } else if (args[0] == "list-brillo-tests") {
        return ListTestCases();
    } else if (args[0] == "generate") {
        return GenerateKey(command_line->GetSwitchValueASCII("name"),
                           securityLevelOption2SecurlityLevel(*command_line),
                           command_line->HasSwitch("auth_bound"));
    } else if (args[0] == "get-chars") {
        return GetCharacteristics(command_line->GetSwitchValueASCII("name"));
    } else if (args[0] == "export") {
        return ExportKey(command_line->GetSwitchValueASCII("name"));
    } else if (args[0] == "delete") {
        return DeleteKey(command_line->GetSwitchValueASCII("name"));
    } else if (args[0] == "exists") {
        return DoesKeyExist(command_line->GetSwitchValueASCII("name"));
    } else if (args[0] == "list") {
        return List();
    } else if (args[0] == "sign-verify") {
        return SignAndVerify(command_line->GetSwitchValueASCII("name"));
    } else if (args[0] == "encrypt") {
        return Encrypt(command_line->GetSwitchValueASCII("name"),
                       command_line->GetSwitchValueASCII("in"),
                       command_line->GetSwitchValueASCII("out"),
                       securityLevelOption2SecurlityLevel(*command_line));
    } else if (args[0] == "decrypt") {
        return Decrypt(command_line->GetSwitchValueASCII("name"),
                       command_line->GetSwitchValueASCII("in"),
                       command_line->GetSwitchValueASCII("out"));
    } else if (args[0] == "confirmation") {
        return Confirmation(command_line->GetSwitchValueNative("prompt_text"),
                            command_line->GetSwitchValueASCII("extra_data"),
                            command_line->GetSwitchValueASCII("locale"),
                            command_line->GetSwitchValueASCII("ui_options"),
                            command_line->GetSwitchValueASCII("cancel_after"));
    } else {
        PrintUsageAndExit();
    }
    return 0;
}
