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

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "base/command_line.h"
#include "base/files/file_util.h"
#include "keymaster/authorization_set.h"
#include "keymaster/keymaster_tags.h"
#include "keystore/keystore_client_impl.h"

using base::CommandLine;
using keymaster::AuthorizationSet;
using keymaster::AuthorizationSetBuilder;
using keystore::KeystoreClient;

namespace {

struct TestCase {
    std::string name;
    bool required_for_brillo_pts;
    AuthorizationSet parameters;
};

void PrintUsageAndExit() {
    printf("Usage: keystore_client_v2 <command> [options]\n");
    printf("Commands: brillo-platform-test [--prefix=<test_name_prefix>]\n"
           "          list-brillo-tests\n"
           "          add-entropy --input=<entropy>\n"
           "          generate --name=<key_name>\n"
           "          get-chars --name=<key_name>\n"
           "          export --name=<key_name>\n"
           "          delete --name=<key_name>\n"
           "          delete-all\n"
           "          exists --name=<key_name>\n"
           "          list [--prefix=<key_name_prefix>]\n"
           "          sign-verify --name=<key_name>\n"
           "          [en|de]crypt --name=<key_name> --in=<file> --out=<file>\n");
    exit(1);
}

std::unique_ptr<KeystoreClient> CreateKeystoreInstance() {
    return std::unique_ptr<KeystoreClient>(new keystore::KeystoreClientImpl);
}

#ifndef KEYMASTER_NAME_TAGS
#erro KEYMASTER_NAME_TAGS must be defined
#endif

void PrintTags(const AuthorizationSet& parameters) {
    const keymaster_key_param_t* iter = nullptr;
    for (iter = parameters.begin(); iter != parameters.end(); ++iter) {
        printf("  %s\n", keymaster::StringifyTag(iter->tag));
    }
}

void PrintKeyCharacteristics(const AuthorizationSet& hardware_enforced_characteristics,
                             const AuthorizationSet& software_enforced_characteristics) {
    printf("Hardware:\n");
    PrintTags(hardware_enforced_characteristics);
    printf("Software:\n");
    PrintTags(software_enforced_characteristics);
}

bool TestKey(const std::string& name, bool required, const AuthorizationSet& parameters) {
    std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
    AuthorizationSet hardware_enforced_characteristics;
    AuthorizationSet software_enforced_characteristics;
    int32_t result = keystore->generateKey("tmp", parameters, &hardware_enforced_characteristics,
                                           &software_enforced_characteristics);
    if (result != KM_ERROR_OK) {
        LOG(ERROR) << "Failed to generate key: " << result;
        printf("%s Result: ABORT\n", name.c_str());
        return false;
    }
    result = keystore->deleteKey("tmp");
    if (result != KM_ERROR_OK) {
        LOG(ERROR) << "Failed to delete key: " << result;
        printf("%s Result: ABORT\n", name.c_str());
        return false;
    }
    printf("===============================================================\n");
    printf("%s Key Characteristics:\n", name.c_str());
    PrintKeyCharacteristics(hardware_enforced_characteristics, software_enforced_characteristics);
    bool hardware_backed = (hardware_enforced_characteristics.size() > 0);
    if (software_enforced_characteristics.GetTagCount(KM_TAG_PURPOSE) > 0 ||
        software_enforced_characteristics.GetTagCount(KM_TAG_ALGORITHM) > 0 ||
        software_enforced_characteristics.GetTagCount(KM_TAG_KEY_SIZE) > 0 ||
        software_enforced_characteristics.GetTagCount(KM_TAG_RSA_PUBLIC_EXPONENT) > 0 ||
        software_enforced_characteristics.GetTagCount(KM_TAG_DIGEST) > 0 ||
        software_enforced_characteristics.GetTagCount(KM_TAG_PADDING) > 0 ||
        software_enforced_characteristics.GetTagCount(KM_TAG_BLOCK_MODE) > 0) {
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

AuthorizationSet GetRSASignParameters(uint32_t key_size, bool sha256_only) {
    AuthorizationSetBuilder parameters;
    parameters.RsaSigningKey(key_size, 65537)
        .Digest(KM_DIGEST_SHA_2_256)
        .Padding(KM_PAD_RSA_PKCS1_1_5_SIGN)
        .Padding(KM_PAD_RSA_PSS)
        .Authorization(keymaster::TAG_NO_AUTH_REQUIRED);
    if (!sha256_only) {
        parameters.Digest(KM_DIGEST_SHA_2_224)
            .Digest(KM_DIGEST_SHA_2_384)
            .Digest(KM_DIGEST_SHA_2_512);
    }
    return parameters.build();
}

AuthorizationSet GetRSAEncryptParameters(uint32_t key_size) {
    AuthorizationSetBuilder parameters;
    parameters.RsaEncryptionKey(key_size, 65537)
        .Padding(KM_PAD_RSA_PKCS1_1_5_ENCRYPT)
        .Padding(KM_PAD_RSA_OAEP)
        .Authorization(keymaster::TAG_NO_AUTH_REQUIRED);
    return parameters.build();
}

AuthorizationSet GetECDSAParameters(uint32_t key_size, bool sha256_only) {
    AuthorizationSetBuilder parameters;
    parameters.EcdsaSigningKey(key_size)
        .Digest(KM_DIGEST_SHA_2_256)
        .Authorization(keymaster::TAG_NO_AUTH_REQUIRED);
    if (!sha256_only) {
        parameters.Digest(KM_DIGEST_SHA_2_224)
            .Digest(KM_DIGEST_SHA_2_384)
            .Digest(KM_DIGEST_SHA_2_512);
    }
    return parameters.build();
}

AuthorizationSet GetAESParameters(uint32_t key_size, bool with_gcm_mode) {
    AuthorizationSetBuilder parameters;
    parameters.AesEncryptionKey(key_size).Authorization(keymaster::TAG_NO_AUTH_REQUIRED);
    if (with_gcm_mode) {
        parameters.Authorization(keymaster::TAG_BLOCK_MODE, KM_MODE_GCM)
            .Authorization(keymaster::TAG_MIN_MAC_LENGTH, 128);
    } else {
        parameters.Authorization(keymaster::TAG_BLOCK_MODE, KM_MODE_ECB);
        parameters.Authorization(keymaster::TAG_BLOCK_MODE, KM_MODE_CBC);
        parameters.Authorization(keymaster::TAG_BLOCK_MODE, KM_MODE_CTR);
    }
    return parameters.build();
}

AuthorizationSet GetHMACParameters(uint32_t key_size, keymaster_digest_t digest) {
    AuthorizationSetBuilder parameters;
    parameters.HmacKey(key_size)
        .Digest(digest)
        .Authorization(keymaster::TAG_MIN_MAC_LENGTH, 224)
        .Authorization(keymaster::TAG_NO_AUTH_REQUIRED);
    return parameters.build();
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
        {"HMAC-SHA256-16", true, GetHMACParameters(16, KM_DIGEST_SHA_2_256)},
        {"HMAC-SHA256-32", true, GetHMACParameters(32, KM_DIGEST_SHA_2_256)},
        {"HMAC-SHA256-64", false, GetHMACParameters(64, KM_DIGEST_SHA_2_256)},
        {"HMAC-SHA224-32", false, GetHMACParameters(32, KM_DIGEST_SHA_2_224)},
        {"HMAC-SHA384-32", false, GetHMACParameters(32, KM_DIGEST_SHA_2_384)},
        {"HMAC-SHA512-32", false, GetHMACParameters(32, KM_DIGEST_SHA_2_512)},
    };
    return std::vector<TestCase>(&test_cases[0], &test_cases[arraysize(test_cases)]);
}

int BrilloPlatformTest(const std::string& prefix) {
    int test_count = 0;
    int fail_count = 0;
    std::vector<TestCase> test_cases = GetTestCases();
    for (const auto& test_case : test_cases) {
        if (!prefix.empty() && test_case.name.find(prefix) != 0) {
            continue;
        }
        ++test_count;
        if (!TestKey(test_case.name, test_case.required_for_brillo_pts, test_case.parameters)) {
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

std::string ReadFile(const std::string& filename) {
    std::string content;
    base::FilePath path(filename);
    if (!base::ReadFileToString(path, &content)) {
        printf("Failed to read file: %s\n", filename.c_str());
        exit(1);
    }
    return content;
}

void WriteFile(const std::string& filename, const std::string& content) {
    base::FilePath path(filename);
    int size = content.size();
    if (base::WriteFile(path, content.data(), size) != size) {
        printf("Failed to write file: %s\n", filename.c_str());
        exit(1);
    }
}

int AddEntropy(const std::string& input) {
    std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
    int32_t result = keystore->addRandomNumberGeneratorEntropy(input);
    printf("AddEntropy: %d\n", result);
    return result;
}

int GenerateKey(const std::string& name) {
    std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
    AuthorizationSetBuilder params;
    params.RsaSigningKey(2048, 65537)
        .Digest(KM_DIGEST_SHA_2_224)
        .Digest(KM_DIGEST_SHA_2_256)
        .Digest(KM_DIGEST_SHA_2_384)
        .Digest(KM_DIGEST_SHA_2_512)
        .Padding(KM_PAD_RSA_PKCS1_1_5_SIGN)
        .Padding(KM_PAD_RSA_PSS)
        .Authorization(keymaster::TAG_NO_AUTH_REQUIRED);
    AuthorizationSet hardware_enforced_characteristics;
    AuthorizationSet software_enforced_characteristics;
    int32_t result = keystore->generateKey(name, params.build(), &hardware_enforced_characteristics,
                                           &software_enforced_characteristics);
    printf("GenerateKey: %d\n", result);
    if (result == KM_ERROR_OK) {
        PrintKeyCharacteristics(hardware_enforced_characteristics,
                                software_enforced_characteristics);
    }
    return result;
}

int GetCharacteristics(const std::string& name) {
    std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
    AuthorizationSet hardware_enforced_characteristics;
    AuthorizationSet software_enforced_characteristics;
    int32_t result = keystore->getKeyCharacteristics(name, &hardware_enforced_characteristics,
                                                     &software_enforced_characteristics);
    printf("GetCharacteristics: %d\n", result);
    if (result == KM_ERROR_OK) {
        PrintKeyCharacteristics(hardware_enforced_characteristics,
                                software_enforced_characteristics);
    }
    return result;
}

int ExportKey(const std::string& name) {
    std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
    std::string data;
    int32_t result = keystore->exportKey(KM_KEY_FORMAT_X509, name, &data);
    printf("ExportKey: %d (%zu)\n", result, data.size());
    return result;
}

int DeleteKey(const std::string& name) {
    std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
    int32_t result = keystore->deleteKey(name);
    printf("DeleteKey: %d\n", result);
    return result;
}

int DeleteAllKeys() {
    std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
    int32_t result = keystore->deleteAllKeys();
    printf("DeleteAllKeys: %d\n", result);
    return result;
}

int DoesKeyExist(const std::string& name) {
    std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
    printf("DoesKeyExist: %s\n", keystore->doesKeyExist(name) ? "yes" : "no");
    return 0;
}

int List(const std::string& prefix) {
    std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
    std::vector<std::string> key_list;
    if (!keystore->listKeys(prefix, &key_list)) {
        printf("ListKeys failed.\n");
        return 1;
    }
    printf("Keys:\n");
    for (const auto& key_name : key_list) {
        printf("  %s\n", key_name.c_str());
    }
    return 0;
}

int SignAndVerify(const std::string& name) {
    std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
    AuthorizationSetBuilder sign_params;
    sign_params.Padding(KM_PAD_RSA_PKCS1_1_5_SIGN);
    sign_params.Digest(KM_DIGEST_SHA_2_256);
    AuthorizationSet output_params;
    keymaster_operation_handle_t handle;
    int32_t result = keystore->beginOperation(KM_PURPOSE_SIGN, name, sign_params.build(),
                                              &output_params, &handle);
    if (result != KM_ERROR_OK) {
        printf("Sign: BeginOperation failed: %d\n", result);
        return result;
    }
    AuthorizationSet empty_params;
    size_t num_input_bytes_consumed;
    std::string output_data;
    result = keystore->updateOperation(handle, empty_params, "data_to_sign",
                                       &num_input_bytes_consumed, &output_params, &output_data);
    if (result != KM_ERROR_OK) {
        printf("Sign: UpdateOperation failed: %d\n", result);
        return result;
    }
    result = keystore->finishOperation(handle, empty_params, std::string() /*signature_to_verify*/,
                                       &output_params, &output_data);
    if (result != KM_ERROR_OK) {
        printf("Sign: FinishOperation failed: %d\n", result);
        return result;
    }
    printf("Sign: %zu bytes.\n", output_data.size());
    // We have a signature, now verify it.
    std::string signature_to_verify = output_data;
    output_data.clear();
    result = keystore->beginOperation(KM_PURPOSE_VERIFY, name, sign_params.build(), &output_params,
                                      &handle);
    if (result != KM_ERROR_OK) {
        printf("Verify: BeginOperation failed: %d\n", result);
        return result;
    }
    result = keystore->updateOperation(handle, empty_params, "data_to_sign",
                                       &num_input_bytes_consumed, &output_params, &output_data);
    if (result != KM_ERROR_OK) {
        printf("Verify: UpdateOperation failed: %d\n", result);
        return result;
    }
    result = keystore->finishOperation(handle, empty_params, signature_to_verify, &output_params,
                                       &output_data);
    if (result == KM_ERROR_VERIFICATION_FAILED) {
        printf("Verify: Failed to verify signature.\n");
        return result;
    }
    if (result != KM_ERROR_OK) {
        printf("Verify: FinishOperation failed: %d\n", result);
        return result;
    }
    printf("Verify: OK\n");
    return 0;
}

int Encrypt(const std::string& key_name, const std::string& input_filename,
            const std::string& output_filename) {
    std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
    std::string input = ReadFile(input_filename);
    std::string output;
    if (!keystore->encryptWithAuthentication(key_name, input, &output)) {
        printf("EncryptWithAuthentication failed.\n");
        return 1;
    }
    WriteFile(output_filename, output);
    return 0;
}

int Decrypt(const std::string& key_name, const std::string& input_filename,
            const std::string& output_filename) {
    std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
    std::string input = ReadFile(input_filename);
    std::string output;
    if (!keystore->decryptWithAuthentication(key_name, input, &output)) {
        printf("DecryptWithAuthentication failed.\n");
        return 1;
    }
    WriteFile(output_filename, output);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    CommandLine::Init(argc, argv);
    CommandLine* command_line = CommandLine::ForCurrentProcess();
    CommandLine::StringVector args = command_line->GetArgs();
    if (args.empty()) {
        PrintUsageAndExit();
    }
    if (args[0] == "brillo-platform-test") {
        return BrilloPlatformTest(command_line->GetSwitchValueASCII("prefix"));
    } else if (args[0] == "list-brillo-tests") {
        return ListTestCases();
    } else if (args[0] == "add-entropy") {
        return AddEntropy(command_line->GetSwitchValueASCII("input"));
    } else if (args[0] == "generate") {
        return GenerateKey(command_line->GetSwitchValueASCII("name"));
    } else if (args[0] == "get-chars") {
        return GetCharacteristics(command_line->GetSwitchValueASCII("name"));
    } else if (args[0] == "export") {
        return ExportKey(command_line->GetSwitchValueASCII("name"));
    } else if (args[0] == "delete") {
        return DeleteKey(command_line->GetSwitchValueASCII("name"));
    } else if (args[0] == "delete-all") {
        return DeleteAllKeys();
    } else if (args[0] == "exists") {
        return DoesKeyExist(command_line->GetSwitchValueASCII("name"));
    } else if (args[0] == "list") {
        return List(command_line->GetSwitchValueASCII("prefix"));
    } else if (args[0] == "sign-verify") {
        return SignAndVerify(command_line->GetSwitchValueASCII("name"));
    } else if (args[0] == "encrypt") {
        return Encrypt(command_line->GetSwitchValueASCII("name"),
                       command_line->GetSwitchValueASCII("in"),
                       command_line->GetSwitchValueASCII("out"));
    } else if (args[0] == "decrypt") {
        return Decrypt(command_line->GetSwitchValueASCII("name"),
                       command_line->GetSwitchValueASCII("in"),
                       command_line->GetSwitchValueASCII("out"));
    } else {
        PrintUsageAndExit();
    }
    return 0;
}
