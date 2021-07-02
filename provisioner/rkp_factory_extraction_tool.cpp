/*
 * Copyright 2021 The Android Open Source Project
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

#include <string>
#include <vector>

#include <aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.h>
#include <android/binder_manager.h>
#include <cppbor.h>
#include <gflags/gflags.h>
#include <keymaster/cppcose/cppcose.h>
#include <remote_prov/remote_prov_utils.h>
#include <sys/random.h>

using aidl::android::hardware::security::keymint::DeviceInfo;
using aidl::android::hardware::security::keymint::IRemotelyProvisionedComponent;
using aidl::android::hardware::security::keymint::MacedPublicKey;
using aidl::android::hardware::security::keymint::ProtectedData;
using aidl::android::hardware::security::keymint::remote_prov::generateEekChain;
using aidl::android::hardware::security::keymint::remote_prov::getProdEekChain;
using aidl::android::hardware::security::keymint::remote_prov::jsonEncodeCsrWithBuild;

using namespace cppbor;
using namespace cppcose;

DEFINE_bool(test_mode, false, "If enabled, a fake EEK key/cert are used.");

DEFINE_string(output_format, "csr", "How to format the output. Defaults to 'csr'.");

namespace {

// Various supported --output_format values.
constexpr std::string_view kBinaryCsrOutput = "csr";     // Just the raw csr as binary
constexpr std::string_view kBuildPlusCsr = "build+csr";  // Text-encoded (JSON) build
                                                         // fingerprint plus CSR.

constexpr size_t kChallengeSize = 16;

std::vector<uint8_t> generateChallenge() {
    std::vector<uint8_t> challenge(kChallengeSize);

    ssize_t bytesRemaining = static_cast<ssize_t>(challenge.size());
    uint8_t* writePtr = challenge.data();
    while (bytesRemaining > 0) {
        int bytesRead = getrandom(writePtr, bytesRemaining, /*flags=*/0);
        if (bytesRead < 0 && errno != EINTR) {
            std::cerr << errno << ": " << strerror(errno) << std::endl;
            exit(-1);
        }
        bytesRemaining -= bytesRead;
        writePtr += bytesRead;
    }

    return challenge;
}

Array composeCertificateRequest(ProtectedData&& protectedData, DeviceInfo&& deviceInfo,
                                const std::vector<uint8_t>& challenge) {
    Array emptyMacedKeysToSign;
    emptyMacedKeysToSign
        .add(std::vector<uint8_t>(0))   // empty protected headers as bstr
        .add(Map())                     // empty unprotected headers
        .add(Null())                    // nil for the payload
        .add(std::vector<uint8_t>(0));  // empty tag as bstr
    Array certificateRequest;
    certificateRequest.add(EncodedItem(std::move(deviceInfo.deviceInfo)))
        .add(challenge)
        .add(EncodedItem(std::move(protectedData.protectedData)))
        .add(std::move(emptyMacedKeysToSign));
    return certificateRequest;
}

std::vector<uint8_t> getEekChain() {
    if (FLAGS_test_mode) {
        const std::vector<uint8_t> kFakeEekId = {'f', 'a', 'k', 'e', 0};
        auto eekOrErr = generateEekChain(3 /* chainlength */, kFakeEekId);
        if (!eekOrErr) {
            std::cerr << "Failed to generate test EEK somehow: " << eekOrErr.message() << std::endl;
            exit(-1);
        }
        auto [eek, ignored_pubkey, ignored_privkey] = eekOrErr.moveValue();
        return eek;
    }

    return getProdEekChain();
}

void writeOutput(const Array& csr) {
    if (FLAGS_output_format == kBinaryCsrOutput) {
        auto bytes = csr.encode();
        std::copy(bytes.begin(), bytes.end(), std::ostream_iterator<char>(std::cout));
    } else if (FLAGS_output_format == kBuildPlusCsr) {
        auto [json, error] = jsonEncodeCsrWithBuild(csr);
        if (!error.empty()) {
            std::cerr << "Error JSON encoding the output: " << error;
            exit(1);
        }
        std::cout << json << std::endl;
    } else {
        std::cerr << "Unexpected output_format '" << FLAGS_output_format << "'" << std::endl;
        std::cerr << "Valid formats:" << std::endl;
        std::cerr << "  " << kBinaryCsrOutput << std::endl;
        std::cerr << "  " << kBuildPlusCsr << std::endl;
        exit(1);
    }
}

// Callback for AServiceManager_forEachDeclaredInstance that writes out a CSR
// for every IRemotelyProvisionedComponent.
void getCsrForInstance(const char* name, void* /*context*/) {
    const std::vector<uint8_t> challenge = generateChallenge();

    auto fullName = std::string(IRemotelyProvisionedComponent::descriptor) + "/" + name;
    AIBinder* rkpAiBinder = AServiceManager_getService(fullName.c_str());
    ::ndk::SpAIBinder rkp_binder(rkpAiBinder);
    auto rkp_service = IRemotelyProvisionedComponent::fromBinder(rkp_binder);
    if (!rkp_service) {
        std::cerr << "Unable to get binder object for '" << fullName << "', skipping.";
        return;
    }

    std::vector<uint8_t> keysToSignMac;
    std::vector<MacedPublicKey> emptyKeys;
    DeviceInfo deviceInfo;
    ProtectedData protectedData;
    ::ndk::ScopedAStatus status = rkp_service->generateCertificateRequest(
        FLAGS_test_mode, emptyKeys, getEekChain(), challenge, &deviceInfo, &protectedData,
        &keysToSignMac);
    if (!status.isOk()) {
        std::cerr << "Bundle extraction failed for '" << fullName
                  << "'. Error code: " << status.getServiceSpecificError() << "." << std::endl;
        exit(-1);
    }
    writeOutput(
        composeCertificateRequest(std::move(protectedData), std::move(deviceInfo), challenge));
}

}  // namespace

int main(int argc, char** argv) {
    gflags::ParseCommandLineFlags(&argc, &argv, /*remove_flags=*/true);

    AServiceManager_forEachDeclaredInstance(IRemotelyProvisionedComponent::descriptor,
                                            /*context=*/nullptr, getCsrForInstance);

    return 0;
}
