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
#include <log/log.h>
#include <remote_prov/remote_prov_utils.h>
#include <vintf/VintfObject.h>

using std::set;
using std::string;
using std::vector;

using aidl::android::hardware::security::keymint::DeviceInfo;
using aidl::android::hardware::security::keymint::IRemotelyProvisionedComponent;
using aidl::android::hardware::security::keymint::MacedPublicKey;
using aidl::android::hardware::security::keymint::ProtectedData;
using aidl::android::hardware::security::keymint::remote_prov::generateEekChain;
using aidl::android::hardware::security::keymint::remote_prov::getProdEekChain;

using android::vintf::HalManifest;
using android::vintf::VintfObject;

using namespace cppbor;
using namespace cppcose;

DEFINE_bool(test_mode, false, "If enabled, a fake EEK key/cert are used.");

namespace {

const string kPackage = "android.hardware.security.keymint";
const string kInterface = "IRemotelyProvisionedComponent";
const string kFormattedName = kPackage + "." + kInterface + "/";

std::vector<uint8_t> getChallenge() {
    return std::vector<uint8_t>(0);
}

std::vector<uint8_t> composeCertificateRequest(ProtectedData&& protectedData,
                                               DeviceInfo&& deviceInfo) {
    Array emptyMacedKeysToSign;
    emptyMacedKeysToSign
        .add(std::vector<uint8_t>(0))   // empty protected headers as bstr
        .add(Map())                     // empty unprotected headers
        .add(Null())                    // nil for the payload
        .add(std::vector<uint8_t>(0));  // empty tag as bstr
    Array certificateRequest;
    certificateRequest.add(EncodedItem(std::move(deviceInfo.deviceInfo)))
        .add(getChallenge())  // fake challenge
        .add(EncodedItem(std::move(protectedData.protectedData)))
        .add(std::move(emptyMacedKeysToSign));
    return certificateRequest.encode();
}

int32_t errorMsg(string name) {
    std::cerr << "Failed for rkp instance: " << name;
    return -1;
}

std::vector<uint8_t> getEekChain() {
    if (FLAGS_test_mode) {
        const std::vector<uint8_t> kFakeEekId = {'f', 'a', 'k', 'e', 0};
        auto eekOrErr = generateEekChain(3 /* chainlength */, kFakeEekId);
        LOG_FATAL_IF(!eekOrErr, "Failed to generate test EEK somehow: %s",
                     eekOrErr.message().c_str());
        auto [eek, ignored_pubkey, ignored_privkey] = eekOrErr.moveValue();
        return eek;
    }

    return getProdEekChain();
}

}  // namespace

int main(int argc, char** argv) {
    gflags::ParseCommandLineFlags(&argc, &argv, /*remove_flags=*/true);

    const std::vector<uint8_t> eek_chain = getEekChain();

    std::shared_ptr<const HalManifest> manifest = VintfObject::GetDeviceHalManifest();
    set<string> rkpNames = manifest->getAidlInstances(kPackage, kInterface);
    for (auto name : rkpNames) {
        string fullName = kFormattedName + name;
        if (!AServiceManager_isDeclared(fullName.c_str())) {
            ALOGE("Could not find the following instance declared in the manifest: %s\n",
                  fullName.c_str());
            return errorMsg(name);
        }
        AIBinder* rkpAiBinder = AServiceManager_getService(fullName.c_str());
        ::ndk::SpAIBinder rkp_binder(rkpAiBinder);
        auto rkp_service = IRemotelyProvisionedComponent::fromBinder(rkp_binder);
        std::vector<uint8_t> keysToSignMac;
        std::vector<MacedPublicKey> emptyKeys;

        DeviceInfo deviceInfo;
        ProtectedData protectedData;
        if (rkp_service) {
            ALOGE("extracting bundle");
            ::ndk::ScopedAStatus status = rkp_service->generateCertificateRequest(
                FLAGS_test_mode, emptyKeys, eek_chain, getChallenge(), &deviceInfo, &protectedData,
                &keysToSignMac);
            if (!status.isOk()) {
                ALOGE("Bundle extraction failed. Error code: %d", status.getServiceSpecificError());
                return errorMsg(name);
            }
            std::vector<uint8_t> certificateRequest =
                composeCertificateRequest(std::move(protectedData), std::move(deviceInfo));
            std::copy(certificateRequest.begin(), certificateRequest.end(),
                      std::ostream_iterator<char>(std::cout));
        }
    }
}
