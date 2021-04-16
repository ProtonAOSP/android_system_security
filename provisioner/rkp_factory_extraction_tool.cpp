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
#include <keymaster/cppcose/cppcose.h>
#include <log/log.h>
#include <vintf/VintfObject.h>

using std::set;
using std::string;
using std::vector;

using aidl::android::hardware::security::keymint::DeviceInfo;
using aidl::android::hardware::security::keymint::IRemotelyProvisionedComponent;
using aidl::android::hardware::security::keymint::MacedPublicKey;
using aidl::android::hardware::security::keymint::ProtectedData;

using android::vintf::HalManifest;
using android::vintf::VintfObject;

using namespace cppbor;
using namespace cppcose;

namespace {

const string kPackage = "android.hardware.security.keymint";
const string kInterface = "IRemotelyProvisionedComponent";
const string kFormattedName = kPackage + "." + kInterface + "/";

ErrMsgOr<vector<uint8_t>> generateEekChain(size_t length, const vector<uint8_t>& eekId) {
    auto eekChain = cppbor::Array();

    vector<uint8_t> prevPrivKey;
    for (size_t i = 0; i < length - 1; ++i) {
        vector<uint8_t> pubKey(ED25519_PUBLIC_KEY_LEN);
        vector<uint8_t> privKey(ED25519_PRIVATE_KEY_LEN);

        ED25519_keypair(pubKey.data(), privKey.data());

        // The first signing key is self-signed.
        if (prevPrivKey.empty()) prevPrivKey = privKey;

        auto coseSign1 = constructCoseSign1(prevPrivKey,
                                            cppbor::Map() /* payload CoseKey */
                                                .add(CoseKey::KEY_TYPE, OCTET_KEY_PAIR)
                                                .add(CoseKey::ALGORITHM, EDDSA)
                                                .add(CoseKey::CURVE, ED25519)
                                                .add(CoseKey::PUBKEY_X, pubKey)
                                                .canonicalize()
                                                .encode(),
                                            {} /* AAD */);
        if (!coseSign1) return coseSign1.moveMessage();
        eekChain.add(coseSign1.moveValue());

        prevPrivKey = privKey;
    }

    vector<uint8_t> pubKey(X25519_PUBLIC_VALUE_LEN);
    vector<uint8_t> privKey(X25519_PRIVATE_KEY_LEN);
    X25519_keypair(pubKey.data(), privKey.data());

    auto coseSign1 = constructCoseSign1(prevPrivKey,
                                        cppbor::Map() /* payload CoseKey */
                                            .add(CoseKey::KEY_TYPE, OCTET_KEY_PAIR)
                                            .add(CoseKey::KEY_ID, eekId)
                                            .add(CoseKey::ALGORITHM, ECDH_ES_HKDF_256)
                                            .add(CoseKey::CURVE, cppcose::X25519)
                                            .add(CoseKey::PUBKEY_X, pubKey)
                                            .canonicalize()
                                            .encode(),
                                        {} /* AAD */);
    if (!coseSign1) return coseSign1.moveMessage();
    eekChain.add(coseSign1.moveValue());

    return eekChain.encode();
}

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

}  // namespace

int main() {
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

        // Replace this eek chain generation with the actual production GEEK
        std::vector<uint8_t> eekId(10);  // replace with real KID later (EEK fingerprint)
        auto eekOrErr = generateEekChain(3 /* chainlength */, eekId);
        if (!eekOrErr) {
            ALOGE("Failed to generate test EEK somehow: %s", eekOrErr.message().c_str());
            return errorMsg(name);
        }

        std::vector<uint8_t> eek = eekOrErr.moveValue();
        DeviceInfo deviceInfo;
        ProtectedData protectedData;
        if (rkp_service) {
            ALOGE("extracting bundle");
            ::ndk::ScopedAStatus status = rkp_service->generateCertificateRequest(
                true /* testMode */, emptyKeys, eek, getChallenge(), &deviceInfo, &protectedData,
                &keysToSignMac);
            if (!status.isOk()) {
                ALOGE("Bundle extraction failed. Error code: %d", status.getServiceSpecificError());
                return errorMsg(name);
            }
            std::cout << "\n";
            std::vector<uint8_t> certificateRequest =
                composeCertificateRequest(std::move(protectedData), std::move(deviceInfo));
            std::copy(certificateRequest.begin(), certificateRequest.end(),
                      std::ostream_iterator<char>(std::cout));
        }
    }
}
