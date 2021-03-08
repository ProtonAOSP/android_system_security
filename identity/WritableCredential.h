/*
 * Copyright (c) 2019, The Android Open Source Project
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

#ifndef SYSTEM_SECURITY_WRITABLE_CREDENTIAL_H_
#define SYSTEM_SECURITY_WRITABLE_CREDENTIAL_H_

#include <string>
#include <vector>

#include <android/security/identity/BnWritableCredential.h>

#include <android/hardware/identity/IIdentityCredentialStore.h>

#include "Credential.h"

namespace android {
namespace security {
namespace identity {

using ::android::binder::Status;
using ::android::hardware::identity::HardwareInformation;
using ::android::hardware::identity::IWritableIdentityCredential;
using ::std::string;
using ::std::vector;

class WritableCredential : public BnWritableCredential {
  public:
    WritableCredential(const string& dataPath, const string& credentialName, const string& docType,
                       bool isUpdate, HardwareInformation hwInfo,
                       sp<IWritableIdentityCredential> halBinder);
    ~WritableCredential();

    // Used when updating a credential
    void setAttestationCertificate(const vector<uint8_t>& attestationCertificate);
    void setAvailableAuthenticationKeys(int keyCount, int maxUsesPerKey);

    // Used by Credential::update()
    void setCredentialToReloadWhenUpdated(sp<Credential> credential);

    // IWritableCredential overrides
    Status getCredentialKeyCertificateChain(const vector<uint8_t>& challenge,
                                            vector<uint8_t>* _aidl_return) override;

    Status personalize(const vector<AccessControlProfileParcel>& accessControlProfiles,
                       const vector<EntryNamespaceParcel>& entryNamespaces, int64_t secureUserId,
                       vector<uint8_t>* _aidl_return) override;

  private:
    string dataPath_;
    string credentialName_;
    string docType_;
    bool isUpdate_;
    HardwareInformation hwInfo_;
    sp<IWritableIdentityCredential> halBinder_;

    vector<uint8_t> attestationCertificate_;
    int keyCount_ = 0;
    int maxUsesPerKey_ = 1;

    sp<Credential> credentialToReloadWhenUpdated_;

    ssize_t calcExpectedProofOfProvisioningSize(
        const vector<AccessControlProfileParcel>& accessControlProfiles,
        const vector<EntryNamespaceParcel>& entryNamespaces);

    Status ensureAttestationCertificateExists(const vector<uint8_t>& challenge);
};

}  // namespace identity
}  // namespace security
}  // namespace android

#endif  // SYSTEM_SECURITY_WRITABLE_CREDENTIAL_H_
