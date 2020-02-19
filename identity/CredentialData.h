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

#ifndef SYSTEM_SECURITY_CREDENTIAL_DATA_H_
#define SYSTEM_SECURITY_CREDENTIAL_DATA_H_

#include <sys/types.h>
#include <unistd.h>

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <android/hardware/identity/IIdentityCredential.h>
#include <android/hardware/identity/SecureAccessControlProfile.h>

namespace android {
namespace security {
namespace identity {

using ::android::hardware::identity::Certificate;
using ::android::hardware::identity::IIdentityCredential;
using ::android::hardware::identity::SecureAccessControlProfile;
using ::std::map;
using ::std::optional;
using ::std::pair;
using ::std::string;
using ::std::tuple;
using ::std::vector;

struct EntryData {
    EntryData() {}

    uint64_t size = 0;
    vector<int32_t> accessControlProfileIds;
    vector<vector<uint8_t>> encryptedChunks;
};

struct AuthKeyData {
    AuthKeyData() {}

    vector<uint8_t> certificate;
    vector<uint8_t> keyBlob;
    vector<uint8_t> staticAuthenticationData;
    vector<uint8_t> pendingCertificate;
    vector<uint8_t> pendingKeyBlob;
    int useCount = 0;
};

class CredentialData : public RefBase {
  public:
    CredentialData(const string& dataPath, uid_t ownerUid, const string& name);

    static string calculateCredentialFileName(const string& dataPath, uid_t ownerUid,
                                              const string& name);

    static optional<bool> credentialExists(const string& dataPath, uid_t ownerUid,
                                           const string& name);

    void setSecureUserId(int64_t secureUserId);

    void setCredentialData(const vector<uint8_t>& credentialData);

    void setAttestationCertificate(const vector<uint8_t>& attestationCertificate);

    void
    addSecureAccessControlProfile(const SecureAccessControlProfile& secureAccessControlProfile);

    void addEntryData(const string& namespaceName, const string& entryName, const EntryData& data);

    bool saveToDisk() const;

    bool loadFromDisk();

    bool deleteCredential();

    void setAvailableAuthenticationKeys(int keyCount, int maxUsesPerKey);

    // Getters

    int64_t getSecureUserId();

    const vector<uint8_t>& getCredentialData() const;

    const vector<uint8_t>& getAttestationCertificate() const;

    const vector<SecureAccessControlProfile>& getSecureAccessControlProfiles() const;

    bool hasEntryData(const string& namespaceName, const string& entryName) const;

    optional<EntryData> getEntryData(const string& namespaceName, const string& entryName) const;

    const vector<AuthKeyData>& getAuthKeyDatas() const;

    // Returns |nullptr| if a suitable key cannot be found. Otherwise returns
    // the authentication and increases its use-count.
    const AuthKeyData* selectAuthKey(bool allowUsingExhaustedKeys);

    optional<vector<vector<uint8_t>>>
    getAuthKeysNeedingCertification(const sp<IIdentityCredential>& halBinder);

    bool storeStaticAuthenticationData(const vector<uint8_t>& authenticationKey,
                                       const vector<uint8_t>& staticAuthData);

  private:
    // Set by constructor.
    //
    string dataPath_;
    uid_t ownerUid_;
    string name_;

    // Calculated at construction time, from |dataPath_|, |ownerUid_|, |name_|.
    string fileName_;

    // Data serialized in CBOR from here:
    //
    int64_t secureUserId_;
    vector<uint8_t> credentialData_;
    vector<uint8_t> attestationCertificate_;
    vector<SecureAccessControlProfile> secureAccessControlProfiles_;
    map<string, EntryData> idToEncryptedChunks_;

    int keyCount_ = 0;
    int maxUsesPerKey_ = 1;
    vector<AuthKeyData> authKeyDatas_;  // Always |keyCount_| long.
};

}  // namespace identity
}  // namespace security
}  // namespace android

#endif  // SYSTEM_SECURITY_CREDENTIAL_DATA_H_
