/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef KEYSTORE_KEYSTORE_H_
#define KEYSTORE_KEYSTORE_H_

#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>
#include <keymasterV4_0/Keymaster.h>
#include <utils/Vector.h>

#include <keystore/keymaster_types.h>

#include "blob.h"
#include "grant_store.h"
#include "user_state.h"

namespace keystore {

using ::android::sp;
using keymaster::support::Keymaster;

class KeymasterDevices : public std::array<sp<Keymaster>, 3> {
  public:
    sp<Keymaster>& operator[](SecurityLevel secLevel);
    sp<Keymaster> operator[](SecurityLevel secLevel) const;
};

class KeyStore {
  public:
    KeyStore(const KeymasterDevices& kmDevices,
             SecurityLevel minimalAllowedSecurityLevelForNewKeys);
    ~KeyStore();

    sp<Keymaster> getDevice(SecurityLevel securityLevel) const { return mKmDevices[securityLevel]; }

    std::pair<sp<Keymaster>, SecurityLevel> getMostSecureDevice() const {
        SecurityLevel level = SecurityLevel::STRONGBOX;
        do {
            if (mKmDevices[level].get()) {
                return {mKmDevices[level], level};
            }
            level = static_cast<SecurityLevel>(static_cast<uint32_t>(level) - 1);
        } while (level != SecurityLevel::SOFTWARE);
        return {nullptr, SecurityLevel::SOFTWARE};
    }

    sp<Keymaster> getFallbackDevice() const {
        // we only return the fallback device if the creation of new fallback key blobs is
        // allowed. (also see getDevice below)
        if (mAllowNewFallback) {
            return mKmDevices[SecurityLevel::SOFTWARE];
        } else {
            return nullptr;
        }
    }

    sp<Keymaster> getDevice(const Blob& blob) { return mKmDevices[blob.getSecurityLevel()]; }

    ResponseCode initialize();

    State getState(uid_t userId) { return getUserState(userId)->getState(); }

    ResponseCode initializeUser(const android::String8& pw, uid_t userId);

    ResponseCode copyMasterKey(uid_t srcUser, uid_t dstUser);
    ResponseCode writeMasterKey(const android::String8& pw, uid_t userId);
    ResponseCode readMasterKey(const android::String8& pw, uid_t userId);

    android::String8 getKeyName(const android::String8& keyName, const BlobType type);
    android::String8 getKeyNameForUid(const android::String8& keyName, uid_t uid,
                                      const BlobType type);
    android::String8 getKeyNameForUidWithDir(const android::String8& keyName, uid_t uid,
                                             const BlobType type);
    NullOr<android::String8> getBlobFileNameIfExists(const android::String8& alias, uid_t uid,
                                                     const BlobType type);

    /*
     * Delete entries owned by userId. If keepUnencryptedEntries is true
     * then only encrypted entries will be removed, otherwise all entries will
     * be removed.
     */
    void resetUser(uid_t userId, bool keepUnenryptedEntries);
    bool isEmpty(uid_t userId) const;

    void lock(uid_t userId);

    ResponseCode get(const char* filename, Blob* keyBlob, const BlobType type, uid_t userId);
    ResponseCode put(const char* filename, Blob* keyBlob, uid_t userId);
    ResponseCode del(const char* filename, const BlobType type, uid_t userId);
    ResponseCode list(const android::String8& prefix, android::Vector<android::String16>* matches,
                      uid_t userId);

    std::string addGrant(const char* alias, uid_t granterUid, uid_t granteeUid);
    bool removeGrant(const char* alias, const uid_t granterUid, const uid_t granteeUid);
    void removeAllGrantsToUid(const uid_t granteeUid);

    ResponseCode importKey(const uint8_t* key, size_t keyLen, const char* filename, uid_t userId,
                           int32_t flags);

    bool isHardwareBacked(const android::String16& keyType) const;

    ResponseCode getKeyForName(Blob* keyBlob, const android::String8& keyName, const uid_t uid,
                               const BlobType type);

    /**
     * Returns any existing UserState or creates it if it doesn't exist.
     */
    UserState* getUserState(uid_t userId);

    /**
     * Returns any existing UserState or creates it if it doesn't exist.
     */
    UserState* getUserStateByUid(uid_t uid);

    /**
     * Returns NULL if the UserState doesn't already exist.
     */
    const UserState* getUserState(uid_t userId) const;

    /**
     * Returns NULL if the UserState doesn't already exist.
     */
    const UserState* getUserStateByUid(uid_t uid) const;

  private:
    static const char* kOldMasterKey;
    static const char* kMetaDataFile;
    static const android::String16 kRsaKeyType;
    static const android::String16 kEcKeyType;

    KeymasterDevices mKmDevices;
    bool mAllowNewFallback;

    android::Vector<UserState*> mMasterKeys;

    ::keystore::GrantStore mGrants;

    typedef struct { uint32_t version; } keystore_metadata_t;

    keystore_metadata_t mMetaData;

    /**
     * Upgrade the key from the current version to whatever is newest.
     */
    bool upgradeBlob(const char* filename, Blob* blob, const uint8_t oldVersion,
                     const BlobType type, uid_t uid);

    /**
     * Takes a blob that is an PEM-encoded RSA key as a byte array and converts it to a DER-encoded
     * PKCS#8 for import into a keymaster.  Then it overwrites the original blob with the new blob
     * format that is returned from the keymaster.
     */
    ResponseCode importBlobAsKey(Blob* blob, const char* filename, uid_t uid);

    void readMetaData();
    void writeMetaData();

    bool upgradeKeystore();
};

}  // namespace keystore

#endif  // KEYSTORE_KEYSTORE_H_
