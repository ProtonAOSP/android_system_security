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

#include "user_state.h"

#include <hardware/keymaster2.h>

#include <utils/Vector.h>

#include "blob.h"

typedef struct {
    uint32_t uid;
    const uint8_t* filename;
} grant_t;

class KeyStore {
  public:
    KeyStore(Entropy* entropy, keymaster2_device_t* device, keymaster2_device_t* fallback);
    ~KeyStore();

    keymaster2_device_t* getDevice() const { return mDevice; }

    keymaster2_device_t* getFallbackDevice() const { return mFallbackDevice; }

    keymaster2_device_t* getDeviceForBlob(const Blob& blob) const {
        return blob.isFallback() ? mFallbackDevice : mDevice;
    }

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

    void addGrant(const char* filename, uid_t granteeUid);
    bool removeGrant(const char* filename, uid_t granteeUid);
    bool hasGrant(const char* filename, const uid_t uid) const {
        return getGrant(filename, uid) != NULL;
    }

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
    static const char* sOldMasterKey;
    static const char* sMetaDataFile;
    static const android::String16 sRSAKeyType;
    Entropy* mEntropy;

    keymaster2_device_t* mDevice;
    keymaster2_device_t* mFallbackDevice;

    android::Vector<UserState*> mMasterKeys;

    android::Vector<grant_t*> mGrants;

    typedef struct { uint32_t version; } keystore_metadata_t;

    keystore_metadata_t mMetaData;

    const grant_t* getGrant(const char* filename, uid_t uid) const;

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

#endif  // KEYSTORE_KEYSTORE_H_
