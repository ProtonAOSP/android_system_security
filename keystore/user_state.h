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

#ifndef KEYSTORE_USER_STATE_H_
#define KEYSTORE_USER_STATE_H_

#include <sys/types.h>

#include <openssl/aes.h>

#include <utils/String8.h>

#include <keystore/keystore.h>
#include <vector>

class UserState {
  public:
    explicit UserState(uid_t userId);
    ~UserState();

    bool initialize();

    uid_t getUserId() const { return mUserId; }
    const char* getUserDirName() const { return mUserDir; }

    const char* getMasterKeyFileName() const { return mMasterKeyFile; }

    void setState(State state);
    State getState() const { return mState; }

    int8_t getRetry() const { return mRetry; }

    void zeroizeMasterKeysInMemory();
    bool deleteMasterKey();

    ResponseCode initialize(const android::String8& pw);

    ResponseCode copyMasterKey(UserState* src);
    ResponseCode copyMasterKeyFile(UserState* src);
    ResponseCode writeMasterKey(const android::String8& pw);
    ResponseCode readMasterKey(const android::String8& pw);

    const std::vector<uint8_t>& getEncryptionKey() const { return mMasterKey; }

    bool reset();

  private:
    static const int SHA1_DIGEST_SIZE_BYTES = 16;
    static const int SHA256_DIGEST_SIZE_BYTES = 32;

    static const int MASTER_KEY_SIZE_BYTES = SHA256_DIGEST_SIZE_BYTES;
    static const int MASTER_KEY_SIZE_BITS = MASTER_KEY_SIZE_BYTES * 8;

    static const int MAX_RETRY = 4;
    static const size_t SALT_SIZE = 16;

    void generateKeyFromPassword(std::vector<uint8_t>& key, const android::String8& pw,
                                 uint8_t* salt);
    bool generateSalt();
    bool generateMasterKey();
    void setupMasterKeys();

    uid_t mUserId;

    char* mUserDir;
    char* mMasterKeyFile;

    State mState;
    int8_t mRetry;

    std::vector<uint8_t> mMasterKey;
    uint8_t mSalt[SALT_SIZE];
};

#endif  // KEYSTORE_USER_STATE_H_
