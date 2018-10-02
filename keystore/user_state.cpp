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

#define LOG_TAG "keystore"

#include "user_state.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <openssl/evp.h>

#include <log/log.h>

#include "blob.h"
#include "keystore_utils.h"


UserState::UserState(uid_t userId) :
        mUserId(userId), mState(STATE_UNINITIALIZED), mRetry(MAX_RETRY) {
    asprintf(&mUserDir, "user_%u", mUserId);
    asprintf(&mMasterKeyFile, "%s/.masterkey", mUserDir);
}

UserState::~UserState() {
    free(mUserDir);
    free(mMasterKeyFile);
}

bool UserState::initialize() {
    if ((mkdir(mUserDir, S_IRUSR | S_IWUSR | S_IXUSR) < 0) && (errno != EEXIST)) {
        ALOGE("Could not create directory '%s'", mUserDir);
        return false;
    }

    if (access(mMasterKeyFile, R_OK) == 0) {
        setState(STATE_LOCKED);
    } else {
        setState(STATE_UNINITIALIZED);
    }

    return true;
}

void UserState::setState(State state) {
    mState = state;
    if (mState == STATE_NO_ERROR || mState == STATE_UNINITIALIZED) {
        mRetry = MAX_RETRY;
    }
}

void UserState::zeroizeMasterKeysInMemory() {
    memset(mMasterKey, 0, sizeof(mMasterKey));
    memset(mSalt, 0, sizeof(mSalt));
}

bool UserState::deleteMasterKey() {
    setState(STATE_UNINITIALIZED);
    zeroizeMasterKeysInMemory();
    return unlink(mMasterKeyFile) == 0 || errno == ENOENT;
}

ResponseCode UserState::initialize(const android::String8& pw, Entropy* entropy) {
    if (!generateMasterKey(entropy)) {
        return ResponseCode::SYSTEM_ERROR;
    }
    ResponseCode response = writeMasterKey(pw, entropy);
    if (response != ResponseCode::NO_ERROR) {
        return response;
    }
    setupMasterKeys();
    return ResponseCode::NO_ERROR;
}

ResponseCode UserState::copyMasterKey(UserState* src) {
    if (mState != STATE_UNINITIALIZED) {
        return ResponseCode::SYSTEM_ERROR;
    }
    if (src->getState() != STATE_NO_ERROR) {
        return ResponseCode::SYSTEM_ERROR;
    }
    memcpy(mMasterKey, src->mMasterKey, MASTER_KEY_SIZE_BYTES);
    setupMasterKeys();
    return copyMasterKeyFile(src);
}

ResponseCode UserState::copyMasterKeyFile(UserState* src) {
    /* Copy the master key file to the new user.  Unfortunately we don't have the src user's
     * password so we cannot generate a new file with a new salt.
     */
    int in = TEMP_FAILURE_RETRY(open(src->getMasterKeyFileName(), O_RDONLY));
    if (in < 0) {
        return ResponseCode::SYSTEM_ERROR;
    }
    blobv3 rawBlob;
    size_t length = readFully(in, (uint8_t*)&rawBlob, sizeof(rawBlob));
    if (close(in) != 0) {
        return ResponseCode::SYSTEM_ERROR;
    }
    int out =
        TEMP_FAILURE_RETRY(open(mMasterKeyFile, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR));
    if (out < 0) {
        return ResponseCode::SYSTEM_ERROR;
    }
    size_t outLength = writeFully(out, (uint8_t*)&rawBlob, length);
    if (close(out) != 0) {
        return ResponseCode::SYSTEM_ERROR;
    }
    if (outLength != length) {
        ALOGW("blob not fully written %zu != %zu", outLength, length);
        unlink(mMasterKeyFile);
        return ResponseCode::SYSTEM_ERROR;
    }
    return ResponseCode::NO_ERROR;
}

ResponseCode UserState::writeMasterKey(const android::String8& pw, Entropy* entropy) {
    uint8_t passwordKey[MASTER_KEY_SIZE_BYTES];
    generateKeyFromPassword(passwordKey, MASTER_KEY_SIZE_BYTES, pw, mSalt);
    Blob masterKeyBlob(mMasterKey, sizeof(mMasterKey), mSalt, sizeof(mSalt), TYPE_MASTER_KEY);
    return masterKeyBlob.writeBlob(mMasterKeyFile, passwordKey, STATE_NO_ERROR, entropy);
}

ResponseCode UserState::readMasterKey(const android::String8& pw, Entropy* entropy) {
    int in = TEMP_FAILURE_RETRY(open(mMasterKeyFile, O_RDONLY));
    if (in < 0) {
        return ResponseCode::SYSTEM_ERROR;
    }

    // We read the raw blob to just to get the salt to generate the AES key, then we create the Blob
    // to use with decryptBlob
    blobv3 rawBlob;
    size_t length = readFully(in, (uint8_t*)&rawBlob, sizeof(rawBlob));
    if (close(in) != 0) {
        return ResponseCode::SYSTEM_ERROR;
    }
    // find salt at EOF if present, otherwise we have an old file
    uint8_t* salt;
    if (length > SALT_SIZE && rawBlob.info == SALT_SIZE) {
        salt = (uint8_t*)&rawBlob + length - SALT_SIZE;
    } else {
        salt = nullptr;
    }
    uint8_t passwordKey[MASTER_KEY_SIZE_BYTES];
    generateKeyFromPassword(passwordKey, MASTER_KEY_SIZE_BYTES, pw, salt);
    Blob masterKeyBlob(rawBlob);
    ResponseCode response = masterKeyBlob.readBlob(mMasterKeyFile, passwordKey, STATE_NO_ERROR);
    if (response == ResponseCode::SYSTEM_ERROR) {
        return response;
    }
    if (response == ResponseCode::NO_ERROR && masterKeyBlob.getLength() == MASTER_KEY_SIZE_BYTES) {
        // If salt was missing, generate one and write a new master key file with the salt.
        if (salt == nullptr) {
            if (!generateSalt(entropy)) {
                return ResponseCode::SYSTEM_ERROR;
            }
            response = writeMasterKey(pw, entropy);
        }
        if (response == ResponseCode::NO_ERROR) {
            memcpy(mMasterKey, masterKeyBlob.getValue(), MASTER_KEY_SIZE_BYTES);
            setupMasterKeys();
        }
        return response;
    }
    if (mRetry <= 0) {
        reset();
        return ResponseCode::UNINITIALIZED;
    }
    --mRetry;
    switch (mRetry) {
    case 0:
        return ResponseCode::WRONG_PASSWORD_0;
    case 1:
        return ResponseCode::WRONG_PASSWORD_1;
    case 2:
        return ResponseCode::WRONG_PASSWORD_2;
    case 3:
        return ResponseCode::WRONG_PASSWORD_3;
    default:
        return ResponseCode::WRONG_PASSWORD_3;
    }
}

bool UserState::reset() {
    DIR* dir = opendir(getUserDirName());
    if (!dir) {
        // If the directory doesn't exist then nothing to do.
        if (errno == ENOENT) {
            return true;
        }
        ALOGW("couldn't open user directory: %s", strerror(errno));
        return false;
    }

    struct dirent* file;
    while ((file = readdir(dir)) != nullptr) {
        // skip . and ..
        if (!strcmp(".", file->d_name) || !strcmp("..", file->d_name)) {
            continue;
        }

        unlinkat(dirfd(dir), file->d_name, 0);
    }
    closedir(dir);
    return true;
}

void UserState::generateKeyFromPassword(uint8_t* key, ssize_t keySize, const android::String8& pw,
                                        uint8_t* salt) {
    size_t saltSize;
    if (salt != nullptr) {
        saltSize = SALT_SIZE;
    } else {
        // Pre-gingerbread used this hardwired salt, readMasterKey will rewrite these when found
        salt = (uint8_t*)"keystore";
        // sizeof = 9, not strlen = 8
        saltSize = sizeof("keystore");
    }

    PKCS5_PBKDF2_HMAC_SHA1(reinterpret_cast<const char*>(pw.string()), pw.length(), salt, saltSize,
                           8192, keySize, key);
}

bool UserState::generateSalt(Entropy* entropy) {
    return entropy->generate_random_data(mSalt, sizeof(mSalt));
}

bool UserState::generateMasterKey(Entropy* entropy) {
    if (!entropy->generate_random_data(mMasterKey, sizeof(mMasterKey))) {
        return false;
    }
    if (!generateSalt(entropy)) {
        return false;
    }
    return true;
}

void UserState::setupMasterKeys() {
    setState(STATE_NO_ERROR);
}
