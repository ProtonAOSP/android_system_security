/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <cutils/log.h>

#include "blob.h"
#include "entropy.h"

#include "keystore_utils.h"

Blob::Blob(const uint8_t* value, size_t valueLength, const uint8_t* info, uint8_t infoLength,
           BlobType type) {
    memset(&mBlob, 0, sizeof(mBlob));
    if (valueLength > VALUE_SIZE) {
        valueLength = VALUE_SIZE;
        ALOGW("Provided blob length too large");
    }
    if (infoLength + valueLength > VALUE_SIZE) {
        infoLength = VALUE_SIZE - valueLength;
        ALOGW("Provided info length too large");
    }
    mBlob.length = valueLength;
    memcpy(mBlob.value, value, valueLength);

    mBlob.info = infoLength;
    memcpy(mBlob.value + valueLength, info, infoLength);

    mBlob.version = CURRENT_BLOB_VERSION;
    mBlob.type = uint8_t(type);

    if (type == TYPE_MASTER_KEY) {
        mBlob.flags = KEYSTORE_FLAG_ENCRYPTED;
    } else {
        mBlob.flags = KEYSTORE_FLAG_NONE;
    }
}

Blob::Blob(blob b) {
    mBlob = b;
}

Blob::Blob() {
    memset(&mBlob, 0, sizeof(mBlob));
}

bool Blob::isEncrypted() const {
    if (mBlob.version < 2) {
        return true;
    }

    return mBlob.flags & KEYSTORE_FLAG_ENCRYPTED;
}

void Blob::setEncrypted(bool encrypted) {
    if (encrypted) {
        mBlob.flags |= KEYSTORE_FLAG_ENCRYPTED;
    } else {
        mBlob.flags &= ~KEYSTORE_FLAG_ENCRYPTED;
    }
}

void Blob::setFallback(bool fallback) {
    if (fallback) {
        mBlob.flags |= KEYSTORE_FLAG_FALLBACK;
    } else {
        mBlob.flags &= ~KEYSTORE_FLAG_FALLBACK;
    }
}

ResponseCode Blob::writeBlob(const char* filename, AES_KEY* aes_key, State state,
                             Entropy* entropy) {
    ALOGV("writing blob %s", filename);
    if (isEncrypted()) {
        if (state != STATE_NO_ERROR) {
            ALOGD("couldn't insert encrypted blob while not unlocked");
            return LOCKED;
        }

        if (!entropy->generate_random_data(mBlob.vector, AES_BLOCK_SIZE)) {
            ALOGW("Could not read random data for: %s", filename);
            return SYSTEM_ERROR;
        }
    }

    // data includes the value and the value's length
    size_t dataLength = mBlob.length + sizeof(mBlob.length);
    // pad data to the AES_BLOCK_SIZE
    size_t digestedLength = ((dataLength + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE);
    // encrypted data includes the digest value
    size_t encryptedLength = digestedLength + MD5_DIGEST_LENGTH;
    // move info after space for padding
    memmove(&mBlob.encrypted[encryptedLength], &mBlob.value[mBlob.length], mBlob.info);
    // zero padding area
    memset(mBlob.value + mBlob.length, 0, digestedLength - dataLength);

    mBlob.length = htonl(mBlob.length);

    if (isEncrypted()) {
        MD5(mBlob.digested, digestedLength, mBlob.digest);

        uint8_t vector[AES_BLOCK_SIZE];
        memcpy(vector, mBlob.vector, AES_BLOCK_SIZE);
        AES_cbc_encrypt(mBlob.encrypted, mBlob.encrypted, encryptedLength, aes_key, vector,
                        AES_ENCRYPT);
    }

    size_t headerLength = (mBlob.encrypted - (uint8_t*)&mBlob);
    size_t fileLength = encryptedLength + headerLength + mBlob.info;

    const char* tmpFileName = ".tmp";
    int out =
        TEMP_FAILURE_RETRY(open(tmpFileName, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR));
    if (out < 0) {
        ALOGW("could not open file: %s: %s", tmpFileName, strerror(errno));
        return SYSTEM_ERROR;
    }
    size_t writtenBytes = writeFully(out, (uint8_t*)&mBlob, fileLength);
    if (close(out) != 0) {
        return SYSTEM_ERROR;
    }
    if (writtenBytes != fileLength) {
        ALOGW("blob not fully written %zu != %zu", writtenBytes, fileLength);
        unlink(tmpFileName);
        return SYSTEM_ERROR;
    }
    if (rename(tmpFileName, filename) == -1) {
        ALOGW("could not rename blob to %s: %s", filename, strerror(errno));
        return SYSTEM_ERROR;
    }
    return NO_ERROR;
}

ResponseCode Blob::readBlob(const char* filename, AES_KEY* aes_key, State state) {
    ALOGV("reading blob %s", filename);
    int in = TEMP_FAILURE_RETRY(open(filename, O_RDONLY));
    if (in < 0) {
        return (errno == ENOENT) ? KEY_NOT_FOUND : SYSTEM_ERROR;
    }
    // fileLength may be less than sizeof(mBlob) since the in
    // memory version has extra padding to tolerate rounding up to
    // the AES_BLOCK_SIZE
    size_t fileLength = readFully(in, (uint8_t*)&mBlob, sizeof(mBlob));
    if (close(in) != 0) {
        return SYSTEM_ERROR;
    }

    if (fileLength == 0) {
        return VALUE_CORRUPTED;
    }

    if (isEncrypted() && (state != STATE_NO_ERROR)) {
        return LOCKED;
    }

    size_t headerLength = (mBlob.encrypted - (uint8_t*)&mBlob);
    if (fileLength < headerLength) {
        return VALUE_CORRUPTED;
    }

    ssize_t encryptedLength = fileLength - (headerLength + mBlob.info);
    if (encryptedLength < 0) {
        return VALUE_CORRUPTED;
    }

    ssize_t digestedLength;
    if (isEncrypted()) {
        if (encryptedLength % AES_BLOCK_SIZE != 0) {
            return VALUE_CORRUPTED;
        }

        AES_cbc_encrypt(mBlob.encrypted, mBlob.encrypted, encryptedLength, aes_key, mBlob.vector,
                        AES_DECRYPT);
        digestedLength = encryptedLength - MD5_DIGEST_LENGTH;
        uint8_t computedDigest[MD5_DIGEST_LENGTH];
        MD5(mBlob.digested, digestedLength, computedDigest);
        if (memcmp(mBlob.digest, computedDigest, MD5_DIGEST_LENGTH) != 0) {
            return VALUE_CORRUPTED;
        }
    } else {
        digestedLength = encryptedLength;
    }

    ssize_t maxValueLength = digestedLength - sizeof(mBlob.length);
    mBlob.length = ntohl(mBlob.length);
    if (mBlob.length < 0 || mBlob.length > maxValueLength) {
        return VALUE_CORRUPTED;
    }
    if (mBlob.info != 0) {
        // move info from after padding to after data
        memmove(&mBlob.value[mBlob.length], &mBlob.value[maxValueLength], mBlob.info);
    }
    return ::NO_ERROR;
}
