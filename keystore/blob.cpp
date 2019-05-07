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
#include <openssl/rand.h>
#include <string.h>

#include <cutils/log.h>

#include "blob.h"

#include "keystore_utils.h"

namespace {

constexpr size_t kGcmIvSizeBytes = 96 / 8;

template <typename T, void (*FreeFunc)(T*)> struct OpenSslObjectDeleter {
    void operator()(T* p) { FreeFunc(p); }
};

#define DEFINE_OPENSSL_OBJECT_POINTER(name)                                                        \
    typedef OpenSslObjectDeleter<name, name##_free> name##_Delete;                                 \
    typedef std::unique_ptr<name, name##_Delete> name##_Ptr;

DEFINE_OPENSSL_OBJECT_POINTER(EVP_CIPHER_CTX);

#if defined(__clang__)
#define OPTNONE __attribute__((optnone))
#elif defined(__GNUC__)
#define OPTNONE __attribute__((optimize("O0")))
#else
#error Need a definition for OPTNONE
#endif

class ArrayEraser {
  public:
    ArrayEraser(uint8_t* arr, size_t size) : mArr(arr), mSize(size) {}
    OPTNONE ~ArrayEraser() { std::fill(mArr, mArr + mSize, 0); }

  private:
    volatile uint8_t* mArr;
    size_t mSize;
};

/**
 * Returns a EVP_CIPHER appropriate for the given key, based on the key's size.
 */
const EVP_CIPHER* getAesCipherForKey(const std::vector<uint8_t>& key) {
    const EVP_CIPHER* cipher = EVP_aes_256_gcm();
    if (key.size() == kAes128KeySizeBytes) {
        cipher = EVP_aes_128_gcm();
    }
    return cipher;
}

/*
 * Encrypt 'len' data at 'in' with AES-GCM, using 128-bit or 256-bit key at 'key', 96-bit IV at
 * 'iv' and write output to 'out' (which may be the same location as 'in') and 128-bit tag to
 * 'tag'.
 */
ResponseCode AES_gcm_encrypt(const uint8_t* in, uint8_t* out, size_t len,
                             const std::vector<uint8_t>& key, const uint8_t* iv, uint8_t* tag) {

    // There can be 128-bit and 256-bit keys
    const EVP_CIPHER* cipher = getAesCipherForKey(key);

    EVP_CIPHER_CTX_Ptr ctx(EVP_CIPHER_CTX_new());

    EVP_EncryptInit_ex(ctx.get(), cipher, nullptr /* engine */, key.data(), iv);
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0 /* no padding needed with GCM */);

    std::unique_ptr<uint8_t[]> out_tmp(new uint8_t[len]);
    uint8_t* out_pos = out_tmp.get();
    int out_len;

    EVP_EncryptUpdate(ctx.get(), out_pos, &out_len, in, len);
    out_pos += out_len;
    EVP_EncryptFinal_ex(ctx.get(), out_pos, &out_len);
    out_pos += out_len;
    if (out_pos - out_tmp.get() != static_cast<ssize_t>(len)) {
        ALOGD("Encrypted ciphertext is the wrong size, expected %zu, got %zd", len,
              out_pos - out_tmp.get());
        return ResponseCode::SYSTEM_ERROR;
    }

    std::copy(out_tmp.get(), out_pos, out);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kGcmTagLength, tag);

    return ResponseCode::NO_ERROR;
}

/*
 * Decrypt 'len' data at 'in' with AES-GCM, using 128-bit or 256-bit key at 'key', 96-bit IV at
 * 'iv', checking 128-bit tag at 'tag' and writing plaintext to 'out'(which may be the same
 * location as 'in').
 */
ResponseCode AES_gcm_decrypt(const uint8_t* in, uint8_t* out, size_t len,
                             const std::vector<uint8_t> key, const uint8_t* iv,
                             const uint8_t* tag) {

    // There can be 128-bit and 256-bit keys
    const EVP_CIPHER* cipher = getAesCipherForKey(key);

    EVP_CIPHER_CTX_Ptr ctx(EVP_CIPHER_CTX_new());

    EVP_DecryptInit_ex(ctx.get(), cipher, nullptr /* engine */, key.data(), iv);
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0 /* no padding needed with GCM */);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kGcmTagLength, const_cast<uint8_t*>(tag));

    std::unique_ptr<uint8_t[]> out_tmp(new uint8_t[len]);
    ArrayEraser out_eraser(out_tmp.get(), len);
    uint8_t* out_pos = out_tmp.get();
    int out_len;

    EVP_DecryptUpdate(ctx.get(), out_pos, &out_len, in, len);
    out_pos += out_len;
    if (!EVP_DecryptFinal_ex(ctx.get(), out_pos, &out_len)) {
        ALOGD("Failed to decrypt blob; ciphertext or tag is likely corrupted");
        return ResponseCode::VALUE_CORRUPTED;
    }
    out_pos += out_len;
    if (out_pos - out_tmp.get() != static_cast<ssize_t>(len)) {
        ALOGD("Encrypted plaintext is the wrong size, expected %zu, got %zd", len,
              out_pos - out_tmp.get());
        return ResponseCode::VALUE_CORRUPTED;
    }

    std::copy(out_tmp.get(), out_pos, out);

    return ResponseCode::NO_ERROR;
}

}  // namespace

Blob::Blob(const uint8_t* value, size_t valueLength, const uint8_t* info, uint8_t infoLength,
           BlobType type) {
    memset(&mBlob, 0, sizeof(mBlob));
    if (valueLength > kValueSize) {
        valueLength = kValueSize;
        ALOGW("Provided blob length too large");
    }
    if (infoLength + valueLength > kValueSize) {
        infoLength = kValueSize - valueLength;
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

Blob::Blob(blobv3 b) {
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

bool Blob::isSuperEncrypted() const {
    return mBlob.flags & KEYSTORE_FLAG_SUPER_ENCRYPTED;
}

bool Blob::isCriticalToDeviceEncryption() const {
    return mBlob.flags & KEYSTORE_FLAG_CRITICAL_TO_DEVICE_ENCRYPTION;
}

inline uint8_t setFlag(uint8_t flags, bool set, KeyStoreFlag flag) {
    return set ? (flags | flag) : (flags & ~flag);
}

void Blob::setEncrypted(bool encrypted) {
    mBlob.flags = setFlag(mBlob.flags, encrypted, KEYSTORE_FLAG_ENCRYPTED);
}

void Blob::setSuperEncrypted(bool superEncrypted) {
    mBlob.flags = setFlag(mBlob.flags, superEncrypted, KEYSTORE_FLAG_SUPER_ENCRYPTED);
}

void Blob::setCriticalToDeviceEncryption(bool critical) {
    mBlob.flags = setFlag(mBlob.flags, critical, KEYSTORE_FLAG_CRITICAL_TO_DEVICE_ENCRYPTION);
}

void Blob::setFallback(bool fallback) {
    if (fallback) {
        mBlob.flags |= KEYSTORE_FLAG_FALLBACK;
    } else {
        mBlob.flags &= ~KEYSTORE_FLAG_FALLBACK;
    }
}

ResponseCode Blob::writeBlob(const std::string& filename, const std::vector<uint8_t>& aes_key,
                             State state) {
    ALOGV("writing blob %s", filename.c_str());

    const size_t dataLength = mBlob.length;
    mBlob.length = htonl(mBlob.length);

    if (isEncrypted() || isSuperEncrypted()) {
        if (state != STATE_NO_ERROR) {
            ALOGD("couldn't insert encrypted blob while not unlocked");
            return ResponseCode::LOCKED;
        }

        memset(mBlob.initialization_vector, 0, AES_BLOCK_SIZE);
        if (!RAND_bytes(mBlob.initialization_vector, kGcmIvSizeBytes)) {
            ALOGW("Could not read random data for: %s", filename.c_str());
            return ResponseCode::SYSTEM_ERROR;
        }

        auto rc = AES_gcm_encrypt(mBlob.value /* in */, mBlob.value /* out */, dataLength, aes_key,
                                  mBlob.initialization_vector, mBlob.aead_tag);
        if (rc != ResponseCode::NO_ERROR) return rc;
    }

    size_t fileLength = offsetof(blobv3, value) + dataLength + mBlob.info;

    const char* tmpFileName = ".tmp";
    int out =
        TEMP_FAILURE_RETRY(open(tmpFileName, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR));
    if (out < 0) {
        ALOGW("could not open file: %s: %s", tmpFileName, strerror(errno));
        return ResponseCode::SYSTEM_ERROR;
    }

    const size_t writtenBytes = writeFully(out, (uint8_t*)&mBlob, fileLength);
    if (close(out) != 0) {
        return ResponseCode::SYSTEM_ERROR;
    }
    if (writtenBytes != fileLength) {
        ALOGW("blob not fully written %zu != %zu", writtenBytes, fileLength);
        unlink(tmpFileName);
        return ResponseCode::SYSTEM_ERROR;
    }
    if (rename(tmpFileName, filename.c_str()) == -1) {
        ALOGW("could not rename blob to %s: %s", filename.c_str(), strerror(errno));
        return ResponseCode::SYSTEM_ERROR;
    }
    return ResponseCode::NO_ERROR;
}

ResponseCode Blob::readBlob(const std::string& filename, const std::vector<uint8_t>& aes_key,
                            State state) {
    ALOGV("reading blob %s", filename.c_str());
    const int in = TEMP_FAILURE_RETRY(open(filename.c_str(), O_RDONLY));
    if (in < 0) {
        return (errno == ENOENT) ? ResponseCode::KEY_NOT_FOUND : ResponseCode::SYSTEM_ERROR;
    }

    // fileLength may be less than sizeof(mBlob)
    const size_t fileLength = readFully(in, (uint8_t*)&mBlob, sizeof(mBlob));
    if (close(in) != 0) {
        return ResponseCode::SYSTEM_ERROR;
    }

    if (fileLength == 0) {
        return ResponseCode::VALUE_CORRUPTED;
    }

    if ((isEncrypted() || isSuperEncrypted())) {
        if (state == STATE_LOCKED) return ResponseCode::LOCKED;
        if (state == STATE_UNINITIALIZED) return ResponseCode::UNINITIALIZED;
    }

    if (fileLength < offsetof(blobv3, value)) return ResponseCode::VALUE_CORRUPTED;

    if (mBlob.version == 3) {
        const ssize_t encryptedLength = ntohl(mBlob.length);

        if (isEncrypted() || isSuperEncrypted()) {
            auto rc = AES_gcm_decrypt(mBlob.value /* in */, mBlob.value /* out */, encryptedLength,
                                      aes_key, mBlob.initialization_vector, mBlob.aead_tag);
            if (rc != ResponseCode::NO_ERROR) return rc;
        }
    } else if (mBlob.version < 3) {
        blobv2& blob = reinterpret_cast<blobv2&>(mBlob);
        const size_t headerLength = offsetof(blobv2, encrypted);
        const ssize_t encryptedLength = fileLength - headerLength - blob.info;
        if (encryptedLength < 0) return ResponseCode::VALUE_CORRUPTED;

        if (isEncrypted() || isSuperEncrypted()) {
            if (encryptedLength % AES_BLOCK_SIZE != 0) {
                return ResponseCode::VALUE_CORRUPTED;
            }

            AES_KEY key;
            AES_set_decrypt_key(aes_key.data(), kAesKeySize * 8, &key);
            AES_cbc_encrypt(blob.encrypted, blob.encrypted, encryptedLength, &key, blob.vector,
                            AES_DECRYPT);
            key = {};  // clear key

            uint8_t computedDigest[MD5_DIGEST_LENGTH];
            ssize_t digestedLength = encryptedLength - MD5_DIGEST_LENGTH;
            MD5(blob.digested, digestedLength, computedDigest);
            if (memcmp(blob.digest, computedDigest, MD5_DIGEST_LENGTH) != 0) {
                return ResponseCode::VALUE_CORRUPTED;
            }
        }
    }

    const ssize_t maxValueLength = fileLength - offsetof(blobv3, value) - mBlob.info;
    mBlob.length = ntohl(mBlob.length);
    if (mBlob.length < 0 || mBlob.length > maxValueLength ||
        mBlob.length + mBlob.info + AES_BLOCK_SIZE > static_cast<ssize_t>(sizeof(mBlob.value))) {
        return ResponseCode::VALUE_CORRUPTED;
    }

    if (mBlob.info != 0 && mBlob.version < 3) {
        // move info from after padding to after data
        memmove(mBlob.value + mBlob.length, mBlob.value + maxValueLength, mBlob.info);
    }

    return ResponseCode::NO_ERROR;
}

keystore::SecurityLevel Blob::getSecurityLevel() const {
    return keystore::flagsToSecurityLevel(mBlob.flags);
}

void Blob::setSecurityLevel(keystore::SecurityLevel secLevel) {
    mBlob.flags &= ~(KEYSTORE_FLAG_FALLBACK | KEYSTORE_FLAG_STRONGBOX);
    mBlob.flags |= keystore::securityLevelToFlags(secLevel);
}
