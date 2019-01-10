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

#ifndef KEYSTORE_BLOB_H_
#define KEYSTORE_BLOB_H_

#include <stdint.h>

#include <openssl/aes.h>
#include <openssl/md5.h>

#include <keystore/keymaster_types.h>
#include <keystore/keystore.h>
#include <vector>

constexpr size_t kValueSize = 32768;
constexpr size_t kAesKeySize = 128 / 8;
constexpr size_t kGcmTagLength = 128 / 8;
constexpr size_t kGcmIvLength = 96 / 8;
constexpr size_t kAes128KeySizeBytes = 128 / 8;

/* Here is the file format. There are two parts in blob.value, the secret and
 * the description. The secret is stored in ciphertext, and its original size
 * can be found in blob.length. The description is stored after the secret in
 * plaintext, and its size is specified in blob.info. The total size of the two
 * parts must be no more than kValueSize bytes. The first field is the version,
 * the second is the blob's type, and the third byte is flags. Fields other
 * than blob.info, blob.length, and blob.value are modified by encryptBlob()
 * and decryptBlob(). Thus they should not be accessed from outside. */

struct __attribute__((packed)) blobv3 {
    uint8_t version;
    uint8_t type;
    uint8_t flags;
    uint8_t info;
    uint8_t initialization_vector[AES_BLOCK_SIZE];  // Only 96 bits is used, rest is zeroed.
    uint8_t aead_tag[kGcmTagLength];
    int32_t length;  // in network byte order, only for backward compatibility
    uint8_t value[kValueSize + AES_BLOCK_SIZE];
};

struct __attribute__((packed)) blobv2 {
    uint8_t version;
    uint8_t type;
    uint8_t flags;
    uint8_t info;
    uint8_t vector[AES_BLOCK_SIZE];
    uint8_t encrypted[0];  // Marks offset to encrypted data.
    uint8_t digest[MD5_DIGEST_LENGTH];
    uint8_t digested[0];  // Marks offset to digested data.
    int32_t length;       // in network byte order
    uint8_t value[kValueSize + AES_BLOCK_SIZE];
};

static_assert(sizeof(blobv3) == sizeof(blobv2) &&
                  offsetof(blobv3, initialization_vector) == offsetof(blobv2, vector) &&
                  offsetof(blobv3, aead_tag) == offsetof(blobv2, digest) &&
                  offsetof(blobv3, aead_tag) == offsetof(blobv2, encrypted) &&
                  offsetof(blobv3, length) == offsetof(blobv2, length) &&
                  offsetof(blobv3, value) == offsetof(blobv2, value),
              "Oops.  Blob layout changed.");

static const uint8_t CURRENT_BLOB_VERSION = 3;

typedef enum {
    TYPE_ANY = 0,  // meta type that matches anything
    TYPE_GENERIC = 1,
    TYPE_MASTER_KEY = 2,
    TYPE_KEY_PAIR = 3,
    TYPE_KEYMASTER_10 = 4,
    TYPE_KEY_CHARACTERISTICS = 5,
    TYPE_MASTER_KEY_AES256 = 7,
} BlobType;

class Blob {
  public:
    Blob(const uint8_t* value, size_t valueLength, const uint8_t* info, uint8_t infoLength,
         BlobType type);
    explicit Blob(blobv3 b);
    Blob();

    ~Blob() { mBlob = {}; }

    const uint8_t* getValue() const { return mBlob.value; }

    int32_t getLength() const { return mBlob.length; }

    const uint8_t* getInfo() const { return mBlob.value + mBlob.length; }
    uint8_t getInfoLength() const { return mBlob.info; }

    uint8_t getVersion() const { return mBlob.version; }

    bool isEncrypted() const;
    void setEncrypted(bool encrypted);

    bool isSuperEncrypted() const;
    void setSuperEncrypted(bool superEncrypted);

    bool isCriticalToDeviceEncryption() const;
    void setCriticalToDeviceEncryption(bool critical);

    bool isFallback() const { return mBlob.flags & KEYSTORE_FLAG_FALLBACK; }
    void setFallback(bool fallback);

    void setVersion(uint8_t version) { mBlob.version = version; }
    BlobType getType() const { return BlobType(mBlob.type); }
    void setType(BlobType type) { mBlob.type = uint8_t(type); }

    keystore::SecurityLevel getSecurityLevel() const;
    void setSecurityLevel(keystore::SecurityLevel);

    ResponseCode writeBlob(const std::string& filename, const std::vector<uint8_t>& aes_key,
                           State state);
    ResponseCode readBlob(const std::string& filename, const std::vector<uint8_t>& aes_key,
                          State state);

  private:
    blobv3 mBlob;
};

#endif  // KEYSTORE_BLOB_H_
