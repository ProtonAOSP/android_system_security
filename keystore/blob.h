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

#include <keystore/keystore.h>

#define VALUE_SIZE 32768

/* Here is the file format. There are two parts in blob.value, the secret and
 * the description. The secret is stored in ciphertext, and its original size
 * can be found in blob.length. The description is stored after the secret in
 * plaintext, and its size is specified in blob.info. The total size of the two
 * parts must be no more than VALUE_SIZE bytes. The first field is the version,
 * the second is the blob's type, and the third byte is flags. Fields other
 * than blob.info, blob.length, and blob.value are modified by encryptBlob()
 * and decryptBlob(). Thus they should not be accessed from outside. */

/* ** Note to future implementors of encryption: **
 * Currently this is the construction:
 *   metadata || Enc(MD5(data) || data)
 *
 * This should be the construction used for encrypting if re-implementing:
 *
 *   Derive independent keys for encryption and MAC:
 *     Kenc = AES_encrypt(masterKey, "Encrypt")
 *     Kmac = AES_encrypt(masterKey, "MAC")
 *
 *   Store this:
 *     metadata || AES_CTR_encrypt(Kenc, rand_IV, data) ||
 *             HMAC(Kmac, metadata || Enc(data))
 */
struct __attribute__((packed)) blob {
    uint8_t version;
    uint8_t type;
    uint8_t flags;
    uint8_t info;
    uint8_t vector[AES_BLOCK_SIZE];
    uint8_t encrypted[0];  // Marks offset to encrypted data.
    uint8_t digest[MD5_DIGEST_LENGTH];
    uint8_t digested[0];  // Marks offset to digested data.
    int32_t length;       // in network byte order when encrypted
    uint8_t value[VALUE_SIZE + AES_BLOCK_SIZE];
};

static const uint8_t CURRENT_BLOB_VERSION = 2;

typedef enum {
    TYPE_ANY = 0,  // meta type that matches anything
    TYPE_GENERIC = 1,
    TYPE_MASTER_KEY = 2,
    TYPE_KEY_PAIR = 3,
    TYPE_KEYMASTER_10 = 4,
    TYPE_KEY_CHARACTERISTICS = 5,
} BlobType;

class Entropy;

class Blob {
  public:
    Blob(const uint8_t* value, size_t valueLength, const uint8_t* info, uint8_t infoLength,
         BlobType type);
    Blob(blob b);

    Blob();

    const uint8_t* getValue() const { return mBlob.value; }

    int32_t getLength() const { return mBlob.length; }

    const uint8_t* getInfo() const { return mBlob.value + mBlob.length; }
    uint8_t getInfoLength() const { return mBlob.info; }

    uint8_t getVersion() const { return mBlob.version; }

    bool isEncrypted() const;
    void setEncrypted(bool encrypted);

    bool isFallback() const { return mBlob.flags & KEYSTORE_FLAG_FALLBACK; }
    void setFallback(bool fallback);

    void setVersion(uint8_t version) { mBlob.version = version; }
    BlobType getType() const { return BlobType(mBlob.type); }
    void setType(BlobType type) { mBlob.type = uint8_t(type); }

    ResponseCode writeBlob(const char* filename, AES_KEY* aes_key, State state, Entropy* entropy);
    ResponseCode readBlob(const char* filename, AES_KEY* aes_key, State state);

  private:
    struct blob mBlob;
};

#endif  // KEYSTORE_BLOB_H_
