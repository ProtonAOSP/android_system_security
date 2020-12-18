/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "keystore2"

#include "crypto.hpp"

#include <log/log.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <vector>

// Copied from system/security/keystore/blob.h.

constexpr size_t kGcmTagLength = 128 / 8;
constexpr size_t kAes128KeySizeBytes = 128 / 8;

// Copied from system/security/keystore/blob.cpp.

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
 * Returns a EVP_CIPHER appropriate for the given key size.
 */
const EVP_CIPHER* getAesCipherForKey(size_t key_size) {
    const EVP_CIPHER* cipher = EVP_aes_256_gcm();
    if (key_size == kAes128KeySizeBytes) {
        cipher = EVP_aes_128_gcm();
    }
    return cipher;
}

bool randomBytes(uint8_t* out, size_t len) {
    return RAND_bytes(out, len);
}

/*
 * Encrypt 'len' data at 'in' with AES-GCM, using 128-bit or 256-bit key at 'key', 96-bit IV at
 * 'iv' and write output to 'out' (which may be the same location as 'in') and 128-bit tag to
 * 'tag'.
 */
bool AES_gcm_encrypt(const uint8_t* in, uint8_t* out, size_t len, const uint8_t* key,
                     size_t key_size, const uint8_t* iv, uint8_t* tag) {

    // There can be 128-bit and 256-bit keys
    const EVP_CIPHER* cipher = getAesCipherForKey(key_size);

    bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());

    EVP_EncryptInit_ex(ctx.get(), cipher, nullptr /* engine */, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0 /* no padding needed with GCM */);

    std::vector<uint8_t> out_tmp(len);
    uint8_t* out_pos = out_tmp.data();
    int out_len;

    EVP_EncryptUpdate(ctx.get(), out_pos, &out_len, in, len);
    out_pos += out_len;
    EVP_EncryptFinal_ex(ctx.get(), out_pos, &out_len);
    out_pos += out_len;
    if (out_pos - out_tmp.data() != static_cast<ssize_t>(len)) {
        ALOGD("Encrypted ciphertext is the wrong size, expected %zu, got %zd", len,
              out_pos - out_tmp.data());
        return false;
    }

    std::copy(out_tmp.data(), out_pos, out);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kGcmTagLength, tag);

    return true;
}

/*
 * Decrypt 'len' data at 'in' with AES-GCM, using 128-bit or 256-bit key at 'key', 96-bit IV at
 * 'iv', checking 128-bit tag at 'tag' and writing plaintext to 'out'(which may be the same
 * location as 'in').
 */
bool AES_gcm_decrypt(const uint8_t* in, uint8_t* out, size_t len, const uint8_t* key,
                     size_t key_size, const uint8_t* iv, const uint8_t* tag) {

    // There can be 128-bit and 256-bit keys
    const EVP_CIPHER* cipher = getAesCipherForKey(key_size);

    bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());

    EVP_DecryptInit_ex(ctx.get(), cipher, nullptr /* engine */, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0 /* no padding needed with GCM */);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kGcmTagLength, const_cast<uint8_t*>(tag));

    std::vector<uint8_t> out_tmp(len);
    ArrayEraser out_eraser(out_tmp.data(), len);
    uint8_t* out_pos = out_tmp.data();
    int out_len;

    EVP_DecryptUpdate(ctx.get(), out_pos, &out_len, in, len);
    out_pos += out_len;
    if (!EVP_DecryptFinal_ex(ctx.get(), out_pos, &out_len)) {
        ALOGE("Failed to decrypt blob; ciphertext or tag is likely corrupted");
        return false;
    }
    out_pos += out_len;
    if (out_pos - out_tmp.data() != static_cast<ssize_t>(len)) {
        ALOGE("Encrypted plaintext is the wrong size, expected %zu, got %zd", len,
              out_pos - out_tmp.data());
        return false;
    }

    std::copy(out_tmp.data(), out_pos, out);

    return true;
}

// Copied from system/security/keystore/keymaster_enforcement.cpp.

class EvpMdCtx {
  public:
    EvpMdCtx() { EVP_MD_CTX_init(&ctx_); }
    ~EvpMdCtx() { EVP_MD_CTX_cleanup(&ctx_); }

    EVP_MD_CTX* get() { return &ctx_; }

  private:
    EVP_MD_CTX ctx_;
};

bool CreateKeyId(const uint8_t* key_blob, size_t len, km_id_t* out_id) {
    EvpMdCtx ctx;

    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr /* ENGINE */) &&
        EVP_DigestUpdate(ctx.get(), key_blob, len) &&
        EVP_DigestFinal_ex(ctx.get(), hash, &hash_len)) {
        assert(hash_len >= sizeof(*out_id));
        memcpy(out_id, hash, sizeof(*out_id));
        return true;
    }

    return false;
}

// Copied from system/security/keystore/user_state.h

static constexpr size_t SALT_SIZE = 16;

// Copied from system/security/keystore/user_state.cpp.

void generateKeyFromPassword(uint8_t* key, size_t key_len, const char* pw, size_t pw_len,
                             const uint8_t* salt) {
    size_t saltSize;
    if (salt != nullptr) {
        saltSize = SALT_SIZE;
    } else {
        // Pre-gingerbread used this hardwired salt, readMasterKey will rewrite these when found
        salt = reinterpret_cast<const uint8_t*>("keystore");
        // sizeof = 9, not strlen = 8
        saltSize = sizeof("keystore");
    }

    const EVP_MD* digest = EVP_sha256();

    // SHA1 was used prior to increasing the key size
    if (key_len == kAes128KeySizeBytes) {
        digest = EVP_sha1();
    }

    PKCS5_PBKDF2_HMAC(pw, pw_len, salt, saltSize, 8192, digest, key_len, key);
}
