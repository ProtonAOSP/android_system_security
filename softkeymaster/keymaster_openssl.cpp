/*
 * Copyright (C) 2012 The Android Open Source Project
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
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include <keystore.h>

#include <hardware/hardware.h>
#include <hardware/keymaster.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <utils/UniquePtr.h>

// For debugging
//#define LOG_NDEBUG 0

#define LOG_TAG "OpenSSLKeyMaster"
#include <cutils/log.h>

struct BIGNUM_Delete {
    void operator()(BIGNUM* p) const {
        BN_free(p);
    }
};
typedef UniquePtr<BIGNUM, BIGNUM_Delete> Unique_BIGNUM;

struct EVP_PKEY_Delete {
    void operator()(EVP_PKEY* p) const {
        EVP_PKEY_free(p);
    }
};
typedef UniquePtr<EVP_PKEY, EVP_PKEY_Delete> Unique_EVP_PKEY;

struct PKCS8_PRIV_KEY_INFO_Delete {
    void operator()(PKCS8_PRIV_KEY_INFO* p) const {
        PKCS8_PRIV_KEY_INFO_free(p);
    }
};
typedef UniquePtr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_Delete> Unique_PKCS8_PRIV_KEY_INFO;

struct RSA_Delete {
    void operator()(RSA* p) const {
        RSA_free(p);
    }
};
typedef UniquePtr<RSA, RSA_Delete> Unique_RSA;

typedef UniquePtr<keymaster_device_t> Unique_keymaster_device_t;

/**
 * Many OpenSSL APIs take ownership of an argument on success but don't free the argument
 * on failure. This means we need to tell our scoped pointers when we've transferred ownership,
 * without triggering a warning by not using the result of release().
 */
#define OWNERSHIP_TRANSFERRED(obj) \
    typeof (obj.release()) _dummy __attribute__((unused)) = obj.release()


/*
 * Checks this thread's OpenSSL error queue and logs if
 * necessary.
 */
static void logOpenSSLError(const char* location) {
    int error = ERR_get_error();

    if (error != 0) {
        char message[256];
        ERR_error_string_n(error, message, sizeof(message));
        ALOGE("OpenSSL error in %s %d: %s", location, error, message);
    }

    ERR_clear_error();
    ERR_remove_state(0);
}

static int wrap_key(EVP_PKEY* pkey, int type, uint8_t** keyBlob, size_t* keyBlobLength) {
    /* Find the length of each size */
    int publicLen = i2d_PublicKey(pkey, NULL);
    int privateLen = i2d_PrivateKey(pkey, NULL);

    if (privateLen <= 0 || publicLen <= 0) {
        ALOGE("private or public key size was too big");
        return -1;
    }

    /* int type + int size + private key data + int size + public key data */
    *keyBlobLength = get_softkey_header_size() + sizeof(int) + sizeof(int) + privateLen
            + sizeof(int) + publicLen;

    UniquePtr<unsigned char[]> derData(new unsigned char[*keyBlobLength]);
    if (derData.get() == NULL) {
        ALOGE("could not allocate memory for key blob");
        return -1;
    }
    unsigned char* p = derData.get();

    /* Write the magic value for software keys. */
    p = add_softkey_header(p, *keyBlobLength);

    /* Write key type to allocated buffer */
    for (int i = sizeof(int) - 1; i >= 0; i--) {
        *p++ = (type >> (8*i)) & 0xFF;
    }

    /* Write public key to allocated buffer */
    for (int i = sizeof(int) - 1; i >= 0; i--) {
        *p++ = (publicLen >> (8*i)) & 0xFF;
    }
    if (i2d_PublicKey(pkey, &p) != publicLen) {
        logOpenSSLError("wrap_key");
        return -1;
    }

    /* Write private key to allocated buffer */
    for (int i = sizeof(int) - 1; i >= 0; i--) {
        *p++ = (privateLen >> (8*i)) & 0xFF;
    }
    if (i2d_PrivateKey(pkey, &p) != privateLen) {
        logOpenSSLError("wrap_key");
        return -1;
    }

    *keyBlob = derData.release();

    return 0;
}

static EVP_PKEY* unwrap_key(const uint8_t* keyBlob, const size_t keyBlobLength) {
    long publicLen = 0;
    long privateLen = 0;
    const uint8_t* p = keyBlob;
    const uint8_t *const end = keyBlob + keyBlobLength;

    if (keyBlob == NULL) {
        ALOGE("supplied key blob was NULL");
        return NULL;
    }

    // Should be large enough for:
    // int32 magic, int32 type, int32 pubLen, char* pub, int32 privLen, char* priv
    if (keyBlobLength < (get_softkey_header_size() + sizeof(int) + sizeof(int) + 1
            + sizeof(int) + 1)) {
        ALOGE("key blob appears to be truncated");
        return NULL;
    }

    if (!is_softkey(p, keyBlobLength)) {
        ALOGE("cannot read key; it was not made by this keymaster");
        return NULL;
    }
    p += get_softkey_header_size();

    int type = 0;
    for (size_t i = 0; i < sizeof(int); i++) {
        type = (type << 8) | *p++;
    }

    Unique_EVP_PKEY pkey(EVP_PKEY_new());
    if (pkey.get() == NULL) {
        logOpenSSLError("unwrap_key");
        return NULL;
    }

    for (size_t i = 0; i < sizeof(int); i++) {
        publicLen = (publicLen << 8) | *p++;
    }
    if (p + publicLen > end) {
        ALOGE("public key length encoding error: size=%ld, end=%d", publicLen, end - p);
        return NULL;
    }
    EVP_PKEY* tmp = pkey.get();
    d2i_PublicKey(type, &tmp, &p, publicLen);

    if (end - p < 2) {
        ALOGE("private key truncated");
        return NULL;
    }
    for (size_t i = 0; i < sizeof(int); i++) {
        privateLen = (privateLen << 8) | *p++;
    }
    if (p + privateLen > end) {
        ALOGE("private key length encoding error: size=%ld, end=%d", privateLen, end - p);
        return NULL;
    }
    d2i_PrivateKey(type, &tmp, &p, privateLen);

    return pkey.release();
}

static int openssl_generate_keypair(const keymaster_device_t* dev,
        const keymaster_keypair_t key_type, const void* key_params,
        uint8_t** keyBlob, size_t* keyBlobLength) {
    ssize_t privateLen, publicLen;

    if (key_type != TYPE_RSA) {
        ALOGW("Unsupported key type %d", key_type);
        return -1;
    } else if (key_params == NULL) {
        ALOGW("key_params == null");
        return -1;
    }

    keymaster_rsa_keygen_params_t* rsa_params = (keymaster_rsa_keygen_params_t*) key_params;

    Unique_BIGNUM bn(BN_new());
    if (bn.get() == NULL) {
        logOpenSSLError("openssl_generate_keypair");
        return -1;
    }

    if (BN_set_word(bn.get(), rsa_params->public_exponent) == 0) {
        logOpenSSLError("openssl_generate_keypair");
        return -1;
    }

    /* initialize RSA */
    Unique_RSA rsa(RSA_new());
    if (rsa.get() == NULL) {
        logOpenSSLError("openssl_generate_keypair");
        return -1;
    }

    if (!RSA_generate_key_ex(rsa.get(), rsa_params->modulus_size, bn.get(), NULL)
            || RSA_check_key(rsa.get()) < 0) {
        logOpenSSLError("openssl_generate_keypair");
        return -1;
    }

    /* assign to EVP */
    Unique_EVP_PKEY pkey(EVP_PKEY_new());
    if (pkey.get() == NULL) {
        logOpenSSLError("openssl_generate_keypair");
        return -1;
    }

    if (EVP_PKEY_assign_RSA(pkey.get(), rsa.get()) == 0) {
        logOpenSSLError("openssl_generate_keypair");
        return -1;
    }
    OWNERSHIP_TRANSFERRED(rsa);

    if (wrap_key(pkey.get(), EVP_PKEY_RSA, keyBlob, keyBlobLength)) {
        return -1;
    }

    return 0;
}

static int openssl_import_keypair(const keymaster_device_t* dev,
        const uint8_t* key, const size_t key_length,
        uint8_t** key_blob, size_t* key_blob_length) {
    int response = -1;

    if (key == NULL) {
        ALOGW("input key == NULL");
        return -1;
    } else if (key_blob == NULL || key_blob_length == NULL) {
        ALOGW("output key blob or length == NULL");
        return -1;
    }

    Unique_PKCS8_PRIV_KEY_INFO pkcs8(d2i_PKCS8_PRIV_KEY_INFO(NULL, &key, key_length));
    if (pkcs8.get() == NULL) {
        logOpenSSLError("openssl_import_keypair");
        return -1;
    }

    /* assign to EVP */
    Unique_EVP_PKEY pkey(EVP_PKCS82PKEY(pkcs8.get()));
    if (pkey.get() == NULL) {
        logOpenSSLError("openssl_import_keypair");
        return -1;
    }
    OWNERSHIP_TRANSFERRED(pkcs8);

    if (wrap_key(pkey.get(), EVP_PKEY_type(pkey->type), key_blob, key_blob_length)) {
        return -1;
    }

    return 0;
}

static int openssl_get_keypair_public(const struct keymaster_device* dev,
        const uint8_t* key_blob, const size_t key_blob_length,
        uint8_t** x509_data, size_t* x509_data_length) {

    if (x509_data == NULL || x509_data_length == NULL) {
        ALOGW("output public key buffer == NULL");
        return -1;
    }

    Unique_EVP_PKEY pkey(unwrap_key(key_blob, key_blob_length));
    if (pkey.get() == NULL) {
        return -1;
    }

    int len = i2d_PUBKEY(pkey.get(), NULL);
    if (len <= 0) {
        logOpenSSLError("openssl_get_keypair_public");
        return -1;
    }

    UniquePtr<uint8_t> key(static_cast<uint8_t*>(malloc(len)));
    if (key.get() == NULL) {
        ALOGE("Could not allocate memory for public key data");
        return -1;
    }

    unsigned char* tmp = reinterpret_cast<unsigned char*>(key.get());
    if (i2d_PUBKEY(pkey.get(), &tmp) != len) {
        logOpenSSLError("openssl_get_keypair_public");
        return -1;
    }

    ALOGV("Length of x509 data is %d", len);
    *x509_data_length = len;
    *x509_data = key.release();

    return 0;
}

static int openssl_sign_data(const keymaster_device_t* dev,
        const void* params,
        const uint8_t* keyBlob, const size_t keyBlobLength,
        const uint8_t* data, const size_t dataLength,
        uint8_t** signedData, size_t* signedDataLength) {

    int result = -1;
    EVP_MD_CTX ctx;
    size_t maxSize;

    if (data == NULL) {
        ALOGW("input data to sign == NULL");
        return -1;
    } else if (signedData == NULL || signedDataLength == NULL) {
        ALOGW("output signature buffer == NULL");
        return -1;
    }

    Unique_EVP_PKEY pkey(unwrap_key(keyBlob, keyBlobLength));
    if (pkey.get() == NULL) {
        return -1;
    }

    if (EVP_PKEY_type(pkey->type) != EVP_PKEY_RSA) {
        ALOGW("Cannot handle non-RSA keys yet");
        return -1;
    }

    keymaster_rsa_sign_params_t* sign_params = (keymaster_rsa_sign_params_t*) params;
    if (sign_params->digest_type != DIGEST_NONE) {
        ALOGW("Cannot handle digest type %d", sign_params->digest_type);
        return -1;
    } else if (sign_params->padding_type != PADDING_NONE) {
        ALOGW("Cannot handle padding type %d", sign_params->padding_type);
        return -1;
    }

    Unique_RSA rsa(EVP_PKEY_get1_RSA(pkey.get()));
    if (rsa.get() == NULL) {
        logOpenSSLError("openssl_sign_data");
        return -1;
    }

    UniquePtr<uint8_t> signedDataPtr(reinterpret_cast<uint8_t*>(malloc(dataLength)));
    if (signedDataPtr.get() == NULL) {
        logOpenSSLError("openssl_sign_data");
        return -1;
    }

    unsigned char* tmp = reinterpret_cast<unsigned char*>(signedDataPtr.get());
    if (RSA_private_encrypt(dataLength, data, tmp, rsa.get(), RSA_NO_PADDING) <= 0) {
        logOpenSSLError("openssl_sign_data");
        return -1;
    }

    *signedDataLength = dataLength;
    *signedData = signedDataPtr.release();
    return 0;
}

static int openssl_verify_data(const keymaster_device_t* dev,
        const void* params,
        const uint8_t* keyBlob, const size_t keyBlobLength,
        const uint8_t* signedData, const size_t signedDataLength,
        const uint8_t* signature, const size_t signatureLength) {

    if (signedData == NULL || signature == NULL) {
        ALOGW("data or signature buffers == NULL");
        return -1;
    }

    Unique_EVP_PKEY pkey(unwrap_key(keyBlob, keyBlobLength));
    if (pkey.get() == NULL) {
        return -1;
    }

    if (EVP_PKEY_type(pkey->type) != EVP_PKEY_RSA) {
        ALOGW("Cannot handle non-RSA keys yet");
        return -1;
    }

    keymaster_rsa_sign_params_t* sign_params = (keymaster_rsa_sign_params_t*) params;
    if (sign_params->digest_type != DIGEST_NONE) {
        ALOGW("Cannot handle digest type %d", sign_params->digest_type);
        return -1;
    } else if (sign_params->padding_type != PADDING_NONE) {
        ALOGW("Cannot handle padding type %d", sign_params->padding_type);
        return -1;
    } else if (signatureLength != signedDataLength) {
        ALOGW("signed data length must be signature length");
        return -1;
    }

    Unique_RSA rsa(EVP_PKEY_get1_RSA(pkey.get()));
    if (rsa.get() == NULL) {
        logOpenSSLError("openssl_verify_data");
        return -1;
    }

    UniquePtr<uint8_t> dataPtr(reinterpret_cast<uint8_t*>(malloc(signedDataLength)));
    if (dataPtr.get() == NULL) {
        logOpenSSLError("openssl_verify_data");
        return -1;
    }

    unsigned char* tmp = reinterpret_cast<unsigned char*>(dataPtr.get());
    if (!RSA_public_decrypt(signatureLength, signature, tmp, rsa.get(), RSA_NO_PADDING)) {
        logOpenSSLError("openssl_verify_data");
        return -1;
    }

    int result = 0;
    for (size_t i = 0; i < signedDataLength; i++) {
        result |= tmp[i] ^ signedData[i];
    }

    return result == 0 ? 0 : -1;
}

/* Close an opened OpenSSL instance */
static int openssl_close(hw_device_t *dev) {
    free(dev);
    return 0;
}

/*
 * Generic device handling
 */
static int openssl_open(const hw_module_t* module, const char* name,
        hw_device_t** device) {
    if (strcmp(name, KEYSTORE_KEYMASTER) != 0)
        return -EINVAL;

    Unique_keymaster_device_t dev(new keymaster_device_t);
    if (dev.get() == NULL)
        return -ENOMEM;

    dev->common.tag = HARDWARE_DEVICE_TAG;
    dev->common.version = 1;
    dev->common.module = (struct hw_module_t*) module;
    dev->common.close = openssl_close;

    dev->flags = KEYMASTER_SOFTWARE_ONLY;

    dev->generate_keypair = openssl_generate_keypair;
    dev->import_keypair = openssl_import_keypair;
    dev->get_keypair_public = openssl_get_keypair_public;
    dev->delete_keypair = NULL;
    dev->delete_all = NULL;
    dev->sign_data = openssl_sign_data;
    dev->verify_data = openssl_verify_data;

    ERR_load_crypto_strings();
    ERR_load_BIO_strings();

    *device = reinterpret_cast<hw_device_t*>(dev.release());

    return 0;
}

static struct hw_module_methods_t keystore_module_methods = {
    open: openssl_open,
};

struct keystore_module HAL_MODULE_INFO_SYM
__attribute__ ((visibility ("default"))) = {
    common: {
        tag: HARDWARE_MODULE_TAG,
        version_major: 1,
        version_minor: 0,
        id: KEYSTORE_HARDWARE_MODULE_ID,
        name: "Keymaster OpenSSL HAL",
        author: "The Android Open Source Project",
        methods: &keystore_module_methods,
        dso: 0,
        reserved: {},
    },
};
