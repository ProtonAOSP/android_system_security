/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <keystore.h>

#include <utils/UniquePtr.h>

#include <sys/socket.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/evp.h>

#define LOG_NDEBUG 0
#define LOG_TAG "OpenSSL-keystore"
#include <cutils/log.h>

#include <keystore_client.h>


#define DYNAMIC_ENGINE
#define KEYSTORE_ENGINE_ID   "keystore"
#define KEYSTORE_ENGINE_NAME "Android keystore engine"

/**
 * Many OpenSSL APIs take ownership of an argument on success but don't free the argument
 * on failure. This means we need to tell our scoped pointers when we've transferred ownership,
 * without triggering a warning by not using the result of release().
 */
#define OWNERSHIP_TRANSFERRED(obj) \
    typeof (obj.release()) _dummy __attribute__((unused)) = obj.release()

struct ENGINE_Delete {
    void operator()(ENGINE* p) const {
        ENGINE_free(p);
    }
};
typedef UniquePtr<ENGINE, ENGINE_Delete> Unique_ENGINE;

struct EVP_PKEY_Delete {
    void operator()(EVP_PKEY* p) const {
        EVP_PKEY_free(p);
    }
};
typedef UniquePtr<EVP_PKEY, EVP_PKEY_Delete> Unique_EVP_PKEY;

struct RSA_Delete {
    void operator()(RSA* p) const {
        RSA_free(p);
    }
};
typedef UniquePtr<RSA, RSA_Delete> Unique_RSA;


/*
 * RSA ex_data index for keystore's key handle.
 */
static int rsa_key_handle;

/*
 * Only initialize the rsa_key_handle once.
 */
static pthread_once_t rsa_key_handle_control = PTHREAD_ONCE_INIT;


/**
 * Makes sure the ex_data for the keyhandle is initially set to NULL.
 */
int keyhandle_new(void*, void*, CRYPTO_EX_DATA* ad, int idx, long, void*) {
    return CRYPTO_set_ex_data(ad, idx, NULL);
}

/**
 * Frees a previously allocated keyhandle stored in ex_data.
 */
void keyhandle_free(void *, void *ptr, CRYPTO_EX_DATA*, int, long, void*) {
    char* keyhandle = reinterpret_cast<char*>(ptr);
    if (keyhandle != NULL) {
        free(keyhandle);
    }
}

/**
 * Duplicates a keyhandle stored in ex_data in case we copy a key.
 */
int keyhandle_dup(CRYPTO_EX_DATA* to, CRYPTO_EX_DATA*, void *ptrRef, int idx, long, void *) {
    // This appears to be a bug in OpenSSL.
    void** ptr = reinterpret_cast<void**>(ptrRef);
    char* keyhandle = reinterpret_cast<char*>(*ptr);
    if (keyhandle != NULL) {
        char* keyhandle_copy = strdup(keyhandle);
        *ptr = keyhandle_copy;

        // Call this in case OpenSSL is fixed in the future.
        (void) CRYPTO_set_ex_data(to, idx, keyhandle_copy);
    }
    return 1;
}

int keystore_rsa_priv_enc(int flen, const unsigned char* from, unsigned char* to, RSA* rsa,
        int padding) {
    ALOGV("keystore_rsa_sign(%d, %p, %p, %p, %d)", flen, from, to, rsa, padding);

    int num = RSA_size(rsa);
    UniquePtr<uint8_t> padded(new uint8_t[num]);
    if (padded.get() == NULL) {
        ALOGE("could not allocate padded signature");
        return 0;
    }

    switch (padding) {
    case RSA_PKCS1_PADDING:
        if (!RSA_padding_add_PKCS1_type_1(padded.get(), num, from, flen)) {
            return 0;
        }
        break;
    case RSA_X931_PADDING:
        if (!RSA_padding_add_X931(padded.get(), num, from, flen)) {
            return 0;
        }
        break;
    case RSA_NO_PADDING:
        if (!RSA_padding_add_none(padded.get(), num, from, flen)) {
            return 0;
        }
        break;
    default:
        ALOGE("Unknown padding type: %d", padding);
        return 0;
    }

    uint8_t* key_id = reinterpret_cast<uint8_t*>(RSA_get_ex_data(rsa, rsa_key_handle));
    if (key_id == NULL) {
        ALOGE("key had no key_id!");
        return 0;
    }

    Keystore_Reply reply;
    if (keystore_cmd(CommandCodes[SIGN], &reply, 2, strlen(reinterpret_cast<const char*>(key_id)),
            key_id, static_cast<size_t>(num), reinterpret_cast<const uint8_t*>(padded.get()))
            != NO_ERROR) {
        ALOGE("There was an error during rsa_mod_exp");
        return 0;
    }

    const size_t replyLen = reply.length();
    if (replyLen <= 0) {
        ALOGW("No valid signature returned");
        return 0;
    }

    memcpy(to, reply.get(), replyLen);

    ALOGV("rsa=%p keystore_rsa_sign => returning %p len %llu", rsa, to,
            (unsigned long long) replyLen);
    return static_cast<int>(replyLen);
}

static RSA_METHOD keystore_rsa_meth = {
        KEYSTORE_ENGINE_NAME,
        NULL, /* rsa_pub_enc */
        NULL, /* rsa_pub_dec (verification) */
        keystore_rsa_priv_enc, /* rsa_priv_enc (signing) */
        NULL, /* rsa_priv_dec */
        NULL, /* rsa_mod_exp */
        NULL, /* bn_mod_exp */
        NULL, /* init */
        NULL, /* finish */
        RSA_FLAG_EXT_PKEY | RSA_FLAG_NO_BLINDING, /* flags */
        NULL, /* app_data */
        NULL, /* rsa_sign */
        NULL, /* rsa_verify */
        NULL, /* rsa_keygen */
};

static int register_rsa_methods() {
    const RSA_METHOD* rsa_meth = RSA_PKCS1_SSLeay();

    keystore_rsa_meth.rsa_pub_enc = rsa_meth->rsa_pub_enc;
    keystore_rsa_meth.rsa_pub_dec = rsa_meth->rsa_pub_dec;
    keystore_rsa_meth.rsa_priv_dec = rsa_meth->rsa_priv_dec;
    keystore_rsa_meth.rsa_mod_exp = rsa_meth->rsa_mod_exp;
    keystore_rsa_meth.bn_mod_exp = rsa_meth->bn_mod_exp;

    return 1;
}

static EVP_PKEY* keystore_loadkey(ENGINE* e, const char* key_id, UI_METHOD *ui_method,
        void *callback_data) {
    ALOGV("keystore_loadkey(%p, \"%s\", %p, %p)", e, key_id, ui_method, callback_data);

    Keystore_Reply reply;
    if (keystore_cmd(CommandCodes[GET_PUBKEY], &reply, 1, strlen(key_id), key_id) != NO_ERROR) {
        ALOGV("Cannot get public key for %s", key_id);
        return NULL;
    }

    const unsigned char* tmp = reinterpret_cast<const unsigned char*>(reply.get());
    Unique_EVP_PKEY pkey(d2i_PUBKEY(NULL, &tmp, reply.length()));
    if (pkey.get() == NULL) {
        ALOGW("Cannot convert pubkey");
        return NULL;
    }

    switch (EVP_PKEY_type(pkey->type)) {
    case EVP_PKEY_RSA: {
        Unique_RSA rsa(EVP_PKEY_get1_RSA(pkey.get()));
        if (!RSA_set_ex_data(rsa.get(), rsa_key_handle, reinterpret_cast<void*>(strdup(key_id)))) {
            ALOGW("Could not set ex_data for loaded RSA key");
            return NULL;
        }

        RSA_set_method(rsa.get(), &keystore_rsa_meth);
        RSA_blinding_off(rsa.get());

        /*
         * This should probably be an OpenSSL API, but EVP_PKEY_free calls
         * ENGINE_finish(), so we need to call ENGINE_init() here.
         */
        ENGINE_init(e);
        rsa->engine = e;
        rsa->flags |= RSA_FLAG_EXT_PKEY;

        break;
    }
    default:
        ALOGE("Unsupported key type %d", EVP_PKEY_type(pkey->type));
        return NULL;
    }

    return pkey.release();
}

static const ENGINE_CMD_DEFN keystore_cmd_defns[] = {
    {0, NULL, NULL, 0}
};

/**
 * Called to initialize RSA's ex_data for the key_id handle. This should
 * only be called when protected by a lock.
 */
static void init_rsa_key_handle() {
    rsa_key_handle = RSA_get_ex_new_index(0, NULL, keyhandle_new, keyhandle_dup,
            keyhandle_free);
}

static int keystore_engine_setup(ENGINE* e) {
    ALOGV("keystore_engine_setup");

    if (!ENGINE_set_id(e, KEYSTORE_ENGINE_ID)
            || !ENGINE_set_name(e, KEYSTORE_ENGINE_NAME)
            || !ENGINE_set_load_privkey_function(e, keystore_loadkey)
            || !ENGINE_set_load_pubkey_function(e, keystore_loadkey)
            || !ENGINE_set_cmd_defns(e, keystore_cmd_defns)) {
        ALOGE("Could not set up keystore engine");
        return 0;
    }

    if (!ENGINE_set_RSA(e, &keystore_rsa_meth)
            || !register_rsa_methods()) {
        ALOGE("Could not set up keystore RSA methods");
        return 0;
    }

    /* We need a handle in the RSA keys as well for keygen if it's not already initialized. */
    pthread_once(&rsa_key_handle_control, init_rsa_key_handle);
    if (rsa_key_handle < 0) {
        ALOGE("Could not set up RSA ex_data index");
        return 0;
    }

    return 1;
}

ENGINE* ENGINE_keystore() {
    ALOGV("ENGINE_keystore");

    Unique_ENGINE engine(ENGINE_new());
    if (engine.get() == NULL) {
        return NULL;
    }

    if (!keystore_engine_setup(engine.get())) {
        return NULL;
    }

    return engine.release();
}

static int keystore_bind_fn(ENGINE *e, const char *id) {
    ALOGV("keystore_bind_fn");

    if (!id) {
        return 0;
    }

    if (strcmp(id, KEYSTORE_ENGINE_ID)) {
        return 0;
    }

    if (!keystore_engine_setup(e)) {
        return 0;
    }

    return 1;
}

extern "C" {
#undef OPENSSL_EXPORT
#define OPENSSL_EXPORT extern __attribute__ ((visibility ("default")))

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(keystore_bind_fn)
};
