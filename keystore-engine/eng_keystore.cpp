/*
 * Copyright 2012 The Android Open Source Project
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

#include <utils/UniquePtr.h>

#include <sys/socket.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <openssl/dsa.h>
#include <openssl/engine.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>

//#define LOG_NDEBUG 0
#define LOG_TAG "OpenSSL-keystore"
#include <cutils/log.h>

#include <binder/IServiceManager.h>
#include <keystore/keystore.h>
#include <keystore/IKeystoreService.h>

#include "methods.h"

using namespace android;

#define DYNAMIC_ENGINE
const char* kKeystoreEngineId = "keystore";
static const char* kKeystoreEngineDesc = "Android keystore engine";


/*
 * ex_data index for keystore's key alias.
 */
int rsa_key_handle;
int dsa_key_handle;


/*
 * Only initialize the *_key_handle once.
 */
static pthread_once_t key_handle_control = PTHREAD_ONCE_INIT;

/*
 * Used for generic EVP_PKEY* handling (only for EC stuff currently)
 */
static EVP_PKEY_METHOD* keystore_pkey_ec_methods;

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

/**
 * Called to initialize RSA's ex_data for the key_id handle. This should
 * only be called when protected by a lock.
 */
static void init_key_handle() {
    rsa_key_handle = RSA_get_ex_new_index(0, NULL, keyhandle_new, keyhandle_dup, keyhandle_free);
    dsa_key_handle = DSA_get_ex_new_index(0, NULL, keyhandle_new, keyhandle_dup, keyhandle_free);
}

static int pkey_setup(ENGINE *e, EVP_PKEY *pkey, const char *key_id) {
    int ret = 1;
    switch (EVP_PKEY_type(pkey->type)) {
    case EVP_PKEY_EC: {
        Unique_EC_KEY eckey(EVP_PKEY_get1_EC_KEY(pkey));
        void* oldData = EC_KEY_insert_key_method_data(eckey.get(),
                reinterpret_cast<void*>(strdup(key_id)), ex_data_dup, ex_data_free,
                ex_data_clear_free);
        if (oldData != NULL) {
            free(oldData);
        }
    } break;
    default:
        ALOGW("Unsupported key type during setup %d", EVP_PKEY_type(pkey->type));
        return 0;
    }

    if (ret != 1) {
        return ret;
    }

    ENGINE_init(e);
    pkey->engine = e;

    return 1;
}

static EVP_PKEY* keystore_loadkey(ENGINE* e, const char* key_id, UI_METHOD* ui_method,
        void* callback_data) {
#if LOG_NDEBUG
    (void)ui_method;
    (void)callback_data;
#else
    ALOGV("keystore_loadkey(%p, \"%s\", %p, %p)", e, key_id, ui_method, callback_data);
#endif

    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("android.security.keystore"));
    sp<IKeystoreService> service = interface_cast<IKeystoreService>(binder);

    if (service == NULL) {
        ALOGE("could not contact keystore");
        return 0;
    }

    uint8_t *pubkey = NULL;
    size_t pubkeyLen;
    int32_t ret = service->get_pubkey(String16(key_id), &pubkey, &pubkeyLen);
    if (ret < 0) {
        ALOGW("could not contact keystore");
        free(pubkey);
        return NULL;
    } else if (ret != 0) {
        ALOGW("keystore reports error: %d", ret);
        free(pubkey);
        return NULL;
    }

    const unsigned char* tmp = reinterpret_cast<const unsigned char*>(pubkey);
    Unique_EVP_PKEY pkey(d2i_PUBKEY(NULL, &tmp, pubkeyLen));
    free(pubkey);
    if (pkey.get() == NULL) {
        ALOGW("Cannot convert pubkey");
        return NULL;
    }

    switch (EVP_PKEY_type(pkey->type)) {
    case EVP_PKEY_DSA: {
        dsa_pkey_setup(e, pkey.get(), key_id);
        break;
    }
    case EVP_PKEY_RSA: {
        rsa_pkey_setup(e, pkey.get(), key_id);
        break;
    }
    case EVP_PKEY_EC: {
        pkey_setup(e, pkey.get(), key_id);
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

static uint8_t* get_key_id(EVP_PKEY* pkey) {
    switch (EVP_PKEY_type(pkey->type)) {
    case EVP_PKEY_EC: {
        Unique_EC_KEY eckey(EVP_PKEY_get1_EC_KEY(pkey));
        return reinterpret_cast<uint8_t*>(EC_KEY_get_key_method_data(eckey.get(),
                ex_data_dup, ex_data_free, ex_data_clear_free));
    } break;
    }

    return NULL;
}

static int keystore_pkey_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbs_len) {
    EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);

    const uint8_t* key_id = get_key_id(pkey);
    if (key_id == NULL) {
        ALOGW("key_id is empty");
        return 0;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("android.security.keystore"));
    sp<IKeystoreService> service = interface_cast<IKeystoreService>(binder);

    if (service == NULL) {
        ALOGE("could not contact keystore");
        return 0;
    }

    uint8_t* reply = NULL;
    size_t replyLen;
    int32_t ret = service->sign(String16(reinterpret_cast<const char*>(key_id)), tbs, tbs_len,
            &reply, &replyLen);
    if (ret < 0) {
        ALOGW("There was an error during signing: could not connect");
        free(reply);
        return 0;
    } else if (ret != 0) {
        ALOGW("Error during signing from keystore: %d", ret);
        free(reply);
        return 0;
    } else if (replyLen <= 0) {
        ALOGW("No valid signature returned");
        return 0;
    }

    memcpy(sig, reply, replyLen);
    free(reply);
    *siglen = replyLen;

    return 1;
}

static int register_pkey_methods(EVP_PKEY_METHOD** meth, int nid) {
    *meth = EVP_PKEY_meth_new(nid, 0);
    if (*meth == NULL) {
        ALOGE("Failure allocating PKEY methods for NID %d", nid);
        return 0;
    }

    const EVP_PKEY_METHOD* orig = EVP_PKEY_meth_find(nid);
    EVP_PKEY_meth_copy(*meth, orig);

    EVP_PKEY_meth_set_sign(*meth, NULL, keystore_pkey_sign);

    return 1;
}

static int keystore_nids[] = {
    EVP_PKEY_EC,
};

static int keystore_pkey_meths(ENGINE*, EVP_PKEY_METHOD** meth, const int **nids, int nid) {
    if (meth == NULL) {
        *nids = keystore_nids;
        return sizeof(keystore_nids) / sizeof(keystore_nids[0]);
    }

    switch (nid) {
    case EVP_PKEY_EC:
        *meth = keystore_pkey_ec_methods;
        return 1;
    }

    *meth = NULL;
    return 0;
}

static int keystore_engine_setup(ENGINE* e) {
    ALOGV("keystore_engine_setup");

    if (!register_pkey_methods(&keystore_pkey_ec_methods, EVP_PKEY_EC)) {
        ALOGE("Could not set up keystore engine");
        return 0;
    }

    if (!ENGINE_set_id(e, kKeystoreEngineId)
            || !ENGINE_set_name(e, kKeystoreEngineDesc)
            || !ENGINE_set_pkey_meths(e, keystore_pkey_meths)
            || !ENGINE_set_load_privkey_function(e, keystore_loadkey)
            || !ENGINE_set_load_pubkey_function(e, keystore_loadkey)
            || !ENGINE_set_flags(e, 0)
            || !ENGINE_set_cmd_defns(e, keystore_cmd_defns)) {
        ALOGE("Could not set up keystore engine");
        return 0;
    }

    /* We need a handle in the keys types as well for keygen if it's not already initialized. */
    pthread_once(&key_handle_control, init_key_handle);
    if ((rsa_key_handle < 0) || (dsa_key_handle < 0)) {
        ALOGE("Could not set up ex_data index");
        return 0;
    }

    if (!dsa_register(e)) {
        ALOGE("DSA registration failed");
        return 0;
    } else if (!rsa_register(e)) {
        ALOGE("RSA registration failed");
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

    if (strcmp(id, kKeystoreEngineId)) {
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
