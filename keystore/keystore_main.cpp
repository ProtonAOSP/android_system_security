/*
 * Copyright (C) 2009 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "keystore"

#include <keymaster/keymaster_configuration.h>
#include <keymaster/soft_keymaster_device.h>
#include <keymaster/soft_keymaster_logger.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

#include <cutils/log.h>

#include "entropy.h"
#include "key_store_service.h"
#include "keystore.h"
#include "permissions.h"

/* KeyStore is a secured storage for key-value pairs. In this implementation,
 * each file stores one key-value pair. Keys are encoded in file names, and
 * values are encrypted with checksums. The encryption key is protected by a
 * user-defined password. To keep things simple, buffers are always larger than
 * the maximum space we needed, so boundary checks on buffers are omitted. */

using keymaster::AuthorizationSet;
using keymaster::AuthorizationSetBuilder;
using keymaster::SoftKeymasterDevice;

static int configure_keymaster_devices(keymaster2_device_t* main, keymaster2_device_t* fallback) {
    keymaster_error_t error = keymaster::ConfigureDevice(main);
    if (error != KM_ERROR_OK) {
        return -1;
    }

    error = keymaster::ConfigureDevice(fallback);
    if (error != KM_ERROR_OK) {
        return -1;
    }

    return 0;
}

static int keymaster0_device_initialize(const hw_module_t* mod, keymaster2_device_t** dev) {
    assert(mod->module_api_version < KEYMASTER_MODULE_API_VERSION_1_0);
    ALOGI("Found keymaster0 module %s, version %x", mod->name, mod->module_api_version);

    UniquePtr<SoftKeymasterDevice> soft_keymaster(new SoftKeymasterDevice);
    keymaster0_device_t* km0_device = NULL;
    keymaster_error_t error = KM_ERROR_OK;

    int rc = keymaster0_open(mod, &km0_device);
    if (rc) {
        ALOGE("Error opening keystore keymaster0 device.");
        goto err;
    }

    if (km0_device->flags & KEYMASTER_SOFTWARE_ONLY) {
        ALOGI("Keymaster0 module is software-only.  Using SoftKeymasterDevice instead.");
        km0_device->common.close(&km0_device->common);
        km0_device = NULL;
        // SoftKeymasterDevice will be deleted by keymaster_device_release()
        *dev = soft_keymaster.release()->keymaster2_device();
        return 0;
    }

    ALOGD("Wrapping keymaster0 module %s with SoftKeymasterDevice", mod->name);
    error = soft_keymaster->SetHardwareDevice(km0_device);
    km0_device = NULL;  // SoftKeymasterDevice has taken ownership.
    if (error != KM_ERROR_OK) {
        ALOGE("Got error %d from SetHardwareDevice", error);
        rc = error;
        goto err;
    }

    // SoftKeymasterDevice will be deleted by  keymaster_device_release()
    *dev = soft_keymaster.release()->keymaster2_device();
    return 0;

err:
    if (km0_device)
        km0_device->common.close(&km0_device->common);
    *dev = NULL;
    return rc;
}

static int keymaster1_device_initialize(const hw_module_t* mod, keymaster2_device_t** dev) {
    assert(mod->module_api_version >= KEYMASTER_MODULE_API_VERSION_1_0);
    ALOGI("Found keymaster1 module %s, version %x", mod->name, mod->module_api_version);

    UniquePtr<SoftKeymasterDevice> soft_keymaster(new SoftKeymasterDevice);
    keymaster1_device_t* km1_device = nullptr;
    keymaster_error_t error = KM_ERROR_OK;

    int rc = keymaster1_open(mod, &km1_device);
    if (rc) {
        ALOGE("Error %d opening keystore keymaster1 device", rc);
        goto err;
    }

    ALOGD("Wrapping keymaster1 module %s with SofKeymasterDevice", mod->name);
    error = soft_keymaster->SetHardwareDevice(km1_device);
    km1_device = nullptr;  // SoftKeymasterDevice has taken ownership.
    if (error != KM_ERROR_OK) {
        ALOGE("Got error %d from SetHardwareDevice", error);
        rc = error;
        goto err;
    }

    // SoftKeymasterDevice will be deleted by keymaster_device_release()
    *dev = soft_keymaster.release()->keymaster2_device();
    return 0;

err:
    if (km1_device)
        km1_device->common.close(&km1_device->common);
    *dev = NULL;
    return rc;
}

static int keymaster2_device_initialize(const hw_module_t* mod, keymaster2_device_t** dev) {
    assert(mod->module_api_version >= KEYMASTER_MODULE_API_VERSION_2_0);
    ALOGI("Found keymaster2 module %s, version %x", mod->name, mod->module_api_version);

    UniquePtr<SoftKeymasterDevice> soft_keymaster(new SoftKeymasterDevice);
    keymaster2_device_t* km2_device = nullptr;

    int rc = keymaster2_open(mod, &km2_device);
    if (rc) {
        ALOGE("Error %d opening keystore keymaster2 device", rc);
        goto err;
    }

    *dev = km2_device;
    return 0;

err:
    if (km2_device)
        km2_device->common.close(&km2_device->common);
    *dev = nullptr;
    return rc;
}

static int keymaster_device_initialize(keymaster2_device_t** dev) {
    const hw_module_t* mod;

    int rc = hw_get_module_by_class(KEYSTORE_HARDWARE_MODULE_ID, NULL, &mod);
    if (rc) {
        ALOGI("Could not find any keystore module, using software-only implementation.");
        // SoftKeymasterDevice will be deleted by keymaster_device_release()
        *dev = (new SoftKeymasterDevice)->keymaster2_device();
        return 0;
    }

    if (mod->module_api_version < KEYMASTER_MODULE_API_VERSION_1_0) {
        return keymaster0_device_initialize(mod, dev);
    } else if (mod->module_api_version == KEYMASTER_MODULE_API_VERSION_1_0) {
        return keymaster1_device_initialize(mod, dev);
    } else {
        return keymaster2_device_initialize(mod, dev);
    }
}

// softkeymaster_logger appears not to be used in keystore, but it installs itself as the
// logger used by SoftKeymasterDevice.
static keymaster::SoftKeymasterLogger softkeymaster_logger;

static int fallback_keymaster_device_initialize(keymaster2_device_t** dev) {
    *dev = (new SoftKeymasterDevice)->keymaster2_device();
    // SoftKeymasterDevice will be deleted by keymaster_device_release()
    return 0;
}

static void keymaster_device_release(keymaster2_device_t* dev) {
    dev->common.close(&dev->common);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        ALOGE("A directory must be specified!");
        return 1;
    }
    if (chdir(argv[1]) == -1) {
        ALOGE("chdir: %s: %s", argv[1], strerror(errno));
        return 1;
    }

    Entropy entropy;
    if (!entropy.open()) {
        return 1;
    }

    keymaster2_device_t* dev;
    if (keymaster_device_initialize(&dev)) {
        ALOGE("keystore keymaster could not be initialized; exiting");
        return 1;
    }

    keymaster2_device_t* fallback;
    if (fallback_keymaster_device_initialize(&fallback)) {
        ALOGE("software keymaster could not be initialized; exiting");
        return 1;
    }

    if (configure_keymaster_devices(dev, fallback)) {
        ALOGE("Keymaster devices could not be configured; exiting");
        return 1;
    }

    if (configure_selinux() == -1) {
        return -1;
    }

    KeyStore keyStore(&entropy, dev, fallback);
    keyStore.initialize();
    android::sp<android::IServiceManager> sm = android::defaultServiceManager();
    android::sp<android::KeyStoreService> service = new android::KeyStoreService(&keyStore);
    android::status_t ret = sm->addService(android::String16("android.security.keystore"), service);
    if (ret != android::OK) {
        ALOGE("Couldn't register binder service!");
        return -1;
    }

    /*
     * We're the only thread in existence, so we're just going to process
     * Binder transaction as a single-threaded program.
     */
    android::IPCThreadState::self()->joinThreadPool();

    keymaster_device_release(dev);
    return 1;
}
