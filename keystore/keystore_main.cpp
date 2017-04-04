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

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

#include <android/hardware/keymaster/3.0/IHwKeymasterDevice.h>
#include <android/system/wifi/keystore/1.0/IKeystore.h>
#include <wifikeystorehal/keystore.h>

#include <cutils/log.h>

#include "entropy.h"
#include "key_store_service.h"
#include "keystore.h"
#include "permissions.h"
#include "legacy_keymaster_device_wrapper.h"
#include "include/keystore/keystore_hidl_support.h"
#include "include/keystore/keystore_return_types.h"

/* KeyStore is a secured storage for key-value pairs. In this implementation,
 * each file stores one key-value pair. Keys are encoded in file names, and
 * values are encrypted with checksums. The encryption key is protected by a
 * user-defined password. To keep things simple, buffers are always larger than
 * the maximum space we needed, so boundary checks on buffers are omitted. */

using ::android::system::wifi::keystore::V1_0::IKeystore;
using ::android::system::wifi::keystore::V1_0::implementation::Keystore;
using ::android::hardware::configureRpcThreadpool;

/**
 * TODO implement keystore daemon using binderized keymaster HAL.
 */

int main(int argc, char* argv[]) {
    using android::hardware::hidl_string;
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

    auto dev = android::hardware::keymaster::V3_0::IKeymasterDevice::getService();
    if (dev.get() == nullptr) {
        return -1;
    }
    auto fallback = android::keystore::makeSoftwareKeymasterDevice();
    if (dev.get() == nullptr) {
        return -1;
    }

    if (configure_selinux() == -1) {
        return -1;
    }

    bool allowNewFallbackDevice = false;

    keystore::KeyStoreServiceReturnCode rc;
    rc = KS_HANDLE_HIDL_ERROR(dev->getHardwareFeatures(
            [&] (bool, bool, bool, bool supportsAttestation, bool, const hidl_string&,
                 const hidl_string&) {
                // Attestation support indicates the hardware is keymaster 2.0 or higher.
                // For these devices we will not allow the fallback device for import or generation
                // of keys. The fallback device is only used for legacy keys present on the device.
                allowNewFallbackDevice = !supportsAttestation;
            }));

    if (!rc.isOk()) {
        return -1;
    }

    KeyStore keyStore(&entropy, dev, fallback, allowNewFallbackDevice);
    keyStore.initialize();
    android::sp<android::IServiceManager> sm = android::defaultServiceManager();
    android::sp<keystore::KeyStoreService> service = new keystore::KeyStoreService(&keyStore);
    android::status_t ret = sm->addService(android::String16("android.security.keystore"), service);
    if (ret != android::OK) {
        ALOGE("Couldn't register binder service!");
        return -1;
    }

    /**
     * Register the wifi keystore HAL service to run in passthrough mode.
     * This will spawn off a new thread which will service the HIDL
     * transactions.
     */
    configureRpcThreadpool(1, false /* callerWillJoin */);
    android::sp<IKeystore> wifiKeystoreHalService = new Keystore();
    android::status_t err = wifiKeystoreHalService->registerAsService();
    if (ret != android::OK) {
        ALOGE("Cannot register wifi keystore HAL service: %d", err);
    }

    /*
     * This thread is just going to process Binder transactions.
     */
    android::IPCThreadState::self()->joinThreadPool();
    return 1;
}
