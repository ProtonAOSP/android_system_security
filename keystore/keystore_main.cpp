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

#include <android-base/logging.h>
#include <android/security/IKeystoreService.h>
#include <android/system/wifi/keystore/1.0/IKeystore.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <hidl/HidlTransportSupport.h>
#include <utils/StrongPointer.h>
#include <wifikeystorehal/keystore.h>

#include <keystore/keystore_hidl_support.h>
#include <keystore/keystore_return_types.h>

#include "KeyStore.h"
#include "Keymaster3.h"
#include "entropy.h"
#include "key_store_service.h"
#include "legacy_keymaster_device_wrapper.h"
#include "permissions.h"

/* KeyStore is a secured storage for key-value pairs. In this implementation,
 * each file stores one key-value pair. Keys are encoded in file names, and
 * values are encrypted with checksums. The encryption key is protected by a
 * user-defined password. To keep things simple, buffers are always larger than
 * the maximum space we needed, so boundary checks on buffers are omitted. */

using ::android::sp;
using ::android::hardware::configureRpcThreadpool;
using ::android::system::wifi::keystore::V1_0::IKeystore;
using ::android::system::wifi::keystore::V1_0::implementation::Keystore;

using keystore::Keymaster;

/**
 * TODO implement keystore daemon using binderized keymaster HAL.
 */

int main(int argc, char* argv[]) {
    using android::hardware::hidl_string;
    CHECK(argc >= 2) << "A directory must be specified!";
    CHECK(chdir(argv[1]) != -1) << "chdir: " << argv[1] << ": " << strerror(errno);

    Entropy entropy;
    CHECK(entropy.open()) << "Failed to open entropy source.";

    auto hwdev = android::hardware::keymaster::V3_0::IKeymasterDevice::getService();
    CHECK(hwdev.get()) << "Failed to load @3.0::IKeymasterDevice";
    sp<Keymaster> dev = new keystore::Keymaster3(hwdev);

    auto fbdev = android::keystore::makeSoftwareKeymasterDevice();
    if (fbdev.get() == nullptr) return -1;
    sp<Keymaster> fallback = new keystore::Keymaster3(fbdev);

    CHECK(configure_selinux() != -1) << "Failed to configure SELinux.";

    auto halVersion = dev->halVersion();
    CHECK(halVersion.error == keystore::ErrorCode::OK)
        << "Error " << toString(halVersion.error) << " getting HAL version";

    // If the hardware is keymaster 2.0 or higher we will not allow the fallback device for import
    // or generation of keys. The fallback device is only used for legacy keys present on the
    // device.
    bool allowNewFallbackDevice = halVersion.majorVersion >= 2 && halVersion.isSecure;

    keystore::KeyStore keyStore(&entropy, dev, fallback, allowNewFallbackDevice);
    keyStore.initialize();
    android::sp<android::IServiceManager> sm = android::defaultServiceManager();
    android::sp<keystore::KeyStoreService> service = new keystore::KeyStoreService(&keyStore);
    android::status_t ret = sm->addService(android::String16("android.security.keystore"), service);
    CHECK(ret == android::OK) << "Couldn't register binder service!";

    /**
     * Register the wifi keystore HAL service to run in passthrough mode.
     * This will spawn off a new thread which will service the HIDL
     * transactions.
     */
    configureRpcThreadpool(1, false /* callerWillJoin */);
    android::sp<IKeystore> wifiKeystoreHalService = new Keystore();
    android::status_t err = wifiKeystoreHalService->registerAsService();
    CHECK(ret == android::OK) << "Cannot register wifi keystore HAL service: " << err;

    /*
     * This thread is just going to process Binder transactions.
     */
    android::IPCThreadState::self()->joinThreadPool();
    return 1;
}
