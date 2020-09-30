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

#include "km_compat.h"
#include <android/binder_manager.h>

extern "C" {

// Create a KeyMintDevice and add it as a service.
int32_t addKeyMintDeviceService() {
    std::shared_ptr<KeystoreCompatService> ti = ndk::SharedRefBase::make<KeystoreCompatService>();
    const auto instanceName = "android.security.compat";
    binder_status_t status = AServiceManager_addService(ti->asBinder().get(), instanceName);
    return status;
}
}
