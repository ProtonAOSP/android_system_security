/*
 * Copyright (C) 2021 The Android Open Source Project
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

#pragma once

#include <optional>

#include <android-base/macros.h>
#include <android-base/result.h>

#include <utils/StrongPointer.h>

#include <android/system/keystore2/IKeystoreService.h>

class KeystoreHmacKey {
    using IKeystoreService = ::android::system::keystore2::IKeystoreService;
    using IKeystoreSecurityLevel = ::android::system::keystore2::IKeystoreSecurityLevel;
    using KeyDescriptor = ::android::system::keystore2::KeyDescriptor;

  public:
    KeystoreHmacKey();
    android::base::Result<void> initialize(android::sp<IKeystoreService> service,
                                           android::sp<IKeystoreSecurityLevel> securityLevel);
    android::base::Result<std::string> sign(const std::string& message) const;
    android::base::Result<void> verify(const std::string& message,
                                       const std::string& signature) const;

  private:
    android::base::Result<void> createKey();
    KeyDescriptor mDescriptor;
    android::sp<IKeystoreService> mService;
    android::sp<IKeystoreSecurityLevel> mSecurityLevel;
};
