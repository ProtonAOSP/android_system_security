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

#pragma once

#include <android-base/macros.h>
#include <android-base/result.h>
#include <android-base/unique_fd.h>

#include <utils/StrongPointer.h>

#include "Keymaster.h"
#include "SigningKey.h"

class KeymasterSigningKey : public SigningKey {
    using KmDevice = ::android::hardware::keymaster::V4_1::IKeymasterDevice;

  public:
    friend std::unique_ptr<KeymasterSigningKey> std::make_unique<KeymasterSigningKey>();
    virtual ~KeymasterSigningKey(){};

    // Allow the key to be moved around
    KeymasterSigningKey& operator=(KeymasterSigningKey&& other) = default;
    KeymasterSigningKey(KeymasterSigningKey&& other) = default;

    static android::base::Result<SigningKey*> getInstance();

    virtual android::base::Result<std::string> sign(const std::string& message) const;
    virtual android::base::Result<std::vector<uint8_t>> getPublicKey() const;

  private:
    KeymasterSigningKey();

    static android::base::Result<std::unique_ptr<KeymasterSigningKey>> createAndPersistNewKey();
    static android::base::Result<std::unique_ptr<KeymasterSigningKey>>
    loadFromBlobAndVerify(const std::string& path);

    android::base::Result<void> createSigningKey();
    android::base::Result<void> initializeFromKeyblob(const std::string& path);
    android::base::Result<void> saveKeyblob(const std::string& path) const;

    static android::base::Result<KeymasterSigningKey> createNewKey();

    std::optional<Keymaster> mKeymaster;
    std::vector<uint8_t> mVerifiedKeyBlob;

    DISALLOW_COPY_AND_ASSIGN(KeymasterSigningKey);
};
