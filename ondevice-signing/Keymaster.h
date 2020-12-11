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

#include <optional>

#include <android-base/macros.h>
#include <android-base/result.h>
#include <android-base/unique_fd.h>

#include <keymasterV4_1/Keymaster.h>

#include <utils/StrongPointer.h>

enum class KeymasterVerifyResult {
    OK = 0,
    UPGRADE = -1,
};

class Keymaster {
    using KmDevice = ::android::hardware::keymaster::V4_1::IKeymasterDevice;

  public:
    static std::optional<Keymaster> getInstance();

    android::base::Result<std::vector<uint8_t>> createKey() const;

    android::base::Result<std::vector<uint8_t>>
    extractPublicKey(const std::vector<uint8_t>& keyBlob) const;

    android::base::Result<KeymasterVerifyResult>
    verifyKey(const std::vector<uint8_t>& keyBlob) const;

    android::base::Result<std::vector<uint8_t>>
    upgradeKey(const std::vector<uint8_t>& keyBlob) const;

    /* Sign a message with an initialized signing key */
    android::base::Result<std::string> sign(const std::vector<uint8_t>& keyBlob,
                                            const std::string& message) const;

  private:
    Keymaster();
    bool initialize();

    android::sp<KmDevice> mDevice;
};
