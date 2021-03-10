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

class SigningKey {
  public:
    virtual ~SigningKey(){};
    /* Sign a message with an initialized signing key */
    virtual android::base::Result<std::string> sign(const std::string& message) const = 0;
    /* Retrieve the associated public key */
    virtual android::base::Result<std::vector<uint8_t>> getPublicKey() const = 0;
};
