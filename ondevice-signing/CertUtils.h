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

#include <android-base/result.h>

android::base::Result<void> createSelfSignedCertificate(
    const std::vector<uint8_t>& publicKey,
    const std::function<android::base::Result<std::string>(const std::string&)>& signFunction,
    const std::string& path);
android::base::Result<std::vector<uint8_t>> createPkcs7(const std::vector<uint8_t>& signedData);

android::base::Result<std::vector<uint8_t>>
extractPublicKeyFromX509(const std::vector<uint8_t>& x509);
android::base::Result<std::vector<uint8_t>>
extractPublicKeyFromSubjectPublicKeyInfo(const std::vector<uint8_t>& subjectKeyInfo);
android::base::Result<std::vector<uint8_t>> extractPublicKeyFromX509(const std::string& path);

android::base::Result<void> verifySignature(const std::string& message,
                                            const std::string& signature,
                                            const std::vector<uint8_t>& publicKey);
