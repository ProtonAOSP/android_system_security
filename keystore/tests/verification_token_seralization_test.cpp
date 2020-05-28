/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <keymasterV4_0/keymaster_utils.h>

namespace keystore {
namespace test {

using android::hardware::keymaster::V4_0::SecurityLevel;
using android::hardware::keymaster::V4_0::VerificationToken;
using android::hardware::keymaster::V4_0::support::deserializeVerificationToken;
using android::hardware::keymaster::V4_0::support::serializeVerificationToken;
using std::optional;
using std::vector;

TEST(VerificationTokenSeralizationTest, SerializationTest) {
    VerificationToken token;
    token.challenge = 12345;
    token.timestamp = 67890;
    token.securityLevel = SecurityLevel::TRUSTED_ENVIRONMENT;
    token.mac.resize(32);
    for (size_t n = 0; n < 32; n++) {
        token.mac[n] = n;
    }
    optional<vector<uint8_t>> serialized = serializeVerificationToken(token);
    ASSERT_TRUE(serialized.has_value());
    optional<VerificationToken> deserialized = deserializeVerificationToken(serialized.value());
    ASSERT_TRUE(deserialized.has_value());
    ASSERT_EQ(token.challenge, deserialized.value().challenge);
    ASSERT_EQ(token.timestamp, deserialized.value().timestamp);
    ASSERT_EQ(token.securityLevel, deserialized.value().securityLevel);
    ASSERT_EQ(0u, deserialized.value().parametersVerified.size());
    ASSERT_EQ(token.mac, deserialized.value().mac);
}

TEST(VerificationTokenSeralizationTest, SerializationTestNoMac) {
    VerificationToken token;
    token.challenge = 12345;
    token.timestamp = 67890;
    token.securityLevel = SecurityLevel::TRUSTED_ENVIRONMENT;
    token.mac.resize(0);
    optional<vector<uint8_t>> serialized = serializeVerificationToken(token);
    ASSERT_TRUE(serialized.has_value());
    optional<VerificationToken> deserialized = deserializeVerificationToken(serialized.value());
    ASSERT_TRUE(deserialized.has_value());
    ASSERT_EQ(token.challenge, deserialized.value().challenge);
    ASSERT_EQ(token.timestamp, deserialized.value().timestamp);
    ASSERT_EQ(token.securityLevel, deserialized.value().securityLevel);
    ASSERT_EQ(0u, deserialized.value().parametersVerified.size());
    ASSERT_EQ(token.mac, deserialized.value().mac);
}

}  // namespace test
}  // namespace keystore
