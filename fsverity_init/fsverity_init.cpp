/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "fsverity_init"

#include <sys/types.h>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <keystore/keystore_client.h>
#include <keystore/keystore_client_impl.h>
#include <keystore/keystore_get.h>
#include <log/log.h>
#include <mini_keyctl_utils.h>
#include <private/android_filesystem_config.h>

bool LoadKeyToKeyring(key_serial_t keyring_id, const char* desc, const char* data, size_t size) {
    key_serial_t key = add_key("asymmetric", desc, data, size, keyring_id);
    if (key < 0) {
        PLOG(ERROR) << "Failed to add key";
        return false;
    }
    return true;
}

void LoadKeyFromVerifiedPartitions(key_serial_t keyring_id) {
    const char* dir = "/product/etc/security/fsverity";
    if (!std::filesystem::exists(dir)) {
        LOG(ERROR) << "no such dir: " << dir;
        return;
    }
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (!android::base::EndsWithIgnoreCase(entry.path().c_str(), ".der")) continue;
        std::string content;
        if (!android::base::ReadFileToString(entry.path(), &content)) {
            continue;
        }
        if (!LoadKeyToKeyring(keyring_id, "fsv_system", content.c_str(), content.size())) {
            LOG(ERROR) << "Failed to load key from " << entry.path();
        }
    }
}

std::unique_ptr<keystore::KeystoreClient> CreateKeystoreInstance() {
    return std::unique_ptr<keystore::KeystoreClient>(
        static_cast<keystore::KeystoreClient*>(new keystore::KeystoreClientImpl));
}

void LoadKeysFromKeystore(key_serial_t keyring_id) {
    auto client = CreateKeystoreInstance();

    std::vector<std::string> aliases;
    if (client == nullptr || !client->listKeysOfUid("FSV_", AID_FSVERITY_CERT, &aliases)) {
        LOG(ERROR) << "Failed to list key";
        return;
    }

    // Always try to load all keys even if some fails to load. The rest may still
    // be important to have.
    for (auto& alias : aliases) {
        auto blob = client->getKey(alias, AID_FSVERITY_CERT);
        if (!LoadKeyToKeyring(keyring_id, "fsv_user", reinterpret_cast<char*>(blob->data()),
                              blob->size())) {
            LOG(ERROR) << "Failed to load key " << alias << " from keyring";
        }
    }
}

int main(int /*argc*/, const char** /*argv*/) {
    key_serial_t keyring_id = android::GetKeyringId(".fs-verity");
    if (keyring_id < 0) {
        LOG(ERROR) << "Failed to find .fs-verity keyring id";
        return -1;
    }

    // Requires files backed by fs-verity to be verified with a key in .fs-verity
    // keyring.
    if (!android::base::WriteStringToFile("1", "/proc/sys/fs/verity/require_signatures")) {
        PLOG(ERROR) << "Failed to enforce fs-verity signature";
    }

    LoadKeyFromVerifiedPartitions(keyring_id);
    LoadKeysFromKeystore(keyring_id);

    if (!android::base::GetBoolProperty("ro.debuggable", false)) {
        if (keyctl_restrict_keyring(keyring_id, nullptr, nullptr) < 0) {
            PLOG(ERROR) << "Cannot restrict .fs-verity keyring";
        }
    }
    return 0;
}
