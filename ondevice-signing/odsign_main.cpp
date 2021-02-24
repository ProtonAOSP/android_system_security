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

#include <fcntl.h>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/scopeguard.h>
#include <logwrap/logwrap.h>

#include "CertUtils.h"
#include "KeymasterSigningKey.h"
#include "VerityUtils.h"

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;

const std::string kSigningKeyBlob = "/data/misc/odsign/key.blob";
const std::string kSigningKeyCert = "/data/misc/odsign/key.cert";

const std::string kArtArtifactsDir = "/data/misc/apexdata/com.android.art/dalvik-cache";

static const char* kOdrefreshPath = "/apex/com.android.art/bin/odrefresh";

static const char* kFsVerityInitPath = "/system/bin/fsverity_init";

static const bool kForceCompilation = false;

Result<void> addCertToFsVerityKeyring(const std::string& path) {
    const char* const argv[] = {kFsVerityInitPath, "--load-extra-key", "fsv_ods"};

    // NOLINTNEXTLINE(android-cloexec-open): Deliberately not O_CLOEXEC
    int fd = open(path.c_str(), O_RDONLY);
    pid_t pid = fork();
    if (pid == 0) {
        dup2(fd, STDIN_FILENO);
        close(fd);
        int argc = arraysize(argv);
        char* argv_child[argc + 1];
        memcpy(argv_child, argv, argc * sizeof(char*));
        argv_child[argc] = nullptr;
        execvp(argv_child[0], const_cast<char**>(argv_child));
        PLOG(ERROR) << "exec in ForkExecvp";
        _exit(EXIT_FAILURE);
    } else {
        close(fd);
    }
    if (pid == -1) {
        return ErrnoError() << "Failed to fork.";
    }
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        return ErrnoError() << "waitpid() failed.";
    }
    if (!WIFEXITED(status)) {
        return Error() << kFsVerityInitPath << ": abnormal process exit";
    }
    if (WEXITSTATUS(status)) {
        if (status != 0) {
            return Error() << kFsVerityInitPath << " exited with " << status;
        }
    }

    return {};
}

Result<KeymasterSigningKey> loadAndVerifyExistingKey() {
    if (access(kSigningKeyBlob.c_str(), F_OK) < 0) {
        return ErrnoError() << "Key blob not found: " << kSigningKeyBlob;
    }
    return KeymasterSigningKey::loadFromBlobAndVerify(kSigningKeyBlob);
}

Result<void> verifyExistingCert(const KeymasterSigningKey& key) {
    if (access(kSigningKeyCert.c_str(), F_OK) < 0) {
        return ErrnoError() << "Key certificate not found: " << kSigningKeyCert;
    }
    auto trustedPublicKey = key.getPublicKey();
    if (!trustedPublicKey.ok()) {
        return Error() << "Failed to retrieve signing public key.";
    }

    auto publicKeyFromExistingCert = extractPublicKeyFromX509(kSigningKeyCert);
    if (!publicKeyFromExistingCert.ok()) {
        return publicKeyFromExistingCert.error();
    }
    if (publicKeyFromExistingCert.value() != trustedPublicKey.value()) {
        return Error() << "Public key of existing certificate at " << kSigningKeyCert
                       << " does not match signing public key.";
    }

    // At this point, we know the cert matches
    return {};
}

Result<KeymasterSigningKey> createAndPersistKey(const std::string& path) {
    auto key = KeymasterSigningKey::createNewKey();

    if (!key.ok()) {
        return key.error();
    }

    auto result = key->saveKeyblob(path);
    if (!result.ok()) {
        return result.error();
    }

    return key;
}

bool compileArtifacts(bool force) {
    const char* const argv[] = {kOdrefreshPath, force ? "--force-compile" : "--compile"};

    return logwrap_fork_execvp(arraysize(argv), argv, nullptr, false, LOG_ALOG, false, nullptr) ==
           0;
}

bool validateArtifacts() {
    const char* const argv[] = {kOdrefreshPath, "--check"};

    return logwrap_fork_execvp(arraysize(argv), argv, nullptr, false, LOG_ALOG, false, nullptr) ==
           0;
}

int main(int /* argc */, char** /* argv */) {
    auto removeArtifacts = []() {
        std::error_code ec;
        auto num_removed = std::filesystem::remove_all(kArtArtifactsDir, ec);
        if (ec) {
            // TODO can't remove artifacts, signal Zygote shouldn't use them
            LOG(ERROR) << "Can't remove " << kArtArtifactsDir << ": " << ec.message();
        } else {
            LOG(INFO) << "Removed " << num_removed << " entries from " << kArtArtifactsDir;
        }
    };
    // Make sure we delete the artifacts in all early (error) exit paths
    auto scope_guard = android::base::make_scope_guard(removeArtifacts);

    auto key = loadAndVerifyExistingKey();
    if (!key.ok()) {
        LOG(WARNING) << key.error().message();

        key = createAndPersistKey(kSigningKeyBlob);
        if (!key.ok()) {
            LOG(ERROR) << "Failed to create or persist new key: " << key.error().message();
            return -1;
        }
    } else {
        LOG(INFO) << "Found and verified existing key: " << kSigningKeyBlob;
    }

    auto existing_cert = verifyExistingCert(key.value());
    if (!existing_cert.ok()) {
        LOG(WARNING) << existing_cert.error().message();

        // Try to create a new cert
        auto new_cert = key->createX509Cert(kSigningKeyCert);
        if (!new_cert.ok()) {
            LOG(ERROR) << "Failed to create X509 certificate: " << new_cert.error().message();
            // TODO apparently the key become invalid - delete the blob / cert
            return -1;
        }
    } else {
        LOG(INFO) << "Found and verified existing public key certificate: " << kSigningKeyCert;
    }
    auto cert_add_result = addCertToFsVerityKeyring(kSigningKeyCert);
    if (!cert_add_result.ok()) {
        LOG(ERROR) << "Failed to add certificate to fs-verity keyring: "
                   << cert_add_result.error().message();
        return -1;
    }

    auto verityStatus = verifyAllFilesInVerity(kArtArtifactsDir);
    if (!verityStatus.ok()) {
        LOG(WARNING) << verityStatus.error().message() << ", removing " << kArtArtifactsDir;
        removeArtifacts();
    }

    bool artifactsValid = validateArtifacts();

    if (!artifactsValid || kForceCompilation) {
        removeArtifacts();

        LOG(INFO) << "Starting compilation... ";
        bool ret = compileArtifacts(kForceCompilation);
        LOG(INFO) << "Compilation done, returned " << ret;

        verityStatus = addFilesToVerityRecursive(kArtArtifactsDir, key.value());

        if (!verityStatus.ok()) {
            LOG(ERROR) << "Failed to add " << verityStatus.error().message();
            return -1;
        }
    }

    // TODO we want to make sure Zygote only picks up the artifacts if we deemed
    // everything was ok here. We could use a sysprop, or some other mechanism?
    LOG(INFO) << "On-device signing done.";

    scope_guard.Disable();
    return 0;
}
