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
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
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

#include "odsign_info.pb.h"

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;

using OdsignInfo = ::odsign::proto::OdsignInfo;

const std::string kSigningKeyBlob = "/data/misc/odsign/key.blob";
const std::string kSigningKeyCert = "/data/misc/odsign/key.cert";
const std::string kOdsignInfo = "/data/misc/odsign/odsign.info";
const std::string kOdsignInfoSignature = "/data/misc/odsign/odsign.info.signature";

const std::string kArtArtifactsDir = "/data/misc/apexdata/com.android.art/dalvik-cache";

static const char* kOdrefreshPath = "/apex/com.android.art/bin/odrefresh";

static const char* kFsVerityInitPath = "/system/bin/fsverity_init";
static const char* kFsVerityProcPath = "/proc/sys/fs/verity";

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

static std::string toHex(const std::vector<uint8_t>& digest) {
    std::stringstream ss;
    for (auto it = digest.begin(); it != digest.end(); ++it) {
        ss << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned>(*it);
    }
    return ss.str();
}

Result<std::map<std::string, std::string>> computeDigests(const std::string& path) {
    std::error_code ec;
    std::map<std::string, std::string> digests;

    auto it = std::filesystem::recursive_directory_iterator(path, ec);
    auto end = std::filesystem::recursive_directory_iterator();

    while (!ec && it != end) {
        if (it->is_regular_file()) {
            auto digest = createDigest(it->path());
            if (!digest.ok()) {
                return Error() << "Failed to compute digest for " << it->path();
            }
            digests[it->path()] = toHex(*digest);
        }
        ++it;
    }
    if (ec) {
        return Error() << "Failed to iterate " << path << ": " << ec;
    }

    return digests;
}

Result<void> verifyDigests(const std::map<std::string, std::string>& digests,
                           const std::map<std::string, std::string>& trusted_digests) {
    for (const auto& path_digest : digests) {
        auto path = path_digest.first;
        auto digest = path_digest.second;
        if ((trusted_digests.count(path) == 0)) {
            return Error() << "Couldn't find digest for " << path;
        }
        if (trusted_digests.at(path) != digest) {
            return Error() << "Digest mismatch for " << path;
        }
    }

    // All digests matched!
    if (digests.size() > 0) {
        LOG(INFO) << "All root hashes match.";
    }
    return {};
}

Result<void> verifyIntegrityFsVerity(const std::map<std::string, std::string>& trusted_digests) {
    // Just verify that the files are in verity, and get their digests
    auto result = verifyAllFilesInVerity(kArtArtifactsDir);
    if (!result.ok()) {
        return result.error();
    }

    return verifyDigests(*result, trusted_digests);
}

Result<void> verifyIntegrityNoFsVerity(const std::map<std::string, std::string>& trusted_digests) {
    // On these devices, just compute the digests, and verify they match the ones we trust
    auto result = computeDigests(kArtArtifactsDir);
    if (!result.ok()) {
        return result.error();
    }

    return verifyDigests(*result, trusted_digests);
}

Result<OdsignInfo> getOdsignInfo(const KeymasterSigningKey& /* key */) {
    std::string persistedSignature;
    OdsignInfo odsignInfo;

    if (!android::base::ReadFileToString(kOdsignInfoSignature, &persistedSignature)) {
        return ErrnoError() << "Failed to read " << kOdsignInfoSignature;
    }

    std::fstream odsign_info(kOdsignInfo, std::ios::in | std::ios::binary);
    if (!odsign_info) {
        return Error() << "Failed to open " << kOdsignInfo;
    }
    // Verify the hash
    std::string odsign_info_str((std::istreambuf_iterator<char>(odsign_info)),
                                std::istreambuf_iterator<char>());

    // TODO: this is way too slow - replace with a local RSA_verify implementation.
    /*
    auto verifiedSignature = key.sign(odsign_info_str);
    if (!verifiedSignature.ok()) {
        return Error() << "Failed to sign " << kOdsignInfo;
    }

    if (*verifiedSignature != persistedSignature) {
        return Error() << kOdsignInfoSignature << " does not match.";
    } else {
        LOG(INFO) << kOdsignInfoSignature << " matches.";
    }
    */

    if (!odsignInfo.ParseFromIstream(&odsign_info)) {
        return Error() << "Failed to parse " << kOdsignInfo;
    }

    LOG(INFO) << "Loaded " << kOdsignInfo;
    return odsignInfo;
}

Result<void> persistDigests(const std::map<std::string, std::string>& digests,
                            const KeymasterSigningKey& key) {
    OdsignInfo signInfo;
    google::protobuf::Map<std::string, std::string> proto_hashes(digests.begin(), digests.end());
    auto map = signInfo.mutable_file_hashes();
    *map = proto_hashes;

    std::fstream odsign_info(kOdsignInfo, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!signInfo.SerializeToOstream(&odsign_info)) {
        return Error() << "Failed to persist root hashes in " << kOdsignInfo;
    }

    odsign_info.seekg(0);
    std::string odsign_info_str((std::istreambuf_iterator<char>(odsign_info)),
                                std::istreambuf_iterator<char>());
    auto signResult = key.sign(odsign_info_str);
    if (!signResult.ok()) {
        return Error() << "Failed to sign " << kOdsignInfo;
    }
    // Sign the files with our key itself, and write that to storage
    android::base::WriteStringToFile(*signResult, kOdsignInfoSignature);
    return {};
}

int main(int /* argc */, char** /* argv */) {
    auto removeArtifacts = []() -> std::uintmax_t {
        std::error_code ec;
        auto num_removed = std::filesystem::remove_all(kArtArtifactsDir, ec);
        if (ec) {
            // TODO can't remove artifacts, signal Zygote shouldn't use them
            LOG(ERROR) << "Can't remove " << kArtArtifactsDir << ": " << ec.message();
            return 0;
        } else {
            if (num_removed > 0) {
                LOG(INFO) << "Removed " << num_removed << " entries from " << kArtArtifactsDir;
            }
            return num_removed;
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

    bool supportsFsVerity = access(kFsVerityProcPath, F_OK) == 0;
    if (!supportsFsVerity) {
        LOG(INFO) << "Device doesn't support fsverity. Falling back to full verification.";
    }

    if (supportsFsVerity) {
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
    }

    auto signInfo = getOdsignInfo(key.value());
    if (!signInfo.ok()) {
        int num_removed = removeArtifacts();
        // Only a warning if there were artifacts to begin with, which suggests tampering or
        // corruption
        if (num_removed > 0) {
            LOG(WARNING) << signInfo.error().message();
        }
    } else {
        std::map<std::string, std::string> trusted_digests(signInfo->file_hashes().begin(),
                                                           signInfo->file_hashes().end());
        Result<void> integrityStatus;

        if (supportsFsVerity) {
            integrityStatus = verifyIntegrityFsVerity(trusted_digests);
        } else {
            integrityStatus = verifyIntegrityNoFsVerity(trusted_digests);
        }
        if (!integrityStatus.ok()) {
            LOG(WARNING) << integrityStatus.error().message() << ", removing " << kArtArtifactsDir;
            removeArtifacts();
        }
    }

    // Ask ART whether it considers the artifacts valid
    LOG(INFO) << "Asking odrefresh to verify artifacts (if present)...";
    bool artifactsValid = validateArtifacts();
    LOG(INFO) << "odrefresh said they are " << (artifactsValid ? "VALID" : "INVALID");

    if (!artifactsValid || kForceCompilation) {
        LOG(INFO) << "Starting compilation... ";
        bool ret = compileArtifacts(kForceCompilation);
        LOG(INFO) << "Compilation done, returned " << ret;

        Result<std::map<std::string, std::string>> digests;
        if (supportsFsVerity) {
            digests = addFilesToVerityRecursive(kArtArtifactsDir, key.value());
        } else {
            // If we can't use verity, just compute the root hashes and store
            // those, so we can reverify them at the next boot.
            digests = computeDigests(kArtArtifactsDir);
        }
        if (!digests.ok()) {
            LOG(ERROR) << digests.error().message();
            return -1;
        }

        auto persistStatus = persistDigests(*digests, key.value());
        if (!persistStatus.ok()) {
            LOG(ERROR) << persistStatus.error().message();
            return -1;
        }
    }

    // TODO we want to make sure Zygote only picks up the artifacts if we deemed
    // everything was ok here. We could use a sysprop, or some other mechanism?
    LOG(INFO) << "On-device signing done.";

    scope_guard.Disable();
    return 0;
}
