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

#include <filesystem>
#include <map>
#include <string>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <libfsverity.h>
#include <linux/fsverity.h>

#include "CertUtils.h"
#include "SigningKey.h"

#define FS_VERITY_MAX_DIGEST_SIZE 64

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::unique_fd;

static const char* kFsVerityInitPath = "/system/bin/fsverity_init";

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define cpu_to_le16(v) ((__force __le16)(uint16_t)(v))
#define le16_to_cpu(v) ((__force uint16_t)(__le16)(v))
#else
#define cpu_to_le16(v) ((__force __le16)__builtin_bswap16(v))
#define le16_to_cpu(v) (__builtin_bswap16((__force uint16_t)(v)))
#endif

struct fsverity_signed_digest {
    char magic[8]; /* must be "FSVerity" */
    __le16 digest_algorithm;
    __le16 digest_size;
    __u8 digest[];
};

static std::string toHex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    for (auto it = data.begin(); it != data.end(); ++it) {
        ss << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned>(*it);
    }
    return ss.str();
}

static int read_callback(void* file, void* buf, size_t count) {
    int* fd = (int*)file;
    if (TEMP_FAILURE_RETRY(read(*fd, buf, count)) < 0) return errno ? -errno : -EIO;
    return 0;
}

Result<std::vector<uint8_t>> createDigest(const std::string& path) {
    struct stat filestat;
    unique_fd fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC)));

    stat(path.c_str(), &filestat);
    struct libfsverity_merkle_tree_params params = {
        .version = 1,
        .hash_algorithm = FS_VERITY_HASH_ALG_SHA256,
        .file_size = static_cast<uint64_t>(filestat.st_size),
        .block_size = 4096,
    };

    struct libfsverity_digest* digest;
    libfsverity_compute_digest(&fd, &read_callback, &params, &digest);

    return std::vector<uint8_t>(&digest->digest[0], &digest->digest[32]);
}

namespace {
template <typename T> struct DeleteAsPODArray {
    void operator()(T* x) {
        if (x) {
            x->~T();
            delete[](uint8_t*) x;
        }
    }
};
}  // namespace

template <typename T> using trailing_unique_ptr = std::unique_ptr<T, DeleteAsPODArray<T>>;

template <typename T>
static trailing_unique_ptr<T> makeUniqueWithTrailingData(size_t trailing_data_size) {
    uint8_t* memory = new uint8_t[sizeof(T*) + trailing_data_size];
    T* ptr = new (memory) T;
    return trailing_unique_ptr<T>{ptr};
}

static Result<std::vector<uint8_t>> signDigest(const SigningKey& key,
                                               const std::vector<uint8_t>& digest) {
    auto d = makeUniqueWithTrailingData<fsverity_signed_digest>(digest.size());

    memcpy(d->magic, "FSVerity", 8);
    d->digest_algorithm = cpu_to_le16(FS_VERITY_HASH_ALG_SHA256);
    d->digest_size = cpu_to_le16(digest.size());
    memcpy(d->digest, digest.data(), digest.size());

    auto signed_digest = key.sign(std::string((char*)d.get(), sizeof(*d) + digest.size()));
    if (!signed_digest.ok()) {
        return signed_digest.error();
    }

    return std::vector<uint8_t>(signed_digest->begin(), signed_digest->end());
}

Result<std::string> enableFsVerity(const std::string& path, const SigningKey& key) {
    auto digest = createDigest(path);
    if (!digest.ok()) {
        return digest.error();
    }

    auto signed_digest = signDigest(key, digest.value());
    if (!signed_digest.ok()) {
        return signed_digest.error();
    }

    auto pkcs7_data = createPkcs7(signed_digest.value());

    struct fsverity_enable_arg arg = {.version = 1};

    arg.sig_ptr = (uint64_t)pkcs7_data->data();
    arg.sig_size = pkcs7_data->size();
    arg.hash_algorithm = FS_VERITY_HASH_ALG_SHA256;
    arg.block_size = 4096;

    unique_fd fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC)));
    int ret = ioctl(fd, FS_IOC_ENABLE_VERITY, &arg);

    if (ret != 0) {
        return ErrnoError() << "Failed to call FS_IOC_ENABLE_VERITY on " << path;
    }

    // Return the root hash as a hex string
    return toHex(digest.value());
}

Result<std::map<std::string, std::string>> addFilesToVerityRecursive(const std::string& path,
                                                                     const SigningKey& key) {
    std::map<std::string, std::string> digests;
    std::error_code ec;

    auto it = std::filesystem::recursive_directory_iterator(path, ec);
    auto end = std::filesystem::recursive_directory_iterator();

    while (!ec && it != end) {
        if (it->is_regular_file()) {
            LOG(INFO) << "Adding " << it->path() << " to fs-verity...";
            auto result = enableFsVerity(it->path(), key);
            if (!result.ok()) {
                return result.error();
            }
            digests[it->path()] = *result;
        }
        ++it;
    }
    if (ec) {
        return Error() << "Failed to iterate " << path << ": " << ec;
    }

    return digests;
}

Result<std::string> isFileInVerity(const std::string& path) {
    unsigned int flags;

    unique_fd fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        return ErrnoError() << "Failed to open " << path;
    }

    int ret = ioctl(fd, FS_IOC_GETFLAGS, &flags);
    if (ret < 0) {
        return ErrnoError() << "Failed to FS_IOC_GETFLAGS for " << path;
    }
    if (!(flags & FS_VERITY_FL)) {
        return Error() << "File is not in fs-verity: " << path;
    }

    auto d = makeUniqueWithTrailingData<fsverity_digest>(FS_VERITY_MAX_DIGEST_SIZE);
    d->digest_size = FS_VERITY_MAX_DIGEST_SIZE;
    ret = ioctl(fd, FS_IOC_MEASURE_VERITY, d.get());
    if (ret < 0) {
        return ErrnoError() << "Failed to FS_IOC_MEASURE_VERITY for " << path;
    }
    std::vector<uint8_t> digest_vector(&d->digest[0], &d->digest[d->digest_size]);

    return toHex(digest_vector);
}

Result<std::map<std::string, std::string>> verifyAllFilesInVerity(const std::string& path) {
    std::map<std::string, std::string> digests;
    std::error_code ec;

    auto it = std::filesystem::recursive_directory_iterator(path, ec);
    auto end = std::filesystem::recursive_directory_iterator();

    while (!ec && it != end) {
        if (it->is_regular_file()) {
            // Verify
            auto result = isFileInVerity(it->path());
            if (!result.ok()) {
                return result.error();
            }
            digests[it->path()] = *result;
        }  // TODO reject other types besides dirs?
        ++it;
    }
    if (ec) {
        return Error() << "Failed to iterate " << path << ": " << ec;
    }

    return digests;
}

Result<void> addCertToFsVerityKeyring(const std::string& path) {
    const char* const argv[] = {kFsVerityInitPath, "--load-extra-key", "fsv_ods"};

    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
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
