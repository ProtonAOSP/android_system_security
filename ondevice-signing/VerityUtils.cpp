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
#include <string>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <libfsverity.h>
#include <linux/fsverity.h>

#include "CertUtils.h"
#include "KeymasterSigningKey.h"

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::unique_fd;

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

static int read_callback(void* file, void* buf, size_t count) {
    int* fd = (int*)file;
    if (TEMP_FAILURE_RETRY(read(*fd, buf, count)) < 0) return errno ? -errno : -EIO;
    return 0;
}

static Result<std::vector<uint8_t>> createDigest(const std::string& path) {
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

static Result<std::vector<uint8_t>> signDigest(const KeymasterSigningKey& key,
                                               const std::vector<uint8_t>& digest) {
    fsverity_signed_digest* d;
    size_t signed_digest_size = sizeof(*d) + digest.size();
    std::unique_ptr<uint8_t[]> digest_buffer{new uint8_t[signed_digest_size]};
    d = (fsverity_signed_digest*)digest_buffer.get();

    memcpy(d->magic, "FSVerity", 8);
    d->digest_algorithm = cpu_to_le16(FS_VERITY_HASH_ALG_SHA256);
    d->digest_size = cpu_to_le16(digest.size());
    memcpy(d->digest, digest.data(), digest.size());

    auto signed_digest = key.sign(std::string((char*)d, signed_digest_size));
    if (!signed_digest.ok()) {
        return signed_digest.error();
    }

    return std::vector<uint8_t>(signed_digest->begin(), signed_digest->end());
}

Result<void> enableFsVerity(const std::string& path, const KeymasterSigningKey& key) {
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

    return {};
}

Result<void> addFilesToVerityRecursive(const std::string& path, const KeymasterSigningKey& key) {
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
        }
        ++it;
    }

    return {};
}

Result<bool> isFileInVerity(const std::string& path) {
    unsigned int flags;

    unique_fd fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        return ErrnoError() << "Failed to open " << path;
    }

    int ret = ioctl(fd, FS_IOC_GETFLAGS, &flags);
    if (ret < 0) {
        return ErrnoError() << "Failed to FS_IOC_GETFLAGS for " << path;
    }

    return (flags & FS_VERITY_FL);
}

Result<void> verifyAllFilesInVerity(const std::string& path) {
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
            if (!*result) {
                return Error() << "File " << it->path() << " not in fs-verity";
            }
        }  // TODO reject other types besides dirs?
        ++it;
    }

    return {};
}
