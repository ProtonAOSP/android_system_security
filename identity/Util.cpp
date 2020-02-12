/*
 * Copyright (c) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "Util"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include <android/security/identity/ICredentialStore.h>

#include "Util.h"

namespace android {
namespace security {
namespace identity {

using ::android::base::StringPrintf;

Status halStatusToError(const Status& halStatus, int credStoreError) {
    string message = StringPrintf(
        "HAL failed with exception code %d (%s), service-specific error code %d, message '%s'",
        halStatus.exceptionCode(), Status::exceptionToString(halStatus.exceptionCode()).c_str(),
        halStatus.serviceSpecificErrorCode(), halStatus.exceptionMessage().c_str());
    return Status::fromServiceSpecificError(credStoreError, message.c_str());
}

Status halStatusToGenericError(const Status& halStatus) {
    return halStatusToError(halStatus, ICredentialStore::ERROR_GENERIC);
}

optional<vector<uint8_t>> fileGetContents(const string& path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        PLOG(ERROR) << "Error opening " << path;
        return {};
    }

    struct stat statbuf;
    if (fstat(fd, &statbuf) != 0) {
        PLOG(ERROR) << "Error statting " << path;
        close(fd);
        return {};
    }
    vector<uint8_t> data;
    data.resize(statbuf.st_size);

    uint8_t* p = data.data();
    size_t remaining = data.size();
    while (remaining > 0) {
        ssize_t numRead = TEMP_FAILURE_RETRY(read(fd, p, remaining));
        if (numRead <= 0) {
            PLOG(ERROR) << "Failed reading from '" << path << "'";
            close(fd);
            return {};
        }
        p += numRead;
        remaining -= numRead;
    }
    close(fd);

    return data;
}

bool fileSetContents(const string& path, const vector<uint8_t>& data) {
    char tempName[4096];
    int fd;

    string tempNameStr = path + ".XXXXXX";
    if (tempNameStr.size() >= sizeof tempName - 1) {
        LOG(ERROR) << "Path name too long";
        return false;
    }
    strncpy(tempName, tempNameStr.c_str(), sizeof tempName);

    fd = mkstemp(tempName);
    if (fd == -1) {
        PLOG(ERROR) << "Error creating temp file for '" << path << "'";
        return false;
    }

    const uint8_t* p = data.data();
    size_t remaining = data.size();
    while (remaining > 0) {
        ssize_t numWritten = TEMP_FAILURE_RETRY(write(fd, p, remaining));
        if (numWritten <= 0) {
            PLOG(ERROR) << "Failed writing into temp file for '" << path << "'";
            close(fd);
            return false;
        }
        p += numWritten;
        remaining -= numWritten;
    }

    if (TEMP_FAILURE_RETRY(fsync(fd) == -1)) {
        PLOG(ERROR) << "Failed fsyncing temp file for '" << path << "'";
        close(fd);
        return false;
    }
    close(fd);

    if (rename(tempName, path.c_str()) != 0) {
        PLOG(ERROR) << "Error renaming temp file for '" << path << "'";
        close(fd);
        return false;
    }

    return true;
}

}  // namespace identity
}  // namespace security
}  // namespace android
