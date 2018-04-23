/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "keystore"

#include "entropy.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <log/log.h>

#include "keystore_utils.h"

Entropy::~Entropy() {
    if (mRandom >= 0) {
        close(mRandom);
    }
}

bool Entropy::open() {
    const char* randomDevice = "/dev/urandom";
    mRandom = TEMP_FAILURE_RETRY(::open(randomDevice, O_RDONLY));
    if (mRandom < 0) {
        ALOGE("open: %s: %s", randomDevice, strerror(errno));
        return false;
    }
    return true;
}

bool Entropy::generate_random_data(uint8_t* data, size_t size) const {
    return (readFully(mRandom, data, size) == size);
}
