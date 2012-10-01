/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <keystore.h>
#include <keystore_client.h>

#include <cutils/sockets.h>

#define LOG_TAG "keystore_client"
#include <cutils/log.h>

ResponseCode keystore_cmd(command_code_t cmd, Keystore_Reply* reply, int numArgs, ...) {
    int sock;

    sock = socket_local_client("keystore", ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
    if (sock == -1) {
        return SYSTEM_ERROR;
    }

    if (TEMP_FAILURE_RETRY(send(sock, &cmd, 1, MSG_NOSIGNAL)) != 1) {
        close(sock);
        return SYSTEM_ERROR;
    }

    va_list vl;
    va_start(vl, numArgs);
    for (int i = 0; i < numArgs; i++) {
        size_t argLen = va_arg(vl, size_t);
        uint8_t* arg = va_arg(vl, uint8_t*);

        if (argLen > KEYSTORE_MESSAGE_SIZE) {
            ALOGE("code called us with an argLen out of bounds: %llu", (unsigned long long) argLen);
            close(sock);
            return SYSTEM_ERROR;
        }

        uint8_t bytes[2] = { (uint8_t)(argLen >> 8), (uint8_t)argLen };
        if (TEMP_FAILURE_RETRY(send(sock, bytes, 2, MSG_NOSIGNAL)) != 2
                || TEMP_FAILURE_RETRY(send(sock, arg, argLen, MSG_NOSIGNAL))
                        != static_cast<ssize_t>(argLen)) {
            ALOGW("truncated write to keystore");
            close(sock);
            return SYSTEM_ERROR;
        }
    }
    va_end(vl);

    uint8_t code = 0;
    if (shutdown(sock, SHUT_WR) != 0
            || TEMP_FAILURE_RETRY(recv(sock, &code, 1, 0)) != 1
            || code != NO_ERROR) {
        ALOGW("Error from keystore: %d", code);
        close(sock);
        return SYSTEM_ERROR;
    }

    if (reply != NULL) {
        reply->setCode(static_cast<ResponseCode>(code));

        uint8_t bytes[2];
        uint8_t* data = reply->get();
        if (TEMP_FAILURE_RETRY(recv(sock, &bytes[0], 1, 0)) == 1
                && TEMP_FAILURE_RETRY(recv(sock, &bytes[1], 1, 0)) == 1) {
            int offset = 0;
            int length = bytes[0] << 8 | bytes[1];
            while (offset < length) {
                int n = TEMP_FAILURE_RETRY(recv(sock, &data[offset], length - offset, 0));
                if (n <= 0) {
                    ALOGW("truncated read from keystore for data");
                    code = SYSTEM_ERROR;
                    break;
                }
                offset += n;
            }
            reply->setLength(length);
        } else {
            ALOGW("truncated read from keystore for length");
            code = SYSTEM_ERROR;
        }
    }

    close(sock);
    return static_cast<ResponseCode>(code);
}

Keystore_Reply::Keystore_Reply()
        : mCode(SYSTEM_ERROR)
        , mLength(-1) {
    mData = new uint8_t[KEYSTORE_MESSAGE_SIZE];
}

Keystore_Reply::~Keystore_Reply() {
    delete[] mData;
}

uint8_t* Keystore_Reply::get() {
    return mData;
}

void Keystore_Reply::setLength(size_t length) {
    mLength = length;
}

size_t Keystore_Reply::length() const {
    return mLength;
}

void Keystore_Reply::setCode(ResponseCode code) {
    mCode = code;
}

ResponseCode Keystore_Reply::code() const {
    return mCode;
}

uint8_t* Keystore_Reply::release() {
    uint8_t* data = mData;
    mData = NULL;
    return data;
}
