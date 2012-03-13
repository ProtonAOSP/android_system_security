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

#ifndef __KEYSTORE_CLIENT_H__
#define __KEYSTORE_CLIENT_H__

#include <keystore.h>

#define KEYSTORE_MESSAGE_SIZE 65535


class Keystore_Reply {
public:
    Keystore_Reply();
    ~Keystore_Reply();

    uint8_t* get();
    void setLength(size_t length);
    size_t length() const;
    void setCode(ResponseCode code);
    ResponseCode code() const;
    uint8_t* release();

private:
    ResponseCode mCode;
    uint8_t* mData;
    size_t mLength;
};


/**
 * This sends a command to the keystore. The arguments must be of the format:
 *
 * size_t length, const uint8_t* data, [size_t length, const uint8_t* data, [...]]
 */
ResponseCode keystore_cmd(command_code_t cmd, Keystore_Reply* reply, int numArgs, ...);

#endif /* __KEYSTORE_CLIENT_H__ */
