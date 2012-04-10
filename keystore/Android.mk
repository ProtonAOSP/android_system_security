#
# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CFLAGS := -Wall -Wextra -Werror
LOCAL_SRC_FILES := keystore.cpp keyblob_utils.cpp
LOCAL_C_INCLUDES := external/openssl/include
LOCAL_SHARED_LIBRARIES := libcutils libcrypto libhardware
LOCAL_MODULE := keystore
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_CFLAGS := -Wall -Wextra -Werror
LOCAL_SRC_FILES := keystore_cli.cpp
LOCAL_C_INCLUDES := external/openssl/include
LOCAL_SHARED_LIBRARIES := libcutils libcrypto
LOCAL_MODULE := keystore_cli
LOCAL_MODULE_TAGS := debug
include $(BUILD_EXECUTABLE)

# Library for keystore clients
include $(CLEAR_VARS)
LOCAL_CFLAGS := -Wall -Wextra -Werror
LOCAL_SRC_FILES := keystore_client.cpp keyblob_utils.cpp
LOCAL_SHARED_LIBRARIES := libcutils
LOCAL_MODULE := libkeystore_client
LOCAL_MODULE_TAGS := optional
include $(BUILD_SHARED_LIBRARY)
