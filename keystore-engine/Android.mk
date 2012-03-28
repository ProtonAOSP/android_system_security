# Copyright (C) 2012 The Android Open Source Project
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

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libkeystore

LOCAL_MODULE_TAGS := optional

LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)/ssl/engines

LOCAL_SRC_FILES := eng_keystore.cpp

LOCAL_CFLAGS := -fvisibility=hidden -Wall -Werror

LOCAL_C_INCLUDES += \
	system/security/keystore \
	external/openssl/include

LOCAL_SHARED_LIBRARIES += \
	libcrypto \
	liblog \
	libcutils \
	libkeystore_client

include $(BUILD_SHARED_LIBRARY)
