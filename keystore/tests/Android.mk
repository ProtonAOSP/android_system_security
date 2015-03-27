#
# Copyright (C) 2015 The Android Open Source Project
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

# Unit test for AuthTokenTable
include $(CLEAR_VARS)
ifeq ($(USE_32_BIT_KEYSTORE), true)
LOCAL_MULTILIB := 32
endif
LOCAL_CFLAGS := -Wall -Wextra -Werror
LOCAL_SRC_FILES := auth_token_table_test.cpp
LOCAL_MODULE := auth_token_table_test
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_STATIC_LIBRARIES := libgtest_main libkeystore_test
LOCAL_SHARED_LIBRARIES := libkeymaster_messages
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_NATIVE_TEST)
