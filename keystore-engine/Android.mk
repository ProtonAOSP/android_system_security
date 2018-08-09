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

LOCAL_MODULE := libkeystore-engine

LOCAL_SRC_FILES := \
	android_engine.cpp \
	keystore_backend_binder.cpp

LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -fvisibility=hidden -Wall -Werror

LOCAL_SHARED_LIBRARIES += \
	libbinder \
	libcrypto \
	libcutils \
	libhidlbase \
	libkeystore_aidl \
	libkeystore_binder \
	libkeystore_parcelables \
	liblog \
	libbase \
	libutils

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

# This builds a variant of libkeystore-engine that uses a HIDL HAL
# owned by the WiFi user to perform signing operations.
LOCAL_MODULE := libkeystore-engine-wifi-hidl

LOCAL_SRC_FILES := \
	android_engine.cpp \
	keystore_backend_hidl.cpp

LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -fvisibility=hidden -Wall -Werror -DBACKEND_WIFI_HIDL

LOCAL_SHARED_LIBRARIES += \
	android.system.wifi.keystore@1.0 \
	libcrypto \
	liblog \
	libhidlbase \
	libhidltransport \
	libcutils \
	libutils

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_VENDOR_MODULE := true

include $(BUILD_SHARED_LIBRARY)
