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

# This has to be lazy-resolved because it depends on the LOCAL_MODULE_CLASS
# which varies depending on what is being built.
define keystore_proto_include
$(call local-generated-sources-dir)/proto/$(LOCAL_PATH)
endef

ifneq ($(TARGET_BUILD_PDK),true)
include $(CLEAR_VARS)
ifeq ($(USE_32_BIT_KEYSTORE), true)
LOCAL_MULTILIB := 32
endif
LOCAL_CFLAGS := -Wall -Wextra -Werror -Wunused
LOCAL_SRC_FILES := \
	auth_token_table.cpp \
	blob.cpp \
	entropy.cpp \
	key_store_service.cpp \
	keystore_attestation_id.cpp \
	keyblob_utils.cpp \
	keystore.cpp \
	keystore_main.cpp \
	keystore_utils.cpp \
	legacy_keymaster_device_wrapper.cpp \
	keymaster_enforcement.cpp \
	operation.cpp \
	permissions.cpp \
	user_state.cpp \
	grant_store.cpp \
	../../../frameworks/base/core/java/android/security/keymaster/IKeyAttestationApplicationIdProvider.aidl
LOCAL_SHARED_LIBRARIES := \
	libbinder \
	libcutils \
	libcrypto \
	libhardware \
	libwifikeystorehal \
	libkeystore_binder \
	liblog \
	libsoftkeymaster \
	libutils \
	libselinux \
	libsoftkeymasterdevice \
	libkeymaster_messages \
	libkeymaster_portable \
	libkeymaster_staging \
	libhwbinder \
	libhidlbase \
	libhidltransport \
	android.hardware.keymaster@3.0 \
	android.system.wifi.keystore@1.0
LOCAL_HEADER_LIBRARIES := libbase_headers
LOCAL_MODULE := keystore
LOCAL_MODULE_TAGS := optional
LOCAL_INIT_RC := keystore.rc
LOCAL_C_INCLUES := system/keymaster/
LOCAL_CLANG := true
LOCAL_SANITIZE := integer
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_AIDL_INCLUDES := frameworks/base/core/java/
include $(BUILD_EXECUTABLE)
endif

include $(CLEAR_VARS)
ifeq ($(USE_32_BIT_KEYSTORE), true)
LOCAL_MULTILIB := 32
endif
LOCAL_CFLAGS := -Wall -Wextra -Werror
LOCAL_SRC_FILES := keystore_cli.cpp
LOCAL_SHARED_LIBRARIES := libcutils libcrypto libkeystore_binder libutils liblog libbinder \
	libhwbinder \
	libhidlbase \
	android.hardware.keymaster@3.0
LOCAL_MODULE := keystore_cli
LOCAL_MODULE_TAGS := debug
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
ifeq ($(USE_32_BIT_KEYSTORE), true)
LOCAL_MULTILIB := 32
endif
LOCAL_CFLAGS := -Wall -Wextra -Werror -Wno-unused-parameter -DKEYMASTER_NAME_TAGS
LOCAL_SRC_FILES := keystore_cli_v2.cpp
LOCAL_SHARED_LIBRARIES := \
	libchrome \
	libkeystore_binder \
	libhwbinder \
	libhidlbase \
	android.hardware.keymaster@3.0

LOCAL_MODULE := keystore_cli_v2
LOCAL_MODULE_TAGS := debug
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include external/gtest/include
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_EXECUTABLE)

# Library for keystore clients
include $(CLEAR_VARS)
ifeq ($(USE_32_BIT_KEYSTORE), true)
LOCAL_MULTILIB := 32
endif
LOCAL_CFLAGS := -Wall -Wextra -Werror
LOCAL_SRC_FILES := \
	IKeystoreService.cpp \
	KeyAttestationApplicationId.cpp \
	KeyAttestationPackageInfo.cpp \
	Signature.cpp \
	keyblob_utils.cpp \
	keystore_client.proto \
	keystore_client_impl.cpp \
	keystore_get.cpp \
	authorization_set.cpp \
	keystore_tags_utils.cpp \
	keystore_aidl_hidl_marshalling_utils.cpp
LOCAL_SHARED_LIBRARIES := \
	libbinder \
	liblog \
	libprotobuf-cpp-lite \
	libutils \
	libhwbinder \
	libhidlbase \
	android.hardware.keymaster@3.0
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
LOCAL_MODULE := libkeystore_binder
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include $(call keystore_proto_include)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_EXPORT_SHARED_LIBRARY_HEADERS := libbinder \
	libhwbinder \
	libhidlbase \
	android.hardware.keymaster@3.0
LOCAL_CLANG := true
LOCAL_SANITIZE := integer
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_SHARED_LIBRARY)

# Library for keystore clients using the WiFi HIDL interface
include $(CLEAR_VARS)
LOCAL_CFLAGS := -Wall -Wextra -Werror
LOCAL_SRC_FILES := \
	keystore_get_wifi_hidl.cpp
LOCAL_SHARED_LIBRARIES := \
	android.system.wifi.keystore@1.0 \
	libbase \
	libhidlbase \
	libhidltransport \
	liblog \
	libutils
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
LOCAL_MODULE := libkeystore-wifi-hidl
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_CLANG := true
LOCAL_SANITIZE := integer
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_VENDOR_MODULE := true
include $(BUILD_SHARED_LIBRARY)

# Library for unit tests
include $(CLEAR_VARS)
ifeq ($(USE_32_BIT_KEYSTORE), true)
LOCAL_MULTILIB := 32
endif
LOCAL_CFLAGS := -Wall -Wextra -Werror
LOCAL_SRC_FILES := auth_token_table.cpp
LOCAL_MODULE := libkeystore_test
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_STATIC_LIBRARIES := libgtest_main
LOCAL_SHARED_LIBRARIES := libkeymaster_messages \
	libutils \
	libhwbinder \
	libhidlbase \
	android.hardware.keymaster@3.0

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)
