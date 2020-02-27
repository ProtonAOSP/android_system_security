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

#define LOG_TAG "CredentialStoreFactory"

#include <android-base/logging.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

//#include "CredentialStore.h"
#include "CredentialStoreFactory.h"

namespace android {
namespace security {
namespace identity {

using ::android::hardware::identity::IIdentityCredentialStore;

CredentialStoreFactory::CredentialStoreFactory(const std::string& dataPath) : dataPath_(dataPath) {}

CredentialStoreFactory::~CredentialStoreFactory() {}

CredentialStore* CredentialStoreFactory::createCredentialStore(const string& instanceName) {
    String16 serviceName =
        IIdentityCredentialStore::descriptor + String16("/") + String16(instanceName.c_str());
    sp<IIdentityCredentialStore> hal =
        android::waitForDeclaredService<IIdentityCredentialStore>(serviceName);
    if (hal.get() == nullptr) {
        LOG(ERROR) << "Error getting HAL for IdentityCredentialStore store with service name '"
                   << serviceName << "'";
        return nullptr;
    }

    CredentialStore* store = new CredentialStore(dataPath_, hal);
    if (!store->init()) {
        LOG(ERROR) << "Error initializing CredentialStore with service name '" << serviceName
                   << "'";
        delete store;
        return nullptr;
    }
    return store;
}

Status CredentialStoreFactory::getCredentialStore(int32_t credentialStoreType,
                                                  sp<ICredentialStore>* _aidl_return) {
    switch (credentialStoreType) {
    case CREDENTIAL_STORE_TYPE_DEFAULT:
        if (defaultStore_.get() == nullptr) {
            defaultStore_ = createCredentialStore("default");
        }
        if (defaultStore_.get() == nullptr) {
            return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                    "Error creating default store");
        }
        *_aidl_return = defaultStore_.get();
        return Status::ok();

    case CREDENTIAL_STORE_TYPE_DIRECT_ACCESS:
        if (directAccessStore_.get() == nullptr) {
            directAccessStore_ = createCredentialStore("directAccess");
        }
        if (directAccessStore_.get() == nullptr) {
            return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                    "Error creating direct access store");
        }
        *_aidl_return = directAccessStore_.get();
        return Status::ok();
        break;
    }

    return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                            "Unknown credential store type");
}

}  // namespace identity
}  // namespace security
}  // namespace android
