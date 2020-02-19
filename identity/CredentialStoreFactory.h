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

#ifndef SYSTEM_SECURITY_CREDENTIAL_STORE_FACTORY_H_
#define SYSTEM_SECURITY_CREDENTIAL_STORE_FACTORY_H_

#include <android/security/identity/BnCredentialStoreFactory.h>

#include "CredentialStore.h"

namespace android {
namespace security {
namespace identity {

using ::android::sp;
using ::android::binder::Status;
using ::std::string;

class CredentialStoreFactory : public BnCredentialStoreFactory {
  public:
    explicit CredentialStoreFactory(const string& dataPath);
    ~CredentialStoreFactory();

    Status getCredentialStore(int32_t credentialStoreType,
                              sp<ICredentialStore>* _aidl_return) override;

  private:
    CredentialStore* createCredentialStore(const string& instanceName);

    string dataPath_;

    sp<CredentialStore> defaultStore_;
    sp<CredentialStore> directAccessStore_;
};

}  // namespace identity
}  // namespace security
}  // namespace android

#endif  // SYSTEM_SECURITY_CREDENTIAL_STORE_FACTORY_H_
