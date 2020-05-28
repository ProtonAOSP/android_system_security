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

#define LOG_TAG "android.security.identity"

#include <filesystem>

#include <unistd.h>

#include <android-base/logging.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

#include "CredentialStoreFactory.h"

#include <cppbor.h>

using ::std::string;

using ::android::IPCThreadState;
using ::android::IServiceManager;
using ::android::sp;
using ::android::String16;
using ::android::base::InitLogging;
using ::android::base::StderrLogger;

using ::android::security::identity::CredentialStoreFactory;

int main(int argc, char* argv[]) {
    InitLogging(argv, StderrLogger);

    CHECK(argc == 2) << "A directory must be specified";
    string data_dir = string(argv[1]);
    CHECK(chdir(data_dir.c_str()) != -1) << "chdir: " << data_dir << ": " << strerror(errno);

    sp<IServiceManager> sm = ::android::defaultServiceManager();
    sp<CredentialStoreFactory> factory = new CredentialStoreFactory(data_dir);

    auto ret = sm->addService(String16("android.security.identity"), factory);
    CHECK(ret == ::android::OK) << "Couldn't register binder service";
    LOG(ERROR) << "Registered binder service";

    // This is needed for binder callbacks from keystore on a ICredstoreTokenCallback binder.
    android::ProcessState::self()->startThreadPool();

    IPCThreadState::self()->joinThreadPool();

    return 0;
}
