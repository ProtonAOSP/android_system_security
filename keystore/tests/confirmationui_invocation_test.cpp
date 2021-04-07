/*
**
** Copyright 2019, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <aidl/android/security/apc/BnConfirmationCallback.h>
#include <aidl/android/security/apc/IProtectedConfirmation.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <tuple>
#include <vector>

using namespace std::literals::chrono_literals;
namespace apc = ::aidl::android::security::apc;

class ConfirmationListener
    : public apc::BnConfirmationCallback,
      public std::promise<std::tuple<apc::ResponseCode, std::optional<std::vector<uint8_t>>>> {
  public:
    ConfirmationListener() {}

    virtual ::ndk::ScopedAStatus
    onCompleted(::aidl::android::security::apc::ResponseCode result,
                const std::optional<std::vector<uint8_t>>& dataConfirmed) override {
        this->set_value({result, dataConfirmed});
        return ::ndk::ScopedAStatus::ok();
    };
};

TEST(ConfirmationInvocationTest, InvokeAndCancel) {
    ABinderProcess_startThreadPool();

    ::ndk::SpAIBinder apcBinder(AServiceManager_getService("android.security.apc"));
    auto apcService = apc::IProtectedConfirmation::fromBinder(apcBinder);
    ASSERT_TRUE(apcService);

    std::string promptText("Just a little test!");
    std::string locale("en");
    std::vector<uint8_t> extraData{0xaa, 0xff, 0x00, 0x55};

    auto listener = std::make_shared<ConfirmationListener>();

    auto future = listener->get_future();

    auto rc = apcService->presentPrompt(listener, promptText, extraData, locale, 0);

    ASSERT_TRUE(rc.isOk());

    auto fstatus = future.wait_for(2s);
    EXPECT_EQ(fstatus, std::future_status::timeout);

    rc = apcService->cancelPrompt(listener);
    ASSERT_TRUE(rc.isOk());

    future.wait();
    auto [responseCode, dataThatWasConfirmed] = future.get();

    ASSERT_EQ(responseCode, apc::ResponseCode::ABORTED);
}
