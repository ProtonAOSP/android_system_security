/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "apc_compat.hpp"
#include <android-base/logging.h>
#include <android/hardware/confirmationui/1.0/IConfirmationUI.h>
#include <hwbinder/IBinder.h>

#include <memory>
#include <string>
#include <thread>
#include <vector>

#define LOG_TAG "keystore2_apc_compat"

namespace keystore2 {

using android::sp;
using android::hardware::hidl_death_recipient;
using android::hardware::hidl_vec;
using android::hardware::Return;
using android::hardware::Status;
using android::hardware::confirmationui::V1_0::IConfirmationResultCallback;
using android::hardware::confirmationui::V1_0::IConfirmationUI;
using android::hardware::confirmationui::V1_0::ResponseCode;
using android::hardware::confirmationui::V1_0::UIOption;

static uint32_t responseCode2Compat(ResponseCode rc) {
    switch (rc) {
    case ResponseCode::OK:
        return APC_COMPAT_ERROR_OK;
    case ResponseCode::Canceled:
        return APC_COMPAT_ERROR_CANCELLED;
    case ResponseCode::Aborted:
        return APC_COMPAT_ERROR_ABORTED;
    case ResponseCode::OperationPending:
        return APC_COMPAT_ERROR_OPERATION_PENDING;
    case ResponseCode::Ignored:
        return APC_COMPAT_ERROR_IGNORED;
    case ResponseCode::SystemError:
    case ResponseCode::Unimplemented:
    case ResponseCode::Unexpected:
    case ResponseCode::UIError:
    case ResponseCode::UIErrorMissingGlyph:
    case ResponseCode::UIErrorMessageTooLong:
    case ResponseCode::UIErrorMalformedUTF8Encoding:
    default:
        return APC_COMPAT_ERROR_SYSTEM_ERROR;
    }
}

class ConfuiCompatSession : public IConfirmationResultCallback, public hidl_death_recipient {
  public:
    static sp<ConfuiCompatSession>* tryGetService() {
        sp<IConfirmationUI> service = IConfirmationUI::tryGetService();
        if (service) {
            return new sp(new ConfuiCompatSession(std::move(service)));
        } else {
            return nullptr;
        }
    }

    uint32_t promptUserConfirmation(ApcCompatCallback callback, const char* prompt_text,
                                    const uint8_t* extra_data, size_t extra_data_size,
                                    const char* locale, ApcCompatUiOptions ui_options) {
        std::string hidl_prompt(prompt_text);
        std::vector<uint8_t> hidl_extra(extra_data, extra_data + extra_data_size);
        std::string hidl_locale(locale);
        std::vector<UIOption> hidl_ui_options;
        if (ui_options.inverted) {
            hidl_ui_options.push_back(UIOption::AccessibilityInverted);
        }
        if (ui_options.magnified) {
            hidl_ui_options.push_back(UIOption::AccessibilityMagnified);
        }
        auto lock = std::lock_guard(callback_lock_);
        if (callback_.result != nullptr) {
            return APC_COMPAT_ERROR_OPERATION_PENDING;
        }
        auto err = service_->linkToDeath(sp(this), 0);
        if (!err.isOk()) {
            LOG(ERROR) << "Communication error: promptUserConfirmation: "
                          "Trying to register death recipient: "
                       << err.description();
            return APC_COMPAT_ERROR_SYSTEM_ERROR;
        }

        auto rc = service_->promptUserConfirmation(sp(this), hidl_prompt, hidl_extra, hidl_locale,
                                                   hidl_ui_options);
        if (!rc.isOk()) {
            LOG(ERROR) << "Communication error: promptUserConfirmation: " << rc.description();
        }
        if (rc == ResponseCode::OK) {
            callback_ = callback;
        }
        return responseCode2Compat(rc.withDefault(ResponseCode::SystemError));
    }

    void abort() { service_->abort(); }

    void
    finalize(ResponseCode responseCode,
             std::optional<std::reference_wrapper<const hidl_vec<uint8_t>>> dataConfirmed,
             std::optional<std::reference_wrapper<const hidl_vec<uint8_t>>> confirmationToken) {
        ApcCompatCallback callback;
        {
            auto lock = std::lock_guard(callback_lock_);
            // Calling the callback consumes the callback data structure. We have to make
            // sure that it can only be called once.
            callback = callback_;
            callback_ = {nullptr, nullptr};
            // Unlock the callback_lock_ here. It must never be held while calling the callback.
        }

        if (callback.result != nullptr) {
            service_->unlinkToDeath(sp(this));

            size_t dataConfirmedSize = 0;
            const uint8_t* dataConfirmedPtr = nullptr;
            size_t confirmationTokenSize = 0;
            const uint8_t* confirmationTokenPtr = nullptr;
            if (responseCode == ResponseCode::OK) {
                if (dataConfirmed) {
                    dataConfirmedPtr = dataConfirmed->get().data();
                    dataConfirmedSize = dataConfirmed->get().size();
                }
                if (dataConfirmed) {
                    confirmationTokenPtr = confirmationToken->get().data();
                    confirmationTokenSize = confirmationToken->get().size();
                }
            }
            callback.result(callback.data, responseCode2Compat(responseCode), dataConfirmedPtr,
                            dataConfirmedSize, confirmationTokenPtr, confirmationTokenSize);
        }
    }

    // IConfirmationResultCallback overrides:
    android::hardware::Return<void> result(ResponseCode responseCode,
                                           const hidl_vec<uint8_t>& dataConfirmed,
                                           const hidl_vec<uint8_t>& confirmationToken) override {
        finalize(responseCode, dataConfirmed, confirmationToken);
        return Status::ok();
    };

    void serviceDied(uint64_t /* cookie */,
                     const ::android::wp<::android::hidl::base::V1_0::IBase>& /* who */) override {
        finalize(ResponseCode::SystemError, {}, {});
    }

  private:
    ConfuiCompatSession(sp<IConfirmationUI> service)
        : service_(service), callback_{nullptr, nullptr} {}
    sp<IConfirmationUI> service_;

    // The callback_lock_ protects the callback_ field against concurrent modification.
    // IMPORTANT: It must never be held while calling the call back.
    std::mutex callback_lock_;
    ApcCompatCallback callback_;
};

}  // namespace keystore2

using namespace keystore2;

ApcCompatServiceHandle tryGetUserConfirmationService() {
    return reinterpret_cast<ApcCompatServiceHandle>(ConfuiCompatSession::tryGetService());
}

uint32_t promptUserConfirmation(ApcCompatServiceHandle handle, ApcCompatCallback callback,
                                const char* prompt_text, const uint8_t* extra_data,
                                size_t extra_data_size, char const* locale,
                                ApcCompatUiOptions ui_options) {
    auto session = reinterpret_cast<sp<ConfuiCompatSession>*>(handle);
    return (*session)->promptUserConfirmation(callback, prompt_text, extra_data, extra_data_size,
                                              locale, ui_options);
}

void abortUserConfirmation(ApcCompatServiceHandle handle) {
    auto session = reinterpret_cast<sp<ConfuiCompatSession>*>(handle);
    (*session)->abort();
}

void closeUserConfirmationService(ApcCompatServiceHandle handle) {
    // Closing the handle implicitly aborts an ongoing sessions.
    // Note that a resulting callback is still safely conducted, because we only delete a
    // StrongPointer below. libhwbinder still owns another StrongPointer to this session.
    abortUserConfirmation(handle);
    delete reinterpret_cast<sp<ConfuiCompatSession>*>(handle);
}

const ApcCompatServiceHandle INVALID_SERVICE_HANDLE = nullptr;
