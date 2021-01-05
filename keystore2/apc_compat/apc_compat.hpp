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
#pragma once

#include <stddef.h>
#include <stdint.h>

using ApcCompatServiceHandle = void*;

#define APC_COMPAT_ERROR_OK 0
#define APC_COMPAT_ERROR_CANCELLED 1
#define APC_COMPAT_ERROR_ABORTED 2
#define APC_COMPAT_ERROR_OPERATION_PENDING 3
#define APC_COMPAT_ERROR_IGNORED 4
#define APC_COMPAT_ERROR_SYSTEM_ERROR 5

extern "C" {

extern const ApcCompatServiceHandle INVALID_SERVICE_HANDLE;

/**
 * This struct holds the ui options for the protected confirmation dialog.
 */
struct ApcCompatUiOptions {
    /**
     * If set to true inverted color mode is used.
     */
    bool inverted;
    /**
     * If set to true magnified fonts are used.
     */
    bool magnified;
};

/**
 * Represents a result callback that is called when a confirmation session was successfully
 * started.
 * The field `data` is an opaque callback context handle. It must be passed to the `result`
 * function.
 *
 * IMPORTANT: The life cycle of `data` ends when `result` is called. The callback must not
 *            be called a second time.
 *
 * The callback function `result` has the prototype:
 * void result(
 *     void* data,
 *     uint32_t rc,
 *     const uint8_t* tbs_message,
 *     size_t tbs_message_size,
 *     const uint8_t* confirmation_token,
 *     size_t confirmation_token_size)
 *
 * * data - must be the data field of the structure.
 * * rc - response code, one of:
 *      * APC_COMPAT_ERROR_OK - The user confirmed the prompt text.
 *      * APC_COMPAT_ERROR_CANCELLED - The user rejected the prompt text.
 *      * APC_COMPAT_ERROR_ABORTED - `abortUserConfirmation` was called.
 *      * APC_COMPAT_ERROR_SYSTEM_ERROR - An unspecified system error occurred.
 * * tbs_message(_size) - Pointer to and size of the to-be-signed message. Must
 *      be NULL and 0 respectively if `rc != APC_COMPAT_ERROR_OK`.
 * * confirmation_token(_size) - Pointer to and size of the confirmation token. Must
 *      be NULL and 0 respectively if `rc != APC_COMPAT_ERROR_OK`.
 */
struct ApcCompatCallback {
    void* data;
    void (*result)(void*, uint32_t, const uint8_t*, size_t, const uint8_t*, size_t);
};

/**
 * Attempts to make a connection to the confirmationui HIDL backend.
 * If a valid service handle is returned it stays valid until
 * `closeUserConfirmationService` is called.
 *
 * @return A valid service handle on success or INVALID_SERVICE_HANDLE
 *         on failure.
 */
ApcCompatServiceHandle tryGetUserConfirmationService();

/**
 * Attempts to start a protected confirmation session on the given service handle.
 * The function takes ownership of the callback object (`cb`) IFF APC_COMPAT_ERROR_OK
 * is returned. The resources referenced by the callback object must stay valid
 * until the callback is called.
 *
 * @param handle A valid service handle as returned by `tryGetUserConfirmationService()`.
 * @cb A ApcCompatCallback structure that represents a callback function with session data.
 * @param prompt_text A UTF-8 encoded prompt string.
 * @param extra_data Free form extra data.
 * @param extra_data_size size of the extra data buffer in bytes.
 * @param locale A locale string.
 * @param ui_options A UI options. See ApcCompatUiOptions above.
 * @retval APC_COMPAT_ERROR_OK on success.
 * @retval APC_COMPAT_ERROR_OPERATION_PENDING if another operation was already in progress.
 * @retval APC_COMPAT_ERROR_SYSTEM_ERROR if an unspecified system error occurred.
 */
uint32_t promptUserConfirmation(ApcCompatServiceHandle handle, struct ApcCompatCallback cb,
                                const char* prompt_text, const uint8_t* extra_data,
                                size_t extra_data_size, char const* locale,
                                ApcCompatUiOptions ui_options);

/**
 * Aborts a running confirmation session or no-op if no session is running.
 * If a session is running this results in a `result` callback with
 * `rc == APC_COMPAT_ERROR_ABORTED`. Mind though that the callback can still yield other
 * results even after this function was called, because it may race with an actual user
 * response. In any case, there will be only one callback response for each session
 * successfully started with promptUserConfirmation.
 *
 * @param handle A valid session handle as returned by `tryGetUserConfirmationService()`
 */
void abortUserConfirmation(ApcCompatServiceHandle handle);

/**
 * Closes a valid service session as returned by `tryGetUserConfirmationService()`.
 * If a session is still running it is implicitly aborted. In this case, freeing up of the resources
 * referenced by the service handle is deferred until the callback has completed.
 *
 * @param handle A valid session handle as returned by `tryGetUserConfirmationService()`
 */
void closeUserConfirmationService(ApcCompatServiceHandle);

}
