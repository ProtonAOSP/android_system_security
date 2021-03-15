/*
 * Copyright 2020, The Android Open Source Project
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

package android.security.apc;

/**
 * Used as service specific exception code by IProtectedConfirmation and as result
 * code by IConfirmationCallback
 * @hide
 */
@Backing(type="int")
enum ResponseCode {
    /**
     * The prompt completed successfully with the user confirming the message (callback result).
     */
    OK = 0,
    /**
     * The user cancelled the TUI (callback result).
     */
    CANCELLED = 1,
    /**
     * The prompt was aborted (callback result). This may happen when the app cancels the prompt,
     * or when the prompt was cancelled due to an unexpected asynchronous event, such as an
     * incoming phone call.
     */
    ABORTED = 2,
    /**
     * Another prompt cannot be started because another prompt is pending.
     */
    OPERATION_PENDING = 3,
    /**
     * The request was ignored.
     */
    IGNORED = 4,
    /**
     * An unexpected system error occurred.
     */
    SYSTEM_ERROR = 5,
    /**
     * Backend is not implemented.
     */
    UNIMPLEMENTED = 6,
    /**
     * Permission Denied.
     */
    PERMISSION_DENIED = 30,
}
