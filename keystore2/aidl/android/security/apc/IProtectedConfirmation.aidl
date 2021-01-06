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

package android.security.apc;

import android.security.apc.IConfirmationCallback;

interface IProtectedConfirmation {

    /**
     * When set in the uiOptionFlags parameter of presentPrompt, indicates to the implementation
     * that it shall use inverted color mode.
     */
    const int FLAG_UI_OPTION_INVERTED = 1;
    /**
     * When set in the uiOptionFlags parameter of presentPrompt, indicates to the implementation
     * that it shall use magnified font mode.
     */
    const int FLAG_UI_OPTION_MAGNIFIED = 2;

    /**
     * Present the confirmation prompt. The caller must implement IConfirmationCallback and pass
     * it to this function as listener.
     *
     * @param listener Must implement IConfirmationCallback. Doubles as session identifier when
     *           passed to cancelPrompt.
     * @param promptText The text that will be displayed to the user using the protected
     *           confirmation UI.
     * @param extraData Extra data, e.g., a nonce, that will be included in the to-be-signed
     *           message.
     * @param locale The locale string is used to select the language for the instructions
     *           displayed by the confirmation prompt.
     * @param uiOptionFlags Bitwise combination of FLAG_UI_OPTION_* see above.
     *
     * Service specific error codes:
     *  - ResponseCode.OPERATION_PENDING If another prompt is already pending.
     *  - ResponseCode.SYSTEM_ERROR An unexpected error occurred.
     */
    void presentPrompt(in IConfirmationCallback listener, in String promptText,
            in byte[] extraData, in String locale, in int uiOptionFlags);

    /**
     * Cancel an ongoing prompt.
     *
     * @param listener Must implement IConfirmationCallback, although in this context this binder
     *            token is only used to identify the session that is to be cancelled.
     *
     * Service specific error code:
     *  - ResponseCode.IGNORED If the listener does not represent an ongoing prompt session.
     */
    void cancelPrompt(IConfirmationCallback listener);

    /**
     * Returns true if the device supports Android Protected Confirmation.
     */
    boolean isSupported();
}
