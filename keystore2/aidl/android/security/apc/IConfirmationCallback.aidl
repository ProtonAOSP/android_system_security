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

import android.security.apc.ResponseCode;

/**
 * This callback interface must be implemented by the client to receive the result of the user
 * confirmation.
 * @hide
 */
interface IConfirmationCallback {
    /**
     * This callback gets called by the implementing service when a pending confirmation prompt
     * gets finalized.
     *
     * @param result
     *  - ResponseCode.OK On success. In this case dataConfirmed must be non null.
     *  - ResponseCode.CANCELLED If the user cancelled the prompt. In this case dataConfirmed must
     *           be null.
     *  - ResponseCode.ABORTED If the client called IProtectedConfirmation.cancelPrompt() or if the
     *           prompt was cancelled by the system due to an asynchronous event. In this case
     *           dataConfirmed must be null.
     *
     * @param dataConfirmed This is the message that was confirmed and for which a confirmation
     *           token is now available in implementing service. A subsequent attempt to sign this
     *           message with a confirmation bound key will succeed. The message is a CBOR map
     *           including the prompt text and the extra data.
     */
    oneway void onCompleted(in ResponseCode result, in @nullable byte[] dataConfirmed);
}
