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

package android.security.identity;

import android.security.identity.IWritableCredential;
import android.security.identity.ICredential;
import android.security.identity.SecurityHardwareInfoParcel;

/**
 * @hide
 */
interface ICredentialStore {
    /* All binder calls may return a ServiceSpecificException
     * with the following error codes:
     */
    const int ERROR_NONE = 0;
    const int ERROR_GENERIC = 1;
    const int ERROR_ALREADY_PERSONALIZED = 2;
    const int ERROR_NO_SUCH_CREDENTIAL = 3;
    const int ERROR_CIPHER_SUITE_NOT_SUPPORTED = 4;
    const int ERROR_EPHEMERAL_PUBLIC_KEY_NOT_FOUND = 5;
    const int ERROR_NO_AUTHENTICATION_KEY_AVAILABLE = 6;
    const int ERROR_INVALID_READER_SIGNATURE = 7;
    const int ERROR_DOCUMENT_TYPE_NOT_SUPPORTED = 8;
    const int ERROR_AUTHENTICATION_KEY_NOT_FOUND = 9;
    const int ERROR_INVALID_ITEMS_REQUEST_MESSAGE = 10;
    const int ERROR_SESSION_TRANSCRIPT_MISMATCH = 11;

    SecurityHardwareInfoParcel getSecurityHardwareInfo();

    IWritableCredential createCredential(in @utf8InCpp String credentialName,
                                         in @utf8InCpp String docType);
    ICredential getCredentialByName(in @utf8InCpp String credentialName,
                                    in int cipherSuite);
}
