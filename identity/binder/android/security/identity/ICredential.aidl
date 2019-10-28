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

import android.security.identity.RequestNamespaceParcel;
import android.security.identity.GetEntriesResultParcel;
import android.security.identity.AuthKeyParcel;

/**
 * @hide
 */
interface ICredential {
    /* The STATUS_* constants are used in the status field in ResultEntryParcel.
     * Keep in sync with ResultNamespace.java.
     */
    const int STATUS_OK = 0;
    const int STATUS_NO_SUCH_ENTRY = 1;
    const int STATUS_NOT_REQUESTED = 2;
    const int STATUS_NOT_IN_REQUEST_MESSAGE = 3;
    const int STATUS_USER_AUTHENTICATION_FAILED = 4;
    const int STATUS_READER_AUTHENTICATION_FAILED = 5;
    const int STATUS_NO_ACCESS_CONTROL_PROFILES = 6;

    byte[] createEphemeralKeyPair();

    void setReaderEphemeralPublicKey(in byte[] publicKey);

    byte[] deleteCredential();

    byte[] getCredentialKeyCertificateChain();

    long selectAuthKey(in boolean allowUsingExhaustedKeys);

    GetEntriesResultParcel getEntries(in byte[] requestMessage,
                                      in RequestNamespaceParcel[] requestNamespaces,
                                      in byte[] sessionTranscript,
                                      in byte[] readerSignature,
                                      in boolean allowUsingExhaustedKeys);

    void setAvailableAuthenticationKeys(in int keyCount, in int maxUsesPerKey);

    AuthKeyParcel[] getAuthKeysNeedingCertification();

    void storeStaticAuthenticationData(in AuthKeyParcel authenticationKey, in byte[] staticAuthData);

    int[] getAuthenticationDataUsageCount();
}

