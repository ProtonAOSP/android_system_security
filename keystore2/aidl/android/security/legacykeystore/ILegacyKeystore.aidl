/*
 * Copyright (C) 2021 The Android Open Source Project
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

package android.security.legacykeystore;

/**
 * Internal interface for accessing and storing legacy keystore blobs.
 * Before Android S, Keystore offered a key-value store that was intended for storing
 * data associated with certain types of keys. E.g., public certificates for asymmetric keys.
 * This key value store no longer exists as part of the Keystore 2.0 protocol.
 * However, there are some clients that used Keystore in an unintended way.
 * This interface exists to give these clients a grace period to migrate their keys
 * out of legacy keystore. In Android S, this legacy keystore may be used as keystore was
 * used in earlier versions, and provides access to entries that were put into keystore
 * before Android S.
 *
 * DEPRECATION NOTICE: In Android T, the `put` function is slated to be removed.
 * This will allow clients to use the `get`, `list`, and `remove` API to migrate blobs out
 * of legacy keystore.
 * @hide
 */
interface ILegacyKeystore {

    /**
     * Special value indicating the callers uid.
     */
    const int UID_SELF = -1;

    /**
     * Service specific error code indicating that an unexpected system error occurred.
     */
    const int ERROR_SYSTEM_ERROR = 4;

    /**
     * Service specific error code indicating that the caller does not have the
     * right to access the requested uid.
     */
    const int ERROR_PERMISSION_DENIED = 6;

    /**
     * Service specific error code indicating that the entry was not found.
     */
    const int ERROR_ENTRY_NOT_FOUND = 7;

    /**
     * Returns the blob stored under the given name.
     *
     * @param alias name of the blob entry.
     * @param uid designates the legacy namespace. Specify UID_SELF for the caller's namespace.
     * @return The unstructured blob that was passed as blob parameter into put()
     */
    byte[] get(in String alias, int uid);

    /**
     * Stores one entry as unstructured blob under the given alias.
     * Overwrites existing entries with the same alias.
     *
     * @param alias name of the new entry.
     * @param uid designates the legacy namespace. Specify UID_SELF for the caller's namespace.
     * @param blob the payload of the new entry.
     *
     * IMPORTANT DEPRECATION NOTICE: This function is slated to be removed in Android T.
     *     Do not add new callers. The remaining functionality will remain for the purpose
     *     of migrating legacy configuration out.
     */
    void put(in String alias, int uid, in byte[] blob);

    /**
     * Deletes the entry under the given alias.
     *
     * @param alias name of the entry to be removed.
     * @param uid designates the legacy namespace of the entry. Specify UID_SELF for the caller's
     *            namespace.
     */
    void remove(in String alias, int uid);

    /**
     * Returns a list of aliases of entries stored. The list is filtered by prefix.
     * The resulting strings are the full aliases including the prefix.
     *
     * @param prefix used to filter results.
     * @param uid legacy namespace to list. Specify UID_SELF for caller's namespace.
     */
    String[] list(in String prefix, int uid);
}