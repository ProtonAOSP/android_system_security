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

package android.security.vpnprofilestore;

/**
 * Internal interface for accessing and storing VPN profiles.
 * @hide
 */
interface IVpnProfileStore {
    /**
     * Service specific error code indicating that the profile was not found.
     */
    const int ERROR_PROFILE_NOT_FOUND = 1;

    /**
     * Service specific error code indicating that an unexpected system error occurred.
     */
    const int ERROR_SYSTEM_ERROR = 2;

    /**
     * Returns the profile stored under the given alias.
     *
     * @param alias name of the profile.
     * @return The unstructured blob that was passed as profile parameter into put()
     */
    byte[] get(in String alias);

    /**
     * Stores one profile as unstructured blob under the given alias.
     */
    void put(in String alias, in byte[] profile);

    /**
     * Deletes the profile under the given alias.
     */
    void remove(in String alias);

    /**
     * Returns a list of aliases of profiles stored. The list is filtered by prefix.
     * The resulting strings are the full aliases including the prefix.
     */
    String[] list(in String prefix);
}