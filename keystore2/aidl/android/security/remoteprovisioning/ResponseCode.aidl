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

package android.security.remoteprovisioning;

@Backing(type="int")
/** @hide */
enum ResponseCode {
    /**
     * Returned if there are no keys available in the database to be used in a CSR
     */
    NO_UNSIGNED_KEYS = 1,
    /**
     * The caller has imrproper SELinux permissions to access the Remote Provisioning API.
     */
    PERMISSION_DENIED = 2,
    /**
     * An unexpected error occurred, likely with IO or IPC.
     */
    SYSTEM_ERROR = 3,
}
