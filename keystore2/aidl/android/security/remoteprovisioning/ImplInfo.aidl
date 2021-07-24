/*
 * Copyright 2021, The Android Open Source Project
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

import android.hardware.security.keymint.SecurityLevel;

/**
 * This parcelable provides information about the underlying IRemotelyProvisionedComponent
 * implementation.
 * @hide
 */
parcelable ImplInfo {
    /**
     * The security level of the underlying implementation: TEE or StrongBox.
     */
    SecurityLevel secLevel;
    /**
     * An integer denoting which EC curve is supported in the underlying implementation. The current
     * options are either P256 or 25519, with values defined in
     * hardware/interfaces/security/keymint/aidl/.../RpcHardwareInfo.aidl
     */
    int supportedCurve;
}
