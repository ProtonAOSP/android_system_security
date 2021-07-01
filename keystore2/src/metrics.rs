// Copyright 2021, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module implements the IKeystoreMetrics AIDL interface, which exposes the API method for the
//! proxy in the system server to pull the aggregated metrics in keystore.
use crate::error::map_or_log_err;
use crate::metrics_store::METRICS_STORE;
use crate::permission::KeystorePerm;
use crate::utils::{check_keystore_permission, watchdog as wd};
use android_security_metrics::aidl::android::security::metrics::{
    AtomID::AtomID,
    IKeystoreMetrics::{BnKeystoreMetrics, IKeystoreMetrics},
    KeystoreAtom::KeystoreAtom,
};
use android_security_metrics::binder::{BinderFeatures, Interface, Result as BinderResult, Strong};
use anyhow::{Context, Result};

/// This struct is defined to implement IKeystoreMetrics AIDL interface.
pub struct Metrics;

impl Metrics {
    /// Create a new instance of Keystore Metrics service.
    pub fn new_native_binder() -> Result<Strong<dyn IKeystoreMetrics>> {
        Ok(BnKeystoreMetrics::new_binder(
            Self,
            BinderFeatures { set_requesting_sid: true, ..BinderFeatures::default() },
        ))
    }

    fn pull_metrics(&self, atom_id: AtomID) -> Result<Vec<KeystoreAtom>> {
        // Check permission. Function should return if this failed. Therefore having '?' at the end
        // is very important.
        check_keystore_permission(KeystorePerm::pull_metrics()).context("In pull_metrics.")?;
        METRICS_STORE.get_atoms(atom_id)
    }
}

impl Interface for Metrics {}

impl IKeystoreMetrics for Metrics {
    fn pullMetrics(&self, atom_id: AtomID) -> BinderResult<Vec<KeystoreAtom>> {
        let _wp = wd::watch_millis("IKeystoreMetrics::pullMetrics", 500);
        map_or_log_err(self.pull_metrics(atom_id), Ok)
    }
}
