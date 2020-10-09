// Copyright 2020, The Android Open Source Project
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

//! This module implements utility functions used by the Keystore 2.0 service
//! implementation.

use crate::error::Error;
use crate::permission;
use crate::permission::{KeyPerm, KeyPermSet, KeystorePerm};
use android_hardware_keymint::aidl::android::hardware::keymint::{
    KeyParameter::KeyParameter as KmParam, Tag::Tag,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    KeyDescriptor::KeyDescriptor, KeyParameter::KeyParameter,
};
use anyhow::{anyhow, Context};
use binder::{FromIBinder, SpIBinder, ThreadState};
use std::sync::Mutex;

/// This function uses its namesake in the permission module and in
/// combination with with_calling_sid from the binder crate to check
/// if the caller has the given keystore permission.
pub fn check_keystore_permission(perm: KeystorePerm) -> anyhow::Result<()> {
    ThreadState::with_calling_sid(|calling_sid| {
        permission::check_keystore_permission(
            &calling_sid.ok_or_else(Error::sys).context(
                "In check_keystore_permission: Cannot check permission without calling_sid.",
            )?,
            perm,
        )
    })
}

/// This function uses its namesake in the permission module and in
/// combination with with_calling_sid from the binder crate to check
/// if the caller has the given grant permission.
pub fn check_grant_permission(access_vec: KeyPermSet, key: &KeyDescriptor) -> anyhow::Result<()> {
    ThreadState::with_calling_sid(|calling_sid| {
        permission::check_grant_permission(
            &calling_sid.ok_or_else(Error::sys).context(
                "In check_grant_permission: Cannot check permission without calling_sid.",
            )?,
            access_vec,
            key,
        )
    })
}

/// This function uses its namesake in the permission module and in
/// combination with with_calling_sid from the binder crate to check
/// if the caller has the given key permission.
pub fn check_key_permission(
    perm: KeyPerm,
    key: &KeyDescriptor,
    access_vector: &Option<KeyPermSet>,
) -> anyhow::Result<()> {
    ThreadState::with_calling_sid(|calling_sid| {
        permission::check_key_permission(
            &calling_sid
                .ok_or_else(Error::sys)
                .context("In check_key_permission: Cannot check permission without calling_sid.")?,
            perm,
            key,
            access_vector,
        )
    })
}

/// This function converts a `KeyParameter` from the keystore2 AIDL
/// bindings into a `KeyParameter` from the keymint AIDL bindings.
/// TODO This is a temporary workaround until the keymint AIDL spec
/// lands.
pub fn keyparam_ks_to_km(p: &KeyParameter) -> KmParam {
    KmParam {
        tag: Tag(p.tag),
        boolValue: p.boolValue,
        integer: p.integer,
        longInteger: p.longInteger,
        dateTime: p.dateTime,
        blob: match &p.blob {
            Some(b) => b.clone(),
            None => vec![],
        },
    }
}

/// Thread safe wrapper around SpIBinder. It is safe to have SpIBinder smart pointers to the
/// same object in multiple threads, but cloning a SpIBinder is not thread safe.
/// Keystore frequently hands out binder tokens to the security level interface. If this
/// is to happen from a multi threaded thread pool, the SpIBinder needs to be protected by a
/// Mutex.
#[derive(Debug)]
pub struct Asp(Mutex<SpIBinder>);

impl Asp {
    /// Creates a new instance owning a SpIBinder wrapped in a Mutex.
    pub fn new(i: SpIBinder) -> Self {
        Self(Mutex::new(i))
    }

    /// Clones the owned SpIBinder and attempts to convert it into the requested interface.
    pub fn get_interface<T: FromIBinder + ?Sized>(&self) -> anyhow::Result<Box<T>> {
        // We can use unwrap here because we never panic when locked, so the mutex
        // can never be poisoned.
        let lock = self.0.lock().unwrap();
        (*lock)
            .clone()
            .into_interface()
            .map_err(|e| anyhow!(format!("get_interface failed with error code {:?}", e)))
    }
}
