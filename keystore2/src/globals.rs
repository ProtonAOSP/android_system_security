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

//! This module holds global state of Keystore such as the thread local
//! database connections and connections to services that Keystore needs
//! to talk to.

use crate::super_key::SuperKeyManager;
use crate::utils::Asp;
use crate::{
    database::KeystoreDB,
    error::{map_binder_status_code, Error, ErrorCode},
};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    IKeyMintDevice::IKeyMintDevice, SecurityLevel::SecurityLevel,
};
use anyhow::{Context, Result};
use lazy_static::lazy_static;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Mutex;

thread_local! {
    /// Database connections are not thread safe, but connecting to the
    /// same database multiple times is safe as long as each connection is
    /// used by only one thread. So we store one database connection per
    /// thread in this thread local key.
    pub static DB: RefCell<KeystoreDB> =
            RefCell::new(
                KeystoreDB::new(
                    // Keystore changes to the database directory on startup
                    // (see keystor2_main.rs).
                    &std::env::current_dir()
                    .expect("Could not get the current working directory.")
                )
                .expect("Failed to open database."));
}

lazy_static! {
    /// Runtime database of unwrapped super keys.
    pub static ref SUPER_KEY: SuperKeyManager = Default::default();
    /// Map of KeyMint devices.
    static ref KEY_MINT_DEVICES: Mutex<HashMap<SecurityLevel, Asp>> = Default::default();
}

static KEYMINT_SERVICE_NAME: &str = "android.hardware.security.keymint.IKeyMintDevice";

/// Make a new connection to a KeyMint device of the given security level.
fn connect_keymint(security_level: SecurityLevel) -> Result<Asp> {
    let service_name = match security_level {
        SecurityLevel::TRUSTED_ENVIRONMENT => format!("{}/default", KEYMINT_SERVICE_NAME),
        SecurityLevel::STRONGBOX => format!("{}/strongbox", KEYMINT_SERVICE_NAME),
        _ => {
            return Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                .context("In connect_keymint.")
        }
    };

    let keymint: Box<dyn IKeyMintDevice> =
        map_binder_status_code(binder::get_interface(&service_name))
            .context("In connect_keymint: Trying to connect to genuine KeyMint service.")?;

    Ok(Asp::new(keymint.as_binder()))
}

/// Get a keymint device for the given security level either from our cache or
/// by making a new connection.
pub fn get_keymint_device(security_level: SecurityLevel) -> Result<Asp> {
    let mut devices_map = KEY_MINT_DEVICES.lock().unwrap();
    if let Some(dev) = devices_map.get(&security_level) {
        Ok(dev.clone())
    } else {
        let dev = connect_keymint(security_level).map_err(|e| {
            anyhow::anyhow!(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                .context(format!("In get_keymint_device: {:?}", e))
        })?;
        devices_map.insert(security_level, dev.clone());
        Ok(dev)
    }
}
