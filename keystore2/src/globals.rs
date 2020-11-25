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

use crate::async_task::AsyncTask;
use crate::background_task_handler::BackgroundTaskHandler;
use crate::enforcements::Enforcements;
use crate::gc::Gc;
use crate::super_key::SuperKeyManager;
use crate::utils::Asp;
use crate::{
    database::KeystoreDB,
    error::{map_binder_status, map_binder_status_code, Error, ErrorCode},
};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use android_hardware_security_keymint::binder::StatusCode;
use android_security_compat::aidl::android::security::compat::IKeystoreCompatService::IKeystoreCompatService;
use anyhow::{Context, Result};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Mutex;
use std::{cell::RefCell, sync::Once};

static DB_INIT: Once = Once::new();

/// Open a connection to the Keystore 2.0 database. This is called during the initialization of
/// the thread local DB field. It should never be called directly. The first time this is called
/// we also call KeystoreDB::cleanup_leftovers to restore the key lifecycle invariant. See the
/// documentation of cleanup_leftovers for more details.
fn create_thread_local_db() -> KeystoreDB {
    let mut db = KeystoreDB::new(
        // Keystore changes to the database directory on startup
        // (see keystore2_main.rs).
        &std::env::current_dir().expect("Could not get the current working directory."),
    )
    .expect("Failed to open database.");
    DB_INIT.call_once(|| {
        log::info!("Touching Keystore 2.0 database for this first time since boot.");
        log::info!("Calling cleanup leftovers.");
        let n = db.cleanup_leftovers().expect("Failed to cleanup database on startup.");
        if n != 0 {
            log::info!(
                concat!(
                    "Cleaned up {} failed entries. ",
                    "This indicates keystore crashed during key generation."
                ),
                n
            );
        }
        Gc::notify_gc();
    });
    db
}

thread_local! {
    /// Database connections are not thread safe, but connecting to the
    /// same database multiple times is safe as long as each connection is
    /// used by only one thread. So we store one database connection per
    /// thread in this thread local key.
    pub static DB: RefCell<KeystoreDB> =
            RefCell::new(create_thread_local_db());
}

lazy_static! {
    /// Runtime database of unwrapped super keys.
    pub static ref SUPER_KEY: SuperKeyManager = Default::default();
    /// Map of KeyMint devices.
    static ref KEY_MINT_DEVICES: Mutex<HashMap<SecurityLevel, Asp>> = Default::default();
    /// A single on-demand worker thread that handles deferred tasks with two different
    /// priorities.
    pub static ref ASYNC_TASK: AsyncTask = Default::default();
    /// Singeleton for enforcements.
    /// It is safe for this enforcements object to be called by multiple threads because the two
    /// data structures which maintain its state are protected by mutexes.
    pub static ref ENFORCEMENTS: Enforcements = Enforcements::new();
    /// Background task handler is initialized and exists globally.
    /// The other modules (e.g. enforcements) communicate with it via a channel initialized during
    /// keystore startup.
    pub static ref BACKGROUND_TASK_HANDLER: BackgroundTaskHandler = BackgroundTaskHandler::new();
}

static KEYMINT_SERVICE_NAME: &str = "android.hardware.security.keymint.IKeyMintDevice";

/// Make a new connection to a KeyMint device of the given security level.
/// If no native KeyMint device can be found this function also brings
/// up the compatibility service and attempts to connect to the legacy wrapper.
fn connect_keymint(security_level: SecurityLevel) -> Result<Asp> {
    let service_name = match security_level {
        SecurityLevel::TRUSTED_ENVIRONMENT => format!("{}/default", KEYMINT_SERVICE_NAME),
        SecurityLevel::STRONGBOX => format!("{}/strongbox", KEYMINT_SERVICE_NAME),
        _ => {
            return Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                .context("In connect_keymint.")
        }
    };

    let keymint = map_binder_status_code(binder::get_interface(&service_name))
        .context("In connect_keymint: Trying to connect to genuine KeyMint service.")
        .or_else(|e| {
            match e.root_cause().downcast_ref::<Error>() {
                Some(Error::BinderTransaction(StatusCode::NAME_NOT_FOUND)) => {
                    // This is a no-op if it was called before.
                    keystore2_km_compat::add_keymint_device_service();

                    let keystore_compat_service: Box<dyn IKeystoreCompatService> =
                        map_binder_status_code(binder::get_interface("android.security.compat"))
                            .context("In connect_keymint: Trying to connect to compat service.")?;
                    map_binder_status(keystore_compat_service.getKeyMintDevice(security_level))
                        .map_err(|e| match e {
                            Error::BinderTransaction(StatusCode::NAME_NOT_FOUND) => {
                                Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE)
                            }
                            e => e,
                        })
                        .context("In connext_keymint: Trying to get Legacy wrapper.")
                }
                _ => Err(e),
            }
        })?;

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
