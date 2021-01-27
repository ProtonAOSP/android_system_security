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

//! This crate implements the Keystore 2.0 service entry point.

use keystore2::apc::ApcManager;
use keystore2::authorization::AuthorizationManager;
use keystore2::globals::ENFORCEMENTS;
use keystore2::service::KeystoreService;
use keystore2::user_manager::UserManager;
use log::{error, info};
use std::{panic, path::Path, sync::mpsc::channel};

static KS2_SERVICE_NAME: &str = "android.system.keystore2";
static APC_SERVICE_NAME: &str = "android.security.apc";
static AUTHORIZATION_SERVICE_NAME: &str = "android.security.authorization";
static USER_MANAGER_SERVICE_NAME: &str = "android.security.usermanager";

/// Keystore 2.0 takes one argument which is a path indicating its designated working directory.
fn main() {
    // Initialize android logging.
    android_logger::init_once(
        android_logger::Config::default().with_tag("keystore2").with_min_level(log::Level::Debug),
    );
    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    // Saying hi.
    info!("Keystore2 is starting.");

    // Initialize the per boot database.
    let _keep_me_alive = keystore2::database::KeystoreDB::keep_perboot_db_alive()
        .expect("Failed to initialize the perboot database.");

    let mut args = std::env::args();
    args.next().expect("That's odd. How is there not even a first argument?");

    // Keystore 2.0 cannot change to the database directory (typically /data/misc/keystore) on
    // startup as Keystore 1.0 did because Keystore 2.0 is intended to run much earlier than
    // Keystore 1.0. Instead we set a global variable to the database path.
    // For the ground truth check the service startup rule for init (typically in keystore2.rc).
    if let Some(dir) = args.next() {
        *keystore2::globals::DB_PATH.lock().expect("Could not lock DB_PATH.") =
            Path::new(&dir).to_path_buf();
    } else {
        panic!("Must specify a working directory.");
    }

    let (confirmation_token_sender, confirmation_token_receiver) = channel();

    ENFORCEMENTS.install_confirmation_token_receiver(confirmation_token_receiver);

    info!("Starting thread pool now.");
    binder::ProcessState::start_thread_pool();

    let ks_service = KeystoreService::new_native_binder().unwrap_or_else(|e| {
        panic!("Failed to create service {} because of {:?}.", KS2_SERVICE_NAME, e);
    });
    binder::add_service(KS2_SERVICE_NAME, ks_service.as_binder()).unwrap_or_else(|e| {
        panic!("Failed to register service {} because of {:?}.", KS2_SERVICE_NAME, e);
    });

    let apc_service =
        ApcManager::new_native_binder(confirmation_token_sender).unwrap_or_else(|e| {
            panic!("Failed to create service {} because of {:?}.", APC_SERVICE_NAME, e);
        });
    binder::add_service(APC_SERVICE_NAME, apc_service.as_binder()).unwrap_or_else(|e| {
        panic!("Failed to register service {} because of {:?}.", APC_SERVICE_NAME, e);
    });

    let authorization_service = AuthorizationManager::new_native_binder().unwrap_or_else(|e| {
        panic!("Failed to create service {} because of {:?}.", AUTHORIZATION_SERVICE_NAME, e);
    });
    binder::add_service(AUTHORIZATION_SERVICE_NAME, authorization_service.as_binder())
        .unwrap_or_else(|e| {
            panic!("Failed to register service {} because of {:?}.", AUTHORIZATION_SERVICE_NAME, e);
        });

    let usermanager_service = UserManager::new_native_binder().unwrap_or_else(|e| {
        panic!("Failed to create service {} because of {:?}.", USER_MANAGER_SERVICE_NAME, e);
    });
    binder::add_service(USER_MANAGER_SERVICE_NAME, usermanager_service.as_binder()).unwrap_or_else(
        |e| {
            panic!("Failed to register service {} because of {:?}.", USER_MANAGER_SERVICE_NAME, e);
        },
    );

    info!("Successfully registered Keystore 2.0 service.");

    info!("Joining thread pool now.");
    binder::ProcessState::join_thread_pool();
}
