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

use binder::Interface;
use keystore2::apc::ApcManager;
use keystore2::authorization::AuthorizationManager;
use keystore2::service::KeystoreService;
use log::{error, info};
use std::panic;

static KS2_SERVICE_NAME: &str = "android.system.keystore2";
static APC_SERVICE_NAME: &str = "android.security.apc";
static AUTHORIZATION_SERVICE_NAME: &str = "android.security.authorization";

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

    let mut args = std::env::args();
    args.next().expect("That's odd. How is there not even a first argument?");

    // Keystore changes to the database directory on startup (typically /data/misc/keystore).
    // For the ground truth check the service startup rule for init (typically in keystore2.rc).
    if let Some(dir) = args.next() {
        if std::env::set_current_dir(dir.clone()).is_err() {
            panic!("Failed to set working directory {}.", dir)
        }
    } else {
        panic!("Must specify a working directory.");
    }

    info!("Starting thread pool now.");
    binder::ProcessState::start_thread_pool();

    let ks_service = KeystoreService::new_native_binder().unwrap_or_else(|e| {
        panic!("Failed to create service {} because of {:?}.", KS2_SERVICE_NAME, e);
    });
    binder::add_service(KS2_SERVICE_NAME, ks_service.as_binder()).unwrap_or_else(|e| {
        panic!("Failed to register service {} because of {:?}.", KS2_SERVICE_NAME, e);
    });

    let apc_service = ApcManager::new_native_binder().unwrap_or_else(|e| {
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

    info!("Successfully registered Keystore 2.0 service.");

    info!("Joining thread pool now.");
    binder::ProcessState::join_thread_pool();
}
