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
use keystore2::service::KeystoreService;
use log::{error, info};
use std::panic;

static KS2_SERVICE_NAME: &str = "android.system.keystore2";

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
    if let Some(dir) = args.next() {
        if std::env::set_current_dir(dir.clone()).is_err() {
            panic!("Failed to set working directory {}.", dir)
        }
    } else {
        panic!("Must specify a working directory.");
    }

    let ks_service = KeystoreService::new_native_binder().unwrap_or_else(|e| {
        panic!("Failed to create service {} because of {:?}.", KS2_SERVICE_NAME, e);
    });
    binder::add_service(KS2_SERVICE_NAME, ks_service.as_binder()).unwrap_or_else(|e| {
        panic!("Failed to register service {} because of {:?}.", KS2_SERVICE_NAME, e);
    });

    info!("Successfully registered Keystore 2.0 service.");

    info!("Starting thread pool now.");
    binder::ProcessState::start_thread_pool();

    info!("Joining thread pool now.");
    binder::ProcessState::join_thread_pool();
}
