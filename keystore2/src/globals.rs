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

use crate::database::KeystoreDB;
use crate::super_key::SuperKeyManager;
use lazy_static::lazy_static;
use std::cell::RefCell;

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
}
