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

//! This crate implements the Android Keystore 2.0 service.
#![recursion_limit = "256"]

pub mod apc;
pub mod auth_token_handler;
pub mod authorization;
pub mod background_task_handler;
pub mod database;
pub mod enforcements;
pub mod error;
pub mod globals;
/// Internal Representation of Key Parameter and convenience functions.
pub mod key_parameter;
pub mod legacy_blob;
pub mod operation;
pub mod permission;
pub mod security_level;
pub mod service;
pub mod utils;

mod async_task;
mod db_utils;
mod gc;
mod super_key;

#[cfg(test)]
mod test {
    pub mod utils;
}
