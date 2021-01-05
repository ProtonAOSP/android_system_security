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

use std::fs::{create_dir, remove_dir_all};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::{env::temp_dir, ops::Deref};

#[derive(Debug)]
pub struct TempDir {
    path: std::path::PathBuf,
    do_drop: bool,
}

impl TempDir {
    pub fn new(prefix: &str) -> std::io::Result<Self> {
        let tmp = loop {
            let mut tmp = temp_dir();
            let number: u16 = rand::random();
            tmp.push(format!("{}_{:05}", prefix, number));
            match create_dir(&tmp) {
                Err(e) => match e.kind() {
                    ErrorKind::AlreadyExists => continue,
                    _ => return Err(e),
                },
                Ok(()) => break tmp,
            }
        };
        Ok(Self { path: tmp, do_drop: true })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn build(&self) -> PathBuilder {
        PathBuilder(self.path.clone())
    }

    /// When a test is failing you can set this to false in order to inspect
    /// the directory structure after the test failed.
    #[allow(dead_code)]
    pub fn do_not_drop(&mut self) {
        println!("Disabled automatic cleanup for: {:?}", self.path);
        log::info!("Disabled automatic cleanup for: {:?}", self.path);
        self.do_drop = false;
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if self.do_drop {
            remove_dir_all(&self.path).expect("Cannot delete temporary dir.");
        }
    }
}

pub struct PathBuilder(PathBuf);

impl PathBuilder {
    pub fn push(mut self, segment: &str) -> Self {
        self.0.push(segment);
        self
    }
}

impl Deref for PathBuilder {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
