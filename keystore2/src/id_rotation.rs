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

//! This module implements the unique id rotation privacy feature. Certain system components
//! have the ability to include a per-app unique id into the key attestation. The key rotation
//! feature assures that the unique id is rotated on factory reset at least once in a 30 day
//! key rotation period.
//!
//! It is assumed that the timestamp file does not exist after a factory reset. So the creation
//! time of the timestamp file provides a lower bound for the time since factory reset.

use anyhow::{Context, Result};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

const ID_ROTATION_PERIOD: Duration = Duration::from_secs(30 * 24 * 60 * 60); // Thirty days.
static TIMESTAMP_FILE_NAME: &str = &"timestamp";

/// The IdRotationState stores the path to the timestamp file for deferred usage. The data
/// partition is usually not available when Keystore 2.0 starts up. So this object is created
/// and passed down to the users of the feature which can then query the timestamp on demand.
#[derive(Debug, Clone)]
pub struct IdRotationState {
    timestamp_path: PathBuf,
}

impl IdRotationState {
    /// Creates a new IdRotationState. It holds the path to the timestamp file for deferred usage.
    pub fn new(keystore_db_path: &Path) -> Self {
        let mut timestamp_path = keystore_db_path.to_owned();
        timestamp_path.push(TIMESTAMP_FILE_NAME);
        Self { timestamp_path }
    }

    /// Reads the metadata of or creates the timestamp file. It returns true if the timestamp
    /// file is younger than `ID_ROTATION_PERIOD`, i.e., 30 days.
    pub fn had_factory_reset_since_id_rotation(&self) -> Result<bool> {
        match fs::metadata(&self.timestamp_path) {
            Ok(metadata) => {
                let duration_since_factory_reset = metadata
                    .modified()
                    .context("File creation time not supported.")?
                    .elapsed()
                    .context("Failed to compute time elapsed since factory reset.")?;
                Ok(duration_since_factory_reset < ID_ROTATION_PERIOD)
            }
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    fs::File::create(&self.timestamp_path)
                        .context("Failed to create timestamp file.")?;
                    Ok(true)
                }
                _ => Err(e).context("Failed to open timestamp file."),
            },
        }
        .context("In had_factory_reset_since_id_rotation:")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use keystore2_test_utils::TempDir;
    use nix::sys::stat::utimes;
    use nix::sys::time::{TimeVal, TimeValLike};
    use std::convert::TryInto;
    use std::time::UNIX_EPOCH;

    #[test]
    fn test_had_factory_reset_since_id_rotation() -> Result<()> {
        let temp_dir = TempDir::new("test_had_factory_reset_since_id_rotation_")
            .expect("Failed to create temp dir.");
        let id_rotation_state = IdRotationState::new(&temp_dir.path());

        let mut temp_file_path = temp_dir.path().to_owned();
        temp_file_path.push(TIMESTAMP_FILE_NAME);

        // The timestamp file should not exist.
        assert!(!temp_file_path.exists());

        // This should return true.
        assert!(id_rotation_state.had_factory_reset_since_id_rotation()?);

        // Now the timestamp file should exist.
        assert!(temp_file_path.exists());

        // We should still return true because the timestamp file is young.
        assert!(id_rotation_state.had_factory_reset_since_id_rotation()?);

        // Now let's age the timestamp file by backdating the modification time.
        let metadata = fs::metadata(&temp_file_path)?;
        let mtime = metadata.modified()?;
        let mtime = mtime.duration_since(UNIX_EPOCH)?;
        let mtime =
            mtime.checked_sub(ID_ROTATION_PERIOD).expect("Failed to subtract id rotation period");
        let mtime = TimeVal::seconds(mtime.as_secs().try_into().unwrap());

        let atime = metadata.accessed()?;
        let atime = atime.duration_since(UNIX_EPOCH)?;
        let atime = TimeVal::seconds(atime.as_secs().try_into().unwrap());

        utimes(&temp_file_path, &atime, &mtime)?;

        // Now that the file has aged we should see false.
        assert!(!id_rotation_state.had_factory_reset_since_id_rotation()?);

        Ok(())
    }
}
