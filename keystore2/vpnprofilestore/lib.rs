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

//! Implements the android.security.vpnprofilestore interface.

use android_security_vpnprofilestore::aidl::android::security::vpnprofilestore::{
    IVpnProfileStore::BnVpnProfileStore, IVpnProfileStore::IVpnProfileStore,
    IVpnProfileStore::ERROR_PROFILE_NOT_FOUND, IVpnProfileStore::ERROR_SYSTEM_ERROR,
};
use android_security_vpnprofilestore::binder::{Result as BinderResult, Status as BinderStatus};
use anyhow::{Context, Result};
use binder::{ExceptionCode, Strong, ThreadState};
use rusqlite::{
    params, Connection, OptionalExtension, Transaction, TransactionBehavior, NO_PARAMS,
};
use std::path::{Path, PathBuf};

struct DB {
    conn: Connection,
}

impl DB {
    fn new(db_file: &Path) -> Result<Self> {
        let mut db = Self {
            conn: Connection::open(db_file).context("Failed to initialize SQLite connection.")?,
        };
        db.init_tables().context("Trying to initialize vpnstore db.")?;
        Ok(db)
    }

    fn with_transaction<T, F>(&mut self, behavior: TransactionBehavior, f: F) -> Result<T>
    where
        F: Fn(&Transaction) -> Result<T>,
    {
        loop {
            match self
                .conn
                .transaction_with_behavior(behavior)
                .context("In with_transaction.")
                .and_then(|tx| f(&tx).map(|result| (result, tx)))
                .and_then(|(result, tx)| {
                    tx.commit().context("In with_transaction: Failed to commit transaction.")?;
                    Ok(result)
                }) {
                Ok(result) => break Ok(result),
                Err(e) => {
                    if Self::is_locked_error(&e) {
                        std::thread::sleep(std::time::Duration::from_micros(500));
                        continue;
                    } else {
                        return Err(e).context("In with_transaction.");
                    }
                }
            }
        }
    }

    fn is_locked_error(e: &anyhow::Error) -> bool {
        matches!(e.root_cause().downcast_ref::<rusqlite::ffi::Error>(),
        Some(rusqlite::ffi::Error {
            code: rusqlite::ErrorCode::DatabaseBusy,
            ..
        })
        | Some(rusqlite::ffi::Error {
            code: rusqlite::ErrorCode::DatabaseLocked,
            ..
        }))
    }

    fn init_tables(&mut self) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            tx.execute(
                "CREATE TABLE IF NOT EXISTS profiles (
                     owner INTEGER,
                     alias BLOB,
                     profile BLOB,
                     UNIQUE(owner, alias));",
                NO_PARAMS,
            )
            .context("Failed to initialize \"profiles\" table.")?;
            Ok(())
        })
    }

    fn list(&mut self, caller_uid: u32) -> Result<Vec<String>> {
        self.with_transaction(TransactionBehavior::Deferred, |tx| {
            let mut stmt = tx
                .prepare("SELECT alias FROM profiles WHERE owner = ? ORDER BY alias ASC;")
                .context("In list: Failed to prepare statement.")?;

            let aliases = stmt
                .query_map(params![caller_uid], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()
                .context("In list: query_map failed.");
            aliases
        })
    }

    fn put(&mut self, caller_uid: u32, alias: &str, profile: &[u8]) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            tx.execute(
                "INSERT OR REPLACE INTO profiles (owner, alias, profile) values (?, ?, ?)",
                params![caller_uid, alias, profile,],
            )
            .context("In put: Failed to insert or replace.")?;
            Ok(())
        })
    }

    fn get(&mut self, caller_uid: u32, alias: &str) -> Result<Option<Vec<u8>>> {
        self.with_transaction(TransactionBehavior::Deferred, |tx| {
            tx.query_row(
                "SELECT profile FROM profiles WHERE owner = ? AND alias = ?;",
                params![caller_uid, alias],
                |row| row.get(0),
            )
            .optional()
            .context("In get: failed loading profile.")
        })
    }

    fn remove(&mut self, caller_uid: u32, alias: &str) -> Result<bool> {
        let removed = self.with_transaction(TransactionBehavior::Immediate, |tx| {
            tx.execute(
                "DELETE FROM profiles WHERE owner = ? AND alias = ?;",
                params![caller_uid, alias],
            )
            .context("In remove: Failed to delete row.")
        })?;
        Ok(removed == 1)
    }
}

/// This is the main VpnProfileStore error type, it wraps binder exceptions and the
/// VnpStore errors.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    /// Wraps a VpnProfileStore error code.
    #[error("Error::Error({0:?})")]
    Error(i32),
    /// Wraps a Binder exception code other than a service specific exception.
    #[error("Binder exception code {0:?}, {1:?}")]
    Binder(ExceptionCode, i32),
}

impl Error {
    /// Short hand for `Error::Error(ERROR_SYSTEM_ERROR)`
    pub fn sys() -> Self {
        Error::Error(ERROR_SYSTEM_ERROR)
    }

    /// Short hand for `Error::Error(ERROR_PROFILE_NOT_FOUND)`
    pub fn not_found() -> Self {
        Error::Error(ERROR_PROFILE_NOT_FOUND)
    }
}

/// This function should be used by vpnprofilestore service calls to translate error conditions
/// into service specific exceptions.
///
/// All error conditions get logged by this function.
///
/// `Error::Error(x)` variants get mapped onto a service specific error code of `x`.
///
/// All non `Error` error conditions get mapped onto `ERROR_SYSTEM_ERROR`.
///
/// `handle_ok` will be called if `result` is `Ok(value)` where `value` will be passed
/// as argument to `handle_ok`. `handle_ok` must generate a `BinderResult<T>`, but it
/// typically returns Ok(value).
fn map_or_log_err<T, U, F>(result: Result<U>, handle_ok: F) -> BinderResult<T>
where
    F: FnOnce(U) -> BinderResult<T>,
{
    result.map_or_else(
        |e| {
            log::error!("{:#?}", e);
            let root_cause = e.root_cause();
            let rc = match root_cause.downcast_ref::<Error>() {
                Some(Error::Error(e)) => *e,
                Some(Error::Binder(_, _)) | None => ERROR_SYSTEM_ERROR,
            };
            Err(BinderStatus::new_service_specific_error(rc, None))
        },
        handle_ok,
    )
}

// TODO make sure that ALIASES have a prefix of VPN_ PLATFORM_VPN_ or
// is equal to LOCKDOWN_VPN.

/// Implements IVpnProfileStore AIDL interface.
pub struct VpnProfileStore {
    db_path: PathBuf,
}

impl VpnProfileStore {
    /// Creates a new VpnProfileStore instance.
    pub fn new_native_binder(db_path: &Path) -> Strong<dyn IVpnProfileStore> {
        let mut db_path = path.to_path_buf();
        db_path.push("vpnprofilestore.sqlite");
        BnVpnProfileStore::new_binder(Self { db_path })
    }

    fn open_db(&self) -> Result<DB> {
        DB::new(&self.db_path).context("In open_db: Failed to open db.")
    }

    fn get(&self, alias: &str) -> Result<Vec<u8>> {
        let mut db = self.open_db().context("In get.")?;
        let calling_uid = ThreadState::get_calling_uid();
        db.get(calling_uid, alias)
            .context("In get: Trying to load profile from DB.")?
            .ok_or_else(Error::not_found)
            .context("In get: No such profile.")
    }

    fn put(&self, alias: &str, profile: &[u8]) -> Result<()> {
        let mut db = self.open_db().context("In put.")?;
        let calling_uid = ThreadState::get_calling_uid();
        db.put(calling_uid, alias, profile).context("In put: Trying to insert profile into DB.")
    }

    fn remove(&self, alias: &str) -> Result<()> {
        let mut db = self.open_db().context("In remove.")?;
        let calling_uid = ThreadState::get_calling_uid();
        let removed = db
            .remove(calling_uid, alias)
            .context("In remove: Trying to remove profile from DB.")?;
        if removed {
            Ok(())
        } else {
            Err(Error::not_found()).context("In remove: No such profile.")
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut db = self.open_db().context("In list.")?;
        let calling_uid = ThreadState::get_calling_uid();
        Ok(db
            .list(calling_uid)
            .context("In list: Trying to get list of profiles.")?
            .into_iter()
            .filter(|s| s.starts_with(prefix))
            .collect())
    }
}

impl binder::Interface for VpnProfileStore {}

impl IVpnProfileStore for VpnProfileStore {
    fn get(&self, alias: &str) -> BinderResult<Vec<u8>> {
        map_or_log_err(self.get(alias), Ok)
    }
    fn put(&self, alias: &str, profile: &[u8]) -> BinderResult<()> {
        map_or_log_err(self.put(alias, profile), Ok)
    }
    fn remove(&self, alias: &str) -> BinderResult<()> {
        map_or_log_err(self.remove(alias), Ok)
    }
    fn list(&self, prefix: &str) -> BinderResult<Vec<String>> {
        map_or_log_err(self.list(prefix), Ok)
    }
}

#[cfg(test)]
mod db_test {
    use super::*;
    use keystore2_test_utils::TempDir;

    static TEST_BLOB1: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
    static TEST_BLOB2: &[u8] = &[2, 2, 3, 4, 5, 6, 7, 8, 9, 0];
    static TEST_BLOB3: &[u8] = &[3, 2, 3, 4, 5, 6, 7, 8, 9, 0];
    static TEST_BLOB4: &[u8] = &[3, 2, 3, 4, 5, 6, 7, 8, 9, 0];

    #[test]
    fn test_profile_db() {
        let test_dir = TempDir::new("profiledb_test_").expect("Failed to create temp dir.");
        let mut db =
            DB::new(&test_dir.build().push("vpnprofile.sqlite")).expect("Failed to open database.");

        // Insert three profiles for owner 2.
        db.put(2, "test1", TEST_BLOB1).expect("Failed to insert test1.");
        db.put(2, "test2", TEST_BLOB2).expect("Failed to insert test2.");
        db.put(2, "test3", TEST_BLOB3).expect("Failed to insert test3.");

        // Check list returns all inserted aliases.
        assert_eq!(
            vec!["test1".to_string(), "test2".to_string(), "test3".to_string(),],
            db.list(2).expect("Failed to list profiles.")
        );

        // There should be no profiles for owner 1.
        assert_eq!(Vec::<String>::new(), db.list(1).expect("Failed to list profiles."));

        // Check the content of the three entries.
        assert_eq!(
            Some(TEST_BLOB1),
            db.get(2, "test1").expect("Failed to get profile.").as_deref()
        );
        assert_eq!(
            Some(TEST_BLOB2),
            db.get(2, "test2").expect("Failed to get profile.").as_deref()
        );
        assert_eq!(
            Some(TEST_BLOB3),
            db.get(2, "test3").expect("Failed to get profile.").as_deref()
        );

        // Remove test2 and check and check that it is no longer retrievable.
        assert!(db.remove(2, "test2").expect("Failed to remove profile."));
        assert!(db.get(2, "test2").expect("Failed to get profile.").is_none());

        // test2 should now no longer be in the list.
        assert_eq!(
            vec!["test1".to_string(), "test3".to_string(),],
            db.list(2).expect("Failed to list profiles.")
        );

        // Put on existing alias replaces it.
        // Verify test1 is TEST_BLOB1.
        assert_eq!(
            Some(TEST_BLOB1),
            db.get(2, "test1").expect("Failed to get profile.").as_deref()
        );
        db.put(2, "test1", TEST_BLOB4).expect("Failed to replace test1.");
        // Verify test1 is TEST_BLOB4.
        assert_eq!(
            Some(TEST_BLOB4),
            db.get(2, "test1").expect("Failed to get profile.").as_deref()
        );
    }
}
