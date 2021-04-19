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
use keystore2::{async_task::AsyncTask, legacy_blob::LegacyBlobLoader};
use rusqlite::{
    params, Connection, OptionalExtension, Transaction, TransactionBehavior, NO_PARAMS,
};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

struct DB {
    conn: Connection,
}

impl DB {
    fn new(db_file: &Path) -> Result<Self> {
        let mut db = Self {
            conn: Connection::open(db_file).context("Failed to initialize SQLite connection.")?,
        };

        // On busy fail Immediately. It is unlikely to succeed given a bug in sqlite.
        db.conn.busy_handler(None).context("Failed to set busy handler.")?;

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
        matches!(
            e.root_cause().downcast_ref::<rusqlite::ffi::Error>(),
            Some(rusqlite::ffi::Error { code: rusqlite::ErrorCode::DatabaseBusy, .. })
                | Some(rusqlite::ffi::Error { code: rusqlite::ErrorCode::DatabaseLocked, .. })
        )
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
            log::error!("{:?}", e);
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

/// Implements IVpnProfileStore AIDL interface.
pub struct VpnProfileStore {
    db_path: PathBuf,
    async_task: AsyncTask,
}

struct AsyncState {
    recently_imported: HashSet<(u32, String)>,
    legacy_loader: LegacyBlobLoader,
    db_path: PathBuf,
}

impl VpnProfileStore {
    /// Creates a new VpnProfileStore instance.
    pub fn new_native_binder(path: &Path) -> Strong<dyn IVpnProfileStore> {
        let mut db_path = path.to_path_buf();
        db_path.push("vpnprofilestore.sqlite");

        let result = Self { db_path, async_task: Default::default() };
        result.init_shelf(path);
        BnVpnProfileStore::new_binder(result)
    }

    fn open_db(&self) -> Result<DB> {
        DB::new(&self.db_path).context("In open_db: Failed to open db.")
    }

    fn get(&self, alias: &str) -> Result<Vec<u8>> {
        let mut db = self.open_db().context("In get.")?;
        let calling_uid = ThreadState::get_calling_uid();

        if let Some(profile) =
            db.get(calling_uid, alias).context("In get: Trying to load profile from DB.")?
        {
            return Ok(profile);
        }
        if self.get_legacy(calling_uid, alias).context("In get: Trying to migrate legacy blob.")? {
            // If we were able to migrate a legacy blob try again.
            if let Some(profile) =
                db.get(calling_uid, alias).context("In get: Trying to load profile from DB.")?
            {
                return Ok(profile);
            }
        }
        Err(Error::not_found()).context("In get: No such profile.")
    }

    fn put(&self, alias: &str, profile: &[u8]) -> Result<()> {
        let calling_uid = ThreadState::get_calling_uid();
        // In order to make sure that we don't have stale legacy profiles, make sure they are
        // migrated before replacing them.
        let _ = self.get_legacy(calling_uid, alias);
        let mut db = self.open_db().context("In put.")?;
        db.put(calling_uid, alias, profile).context("In put: Trying to insert profile into DB.")
    }

    fn remove(&self, alias: &str) -> Result<()> {
        let calling_uid = ThreadState::get_calling_uid();
        let mut db = self.open_db().context("In remove.")?;
        // In order to make sure that we don't have stale legacy profiles, make sure they are
        // migrated before removing them.
        let _ = self.get_legacy(calling_uid, alias);
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
        let mut result = self.list_legacy(calling_uid).context("In list.")?;
        result
            .append(&mut db.list(calling_uid).context("In list: Trying to get list of profiles.")?);
        result = result.into_iter().filter(|s| s.starts_with(prefix)).collect();
        result.sort_unstable();
        result.dedup();
        Ok(result)
    }

    fn init_shelf(&self, path: &Path) {
        let mut db_path = path.to_path_buf();
        self.async_task.queue_hi(move |shelf| {
            let legacy_loader = LegacyBlobLoader::new(&db_path);
            db_path.push("vpnprofilestore.sqlite");

            shelf.put(AsyncState { legacy_loader, db_path, recently_imported: Default::default() });
        })
    }

    fn do_serialized<F, T: Send + 'static>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut AsyncState) -> Result<T> + Send + 'static,
    {
        let (sender, receiver) = std::sync::mpsc::channel::<Result<T>>();
        self.async_task.queue_hi(move |shelf| {
            let state = shelf.get_downcast_mut::<AsyncState>().expect("Failed to get shelf.");
            sender.send(f(state)).expect("Failed to send result.");
        });
        receiver.recv().context("In do_serialized: Failed to receive result.")?
    }

    fn list_legacy(&self, uid: u32) -> Result<Vec<String>> {
        self.do_serialized(move |state| {
            state
                .legacy_loader
                .list_vpn_profiles(uid)
                .context("Trying to list legacy vnp profiles.")
        })
        .context("In list_legacy.")
    }

    fn get_legacy(&self, uid: u32, alias: &str) -> Result<bool> {
        let alias = alias.to_string();
        self.do_serialized(move |state| {
            if state.recently_imported.contains(&(uid, alias.clone())) {
                return Ok(true);
            }
            let mut db = DB::new(&state.db_path).context("In open_db: Failed to open db.")?;
            let migrated =
                Self::migrate_one_legacy_profile(uid, &alias, &state.legacy_loader, &mut db)
                    .context("Trying to migrate legacy vpn profile.")?;
            if migrated {
                state.recently_imported.insert((uid, alias));
            }
            Ok(migrated)
        })
        .context("In get_legacy.")
    }

    fn migrate_one_legacy_profile(
        uid: u32,
        alias: &str,
        legacy_loader: &LegacyBlobLoader,
        db: &mut DB,
    ) -> Result<bool> {
        let blob = legacy_loader
            .read_vpn_profile(uid, alias)
            .context("In migrate_one_legacy_profile: Trying to read legacy vpn profile.")?;
        if let Some(profile) = blob {
            db.put(uid, alias, &profile)
                .context("In migrate_one_legacy_profile: Trying to insert profile into DB.")?;
            legacy_loader
                .remove_vpn_profile(uid, alias)
                .context("In migrate_one_legacy_profile: Trying to delete legacy profile.")?;
            Ok(true)
        } else {
            Ok(false)
        }
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
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use std::time::Instant;

    static TEST_ALIAS: &str = &"test_alias";
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

    #[test]
    fn concurrent_vpn_profile_test() -> Result<()> {
        let temp_dir = Arc::new(
            TempDir::new("concurrent_vpn_profile_test_").expect("Failed to create temp dir."),
        );

        let db_path = temp_dir.build().push("vpnprofile.sqlite").to_owned();

        let test_begin = Instant::now();

        let mut db = DB::new(&db_path).expect("Failed to open database.");
        const PROFILE_COUNT: u32 = 5000u32;
        const PROFILE_DB_COUNT: u32 = 5000u32;

        let mut actual_profile_count = PROFILE_COUNT;
        // First insert PROFILE_COUNT profiles.
        for count in 0..PROFILE_COUNT {
            if Instant::now().duration_since(test_begin) >= Duration::from_secs(15) {
                actual_profile_count = count;
                break;
            }
            let alias = format!("test_alias_{}", count);
            db.put(1, &alias, TEST_BLOB1).expect("Failed to add profile (1).");
        }

        // Insert more keys from a different thread and into a different namespace.
        let db_path1 = db_path.clone();
        let handle1 = thread::spawn(move || {
            let mut db = DB::new(&db_path1).expect("Failed to open database.");

            for count in 0..actual_profile_count {
                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                    return;
                }
                let alias = format!("test_alias_{}", count);
                db.put(2, &alias, TEST_BLOB2).expect("Failed to add profile (2).");
            }

            // Then delete them again.
            for count in 0..actual_profile_count {
                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                    return;
                }
                let alias = format!("test_alias_{}", count);
                db.remove(2, &alias).expect("Remove Failed (2).");
            }
        });

        // And start deleting the first set of profiles.
        let db_path2 = db_path.clone();
        let handle2 = thread::spawn(move || {
            let mut db = DB::new(&db_path2).expect("Failed to open database.");

            for count in 0..actual_profile_count {
                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                    return;
                }
                let alias = format!("test_alias_{}", count);
                db.remove(1, &alias).expect("Remove Failed (1)).");
            }
        });

        // While a lot of inserting and deleting is going on we have to open database connections
        // successfully and then insert and delete a specific profile.
        let db_path3 = db_path.clone();
        let handle3 = thread::spawn(move || {
            for _count in 0..PROFILE_DB_COUNT {
                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                    return;
                }
                let mut db = DB::new(&db_path3).expect("Failed to open database.");

                db.put(3, &TEST_ALIAS, TEST_BLOB3).expect("Failed to add profile (3).");

                db.remove(3, &TEST_ALIAS).expect("Remove failed (3).");
            }
        });

        // While thread 3 is inserting and deleting TEST_ALIAS, we try to get the alias.
        // This may yield an entry or none, but it must not fail.
        let handle4 = thread::spawn(move || {
            for _count in 0..PROFILE_DB_COUNT {
                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                    return;
                }
                let mut db = DB::new(&db_path).expect("Failed to open database.");

                // This may return Some or None but it must not fail.
                db.get(3, &TEST_ALIAS).expect("Failed to get profile (4).");
            }
        });

        handle1.join().expect("Thread 1 panicked.");
        handle2.join().expect("Thread 2 panicked.");
        handle3.join().expect("Thread 3 panicked.");
        handle4.join().expect("Thread 4 panicked.");

        Ok(())
    }
}
