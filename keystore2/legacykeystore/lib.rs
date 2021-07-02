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

//! Implements the android.security.legacykeystore interface.

use android_security_legacykeystore::aidl::android::security::legacykeystore::{
    ILegacyKeystore::BnLegacyKeystore, ILegacyKeystore::ILegacyKeystore,
    ILegacyKeystore::ERROR_ENTRY_NOT_FOUND, ILegacyKeystore::ERROR_PERMISSION_DENIED,
    ILegacyKeystore::ERROR_SYSTEM_ERROR, ILegacyKeystore::UID_SELF,
};
use android_security_legacykeystore::binder::{
    BinderFeatures, ExceptionCode, Result as BinderResult, Status as BinderStatus, Strong,
    ThreadState,
};
use anyhow::{Context, Result};
use keystore2::{
    async_task::AsyncTask, legacy_blob::LegacyBlobLoader, maintenance::DeleteListener,
    maintenance::Domain, utils::watchdog as wd,
};
use rusqlite::{
    params, Connection, OptionalExtension, Transaction, TransactionBehavior, NO_PARAMS,
};
use std::sync::Arc;
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

        db.init_tables().context("Trying to initialize legacy keystore db.")?;
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

    fn put(&mut self, caller_uid: u32, alias: &str, entry: &[u8]) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            tx.execute(
                "INSERT OR REPLACE INTO profiles (owner, alias, profile) values (?, ?, ?)",
                params![caller_uid, alias, entry,],
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
            .context("In get: failed loading entry.")
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

    fn remove_uid(&mut self, uid: u32) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            tx.execute("DELETE FROM profiles WHERE owner = ?;", params![uid])
                .context("In remove_uid: Failed to delete.")
        })?;
        Ok(())
    }

    fn remove_user(&mut self, user_id: u32) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            tx.execute(
                "DELETE FROM profiles WHERE cast ( ( owner/? ) as int) = ?;",
                params![cutils_bindgen::AID_USER_OFFSET, user_id],
            )
            .context("In remove_uid: Failed to delete.")
        })?;
        Ok(())
    }
}

/// This is the main LegacyKeystore error type, it wraps binder exceptions and the
/// LegacyKeystore errors.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    /// Wraps a LegacyKeystore error code.
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

    /// Short hand for `Error::Error(ERROR_ENTRY_NOT_FOUND)`
    pub fn not_found() -> Self {
        Error::Error(ERROR_ENTRY_NOT_FOUND)
    }

    /// Short hand for `Error::Error(ERROR_PERMISSION_DENIED)`
    pub fn perm() -> Self {
        Error::Error(ERROR_PERMISSION_DENIED)
    }
}

/// This function should be used by legacykeystore service calls to translate error conditions
/// into service specific exceptions.
///
/// All error conditions get logged by this function, except for ERROR_ENTRY_NOT_FOUND error.
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
            let root_cause = e.root_cause();
            let (rc, log_error) = match root_cause.downcast_ref::<Error>() {
                // Make the entry not found errors silent.
                Some(Error::Error(ERROR_ENTRY_NOT_FOUND)) => (ERROR_ENTRY_NOT_FOUND, false),
                Some(Error::Error(e)) => (*e, true),
                Some(Error::Binder(_, _)) | None => (ERROR_SYSTEM_ERROR, true),
            };
            if log_error {
                log::error!("{:?}", e);
            }
            Err(BinderStatus::new_service_specific_error(rc, None))
        },
        handle_ok,
    )
}

struct LegacyKeystoreDeleteListener {
    legacy_keystore: Arc<LegacyKeystore>,
}

impl DeleteListener for LegacyKeystoreDeleteListener {
    fn delete_namespace(&self, domain: Domain, namespace: i64) -> Result<()> {
        self.legacy_keystore.delete_namespace(domain, namespace)
    }
    fn delete_user(&self, user_id: u32) -> Result<()> {
        self.legacy_keystore.delete_user(user_id)
    }
}

/// Implements ILegacyKeystore AIDL interface.
pub struct LegacyKeystore {
    db_path: PathBuf,
    async_task: AsyncTask,
}

struct AsyncState {
    recently_imported: HashSet<(u32, String)>,
    legacy_loader: LegacyBlobLoader,
    db_path: PathBuf,
}

impl LegacyKeystore {
    /// Note: The filename was chosen before the purpose of this module was extended.
    ///       It is kept for backward compatibility with early adopters.
    const LEGACY_KEYSTORE_FILE_NAME: &'static str = "vpnprofilestore.sqlite";

    const WIFI_NAMESPACE: i64 = 102;
    const AID_WIFI: u32 = 1010;

    /// Creates a new LegacyKeystore instance.
    pub fn new_native_binder(
        path: &Path,
    ) -> (Box<dyn DeleteListener + Send + Sync + 'static>, Strong<dyn ILegacyKeystore>) {
        let mut db_path = path.to_path_buf();
        db_path.push(Self::LEGACY_KEYSTORE_FILE_NAME);

        let legacy_keystore = Arc::new(Self { db_path, async_task: Default::default() });
        legacy_keystore.init_shelf(path);
        let service = LegacyKeystoreService { legacy_keystore: legacy_keystore.clone() };
        (
            Box::new(LegacyKeystoreDeleteListener { legacy_keystore }),
            BnLegacyKeystore::new_binder(service, BinderFeatures::default()),
        )
    }

    fn open_db(&self) -> Result<DB> {
        DB::new(&self.db_path).context("In open_db: Failed to open db.")
    }

    fn get_effective_uid(uid: i32) -> Result<u32> {
        const AID_SYSTEM: u32 = 1000;
        let calling_uid = ThreadState::get_calling_uid();
        let uid = uid as u32;

        if uid == UID_SELF as u32 || uid == calling_uid {
            Ok(calling_uid)
        } else if calling_uid == AID_SYSTEM && uid == Self::AID_WIFI {
            // The only exception for legacy reasons is allowing SYSTEM to access
            // the WIFI namespace.
            // IMPORTANT: If you attempt to add more exceptions, it means you are adding
            // more callers to this deprecated feature. DON'T!
            Ok(Self::AID_WIFI)
        } else {
            Err(Error::perm()).with_context(|| {
                format!("In get_effective_uid: caller: {}, requested uid: {}.", calling_uid, uid)
            })
        }
    }

    fn get(&self, alias: &str, uid: i32) -> Result<Vec<u8>> {
        let mut db = self.open_db().context("In get.")?;
        let uid = Self::get_effective_uid(uid).context("In get.")?;

        if let Some(entry) = db.get(uid, alias).context("In get: Trying to load entry from DB.")? {
            return Ok(entry);
        }
        if self.get_legacy(uid, alias).context("In get: Trying to migrate legacy blob.")? {
            // If we were able to migrate a legacy blob try again.
            if let Some(entry) =
                db.get(uid, alias).context("In get: Trying to load entry from DB.")?
            {
                return Ok(entry);
            }
        }
        Err(Error::not_found()).context("In get: No such entry.")
    }

    fn put(&self, alias: &str, uid: i32, entry: &[u8]) -> Result<()> {
        let uid = Self::get_effective_uid(uid).context("In put.")?;
        // In order to make sure that we don't have stale legacy entries, make sure they are
        // migrated before replacing them.
        let _ = self.get_legacy(uid, alias);
        let mut db = self.open_db().context("In put.")?;
        db.put(uid, alias, entry).context("In put: Trying to insert entry into DB.")
    }

    fn remove(&self, alias: &str, uid: i32) -> Result<()> {
        let uid = Self::get_effective_uid(uid).context("In remove.")?;
        let mut db = self.open_db().context("In remove.")?;
        // In order to make sure that we don't have stale legacy entries, make sure they are
        // migrated before removing them.
        let _ = self.get_legacy(uid, alias);
        let removed =
            db.remove(uid, alias).context("In remove: Trying to remove entry from DB.")?;
        if removed {
            Ok(())
        } else {
            Err(Error::not_found()).context("In remove: No such entry.")
        }
    }

    fn delete_namespace(&self, domain: Domain, namespace: i64) -> Result<()> {
        let uid = match domain {
            Domain::APP => namespace as u32,
            Domain::SELINUX => {
                if namespace == Self::WIFI_NAMESPACE {
                    // Namespace WIFI gets mapped to AID_WIFI.
                    Self::AID_WIFI
                } else {
                    // Nothing to do for any other namespace.
                    return Ok(());
                }
            }
            _ => return Ok(()),
        };

        if let Err(e) = self.bulk_delete_uid(uid) {
            log::warn!("In LegacyKeystore::delete_namespace: {:?}", e);
        }
        let mut db = self.open_db().context("In LegacyKeystore::delete_namespace.")?;
        db.remove_uid(uid).context("In LegacyKeystore::delete_namespace.")
    }

    fn delete_user(&self, user_id: u32) -> Result<()> {
        if let Err(e) = self.bulk_delete_user(user_id) {
            log::warn!("In LegacyKeystore::delete_user: {:?}", e);
        }
        let mut db = self.open_db().context("In LegacyKeystore::delete_user.")?;
        db.remove_user(user_id).context("In LegacyKeystore::delete_user.")
    }

    fn list(&self, prefix: &str, uid: i32) -> Result<Vec<String>> {
        let mut db = self.open_db().context("In list.")?;
        let uid = Self::get_effective_uid(uid).context("In list.")?;
        let mut result = self.list_legacy(uid).context("In list.")?;
        result.append(&mut db.list(uid).context("In list: Trying to get list of entries.")?);
        result = result.into_iter().filter(|s| s.starts_with(prefix)).collect();
        result.sort_unstable();
        result.dedup();
        Ok(result)
    }

    fn init_shelf(&self, path: &Path) {
        let mut db_path = path.to_path_buf();
        self.async_task.queue_hi(move |shelf| {
            let legacy_loader = LegacyBlobLoader::new(&db_path);
            db_path.push(Self::LEGACY_KEYSTORE_FILE_NAME);

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
                .list_legacy_keystore_entries_for_uid(uid)
                .context("Trying to list legacy keystore entries.")
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
                Self::migrate_one_legacy_entry(uid, &alias, &state.legacy_loader, &mut db)
                    .context("Trying to migrate legacy keystore entries.")?;
            if migrated {
                state.recently_imported.insert((uid, alias));
            }
            Ok(migrated)
        })
        .context("In get_legacy.")
    }

    fn bulk_delete_uid(&self, uid: u32) -> Result<()> {
        self.do_serialized(move |state| {
            let entries = state
                .legacy_loader
                .list_legacy_keystore_entries_for_uid(uid)
                .context("In bulk_delete_uid: Trying to list entries.")?;
            for alias in entries.iter() {
                if let Err(e) = state.legacy_loader.remove_legacy_keystore_entry(uid, alias) {
                    log::warn!("In bulk_delete_uid: Failed to delete legacy entry. {:?}", e);
                }
            }
            Ok(())
        })
    }

    fn bulk_delete_user(&self, user_id: u32) -> Result<()> {
        self.do_serialized(move |state| {
            let entries = state
                .legacy_loader
                .list_legacy_keystore_entries_for_user(user_id)
                .context("In bulk_delete_user: Trying to list entries.")?;
            for (uid, entries) in entries.iter() {
                for alias in entries.iter() {
                    if let Err(e) = state.legacy_loader.remove_legacy_keystore_entry(*uid, alias) {
                        log::warn!("In bulk_delete_user: Failed to delete legacy entry. {:?}", e);
                    }
                }
            }
            Ok(())
        })
    }

    fn migrate_one_legacy_entry(
        uid: u32,
        alias: &str,
        legacy_loader: &LegacyBlobLoader,
        db: &mut DB,
    ) -> Result<bool> {
        let blob = legacy_loader
            .read_legacy_keystore_entry(uid, alias)
            .context("In migrate_one_legacy_entry: Trying to read legacy keystore entry.")?;
        if let Some(entry) = blob {
            db.put(uid, alias, &entry)
                .context("In migrate_one_legacy_entry: Trying to insert entry into DB.")?;
            legacy_loader
                .remove_legacy_keystore_entry(uid, alias)
                .context("In migrate_one_legacy_entry: Trying to delete legacy keystore entry.")?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

struct LegacyKeystoreService {
    legacy_keystore: Arc<LegacyKeystore>,
}

impl binder::Interface for LegacyKeystoreService {}

impl ILegacyKeystore for LegacyKeystoreService {
    fn get(&self, alias: &str, uid: i32) -> BinderResult<Vec<u8>> {
        let _wp = wd::watch_millis("ILegacyKeystore::get", 500);
        map_or_log_err(self.legacy_keystore.get(alias, uid), Ok)
    }
    fn put(&self, alias: &str, uid: i32, entry: &[u8]) -> BinderResult<()> {
        let _wp = wd::watch_millis("ILegacyKeystore::put", 500);
        map_or_log_err(self.legacy_keystore.put(alias, uid, entry), Ok)
    }
    fn remove(&self, alias: &str, uid: i32) -> BinderResult<()> {
        let _wp = wd::watch_millis("ILegacyKeystore::remove", 500);
        map_or_log_err(self.legacy_keystore.remove(alias, uid), Ok)
    }
    fn list(&self, prefix: &str, uid: i32) -> BinderResult<Vec<String>> {
        let _wp = wd::watch_millis("ILegacyKeystore::list", 500);
        map_or_log_err(self.legacy_keystore.list(prefix, uid), Ok)
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
    fn test_entry_db() {
        let test_dir = TempDir::new("entrydb_test_").expect("Failed to create temp dir.");
        let mut db = DB::new(&test_dir.build().push(LegacyKeystore::LEGACY_KEYSTORE_FILE_NAME))
            .expect("Failed to open database.");

        // Insert three entries for owner 2.
        db.put(2, "test1", TEST_BLOB1).expect("Failed to insert test1.");
        db.put(2, "test2", TEST_BLOB2).expect("Failed to insert test2.");
        db.put(2, "test3", TEST_BLOB3).expect("Failed to insert test3.");

        // Check list returns all inserted aliases.
        assert_eq!(
            vec!["test1".to_string(), "test2".to_string(), "test3".to_string(),],
            db.list(2).expect("Failed to list entries.")
        );

        // There should be no entries for owner 1.
        assert_eq!(Vec::<String>::new(), db.list(1).expect("Failed to list entries."));

        // Check the content of the three entries.
        assert_eq!(Some(TEST_BLOB1), db.get(2, "test1").expect("Failed to get entry.").as_deref());
        assert_eq!(Some(TEST_BLOB2), db.get(2, "test2").expect("Failed to get entry.").as_deref());
        assert_eq!(Some(TEST_BLOB3), db.get(2, "test3").expect("Failed to get entry.").as_deref());

        // Remove test2 and check and check that it is no longer retrievable.
        assert!(db.remove(2, "test2").expect("Failed to remove entry."));
        assert!(db.get(2, "test2").expect("Failed to get entry.").is_none());

        // test2 should now no longer be in the list.
        assert_eq!(
            vec!["test1".to_string(), "test3".to_string(),],
            db.list(2).expect("Failed to list entries.")
        );

        // Put on existing alias replaces it.
        // Verify test1 is TEST_BLOB1.
        assert_eq!(Some(TEST_BLOB1), db.get(2, "test1").expect("Failed to get entry.").as_deref());
        db.put(2, "test1", TEST_BLOB4).expect("Failed to replace test1.");
        // Verify test1 is TEST_BLOB4.
        assert_eq!(Some(TEST_BLOB4), db.get(2, "test1").expect("Failed to get entry.").as_deref());
    }

    #[test]
    fn test_delete_uid() {
        let test_dir = TempDir::new("test_delete_uid_").expect("Failed to create temp dir.");
        let mut db = DB::new(&test_dir.build().push(LegacyKeystore::LEGACY_KEYSTORE_FILE_NAME))
            .expect("Failed to open database.");

        // Insert three entries for owner 2.
        db.put(2, "test1", TEST_BLOB1).expect("Failed to insert test1.");
        db.put(2, "test2", TEST_BLOB2).expect("Failed to insert test2.");
        db.put(3, "test3", TEST_BLOB3).expect("Failed to insert test3.");

        db.remove_uid(2).expect("Failed to remove uid 2");

        assert_eq!(Vec::<String>::new(), db.list(2).expect("Failed to list entries."));

        assert_eq!(vec!["test3".to_string(),], db.list(3).expect("Failed to list entries."));
    }

    #[test]
    fn test_delete_user() {
        let test_dir = TempDir::new("test_delete_user_").expect("Failed to create temp dir.");
        let mut db = DB::new(&test_dir.build().push(LegacyKeystore::LEGACY_KEYSTORE_FILE_NAME))
            .expect("Failed to open database.");

        // Insert three entries for owner 2.
        db.put(2 + 2 * cutils_bindgen::AID_USER_OFFSET, "test1", TEST_BLOB1)
            .expect("Failed to insert test1.");
        db.put(4 + 2 * cutils_bindgen::AID_USER_OFFSET, "test2", TEST_BLOB2)
            .expect("Failed to insert test2.");
        db.put(3, "test3", TEST_BLOB3).expect("Failed to insert test3.");

        db.remove_user(2).expect("Failed to remove user 2");

        assert_eq!(
            Vec::<String>::new(),
            db.list(2 + 2 * cutils_bindgen::AID_USER_OFFSET).expect("Failed to list entries.")
        );

        assert_eq!(
            Vec::<String>::new(),
            db.list(4 + 2 * cutils_bindgen::AID_USER_OFFSET).expect("Failed to list entries.")
        );

        assert_eq!(vec!["test3".to_string(),], db.list(3).expect("Failed to list entries."));
    }

    #[test]
    fn concurrent_legacy_keystore_entry_test() -> Result<()> {
        let temp_dir = Arc::new(
            TempDir::new("concurrent_legacy_keystore_entry_test_")
                .expect("Failed to create temp dir."),
        );

        let db_path = temp_dir.build().push(LegacyKeystore::LEGACY_KEYSTORE_FILE_NAME).to_owned();

        let test_begin = Instant::now();

        let mut db = DB::new(&db_path).expect("Failed to open database.");
        const ENTRY_COUNT: u32 = 5000u32;
        const ENTRY_DB_COUNT: u32 = 5000u32;

        let mut actual_entry_count = ENTRY_COUNT;
        // First insert ENTRY_COUNT entries.
        for count in 0..ENTRY_COUNT {
            if Instant::now().duration_since(test_begin) >= Duration::from_secs(15) {
                actual_entry_count = count;
                break;
            }
            let alias = format!("test_alias_{}", count);
            db.put(1, &alias, TEST_BLOB1).expect("Failed to add entry (1).");
        }

        // Insert more keys from a different thread and into a different namespace.
        let db_path1 = db_path.clone();
        let handle1 = thread::spawn(move || {
            let mut db = DB::new(&db_path1).expect("Failed to open database.");

            for count in 0..actual_entry_count {
                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                    return;
                }
                let alias = format!("test_alias_{}", count);
                db.put(2, &alias, TEST_BLOB2).expect("Failed to add entry (2).");
            }

            // Then delete them again.
            for count in 0..actual_entry_count {
                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                    return;
                }
                let alias = format!("test_alias_{}", count);
                db.remove(2, &alias).expect("Remove Failed (2).");
            }
        });

        // And start deleting the first set of entries.
        let db_path2 = db_path.clone();
        let handle2 = thread::spawn(move || {
            let mut db = DB::new(&db_path2).expect("Failed to open database.");

            for count in 0..actual_entry_count {
                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                    return;
                }
                let alias = format!("test_alias_{}", count);
                db.remove(1, &alias).expect("Remove Failed (1)).");
            }
        });

        // While a lot of inserting and deleting is going on we have to open database connections
        // successfully and then insert and delete a specific entry.
        let db_path3 = db_path.clone();
        let handle3 = thread::spawn(move || {
            for _count in 0..ENTRY_DB_COUNT {
                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                    return;
                }
                let mut db = DB::new(&db_path3).expect("Failed to open database.");

                db.put(3, &TEST_ALIAS, TEST_BLOB3).expect("Failed to add entry (3).");

                db.remove(3, &TEST_ALIAS).expect("Remove failed (3).");
            }
        });

        // While thread 3 is inserting and deleting TEST_ALIAS, we try to get the alias.
        // This may yield an entry or none, but it must not fail.
        let handle4 = thread::spawn(move || {
            for _count in 0..ENTRY_DB_COUNT {
                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                    return;
                }
                let mut db = DB::new(&db_path).expect("Failed to open database.");

                // This may return Some or None but it must not fail.
                db.get(3, &TEST_ALIAS).expect("Failed to get entry (4).");
            }
        });

        handle1.join().expect("Thread 1 panicked.");
        handle2.join().expect("Thread 2 panicked.");
        handle3.join().expect("Thread 3 panicked.");
        handle4.join().expect("Thread 4 panicked.");

        Ok(())
    }
}
