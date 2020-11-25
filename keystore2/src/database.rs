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

//! This is the Keystore 2.0 database module.
//! The database module provides a connection to the backing SQLite store.
//! We have two databases one for persistent key blob storage and one for
//! items that have a per boot life cycle.
//!
//! ## Persistent database
//! The persistent database has tables for key blobs. They are organized
//! as follows:
//! The `keyentry` table is the primary table for key entries. It is
//! accompanied by two tables for blobs and parameters.
//! Each key entry occupies exactly one row in the `keyentry` table and
//! zero or more rows in the tables `blobentry` and `keyparameter`.
//!
//! ## Per boot database
//! The per boot database stores items with a per boot lifecycle.
//! Currently, there is only the `grant` table in this database.
//! Grants are references to a key that can be used to access a key by
//! clients that don't own that key. Grants can only be created by the
//! owner of a key. And only certain components can create grants.
//! This is governed by SEPolicy.
//!
//! ## Access control
//! Some database functions that load keys or create grants perform
//! access control. This is because in some cases access control
//! can only be performed after some information about the designated
//! key was loaded from the database. To decouple the permission checks
//! from the database module these functions take permission check
//! callbacks.

use crate::error::{Error as KsError, ResponseCode};
use crate::key_parameter::{KeyParameter, SqlField, Tag};
use crate::permission::KeyPermSet;
use anyhow::{anyhow, Context, Result};

use android_hardware_keymint::aidl::android::hardware::keymint::SecurityLevel::SecurityLevel;
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor,
};

use lazy_static::lazy_static;
#[cfg(not(test))]
use rand::prelude::random;
use rusqlite::{
    params, types::FromSql, types::FromSqlResult, types::ToSqlOutput, types::ValueRef, Connection,
    OptionalExtension, Row, Rows, ToSql, Transaction, TransactionBehavior, NO_PARAMS,
};
use std::{
    collections::HashSet,
    sync::{Condvar, Mutex, Once},
};
#[cfg(test)]
use tests::random;

/// Keys have a KeyMint blob component and optional public certificate and
/// certificate chain components.
/// KeyEntryLoadBits is a bitmap that indicates to `KeystoreDB::load_key_entry`
/// which components shall be loaded from the database if present.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyEntryLoadBits(u32);

impl KeyEntryLoadBits {
    /// Indicate to `KeystoreDB::load_key_entry` that no component shall be loaded.
    pub const NONE: KeyEntryLoadBits = Self(0);
    /// Indicate to `KeystoreDB::load_key_entry` that the KeyMint component shall be loaded.
    pub const KM: KeyEntryLoadBits = Self(1);
    /// Indicate to `KeystoreDB::load_key_entry` that the Public components shall be loaded.
    pub const PUBLIC: KeyEntryLoadBits = Self(2);
    /// Indicate to `KeystoreDB::load_key_entry` that both components shall be loaded.
    pub const BOTH: KeyEntryLoadBits = Self(3);

    /// Returns true if this object indicates that the public components shall be loaded.
    pub const fn load_public(&self) -> bool {
        self.0 & Self::PUBLIC.0 != 0
    }

    /// Returns true if the object indicates that the KeyMint component shall be loaded.
    pub const fn load_km(&self) -> bool {
        self.0 & Self::KM.0 != 0
    }
}

lazy_static! {
    static ref KEY_ID_LOCK: KeyIdLockDb = KeyIdLockDb::new();
}

struct KeyIdLockDb {
    locked_keys: Mutex<HashSet<i64>>,
    cond_var: Condvar,
}

/// A locked key. While a guard exists for a given key id, the same key cannot be loaded
/// from the database a second time. Most functions manipulating the key blob database
/// require a KeyIdGuard.
#[derive(Debug)]
pub struct KeyIdGuard(i64);

impl KeyIdLockDb {
    fn new() -> Self {
        Self { locked_keys: Mutex::new(HashSet::new()), cond_var: Condvar::new() }
    }

    /// This function blocks until an exclusive lock for the given key entry id can
    /// be acquired. It returns a guard object, that represents the lifecycle of the
    /// acquired lock.
    pub fn get(&self, key_id: i64) -> KeyIdGuard {
        let mut locked_keys = self.locked_keys.lock().unwrap();
        while locked_keys.contains(&key_id) {
            locked_keys = self.cond_var.wait(locked_keys).unwrap();
        }
        locked_keys.insert(key_id);
        KeyIdGuard(key_id)
    }

    /// This function attempts to acquire an exclusive lock on a given key id. If the
    /// given key id is already taken the function returns None immediately. If a lock
    /// can be acquired this function returns a guard object, that represents the
    /// lifecycle of the acquired lock.
    pub fn try_get(&self, key_id: i64) -> Option<KeyIdGuard> {
        let mut locked_keys = self.locked_keys.lock().unwrap();
        if locked_keys.insert(key_id) {
            Some(KeyIdGuard(key_id))
        } else {
            None
        }
    }
}

impl KeyIdGuard {
    /// Get the numeric key id of the locked key.
    pub fn id(&self) -> i64 {
        self.0
    }
}

impl Drop for KeyIdGuard {
    fn drop(&mut self) {
        let mut locked_keys = KEY_ID_LOCK.locked_keys.lock().unwrap();
        locked_keys.remove(&self.0);
        drop(locked_keys);
        KEY_ID_LOCK.cond_var.notify_all();
    }
}

/// This type represents a Keystore 2.0 key entry.
/// An entry has a unique `id` by which it can be found in the database.
/// It has a security level field, key parameters, and three optional fields
/// for the KeyMint blob, public certificate and a public certificate chain.
#[derive(Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyEntry {
    id: i64,
    km_blob: Option<Vec<u8>>,
    cert: Option<Vec<u8>>,
    cert_chain: Option<Vec<u8>>,
    sec_level: SecurityLevel,
    parameters: Vec<KeyParameter>,
}

impl KeyEntry {
    /// Returns the unique id of the Key entry.
    pub fn id(&self) -> i64 {
        self.id
    }
    /// Exposes the optional KeyMint blob.
    pub fn km_blob(&self) -> &Option<Vec<u8>> {
        &self.km_blob
    }
    /// Extracts the Optional KeyMint blob.
    pub fn take_km_blob(&mut self) -> Option<Vec<u8>> {
        self.km_blob.take()
    }
    /// Exposes the optional public certificate.
    pub fn cert(&self) -> &Option<Vec<u8>> {
        &self.cert
    }
    /// Extracts the optional public certificate.
    pub fn take_cert(&mut self) -> Option<Vec<u8>> {
        self.cert.take()
    }
    /// Exposes the optional public certificate chain.
    pub fn cert_chain(&self) -> &Option<Vec<u8>> {
        &self.cert_chain
    }
    /// Extracts the optional public certificate_chain.
    pub fn take_cert_chain(&mut self) -> Option<Vec<u8>> {
        self.cert_chain.take()
    }
    /// Returns the security level of the key entry.
    pub fn sec_level(&self) -> SecurityLevel {
        self.sec_level
    }
    /// Exposes the key parameters of this key entry.
    pub fn key_parameters(&self) -> &Vec<KeyParameter> {
        &self.parameters
    }
    /// Consumes this key entry and extracts the keyparameters from it.
    pub fn into_key_parameters(self) -> Vec<KeyParameter> {
        self.parameters
    }
}

/// Indicates the sub component of a key entry for persistent storage.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SubComponentType(u32);
impl SubComponentType {
    /// Persistent identifier for a KeyMint blob.
    pub const KM_BLOB: SubComponentType = Self(0);
    /// Persistent identifier for a certificate blob.
    pub const CERT: SubComponentType = Self(1);
    /// Persistent identifier for a certificate chain blob.
    pub const CERT_CHAIN: SubComponentType = Self(2);
}

impl ToSql for SubComponentType {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        self.0.to_sql()
    }
}

impl FromSql for SubComponentType {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        Ok(Self(u32::column_result(value)?))
    }
}

static INIT_TABLES: Once = Once::new();

/// KeystoreDB wraps a connection to an SQLite database and tracks its
/// ownership. It also implements all of Keystore 2.0's database functionality.
pub struct KeystoreDB {
    conn: Connection,
}

impl KeystoreDB {
    /// This will create a new database connection connecting the two
    /// files persistent.sqlite and perboot.sqlite in the current working
    /// directory, which is usually `/data/misc/keystore/`.
    /// It also attempts to initialize all of the tables on the first instantiation
    /// per service startup. KeystoreDB cannot be used by multiple threads.
    /// Each thread should open their own connection using `thread_local!`.
    pub fn new() -> Result<Self> {
        let conn = Self::make_connection("file:persistent.sqlite", "file:perboot.sqlite")?;

        INIT_TABLES.call_once(|| Self::init_tables(&conn).expect("Failed to initialize tables."));
        Ok(Self { conn })
    }

    fn init_tables(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS persistent.keyentry (
                     id INTEGER UNIQUE,
                     creation_date DATETIME,
                     domain INTEGER,
                     namespace INTEGER,
                     alias TEXT);",
            NO_PARAMS,
        )
        .context("Failed to initialize \"keyentry\" table.")?;

        conn.execute(
            "CREATE VIEW IF NOT EXISTS persistent.orphaned AS
                    SELECT id FROM persistent.keyentry WHERE domain IS NULL;",
            NO_PARAMS,
        )
        .context("Failed to initialize \"orphaned\" view")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS persistent.blobentry (
                    id INTEGER PRIMARY KEY,
                    subcomponent_type INTEGER,
                    keyentryid INTEGER,
                    blob BLOB,
                    sec_level INTEGER);",
            NO_PARAMS,
        )
        .context("Failed to initialize \"blobentry\" table.")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS persistent.keyparameter (
                     keyentryid INTEGER,
                     tag INTEGER,
                     data ANY,
                     security_level INTEGER);",
            NO_PARAMS,
        )
        .context("Failed to initialize \"keyparameter\" table.")?;

        // TODO only drop the perboot table if we start up for the first time per boot.
        // Right now this is done once per startup which will lose some information
        // upon a crash.
        // Note: This is no regression with respect to the legacy Keystore.
        conn.execute("DROP TABLE IF EXISTS perboot.grant;", NO_PARAMS)
            .context("Failed to drop perboot.grant table")?;
        conn.execute(
            "CREATE TABLE perboot.grant (
                    id INTEGER UNIQUE,
                    grantee INTEGER,
                    keyentryid INTEGER,
                    access_vector INTEGER);",
            NO_PARAMS,
        )
        .context("Failed to initialize \"grant\" table.")?;

        Ok(())
    }

    fn make_connection(persistent_file: &str, perboot_file: &str) -> Result<Connection> {
        let conn =
            Connection::open_in_memory().context("Failed to initialize SQLite connection.")?;

        conn.execute("ATTACH DATABASE ? as persistent;", params![persistent_file])
            .context("Failed to attach database persistent.")?;
        conn.execute("ATTACH DATABASE ? as perboot;", params![perboot_file])
            .context("Failed to attach database perboot.")?;

        Ok(conn)
    }

    /// Creates a new key entry and allocates a new randomized id for the new key.
    /// The key id gets associated with a domain and namespace but not with an alias.
    /// To complete key generation `rebind_alias` should be called after all of the
    /// key artifacts, i.e., blobs and parameters have been associated with the new
    /// key id. Finalizing with `rebind_alias` makes the creation of a new key entry
    /// atomic even if key generation is not.
    pub fn create_key_entry(&self, domain: Domain, namespace: i64) -> Result<KeyIdGuard> {
        match domain {
            Domain::APP | Domain::SELINUX => {}
            _ => {
                return Err(KsError::sys())
                    .context(format!("Domain {:?} must be either App or SELinux.", domain));
            }
        }
        Ok(KEY_ID_LOCK.get(
            Self::insert_with_retry(|id| {
                self.conn.execute(
                    "INSERT into persistent.keyentry (id, creation_date, domain, namespace, alias)
                     VALUES(?, datetime('now'), ?, ?, NULL);",
                    params![id, domain.0 as u32, namespace],
                )
            })
            .context("In create_key_entry")?,
        ))
    }

    /// Inserts a new blob and associates it with the given key id. Each blob
    /// has a sub component type and a security level.
    /// Each key can have one of each sub component type associated. If more
    /// are added only the most recent can be retrieved, and superseded blobs
    /// will get garbage collected. The security level field of components
    /// other than `SubComponentType::KM_BLOB` are ignored.
    pub fn insert_blob(
        &mut self,
        key_id: &KeyIdGuard,
        sc_type: SubComponentType,
        blob: &[u8],
        sec_level: SecurityLevel,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT into persistent.blobentry (subcomponent_type, keyentryid, blob, sec_level)
                    VALUES (?, ?, ?, ?);",
                params![sc_type, key_id.0, blob, sec_level.0],
            )
            .context("Failed to insert blob.")?;
        Ok(())
    }

    /// Inserts a collection of key parameters into the `persistent.keyparameter` table
    /// and associates them with the given `key_id`.
    pub fn insert_keyparameter<'a>(
        &mut self,
        key_id: &KeyIdGuard,
        params: impl IntoIterator<Item = &'a KeyParameter>,
    ) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare(
                "INSERT into persistent.keyparameter (keyentryid, tag, data, security_level)
                    VALUES (?, ?, ?, ?);",
            )
            .context("In insert_keyparameter: Failed to prepare statement.")?;

        let iter = params.into_iter();
        for p in iter {
            stmt.insert(params![
                key_id.0,
                p.get_tag().0,
                p.key_parameter_value(),
                p.security_level().0
            ])
            .with_context(|| format!("In insert_keyparameter: Failed to insert {:?}", p))?;
        }
        Ok(())
    }

    /// Updates the alias column of the given key id `newid` with the given alias,
    /// and atomically, removes the alias, domain, and namespace from another row
    /// with the same alias-domain-namespace tuple if such row exits.
    pub fn rebind_alias(
        &mut self,
        newid: &KeyIdGuard,
        alias: &str,
        domain: Domain,
        namespace: i64,
    ) -> Result<()> {
        match domain {
            Domain::APP | Domain::SELINUX => {}
            _ => {
                return Err(KsError::sys()).context(format!(
                    "In rebind_alias: Domain {:?} must be either App or SELinux.",
                    domain
                ));
            }
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("In rebind_alias: Failed to initialize transaction.")?;
        tx.execute(
            "UPDATE persistent.keyentry
                 SET alias = NULL, domain = NULL, namespace = NULL
                 WHERE alias = ? AND domain = ? AND namespace = ?;",
            params![alias, domain.0 as u32, namespace],
        )
        .context("In rebind_alias: Failed to rebind existing entry.")?;
        let result = tx
            .execute(
                "UPDATE persistent.keyentry
                    SET alias = ?
                    WHERE id = ? AND domain = ? AND namespace = ?;",
                params![alias, newid.0, domain.0 as u32, namespace],
            )
            .context("In rebind_alias: Failed to set alias.")?;
        if result != 1 {
            // Note that this explicit rollback is not required, as
            // the transaction should rollback if we do not commit it.
            // We leave it here for readability.
            tx.rollback().context("In rebind_alias: Failed to rollback a failed transaction.")?;
            return Err(KsError::sys()).context(format!(
                "In rebind_alias: Expected to update a single entry but instead updated {}.",
                result
            ));
        }
        tx.commit().context("In rebind_alias: Failed to commit transaction.")
    }

    // Helper function loading the key_id given the key descriptor
    // tuple comprising domain, namespace, and alias.
    // Requires a valid transaction.
    fn load_key_entry_id(key: &KeyDescriptor, tx: &Transaction) -> Result<i64> {
        let alias = key
            .alias
            .as_ref()
            .map_or_else(|| Err(KsError::sys()), Ok)
            .context("In load_key_entry_id: Alias must be specified.")?;
        let mut stmt = tx
            .prepare(
                "SELECT id FROM persistent.keyentry
                    WHERE
                    domain = ?
                    AND namespace = ?
                    AND alias = ?;",
            )
            .context("In load_key_entry_id: Failed to select from keyentry table.")?;
        let mut rows = stmt
            .query(params![key.domain.0 as u32, key.nspace, alias])
            .context("In load_key_entry_id: Failed to read from keyentry table.")?;
        Self::with_rows_extract_one(&mut rows, |row| {
            row.map_or_else(|| Err(KsError::Rc(ResponseCode::KEY_NOT_FOUND)), Ok)?
                .get(0)
                .context("Failed to unpack id.")
        })
        .context("In load_key_entry_id.")
    }

    /// This helper function completes the access tuple of a key, which is required
    /// to perform access control. The strategy depends on the `domain` field in the
    /// key descriptor.
    /// * Domain::SELINUX: The access tuple is complete and this function only loads
    ///       the key_id for further processing.
    /// * Domain::APP: Like Domain::SELINUX, but the tuple is completed by `caller_uid`
    ///       which serves as the namespace.
    /// * Domain::GRANT: The grant table is queried for the `key_id` and the
    ///       `access_vector`.
    /// * Domain::KEY_ID: The keyentry table is queried for the owning `domain` and
    ///       `namespace`.
    /// In each case the information returned is sufficient to perform the access
    /// check and the key id can be used to load further key artifacts.
    fn load_access_tuple(
        tx: &Transaction,
        key: KeyDescriptor,
        caller_uid: u32,
    ) -> Result<(i64, KeyDescriptor, Option<KeyPermSet>)> {
        match key.domain {
            // Domain App or SELinux. In this case we load the key_id from
            // the keyentry database for further loading of key components.
            // We already have the full access tuple to perform access control.
            // The only distinction is that we use the caller_uid instead
            // of the caller supplied namespace if the domain field is
            // Domain::APP.
            Domain::APP | Domain::SELINUX => {
                let mut access_key = key;
                if access_key.domain == Domain::APP {
                    access_key.nspace = caller_uid as i64;
                }
                let key_id = Self::load_key_entry_id(&access_key, &tx)
                    .with_context(|| format!("With key.domain = {:?}.", access_key.domain))?;

                Ok((key_id, access_key, None))
            }

            // Domain::GRANT. In this case we load the key_id and the access_vector
            // from the grant table.
            Domain::GRANT => {
                let mut stmt = tx
                    .prepare(
                        "SELECT keyentryid, access_vector FROM perboot.grant
                            WHERE grantee = ? AND id = ?;",
                    )
                    .context("Domain::GRANT prepare statement failed")?;
                let mut rows = stmt
                    .query(params![caller_uid as i64, key.nspace])
                    .context("Domain:Grant: query failed.")?;
                let (key_id, access_vector): (i64, i32) =
                    Self::with_rows_extract_one(&mut rows, |row| {
                        let r =
                            row.map_or_else(|| Err(KsError::Rc(ResponseCode::KEY_NOT_FOUND)), Ok)?;
                        Ok((
                            r.get(0).context("Failed to unpack key_id.")?,
                            r.get(1).context("Failed to unpack access_vector.")?,
                        ))
                    })
                    .context("Domain::GRANT.")?;
                Ok((key_id, key, Some(access_vector.into())))
            }

            // Domain::KEY_ID. In this case we load the domain and namespace from the
            // keyentry database because we need them for access control.
            Domain::KEY_ID => {
                let mut stmt = tx
                    .prepare(
                        "SELECT domain, namespace FROM persistent.keyentry
                            WHERE
                            id = ?;",
                    )
                    .context("Domain::KEY_ID: prepare statement failed")?;
                let mut rows =
                    stmt.query(params![key.nspace]).context("Domain::KEY_ID: query failed.")?;
                let (domain, namespace): (Domain, i64) =
                    Self::with_rows_extract_one(&mut rows, |row| {
                        let r =
                            row.map_or_else(|| Err(KsError::Rc(ResponseCode::KEY_NOT_FOUND)), Ok)?;
                        Ok((
                            Domain(r.get(0).context("Failed to unpack domain.")?),
                            r.get(1).context("Failed to unpack namespace.")?,
                        ))
                    })
                    .context("Domain::KEY_ID.")?;
                let key_id = key.nspace;
                let mut access_key = key;
                access_key.domain = domain;
                access_key.nspace = namespace;

                Ok((key_id, access_key, None))
            }
            _ => Err(anyhow!(KsError::sys())),
        }
    }

    fn load_blob_components(
        key_id: i64,
        load_bits: KeyEntryLoadBits,
        tx: &Transaction,
    ) -> Result<(SecurityLevel, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> {
        let mut stmt = tx
            .prepare(
                "SELECT MAX(id), sec_level, subcomponent_type, blob FROM persistent.blobentry
                    WHERE keyentryid = ? GROUP BY subcomponent_type;",
            )
            .context("In load_blob_components: prepare statement failed.")?;

        let mut rows =
            stmt.query(params![key_id]).context("In load_blob_components: query failed.")?;

        let mut sec_level: SecurityLevel = Default::default();
        let mut km_blob: Option<Vec<u8>> = None;
        let mut cert_blob: Option<Vec<u8>> = None;
        let mut cert_chain_blob: Option<Vec<u8>> = None;
        Self::with_rows_extract_all(&mut rows, |row| {
            let sub_type: SubComponentType =
                row.get(2).context("Failed to extract subcomponent_type.")?;
            match (sub_type, load_bits.load_public()) {
                (SubComponentType::KM_BLOB, _) => {
                    sec_level =
                        SecurityLevel(row.get(1).context("Failed to extract security level.")?);
                    if load_bits.load_km() {
                        km_blob = Some(row.get(3).context("Failed to extract KM blob.")?);
                    }
                }
                (SubComponentType::CERT, true) => {
                    cert_blob =
                        Some(row.get(3).context("Failed to extract public certificate blob.")?);
                }
                (SubComponentType::CERT_CHAIN, true) => {
                    cert_chain_blob =
                        Some(row.get(3).context("Failed to extract certificate chain blob.")?);
                }
                (SubComponentType::CERT, _) | (SubComponentType::CERT_CHAIN, _) => {}
                _ => Err(KsError::sys()).context("Unknown subcomponent type.")?,
            }
            Ok(())
        })
        .context("In load_blob_components.")?;

        Ok((sec_level, km_blob, cert_blob, cert_chain_blob))
    }

    fn load_key_parameters(key_id: i64, tx: &Transaction) -> Result<Vec<KeyParameter>> {
        let mut stmt = tx
            .prepare(
                "SELECT tag, data, security_level from persistent.keyparameter
                    WHERE keyentryid = ?;",
            )
            .context("In load_key_parameters: prepare statement failed.")?;

        let mut parameters: Vec<KeyParameter> = Vec::new();

        let mut rows =
            stmt.query(params![key_id]).context("In load_key_parameters: query failed.")?;
        Self::with_rows_extract_all(&mut rows, |row| {
            let tag = Tag(row.get(0).context("Failed to read tag.")?);
            let sec_level = SecurityLevel(row.get(2).context("Failed to read sec_level.")?);
            parameters.push(
                KeyParameter::new_from_sql(tag, &SqlField::new(1, &row), sec_level)
                    .context("Failed to read KeyParameter.")?,
            );
            Ok(())
        })
        .context("In load_key_parameters.")?;

        Ok(parameters)
    }

    /// Load a key entry by the given key descriptor.
    /// It uses the `check_permission` callback to verify if the access is allowed
    /// given the key access tuple read from the database using `load_access_tuple`.
    /// With `load_bits` the caller may specify which blobs shall be loaded from
    /// the blob database.
    pub fn load_key_entry(
        &mut self,
        key: KeyDescriptor,
        load_bits: KeyEntryLoadBits,
        caller_uid: u32,
        check_permission: impl FnOnce(&KeyDescriptor, Option<KeyPermSet>) -> Result<()>,
    ) -> Result<(KeyIdGuard, KeyEntry)> {
        // KEY ID LOCK 1/2
        // If we got a key descriptor with a key id we can get the lock right away.
        // Otherwise we have to defer it until we know the key id.
        let key_id_guard = match key.domain {
            Domain::KEY_ID => Some(KEY_ID_LOCK.get(key.nspace)),
            _ => None,
        };

        let tx = self
            .conn
            .unchecked_transaction()
            .context("In load_key_entry: Failed to initialize transaction.")?;

        // Load the key_id and complete the access control tuple.
        let (key_id, access_key_descriptor, access_vector) =
            Self::load_access_tuple(&tx, key, caller_uid).context("In load_key_entry.")?;

        // Perform access control. It is vital that we return here if the permission is denied.
        // So do not touch that '?' at the end.
        check_permission(&access_key_descriptor, access_vector).context("In load_key_entry.")?;

        // KEY ID LOCK 2/2
        // If we did not get a key id lock by now, it was because we got a key descriptor
        // without a key id. At this point we got the key id, so we can try and get a lock.
        // However, we cannot block here, because we are in the middle of the transaction.
        // So first we try to get the lock non blocking. If that fails, we roll back the
        // transaction and block until we get the lock. After we successfully got the lock,
        // we start a new transaction and load the access tuple again.
        //
        // We don't need to perform access control again, because we already established
        // that the caller had access to the given key. But we need to make sure that the
        // key id still exists. So we have to load the key entry by key id this time.
        let (key_id_guard, tx) = match key_id_guard {
            None => match KEY_ID_LOCK.try_get(key_id) {
                None => {
                    // Roll back the transaction.
                    tx.rollback().context("In load_key_entry: Failed to roll back transaction.")?;

                    // Block until we have a key id lock.
                    let key_id_guard = KEY_ID_LOCK.get(key_id);

                    // Create a new transaction.
                    let tx = self.conn.unchecked_transaction().context(
                        "In load_key_entry: Failed to initialize transaction. (deferred key lock)",
                    )?;

                    Self::load_access_tuple(
                        &tx,
                        // This time we have to load the key by the retrieved key id, because the
                        // alias may have been rebound after we rolled back the transaction.
                        KeyDescriptor {
                            domain: Domain::KEY_ID,
                            nspace: key_id,
                            ..Default::default()
                        },
                        caller_uid,
                    )
                    .context("In load_key_entry. (deferred key lock)")?;
                    (key_id_guard, tx)
                }
                Some(l) => (l, tx),
            },
            Some(key_id_guard) => (key_id_guard, tx),
        };

        let (sec_level, km_blob, cert_blob, cert_chain_blob) =
            Self::load_blob_components(key_id_guard.id(), load_bits, &tx)
                .context("In load_key_entry.")?;

        let parameters =
            Self::load_key_parameters(key_id_guard.id(), &tx).context("In load_key_entry.")?;

        tx.commit().context("In load_key_entry: Failed to commit transaction.")?;

        let key_id = key_id_guard.id();
        Ok((
            key_id_guard,
            KeyEntry {
                id: key_id,
                km_blob,
                cert: cert_blob,
                cert_chain: cert_chain_blob,
                sec_level,
                parameters,
            },
        ))
    }

    /// Adds a grant to the grant table.
    /// Like `load_key_entry` this function loads the access tuple before
    /// it uses the callback for a permission check. Upon success,
    /// it inserts the `grantee_uid`, `key_id`, and `access_vector` into the
    /// grant table. The new row will have a randomized id, which is used as
    /// grant id in the namespace field of the resulting KeyDescriptor.
    pub fn grant(
        &mut self,
        key: KeyDescriptor,
        caller_uid: u32,
        grantee_uid: u32,
        access_vector: KeyPermSet,
        check_permission: impl FnOnce(&KeyDescriptor, &KeyPermSet) -> Result<()>,
    ) -> Result<KeyDescriptor> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("In grant: Failed to initialize transaction.")?;

        // Load the key_id and complete the access control tuple.
        // We ignore the access vector here because grants cannot be granted.
        // The access vector returned here expresses the permissions the
        // grantee has if key.domain == Domain::GRANT. But this vector
        // cannot include the grant permission by design, so there is no way the
        // subsequent permission check can pass.
        // We could check key.domain == Domain::GRANT and fail early.
        // But even if we load the access tuple by grant here, the permission
        // check denies the attempt to create a grant by grant descriptor.
        let (key_id, access_key_descriptor, _) =
            Self::load_access_tuple(&tx, key, caller_uid).context("In grant")?;

        // Perform access control. It is vital that we return here if the permission
        // was denied. So do not touch that '?' at the end of the line.
        // This permission check checks if the caller has the grant permission
        // for the given key and in addition to all of the permissions
        // expressed in `access_vector`.
        check_permission(&access_key_descriptor, &access_vector)
            .context("In grant: check_permission failed.")?;

        let grant_id = if let Some(grant_id) = tx
            .query_row(
                "SELECT id FROM perboot.grant
                WHERE keyentryid = ? AND grantee = ?;",
                params![key_id, grantee_uid],
                |row| row.get(0),
            )
            .optional()
            .context("In grant: Failed get optional existing grant id.")?
        {
            tx.execute(
                "UPDATE perboot.grant
                    SET access_vector = ?
                    WHERE id = ?;",
                params![i32::from(access_vector), grant_id],
            )
            .context("In grant: Failed to update existing grant.")?;
            grant_id
        } else {
            Self::insert_with_retry(|id| {
                tx.execute(
                    "INSERT INTO perboot.grant (id, grantee, keyentryid, access_vector)
                        VALUES (?, ?, ?, ?);",
                    params![id, grantee_uid, key_id, i32::from(access_vector)],
                )
            })
            .context("In grant")?
        };
        tx.commit().context("In grant: failed to commit transaction.")?;

        Ok(KeyDescriptor { domain: Domain::GRANT, nspace: grant_id, alias: None, blob: None })
    }

    /// This function checks permissions like `grant` and `load_key_entry`
    /// before removing a grant from the grant table.
    pub fn ungrant(
        &mut self,
        key: KeyDescriptor,
        caller_uid: u32,
        grantee_uid: u32,
        check_permission: impl FnOnce(&KeyDescriptor) -> Result<()>,
    ) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("In ungrant: Failed to initialize transaction.")?;

        // Load the key_id and complete the access control tuple.
        // We ignore the access vector here because grants cannot be granted.
        let (key_id, access_key_descriptor, _) =
            Self::load_access_tuple(&tx, key, caller_uid).context("In ungrant.")?;

        // Perform access control. We must return here if the permission
        // was denied. So do not touch the '?' at the end of this line.
        check_permission(&access_key_descriptor).context("In grant: check_permission failed.")?;

        tx.execute(
            "DELETE FROM perboot.grant
                WHERE keyentryid = ? AND grantee = ?;",
            params![key_id, grantee_uid],
        )
        .context("Failed to delete grant.")?;

        tx.commit().context("In ungrant: failed to commit transaction.")?;

        Ok(())
    }

    // Generates a random id and passes it to the given function, which will
    // try to insert it into a database.  If that insertion fails, retry;
    // otherwise return the id.
    fn insert_with_retry(inserter: impl Fn(i64) -> rusqlite::Result<usize>) -> Result<i64> {
        loop {
            let newid: i64 = random();
            match inserter(newid) {
                // If the id already existed, try again.
                Err(rusqlite::Error::SqliteFailure(
                    libsqlite3_sys::Error {
                        code: libsqlite3_sys::ErrorCode::ConstraintViolation,
                        extended_code: libsqlite3_sys::SQLITE_CONSTRAINT_UNIQUE,
                    },
                    _,
                )) => (),
                Err(e) => {
                    return Err(e).context("In insert_with_retry: failed to insert into database.")
                }
                _ => return Ok(newid),
            }
        }
    }

    // Takes Rows as returned by a query call on prepared statement.
    // Extracts exactly one row with the `row_extractor` and fails if more
    // rows are available.
    // If no row was found, `None` is passed to the `row_extractor`.
    // This allows the row extractor to decide on an error condition or
    // a different default behavior.
    fn with_rows_extract_one<'a, T, F>(rows: &mut Rows<'a>, row_extractor: F) -> Result<T>
    where
        F: FnOnce(Option<&Row<'a>>) -> Result<T>,
    {
        let result =
            row_extractor(rows.next().context("with_rows_extract_one: Failed to unpack row.")?);

        rows.next()
            .context("In with_rows_extract_one: Failed to unpack unexpected row.")?
            .map_or_else(|| Ok(()), |_| Err(KsError::sys()))
            .context("In with_rows_extract_one: Unexpected row.")?;

        result
    }

    fn with_rows_extract_all<'a, F>(rows: &mut Rows<'a>, mut row_extractor: F) -> Result<()>
    where
        F: FnMut(&Row<'a>) -> Result<()>,
    {
        loop {
            match rows.next().context("In with_rows_extract_all: Failed to unpack row")? {
                Some(row) => {
                    row_extractor(&row).context("In with_rows_extract_all.")?;
                }
                None => break Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::key_parameter::{
        Algorithm, BlockMode, Digest, EcCurve, HardwareAuthenticatorType, KeyOrigin, KeyParameter,
        KeyParameterValue, KeyPurpose, PaddingMode, SecurityLevel,
    };
    use crate::key_perm_set;
    use crate::permission::{KeyPerm, KeyPermSet};
    use rusqlite::NO_PARAMS;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Arc;
    use std::thread;

    static PERSISTENT_TEST_SQL: &str = "/data/local/tmp/persistent.sqlite";
    static PERBOOT_TEST_SQL: &str = "/data/local/tmp/perboot.sqlite";

    fn new_test_db() -> Result<KeystoreDB> {
        let conn = KeystoreDB::make_connection("file::memory:", "file::memory:")?;

        KeystoreDB::init_tables(&conn).context("Failed to initialize tables.")?;
        Ok(KeystoreDB { conn })
    }

    fn new_test_db_with_persistent_file() -> Result<KeystoreDB> {
        let conn = KeystoreDB::make_connection(PERSISTENT_TEST_SQL, PERBOOT_TEST_SQL)?;

        KeystoreDB::init_tables(&conn).context("Failed to initialize tables.")?;
        Ok(KeystoreDB { conn })
    }

    // Ensure that we're using the "injected" random function, not the real one.
    #[test]
    fn test_mocked_random() {
        let rand1 = random();
        let rand2 = random();
        let rand3 = random();
        if rand1 == rand2 {
            assert_eq!(rand2 + 1, rand3);
        } else {
            assert_eq!(rand1 + 1, rand2);
            assert_eq!(rand2, rand3);
        }
    }

    // Test that we have the correct tables.
    #[test]
    fn test_tables() -> Result<()> {
        let db = new_test_db()?;
        let tables = db
            .conn
            .prepare("SELECT name from persistent.sqlite_master WHERE type='table' ORDER BY name;")?
            .query_map(params![], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        assert_eq!(tables.len(), 3);
        assert_eq!(tables[0], "blobentry");
        assert_eq!(tables[1], "keyentry");
        assert_eq!(tables[2], "keyparameter");
        let tables = db
            .conn
            .prepare("SELECT name from perboot.sqlite_master WHERE type='table' ORDER BY name;")?
            .query_map(params![], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0], "grant");
        Ok(())
    }

    #[test]
    fn test_no_persistence_for_tests() -> Result<()> {
        let db = new_test_db()?;

        db.create_key_entry(Domain::APP, 100)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 1);
        let db = new_test_db()?;

        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 0);
        Ok(())
    }

    #[test]
    fn test_persistence_for_files() -> Result<()> {
        let _file_guard_persistent = TempFile { filename: PERSISTENT_TEST_SQL };
        let _file_guard_perboot = TempFile { filename: PERBOOT_TEST_SQL };
        let db = new_test_db_with_persistent_file()?;

        db.create_key_entry(Domain::APP, 100)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 1);
        let db = new_test_db_with_persistent_file()?;

        let entries_new = get_keyentry(&db)?;
        assert_eq!(entries, entries_new);
        Ok(())
    }

    #[test]
    fn test_create_key_entry() -> Result<()> {
        fn extractor(ke: &KeyEntryRow) -> (Domain, i64, Option<&str>) {
            (ke.domain.unwrap(), ke.namespace.unwrap(), ke.alias.as_deref())
        }

        let db = new_test_db()?;

        db.create_key_entry(Domain::APP, 100)?;
        db.create_key_entry(Domain::SELINUX, 101)?;

        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(extractor(&entries[0]), (Domain::APP, 100, None));
        assert_eq!(extractor(&entries[1]), (Domain::SELINUX, 101, None));

        // Test that we must pass in a valid Domain.
        check_result_is_error_containing_string(
            db.create_key_entry(Domain::GRANT, 102),
            "Domain Domain(1) must be either App or SELinux.",
        );
        check_result_is_error_containing_string(
            db.create_key_entry(Domain::BLOB, 103),
            "Domain Domain(3) must be either App or SELinux.",
        );
        check_result_is_error_containing_string(
            db.create_key_entry(Domain::KEY_ID, 104),
            "Domain Domain(4) must be either App or SELinux.",
        );

        Ok(())
    }

    #[test]
    fn test_rebind_alias() -> Result<()> {
        fn extractor(ke: &KeyEntryRow) -> (Option<Domain>, Option<i64>, Option<&str>) {
            (ke.domain, ke.namespace, ke.alias.as_deref())
        }

        let mut db = new_test_db()?;
        db.create_key_entry(Domain::APP, 42)?;
        db.create_key_entry(Domain::APP, 42)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(extractor(&entries[0]), (Some(Domain::APP), Some(42), None));
        assert_eq!(extractor(&entries[1]), (Some(Domain::APP), Some(42), None));

        // Test that the first call to rebind_alias sets the alias.
        db.rebind_alias(&KEY_ID_LOCK.get(entries[0].id), "foo", Domain::APP, 42)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(extractor(&entries[0]), (Some(Domain::APP), Some(42), Some("foo")));
        assert_eq!(extractor(&entries[1]), (Some(Domain::APP), Some(42), None));

        // Test that the second call to rebind_alias also empties the old one.
        db.rebind_alias(&KEY_ID_LOCK.get(entries[1].id), "foo", Domain::APP, 42)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(extractor(&entries[0]), (None, None, None));
        assert_eq!(extractor(&entries[1]), (Some(Domain::APP), Some(42), Some("foo")));

        // Test that we must pass in a valid Domain.
        check_result_is_error_containing_string(
            db.rebind_alias(&KEY_ID_LOCK.get(0), "foo", Domain::GRANT, 42),
            "Domain Domain(1) must be either App or SELinux.",
        );
        check_result_is_error_containing_string(
            db.rebind_alias(&KEY_ID_LOCK.get(0), "foo", Domain::BLOB, 42),
            "Domain Domain(3) must be either App or SELinux.",
        );
        check_result_is_error_containing_string(
            db.rebind_alias(&KEY_ID_LOCK.get(0), "foo", Domain::KEY_ID, 42),
            "Domain Domain(4) must be either App or SELinux.",
        );

        // Test that we correctly handle setting an alias for something that does not exist.
        check_result_is_error_containing_string(
            db.rebind_alias(&KEY_ID_LOCK.get(0), "foo", Domain::SELINUX, 42),
            "Expected to update a single entry but instead updated 0",
        );
        // Test that we correctly abort the transaction in this case.
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(extractor(&entries[0]), (None, None, None));
        assert_eq!(extractor(&entries[1]), (Some(Domain::APP), Some(42), Some("foo")));

        Ok(())
    }

    #[test]
    fn test_grant_ungrant() -> Result<()> {
        const CALLER_UID: u32 = 15;
        const GRANTEE_UID: u32 = 12;
        const SELINUX_NAMESPACE: i64 = 7;

        let mut db = new_test_db()?;
        db.conn.execute(
            "INSERT INTO persistent.keyentry (id, creation_date, domain, namespace, alias)
                VALUES (1, '1980', 0, 15, 'key'), (2, '1980', 2, 7, 'yek');",
            NO_PARAMS,
        )?;
        let app_key = KeyDescriptor {
            domain: super::Domain::APP,
            nspace: 0,
            alias: Some("key".to_string()),
            blob: None,
        };
        const PVEC1: KeyPermSet = key_perm_set![KeyPerm::use_(), KeyPerm::get_info()];
        const PVEC2: KeyPermSet = key_perm_set![KeyPerm::use_()];

        // Reset totally predictable random number generator in case we
        // are not the first test running on this thread.
        reset_random();
        let next_random = 0i64;

        let app_granted_key =
            db.grant(app_key.clone(), CALLER_UID, GRANTEE_UID, PVEC1, |k, a| {
                assert_eq!(*a, PVEC1);
                assert_eq!(
                    *k,
                    KeyDescriptor {
                        domain: super::Domain::APP,
                        // namespace must be set to the caller_uid.
                        nspace: CALLER_UID as i64,
                        alias: Some("key".to_string()),
                        blob: None,
                    }
                );
                Ok(())
            })?;

        assert_eq!(
            app_granted_key,
            KeyDescriptor {
                domain: super::Domain::GRANT,
                // The grantid is next_random due to the mock random number generator.
                nspace: next_random,
                alias: None,
                blob: None,
            }
        );

        let selinux_key = KeyDescriptor {
            domain: super::Domain::SELINUX,
            nspace: SELINUX_NAMESPACE,
            alias: Some("yek".to_string()),
            blob: None,
        };

        let selinux_granted_key =
            db.grant(selinux_key.clone(), CALLER_UID, 12, PVEC1, |k, a| {
                assert_eq!(*a, PVEC1);
                assert_eq!(
                    *k,
                    KeyDescriptor {
                        domain: super::Domain::SELINUX,
                        // namespace must be the supplied SELinux
                        // namespace.
                        nspace: SELINUX_NAMESPACE,
                        alias: Some("yek".to_string()),
                        blob: None,
                    }
                );
                Ok(())
            })?;

        assert_eq!(
            selinux_granted_key,
            KeyDescriptor {
                domain: super::Domain::GRANT,
                // The grantid is next_random + 1 due to the mock random number generator.
                nspace: next_random + 1,
                alias: None,
                blob: None,
            }
        );

        // This should update the existing grant with PVEC2.
        let selinux_granted_key =
            db.grant(selinux_key.clone(), CALLER_UID, 12, PVEC2, |k, a| {
                assert_eq!(*a, PVEC2);
                assert_eq!(
                    *k,
                    KeyDescriptor {
                        domain: super::Domain::SELINUX,
                        // namespace must be the supplied SELinux
                        // namespace.
                        nspace: SELINUX_NAMESPACE,
                        alias: Some("yek".to_string()),
                        blob: None,
                    }
                );
                Ok(())
            })?;

        assert_eq!(
            selinux_granted_key,
            KeyDescriptor {
                domain: super::Domain::GRANT,
                // Same grant id as before. The entry was only updated.
                nspace: next_random + 1,
                alias: None,
                blob: None,
            }
        );

        {
            // Limiting scope of stmt, because it borrows db.
            let mut stmt = db
                .conn
                .prepare("SELECT id, grantee, keyentryid, access_vector FROM perboot.grant;")?;
            let mut rows =
                stmt.query_map::<(i64, u32, i64, KeyPermSet), _, _>(NO_PARAMS, |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        KeyPermSet::from(row.get::<_, i32>(3)?),
                    ))
                })?;

            let r = rows.next().unwrap().unwrap();
            assert_eq!(r, (next_random, GRANTEE_UID, 1, PVEC1));
            let r = rows.next().unwrap().unwrap();
            assert_eq!(r, (next_random + 1, GRANTEE_UID, 2, PVEC2));
            assert!(rows.next().is_none());
        }

        debug_dump_keyentry_table(&mut db)?;
        println!("app_key {:?}", app_key);
        println!("selinux_key {:?}", selinux_key);

        db.ungrant(app_key, CALLER_UID, GRANTEE_UID, |_| Ok(()))?;
        db.ungrant(selinux_key, CALLER_UID, GRANTEE_UID, |_| Ok(()))?;

        Ok(())
    }

    static TEST_KM_BLOB: &[u8] = b"my test blob";
    static TEST_CERT_BLOB: &[u8] = b"my test cert";
    static TEST_CERT_CHAIN_BLOB: &[u8] = b"my test cert_chain";

    #[test]
    fn test_insert_blob() -> Result<()> {
        let mut db = new_test_db()?;
        db.insert_blob(
            &KEY_ID_LOCK.get(1),
            SubComponentType::KM_BLOB,
            TEST_KM_BLOB,
            SecurityLevel::SOFTWARE,
        )?;
        db.insert_blob(
            &KEY_ID_LOCK.get(1),
            SubComponentType::CERT,
            TEST_CERT_BLOB,
            SecurityLevel::TRUSTED_ENVIRONMENT,
        )?;
        db.insert_blob(
            &KEY_ID_LOCK.get(1),
            SubComponentType::CERT_CHAIN,
            TEST_CERT_CHAIN_BLOB,
            SecurityLevel::STRONGBOX,
        )?;

        let mut stmt = db.conn.prepare(
            "SELECT subcomponent_type, keyentryid, blob, sec_level FROM persistent.blobentry
                ORDER BY sec_level ASC;",
        )?;
        let mut rows = stmt
            .query_map::<(SubComponentType, i64, Vec<u8>, i64), _, _>(NO_PARAMS, |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?;
        let r = rows.next().unwrap().unwrap();
        assert_eq!(r, (SubComponentType::KM_BLOB, 1, TEST_KM_BLOB.to_vec(), 0));
        let r = rows.next().unwrap().unwrap();
        assert_eq!(r, (SubComponentType::CERT, 1, TEST_CERT_BLOB.to_vec(), 1));
        let r = rows.next().unwrap().unwrap();
        assert_eq!(r, (SubComponentType::CERT_CHAIN, 1, TEST_CERT_CHAIN_BLOB.to_vec(), 2));

        Ok(())
    }

    static TEST_ALIAS: &str = "my super duper key";

    #[test]
    fn test_insert_and_load_full_keyentry_domain_app() -> Result<()> {
        let mut db = new_test_db()?;
        let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS)
            .context("test_insert_and_load_full_keyentry_domain_app")?
            .0;
        let (_key_guard, key_entry) = db.load_key_entry(
            KeyDescriptor {
                domain: Domain::APP,
                nspace: 0,
                alias: Some(TEST_ALIAS.to_string()),
                blob: None,
            },
            KeyEntryLoadBits::BOTH,
            1,
            |_k, _av| Ok(()),
        )?;
        assert_eq!(
            key_entry,
            KeyEntry {
                id: key_id,
                km_blob: Some(TEST_KM_BLOB.to_vec()),
                cert: Some(TEST_CERT_BLOB.to_vec()),
                cert_chain: Some(TEST_CERT_CHAIN_BLOB.to_vec()),
                sec_level: SecurityLevel::TRUSTED_ENVIRONMENT,
                parameters: make_test_params(),
            }
        );
        Ok(())
    }

    #[test]
    fn test_insert_and_load_full_keyentry_domain_selinux() -> Result<()> {
        let mut db = new_test_db()?;
        let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS)
            .context("test_insert_and_load_full_keyentry_domain_selinux")?
            .0;
        let (_key_guard, key_entry) = db.load_key_entry(
            KeyDescriptor {
                domain: Domain::SELINUX,
                nspace: 1,
                alias: Some(TEST_ALIAS.to_string()),
                blob: None,
            },
            KeyEntryLoadBits::BOTH,
            1,
            |_k, _av| Ok(()),
        )?;
        assert_eq!(
            key_entry,
            KeyEntry {
                id: key_id,
                km_blob: Some(TEST_KM_BLOB.to_vec()),
                cert: Some(TEST_CERT_BLOB.to_vec()),
                cert_chain: Some(TEST_CERT_CHAIN_BLOB.to_vec()),
                sec_level: SecurityLevel::TRUSTED_ENVIRONMENT,
                parameters: make_test_params(),
            }
        );
        Ok(())
    }

    #[test]
    fn test_insert_and_load_full_keyentry_domain_key_id() -> Result<()> {
        let mut db = new_test_db()?;
        let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS)
            .context("test_insert_and_load_full_keyentry_domain_key_id")?
            .0;
        let (_key_guard, key_entry) = db.load_key_entry(
            KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
            KeyEntryLoadBits::BOTH,
            1,
            |_k, _av| Ok(()),
        )?;
        assert_eq!(
            key_entry,
            KeyEntry {
                id: key_id,
                km_blob: Some(TEST_KM_BLOB.to_vec()),
                cert: Some(TEST_CERT_BLOB.to_vec()),
                cert_chain: Some(TEST_CERT_CHAIN_BLOB.to_vec()),
                sec_level: SecurityLevel::TRUSTED_ENVIRONMENT,
                parameters: make_test_params(),
            }
        );

        Ok(())
    }

    #[test]
    fn test_insert_and_load_full_keyentry_from_grant() -> Result<()> {
        let mut db = new_test_db()?;
        let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS)
            .context("test_insert_and_load_full_keyentry_from_grant")?
            .0;

        let granted_key = db.grant(
            KeyDescriptor {
                domain: Domain::APP,
                nspace: 0,
                alias: Some(TEST_ALIAS.to_string()),
                blob: None,
            },
            1,
            2,
            key_perm_set![KeyPerm::use_()],
            |_k, _av| Ok(()),
        )?;

        debug_dump_grant_table(&mut db)?;

        let (_key_guard, key_entry) =
            db.load_key_entry(granted_key, KeyEntryLoadBits::BOTH, 2, |k, av| {
                assert_eq!(Domain::GRANT, k.domain);
                assert!(av.unwrap().includes(KeyPerm::use_()));
                Ok(())
            })?;

        assert_eq!(
            key_entry,
            KeyEntry {
                id: key_id,
                km_blob: Some(TEST_KM_BLOB.to_vec()),
                cert: Some(TEST_CERT_BLOB.to_vec()),
                cert_chain: Some(TEST_CERT_CHAIN_BLOB.to_vec()),
                sec_level: SecurityLevel::TRUSTED_ENVIRONMENT,
                parameters: make_test_params(),
            }
        );
        Ok(())
    }

    static KEY_LOCK_TEST_ALIAS: &str = "my super duper locked key";

    static KEY_LOCK_TEST_SQL: &str = "/data/local/tmp/persistent_key_lock.sqlite";
    static KEY_LOCK_PERBOOT_TEST_SQL: &str = "/data/local/tmp/perboot_key_lock.sqlite";

    fn new_test_db_with_persistent_file_key_lock() -> Result<KeystoreDB> {
        let conn = KeystoreDB::make_connection(KEY_LOCK_TEST_SQL, KEY_LOCK_PERBOOT_TEST_SQL)?;

        KeystoreDB::init_tables(&conn).context("Failed to initialize tables.")?;
        Ok(KeystoreDB { conn })
    }

    #[test]
    fn test_insert_and_load_full_keyentry_domain_app_concurrently() -> Result<()> {
        let handle = {
            let _file_guard_persistent = Arc::new(TempFile { filename: KEY_LOCK_TEST_SQL });
            let _file_guard_perboot = Arc::new(TempFile { filename: KEY_LOCK_PERBOOT_TEST_SQL });
            let mut db = new_test_db_with_persistent_file_key_lock()?;
            let key_id = make_test_key_entry(&mut db, Domain::APP, 33, KEY_LOCK_TEST_ALIAS)
                .context("test_insert_and_load_full_keyentry_domain_app")?
                .0;
            let (_key_guard, key_entry) = db.load_key_entry(
                KeyDescriptor {
                    domain: Domain::APP,
                    nspace: 0,
                    alias: Some(KEY_LOCK_TEST_ALIAS.to_string()),
                    blob: None,
                },
                KeyEntryLoadBits::BOTH,
                33,
                |_k, _av| Ok(()),
            )?;
            assert_eq!(
                key_entry,
                KeyEntry {
                    id: key_id,
                    km_blob: Some(TEST_KM_BLOB.to_vec()),
                    cert: Some(TEST_CERT_BLOB.to_vec()),
                    cert_chain: Some(TEST_CERT_CHAIN_BLOB.to_vec()),
                    sec_level: SecurityLevel::TRUSTED_ENVIRONMENT,
                    parameters: make_test_params(),
                }
            );
            let state = Arc::new(AtomicU8::new(1));
            let state2 = state.clone();

            // Spawning a second thread that attempts to acquire the key id lock
            // for the same key as the primary thread. The primary thread then
            // waits, thereby forcing the secondary thread into the second stage
            // of acquiring the lock (see KEY ID LOCK 2/2 above).
            // The test succeeds if the secondary thread observes the transition
            // of `state` from 1 to 2, despite having a whole second to overtake
            // the primary thread.
            let handle = thread::spawn(move || {
                let _file_a = _file_guard_persistent;
                let _file_b = _file_guard_perboot;
                let mut db = new_test_db_with_persistent_file_key_lock().unwrap();
                assert!(db
                    .load_key_entry(
                        KeyDescriptor {
                            domain: Domain::APP,
                            nspace: 0,
                            alias: Some(KEY_LOCK_TEST_ALIAS.to_string()),
                            blob: None,
                        },
                        KeyEntryLoadBits::BOTH,
                        33,
                        |_k, _av| Ok(()),
                    )
                    .is_ok());
                // We should only see a 2 here because we can only return
                // from load_key_entry when the `_key_guard` expires,
                // which happens at the end of the scope.
                assert_eq!(2, state2.load(Ordering::Relaxed));
            });

            thread::sleep(std::time::Duration::from_millis(1000));

            assert_eq!(Ok(1), state.compare_exchange(1, 2, Ordering::Relaxed, Ordering::Relaxed));

            // Return the handle from this scope so we can join with the
            // secondary thread after the key id lock has expired.
            handle
            // This is where the `_key_guard` goes out of scope,
            // which is the reason for concurrent load_key_entry on the same key
            // to unblock.
        };
        // Join with the secondary thread and unwrap, to propagate failing asserts to the
        // main test thread. We will not see failing asserts in secondary threads otherwise.
        handle.join().unwrap();
        Ok(())
    }

    // Helpers

    // Checks that the given result is an error containing the given string.
    fn check_result_is_error_containing_string<T>(result: Result<T>, target: &str) {
        let error_str = format!(
            "{:#?}",
            result.err().unwrap_or_else(|| panic!("Expected the error: {}", target))
        );
        assert!(
            error_str.contains(target),
            "The string \"{}\" should contain \"{}\"",
            error_str,
            target
        );
    }

    #[derive(Debug, PartialEq)]
    #[allow(dead_code)]
    struct KeyEntryRow {
        id: i64,
        creation_date: String,
        domain: Option<Domain>,
        namespace: Option<i64>,
        alias: Option<String>,
    }

    fn get_keyentry(db: &KeystoreDB) -> Result<Vec<KeyEntryRow>> {
        db.conn
            .prepare("SELECT * FROM persistent.keyentry;")?
            .query_map(NO_PARAMS, |row| {
                Ok(KeyEntryRow {
                    id: row.get(0)?,
                    creation_date: row.get(1)?,
                    domain: match row.get(2)? {
                        Some(i) => Some(Domain(i)),
                        None => None,
                    },
                    namespace: row.get(3)?,
                    alias: row.get(4)?,
                })
            })?
            .map(|r| r.context("Could not read keyentry row."))
            .collect::<Result<Vec<_>>>()
    }

    // Note: The parameters and SecurityLevel associations are nonsensical. This
    // collection is only used to check if the parameters are preserved as expected by the
    // database.
    fn make_test_params() -> Vec<KeyParameter> {
        vec![
            KeyParameter::new(KeyParameterValue::Invalid, SecurityLevel::TRUSTED_ENVIRONMENT),
            KeyParameter::new(
                KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::KeyPurpose(KeyPurpose::DECRYPT),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::Algorithm(Algorithm::RSA),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(KeyParameterValue::KeySize(1024), SecurityLevel::TRUSTED_ENVIRONMENT),
            KeyParameter::new(
                KeyParameterValue::BlockMode(BlockMode::ECB),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::BlockMode(BlockMode::GCM),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(KeyParameterValue::Digest(Digest::NONE), SecurityLevel::STRONGBOX),
            KeyParameter::new(
                KeyParameterValue::Digest(Digest::MD5),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::Digest(Digest::SHA_2_224),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::Digest(Digest::SHA_2_256),
                SecurityLevel::STRONGBOX,
            ),
            KeyParameter::new(
                KeyParameterValue::PaddingMode(PaddingMode::NONE),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::PaddingMode(PaddingMode::RSA_OAEP),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::PaddingMode(PaddingMode::RSA_PSS),
                SecurityLevel::STRONGBOX,
            ),
            KeyParameter::new(
                KeyParameterValue::PaddingMode(PaddingMode::RSA_PKCS1_1_5_SIGN),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(KeyParameterValue::CallerNonce, SecurityLevel::TRUSTED_ENVIRONMENT),
            KeyParameter::new(KeyParameterValue::MinMacLength(256), SecurityLevel::STRONGBOX),
            KeyParameter::new(
                KeyParameterValue::EcCurve(EcCurve::P_224),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(KeyParameterValue::EcCurve(EcCurve::P_256), SecurityLevel::STRONGBOX),
            KeyParameter::new(
                KeyParameterValue::EcCurve(EcCurve::P_384),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::EcCurve(EcCurve::P_521),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::RSAPublicExponent(3),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::IncludeUniqueID,
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(KeyParameterValue::BootLoaderOnly, SecurityLevel::STRONGBOX),
            KeyParameter::new(KeyParameterValue::RollbackResistance, SecurityLevel::STRONGBOX),
            KeyParameter::new(
                KeyParameterValue::ActiveDateTime(1234567890),
                SecurityLevel::STRONGBOX,
            ),
            KeyParameter::new(
                KeyParameterValue::OriginationExpireDateTime(1234567890),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::UsageExpireDateTime(1234567890),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::MinSecondsBetweenOps(1234567890),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::MaxUsesPerBoot(1234567890),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(KeyParameterValue::UserID(1), SecurityLevel::STRONGBOX),
            KeyParameter::new(KeyParameterValue::UserSecureID(42), SecurityLevel::STRONGBOX),
            KeyParameter::new(
                KeyParameterValue::NoAuthRequired,
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::HardwareAuthenticatorType(HardwareAuthenticatorType::PASSWORD),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(KeyParameterValue::AuthTimeout(1234567890), SecurityLevel::SOFTWARE),
            KeyParameter::new(KeyParameterValue::AllowWhileOnBody, SecurityLevel::SOFTWARE),
            KeyParameter::new(
                KeyParameterValue::TrustedUserPresenceRequired,
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::TrustedConfirmationRequired,
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::UnlockedDeviceRequired,
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::ApplicationID(vec![1u8, 2u8, 3u8, 4u8]),
                SecurityLevel::SOFTWARE,
            ),
            KeyParameter::new(
                KeyParameterValue::ApplicationData(vec![4u8, 3u8, 2u8, 1u8]),
                SecurityLevel::SOFTWARE,
            ),
            KeyParameter::new(
                KeyParameterValue::CreationDateTime(12345677890),
                SecurityLevel::SOFTWARE,
            ),
            KeyParameter::new(
                KeyParameterValue::KeyOrigin(KeyOrigin::GENERATED),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::RootOfTrust(vec![3u8, 2u8, 1u8, 4u8]),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(KeyParameterValue::OSVersion(1), SecurityLevel::TRUSTED_ENVIRONMENT),
            KeyParameter::new(KeyParameterValue::OSPatchLevel(2), SecurityLevel::SOFTWARE),
            KeyParameter::new(
                KeyParameterValue::UniqueID(vec![4u8, 3u8, 1u8, 2u8]),
                SecurityLevel::SOFTWARE,
            ),
            KeyParameter::new(
                KeyParameterValue::AttestationChallenge(vec![4u8, 3u8, 1u8, 2u8]),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::AttestationApplicationID(vec![4u8, 3u8, 1u8, 2u8]),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::AttestationIdBrand(vec![4u8, 3u8, 1u8, 2u8]),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::AttestationIdDevice(vec![4u8, 3u8, 1u8, 2u8]),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::AttestationIdProduct(vec![4u8, 3u8, 1u8, 2u8]),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::AttestationIdSerial(vec![4u8, 3u8, 1u8, 2u8]),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::AttestationIdIMEI(vec![4u8, 3u8, 1u8, 2u8]),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::AttestationIdMEID(vec![4u8, 3u8, 1u8, 2u8]),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::AttestationIdManufacturer(vec![4u8, 3u8, 1u8, 2u8]),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::AttestationIdModel(vec![4u8, 3u8, 1u8, 2u8]),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::VendorPatchLevel(3),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::BootPatchLevel(4),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::AssociatedData(vec![4u8, 3u8, 1u8, 2u8]),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::Nonce(vec![4u8, 3u8, 1u8, 2u8]),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::MacLength(256),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::ResetSinceIdRotation,
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
            KeyParameter::new(
                KeyParameterValue::ConfirmationToken(vec![5u8, 5u8, 5u8, 5u8]),
                SecurityLevel::TRUSTED_ENVIRONMENT,
            ),
        ]
    }

    fn make_test_key_entry(
        db: &mut KeystoreDB,
        domain: Domain,
        namespace: i64,
        alias: &str,
    ) -> Result<KeyIdGuard> {
        let key_id = db.create_key_entry(domain, namespace)?;
        db.insert_blob(
            &key_id,
            SubComponentType::KM_BLOB,
            TEST_KM_BLOB,
            SecurityLevel::TRUSTED_ENVIRONMENT,
        )?;
        db.insert_blob(
            &key_id,
            SubComponentType::CERT,
            TEST_CERT_BLOB,
            SecurityLevel::TRUSTED_ENVIRONMENT,
        )?;
        db.insert_blob(
            &key_id,
            SubComponentType::CERT_CHAIN,
            TEST_CERT_CHAIN_BLOB,
            SecurityLevel::TRUSTED_ENVIRONMENT,
        )?;
        db.insert_keyparameter(&key_id, &make_test_params())?;
        db.rebind_alias(&key_id, alias, domain, namespace)?;
        Ok(key_id)
    }

    fn debug_dump_keyentry_table(db: &mut KeystoreDB) -> Result<()> {
        let mut stmt = db.conn.prepare(
            "SELECT id, creation_date, domain, namespace, alias FROM persistent.keyentry;",
        )?;
        let rows = stmt.query_map::<(i64, i64, i32, i64, String), _, _>(NO_PARAMS, |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        })?;

        println!("Key entry table rows:");
        for r in rows {
            let (id, cdate, domain, namespace, alias) = r.unwrap();
            println!(
                "    id: {} Creation date: {} Domain: {} Namespace: {} Alias: {}",
                id, cdate, domain, namespace, alias
            );
        }
        Ok(())
    }

    fn debug_dump_grant_table(db: &mut KeystoreDB) -> Result<()> {
        let mut stmt =
            db.conn.prepare("SELECT id, grantee, keyentryid, access_vector FROM perboot.grant;")?;
        let rows = stmt.query_map::<(i64, i64, i64, i64), _, _>(NO_PARAMS, |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;

        println!("Grant table rows:");
        for r in rows {
            let (id, gt, ki, av) = r.unwrap();
            println!("    id: {} grantee: {} key_id: {} access_vector: {}", id, gt, ki, av);
        }
        Ok(())
    }

    // A class that deletes a file when it is dropped.
    // TODO: If we ever add a crate that does this, we can use it instead.
    struct TempFile {
        filename: &'static str,
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            std::fs::remove_file(self.filename).expect("Cannot delete temporary file");
        }
    }

    // Use a custom random number generator that repeats each number once.
    // This allows us to test repeated elements.

    thread_local! {
        static RANDOM_COUNTER: RefCell<i64> = RefCell::new(0);
    }

    fn reset_random() {
        RANDOM_COUNTER.with(|counter| {
            *counter.borrow_mut() = 0;
        })
    }

    pub fn random() -> i64 {
        RANDOM_COUNTER.with(|counter| {
            let result = *counter.borrow() / 2;
            *counter.borrow_mut() += 1;
            result
        })
    }
}
