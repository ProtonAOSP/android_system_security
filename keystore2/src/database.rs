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

#![allow(dead_code)]

use crate::error::{Error as KsError, ResponseCode};
use crate::impl_metadata; // This is in db_utils.rs
use crate::key_parameter::{KeyParameter, Tag};
use crate::permission::KeyPermSet;
use crate::utils::get_current_time_in_seconds;
use crate::{
    db_utils::{self, SqlField},
    gc::Gc,
};
use anyhow::{anyhow, Context, Result};
use std::{convert::TryFrom, convert::TryInto, time::SystemTimeError};

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    ErrorCode::ErrorCode as Ec, HardwareAuthToken::HardwareAuthToken,
    HardwareAuthenticatorType::HardwareAuthenticatorType, SecurityLevel::SecurityLevel,
    Timestamp::Timestamp,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor,
};
use lazy_static::lazy_static;
use log::error;
#[cfg(not(test))]
use rand::prelude::random;
use rusqlite::{
    params,
    types::FromSql,
    types::FromSqlResult,
    types::ToSqlOutput,
    types::{FromSqlError, Value, ValueRef},
    Connection, Error, OptionalExtension, ToSql, Transaction, TransactionBehavior, NO_PARAMS,
};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{Condvar, Mutex},
    time::{Duration, SystemTime},
};
#[cfg(test)]
use tests::random;

impl_metadata!(
    /// A set of metadata for key entries.
    #[derive(Debug, Default, Eq, PartialEq)]
    pub struct KeyMetaData;
    /// A metadata entry for key entries.
    #[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
    pub enum KeyMetaEntry {
        /// If present, indicates that the sensitive part of key
        /// is encrypted with another key or a key derived from a password.
        EncryptedBy(EncryptedBy) with accessor encrypted_by,
        /// If the blob is password encrypted this field is set to the
        /// salt used for the key derivation.
        Salt(Vec<u8>) with accessor salt,
        /// If the blob is encrypted, this field is set to the initialization vector.
        Iv(Vec<u8>) with accessor iv,
        /// If the blob is encrypted, this field holds the AEAD TAG.
        AeadTag(Vec<u8>) with accessor aead_tag,
        /// Creation date of a the key entry.
        CreationDate(DateTime) with accessor creation_date,
        /// Expiration date for attestation keys.
        AttestationExpirationDate(DateTime) with accessor attestation_expiration_date,
        //  --- ADD NEW META DATA FIELDS HERE ---
        // For backwards compatibility add new entries only to
        // end of this list and above this comment.
    };
);

impl KeyMetaData {
    fn load_from_db(key_id: i64, tx: &Transaction) -> Result<Self> {
        let mut stmt = tx
            .prepare(
                "SELECT tag, data from persistent.keymetadata
                    WHERE keyentryid = ?;",
            )
            .context("In KeyMetaData::load_from_db: prepare statement failed.")?;

        let mut metadata: HashMap<i64, KeyMetaEntry> = Default::default();

        let mut rows =
            stmt.query(params![key_id]).context("In KeyMetaData::load_from_db: query failed.")?;
        db_utils::with_rows_extract_all(&mut rows, |row| {
            let db_tag: i64 = row.get(0).context("Failed to read tag.")?;
            metadata.insert(
                db_tag,
                KeyMetaEntry::new_from_sql(db_tag, &SqlField::new(1, &row))
                    .context("Failed to read KeyMetaEntry.")?,
            );
            Ok(())
        })
        .context("In KeyMetaData::load_from_db.")?;

        Ok(Self { data: metadata })
    }

    fn store_in_db(&self, key_id: i64, tx: &Transaction) -> Result<()> {
        let mut stmt = tx
            .prepare(
                "INSERT into persistent.keymetadata (keyentryid, tag, data)
                    VALUES (?, ?, ?);",
            )
            .context("In KeyMetaData::store_in_db: Failed to prepare statement.")?;

        let iter = self.data.iter();
        for (tag, entry) in iter {
            stmt.insert(params![key_id, tag, entry,]).with_context(|| {
                format!("In KeyMetaData::store_in_db: Failed to insert {:?}", entry)
            })?;
        }
        Ok(())
    }
}

/// Indicates the type of the keyentry.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum KeyType {
    /// This is a client key type. These keys are created or imported through the Keystore 2.0
    /// AIDL interface android.system.keystore2.
    Client,
    /// This is a super key type. These keys are created by keystore itself and used to encrypt
    /// other key blobs to provide LSKF binding.
    Super,
    /// This is an attestation key. These keys are created by the remote provisioning mechanism.
    Attestation,
}

impl ToSql for KeyType {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        Ok(ToSqlOutput::Owned(Value::Integer(match self {
            KeyType::Client => 0,
            KeyType::Super => 1,
            KeyType::Attestation => 2,
        })))
    }
}

impl FromSql for KeyType {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        match i64::column_result(value)? {
            0 => Ok(KeyType::Client),
            1 => Ok(KeyType::Super),
            2 => Ok(KeyType::Attestation),
            v => Err(FromSqlError::OutOfRange(v)),
        }
    }
}

/// Indicates how the sensitive part of this key blob is encrypted.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum EncryptedBy {
    /// The keyblob is encrypted by a user password.
    /// In the database this variant is represented as NULL.
    Password,
    /// The keyblob is encrypted by another key with wrapped key id.
    /// In the database this variant is represented as non NULL value
    /// that is convertible to i64, typically NUMERIC.
    KeyId(i64),
}

impl ToSql for EncryptedBy {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        match self {
            Self::Password => Ok(ToSqlOutput::Owned(Value::Null)),
            Self::KeyId(id) => id.to_sql(),
        }
    }
}

impl FromSql for EncryptedBy {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        match value {
            ValueRef::Null => Ok(Self::Password),
            _ => Ok(Self::KeyId(i64::column_result(value)?)),
        }
    }
}

/// A database representation of wall clock time. DateTime stores unix epoch time as
/// i64 in milliseconds.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct DateTime(i64);

/// Error type returned when creating DateTime or converting it from and to
/// SystemTime.
#[derive(thiserror::Error, Debug)]
pub enum DateTimeError {
    /// This is returned when SystemTime and Duration computations fail.
    #[error(transparent)]
    SystemTimeError(#[from] SystemTimeError),

    /// This is returned when type conversions fail.
    #[error(transparent)]
    TypeConversion(#[from] std::num::TryFromIntError),

    /// This is returned when checked time arithmetic failed.
    #[error("Time arithmetic failed.")]
    TimeArithmetic,
}

impl DateTime {
    /// Constructs a new DateTime object denoting the current time. This may fail during
    /// conversion to unix epoch time and during conversion to the internal i64 representation.
    pub fn now() -> Result<Self, DateTimeError> {
        Ok(Self(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_millis().try_into()?))
    }

    /// Constructs a new DateTime object from milliseconds.
    pub fn from_millis_epoch(millis: i64) -> Self {
        Self(millis)
    }

    /// Returns unix epoch time in milliseconds.
    pub fn to_millis_epoch(&self) -> i64 {
        self.0
    }

    /// Returns unix epoch time in seconds.
    pub fn to_secs_epoch(&self) -> i64 {
        self.0 / 1000
    }
}

impl ToSql for DateTime {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        Ok(ToSqlOutput::Owned(Value::Integer(self.0)))
    }
}

impl FromSql for DateTime {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        Ok(Self(i64::column_result(value)?))
    }
}

impl TryInto<SystemTime> for DateTime {
    type Error = DateTimeError;

    fn try_into(self) -> Result<SystemTime, Self::Error> {
        // We want to construct a SystemTime representation equivalent to self, denoting
        // a point in time THEN, but we cannot set the time directly. We can only construct
        // a SystemTime denoting NOW, and we can get the duration between EPOCH and NOW,
        // and between EPOCH and THEN. With this common reference we can construct the
        // duration between NOW and THEN which we can add to our SystemTime representation
        // of NOW to get a SystemTime representation of THEN.
        // Durations can only be positive, thus the if statement below.
        let now = SystemTime::now();
        let now_epoch = now.duration_since(SystemTime::UNIX_EPOCH)?;
        let then_epoch = Duration::from_millis(self.0.try_into()?);
        Ok(if now_epoch > then_epoch {
            // then = now - (now_epoch - then_epoch)
            now_epoch
                .checked_sub(then_epoch)
                .and_then(|d| now.checked_sub(d))
                .ok_or(DateTimeError::TimeArithmetic)?
        } else {
            // then = now + (then_epoch - now_epoch)
            then_epoch
                .checked_sub(now_epoch)
                .and_then(|d| now.checked_add(d))
                .ok_or(DateTimeError::TimeArithmetic)?
        })
    }
}

impl TryFrom<SystemTime> for DateTime {
    type Error = DateTimeError;

    fn try_from(t: SystemTime) -> Result<Self, Self::Error> {
        Ok(Self(t.duration_since(SystemTime::UNIX_EPOCH)?.as_millis().try_into()?))
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
enum KeyLifeCycle {
    /// Existing keys have a key ID but are not fully populated yet.
    /// This is a transient state. If Keystore finds any such keys when it starts up, it must move
    /// them to Unreferenced for garbage collection.
    Existing,
    /// A live key is fully populated and usable by clients.
    Live,
    /// An unreferenced key is scheduled for garbage collection.
    Unreferenced,
}

impl ToSql for KeyLifeCycle {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        match self {
            Self::Existing => Ok(ToSqlOutput::Owned(Value::Integer(0))),
            Self::Live => Ok(ToSqlOutput::Owned(Value::Integer(1))),
            Self::Unreferenced => Ok(ToSqlOutput::Owned(Value::Integer(2))),
        }
    }
}

impl FromSql for KeyLifeCycle {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        match i64::column_result(value)? {
            0 => Ok(KeyLifeCycle::Existing),
            1 => Ok(KeyLifeCycle::Live),
            2 => Ok(KeyLifeCycle::Unreferenced),
            v => Err(FromSqlError::OutOfRange(v)),
        }
    }
}

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
#[derive(Debug, Default, Eq, PartialEq)]
pub struct KeyEntry {
    id: i64,
    km_blob: Option<Vec<u8>>,
    cert: Option<Vec<u8>>,
    cert_chain: Option<Vec<u8>>,
    sec_level: SecurityLevel,
    parameters: Vec<KeyParameter>,
    metadata: KeyMetaData,
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
    /// Exposes the key metadata of this key entry.
    pub fn metadata(&self) -> &KeyMetaData {
        &self.metadata
    }
}

/// Indicates the sub component of a key entry for persistent storage.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SubComponentType(u32);
impl SubComponentType {
    /// Persistent identifier for a key blob.
    pub const KEY_BLOB: SubComponentType = Self(0);
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

/// KeystoreDB wraps a connection to an SQLite database and tracks its
/// ownership. It also implements all of Keystore 2.0's database functionality.
pub struct KeystoreDB {
    conn: Connection,
}

/// Database representation of the monotonic time retrieved from the system call clock_gettime with
/// CLOCK_MONOTONIC_RAW. Stores monotonic time as i64 in seconds.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct MonotonicRawTime(i64);

impl MonotonicRawTime {
    /// Constructs a new MonotonicRawTime
    pub fn now() -> Self {
        Self(get_current_time_in_seconds())
    }

    /// Returns the integer value of MonotonicRawTime as i64
    pub fn seconds(&self) -> i64 {
        self.0
    }
}

impl ToSql for MonotonicRawTime {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        Ok(ToSqlOutput::Owned(Value::Integer(self.0)))
    }
}

impl FromSql for MonotonicRawTime {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        Ok(Self(i64::column_result(value)?))
    }
}

/// This struct encapsulates the information to be stored in the database about the auth tokens
/// received by keystore.
pub struct AuthTokenEntry {
    auth_token: HardwareAuthToken,
    time_received: MonotonicRawTime,
}

impl AuthTokenEntry {
    fn new(auth_token: HardwareAuthToken, time_received: MonotonicRawTime) -> Self {
        AuthTokenEntry { auth_token, time_received }
    }

    /// Checks if this auth token satisfies the given authentication information.
    pub fn satisfies_auth(
        auth_token: &HardwareAuthToken,
        user_secure_ids: &[i64],
        auth_type: HardwareAuthenticatorType,
    ) -> bool {
        user_secure_ids.iter().any(|&sid| {
            (sid == auth_token.userId || sid == auth_token.authenticatorId)
                && (((auth_type.0 as i32) & (auth_token.authenticatorType.0 as i32)) != 0)
        })
    }

    /// Returns the auth token wrapped by the AuthTokenEntry
    pub fn get_auth_token(self) -> HardwareAuthToken {
        self.auth_token
    }
}

impl KeystoreDB {
    /// This will create a new database connection connecting the two
    /// files persistent.sqlite and perboot.sqlite in the given directory.
    /// It also attempts to initialize all of the tables.
    /// KeystoreDB cannot be used by multiple threads.
    /// Each thread should open their own connection using `thread_local!`.
    pub fn new(db_root: &Path) -> Result<Self> {
        // Build the path to the sqlite files.
        let mut persistent_path = db_root.to_path_buf();
        persistent_path.push("persistent.sqlite");
        let mut perboot_path = db_root.to_path_buf();
        perboot_path.push("perboot.sqlite");

        // Now convert them to strings prefixed with "file:"
        let mut persistent_path_str = "file:".to_owned();
        persistent_path_str.push_str(&persistent_path.to_string_lossy());
        let mut perboot_path_str = "file:".to_owned();
        perboot_path_str.push_str(&perboot_path.to_string_lossy());

        let conn = Self::make_connection(&persistent_path_str, &perboot_path_str)?;

        Self::init_tables(&conn)?;
        Ok(Self { conn })
    }

    fn init_tables(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS persistent.keyentry (
                     id INTEGER UNIQUE,
                     key_type INTEGER,
                     domain INTEGER,
                     namespace INTEGER,
                     alias BLOB,
                     state INTEGER);",
            NO_PARAMS,
        )
        .context("Failed to initialize \"keyentry\" table.")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS persistent.blobentry (
                    id INTEGER PRIMARY KEY,
                    subcomponent_type INTEGER,
                    keyentryid INTEGER,
                    blob BLOB);",
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

        conn.execute(
            "CREATE TABLE IF NOT EXISTS persistent.keymetadata (
                     keyentryid INTEGER,
                     tag INTEGER,
                     data ANY);",
            NO_PARAMS,
        )
        .context("Failed to initialize \"keymetadata\" table.")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS persistent.grant (
                    id INTEGER UNIQUE,
                    grantee INTEGER,
                    keyentryid INTEGER,
                    access_vector INTEGER);",
            NO_PARAMS,
        )
        .context("Failed to initialize \"grant\" table.")?;

        //TODO: only drop the following two perboot tables if this is the first start up
        //during the boot (b/175716626).
        // conn.execute("DROP TABLE IF EXISTS perboot.authtoken;", NO_PARAMS)
        //     .context("Failed to drop perboot.authtoken table")?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS perboot.authtoken (
                        id INTEGER PRIMARY KEY,
                        challenge INTEGER,
                        user_id INTEGER,
                        auth_id INTEGER,
                        authenticator_type INTEGER,
                        timestamp INTEGER,
                        mac BLOB,
                        time_received INTEGER,
                        UNIQUE(user_id, auth_id, authenticator_type));",
            NO_PARAMS,
        )
        .context("Failed to initialize \"authtoken\" table.")?;

        // conn.execute("DROP TABLE IF EXISTS perboot.metadata;", NO_PARAMS)
        //     .context("Failed to drop perboot.metadata table")?;
        // metadata table stores certain miscellaneous information required for keystore functioning
        // during a boot cycle, as key-value pairs.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS perboot.metadata (
                        key TEXT,
                        value BLOB,
                        UNIQUE(key));",
            NO_PARAMS,
        )
        .context("Failed to initialize \"metadata\" table.")?;
        // TODO: Add the initial entry on last_off_body to the metadata table during the boot of the
        // device (i.e. during the first startup of the keystore during a boot cycle).
        Self::insert_last_off_body(conn, MonotonicRawTime::now()).context("In init-tables.")?;
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

    /// Get one unreferenced key. There is no particular order in which the keys are returned.
    fn get_unreferenced_key_id(tx: &Transaction) -> Result<Option<i64>> {
        tx.query_row(
            "SELECT id FROM persistent.keyentry WHERE state = ?",
            params![KeyLifeCycle::Unreferenced],
            |row| row.get(0),
        )
        .optional()
        .context("In get_unreferenced_key_id: Trying to get unreferenced key id.")
    }

    /// Returns a key id guard and key entry for one unreferenced key entry. Of the optional
    /// fields of the key entry only the km_blob field will be populated. This is required
    /// to subject the blob to its KeyMint instance for deletion.
    pub fn get_unreferenced_key(&mut self) -> Result<Option<(KeyIdGuard, KeyEntry)>> {
        self.with_transaction(TransactionBehavior::Deferred, |tx| {
            let key_id = match Self::get_unreferenced_key_id(tx)
                .context("Trying to get unreferenced key id")?
            {
                None => return Ok(None),
                Some(id) => KEY_ID_LOCK.try_get(id).ok_or_else(KsError::sys).context(concat!(
                    "A key id lock was held for an unreferenced key. ",
                    "This should never happen."
                ))?,
            };
            let key_entry = Self::load_key_components(tx, KeyEntryLoadBits::KM, key_id.id())
                .context("Trying to get key components.")?;
            Ok(Some((key_id, key_entry)))
        })
        .context("In get_unreferenced_key.")
    }

    /// This function purges all remnants of a key entry from the database.
    /// Important: This does not check if the key was unreferenced, nor does it
    /// subject the key to its KeyMint instance for permanent invalidation.
    /// This function should only be called by the garbage collector.
    /// To delete a key call `mark_unreferenced`, which transitions the key to the unreferenced
    /// state, deletes all grants to the key, and notifies the garbage collector.
    /// The garbage collector will:
    ///  1. Call get_unreferenced_key.
    ///  2. Determine the proper way to dispose of sensitive key material, e.g., call
    ///     `KeyMintDevice::delete()`.
    ///  3. Call `purge_key_entry`.
    pub fn purge_key_entry(&mut self, key_id: KeyIdGuard) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            tx.execute("DELETE FROM persistent.keyentry WHERE id = ?;", params![key_id.id()])
                .context("Trying to delete keyentry.")?;
            tx.execute(
                "DELETE FROM persistent.blobentry WHERE keyentryid = ?;",
                params![key_id.id()],
            )
            .context("Trying to delete blobentries.")?;
            tx.execute(
                "DELETE FROM persistent.keymetadata WHERE keyentryid = ?;",
                params![key_id.id()],
            )
            .context("Trying to delete keymetadata.")?;
            tx.execute(
                "DELETE FROM persistent.keyparameter WHERE keyentryid = ?;",
                params![key_id.id()],
            )
            .context("Trying to delete keyparameters.")?;
            let grants_deleted = tx
                .execute("DELETE FROM persistent.grant WHERE keyentryid = ?;", params![key_id.id()])
                .context("Trying to delete grants.")?;
            if grants_deleted != 0 {
                log::error!("Purged key that still had grants. This should not happen.");
            }
            Ok(())
        })
        .context("In purge_key_entry.")
    }

    /// This maintenance function should be called only once before the database is used for the
    /// first time. It restores the invariant that `KeyLifeCycle::Existing` is a transient state.
    /// The function transitions all key entries from Existing to Unreferenced unconditionally and
    /// returns the number of rows affected. If this returns a value greater than 0, it means that
    /// Keystore crashed at some point during key generation. Callers may want to log such
    /// occurrences.
    /// Unlike with `mark_unreferenced`, we don't need to purge grants, because only keys that made
    /// it to `KeyLifeCycle::Live` may have grants.
    pub fn cleanup_leftovers(&mut self) -> Result<usize> {
        self.conn
            .execute(
                "UPDATE persistent.keyentry SET state = ? WHERE state = ?;",
                params![KeyLifeCycle::Unreferenced, KeyLifeCycle::Existing],
            )
            .context("In cleanup_leftovers.")
    }

    /// Atomically loads a key entry and associated metadata or creates it using the
    /// callback create_new_key callback. The callback is called during a database
    /// transaction. This means that implementers should be mindful about using
    /// blocking operations such as IPC or grabbing mutexes.
    pub fn get_or_create_key_with<F>(
        &mut self,
        domain: Domain,
        namespace: i64,
        alias: &str,
        create_new_key: F,
    ) -> Result<(KeyIdGuard, KeyEntry)>
    where
        F: FnOnce() -> Result<(Vec<u8>, KeyMetaData)>,
    {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("In get_or_create_key_with: Failed to initialize transaction.")?;

        let id = {
            let mut stmt = tx
                .prepare(
                    "SELECT id FROM persistent.keyentry
                    WHERE
                    key_type = ?
                    AND domain = ?
                    AND namespace = ?
                    AND alias = ?
                    AND state = ?;",
                )
                .context("In get_or_create_key_with: Failed to select from keyentry table.")?;
            let mut rows = stmt
                .query(params![KeyType::Super, domain.0, namespace, alias, KeyLifeCycle::Live])
                .context("In get_or_create_key_with: Failed to query from keyentry table.")?;

            db_utils::with_rows_extract_one(&mut rows, |row| {
                Ok(match row {
                    Some(r) => r.get(0).context("Failed to unpack id.")?,
                    None => None,
                })
            })
            .context("In get_or_create_key_with.")?
        };

        let (id, entry) = match id {
            Some(id) => (
                id,
                Self::load_key_components(&tx, KeyEntryLoadBits::KM, id)
                    .context("In get_or_create_key_with.")?,
            ),

            None => {
                let id = Self::insert_with_retry(|id| {
                    tx.execute(
                        "INSERT into persistent.keyentry
                        (id, key_type, domain, namespace, alias, state)
                        VALUES(?, ?, ?, ?, ?, ?);",
                        params![id, KeyType::Super, domain.0, namespace, alias, KeyLifeCycle::Live],
                    )
                })
                .context("In get_or_create_key_with.")?;

                let (blob, metadata) = create_new_key().context("In get_or_create_key_with.")?;
                Self::insert_blob_internal(&tx, id, SubComponentType::KEY_BLOB, &blob)
                    .context("In get_of_create_key_with.")?;
                metadata.store_in_db(id, &tx).context("In get_or_create_key_with.")?;
                (id, KeyEntry { id, km_blob: Some(blob), metadata, ..Default::default() })
            }
        };
        tx.commit().context("In get_or_create_key_with: Failed to commit transaction.")?;
        Ok((KEY_ID_LOCK.get(id), entry))
    }

    /// Creates a transaction with the given behavior and executes f with the new transaction.
    /// The transaction is committed only if f returns Ok.
    fn with_transaction<T, F>(&mut self, behavior: TransactionBehavior, f: F) -> Result<T>
    where
        F: FnOnce(&Transaction) -> Result<T>,
    {
        let tx = self
            .conn
            .transaction_with_behavior(behavior)
            .context("In with_transaction: Failed to initialize transaction.")?;
        f(&tx).and_then(|result| {
            tx.commit().context("In with_transaction: Failed to commit transaction.")?;
            Ok(result)
        })
    }

    /// Creates a new key entry and allocates a new randomized id for the new key.
    /// The key id gets associated with a domain and namespace but not with an alias.
    /// To complete key generation `rebind_alias` should be called after all of the
    /// key artifacts, i.e., blobs and parameters have been associated with the new
    /// key id. Finalizing with `rebind_alias` makes the creation of a new key entry
    /// atomic even if key generation is not.
    pub fn create_key_entry(&mut self, domain: Domain, namespace: i64) -> Result<KeyIdGuard> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            Self::create_key_entry_internal(tx, domain, namespace)
        })
        .context("In create_key_entry.")
    }

    fn create_key_entry_internal(
        tx: &Transaction,
        domain: Domain,
        namespace: i64,
    ) -> Result<KeyIdGuard> {
        match domain {
            Domain::APP | Domain::SELINUX => {}
            _ => {
                return Err(KsError::sys())
                    .context(format!("Domain {:?} must be either App or SELinux.", domain));
            }
        }
        Ok(KEY_ID_LOCK.get(
            Self::insert_with_retry(|id| {
                tx.execute(
                    "INSERT into persistent.keyentry
                     (id, key_type, domain, namespace, alias, state)
                     VALUES(?, ?, ?, ?, NULL, ?);",
                    params![
                        id,
                        KeyType::Client,
                        domain.0 as u32,
                        namespace,
                        KeyLifeCycle::Existing
                    ],
                )
            })
            .context("In create_key_entry_internal")?,
        ))
    }

    /// Inserts a new blob and associates it with the given key id. Each blob
    /// has a sub component type and a security level.
    /// Each key can have one of each sub component type associated. If more
    /// are added only the most recent can be retrieved, and superseded blobs
    /// will get garbage collected. The security level field of components
    /// other than `SubComponentType::KEY_BLOB` are ignored.
    pub fn insert_blob(
        &mut self,
        key_id: &KeyIdGuard,
        sc_type: SubComponentType,
        blob: &[u8],
    ) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            Self::insert_blob_internal(&tx, key_id.0, sc_type, blob)
        })
        .context("In insert_blob.")
    }

    fn insert_blob_internal(
        tx: &Transaction,
        key_id: i64,
        sc_type: SubComponentType,
        blob: &[u8],
    ) -> Result<()> {
        tx.execute(
            "INSERT into persistent.blobentry (subcomponent_type, keyentryid, blob)
                VALUES (?, ?, ?);",
            params![sc_type, key_id, blob],
        )
        .context("In insert_blob_internal: Failed to insert blob.")?;
        Ok(())
    }

    /// Inserts a collection of key parameters into the `persistent.keyparameter` table
    /// and associates them with the given `key_id`.
    pub fn insert_keyparameter<'a>(
        &mut self,
        key_id: &KeyIdGuard,
        params: impl IntoIterator<Item = &'a KeyParameter>,
    ) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            Self::insert_keyparameter_internal(tx, key_id, params)
        })
        .context("In insert_keyparameter.")
    }

    fn insert_keyparameter_internal<'a>(
        tx: &Transaction,
        key_id: &KeyIdGuard,
        params: impl IntoIterator<Item = &'a KeyParameter>,
    ) -> Result<()> {
        let mut stmt = tx
            .prepare(
                "INSERT into persistent.keyparameter (keyentryid, tag, data, security_level)
                VALUES (?, ?, ?, ?);",
            )
            .context("In insert_keyparameter_internal: Failed to prepare statement.")?;

        let iter = params.into_iter();
        for p in iter {
            stmt.insert(params![
                key_id.0,
                p.get_tag().0,
                p.key_parameter_value(),
                p.security_level().0
            ])
            .with_context(|| {
                format!("In insert_keyparameter_internal: Failed to insert {:?}", p)
            })?;
        }
        Ok(())
    }

    /// Insert a set of key entry specific metadata into the database.
    pub fn insert_key_metadata(
        &mut self,
        key_id: &KeyIdGuard,
        metadata: &KeyMetaData,
    ) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            metadata.store_in_db(key_id.0, &tx)
        })
        .context("In insert_key_metadata.")
    }

    fn rebind_alias(
        &mut self,
        newid: &KeyIdGuard,
        alias: &str,
        domain: Domain,
        namespace: i64,
    ) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            Self::rebind_alias_internal(tx, newid, alias, domain, namespace)
        })
        .context("In rebind_alias.")
    }

    /// Updates the alias column of the given key id `newid` with the given alias,
    /// and atomically, removes the alias, domain, and namespace from another row
    /// with the same alias-domain-namespace tuple if such row exits.
    fn rebind_alias_internal(
        tx: &Transaction,
        newid: &KeyIdGuard,
        alias: &str,
        domain: Domain,
        namespace: i64,
    ) -> Result<()> {
        match domain {
            Domain::APP | Domain::SELINUX => {}
            _ => {
                return Err(KsError::sys()).context(format!(
                    "In rebind_alias_internal: Domain {:?} must be either App or SELinux.",
                    domain
                ));
            }
        }
        let updated = tx
            .execute(
                "UPDATE persistent.keyentry
                 SET alias = NULL, domain = NULL, namespace = NULL, state = ?
                 WHERE alias = ? AND domain = ? AND namespace = ?;",
                params![KeyLifeCycle::Unreferenced, alias, domain.0 as u32, namespace],
            )
            .context("In rebind_alias_internal: Failed to rebind existing entry.")?;
        if updated != 0 {
            Gc::notify_gc();
        }
        let result = tx
            .execute(
                "UPDATE persistent.keyentry
                    SET alias = ?, state = ?
                    WHERE id = ? AND domain = ? AND namespace = ? AND state = ?;",
                params![
                    alias,
                    KeyLifeCycle::Live,
                    newid.0,
                    domain.0 as u32,
                    namespace,
                    KeyLifeCycle::Existing
                ],
            )
            .context("In rebind_alias_internal: Failed to set alias.")?;
        if result != 1 {
            return Err(KsError::sys()).context(format!(
                "In rebind_alias_internal: Expected to update a single entry but instead updated {}.",
                result
            ));
        }
        Ok(())
    }

    /// Store a new key in a single transaction.
    /// The function creates a new key entry, populates the blob, key parameter, and metadata
    /// fields, and rebinds the given alias to the new key.
    pub fn store_new_key<'a>(
        &mut self,
        key: KeyDescriptor,
        params: impl IntoIterator<Item = &'a KeyParameter>,
        blob: &[u8],
        cert: Option<&[u8]>,
        cert_chain: Option<&[u8]>,
        metadata: &KeyMetaData,
    ) -> Result<KeyIdGuard> {
        let (alias, domain, namespace) = match key {
            KeyDescriptor { alias: Some(alias), domain: Domain::APP, nspace, blob: None }
            | KeyDescriptor { alias: Some(alias), domain: Domain::SELINUX, nspace, blob: None } => {
                (alias, key.domain, nspace)
            }
            _ => {
                return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT))
                    .context("In store_new_key: Need alias and domain must be APP or SELINUX.")
            }
        };
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            let key_id = Self::create_key_entry_internal(tx, domain, namespace)
                .context("Trying to create new key entry.")?;
            Self::insert_blob_internal(tx, key_id.id(), SubComponentType::KEY_BLOB, blob)
                .context("Trying to insert the key blob.")?;
            if let Some(cert) = cert {
                Self::insert_blob_internal(tx, key_id.id(), SubComponentType::CERT, cert)
                    .context("Trying to insert the certificate.")?;
            }
            if let Some(cert_chain) = cert_chain {
                Self::insert_blob_internal(
                    tx,
                    key_id.id(),
                    SubComponentType::CERT_CHAIN,
                    cert_chain,
                )
                .context("Trying to insert the certificate chain.")?;
            }
            Self::insert_keyparameter_internal(tx, &key_id, params)
                .context("Trying to insert key parameters.")?;
            metadata.store_in_db(key_id.id(), tx).context("Tryin to insert key metadata.")?;
            Self::rebind_alias_internal(tx, &key_id, &alias, domain, namespace)
                .context("Trying to rebind alias.")?;
            Ok(key_id)
        })
        .context("In store_new_key.")
    }

    // Helper function loading the key_id given the key descriptor
    // tuple comprising domain, namespace, and alias.
    // Requires a valid transaction.
    fn load_key_entry_id(tx: &Transaction, key: &KeyDescriptor, key_type: KeyType) -> Result<i64> {
        let alias = key
            .alias
            .as_ref()
            .map_or_else(|| Err(KsError::sys()), Ok)
            .context("In load_key_entry_id: Alias must be specified.")?;
        let mut stmt = tx
            .prepare(
                "SELECT id FROM persistent.keyentry
                    WHERE
                    key_type =  ?
                    AND domain = ?
                    AND namespace = ?
                    AND alias = ?
                    AND state = ?;",
            )
            .context("In load_key_entry_id: Failed to select from keyentry table.")?;
        let mut rows = stmt
            .query(params![key_type, key.domain.0 as u32, key.nspace, alias, KeyLifeCycle::Live])
            .context("In load_key_entry_id: Failed to read from keyentry table.")?;
        db_utils::with_rows_extract_one(&mut rows, |row| {
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
        key_type: KeyType,
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
                let key_id = Self::load_key_entry_id(&tx, &access_key, key_type)
                    .with_context(|| format!("With key.domain = {:?}.", access_key.domain))?;

                Ok((key_id, access_key, None))
            }

            // Domain::GRANT. In this case we load the key_id and the access_vector
            // from the grant table.
            Domain::GRANT => {
                let mut stmt = tx
                    .prepare(
                        "SELECT keyentryid, access_vector FROM persistent.grant
                            WHERE grantee = ? AND id = ?;",
                    )
                    .context("Domain::GRANT prepare statement failed")?;
                let mut rows = stmt
                    .query(params![caller_uid as i64, key.nspace])
                    .context("Domain:Grant: query failed.")?;
                let (key_id, access_vector): (i64, i32) =
                    db_utils::with_rows_extract_one(&mut rows, |row| {
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
                            id = ?
                            AND state = ?;",
                    )
                    .context("Domain::KEY_ID: prepare statement failed")?;
                let mut rows = stmt
                    .query(params![key.nspace, KeyLifeCycle::Live])
                    .context("Domain::KEY_ID: query failed.")?;
                let (domain, namespace): (Domain, i64) =
                    db_utils::with_rows_extract_one(&mut rows, |row| {
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
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> {
        let mut stmt = tx
            .prepare(
                "SELECT MAX(id), subcomponent_type, blob FROM persistent.blobentry
                    WHERE keyentryid = ? GROUP BY subcomponent_type;",
            )
            .context("In load_blob_components: prepare statement failed.")?;

        let mut rows =
            stmt.query(params![key_id]).context("In load_blob_components: query failed.")?;

        let mut km_blob: Option<Vec<u8>> = None;
        let mut cert_blob: Option<Vec<u8>> = None;
        let mut cert_chain_blob: Option<Vec<u8>> = None;
        db_utils::with_rows_extract_all(&mut rows, |row| {
            let sub_type: SubComponentType =
                row.get(1).context("Failed to extract subcomponent_type.")?;
            match (sub_type, load_bits.load_public(), load_bits.load_km()) {
                (SubComponentType::KEY_BLOB, _, true) => {
                    km_blob = Some(row.get(2).context("Failed to extract KM blob.")?);
                }
                (SubComponentType::CERT, true, _) => {
                    cert_blob =
                        Some(row.get(2).context("Failed to extract public certificate blob.")?);
                }
                (SubComponentType::CERT_CHAIN, true, _) => {
                    cert_chain_blob =
                        Some(row.get(2).context("Failed to extract certificate chain blob.")?);
                }
                (SubComponentType::CERT, _, _)
                | (SubComponentType::CERT_CHAIN, _, _)
                | (SubComponentType::KEY_BLOB, _, _) => {}
                _ => Err(KsError::sys()).context("Unknown subcomponent type.")?,
            }
            Ok(())
        })
        .context("In load_blob_components.")?;

        Ok((km_blob, cert_blob, cert_chain_blob))
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
        db_utils::with_rows_extract_all(&mut rows, |row| {
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
        key_type: KeyType,
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
            Self::load_access_tuple(&tx, key, key_type, caller_uid)
                .context("In load_key_entry.")?;

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
                        key_type,
                        caller_uid,
                    )
                    .context("In load_key_entry. (deferred key lock)")?;
                    (key_id_guard, tx)
                }
                Some(l) => (l, tx),
            },
            Some(key_id_guard) => (key_id_guard, tx),
        };

        let key_entry = Self::load_key_components(&tx, load_bits, key_id_guard.id())
            .context("In load_key_entry.")?;

        tx.commit().context("In load_key_entry: Failed to commit transaction.")?;

        Ok((key_id_guard, key_entry))
    }

    fn mark_unreferenced(tx: &Transaction, key_id: i64) -> Result<()> {
        let updated = tx
            .execute(
                "UPDATE persistent.keyentry SET state = ? WHERE id = ?;",
                params![KeyLifeCycle::Unreferenced, key_id],
            )
            .context("In mark_unreferenced: Failed to update state of key entry.")?;
        if updated != 0 {
            Gc::notify_gc();
        }
        tx.execute("DELETE from persistent.grant WHERE keyentryid = ?;", params![key_id])
            .context("In mark_unreferenced: Failed to drop grants.")?;
        Ok(())
    }

    /// Marks the given key as unreferenced and removes all of the grants to this key.
    pub fn unbind_key(
        &mut self,
        key: KeyDescriptor,
        key_type: KeyType,
        caller_uid: u32,
        check_permission: impl FnOnce(&KeyDescriptor, Option<KeyPermSet>) -> Result<()>,
    ) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            let (key_id, access_key_descriptor, access_vector) =
                Self::load_access_tuple(tx, key, key_type, caller_uid)
                    .context("Trying to get access tuple.")?;

            // Perform access control. It is vital that we return here if the permission is denied.
            // So do not touch that '?' at the end.
            check_permission(&access_key_descriptor, access_vector)
                .context("While checking permission.")?;

            Self::mark_unreferenced(tx, key_id).context("Trying to mark the key unreferenced.")
        })
        .context("In unbind_key.")
    }

    fn load_key_components(
        tx: &Transaction,
        load_bits: KeyEntryLoadBits,
        key_id: i64,
    ) -> Result<KeyEntry> {
        let metadata = KeyMetaData::load_from_db(key_id, &tx).context("In load_key_components.")?;

        let (km_blob, cert_blob, cert_chain_blob) =
            Self::load_blob_components(key_id, load_bits, &tx)
                .context("In load_key_components.")?;

        let parameters =
            Self::load_key_parameters(key_id, &tx).context("In load_key_components.")?;

        // Extract the security level by checking the security level of the origin tag.
        // Super keys don't have key parameters so we use security_level software by default.
        let sec_level = parameters
            .iter()
            .find_map(|k| match k.get_tag() {
                Tag::ORIGIN => Some(*k.security_level()),
                _ => None,
            })
            .unwrap_or(SecurityLevel::SOFTWARE);

        Ok(KeyEntry {
            id: key_id,
            km_blob,
            cert: cert_blob,
            cert_chain: cert_chain_blob,
            sec_level,
            parameters,
            metadata,
        })
    }

    /// Returns a list of KeyDescriptors in the selected domain/namespace.
    /// The key descriptors will have the domain, nspace, and alias field set.
    /// Domain must be APP or SELINUX, the caller must make sure of that.
    pub fn list(&mut self, domain: Domain, namespace: i64) -> Result<Vec<KeyDescriptor>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT alias FROM persistent.keyentry
             WHERE domain = ? AND namespace = ? AND alias IS NOT NULL AND state = ?;",
            )
            .context("In list: Failed to prepare.")?;

        let mut rows = stmt
            .query(params![domain.0 as u32, namespace, KeyLifeCycle::Live])
            .context("In list: Failed to query.")?;

        let mut descriptors: Vec<KeyDescriptor> = Vec::new();
        db_utils::with_rows_extract_all(&mut rows, |row| {
            descriptors.push(KeyDescriptor {
                domain,
                nspace: namespace,
                alias: Some(row.get(0).context("Trying to extract alias.")?),
                blob: None,
            });
            Ok(())
        })
        .context("In list.")?;
        Ok(descriptors)
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
            Self::load_access_tuple(&tx, key, KeyType::Client, caller_uid).context("In grant")?;

        // Perform access control. It is vital that we return here if the permission
        // was denied. So do not touch that '?' at the end of the line.
        // This permission check checks if the caller has the grant permission
        // for the given key and in addition to all of the permissions
        // expressed in `access_vector`.
        check_permission(&access_key_descriptor, &access_vector)
            .context("In grant: check_permission failed.")?;

        let grant_id = if let Some(grant_id) = tx
            .query_row(
                "SELECT id FROM persistent.grant
                WHERE keyentryid = ? AND grantee = ?;",
                params![key_id, grantee_uid],
                |row| row.get(0),
            )
            .optional()
            .context("In grant: Failed get optional existing grant id.")?
        {
            tx.execute(
                "UPDATE persistent.grant
                    SET access_vector = ?
                    WHERE id = ?;",
                params![i32::from(access_vector), grant_id],
            )
            .context("In grant: Failed to update existing grant.")?;
            grant_id
        } else {
            Self::insert_with_retry(|id| {
                tx.execute(
                    "INSERT INTO persistent.grant (id, grantee, keyentryid, access_vector)
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
            Self::load_access_tuple(&tx, key, KeyType::Client, caller_uid)
                .context("In ungrant.")?;

        // Perform access control. We must return here if the permission
        // was denied. So do not touch the '?' at the end of this line.
        check_permission(&access_key_descriptor).context("In grant: check_permission failed.")?;

        tx.execute(
            "DELETE FROM persistent.grant
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

    /// Insert or replace the auth token based on the UNIQUE constraint of the auth token table
    pub fn insert_auth_token(&mut self, auth_token: &HardwareAuthToken) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO perboot.authtoken (challenge, user_id, auth_id,
            authenticator_type, timestamp, mac, time_received) VALUES(?, ?, ?, ?, ?, ?, ?);",
                params![
                    auth_token.challenge,
                    auth_token.userId,
                    auth_token.authenticatorId,
                    auth_token.authenticatorType.0 as i32,
                    auth_token.timestamp.milliSeconds as i64,
                    auth_token.mac,
                    MonotonicRawTime::now(),
                ],
            )
            .context("In insert_auth_token: failed to insert auth token into the database")?;
        Ok(())
    }

    /// find the auth token entry issued for a time-out token
    pub fn find_timed_auth_token_entry(
        &mut self,
        user_secure_ids: &[i64],
        auth_type: HardwareAuthenticatorType,
        key_time_out: i64,
        allow_while_on_body: bool,
    ) -> Result<AuthTokenEntry> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("In find_timed_auth_token_entry: failed to initialize transaction.")?;
        let auth_token_entries =
            Self::load_auth_token_entries(&tx).context("In find_timed_auth_token_entry.")?;
        // NOTE: Although in legacy keystore both timestamp and time_received are used when finding
        // the newest match, we decided to only consider time_received in keystore2 code.
        // TODO: verify that the iter().find() preserves the order.
        let newest_match: Option<AuthTokenEntry> = auth_token_entries.into_iter().find(|entry| {
            AuthTokenEntry::satisfies_auth(&entry.auth_token, user_secure_ids, auth_type)
        });

        // Tag::ALLOW_WHILE_ON_BODY specifies that the key may be used after authentication
        // timeout if device is still on-body. So we return error only if both checks fail.
        if let Some(newest_match_entry) = newest_match {
            let current_time = MonotonicRawTime::now();
            let time_since_received_plus_time_out =
                match newest_match_entry.time_received.seconds().checked_add(key_time_out) {
                    Some(t) => t,
                    None => {
                        // we do not expect this behavior, so we need to log this error if it ever
                        // happens.
                        error!("In find_timed_auth_token_entry: overflow occurred.");
                        return Err(KsError::Km(Ec::KEY_USER_NOT_AUTHENTICATED)).context(
                            "In find_timed_auth_token_entry: matching auth token is expired.",
                        );
                    }
                };
            if (time_since_received_plus_time_out < current_time.seconds())
                && (!allow_while_on_body
                    || (newest_match_entry.time_received.seconds()
                        < Self::get_last_off_body(&tx)?.seconds()))
            {
                return Err(KsError::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
                    .context("In find_timed_auth_token_entry: matching auth token is expired.");
            }
            tx.commit().context("In find_timed_auth_token_entry, failed to commit transaction.")?;
            Ok(newest_match_entry)
        } else {
            Err(KsError::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
                .context("In find_timed_auth_token_entry: no matching auth token found.")
        }
    }

    /// load the existing auth token entries in perboot.authtoken table into a vector.
    /// return None if the table is empty.
    fn load_auth_token_entries(tx: &Transaction) -> Result<Vec<AuthTokenEntry>> {
        let mut stmt = tx
            .prepare("SELECT * from perboot.authtoken ORDER BY time_received DESC;")
            .context("In load_auth_token_entries: select prepare statement failed.")?;

        let auth_token_entries: Vec<AuthTokenEntry> = stmt
            .query_map(NO_PARAMS, |row| {
                Ok(AuthTokenEntry::new(
                    HardwareAuthToken {
                        challenge: row.get(1)?,
                        userId: row.get(2)?,
                        authenticatorId: row.get(3)?,
                        authenticatorType: HardwareAuthenticatorType(row.get(4)?),
                        timestamp: Timestamp { milliSeconds: row.get(5)? },
                        mac: row.get(6)?,
                    },
                    row.get(7)?,
                ))
            })
            .context("In load_auth_token_entries: query_map failed.")?
            .collect::<Result<Vec<AuthTokenEntry>, Error>>()
            .context(
                "In load_auth_token_entries: failed to create a vector of auth token entries
                from mapped rows.",
            )?;
        Ok(auth_token_entries)
    }

    /// insert last_off_body into the metadata table at the initialization of auth token table
    pub fn insert_last_off_body(conn: &Connection, last_off_body: MonotonicRawTime) -> Result<()> {
        conn.execute(
            "INSERT OR REPLACE INTO perboot.metadata (key, value) VALUES (?, ?);",
            params!["last_off_body", last_off_body],
        )
        .context("In insert_last_off_body: failed to insert.")?;
        Ok(())
    }

    /// update last_off_body when on_device_off_body is called
    pub fn update_last_off_body(&self, last_off_body: MonotonicRawTime) -> Result<()> {
        self.conn
            .execute(
                "UPDATE perboot.metadata SET value = ? WHERE key = ?;",
                params![last_off_body, "last_off_body"],
            )
            .context("In update_last_off_body: failed to update.")?;
        Ok(())
    }

    /// get last_off_body time when finding auth tokens
    fn get_last_off_body(tx: &Transaction) -> Result<MonotonicRawTime> {
        let mut stmt = tx
            .prepare("SELECT value from perboot.metadata WHERE key = ?;")
            .context("In get_last_off_body: select prepare statement failed.")?;
        let last_off_body: Result<MonotonicRawTime> = stmt
            .query_row(params!["last_off_body"], |row| Ok(row.get(0)?))
            .context("In get_last_off_body: query_row failed.");
        last_off_body
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
    use crate::test::utils::TempDir;
    use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
        HardwareAuthToken::HardwareAuthToken,
        HardwareAuthenticatorType::HardwareAuthenticatorType as kmhw_authenticator_type,
        Timestamp::Timestamp,
    };
    use rusqlite::NO_PARAMS;
    use rusqlite::{Error, TransactionBehavior};
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, SystemTime};

    fn new_test_db() -> Result<KeystoreDB> {
        let conn = KeystoreDB::make_connection("file::memory:", "file::memory:")?;

        KeystoreDB::init_tables(&conn).context("Failed to initialize tables.")?;
        Ok(KeystoreDB { conn })
    }

    #[test]
    fn datetime() -> Result<()> {
        let conn = Connection::open_in_memory()?;
        conn.execute("CREATE TABLE test (ts DATETIME);", NO_PARAMS)?;
        let now = SystemTime::now();
        let duration = Duration::from_secs(1000);
        let then = now.checked_sub(duration).unwrap();
        let soon = now.checked_add(duration).unwrap();
        conn.execute(
            "INSERT INTO test (ts) VALUES (?), (?), (?);",
            params![DateTime::try_from(now)?, DateTime::try_from(then)?, DateTime::try_from(soon)?],
        )?;
        let mut stmt = conn.prepare("SELECT ts FROM test ORDER BY ts ASC;")?;
        let mut rows = stmt.query(NO_PARAMS)?;
        assert_eq!(DateTime::try_from(then)?, rows.next()?.unwrap().get(0)?);
        assert_eq!(DateTime::try_from(now)?, rows.next()?.unwrap().get(0)?);
        assert_eq!(DateTime::try_from(soon)?, rows.next()?.unwrap().get(0)?);
        assert!(rows.next()?.is_none());
        assert!(DateTime::try_from(then)? < DateTime::try_from(now)?);
        assert!(DateTime::try_from(then)? < DateTime::try_from(soon)?);
        assert!(DateTime::try_from(now)? < DateTime::try_from(soon)?);
        Ok(())
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
        assert_eq!(tables.len(), 5);
        assert_eq!(tables[0], "blobentry");
        assert_eq!(tables[1], "grant");
        assert_eq!(tables[2], "keyentry");
        assert_eq!(tables[3], "keymetadata");
        assert_eq!(tables[4], "keyparameter");
        let tables = db
            .conn
            .prepare("SELECT name from perboot.sqlite_master WHERE type='table' ORDER BY name;")?
            .query_map(params![], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;

        assert_eq!(tables.len(), 2);
        assert_eq!(tables[0], "authtoken");
        assert_eq!(tables[1], "metadata");
        Ok(())
    }

    #[test]
    fn test_auth_token_table_invariant() -> Result<()> {
        let mut db = new_test_db()?;
        let auth_token1 = HardwareAuthToken {
            challenge: i64::MAX,
            userId: 200,
            authenticatorId: 200,
            authenticatorType: kmhw_authenticator_type(kmhw_authenticator_type::PASSWORD.0),
            timestamp: Timestamp { milliSeconds: 500 },
            mac: String::from("mac").into_bytes(),
        };
        db.insert_auth_token(&auth_token1)?;
        let auth_tokens_returned = get_auth_tokens(&mut db)?;
        assert_eq!(auth_tokens_returned.len(), 1);

        // insert another auth token with the same values for the columns in the UNIQUE constraint
        // of the auth token table and different value for timestamp
        let auth_token2 = HardwareAuthToken {
            challenge: i64::MAX,
            userId: 200,
            authenticatorId: 200,
            authenticatorType: kmhw_authenticator_type(kmhw_authenticator_type::PASSWORD.0),
            timestamp: Timestamp { milliSeconds: 600 },
            mac: String::from("mac").into_bytes(),
        };

        db.insert_auth_token(&auth_token2)?;
        let mut auth_tokens_returned = get_auth_tokens(&mut db)?;
        assert_eq!(auth_tokens_returned.len(), 1);

        if let Some(auth_token) = auth_tokens_returned.pop() {
            assert_eq!(auth_token.auth_token.timestamp.milliSeconds, 600);
        }

        // insert another auth token with the different values for the columns in the UNIQUE
        // constraint of the auth token table
        let auth_token3 = HardwareAuthToken {
            challenge: i64::MAX,
            userId: 201,
            authenticatorId: 200,
            authenticatorType: kmhw_authenticator_type(kmhw_authenticator_type::PASSWORD.0),
            timestamp: Timestamp { milliSeconds: 600 },
            mac: String::from("mac").into_bytes(),
        };

        db.insert_auth_token(&auth_token3)?;
        let auth_tokens_returned = get_auth_tokens(&mut db)?;
        assert_eq!(auth_tokens_returned.len(), 2);

        Ok(())
    }

    // utility function for test_auth_token_table_invariant()
    fn get_auth_tokens(db: &mut KeystoreDB) -> Result<Vec<AuthTokenEntry>> {
        let mut stmt = db.conn.prepare("SELECT * from perboot.authtoken;")?;

        let auth_token_entries: Vec<AuthTokenEntry> = stmt
            .query_map(NO_PARAMS, |row| {
                Ok(AuthTokenEntry::new(
                    HardwareAuthToken {
                        challenge: row.get(1)?,
                        userId: row.get(2)?,
                        authenticatorId: row.get(3)?,
                        authenticatorType: HardwareAuthenticatorType(row.get(4)?),
                        timestamp: Timestamp { milliSeconds: row.get(5)? },
                        mac: row.get(6)?,
                    },
                    row.get(7)?,
                ))
            })?
            .collect::<Result<Vec<AuthTokenEntry>, Error>>()?;
        Ok(auth_token_entries)
    }

    #[test]
    fn test_persistence_for_files() -> Result<()> {
        let temp_dir = TempDir::new("persistent_db_test")?;
        let mut db = KeystoreDB::new(temp_dir.path())?;

        db.create_key_entry(Domain::APP, 100)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 1);

        let db = KeystoreDB::new(temp_dir.path())?;

        let entries_new = get_keyentry(&db)?;
        assert_eq!(entries, entries_new);
        Ok(())
    }

    #[test]
    fn test_create_key_entry() -> Result<()> {
        fn extractor(ke: &KeyEntryRow) -> (Domain, i64, Option<&str>) {
            (ke.domain.unwrap(), ke.namespace.unwrap(), ke.alias.as_deref())
        }

        let mut db = new_test_db()?;

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
            "INSERT INTO persistent.keyentry (id, key_type, domain, namespace, alias, state)
                VALUES (1, 0, 0, 15, 'key', 1), (2, 0, 2, 7, 'yek', 1);",
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

        let app_granted_key = db
            .grant(app_key.clone(), CALLER_UID, GRANTEE_UID, PVEC1, |k, a| {
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
            })
            .unwrap();

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

        let selinux_granted_key = db
            .grant(selinux_key.clone(), CALLER_UID, 12, PVEC1, |k, a| {
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
            })
            .unwrap();

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
        let selinux_granted_key = db
            .grant(selinux_key.clone(), CALLER_UID, 12, PVEC2, |k, a| {
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
            })
            .unwrap();

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
                .prepare("SELECT id, grantee, keyentryid, access_vector FROM persistent.grant;")?;
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

    static TEST_KEY_BLOB: &[u8] = b"my test blob";
    static TEST_CERT_BLOB: &[u8] = b"my test cert";
    static TEST_CERT_CHAIN_BLOB: &[u8] = b"my test cert_chain";

    #[test]
    fn test_insert_blob() -> Result<()> {
        let key_id = KEY_ID_LOCK.get(3000);
        let mut db = new_test_db()?;
        db.insert_blob(&key_id, SubComponentType::KEY_BLOB, TEST_KEY_BLOB)?;
        db.insert_blob(&key_id, SubComponentType::CERT, TEST_CERT_BLOB)?;
        db.insert_blob(&key_id, SubComponentType::CERT_CHAIN, TEST_CERT_CHAIN_BLOB)?;
        drop(key_id);

        let mut stmt = db.conn.prepare(
            "SELECT subcomponent_type, keyentryid, blob FROM persistent.blobentry
                ORDER BY subcomponent_type ASC;",
        )?;
        let mut rows = stmt
            .query_map::<(SubComponentType, i64, Vec<u8>), _, _>(NO_PARAMS, |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
        let r = rows.next().unwrap().unwrap();
        assert_eq!(r, (SubComponentType::KEY_BLOB, 3000, TEST_KEY_BLOB.to_vec()));
        let r = rows.next().unwrap().unwrap();
        assert_eq!(r, (SubComponentType::CERT, 3000, TEST_CERT_BLOB.to_vec()));
        let r = rows.next().unwrap().unwrap();
        assert_eq!(r, (SubComponentType::CERT_CHAIN, 3000, TEST_CERT_CHAIN_BLOB.to_vec()));

        Ok(())
    }

    static TEST_ALIAS: &str = "my super duper key";

    #[test]
    fn test_insert_and_load_full_keyentry_domain_app() -> Result<()> {
        let mut db = new_test_db()?;
        let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS)
            .context("test_insert_and_load_full_keyentry_domain_app")?
            .0;
        let (_key_guard, key_entry) = db
            .load_key_entry(
                KeyDescriptor {
                    domain: Domain::APP,
                    nspace: 0,
                    alias: Some(TEST_ALIAS.to_string()),
                    blob: None,
                },
                KeyType::Client,
                KeyEntryLoadBits::BOTH,
                1,
                |_k, _av| Ok(()),
            )
            .unwrap();
        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id));

        db.unbind_key(
            KeyDescriptor {
                domain: Domain::APP,
                nspace: 0,
                alias: Some(TEST_ALIAS.to_string()),
                blob: None,
            },
            KeyType::Client,
            1,
            |_, _| Ok(()),
        )
        .unwrap();

        assert_eq!(
            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
            db.load_key_entry(
                KeyDescriptor {
                    domain: Domain::APP,
                    nspace: 0,
                    alias: Some(TEST_ALIAS.to_string()),
                    blob: None,
                },
                KeyType::Client,
                KeyEntryLoadBits::NONE,
                1,
                |_k, _av| Ok(()),
            )
            .unwrap_err()
            .root_cause()
            .downcast_ref::<KsError>()
        );

        Ok(())
    }

    #[test]
    fn test_insert_and_load_full_keyentry_domain_selinux() -> Result<()> {
        let mut db = new_test_db()?;
        let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS)
            .context("test_insert_and_load_full_keyentry_domain_selinux")?
            .0;
        let (_key_guard, key_entry) = db
            .load_key_entry(
                KeyDescriptor {
                    domain: Domain::SELINUX,
                    nspace: 1,
                    alias: Some(TEST_ALIAS.to_string()),
                    blob: None,
                },
                KeyType::Client,
                KeyEntryLoadBits::BOTH,
                1,
                |_k, _av| Ok(()),
            )
            .unwrap();
        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id));

        db.unbind_key(
            KeyDescriptor {
                domain: Domain::SELINUX,
                nspace: 1,
                alias: Some(TEST_ALIAS.to_string()),
                blob: None,
            },
            KeyType::Client,
            1,
            |_, _| Ok(()),
        )
        .unwrap();

        assert_eq!(
            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
            db.load_key_entry(
                KeyDescriptor {
                    domain: Domain::SELINUX,
                    nspace: 1,
                    alias: Some(TEST_ALIAS.to_string()),
                    blob: None,
                },
                KeyType::Client,
                KeyEntryLoadBits::NONE,
                1,
                |_k, _av| Ok(()),
            )
            .unwrap_err()
            .root_cause()
            .downcast_ref::<KsError>()
        );

        Ok(())
    }

    #[test]
    fn test_insert_and_load_full_keyentry_domain_key_id() -> Result<()> {
        let mut db = new_test_db()?;
        let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS)
            .context("test_insert_and_load_full_keyentry_domain_key_id")?
            .0;
        let (_, key_entry) = db
            .load_key_entry(
                KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
                KeyType::Client,
                KeyEntryLoadBits::BOTH,
                1,
                |_k, _av| Ok(()),
            )
            .unwrap();

        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id));

        db.unbind_key(
            KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
            KeyType::Client,
            1,
            |_, _| Ok(()),
        )
        .unwrap();

        assert_eq!(
            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
            db.load_key_entry(
                KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
                KeyType::Client,
                KeyEntryLoadBits::NONE,
                1,
                |_k, _av| Ok(()),
            )
            .unwrap_err()
            .root_cause()
            .downcast_ref::<KsError>()
        );

        Ok(())
    }

    #[test]
    fn test_insert_and_load_full_keyentry_from_grant() -> Result<()> {
        let mut db = new_test_db()?;
        let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS)
            .context("test_insert_and_load_full_keyentry_from_grant")?
            .0;

        let granted_key = db
            .grant(
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
            )
            .unwrap();

        debug_dump_grant_table(&mut db)?;

        let (_key_guard, key_entry) = db
            .load_key_entry(
                granted_key.clone(),
                KeyType::Client,
                KeyEntryLoadBits::BOTH,
                2,
                |k, av| {
                    assert_eq!(Domain::GRANT, k.domain);
                    assert!(av.unwrap().includes(KeyPerm::use_()));
                    Ok(())
                },
            )
            .unwrap();

        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id));

        db.unbind_key(granted_key.clone(), KeyType::Client, 2, |_, _| Ok(())).unwrap();

        assert_eq!(
            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
            db.load_key_entry(
                granted_key,
                KeyType::Client,
                KeyEntryLoadBits::NONE,
                2,
                |_k, _av| Ok(()),
            )
            .unwrap_err()
            .root_cause()
            .downcast_ref::<KsError>()
        );

        Ok(())
    }

    static KEY_LOCK_TEST_ALIAS: &str = "my super duper locked key";

    #[test]
    fn test_insert_and_load_full_keyentry_domain_app_concurrently() -> Result<()> {
        let handle = {
            let temp_dir = Arc::new(TempDir::new("id_lock_test")?);
            let temp_dir_clone = temp_dir.clone();
            let mut db = KeystoreDB::new(temp_dir.path())?;
            let key_id = make_test_key_entry(&mut db, Domain::APP, 33, KEY_LOCK_TEST_ALIAS)
                .context("test_insert_and_load_full_keyentry_domain_app")?
                .0;
            let (_key_guard, key_entry) = db
                .load_key_entry(
                    KeyDescriptor {
                        domain: Domain::APP,
                        nspace: 0,
                        alias: Some(KEY_LOCK_TEST_ALIAS.to_string()),
                        blob: None,
                    },
                    KeyType::Client,
                    KeyEntryLoadBits::BOTH,
                    33,
                    |_k, _av| Ok(()),
                )
                .unwrap();
            assert_eq!(key_entry, make_test_key_entry_test_vector(key_id));
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
                let temp_dir = temp_dir_clone;
                let mut db = KeystoreDB::new(temp_dir.path()).unwrap();
                assert!(db
                    .load_key_entry(
                        KeyDescriptor {
                            domain: Domain::APP,
                            nspace: 0,
                            alias: Some(KEY_LOCK_TEST_ALIAS.to_string()),
                            blob: None,
                        },
                        KeyType::Client,
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

    #[test]
    fn list() -> Result<()> {
        let temp_dir = TempDir::new("list_test")?;
        let mut db = KeystoreDB::new(temp_dir.path())?;
        static LIST_O_ENTRIES: &[(Domain, i64, &str)] = &[
            (Domain::APP, 1, "test1"),
            (Domain::APP, 1, "test2"),
            (Domain::APP, 1, "test3"),
            (Domain::APP, 1, "test4"),
            (Domain::APP, 1, "test5"),
            (Domain::APP, 1, "test6"),
            (Domain::APP, 1, "test7"),
            (Domain::APP, 2, "test1"),
            (Domain::APP, 2, "test2"),
            (Domain::APP, 2, "test3"),
            (Domain::APP, 2, "test4"),
            (Domain::APP, 2, "test5"),
            (Domain::APP, 2, "test6"),
            (Domain::APP, 2, "test8"),
            (Domain::SELINUX, 100, "test1"),
            (Domain::SELINUX, 100, "test2"),
            (Domain::SELINUX, 100, "test3"),
            (Domain::SELINUX, 100, "test4"),
            (Domain::SELINUX, 100, "test5"),
            (Domain::SELINUX, 100, "test6"),
            (Domain::SELINUX, 100, "test9"),
        ];

        let list_o_keys: Vec<(i64, i64)> = LIST_O_ENTRIES
            .iter()
            .map(|(domain, ns, alias)| {
                let entry =
                    make_test_key_entry(&mut db, *domain, *ns, *alias).unwrap_or_else(|e| {
                        panic!("Failed to insert {:?} {} {}. Error {:?}", domain, ns, alias, e)
                    });
                (entry.id(), *ns)
            })
            .collect();

        for (domain, namespace) in
            &[(Domain::APP, 1i64), (Domain::APP, 2i64), (Domain::SELINUX, 100i64)]
        {
            let mut list_o_descriptors: Vec<KeyDescriptor> = LIST_O_ENTRIES
                .iter()
                .filter_map(|(domain, ns, alias)| match ns {
                    ns if *ns == *namespace => Some(KeyDescriptor {
                        domain: *domain,
                        nspace: *ns,
                        alias: Some(alias.to_string()),
                        blob: None,
                    }),
                    _ => None,
                })
                .collect();
            list_o_descriptors.sort();
            let mut list_result = db.list(*domain, *namespace)?;
            list_result.sort();
            assert_eq!(list_o_descriptors, list_result);

            let mut list_o_ids: Vec<i64> = list_o_descriptors
                .into_iter()
                .map(|d| {
                    let (_, entry) = db
                        .load_key_entry(
                            d,
                            KeyType::Client,
                            KeyEntryLoadBits::NONE,
                            *namespace as u32,
                            |_, _| Ok(()),
                        )
                        .unwrap();
                    entry.id()
                })
                .collect();
            list_o_ids.sort_unstable();
            let mut loaded_entries: Vec<i64> = list_o_keys
                .iter()
                .filter_map(|(id, ns)| match ns {
                    ns if *ns == *namespace => Some(*id),
                    _ => None,
                })
                .collect();
            loaded_entries.sort_unstable();
            assert_eq!(list_o_ids, loaded_entries);
        }
        assert_eq!(Vec::<KeyDescriptor>::new(), db.list(Domain::SELINUX, 101)?);

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
        key_type: KeyType,
        domain: Option<Domain>,
        namespace: Option<i64>,
        alias: Option<String>,
        state: KeyLifeCycle,
    }

    fn get_keyentry(db: &KeystoreDB) -> Result<Vec<KeyEntryRow>> {
        db.conn
            .prepare("SELECT * FROM persistent.keyentry;")?
            .query_map(NO_PARAMS, |row| {
                Ok(KeyEntryRow {
                    id: row.get(0)?,
                    key_type: row.get(1)?,
                    domain: match row.get(2)? {
                        Some(i) => Some(Domain(i)),
                        None => None,
                    },
                    namespace: row.get(3)?,
                    alias: row.get(4)?,
                    state: row.get(5)?,
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
        db.insert_blob(&key_id, SubComponentType::KEY_BLOB, TEST_KEY_BLOB)?;
        db.insert_blob(&key_id, SubComponentType::CERT, TEST_CERT_BLOB)?;
        db.insert_blob(&key_id, SubComponentType::CERT_CHAIN, TEST_CERT_CHAIN_BLOB)?;
        db.insert_keyparameter(&key_id, &make_test_params())?;
        let mut metadata = KeyMetaData::new();
        metadata.add(KeyMetaEntry::EncryptedBy(EncryptedBy::Password));
        metadata.add(KeyMetaEntry::Salt(vec![1, 2, 3]));
        metadata.add(KeyMetaEntry::Iv(vec![2, 3, 1]));
        metadata.add(KeyMetaEntry::AeadTag(vec![3, 1, 2]));
        db.insert_key_metadata(&key_id, &metadata)?;
        db.rebind_alias(&key_id, alias, domain, namespace)?;
        Ok(key_id)
    }

    fn make_test_key_entry_test_vector(key_id: i64) -> KeyEntry {
        let mut metadata = KeyMetaData::new();
        metadata.add(KeyMetaEntry::EncryptedBy(EncryptedBy::Password));
        metadata.add(KeyMetaEntry::Salt(vec![1, 2, 3]));
        metadata.add(KeyMetaEntry::Iv(vec![2, 3, 1]));
        metadata.add(KeyMetaEntry::AeadTag(vec![3, 1, 2]));

        KeyEntry {
            id: key_id,
            km_blob: Some(TEST_KEY_BLOB.to_vec()),
            cert: Some(TEST_CERT_BLOB.to_vec()),
            cert_chain: Some(TEST_CERT_CHAIN_BLOB.to_vec()),
            sec_level: SecurityLevel::TRUSTED_ENVIRONMENT,
            parameters: make_test_params(),
            metadata,
        }
    }

    fn debug_dump_keyentry_table(db: &mut KeystoreDB) -> Result<()> {
        let mut stmt = db.conn.prepare(
            "SELECT id, key_type, domain, namespace, alias, state FROM persistent.keyentry;",
        )?;
        let rows = stmt.query_map::<(i64, KeyType, i32, i64, String, KeyLifeCycle), _, _>(
            NO_PARAMS,
            |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
            },
        )?;

        println!("Key entry table rows:");
        for r in rows {
            let (id, key_type, domain, namespace, alias, state) = r.unwrap();
            println!(
                "    id: {} KeyType: {:?} Domain: {} Namespace: {} Alias: {} State: {:?}",
                id, key_type, domain, namespace, alias, state
            );
        }
        Ok(())
    }

    fn debug_dump_grant_table(db: &mut KeystoreDB) -> Result<()> {
        let mut stmt = db
            .conn
            .prepare("SELECT id, grantee, keyentryid, access_vector FROM persistent.grant;")?;
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

    #[test]
    fn test_last_off_body() -> Result<()> {
        let mut db = new_test_db()?;
        KeystoreDB::insert_last_off_body(&db.conn, MonotonicRawTime::now())?;
        let tx = db.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let last_off_body_1 = KeystoreDB::get_last_off_body(&tx)?;
        tx.commit()?;
        let one_second = Duration::from_secs(1);
        thread::sleep(one_second);
        db.update_last_off_body(MonotonicRawTime::now())?;
        let tx2 = db.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let last_off_body_2 = KeystoreDB::get_last_off_body(&tx2)?;
        tx2.commit()?;
        assert!(last_off_body_1.seconds() < last_off_body_2.seconds());
        Ok(())
    }
}
