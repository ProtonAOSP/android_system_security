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

use crate::db_utils::{self, SqlField};
use crate::error::{Error as KsError, ErrorCode, ResponseCode};
use crate::impl_metadata; // This is in db_utils.rs
use crate::key_parameter::{KeyParameter, Tag};
use crate::permission::KeyPermSet;
use crate::utils::get_current_time_in_seconds;
use anyhow::{anyhow, Context, Result};
use std::{convert::TryFrom, convert::TryInto, ops::Deref, time::SystemTimeError};

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken,
    HardwareAuthenticatorType::HardwareAuthenticatorType, SecurityLevel::SecurityLevel,
};
use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
    Timestamp::Timestamp,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor,
};
use android_security_remoteprovisioning::aidl::android::security::remoteprovisioning::{
    AttestationPoolStatus::AttestationPoolStatus,
};

use keystore2_crypto::ZVec;
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
    Connection, OptionalExtension, ToSql, Transaction, TransactionBehavior, NO_PARAMS,
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
        /// CBOR Blob that represents a COSE_Key and associated metadata needed for remote
        /// provisioning
        AttestationMacedPublicKey(Vec<u8>) with accessor attestation_maced_public_key,
        /// Vector representing the raw public key so results from the server can be matched
        /// to the right entry
        AttestationRawPubKey(Vec<u8>) with accessor attestation_raw_pub_key,
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

/// Uuid representation that can be stored in the database.
/// Right now it can only be initialized from SecurityLevel.
/// Once KeyMint provides a UUID type a corresponding From impl shall be added.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid([u8; 16]);

impl Deref for Uuid {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<SecurityLevel> for Uuid {
    fn from(sec_level: SecurityLevel) -> Self {
        Self((sec_level.0 as u128).to_be_bytes())
    }
}

impl ToSql for Uuid {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        self.0.to_sql()
    }
}

impl FromSql for Uuid {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let blob = Vec::<u8>::column_result(value)?;
        if blob.len() != 16 {
            return Err(FromSqlError::OutOfRange(blob.len() as i64));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&blob);
        Ok(Self(arr))
    }
}

/// Key entries that are not associated with any KeyMint instance, such as pure certificate
/// entries are associated with this UUID.
pub static KEYSTORE_UUID: Uuid = Uuid([
    0x41, 0xe3, 0xb9, 0xce, 0x27, 0x58, 0x4e, 0x91, 0xbc, 0xfd, 0xa5, 0x5d, 0x91, 0x85, 0xab, 0x11,
]);

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
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
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

/// This type represents a certificate and certificate chain entry for a key.
#[derive(Debug, Default)]
pub struct CertificateInfo {
    cert: Option<Vec<u8>>,
    cert_chain: Option<Vec<u8>>,
}

impl CertificateInfo {
    /// Constructs a new CertificateInfo object from `cert` and `cert_chain`
    pub fn new(cert: Option<Vec<u8>>, cert_chain: Option<Vec<u8>>) -> Self {
        Self { cert, cert_chain }
    }

    /// Take the cert
    pub fn take_cert(&mut self) -> Option<Vec<u8>> {
        self.cert.take()
    }

    /// Take the cert chain
    pub fn take_cert_chain(&mut self) -> Option<Vec<u8>> {
        self.cert_chain.take()
    }
}

/// This type represents a certificate chain with a private key corresponding to the leaf
/// certificate. TODO(jbires): This will be used in a follow-on CL, for now it's used in the tests.
#[allow(dead_code)]
pub struct CertificateChain {
    private_key: ZVec,
    cert_chain: ZVec,
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
    km_uuid: Uuid,
    parameters: Vec<KeyParameter>,
    metadata: KeyMetaData,
    pure_cert: bool,
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
    /// Returns the uuid of the owning KeyMint instance.
    pub fn km_uuid(&self) -> &Uuid {
        &self.km_uuid
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
    /// This returns true if the entry is a pure certificate entry with no
    /// private key component.
    pub fn pure_cert(&self) -> bool {
        self.pure_cert
    }
}

/// Indicates the sub component of a key entry for persistent storage.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
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

    /// Like i64::checked_sub.
    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
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
    pub fn satisfies(&self, user_secure_ids: &[i64], auth_type: HardwareAuthenticatorType) -> bool {
        user_secure_ids.iter().any(|&sid| {
            (sid == self.auth_token.userId || sid == self.auth_token.authenticatorId)
                && (((auth_type.0 as i32) & (self.auth_token.authenticatorType.0 as i32)) != 0)
        })
    }

    /// Returns the auth token wrapped by the AuthTokenEntry
    pub fn auth_token(&self) -> &HardwareAuthToken {
        &self.auth_token
    }

    /// Returns the auth token wrapped by the AuthTokenEntry
    pub fn take_auth_token(self) -> HardwareAuthToken {
        self.auth_token
    }

    /// Returns the time that this auth token was received.
    pub fn time_received(&self) -> MonotonicRawTime {
        self.time_received
    }
}

/// Shared in-memory databases get destroyed as soon as the last connection to them gets closed.
/// This object does not allow access to the database connection. But it keeps a database
/// connection alive in order to keep the in memory per boot database alive.
pub struct PerBootDbKeepAlive(Connection);

impl KeystoreDB {
    const PERBOOT_DB_FILE_NAME: &'static str = &"file:perboot.sqlite?mode=memory&cache=shared";

    /// This creates a PerBootDbKeepAlive object to keep the per boot database alive.
    pub fn keep_perboot_db_alive() -> Result<PerBootDbKeepAlive> {
        let conn = Connection::open_in_memory()
            .context("In keep_perboot_db_alive: Failed to initialize SQLite connection.")?;

        conn.execute("ATTACH DATABASE ? as perboot;", params![Self::PERBOOT_DB_FILE_NAME])
            .context("In keep_perboot_db_alive: Failed to attach database perboot.")?;
        Ok(PerBootDbKeepAlive(conn))
    }

    /// This will create a new database connection connecting the two
    /// files persistent.sqlite and perboot.sqlite in the given directory.
    /// It also attempts to initialize all of the tables.
    /// KeystoreDB cannot be used by multiple threads.
    /// Each thread should open their own connection using `thread_local!`.
    pub fn new(db_root: &Path) -> Result<Self> {
        // Build the path to the sqlite file.
        let mut persistent_path = db_root.to_path_buf();
        persistent_path.push("persistent.sqlite");

        // Now convert them to strings prefixed with "file:"
        let mut persistent_path_str = "file:".to_owned();
        persistent_path_str.push_str(&persistent_path.to_string_lossy());

        let conn = Self::make_connection(&persistent_path_str, &Self::PERBOOT_DB_FILE_NAME)?;

        // On busy fail Immediately. It is unlikely to succeed given a bug in sqlite.
        conn.busy_handler(None).context("In KeystoreDB::new: Failed to set busy handler.")?;

        let mut db = Self { conn };
        db.with_transaction(TransactionBehavior::Immediate, |tx| {
            Self::init_tables(tx).context("Trying to initialize tables.")
        })?;
        Ok(db)
    }

    fn init_tables(tx: &Transaction) -> Result<()> {
        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.keyentry (
                     id INTEGER UNIQUE,
                     key_type INTEGER,
                     domain INTEGER,
                     namespace INTEGER,
                     alias BLOB,
                     state INTEGER,
                     km_uuid BLOB);",
            NO_PARAMS,
        )
        .context("Failed to initialize \"keyentry\" table.")?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keyentry_id_index
            ON keyentry(id);",
            NO_PARAMS,
        )
        .context("Failed to create index keyentry_id_index.")?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keyentry_domain_namespace_index
            ON keyentry(domain, namespace, alias);",
            NO_PARAMS,
        )
        .context("Failed to create index keyentry_domain_namespace_index.")?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.blobentry (
                    id INTEGER PRIMARY KEY,
                    subcomponent_type INTEGER,
                    keyentryid INTEGER,
                    blob BLOB);",
            NO_PARAMS,
        )
        .context("Failed to initialize \"blobentry\" table.")?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.blobentry_keyentryid_index
            ON blobentry(keyentryid);",
            NO_PARAMS,
        )
        .context("Failed to create index blobentry_keyentryid_index.")?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.keyparameter (
                     keyentryid INTEGER,
                     tag INTEGER,
                     data ANY,
                     security_level INTEGER);",
            NO_PARAMS,
        )
        .context("Failed to initialize \"keyparameter\" table.")?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keyparameter_keyentryid_index
            ON keyparameter(keyentryid);",
            NO_PARAMS,
        )
        .context("Failed to create index keyparameter_keyentryid_index.")?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.keymetadata (
                     keyentryid INTEGER,
                     tag INTEGER,
                     data ANY);",
            NO_PARAMS,
        )
        .context("Failed to initialize \"keymetadata\" table.")?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keymetadata_keyentryid_index
            ON keymetadata(keyentryid);",
            NO_PARAMS,
        )
        .context("Failed to create index keymetadata_keyentryid_index.")?;

        tx.execute(
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
        // tx.execute("DROP TABLE IF EXISTS perboot.authtoken;", NO_PARAMS)
        //     .context("Failed to drop perboot.authtoken table")?;
        tx.execute(
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

        // tx.execute("DROP TABLE IF EXISTS perboot.metadata;", NO_PARAMS)
        //     .context("Failed to drop perboot.metadata table")?;
        // metadata table stores certain miscellaneous information required for keystore functioning
        // during a boot cycle, as key-value pairs.
        tx.execute(
            "CREATE TABLE IF NOT EXISTS perboot.metadata (
                        key TEXT,
                        value BLOB,
                        UNIQUE(key));",
            NO_PARAMS,
        )
        .context("Failed to initialize \"metadata\" table.")?;
        Ok(())
    }

    fn make_connection(persistent_file: &str, perboot_file: &str) -> Result<Connection> {
        let conn =
            Connection::open_in_memory().context("Failed to initialize SQLite connection.")?;

        loop {
            if let Err(e) = conn
                .execute("ATTACH DATABASE ? as persistent;", params![persistent_file])
                .context("Failed to attach database persistent.")
            {
                if Self::is_locked_error(&e) {
                    std::thread::sleep(std::time::Duration::from_micros(500));
                    continue;
                } else {
                    return Err(e);
                }
            }
            break;
        }
        loop {
            if let Err(e) = conn
                .execute("ATTACH DATABASE ? as perboot;", params![perboot_file])
                .context("Failed to attach database perboot.")
            {
                if Self::is_locked_error(&e) {
                    std::thread::sleep(std::time::Duration::from_micros(500));
                    continue;
                } else {
                    return Err(e);
                }
            }
            break;
        }

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
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            tx.execute(
                "UPDATE persistent.keyentry SET state = ? WHERE state = ?;",
                params![KeyLifeCycle::Unreferenced, KeyLifeCycle::Existing],
            )
            .context("Failed to execute query.")
        })
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
        km_uuid: Uuid,
        create_new_key: F,
    ) -> Result<(KeyIdGuard, KeyEntry)>
    where
        F: Fn() -> Result<(Vec<u8>, KeyMetaData)>,
    {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
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
                        (id, key_type, domain, namespace, alias, state, km_uuid)
                        VALUES(?, ?, ?, ?, ?, ?, ?);",
                            params![
                                id,
                                KeyType::Super,
                                domain.0,
                                namespace,
                                alias,
                                KeyLifeCycle::Live,
                                km_uuid,
                            ],
                        )
                    })
                    .context("In get_or_create_key_with.")?;

                    let (blob, metadata) =
                        create_new_key().context("In get_or_create_key_with.")?;
                    Self::set_blob_internal(&tx, id, SubComponentType::KEY_BLOB, Some(&blob))
                        .context("In get_of_create_key_with.")?;
                    metadata.store_in_db(id, &tx).context("In get_or_create_key_with.")?;
                    (
                        id,
                        KeyEntry {
                            id,
                            km_blob: Some(blob),
                            metadata,
                            pure_cert: false,
                            ..Default::default()
                        },
                    )
                }
            };
            Ok((KEY_ID_LOCK.get(id), entry))
        })
        .context("In get_or_create_key_with.")
    }

    /// SQLite3 seems to hold a shared mutex while running the busy handler when
    /// waiting for the database file to become available. This makes it
    /// impossible to successfully recover from a locked database when the
    /// transaction holding the device busy is in the same process on a
    /// different connection. As a result the busy handler has to time out and
    /// fail in order to make progress.
    ///
    /// Instead, we set the busy handler to None (return immediately). And catch
    /// Busy and Locked errors (the latter occur on in memory databases with
    /// shared cache, e.g., the per-boot database.) and restart the transaction
    /// after a grace period of half a millisecond.
    ///
    /// Creates a transaction with the given behavior and executes f with the new transaction.
    /// The transaction is committed only if f returns Ok and retried if DatabaseBusy
    /// or DatabaseLocked is encountered.
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

    /// Creates a new key entry and allocates a new randomized id for the new key.
    /// The key id gets associated with a domain and namespace but not with an alias.
    /// To complete key generation `rebind_alias` should be called after all of the
    /// key artifacts, i.e., blobs and parameters have been associated with the new
    /// key id. Finalizing with `rebind_alias` makes the creation of a new key entry
    /// atomic even if key generation is not.
    pub fn create_key_entry(
        &mut self,
        domain: &Domain,
        namespace: &i64,
        km_uuid: &Uuid,
    ) -> Result<KeyIdGuard> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            Self::create_key_entry_internal(tx, domain, namespace, km_uuid)
        })
        .context("In create_key_entry.")
    }

    fn create_key_entry_internal(
        tx: &Transaction,
        domain: &Domain,
        namespace: &i64,
        km_uuid: &Uuid,
    ) -> Result<KeyIdGuard> {
        match *domain {
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
                     (id, key_type, domain, namespace, alias, state, km_uuid)
                     VALUES(?, ?, ?, ?, NULL, ?, ?);",
                    params![
                        id,
                        KeyType::Client,
                        domain.0 as u32,
                        *namespace,
                        KeyLifeCycle::Existing,
                        km_uuid,
                    ],
                )
            })
            .context("In create_key_entry_internal")?,
        ))
    }

    /// Creates a new attestation key entry and allocates a new randomized id for the new key.
    /// The key id gets associated with a domain and namespace later but not with an alias. The
    /// alias will be used to denote if a key has been signed as each key can only be bound to one
    /// domain and namespace pairing so there is no need to use them as a value for indexing into
    /// a key.
    pub fn create_attestation_key_entry(
        &mut self,
        maced_public_key: &[u8],
        raw_public_key: &[u8],
        private_key: &[u8],
        km_uuid: &Uuid,
    ) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            let key_id = KEY_ID_LOCK.get(
                Self::insert_with_retry(|id| {
                    tx.execute(
                        "INSERT into persistent.keyentry
                            (id, key_type, domain, namespace, alias, state, km_uuid)
                            VALUES(?, ?, NULL, NULL, NULL, ?, ?);",
                        params![id, KeyType::Attestation, KeyLifeCycle::Live, km_uuid],
                    )
                })
                .context("In create_key_entry")?,
            );
            Self::set_blob_internal(&tx, key_id.0, SubComponentType::KEY_BLOB, Some(private_key))?;
            let mut metadata = KeyMetaData::new();
            metadata.add(KeyMetaEntry::AttestationMacedPublicKey(maced_public_key.to_vec()));
            metadata.add(KeyMetaEntry::AttestationRawPubKey(raw_public_key.to_vec()));
            metadata.store_in_db(key_id.0, &tx)?;
            Ok(())
        })
        .context("In create_attestation_key_entry")
    }

    /// Set a new blob and associates it with the given key id. Each blob
    /// has a sub component type.
    /// Each key can have one of each sub component type associated. If more
    /// are added only the most recent can be retrieved, and superseded blobs
    /// will get garbage collected.
    /// Components SubComponentType::CERT and SubComponentType::CERT_CHAIN can be
    /// removed by setting blob to None.
    pub fn set_blob(
        &mut self,
        key_id: &KeyIdGuard,
        sc_type: SubComponentType,
        blob: Option<&[u8]>,
    ) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            Self::set_blob_internal(&tx, key_id.0, sc_type, blob)
        })
        .context("In set_blob.")
    }

    fn set_blob_internal(
        tx: &Transaction,
        key_id: i64,
        sc_type: SubComponentType,
        blob: Option<&[u8]>,
    ) -> Result<()> {
        match (blob, sc_type) {
            (Some(blob), _) => {
                tx.execute(
                    "INSERT INTO persistent.blobentry
                     (subcomponent_type, keyentryid, blob) VALUES (?, ?, ?);",
                    params![sc_type, key_id, blob],
                )
                .context("In set_blob_internal: Failed to insert blob.")?;
            }
            (None, SubComponentType::CERT) | (None, SubComponentType::CERT_CHAIN) => {
                tx.execute(
                    "DELETE FROM persistent.blobentry
                    WHERE subcomponent_type = ? AND keyentryid = ?;",
                    params![sc_type, key_id],
                )
                .context("In set_blob_internal: Failed to delete blob.")?;
            }
            (None, _) => {
                return Err(KsError::sys())
                    .context("In set_blob_internal: Other blobs cannot be deleted in this way.");
            }
        }
        Ok(())
    }

    /// Inserts a collection of key parameters into the `persistent.keyparameter` table
    /// and associates them with the given `key_id`.
    pub fn insert_keyparameter(
        &mut self,
        key_id: &KeyIdGuard,
        params: &[KeyParameter],
    ) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            Self::insert_keyparameter_internal(tx, key_id, params)
        })
        .context("In insert_keyparameter.")
    }

    fn insert_keyparameter_internal(
        tx: &Transaction,
        key_id: &KeyIdGuard,
        params: &[KeyParameter],
    ) -> Result<()> {
        let mut stmt = tx
            .prepare(
                "INSERT into persistent.keyparameter (keyentryid, tag, data, security_level)
                VALUES (?, ?, ?, ?);",
            )
            .context("In insert_keyparameter_internal: Failed to prepare statement.")?;

        for p in params.iter() {
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

    /// Stores a signed certificate chain signed by a remote provisioning server, keyed
    /// on the public key.
    pub fn store_signed_attestation_certificate_chain(
        &mut self,
        raw_public_key: &[u8],
        cert_chain: &[u8],
        expiration_date: i64,
        km_uuid: &Uuid,
    ) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            let mut stmt = tx
                .prepare(
                    "SELECT keyentryid
                    FROM persistent.keymetadata
                    WHERE tag = ? AND data = ? AND keyentryid IN
                    (SELECT id
                     FROM persistent.keyentry
                     WHERE
                        alias IS NULL AND
                        domain IS NULL AND
                        namespace IS NULL AND
                        key_type = ? AND
                        km_uuid = ?);",
                )
                .context("Failed to store attestation certificate chain.")?;
            let mut rows = stmt
                .query(params![
                    KeyMetaData::AttestationRawPubKey,
                    raw_public_key,
                    KeyType::Attestation,
                    km_uuid
                ])
                .context("Failed to fetch keyid")?;
            let key_id = db_utils::with_rows_extract_one(&mut rows, |row| {
                row.map_or_else(|| Err(KsError::Rc(ResponseCode::KEY_NOT_FOUND)), Ok)?
                    .get(0)
                    .context("Failed to unpack id.")
            })
            .context("Failed to get key_id.")?;
            let num_updated = tx
                .execute(
                    "UPDATE persistent.keyentry
                    SET alias = ?
                    WHERE id = ?;",
                    params!["signed", key_id],
                )
                .context("Failed to update alias.")?;
            if num_updated != 1 {
                return Err(KsError::sys()).context("Alias not updated for the key.");
            }
            let mut metadata = KeyMetaData::new();
            metadata.add(KeyMetaEntry::AttestationExpirationDate(DateTime::from_millis_epoch(
                expiration_date,
            )));
            metadata.store_in_db(key_id, &tx).context("Failed to insert key metadata.")?;
            Self::set_blob_internal(&tx, key_id, SubComponentType::CERT_CHAIN, Some(cert_chain))
                .context("Failed to insert cert chain")?;
            Ok(())
        })
        .context("In store_signed_attestation_certificate_chain: ")
    }

    /// Assigns the next unassigned attestation key to a domain/namespace combo that does not
    /// currently have a key assigned to it.
    pub fn assign_attestation_key(
        &mut self,
        domain: Domain,
        namespace: i64,
        km_uuid: &Uuid,
    ) -> Result<()> {
        match domain {
            Domain::APP | Domain::SELINUX => {}
            _ => {
                return Err(KsError::sys()).context(format!(
                    concat!(
                        "In assign_attestation_key: Domain {:?} ",
                        "must be either App or SELinux.",
                    ),
                    domain
                ));
            }
        }
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            let result = tx
                .execute(
                    "UPDATE persistent.keyentry
                        SET domain=?1, namespace=?2
                        WHERE
                            id =
                                (SELECT MIN(id)
                                FROM persistent.keyentry
                                WHERE ALIAS IS NOT NULL
                                    AND domain IS NULL
                                    AND key_type IS ?3
                                    AND state IS ?4
                                    AND km_uuid IS ?5)
                            AND
                                (SELECT COUNT(*)
                                FROM persistent.keyentry
                                WHERE domain=?1
                                    AND namespace=?2
                                    AND key_type IS ?3
                                    AND state IS ?4
                                    AND km_uuid IS ?5) = 0;",
                    params![
                        domain.0 as u32,
                        namespace,
                        KeyType::Attestation,
                        KeyLifeCycle::Live,
                        km_uuid,
                    ],
                )
                .context("Failed to assign attestation key")?;
            if result != 1 {
                return Err(KsError::sys()).context(format!(
                    "Expected to update a single entry but instead updated {}.",
                    result
                ));
            }
            Ok(())
        })
        .context("In assign_attestation_key: ")
    }

    /// Retrieves num_keys number of attestation keys that have not yet been signed by a remote
    /// provisioning server, or the maximum number available if there are not num_keys number of
    /// entries in the table.
    pub fn fetch_unsigned_attestation_keys(
        &mut self,
        num_keys: i32,
        km_uuid: &Uuid,
    ) -> Result<Vec<Vec<u8>>> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            let mut stmt = tx
                .prepare(
                    "SELECT data
                    FROM persistent.keymetadata
                    WHERE tag = ? AND keyentryid IN
                        (SELECT id
                        FROM persistent.keyentry
                        WHERE
                            alias IS NULL AND
                            domain IS NULL AND
                            namespace IS NULL AND
                            key_type = ? AND
                            km_uuid = ?
                        LIMIT ?);",
                )
                .context("Failed to prepare statement")?;
            let rows = stmt
                .query_map(
                    params![
                        KeyMetaData::AttestationMacedPublicKey,
                        KeyType::Attestation,
                        km_uuid,
                        num_keys
                    ],
                    |row| Ok(row.get(0)?),
                )?
                .collect::<rusqlite::Result<Vec<Vec<u8>>>>()
                .context("Failed to execute statement")?;
            Ok(rows)
        })
        .context("In fetch_unsigned_attestation_keys")
    }

    /// Removes any keys that have expired as of the current time. Returns the number of keys
    /// marked unreferenced that are bound to be garbage collected.
    pub fn delete_expired_attestation_keys(&mut self) -> Result<i32> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            let mut stmt = tx
                .prepare(
                    "SELECT keyentryid, data
                     FROM persistent.keymetadata
                     WHERE tag = ? AND keyentryid IN
                         (SELECT id
                         FROM persistent.keyentry
                         WHERE key_type = ?);",
                )
                .context("Failed to prepare query")?;
            let key_ids_to_check = stmt
                .query_map(
                    params![KeyMetaData::AttestationExpirationDate, KeyType::Attestation],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?
                .collect::<rusqlite::Result<Vec<(i64, DateTime)>>>()
                .context("Failed to get date metadata")?;
            let curr_time = DateTime::from_millis_epoch(
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_millis() as i64,
            );
            let mut num_deleted = 0;
            for id in key_ids_to_check.iter().filter(|kt| kt.1 < curr_time).map(|kt| kt.0) {
                if Self::mark_unreferenced(&tx, id)? {
                    num_deleted += 1;
                }
            }
            Ok(num_deleted)
        })
        .context("In delete_expired_attestation_keys: ")
    }

    /// Counts the number of keys that will expire by the provided epoch date and the number of
    /// keys not currently assigned to a domain.
    pub fn get_attestation_pool_status(
        &mut self,
        date: i64,
        km_uuid: &Uuid,
    ) -> Result<AttestationPoolStatus> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            let mut stmt = tx.prepare(
                "SELECT data
                 FROM persistent.keymetadata
                 WHERE tag = ? AND keyentryid IN
                     (SELECT id
                      FROM persistent.keyentry
                      WHERE alias IS NOT NULL
                            AND key_type = ?
                            AND km_uuid = ?
                            AND state = ?);",
            )?;
            let times = stmt
                .query_map(
                    params![
                        KeyMetaData::AttestationExpirationDate,
                        KeyType::Attestation,
                        km_uuid,
                        KeyLifeCycle::Live
                    ],
                    |row| Ok(row.get(0)?),
                )?
                .collect::<rusqlite::Result<Vec<DateTime>>>()
                .context("Failed to execute metadata statement")?;
            let expiring =
                times.iter().filter(|time| time < &&DateTime::from_millis_epoch(date)).count()
                    as i32;
            stmt = tx.prepare(
                "SELECT alias, domain
                 FROM persistent.keyentry
                 WHERE key_type = ? AND km_uuid = ? AND state = ?;",
            )?;
            let rows = stmt
                .query_map(params![KeyType::Attestation, km_uuid, KeyLifeCycle::Live], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?
                .collect::<rusqlite::Result<Vec<(Option<String>, Option<u32>)>>>()
                .context("Failed to execute keyentry statement")?;
            let mut unassigned = 0i32;
            let mut attested = 0i32;
            let total = rows.len() as i32;
            for (alias, domain) in rows {
                match (alias, domain) {
                    (Some(_alias), None) => {
                        attested += 1;
                        unassigned += 1;
                    }
                    (Some(_alias), Some(_domain)) => {
                        attested += 1;
                    }
                    _ => {}
                }
            }
            Ok(AttestationPoolStatus { expiring, unassigned, attested, total })
        })
        .context("In get_attestation_pool_status: ")
    }

    /// Fetches the private key and corresponding certificate chain assigned to a
    /// domain/namespace pair. Will either return nothing if the domain/namespace is
    /// not assigned, or one CertificateChain.
    pub fn retrieve_attestation_key_and_cert_chain(
        &mut self,
        domain: Domain,
        namespace: i64,
        km_uuid: &Uuid,
    ) -> Result<Option<CertificateChain>> {
        match domain {
            Domain::APP | Domain::SELINUX => {}
            _ => {
                return Err(KsError::sys())
                    .context(format!("Domain {:?} must be either App or SELinux.", domain));
            }
        }
        let mut stmt = self.conn.prepare(
            "SELECT subcomponent_type, blob
             FROM persistent.blobentry
             WHERE keyentryid IN
                (SELECT id
                 FROM persistent.keyentry
                 WHERE key_type = ?
                       AND domain = ?
                       AND namespace = ?
                       AND state = ?
                       AND km_uuid = ?);",
        )?;
        let rows = stmt
            .query_map(
                params![
                    KeyType::Attestation,
                    domain.0 as u32,
                    namespace,
                    KeyLifeCycle::Live,
                    km_uuid
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?
            .collect::<rusqlite::Result<Vec<(SubComponentType, Vec<u8>)>>>()
            .context("In retrieve_attestation_key_and_cert_chain: query failed.")?;
        if rows.is_empty() {
            return Ok(None);
        } else if rows.len() != 2 {
            return Err(KsError::sys()).context(format!(
                concat!(
                "In retrieve_attestation_key_and_cert_chain: Expected to get a single attestation",
                "key chain but instead got {}."),
                rows.len()
            ));
        }
        let mut km_blob: Vec<u8> = Vec::new();
        let mut cert_chain_blob: Vec<u8> = Vec::new();
        for row in rows {
            let sub_type: SubComponentType = row.0;
            match sub_type {
                SubComponentType::KEY_BLOB => {
                    km_blob = row.1;
                }
                SubComponentType::CERT_CHAIN => {
                    cert_chain_blob = row.1;
                }
                _ => Err(KsError::sys()).context("Unknown or incorrect subcomponent type.")?,
            }
        }
        Ok(Some(CertificateChain {
            private_key: ZVec::try_from(km_blob)?,
            cert_chain: ZVec::try_from(cert_chain_blob)?,
        }))
    }

    /// Updates the alias column of the given key id `newid` with the given alias,
    /// and atomically, removes the alias, domain, and namespace from another row
    /// with the same alias-domain-namespace tuple if such row exits.
    /// Returns Ok(true) if an old key was marked unreferenced as a hint to the garbage
    /// collector.
    fn rebind_alias(
        tx: &Transaction,
        newid: &KeyIdGuard,
        alias: &str,
        domain: &Domain,
        namespace: &i64,
    ) -> Result<bool> {
        match *domain {
            Domain::APP | Domain::SELINUX => {}
            _ => {
                return Err(KsError::sys()).context(format!(
                    "In rebind_alias: Domain {:?} must be either App or SELinux.",
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
            .context("In rebind_alias: Failed to rebind existing entry.")?;
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
                    *namespace,
                    KeyLifeCycle::Existing,
                ],
            )
            .context("In rebind_alias: Failed to set alias.")?;
        if result != 1 {
            return Err(KsError::sys()).context(format!(
                "In rebind_alias: Expected to update a single entry but instead updated {}.",
                result
            ));
        }
        Ok(updated != 0)
    }

    /// Store a new key in a single transaction.
    /// The function creates a new key entry, populates the blob, key parameter, and metadata
    /// fields, and rebinds the given alias to the new key.
    /// The boolean returned is a hint for the garbage collector. If true, a key was replaced,
    /// is now unreferenced and needs to be collected.
    pub fn store_new_key(
        &mut self,
        key: &KeyDescriptor,
        params: &[KeyParameter],
        blob: &[u8],
        cert_info: &CertificateInfo,
        metadata: &KeyMetaData,
        km_uuid: &Uuid,
    ) -> Result<(bool, KeyIdGuard)> {
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
            let key_id = Self::create_key_entry_internal(tx, &domain, namespace, km_uuid)
                .context("Trying to create new key entry.")?;
            Self::set_blob_internal(tx, key_id.id(), SubComponentType::KEY_BLOB, Some(blob))
                .context("Trying to insert the key blob.")?;
            if let Some(cert) = &cert_info.cert {
                Self::set_blob_internal(tx, key_id.id(), SubComponentType::CERT, Some(&cert))
                    .context("Trying to insert the certificate.")?;
            }
            if let Some(cert_chain) = &cert_info.cert_chain {
                Self::set_blob_internal(
                    tx,
                    key_id.id(),
                    SubComponentType::CERT_CHAIN,
                    Some(&cert_chain),
                )
                .context("Trying to insert the certificate chain.")?;
            }
            Self::insert_keyparameter_internal(tx, &key_id, params)
                .context("Trying to insert key parameters.")?;
            metadata.store_in_db(key_id.id(), tx).context("Trying to insert key metadata.")?;
            let need_gc = Self::rebind_alias(tx, &key_id, &alias, &domain, namespace)
                .context("Trying to rebind alias.")?;
            Ok((need_gc, key_id))
        })
        .context("In store_new_key.")
    }

    /// Store a new certificate
    /// The function creates a new key entry, populates the blob field and metadata, and rebinds
    /// the given alias to the new cert.
    pub fn store_new_certificate(
        &mut self,
        key: &KeyDescriptor,
        cert: &[u8],
        km_uuid: &Uuid,
    ) -> Result<KeyIdGuard> {
        let (alias, domain, namespace) = match key {
            KeyDescriptor { alias: Some(alias), domain: Domain::APP, nspace, blob: None }
            | KeyDescriptor { alias: Some(alias), domain: Domain::SELINUX, nspace, blob: None } => {
                (alias, key.domain, nspace)
            }
            _ => {
                return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT)).context(
                    "In store_new_certificate: Need alias and domain must be APP or SELINUX.",
                )
            }
        };
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            let key_id = Self::create_key_entry_internal(tx, &domain, namespace, km_uuid)
                .context("Trying to create new key entry.")?;

            Self::set_blob_internal(tx, key_id.id(), SubComponentType::CERT_CHAIN, Some(cert))
                .context("Trying to insert certificate.")?;

            let mut metadata = KeyMetaData::new();
            metadata.add(KeyMetaEntry::CreationDate(
                DateTime::now().context("Trying to make creation time.")?,
            ));

            metadata.store_in_db(key_id.id(), tx).context("Trying to insert key metadata.")?;

            Self::rebind_alias(tx, &key_id, &alias, &domain, namespace)
                .context("Trying to rebind alias.")?;
            Ok(key_id)
        })
        .context("In store_new_certificate.")
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
        key: &KeyDescriptor,
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
                let mut access_key = key.clone();
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
                Ok((key_id, key.clone(), Some(access_vector.into())))
            }

            // Domain::KEY_ID. In this case we load the domain and namespace from the
            // keyentry database because we need them for access control.
            Domain::KEY_ID => {
                let (domain, namespace): (Domain, i64) = {
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
                    db_utils::with_rows_extract_one(&mut rows, |row| {
                        let r =
                            row.map_or_else(|| Err(KsError::Rc(ResponseCode::KEY_NOT_FOUND)), Ok)?;
                        Ok((
                            Domain(r.get(0).context("Failed to unpack domain.")?),
                            r.get(1).context("Failed to unpack namespace.")?,
                        ))
                    })
                    .context("Domain::KEY_ID.")?
                };

                // We may use a key by id after loading it by grant.
                // In this case we have to check if the caller has a grant for this particular
                // key. We can skip this if we already know that the caller is the owner.
                // But we cannot know this if domain is anything but App. E.g. in the case
                // of Domain::SELINUX we have to speculatively check for grants because we have to
                // consult the SEPolicy before we know if the caller is the owner.
                let access_vector: Option<KeyPermSet> =
                    if domain != Domain::APP || namespace != caller_uid as i64 {
                        let access_vector: Option<i32> = tx
                            .query_row(
                                "SELECT access_vector FROM persistent.grant
                                WHERE grantee = ? AND keyentryid = ?;",
                                params![caller_uid as i64, key.nspace],
                                |row| row.get(0),
                            )
                            .optional()
                            .context("Domain::KEY_ID: query grant failed.")?;
                        access_vector.map(|p| p.into())
                    } else {
                        None
                    };

                let key_id = key.nspace;
                let mut access_key: KeyDescriptor = key.clone();
                access_key.domain = domain;
                access_key.nspace = namespace;

                Ok((key_id, access_key, access_vector))
            }
            _ => Err(anyhow!(KsError::sys())),
        }
    }

    fn load_blob_components(
        key_id: i64,
        load_bits: KeyEntryLoadBits,
        tx: &Transaction,
    ) -> Result<(bool, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> {
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
        let mut has_km_blob: bool = false;
        db_utils::with_rows_extract_all(&mut rows, |row| {
            let sub_type: SubComponentType =
                row.get(1).context("Failed to extract subcomponent_type.")?;
            has_km_blob = has_km_blob || sub_type == SubComponentType::KEY_BLOB;
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

        Ok((has_km_blob, km_blob, cert_blob, cert_chain_blob))
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

    /// Decrements the usage count of a limited use key. This function first checks whether the
    /// usage has been exhausted, if not, decreases the usage count. If the usage count reaches
    /// zero, the key also gets marked unreferenced and scheduled for deletion.
    /// Returns Ok(true) if the key was marked unreferenced as a hint to the garbage collector.
    pub fn check_and_update_key_usage_count(&mut self, key_id: i64) -> Result<bool> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            let limit: Option<i32> = tx
                .query_row(
                    "SELECT data FROM persistent.keyparameter WHERE keyentryid = ? AND tag = ?;",
                    params![key_id, Tag::USAGE_COUNT_LIMIT.0],
                    |row| row.get(0),
                )
                .optional()
                .context("Trying to load usage count")?;

            let limit = limit
                .ok_or(KsError::Km(ErrorCode::INVALID_KEY_BLOB))
                .context("The Key no longer exists. Key is exhausted.")?;

            tx.execute(
                "UPDATE persistent.keyparameter
                 SET data = data - 1
                 WHERE keyentryid = ? AND tag = ? AND data > 0;",
                params![key_id, Tag::USAGE_COUNT_LIMIT.0],
            )
            .context("Failed to update key usage count.")?;

            match limit {
                1 => Self::mark_unreferenced(tx, key_id)
                    .context("Trying to mark limited use key for deletion."),
                0 => Err(KsError::Km(ErrorCode::INVALID_KEY_BLOB)).context("Key is exhausted."),
                _ => Ok(false),
            }
        })
        .context("In check_and_update_key_usage_count.")
    }

    /// Load a key entry by the given key descriptor.
    /// It uses the `check_permission` callback to verify if the access is allowed
    /// given the key access tuple read from the database using `load_access_tuple`.
    /// With `load_bits` the caller may specify which blobs shall be loaded from
    /// the blob database.
    pub fn load_key_entry(
        &mut self,
        key: &KeyDescriptor,
        key_type: KeyType,
        load_bits: KeyEntryLoadBits,
        caller_uid: u32,
        check_permission: impl Fn(&KeyDescriptor, Option<KeyPermSet>) -> Result<()>,
    ) -> Result<(KeyIdGuard, KeyEntry)> {
        loop {
            match self.load_key_entry_internal(
                key,
                key_type,
                load_bits,
                caller_uid,
                &check_permission,
            ) {
                Ok(result) => break Ok(result),
                Err(e) => {
                    if Self::is_locked_error(&e) {
                        std::thread::sleep(std::time::Duration::from_micros(500));
                        continue;
                    } else {
                        return Err(e).context("In load_key_entry.");
                    }
                }
            }
        }
    }

    fn load_key_entry_internal(
        &mut self,
        key: &KeyDescriptor,
        key_type: KeyType,
        load_bits: KeyEntryLoadBits,
        caller_uid: u32,
        check_permission: &impl Fn(&KeyDescriptor, Option<KeyPermSet>) -> Result<()>,
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
                    let tx = self
                        .conn
                        .unchecked_transaction()
                        .context("In load_key_entry: Failed to initialize transaction.")?;

                    Self::load_access_tuple(
                        &tx,
                        // This time we have to load the key by the retrieved key id, because the
                        // alias may have been rebound after we rolled back the transaction.
                        &KeyDescriptor {
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

    fn mark_unreferenced(tx: &Transaction, key_id: i64) -> Result<bool> {
        let updated = tx
            .execute(
                "UPDATE persistent.keyentry SET state = ? WHERE id = ?;",
                params![KeyLifeCycle::Unreferenced, key_id],
            )
            .context("In mark_unreferenced: Failed to update state of key entry.")?;
        tx.execute("DELETE from persistent.grant WHERE keyentryid = ?;", params![key_id])
            .context("In mark_unreferenced: Failed to drop grants.")?;
        Ok(updated != 0)
    }

    /// Marks the given key as unreferenced and removes all of the grants to this key.
    /// Returns Ok(true) if a key was marked unreferenced as a hint for the garbage collector.
    pub fn unbind_key(
        &mut self,
        key: &KeyDescriptor,
        key_type: KeyType,
        caller_uid: u32,
        check_permission: impl Fn(&KeyDescriptor, Option<KeyPermSet>) -> Result<()>,
    ) -> Result<bool> {
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

    fn get_key_km_uuid(tx: &Transaction, key_id: i64) -> Result<Uuid> {
        tx.query_row(
            "SELECT km_uuid FROM persistent.keyentry WHERE id = ?",
            params![key_id],
            |row| row.get(0),
        )
        .context("In get_key_km_uuid.")
    }

    fn load_key_components(
        tx: &Transaction,
        load_bits: KeyEntryLoadBits,
        key_id: i64,
    ) -> Result<KeyEntry> {
        let metadata = KeyMetaData::load_from_db(key_id, &tx).context("In load_key_components.")?;

        let (has_km_blob, km_blob, cert_blob, cert_chain_blob) =
            Self::load_blob_components(key_id, load_bits, &tx)
                .context("In load_key_components.")?;

        let parameters = Self::load_key_parameters(key_id, &tx)
            .context("In load_key_components: Trying to load key parameters.")?;

        let km_uuid = Self::get_key_km_uuid(&tx, key_id)
            .context("In load_key_components: Trying to get KM uuid.")?;

        Ok(KeyEntry {
            id: key_id,
            km_blob,
            cert: cert_blob,
            cert_chain: cert_chain_blob,
            km_uuid,
            parameters,
            metadata,
            pure_cert: !has_km_blob,
        })
    }

    /// Returns a list of KeyDescriptors in the selected domain/namespace.
    /// The key descriptors will have the domain, nspace, and alias field set.
    /// Domain must be APP or SELINUX, the caller must make sure of that.
    pub fn list(&mut self, domain: Domain, namespace: i64) -> Result<Vec<KeyDescriptor>> {
        self.with_transaction(TransactionBehavior::Deferred, |tx| {
            let mut stmt = tx
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
            .context("In list: Failed to extract rows.")?;
            Ok(descriptors)
        })
    }

    /// Adds a grant to the grant table.
    /// Like `load_key_entry` this function loads the access tuple before
    /// it uses the callback for a permission check. Upon success,
    /// it inserts the `grantee_uid`, `key_id`, and `access_vector` into the
    /// grant table. The new row will have a randomized id, which is used as
    /// grant id in the namespace field of the resulting KeyDescriptor.
    pub fn grant(
        &mut self,
        key: &KeyDescriptor,
        caller_uid: u32,
        grantee_uid: u32,
        access_vector: KeyPermSet,
        check_permission: impl Fn(&KeyDescriptor, &KeyPermSet) -> Result<()>,
    ) -> Result<KeyDescriptor> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
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
                Self::load_access_tuple(&tx, key, KeyType::Client, caller_uid)
                    .context("In grant")?;

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

            Ok(KeyDescriptor { domain: Domain::GRANT, nspace: grant_id, alias: None, blob: None })
        })
    }

    /// This function checks permissions like `grant` and `load_key_entry`
    /// before removing a grant from the grant table.
    pub fn ungrant(
        &mut self,
        key: &KeyDescriptor,
        caller_uid: u32,
        grantee_uid: u32,
        check_permission: impl Fn(&KeyDescriptor) -> Result<()>,
    ) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            // Load the key_id and complete the access control tuple.
            // We ignore the access vector here because grants cannot be granted.
            let (key_id, access_key_descriptor, _) =
                Self::load_access_tuple(&tx, key, KeyType::Client, caller_uid)
                    .context("In ungrant.")?;

            // Perform access control. We must return here if the permission
            // was denied. So do not touch the '?' at the end of this line.
            check_permission(&access_key_descriptor)
                .context("In grant: check_permission failed.")?;

            tx.execute(
                "DELETE FROM persistent.grant
                WHERE keyentryid = ? AND grantee = ?;",
                params![key_id, grantee_uid],
            )
            .context("Failed to delete grant.")?;

            Ok(())
        })
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
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            tx.execute(
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
        })
    }

    /// Find the newest auth token matching the given predicate.
    pub fn find_auth_token_entry<F>(
        &mut self,
        p: F,
    ) -> Result<Option<(AuthTokenEntry, MonotonicRawTime)>>
    where
        F: Fn(&AuthTokenEntry) -> bool,
    {
        self.with_transaction(TransactionBehavior::Deferred, |tx| {
            let mut stmt = tx
                .prepare("SELECT * from perboot.authtoken ORDER BY time_received DESC;")
                .context("Prepare statement failed.")?;

            let mut rows = stmt.query(NO_PARAMS).context("Failed to query.")?;

            while let Some(row) = rows.next().context("Failed to get next row.")? {
                let entry = AuthTokenEntry::new(
                    HardwareAuthToken {
                        challenge: row.get(1)?,
                        userId: row.get(2)?,
                        authenticatorId: row.get(3)?,
                        authenticatorType: HardwareAuthenticatorType(row.get(4)?),
                        timestamp: Timestamp { milliSeconds: row.get(5)? },
                        mac: row.get(6)?,
                    },
                    row.get(7)?,
                );
                if p(&entry) {
                    return Ok(Some((
                        entry,
                        Self::get_last_off_body(tx)
                            .context("In find_auth_token_entry: Trying to get last off body")?,
                    )));
                }
            }
            Ok(None)
        })
        .context("In find_auth_token_entry.")
    }

    /// Insert last_off_body into the metadata table at the initialization of auth token table
    pub fn insert_last_off_body(&mut self, last_off_body: MonotonicRawTime) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            tx.execute(
                "INSERT OR REPLACE INTO perboot.metadata (key, value) VALUES (?, ?);",
                params!["last_off_body", last_off_body],
            )
            .context("In insert_last_off_body: failed to insert.")?;
            Ok(())
        })
    }

    /// Update last_off_body when on_device_off_body is called
    pub fn update_last_off_body(&mut self, last_off_body: MonotonicRawTime) -> Result<()> {
        self.with_transaction(TransactionBehavior::Immediate, |tx| {
            tx.execute(
                "UPDATE perboot.metadata SET value = ? WHERE key = ?;",
                params![last_off_body, "last_off_body"],
            )
            .context("In update_last_off_body: failed to update.")?;
            Ok(())
        })
    }

    /// Get last_off_body time when finding auth tokens
    fn get_last_off_body(tx: &Transaction) -> Result<MonotonicRawTime> {
        tx.query_row(
            "SELECT value from perboot.metadata WHERE key = ?;",
            params!["last_off_body"],
            |row| Ok(row.get(0)?),
        )
        .context("In get_last_off_body: query_row failed.")
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
    use keystore2_test_utils::TempDir;
    use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
        HardwareAuthToken::HardwareAuthToken,
        HardwareAuthenticatorType::HardwareAuthenticatorType as kmhw_authenticator_type,
    };
    use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
        Timestamp::Timestamp,
    };
    use rusqlite::NO_PARAMS;
    use rusqlite::{Error, TransactionBehavior};
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, SystemTime};
    #[cfg(disabled)]
    use std::time::Instant;

    fn new_test_db() -> Result<KeystoreDB> {
        let conn = KeystoreDB::make_connection("file::memory:", "file::memory:")?;

        let mut db = KeystoreDB { conn };
        db.with_transaction(TransactionBehavior::Immediate, |tx| {
            KeystoreDB::init_tables(tx).context("Failed to initialize tables.")
        })?;
        Ok(db)
    }

    fn rebind_alias(
        db: &mut KeystoreDB,
        newid: &KeyIdGuard,
        alias: &str,
        domain: Domain,
        namespace: i64,
    ) -> Result<bool> {
        db.with_transaction(TransactionBehavior::Immediate, |tx| {
            KeystoreDB::rebind_alias(tx, newid, alias, &domain, &namespace)
        })
        .context("In rebind_alias.")
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

        db.create_key_entry(&Domain::APP, &100, &KEYSTORE_UUID)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 1);

        let db = KeystoreDB::new(temp_dir.path())?;

        let entries_new = get_keyentry(&db)?;
        assert_eq!(entries, entries_new);
        Ok(())
    }

    #[test]
    fn test_create_key_entry() -> Result<()> {
        fn extractor(ke: &KeyEntryRow) -> (Domain, i64, Option<&str>, Uuid) {
            (ke.domain.unwrap(), ke.namespace.unwrap(), ke.alias.as_deref(), ke.km_uuid.unwrap())
        }

        let mut db = new_test_db()?;

        db.create_key_entry(&Domain::APP, &100, &KEYSTORE_UUID)?;
        db.create_key_entry(&Domain::SELINUX, &101, &KEYSTORE_UUID)?;

        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(extractor(&entries[0]), (Domain::APP, 100, None, KEYSTORE_UUID));
        assert_eq!(extractor(&entries[1]), (Domain::SELINUX, 101, None, KEYSTORE_UUID));

        // Test that we must pass in a valid Domain.
        check_result_is_error_containing_string(
            db.create_key_entry(&Domain::GRANT, &102, &KEYSTORE_UUID),
            "Domain Domain(1) must be either App or SELinux.",
        );
        check_result_is_error_containing_string(
            db.create_key_entry(&Domain::BLOB, &103, &KEYSTORE_UUID),
            "Domain Domain(3) must be either App or SELinux.",
        );
        check_result_is_error_containing_string(
            db.create_key_entry(&Domain::KEY_ID, &104, &KEYSTORE_UUID),
            "Domain Domain(4) must be either App or SELinux.",
        );

        Ok(())
    }

    #[test]
    fn test_add_unsigned_key() -> Result<()> {
        let mut db = new_test_db()?;
        let public_key: Vec<u8> = vec![0x01, 0x02, 0x03];
        let private_key: Vec<u8> = vec![0x04, 0x05, 0x06];
        let raw_public_key: Vec<u8> = vec![0x07, 0x08, 0x09];
        db.create_attestation_key_entry(
            &public_key,
            &raw_public_key,
            &private_key,
            &KEYSTORE_UUID,
        )?;
        let keys = db.fetch_unsigned_attestation_keys(5, &KEYSTORE_UUID)?;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], public_key);
        Ok(())
    }

    #[test]
    fn test_store_signed_attestation_certificate_chain() -> Result<()> {
        let mut db = new_test_db()?;
        let expiration_date: i64 = 20;
        let namespace: i64 = 30;
        let base_byte: u8 = 1;
        let loaded_values =
            load_attestation_key_pool(&mut db, expiration_date, namespace, base_byte)?;
        let chain =
            db.retrieve_attestation_key_and_cert_chain(Domain::APP, namespace, &KEYSTORE_UUID)?;
        assert_eq!(true, chain.is_some());
        let cert_chain = chain.unwrap();
        assert_eq!(cert_chain.private_key.to_vec(), loaded_values[2]);
        assert_eq!(cert_chain.cert_chain.to_vec(), loaded_values[1]);
        Ok(())
    }

    #[test]
    fn test_get_attestation_pool_status() -> Result<()> {
        let mut db = new_test_db()?;
        let namespace: i64 = 30;
        load_attestation_key_pool(
            &mut db, 10, /* expiration */
            namespace, 0x01, /* base_byte */
        )?;
        load_attestation_key_pool(&mut db, 20 /* expiration */, namespace + 1, 0x02)?;
        load_attestation_key_pool(&mut db, 40 /* expiration */, namespace + 2, 0x03)?;
        let mut status = db.get_attestation_pool_status(9 /* expiration */, &KEYSTORE_UUID)?;
        assert_eq!(status.expiring, 0);
        assert_eq!(status.attested, 3);
        assert_eq!(status.unassigned, 0);
        assert_eq!(status.total, 3);
        assert_eq!(
            db.get_attestation_pool_status(15 /* expiration */, &KEYSTORE_UUID)?.expiring,
            1
        );
        assert_eq!(
            db.get_attestation_pool_status(25 /* expiration */, &KEYSTORE_UUID)?.expiring,
            2
        );
        assert_eq!(
            db.get_attestation_pool_status(60 /* expiration */, &KEYSTORE_UUID)?.expiring,
            3
        );
        let public_key: Vec<u8> = vec![0x01, 0x02, 0x03];
        let private_key: Vec<u8> = vec![0x04, 0x05, 0x06];
        let raw_public_key: Vec<u8> = vec![0x07, 0x08, 0x09];
        let cert_chain: Vec<u8> = vec![0x0a, 0x0b, 0x0c];
        db.create_attestation_key_entry(
            &public_key,
            &raw_public_key,
            &private_key,
            &KEYSTORE_UUID,
        )?;
        status = db.get_attestation_pool_status(0 /* expiration */, &KEYSTORE_UUID)?;
        assert_eq!(status.attested, 3);
        assert_eq!(status.unassigned, 0);
        assert_eq!(status.total, 4);
        db.store_signed_attestation_certificate_chain(
            &raw_public_key,
            &cert_chain,
            20,
            &KEYSTORE_UUID,
        )?;
        status = db.get_attestation_pool_status(0 /* expiration */, &KEYSTORE_UUID)?;
        assert_eq!(status.attested, 4);
        assert_eq!(status.unassigned, 1);
        assert_eq!(status.total, 4);
        Ok(())
    }

    #[test]
    fn test_remove_expired_certs() -> Result<()> {
        let mut db = new_test_db()?;
        let expiration_date: i64 =
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_millis() as i64 + 10000;
        let namespace: i64 = 30;
        let namespace_del1: i64 = 45;
        let namespace_del2: i64 = 60;
        let entry_values = load_attestation_key_pool(
            &mut db,
            expiration_date,
            namespace,
            0x01, /* base_byte */
        )?;
        load_attestation_key_pool(&mut db, 45, namespace_del1, 0x02)?;
        load_attestation_key_pool(&mut db, 60, namespace_del2, 0x03)?;
        assert_eq!(db.delete_expired_attestation_keys()?, 2);

        let mut cert_chain =
            db.retrieve_attestation_key_and_cert_chain(Domain::APP, namespace, &KEYSTORE_UUID)?;
        assert_eq!(true, cert_chain.is_some());
        let value = cert_chain.unwrap();
        assert_eq!(entry_values[1], value.cert_chain.to_vec());
        assert_eq!(entry_values[2], value.private_key.to_vec());

        cert_chain = db.retrieve_attestation_key_and_cert_chain(
            Domain::APP,
            namespace_del1,
            &KEYSTORE_UUID,
        )?;
        assert_eq!(false, cert_chain.is_some());
        cert_chain = db.retrieve_attestation_key_and_cert_chain(
            Domain::APP,
            namespace_del2,
            &KEYSTORE_UUID,
        )?;
        assert_eq!(false, cert_chain.is_some());

        let mut option_entry = db.get_unreferenced_key()?;
        assert_eq!(true, option_entry.is_some());
        let (key_guard, _) = option_entry.unwrap();
        db.purge_key_entry(key_guard)?;

        option_entry = db.get_unreferenced_key()?;
        assert_eq!(true, option_entry.is_some());
        let (key_guard, _) = option_entry.unwrap();
        db.purge_key_entry(key_guard)?;

        option_entry = db.get_unreferenced_key()?;
        assert_eq!(false, option_entry.is_some());
        Ok(())
    }

    #[test]
    fn test_rebind_alias() -> Result<()> {
        fn extractor(
            ke: &KeyEntryRow,
        ) -> (Option<Domain>, Option<i64>, Option<&str>, Option<Uuid>) {
            (ke.domain, ke.namespace, ke.alias.as_deref(), ke.km_uuid)
        }

        let mut db = new_test_db()?;
        db.create_key_entry(&Domain::APP, &42, &KEYSTORE_UUID)?;
        db.create_key_entry(&Domain::APP, &42, &KEYSTORE_UUID)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(
            extractor(&entries[0]),
            (Some(Domain::APP), Some(42), None, Some(KEYSTORE_UUID))
        );
        assert_eq!(
            extractor(&entries[1]),
            (Some(Domain::APP), Some(42), None, Some(KEYSTORE_UUID))
        );

        // Test that the first call to rebind_alias sets the alias.
        rebind_alias(&mut db, &KEY_ID_LOCK.get(entries[0].id), "foo", Domain::APP, 42)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(
            extractor(&entries[0]),
            (Some(Domain::APP), Some(42), Some("foo"), Some(KEYSTORE_UUID))
        );
        assert_eq!(
            extractor(&entries[1]),
            (Some(Domain::APP), Some(42), None, Some(KEYSTORE_UUID))
        );

        // Test that the second call to rebind_alias also empties the old one.
        rebind_alias(&mut db, &KEY_ID_LOCK.get(entries[1].id), "foo", Domain::APP, 42)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(extractor(&entries[0]), (None, None, None, Some(KEYSTORE_UUID)));
        assert_eq!(
            extractor(&entries[1]),
            (Some(Domain::APP), Some(42), Some("foo"), Some(KEYSTORE_UUID))
        );

        // Test that we must pass in a valid Domain.
        check_result_is_error_containing_string(
            rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::GRANT, 42),
            "Domain Domain(1) must be either App or SELinux.",
        );
        check_result_is_error_containing_string(
            rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::BLOB, 42),
            "Domain Domain(3) must be either App or SELinux.",
        );
        check_result_is_error_containing_string(
            rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::KEY_ID, 42),
            "Domain Domain(4) must be either App or SELinux.",
        );

        // Test that we correctly handle setting an alias for something that does not exist.
        check_result_is_error_containing_string(
            rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::SELINUX, 42),
            "Expected to update a single entry but instead updated 0",
        );
        // Test that we correctly abort the transaction in this case.
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(extractor(&entries[0]), (None, None, None, Some(KEYSTORE_UUID)));
        assert_eq!(
            extractor(&entries[1]),
            (Some(Domain::APP), Some(42), Some("foo"), Some(KEYSTORE_UUID))
        );

        Ok(())
    }

    #[test]
    fn test_grant_ungrant() -> Result<()> {
        const CALLER_UID: u32 = 15;
        const GRANTEE_UID: u32 = 12;
        const SELINUX_NAMESPACE: i64 = 7;

        let mut db = new_test_db()?;
        db.conn.execute(
            "INSERT INTO persistent.keyentry (id, key_type, domain, namespace, alias, state, km_uuid)
                VALUES (1, 0, 0, 15, 'key', 1, ?), (2, 0, 2, 7, 'yek', 1, ?);",
            params![KEYSTORE_UUID, KEYSTORE_UUID],
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
            .grant(&app_key, CALLER_UID, GRANTEE_UID, PVEC1, |k, a| {
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
            .grant(&selinux_key, CALLER_UID, 12, PVEC1, |k, a| {
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
            .grant(&selinux_key, CALLER_UID, 12, PVEC2, |k, a| {
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

        db.ungrant(&app_key, CALLER_UID, GRANTEE_UID, |_| Ok(()))?;
        db.ungrant(&selinux_key, CALLER_UID, GRANTEE_UID, |_| Ok(()))?;

        Ok(())
    }

    static TEST_KEY_BLOB: &[u8] = b"my test blob";
    static TEST_CERT_BLOB: &[u8] = b"my test cert";
    static TEST_CERT_CHAIN_BLOB: &[u8] = b"my test cert_chain";

    #[test]
    fn test_set_blob() -> Result<()> {
        let key_id = KEY_ID_LOCK.get(3000);
        let mut db = new_test_db()?;
        db.set_blob(&key_id, SubComponentType::KEY_BLOB, Some(TEST_KEY_BLOB))?;
        db.set_blob(&key_id, SubComponentType::CERT, Some(TEST_CERT_BLOB))?;
        db.set_blob(&key_id, SubComponentType::CERT_CHAIN, Some(TEST_CERT_CHAIN_BLOB))?;
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
        let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS, None)
            .context("test_insert_and_load_full_keyentry_domain_app")?
            .0;
        let (_key_guard, key_entry) = db
            .load_key_entry(
                &KeyDescriptor {
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
        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));

        db.unbind_key(
            &KeyDescriptor {
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
                &KeyDescriptor {
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
    fn test_insert_and_load_certificate_entry_domain_app() -> Result<()> {
        let mut db = new_test_db()?;

        db.store_new_certificate(
            &KeyDescriptor {
                domain: Domain::APP,
                nspace: 1,
                alias: Some(TEST_ALIAS.to_string()),
                blob: None,
            },
            TEST_CERT_BLOB,
            &KEYSTORE_UUID,
        )
        .expect("Trying to insert cert.");

        let (_key_guard, mut key_entry) = db
            .load_key_entry(
                &KeyDescriptor {
                    domain: Domain::APP,
                    nspace: 1,
                    alias: Some(TEST_ALIAS.to_string()),
                    blob: None,
                },
                KeyType::Client,
                KeyEntryLoadBits::PUBLIC,
                1,
                |_k, _av| Ok(()),
            )
            .expect("Trying to read certificate entry.");

        assert!(key_entry.pure_cert());
        assert!(key_entry.cert().is_none());
        assert_eq!(key_entry.take_cert_chain(), Some(TEST_CERT_BLOB.to_vec()));

        db.unbind_key(
            &KeyDescriptor {
                domain: Domain::APP,
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
                &KeyDescriptor {
                    domain: Domain::APP,
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
    fn test_insert_and_load_full_keyentry_domain_selinux() -> Result<()> {
        let mut db = new_test_db()?;
        let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, None)
            .context("test_insert_and_load_full_keyentry_domain_selinux")?
            .0;
        let (_key_guard, key_entry) = db
            .load_key_entry(
                &KeyDescriptor {
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
        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));

        db.unbind_key(
            &KeyDescriptor {
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
                &KeyDescriptor {
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
        let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, None)
            .context("test_insert_and_load_full_keyentry_domain_key_id")?
            .0;
        let (_, key_entry) = db
            .load_key_entry(
                &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
                KeyType::Client,
                KeyEntryLoadBits::BOTH,
                1,
                |_k, _av| Ok(()),
            )
            .unwrap();

        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));

        db.unbind_key(
            &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
            KeyType::Client,
            1,
            |_, _| Ok(()),
        )
        .unwrap();

        assert_eq!(
            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
            db.load_key_entry(
                &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
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
    fn test_check_and_update_key_usage_count_with_limited_use_key() -> Result<()> {
        let mut db = new_test_db()?;
        let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, Some(123))
            .context("test_check_and_update_key_usage_count_with_limited_use_key")?
            .0;
        // Update the usage count of the limited use key.
        db.check_and_update_key_usage_count(key_id)?;

        let (_key_guard, key_entry) = db.load_key_entry(
            &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
            KeyType::Client,
            KeyEntryLoadBits::BOTH,
            1,
            |_k, _av| Ok(()),
        )?;

        // The usage count is decremented now.
        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, Some(122)));

        Ok(())
    }

    #[test]
    fn test_check_and_update_key_usage_count_with_exhausted_limited_use_key() -> Result<()> {
        let mut db = new_test_db()?;
        let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, Some(1))
            .context("test_check_and_update_key_usage_count_with_exhausted_limited_use_key")?
            .0;
        // Update the usage count of the limited use key.
        db.check_and_update_key_usage_count(key_id).expect(concat!(
            "In test_check_and_update_key_usage_count_with_exhausted_limited_use_key: ",
            "This should succeed."
        ));

        // Try to update the exhausted limited use key.
        let e = db.check_and_update_key_usage_count(key_id).expect_err(concat!(
            "In test_check_and_update_key_usage_count_with_exhausted_limited_use_key: ",
            "This should fail."
        ));
        assert_eq!(
            &KsError::Km(ErrorCode::INVALID_KEY_BLOB),
            e.root_cause().downcast_ref::<KsError>().unwrap()
        );

        Ok(())
    }

    #[test]
    fn test_insert_and_load_full_keyentry_from_grant() -> Result<()> {
        let mut db = new_test_db()?;
        let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS, None)
            .context("test_insert_and_load_full_keyentry_from_grant")?
            .0;

        let granted_key = db
            .grant(
                &KeyDescriptor {
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
            .load_key_entry(&granted_key, KeyType::Client, KeyEntryLoadBits::BOTH, 2, |k, av| {
                assert_eq!(Domain::GRANT, k.domain);
                assert!(av.unwrap().includes(KeyPerm::use_()));
                Ok(())
            })
            .unwrap();

        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));

        db.unbind_key(&granted_key, KeyType::Client, 2, |_, _| Ok(())).unwrap();

        assert_eq!(
            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
            db.load_key_entry(
                &granted_key,
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

    // This test attempts to load a key by key id while the caller is not the owner
    // but a grant exists for the given key and the caller.
    #[test]
    fn test_insert_and_load_full_keyentry_from_grant_by_key_id() -> Result<()> {
        let mut db = new_test_db()?;
        const OWNER_UID: u32 = 1u32;
        const GRANTEE_UID: u32 = 2u32;
        const SOMEONE_ELSE_UID: u32 = 3u32;
        let key_id = make_test_key_entry(&mut db, Domain::APP, OWNER_UID as i64, TEST_ALIAS, None)
            .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?
            .0;

        db.grant(
            &KeyDescriptor {
                domain: Domain::APP,
                nspace: 0,
                alias: Some(TEST_ALIAS.to_string()),
                blob: None,
            },
            OWNER_UID,
            GRANTEE_UID,
            key_perm_set![KeyPerm::use_()],
            |_k, _av| Ok(()),
        )
        .unwrap();

        debug_dump_grant_table(&mut db)?;

        let id_descriptor =
            KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, ..Default::default() };

        let (_, key_entry) = db
            .load_key_entry(
                &id_descriptor,
                KeyType::Client,
                KeyEntryLoadBits::BOTH,
                GRANTEE_UID,
                |k, av| {
                    assert_eq!(Domain::APP, k.domain);
                    assert_eq!(OWNER_UID as i64, k.nspace);
                    assert!(av.unwrap().includes(KeyPerm::use_()));
                    Ok(())
                },
            )
            .unwrap();

        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));

        let (_, key_entry) = db
            .load_key_entry(
                &id_descriptor,
                KeyType::Client,
                KeyEntryLoadBits::BOTH,
                SOMEONE_ELSE_UID,
                |k, av| {
                    assert_eq!(Domain::APP, k.domain);
                    assert_eq!(OWNER_UID as i64, k.nspace);
                    assert!(av.is_none());
                    Ok(())
                },
            )
            .unwrap();

        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));

        db.unbind_key(&id_descriptor, KeyType::Client, OWNER_UID, |_, _| Ok(())).unwrap();

        assert_eq!(
            Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
            db.load_key_entry(
                &id_descriptor,
                KeyType::Client,
                KeyEntryLoadBits::NONE,
                GRANTEE_UID,
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
            let key_id = make_test_key_entry(&mut db, Domain::APP, 33, KEY_LOCK_TEST_ALIAS, None)
                .context("test_insert_and_load_full_keyentry_domain_app")?
                .0;
            let (_key_guard, key_entry) = db
                .load_key_entry(
                    &KeyDescriptor {
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
            assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
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
                        &KeyDescriptor {
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
    fn teset_database_busy_error_code() {
        let temp_dir =
            TempDir::new("test_database_busy_error_code_").expect("Failed to create temp dir.");

        let mut db1 = KeystoreDB::new(temp_dir.path()).expect("Failed to open database1.");
        let mut db2 = KeystoreDB::new(temp_dir.path()).expect("Failed to open database2.");

        let _tx1 = db1
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("Failed to create first transaction.");

        let error = db2
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Transaction begin failed.")
            .expect_err("This should fail.");
        let root_cause = error.root_cause();
        if let Some(rusqlite::ffi::Error { code: rusqlite::ErrorCode::DatabaseBusy, .. }) =
            root_cause.downcast_ref::<rusqlite::ffi::Error>()
        {
            return;
        }
        panic!(
            "Unexpected error {:?} \n{:?} \n{:?}",
            error,
            root_cause,
            root_cause.downcast_ref::<rusqlite::ffi::Error>()
        )
    }

    #[cfg(disabled)]
    #[test]
    fn test_large_number_of_concurrent_db_manipulations() -> Result<()> {
        let temp_dir = Arc::new(
            TempDir::new("test_large_number_of_concurrent_db_manipulations_")
                .expect("Failed to create temp dir."),
        );

        let test_begin = Instant::now();

        let mut db = KeystoreDB::new(temp_dir.path()).expect("Failed to open database.");
        const KEY_COUNT: u32 = 500u32;
        const OPEN_DB_COUNT: u32 = 50u32;

        let mut actual_key_count = KEY_COUNT;
        // First insert KEY_COUNT keys.
        for count in 0..KEY_COUNT {
            if Instant::now().duration_since(test_begin) >= Duration::from_secs(15) {
                actual_key_count = count;
                break;
            }
            let alias = format!("test_alias_{}", count);
            make_test_key_entry(&mut db, Domain::APP, 1, &alias, None)
                .expect("Failed to make key entry.");
        }

        // Insert more keys from a different thread and into a different namespace.
        let temp_dir1 = temp_dir.clone();
        let handle1 = thread::spawn(move || {
            let mut db = KeystoreDB::new(temp_dir1.path()).expect("Failed to open database.");

            for count in 0..actual_key_count {
                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                    return;
                }
                let alias = format!("test_alias_{}", count);
                make_test_key_entry(&mut db, Domain::APP, 2, &alias, None)
                    .expect("Failed to make key entry.");
            }

            // then unbind them again.
            for count in 0..actual_key_count {
                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                    return;
                }
                let key = KeyDescriptor {
                    domain: Domain::APP,
                    nspace: -1,
                    alias: Some(format!("test_alias_{}", count)),
                    blob: None,
                };
                db.unbind_key(&key, KeyType::Client, 2, |_, _| Ok(())).expect("Unbind Failed.");
            }
        });

        // And start unbinding the first set of keys.
        let temp_dir2 = temp_dir.clone();
        let handle2 = thread::spawn(move || {
            let mut db = KeystoreDB::new(temp_dir2.path()).expect("Failed to open database.");

            for count in 0..actual_key_count {
                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                    return;
                }
                let key = KeyDescriptor {
                    domain: Domain::APP,
                    nspace: -1,
                    alias: Some(format!("test_alias_{}", count)),
                    blob: None,
                };
                db.unbind_key(&key, KeyType::Client, 1, |_, _| Ok(())).expect("Unbind Failed.");
            }
        });

        let stop_deleting = Arc::new(AtomicU8::new(0));
        let stop_deleting2 = stop_deleting.clone();

        // And delete anything that is unreferenced keys.
        let temp_dir3 = temp_dir.clone();
        let handle3 = thread::spawn(move || {
            let mut db = KeystoreDB::new(temp_dir3.path()).expect("Failed to open database.");

            while stop_deleting2.load(Ordering::Relaxed) != 1 {
                while let Some((key_guard, _key)) =
                    db.get_unreferenced_key().expect("Failed to get unreferenced Key.")
                {
                    if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                        return;
                    }
                    db.purge_key_entry(key_guard).expect("Failed to purge key.");
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });

        // While a lot of inserting and deleting is going on we have to open database connections
        // successfully and use them.
        // This clone is not redundant, because temp_dir needs to be kept alive until db goes
        // out of scope.
        #[allow(clippy::redundant_clone)]
        let temp_dir4 = temp_dir.clone();
        let handle4 = thread::spawn(move || {
            for count in 0..OPEN_DB_COUNT {
                if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                    return;
                }
                let mut db = KeystoreDB::new(temp_dir4.path()).expect("Failed to open database.");

                let alias = format!("test_alias_{}", count);
                make_test_key_entry(&mut db, Domain::APP, 3, &alias, None)
                    .expect("Failed to make key entry.");
                let key = KeyDescriptor {
                    domain: Domain::APP,
                    nspace: -1,
                    alias: Some(alias),
                    blob: None,
                };
                db.unbind_key(&key, KeyType::Client, 3, |_, _| Ok(())).expect("Unbind Failed.");
            }
        });

        handle1.join().expect("Thread 1 panicked.");
        handle2.join().expect("Thread 2 panicked.");
        handle4.join().expect("Thread 4 panicked.");

        stop_deleting.store(1, Ordering::Relaxed);
        handle3.join().expect("Thread 3 panicked.");

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
                let entry = make_test_key_entry(&mut db, *domain, *ns, *alias, None)
                    .unwrap_or_else(|e| {
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
                            &d,
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
        km_uuid: Option<Uuid>,
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
                    km_uuid: row.get(6)?,
                })
            })?
            .map(|r| r.context("Could not read keyentry row."))
            .collect::<Result<Vec<_>>>()
    }

    fn load_attestation_key_pool(
        db: &mut KeystoreDB,
        expiration_date: i64,
        namespace: i64,
        base_byte: u8,
    ) -> Result<Vec<Vec<u8>>> {
        let mut chain: Vec<Vec<u8>> = Vec::new();
        let public_key: Vec<u8> = vec![base_byte, 0x02 * base_byte];
        let cert_chain: Vec<u8> = vec![0x03 * base_byte, 0x04 * base_byte];
        let priv_key: Vec<u8> = vec![0x05 * base_byte, 0x06 * base_byte];
        let raw_public_key: Vec<u8> = vec![0x0b * base_byte, 0x0c * base_byte];
        db.create_attestation_key_entry(&public_key, &raw_public_key, &priv_key, &KEYSTORE_UUID)?;
        db.store_signed_attestation_certificate_chain(
            &raw_public_key,
            &cert_chain,
            expiration_date,
            &KEYSTORE_UUID,
        )?;
        db.assign_attestation_key(Domain::APP, namespace, &KEYSTORE_UUID)?;
        chain.push(public_key);
        chain.push(cert_chain);
        chain.push(priv_key);
        chain.push(raw_public_key);
        Ok(chain)
    }

    // Note: The parameters and SecurityLevel associations are nonsensical. This
    // collection is only used to check if the parameters are preserved as expected by the
    // database.
    fn make_test_params(max_usage_count: Option<i32>) -> Vec<KeyParameter> {
        let mut params = vec![
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
        ];
        if let Some(value) = max_usage_count {
            params.push(KeyParameter::new(
                KeyParameterValue::UsageCountLimit(value),
                SecurityLevel::SOFTWARE,
            ));
        }
        params
    }

    fn make_test_key_entry(
        db: &mut KeystoreDB,
        domain: Domain,
        namespace: i64,
        alias: &str,
        max_usage_count: Option<i32>,
    ) -> Result<KeyIdGuard> {
        let key_id = db.create_key_entry(&domain, &namespace, &KEYSTORE_UUID)?;
        db.set_blob(&key_id, SubComponentType::KEY_BLOB, Some(TEST_KEY_BLOB))?;
        db.set_blob(&key_id, SubComponentType::CERT, Some(TEST_CERT_BLOB))?;
        db.set_blob(&key_id, SubComponentType::CERT_CHAIN, Some(TEST_CERT_CHAIN_BLOB))?;

        let params = make_test_params(max_usage_count);
        db.insert_keyparameter(&key_id, &params)?;

        let mut metadata = KeyMetaData::new();
        metadata.add(KeyMetaEntry::EncryptedBy(EncryptedBy::Password));
        metadata.add(KeyMetaEntry::Salt(vec![1, 2, 3]));
        metadata.add(KeyMetaEntry::Iv(vec![2, 3, 1]));
        metadata.add(KeyMetaEntry::AeadTag(vec![3, 1, 2]));
        db.insert_key_metadata(&key_id, &metadata)?;
        rebind_alias(db, &key_id, alias, domain, namespace)?;
        Ok(key_id)
    }

    fn make_test_key_entry_test_vector(key_id: i64, max_usage_count: Option<i32>) -> KeyEntry {
        let params = make_test_params(max_usage_count);

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
            km_uuid: KEYSTORE_UUID,
            parameters: params,
            metadata,
            pure_cert: false,
        }
    }

    fn debug_dump_keyentry_table(db: &mut KeystoreDB) -> Result<()> {
        let mut stmt = db.conn.prepare(
            "SELECT id, key_type, domain, namespace, alias, state, km_uuid FROM persistent.keyentry;",
        )?;
        let rows = stmt.query_map::<(i64, KeyType, i32, i64, String, KeyLifeCycle, Uuid), _, _>(
            NO_PARAMS,
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )?;

        println!("Key entry table rows:");
        for r in rows {
            let (id, key_type, domain, namespace, alias, state, km_uuid) = r.unwrap();
            println!(
                "    id: {} KeyType: {:?} Domain: {} Namespace: {} Alias: {} State: {:?} KmUuid: {:?}",
                id, key_type, domain, namespace, alias, state, km_uuid
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
        db.insert_last_off_body(MonotonicRawTime::now())?;
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
