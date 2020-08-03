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

// TODO: Once this is stable, remove this and document everything public.
#![allow(missing_docs)]

use crate::error::Error as KsError;
use anyhow::{Context, Result};
use keystore_aidl_generated as aidl;
#[cfg(not(test))]
use rand::prelude::random;
use rusqlite::{params, Connection, TransactionBehavior, NO_PARAMS};
#[cfg(test)]
use tests::random;

pub struct KeystoreDB {
    conn: Connection,
}

impl KeystoreDB {
    // TODO(b/160882985): Figure out the location for this file.
    #[cfg(not(test))]
    pub fn new() -> Result<KeystoreDB> {
        KeystoreDB::new_with_filename("persistent.sql")
    }

    #[cfg(test)]
    pub fn new() -> Result<KeystoreDB> {
        KeystoreDB::new_with_filename("")
    }

    fn new_with_filename(persistent_file: &str) -> Result<KeystoreDB> {
        let db = KeystoreDB {
            conn: Connection::open_in_memory()
                .context("Failed to initialize sqlite connection.")?,
        };
        db.attach_databases(persistent_file).context("Failed to create KeystoreDB.")?;
        db.init_tables().context("Failed to create KeystoreDB.")?;
        Ok(db)
    }

    fn attach_databases(&self, persistent_file: &str) -> Result<()> {
        self.conn
            .execute("ATTACH DATABASE ? as 'persistent';", params![persistent_file])
            .context("Failed to attach databases.")?;
        Ok(())
    }

    fn init_tables(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS persistent.keyentry (
                     id INTEGER UNIQUE,
                     creation_date DATETIME,
                     domain INTEGER,
                     namespace INTEGER,
                     alias TEXT);",
                NO_PARAMS,
            )
            .context("Failed to initialize \"keyentry\" table.")?;
        Ok(())
    }

    pub fn create_key_entry(&self, domain: aidl::Domain, namespace: i64) -> Result<i64> {
        match domain {
            aidl::Domain::App | aidl::Domain::SELinux => {}
            _ => {
                return Err(KsError::sys())
                    .context(format!("Domain {:?} must be either App or SELinux.", domain));
            }
        }
        // Loop until we get a unique id.
        loop {
            let newid: i64 = random();
            let ret = self.conn.execute(
                "INSERT into persistent.keyentry (id, creation_date, domain, namespace, alias)
                     VALUES(?, datetime('now'), ?, ?, NULL);",
                params![newid, domain as i64, namespace],
            );
            match ret {
                // If the id already existed, try again.
                Err(rusqlite::Error::SqliteFailure(
                    libsqlite3_sys::Error {
                        code: libsqlite3_sys::ErrorCode::ConstraintViolation,
                        extended_code: libsqlite3_sys::SQLITE_CONSTRAINT_UNIQUE,
                    },
                    _,
                )) => (),
                _ => return Ok(newid),
            }
        }
    }

    pub fn rebind_alias(
        &mut self,
        newid: u32,
        alias: &str,
        domain: aidl::Domain,
        namespace: i64,
    ) -> Result<()> {
        match domain {
            aidl::Domain::App | aidl::Domain::SELinux => {}
            _ => {
                return Err(KsError::sys())
                    .context(format!("Domain {:?} must be either App or SELinux.", domain));
            }
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Failed to initialize transaction.")?;
        tx.execute(
            "UPDATE persistent.keyentry
                 SET alias = NULL, domain = NULL, namespace = NULL
                 WHERE alias = ? AND domain = ? AND namespace = ?;",
            params![alias, domain as i64, namespace],
        )
        .context("Failed to rebind existing entry.")?;
        let result = tx
            .execute(
                "UPDATE persistent.keyentry
                 SET alias = ?
                 WHERE id = ? AND domain = ? AND namespace = ?;",
                params![alias, newid, domain as i64, namespace],
            )
            .context("Failed to set alias.")?;
        if result != 1 {
            // Note that this explicit rollback is not required, as
            // the transaction should rollback if we do not commit it.
            // We leave it here for readability.
            tx.rollback().context("Failed to rollback a failed transaction.")?;
            return Err(KsError::sys()).context(format!(
                "Expected to update a single entry but instead updated {}.",
                result
            ));
        }
        tx.commit().context("Failed to commit transaction.")
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::cell::RefCell;

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

    // Ensure we can initialize the database.
    #[test]
    fn test_new() -> Result<()> {
        KeystoreDB::new()?;
        Ok(())
    }

    // Test that we have the correct tables.
    #[test]
    fn test_tables() -> Result<()> {
        let db = KeystoreDB::new()?;
        let tables = db
            .conn
            .prepare("SELECT name from persistent.sqlite_master WHERE type='table' ORDER BY name;")?
            .query_map(params![], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0], "keyentry");
        Ok(())
    }

    #[test]
    fn test_no_persistence_for_tests() -> Result<()> {
        let db = KeystoreDB::new()?;

        db.create_key_entry(aidl::Domain::App, 100)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 1);
        let db = KeystoreDB::new()?;

        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 0);
        Ok(())
    }

    #[test]
    fn test_persistence_for_files() -> Result<()> {
        let persistent = TempFile { filename: "/data/local/tmp/persistent.sql" };
        let db = KeystoreDB::new_with_filename(persistent.filename)?;

        db.create_key_entry(aidl::Domain::App, 100)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 1);
        let db = KeystoreDB::new_with_filename(persistent.filename)?;

        let entries_new = get_keyentry(&db)?;
        assert_eq!(entries, entries_new);
        Ok(())
    }

    #[test]
    fn test_create_key_entry() -> Result<()> {
        use aidl::Domain;

        fn extractor(ke: &KeyEntryRow) -> (Domain, i64, Option<&str>) {
            (ke.domain.unwrap(), ke.namespace.unwrap(), ke.alias.as_deref())
        }

        let db = KeystoreDB::new()?;

        db.create_key_entry(Domain::App, 100)?;
        db.create_key_entry(Domain::SELinux, 101)?;

        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(extractor(&entries[0]), (Domain::App, 100, None));
        assert_eq!(extractor(&entries[1]), (Domain::SELinux, 101, None));

        // Test that we must pass in a valid Domain.
        check_result_is_error_containing_string(
            db.create_key_entry(Domain::Grant, 102),
            "Domain Grant must be either App or SELinux.",
        );
        check_result_is_error_containing_string(
            db.create_key_entry(Domain::Blob, 103),
            "Domain Blob must be either App or SELinux.",
        );
        check_result_is_error_containing_string(
            db.create_key_entry(Domain::KeyId, 104),
            "Domain KeyId must be either App or SELinux.",
        );

        Ok(())
    }

    #[test]
    fn test_rebind_alias() -> Result<()> {
        use aidl::Domain;

        fn extractor(ke: &KeyEntryRow) -> (Option<Domain>, Option<i64>, Option<&str>) {
            (ke.domain, ke.namespace, ke.alias.as_deref())
        }

        let mut db = KeystoreDB::new()?;
        db.create_key_entry(Domain::App, 42)?;
        db.create_key_entry(Domain::App, 42)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(extractor(&entries[0]), (Some(Domain::App), Some(42), None));
        assert_eq!(extractor(&entries[1]), (Some(Domain::App), Some(42), None));

        // Test that the first call to rebind_alias sets the alias.
        db.rebind_alias(entries[0].id, "foo", Domain::App, 42)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(extractor(&entries[0]), (Some(Domain::App), Some(42), Some("foo")));
        assert_eq!(extractor(&entries[1]), (Some(Domain::App), Some(42), None));

        // Test that the second call to rebind_alias also empties the old one.
        db.rebind_alias(entries[1].id, "foo", Domain::App, 42)?;
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(extractor(&entries[0]), (None, None, None));
        assert_eq!(extractor(&entries[1]), (Some(Domain::App), Some(42), Some("foo")));

        // Test that we must pass in a valid Domain.
        check_result_is_error_containing_string(
            db.rebind_alias(0, "foo", Domain::Grant, 42),
            "Domain Grant must be either App or SELinux.",
        );
        check_result_is_error_containing_string(
            db.rebind_alias(0, "foo", Domain::Blob, 42),
            "Domain Blob must be either App or SELinux.",
        );
        check_result_is_error_containing_string(
            db.rebind_alias(0, "foo", Domain::KeyId, 42),
            "Domain KeyId must be either App or SELinux.",
        );

        // Test that we correctly handle setting an alias for something that does not exist.
        check_result_is_error_containing_string(
            db.rebind_alias(0, "foo", Domain::SELinux, 42),
            "Expected to update a single entry but instead updated 0",
        );
        // Test that we correctly abort the transaction in this case.
        let entries = get_keyentry(&db)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(extractor(&entries[0]), (None, None, None));
        assert_eq!(extractor(&entries[1]), (Some(Domain::App), Some(42), Some("foo")));

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
        id: u32,
        creation_date: String,
        domain: Option<aidl::Domain>,
        namespace: Option<i64>,
        alias: Option<String>,
    }

    fn get_keyentry(db: &KeystoreDB) -> Result<Vec<KeyEntryRow>> {
        db.conn
            .prepare("SELECT * FROM persistent.keyentry;")?
            .query_map(NO_PARAMS, |row| {
                let domain: Option<i32> = row.get(2)?;
                Ok(KeyEntryRow {
                    id: row.get(0)?,
                    creation_date: row.get(1)?,
                    domain: domain.map(domain_from_integer),
                    namespace: row.get(3)?,
                    alias: row.get(4)?,
                })
            })?
            .map(|r| r.context("Could not read keyentry row."))
            .collect::<Result<Vec<_>>>()
    }

    // TODO: Replace this with num_derive.
    fn domain_from_integer(value: i32) -> aidl::Domain {
        use aidl::Domain;
        match value {
            x if Domain::App as i32 == x => Domain::App,
            x if Domain::Grant as i32 == x => Domain::Grant,
            x if Domain::SELinux as i32 == x => Domain::SELinux,
            x if Domain::Blob as i32 == x => Domain::Blob,
            x if Domain::KeyId as i32 == x => Domain::KeyId,
            _ => panic!("Unexpected domain: {}", value),
        }
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

    pub fn random() -> i64 {
        RANDOM_COUNTER.with(|counter| {
            let result = *counter.borrow() / 2;
            *counter.borrow_mut() += 1;
            result
        })
    }
}
