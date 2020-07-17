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

use anyhow::{Context, Result};
use rusqlite::Connection;

pub struct KeystoreDB {
    #[allow(dead_code)]
    conn: Connection,
}

impl KeystoreDB {
    pub fn new() -> Result<KeystoreDB> {
        Ok(KeystoreDB {
            conn: Connection::open_in_memory()
                .context("Failed to initialize sqlite connection.")?,
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use rusqlite::params;

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
            .prepare("SELECT name from sqlite_master WHERE type='table' ORDER BY name;")?
            .query_map(params![], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        assert_eq!(tables.len(), 0);
        Ok(())
    }
}
