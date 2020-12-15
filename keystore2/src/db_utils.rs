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

use crate::error::Error as KsError;
use anyhow::{Context, Result};
use rusqlite::{Row, Rows};

// Takes Rows as returned by a query call on prepared statement.
// Extracts exactly one row with the `row_extractor` and fails if more
// rows are available.
// If no row was found, `None` is passed to the `row_extractor`.
// This allows the row extractor to decide on an error condition or
// a different default behavior.
pub fn with_rows_extract_one<'a, T, F>(rows: &mut Rows<'a>, row_extractor: F) -> Result<T>
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

pub fn with_rows_extract_all<'a, F>(rows: &mut Rows<'a>, mut row_extractor: F) -> Result<()>
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
