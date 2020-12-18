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

#![allow(dead_code)]

use crate::error::Error;
use nix::sys::mman::{mlock, munlock};
use std::convert::TryFrom;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::ptr::write_volatile;

/// A fixed size u8 vector that is zeroed when dropped. Also the data is
/// pinned in memory with mlock.
#[derive(Default, Eq, PartialEq)]
pub struct ZVec(Box<[u8]>);

impl ZVec {
    /// Create a ZVec with the given size.
    pub fn new(size: usize) -> Result<Self, Error> {
        let v: Vec<u8> = vec![0; size];
        let b = v.into_boxed_slice();
        if size > 0 {
            unsafe { mlock(b.as_ptr() as *const std::ffi::c_void, b.len()) }?;
        }
        Ok(Self(b))
    }
}

impl Drop for ZVec {
    fn drop(&mut self) {
        for i in 0..self.0.len() {
            unsafe { write_volatile(self.0.as_mut_ptr().add(i), 0) };
        }
        if !self.0.is_empty() {
            if let Err(e) =
                unsafe { munlock(self.0.as_ptr() as *const std::ffi::c_void, self.0.len()) }
            {
                log::error!("In ZVec::drop: `munlock` failed: {:?}.", e);
            }
        }
    }
}

impl Deref for ZVec {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ZVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl fmt::Debug for ZVec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.0.is_empty() {
            write!(f, "Zvec empty")
        } else {
            write!(f, "Zvec size: {} [ Sensitive information redacted ]", self.0.len())
        }
    }
}

impl TryFrom<&[u8]> for ZVec {
    type Error = Error;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        let mut z = ZVec::new(v.len())?;
        if !v.is_empty() {
            z.clone_from_slice(v);
        }
        Ok(z)
    }
}

impl TryFrom<Vec<u8>> for ZVec {
    type Error = Error;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        let b = v.into_boxed_slice();
        if !b.is_empty() {
            unsafe { mlock(b.as_ptr() as *const std::ffi::c_void, b.len()) }?;
        }
        Ok(Self(b))
    }
}
