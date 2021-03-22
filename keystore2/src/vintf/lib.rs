// Copyright 2021, The Android Open Source Project
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

//! Bindings for getting the list of HALs.

use keystore2_vintf_bindgen::{
    freeNames, getAidlInstances, getHalNames, getHalNamesAndVersions, getHidlInstances,
};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::str::Utf8Error;

/// A struct that contains a list of HALs (optionally with version numbers).
/// To use it, call as_vec to get a Vec view of the data it contains.
pub struct HalNames {
    data: *mut *mut c_char,
    len: usize,
}

impl Drop for HalNames {
    fn drop(&mut self) {
        // Safety: The memory is allocated by our C shim so it must free it as well.
        unsafe { freeNames(self.data, self.len) }
    }
}

impl<'a> HalNames {
    /// Get a Vec view of the list of HALs.
    pub fn as_vec(&'a self) -> Result<Vec<&'a str>, Utf8Error> {
        // Safety: self.data contains self.len C strings.
        // The lifetimes ensure that the HalNames (and hence the strings) live
        // at least as long as the returned vector.
        unsafe { (0..self.len).map(|i| CStr::from_ptr(*self.data.add(i)).to_str()) }.collect()
    }
}

/// Gets all HAL names.
/// Note that this is not a zero-cost shim: it will make copies of the strings.
pub fn get_hal_names() -> HalNames {
    let mut len: usize = 0;
    // Safety: We'll wrap this in HalNames to free the memory it allocates.
    // It stores the size of the array it returns in len.
    let raw_strs = unsafe { getHalNames(&mut len) };
    HalNames { data: raw_strs, len }
}

/// Gets all HAL names and versions.
/// Note that this is not a zero-cost shim: it will make copies of the strings.
pub fn get_hal_names_and_versions() -> HalNames {
    let mut len: usize = 0;
    // Safety: We'll wrap this in HalNames to free the memory it allocates.
    // It stores the size of the array it returns in len.
    let raw_strs = unsafe { getHalNamesAndVersions(&mut len) };
    HalNames { data: raw_strs, len }
}

/// Gets the instances of the given package, version, and interface tuple.
/// Note that this is not a zero-cost shim: it will make copies of the strings.
pub fn get_hidl_instances(
    package: &str,
    major_version: usize,
    minor_version: usize,
    interface_name: &str,
) -> HalNames {
    let mut len: usize = 0;
    let packages = CString::new(package).expect("Failed to make CString from package.");
    let interface_name =
        CString::new(interface_name).expect("Failed to make CString from interface_name.");
    // Safety: We'll wrap this in HalNames to free the memory it allocates.
    // It stores the size of the array it returns in len.
    let raw_strs = unsafe {
        getHidlInstances(
            &mut len,
            packages.as_ptr(),
            major_version,
            minor_version,
            interface_name.as_ptr(),
        )
    };
    HalNames { data: raw_strs, len }
}

/// Gets the instances of the given package, version, and interface tuple.
/// Note that this is not a zero-cost shim: it will make copies of the strings.
pub fn get_aidl_instances(package: &str, version: usize, interface_name: &str) -> HalNames {
    let mut len: usize = 0;
    let packages = CString::new(package).expect("Failed to make CString from package.");
    let interface_name =
        CString::new(interface_name).expect("Failed to make CString from interface_name.");
    // Safety: We'll wrap this in HalNames to free the memory it allocates.
    // It stores the size of the array it returns in len.
    let raw_strs =
        unsafe { getAidlInstances(&mut len, packages.as_ptr(), version, interface_name.as_ptr()) };
    HalNames { data: raw_strs, len }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test() -> Result<(), Utf8Error> {
        let result = get_hal_names();
        let names = result.as_vec()?;
        assert_ne!(names.len(), 0);

        let result = get_hal_names_and_versions();
        let names_and_versions = result.as_vec()?;
        assert_ne!(names_and_versions.len(), 0);

        assert!(names_and_versions.len() >= names.len());

        Ok(())
    }
}
