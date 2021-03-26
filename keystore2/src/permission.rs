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

//! This crate provides access control primitives for Keystore 2.0.
//! It provides high level functions for checking permissions in the keystore2 and keystore2_key
//! SELinux classes based on the keystore2_selinux backend.
//! It also provides KeystorePerm and KeyPerm as convenience wrappers for the SELinux permission
//! defined by keystore2 and keystore2_key respectively.

use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, KeyPermission::KeyPermission,
};

use std::cmp::PartialEq;
use std::convert::From;
use std::ffi::CStr;

use crate::error::Error as KsError;
use keystore2_selinux as selinux;

use anyhow::Context as AnyhowContext;

use selinux::Backend;

use lazy_static::lazy_static;

// Replace getcon with a mock in the test situation
#[cfg(not(test))]
use selinux::getcon;
#[cfg(test)]
use tests::test_getcon as getcon;

lazy_static! {
    // Panicking here is allowed because keystore cannot function without this backend
    // and it would happen early and indicate a gross misconfiguration of the device.
    static ref KEYSTORE2_KEY_LABEL_BACKEND: selinux::KeystoreKeyBackend =
            selinux::KeystoreKeyBackend::new().unwrap();
}

fn lookup_keystore2_key_context(namespace: i64) -> anyhow::Result<selinux::Context> {
    KEYSTORE2_KEY_LABEL_BACKEND.lookup(&namespace.to_string())
}

/// ## Background
///
/// AIDL enums are represented as constants of the form:
/// ```
/// mod EnumName {
///     pub type EnumName = i32;
///     pub const Variant1: EnumName = <value1>;
///     pub const Variant2: EnumName = <value2>;
///     ...
/// }
///```
/// This macro wraps the enum in a new type, e.g., `MyPerm` and maps each variant to an SELinux
/// permission while providing the following interface:
///  * From<EnumName> and Into<EnumName> are implemented. Where the implementation of From maps
///    any variant not specified to the default.
///  * Every variant has a constructor with a name corresponding to its lower case SELinux string
///    representation.
///  * `MyPerm.to_selinux(&self)` returns the SELinux string representation of the
///    represented permission.
///
/// ## Special behavior
/// If the keyword `use` appears as an selinux name `use_` is used as identifier for the
/// constructor function (e.g. `MePerm::use_()`) but the string returned by `to_selinux` will
/// still be `"use"`.
///
/// ## Example
/// ```
///
/// implement_permission!(
///     /// MyPerm documentation.
///     #[derive(Clone, Copy, Debug, PartialEq)]
///     MyPerm from EnumName with default (None, none) {}
///         Variant1,    selinux name: variant1;
///         Variant2,    selinux name: variant1;
///     }
/// );
/// ```
macro_rules! implement_permission_aidl {
    // This rule provides the public interface of the macro. And starts the preprocessing
    // recursion (see below).
    ($(#[$m:meta])* $name:ident from $aidl_name:ident with default ($($def:tt)*)
        { $($element:tt)* })
    => {
        implement_permission_aidl!(@replace_use $($m)*, $name, $aidl_name, ($($def)*), [],
            $($element)*);
    };

    // The following three rules recurse through the elements of the form
    // `<enum variant>, selinux name: <selinux_name>;`
    // preprocessing the input.

    // The first rule terminates the recursion and passes the processed arguments to the final
    // rule that spills out the implementation.
    (@replace_use $($m:meta)*, $name:ident, $aidl_name:ident, ($($def:tt)*), [$($out:tt)*], ) => {
        implement_permission_aidl!(@end $($m)*, $name, $aidl_name, ($($def)*) { $($out)* } );
    };

    // The second rule is triggered if the selinux name of an element is literally `use`.
    // It produces the tuple `<enum variant>, use_, use;`
    // and appends it to the out list.
    (@replace_use $($m:meta)*, $name:ident, $aidl_name:ident, ($($def:tt)*), [$($out:tt)*],
        $e_name:ident, selinux name: use; $($element:tt)*)
    => {
        implement_permission_aidl!(@replace_use $($m)*, $name, $aidl_name, ($($def)*),
                              [$($out)* $e_name, use_, use;], $($element)*);
    };

    // The third rule is the default rule which replaces every input tuple with
    // `<enum variant>, <selinux_name>, <selinux_name>;`
    // and appends the result to the out list.
    (@replace_use $($m:meta)*, $name:ident, $aidl_name:ident, ($($def:tt)*), [$($out:tt)*],
        $e_name:ident, selinux name: $e_str:ident; $($element:tt)*)
    => {
        implement_permission_aidl!(@replace_use $($m)*, $name, $aidl_name, ($($def)*),
                              [$($out)* $e_name, $e_str, $e_str;], $($element)*);
    };

    (@end $($m:meta)*, $name:ident, $aidl_name:ident,
        ($def_name:ident, $def_selinux_name:ident) {
            $($element_name:ident, $element_identifier:ident,
                $selinux_name:ident;)*
        })
    =>
    {
        $(#[$m])*
        pub struct $name(pub $aidl_name);

        impl From<$aidl_name> for $name {
            fn from (p: $aidl_name) -> Self {
                match p {
                    $aidl_name::$def_name => Self($aidl_name::$def_name),
                    $($aidl_name::$element_name => Self($aidl_name::$element_name),)*
                    _ => Self($aidl_name::$def_name),
                }
            }
        }

        impl Into<$aidl_name> for $name {
            fn into(self) -> $aidl_name {
                self.0
            }
        }

        impl $name {
            /// Returns a string representation of the permission as required by
            /// `selinux::check_access`.
            pub fn to_selinux(&self) -> &'static str {
                match self {
                    Self($aidl_name::$def_name) => stringify!($def_selinux_name),
                    $(Self($aidl_name::$element_name) => stringify!($selinux_name),)*
                    _ => stringify!($def_selinux_name),
                }
            }

            /// Creates an instance representing a permission with the same name.
            pub const fn $def_selinux_name() -> Self { Self($aidl_name::$def_name) }
            $(
                /// Creates an instance representing a permission with the same name.
                pub const fn $element_identifier() -> Self { Self($aidl_name::$element_name) }
            )*
        }
    };
}

implement_permission_aidl!(
    /// KeyPerm provides a convenient abstraction from the SELinux class `keystore2_key`.
    /// At the same time it maps `KeyPermissions` from the Keystore 2.0 AIDL Grant interface to
    /// the SELinux permissions. With the implement_permission macro, we conveniently
    /// provide mappings between the wire type bit field values, the rust enum and the SELinux
    /// string representation.
    ///
    /// ## Example
    ///
    /// In this access check `KeyPerm::get_info().to_selinux()` would return the SELinux representation
    /// "info".
    /// ```
    /// selinux::check_access(source_context, target_context, "keystore2_key",
    ///                       KeyPerm::get_info().to_selinux());
    /// ```
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    KeyPerm from KeyPermission with default (NONE, none) {
        CONVERT_STORAGE_KEY_TO_EPHEMERAL,   selinux name: convert_storage_key_to_ephemeral;
        DELETE,         selinux name: delete;
        GEN_UNIQUE_ID,  selinux name: gen_unique_id;
        GET_INFO,       selinux name: get_info;
        GRANT,          selinux name: grant;
        MANAGE_BLOB,    selinux name: manage_blob;
        REBIND,         selinux name: rebind;
        REQ_FORCED_OP,  selinux name: req_forced_op;
        UPDATE,         selinux name: update;
        USE,            selinux name: use;
        USE_DEV_ID,     selinux name: use_dev_id;
    }
);

/// This macro implements an enum with values mapped to SELinux permission names.
/// The below example wraps the enum MyPermission in the tuple struct `MyPerm` and implements
///  * From<i32> and Into<i32> are implemented. Where the implementation of From maps
///    any variant not specified to the default.
///  * Every variant has a constructor with a name corresponding to its lower case SELinux string
///    representation.
///  * `MyPerm.to_selinux(&self)` returns the SELinux string representation of the
///    represented permission.
///
/// ## Example
/// ```
/// implement_permission!(
///     /// MyPerm documentation.
///     #[derive(Clone, Copy, Debug, Eq, PartialEq)]
///     MyPerm with default (None = 0, none) {
///         Foo = 1,           selinux name: foo;
///         Bar = 2,           selinux name: bar;
///     }
/// );
/// ```
macro_rules! implement_permission {
    // This rule provides the public interface of the macro. And starts the preprocessing
    // recursion (see below).
    ($(#[$m:meta])* $name:ident with default
        ($def_name:ident = $def_val:expr, $def_selinux_name:ident)
        {
            $($(#[$element_meta:meta])*
            $element_name:ident = $element_val:expr, selinux name: $selinux_name:ident;)*
        })
    => {
        $(#[$m])*
        pub enum $name {
            /// The default variant of an enum.
            $def_name = $def_val,
            $(
                $(#[$element_meta])*
                $element_name = $element_val,
            )*
        }

        impl From<i32> for $name {
            fn from (p: i32) -> Self {
                match p {
                    $def_val => Self::$def_name,
                    $($element_val => Self::$element_name,)*
                    _ => Self::$def_name,
                }
            }
        }

        impl Into<i32> for $name {
            fn into(self) -> i32 {
                self as i32
            }
        }

        impl $name {
            /// Returns a string representation of the permission as required by
            /// `selinux::check_access`.
            pub fn to_selinux(&self) -> &'static str {
                match self {
                    Self::$def_name => stringify!($def_selinux_name),
                    $(Self::$element_name => stringify!($selinux_name),)*
                }
            }

            /// Creates an instance representing a permission with the same name.
            pub const fn $def_selinux_name() -> Self { Self::$def_name }
            $(
                /// Creates an instance representing a permission with the same name.
                pub const fn $selinux_name() -> Self { Self::$element_name }
            )*
        }
    };
}

implement_permission!(
    /// KeystorePerm provides a convenient abstraction from the SELinux class `keystore2`.
    /// Using the implement_permission macro we get the same features as `KeyPerm`.
    #[derive(Clone, Copy, Debug, PartialEq)]
    KeystorePerm with default (None = 0, none) {
        /// Checked when a new auth token is installed.
        AddAuth = 1,    selinux name: add_auth;
        /// Checked when an app is uninstalled or wiped.
        ClearNs = 2,    selinux name: clear_ns;
        /// Checked when the user state is queried from Keystore 2.0.
        GetState = 4,   selinux name: get_state;
        /// Checked when Keystore 2.0 is asked to list a namespace that the caller
        /// does not have the get_info permission for.
        List = 8,       selinux name: list;
        /// Checked when Keystore 2.0 gets locked.
        Lock = 0x10,       selinux name: lock;
        /// Checked when Keystore 2.0 shall be reset.
        Reset = 0x20,    selinux name: reset;
        /// Checked when Keystore 2.0 shall be unlocked.
        Unlock = 0x40,    selinux name: unlock;
        /// Checked when user is added or removed.
        ChangeUser = 0x80,    selinux name: change_user;
        /// Checked when password of the user is changed.
        ChangePassword = 0x100,    selinux name: change_password;
        /// Checked when a UID is cleared.
        ClearUID = 0x200,    selinux name: clear_uid;
        /// Checked when Credstore calls IKeystoreAuthorization to obtain auth tokens.
        GetAuthToken = 0x400,  selinux name: get_auth_token;
        /// Checked when earlyBootEnded() is called.
        EarlyBootEnded = 0x800,   selinux name: early_boot_ended;
        /// Checked when IKeystoreMaintenance::onDeviceOffBody is called.
        ReportOffBody = 0x1000, selinux name: report_off_body;
    }
);

/// Represents a set of `KeyPerm` permissions.
/// `IntoIterator` is implemented for this struct allowing the iteration through all the
/// permissions in the set.
/// It also implements a function `includes(self, other)` that checks if the permissions
/// in `other` are included in `self`.
///
/// KeyPermSet can be created with the macro `key_perm_set![]`.
///
/// ## Example
/// ```
/// let perms1 = key_perm_set![KeyPerm::use_(), KeyPerm::manage_blob(), KeyPerm::grant()];
/// let perms2 = key_perm_set![KeyPerm::use_(), KeyPerm::manage_blob()];
///
/// assert!(perms1.includes(perms2))
/// assert!(!perms2.includes(perms1))
///
/// let i = perms1.into_iter();
/// // iteration in ascending order of the permission's numeric representation.
/// assert_eq(Some(KeyPerm::manage_blob()), i.next());
/// assert_eq(Some(KeyPerm::grant()), i.next());
/// assert_eq(Some(KeyPerm::use_()), i.next());
/// assert_eq(None, i.next());
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyPermSet(pub i32);

mod perm {
    use super::*;

    pub struct IntoIter {
        vec: KeyPermSet,
        pos: u8,
    }

    impl IntoIter {
        pub fn new(v: KeyPermSet) -> Self {
            Self { vec: v, pos: 0 }
        }
    }

    impl std::iter::Iterator for IntoIter {
        type Item = KeyPerm;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                if self.pos == 32 {
                    return None;
                }
                let p = self.vec.0 & (1 << self.pos);
                self.pos += 1;
                if p != 0 {
                    return Some(KeyPerm::from(KeyPermission(p)));
                }
            }
        }
    }
}

impl From<KeyPerm> for KeyPermSet {
    fn from(p: KeyPerm) -> Self {
        Self((p.0).0 as i32)
    }
}

/// allow conversion from the AIDL wire type i32 to a permission set.
impl From<i32> for KeyPermSet {
    fn from(p: i32) -> Self {
        Self(p)
    }
}

impl From<KeyPermSet> for i32 {
    fn from(p: KeyPermSet) -> i32 {
        p.0
    }
}

impl KeyPermSet {
    /// Returns true iff this permission set has all of the permissions that are in `other`.
    pub fn includes<T: Into<KeyPermSet>>(&self, other: T) -> bool {
        let o: KeyPermSet = other.into();
        (self.0 & o.0) == o.0
    }
}

/// This macro can be used to create a `KeyPermSet` from a list of `KeyPerm` values.
///
/// ## Example
/// ```
/// let v = key_perm_set![Perm::delete(), Perm::manage_blob()];
/// ```
#[macro_export]
macro_rules! key_perm_set {
    () => { KeyPermSet(0) };
    ($head:expr $(, $tail:expr)* $(,)?) => {
        KeyPermSet(($head.0).0 $(| ($tail.0).0)*)
    };
}

impl IntoIterator for KeyPermSet {
    type Item = KeyPerm;
    type IntoIter = perm::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter::new(self)
    }
}

/// Uses `selinux::check_access` to check if the given caller context `caller_cxt` may access
/// the given permision `perm` of the `keystore2` security class.
pub fn check_keystore_permission(caller_ctx: &CStr, perm: KeystorePerm) -> anyhow::Result<()> {
    let target_context = getcon().context("check_keystore_permission: getcon failed.")?;
    selinux::check_access(caller_ctx, &target_context, "keystore2", perm.to_selinux())
}

/// Uses `selinux::check_access` to check if the given caller context `caller_cxt` has
/// all the permissions indicated in `access_vec` for the target domain indicated by the key
/// descriptor `key` in the security class `keystore2_key`.
///
/// Also checks if the caller has the grant permission for the given target domain.
///
/// Attempts to grant the grant permission are always denied.
///
/// The only viable target domains are
///  * `Domain::APP` in which case u:r:keystore:s0 is used as target context and
///  * `Domain::SELINUX` in which case the `key.nspace` parameter is looked up in
///                      SELinux keystore key backend, and the result is used
///                      as target context.
pub fn check_grant_permission(
    caller_ctx: &CStr,
    access_vec: KeyPermSet,
    key: &KeyDescriptor,
) -> anyhow::Result<()> {
    let target_context = match key.domain {
        Domain::APP => getcon().context("check_grant_permission: getcon failed.")?,
        Domain::SELINUX => lookup_keystore2_key_context(key.nspace)
            .context("check_grant_permission: Domain::SELINUX: Failed to lookup namespace.")?,
        _ => return Err(KsError::sys()).context(format!("Cannot grant {:?}.", key.domain)),
    };

    selinux::check_access(caller_ctx, &target_context, "keystore2_key", "grant")
        .context("Grant permission is required when granting.")?;

    if access_vec.includes(KeyPerm::grant()) {
        return Err(selinux::Error::perm()).context("Grant permission cannot be granted.");
    }

    for p in access_vec.into_iter() {
        selinux::check_access(caller_ctx, &target_context, "keystore2_key", p.to_selinux())
            .context(format!(
                concat!(
                    "check_grant_permission: check_access failed. ",
                    "The caller may have tried to grant a permission that they don't possess. {:?}"
                ),
                p
            ))?
    }
    Ok(())
}

/// Uses `selinux::check_access` to check if the given caller context `caller_cxt`
/// has the permissions indicated by `perm` for the target domain indicated by the key
/// descriptor `key` in the security class `keystore2_key`.
///
/// The behavior differs slightly depending on the selected target domain:
///  * `Domain::APP` u:r:keystore:s0 is used as target context.
///  * `Domain::SELINUX` `key.nspace` parameter is looked up in the SELinux keystore key
///                      backend, and the result is used as target context.
///  * `Domain::BLOB` Same as SELinux but the "manage_blob" permission is always checked additionally
///                   to the one supplied in `perm`.
///  * `Domain::GRANT` Does not use selinux::check_access. Instead the `access_vector`
///                    parameter is queried for permission, which must be supplied in this case.
///
/// ## Return values.
///  * Ok(()) If the requested permissions were granted.
///  * Err(selinux::Error::perm()) If the requested permissions were denied.
///  * Err(KsError::sys()) This error is produced if `Domain::GRANT` is selected but no `access_vec`
///                      was supplied. It is also produced if `Domain::KEY_ID` was selected, and
///                      on various unexpected backend failures.
pub fn check_key_permission(
    caller_uid: u32,
    caller_ctx: &CStr,
    perm: KeyPerm,
    key: &KeyDescriptor,
    access_vector: &Option<KeyPermSet>,
) -> anyhow::Result<()> {
    // If an access vector was supplied, the key is either accessed by GRANT or by KEY_ID.
    // In the former case, key.domain was set to GRANT and we check the failure cases
    // further below. If the access is requested by KEY_ID, key.domain would have been
    // resolved to APP or SELINUX depending on where the key actually resides.
    // Either way we can return here immediately if the access vector covers the requested
    // permission. If it does not, we can still check if the caller has access by means of
    // ownership.
    if let Some(access_vector) = access_vector {
        if access_vector.includes(perm) {
            return Ok(());
        }
    }

    let target_context = match key.domain {
        // apps get the default keystore context
        Domain::APP => {
            if caller_uid as i64 != key.nspace {
                return Err(selinux::Error::perm())
                    .context("Trying to access key without ownership.");
            }
            getcon().context("check_key_permission: getcon failed.")?
        }
        Domain::SELINUX => lookup_keystore2_key_context(key.nspace)
            .context("check_key_permission: Domain::SELINUX: Failed to lookup namespace.")?,
        Domain::GRANT => {
            match access_vector {
                Some(_) => {
                    return Err(selinux::Error::perm())
                        .context(format!("\"{}\" not granted", perm.to_selinux()));
                }
                None => {
                    // If DOMAIN_GRANT was selected an access vector must be supplied.
                    return Err(KsError::sys()).context(
                        "Cannot check permission for Domain::GRANT without access vector.",
                    );
                }
            }
        }
        Domain::KEY_ID => {
            // We should never be called with `Domain::KEY_ID. The database
            // lookup should have converted this into one of `Domain::APP`
            // or `Domain::SELINUX`.
            return Err(KsError::sys()).context("Cannot check permission for Domain::KEY_ID.");
        }
        Domain::BLOB => {
            let tctx = lookup_keystore2_key_context(key.nspace)
                .context("Domain::BLOB: Failed to lookup namespace.")?;
            // If DOMAIN_KEY_BLOB was specified, we check for the "manage_blob"
            // permission in addition to the requested permission.
            selinux::check_access(
                caller_ctx,
                &tctx,
                "keystore2_key",
                KeyPerm::manage_blob().to_selinux(),
            )?;

            tctx
        }
        _ => {
            return Err(KsError::sys())
                .context(format!("Unknown domain value: \"{:?}\".", key.domain))
        }
    };

    selinux::check_access(caller_ctx, &target_context, "keystore2_key", perm.to_selinux())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use anyhow::Result;
    use keystore2_selinux::*;

    const ALL_PERMS: KeyPermSet = key_perm_set![
        KeyPerm::manage_blob(),
        KeyPerm::delete(),
        KeyPerm::use_dev_id(),
        KeyPerm::req_forced_op(),
        KeyPerm::gen_unique_id(),
        KeyPerm::grant(),
        KeyPerm::get_info(),
        KeyPerm::rebind(),
        KeyPerm::update(),
        KeyPerm::use_(),
        KeyPerm::convert_storage_key_to_ephemeral(),
    ];

    const SYSTEM_SERVER_PERMISSIONS_NO_GRANT: KeyPermSet = key_perm_set![
        KeyPerm::delete(),
        KeyPerm::use_dev_id(),
        // No KeyPerm::grant()
        KeyPerm::get_info(),
        KeyPerm::rebind(),
        KeyPerm::update(),
        KeyPerm::use_(),
    ];

    const NOT_GRANT_PERMS: KeyPermSet = key_perm_set![
        KeyPerm::manage_blob(),
        KeyPerm::delete(),
        KeyPerm::use_dev_id(),
        KeyPerm::req_forced_op(),
        KeyPerm::gen_unique_id(),
        // No KeyPerm::grant()
        KeyPerm::get_info(),
        KeyPerm::rebind(),
        KeyPerm::update(),
        KeyPerm::use_(),
        KeyPerm::convert_storage_key_to_ephemeral(),
    ];

    const UNPRIV_PERMS: KeyPermSet = key_perm_set![
        KeyPerm::delete(),
        KeyPerm::get_info(),
        KeyPerm::rebind(),
        KeyPerm::update(),
        KeyPerm::use_(),
    ];

    /// The su_key namespace as defined in su.te and keystore_key_contexts of the
    /// SePolicy (system/sepolicy).
    const SU_KEY_NAMESPACE: i32 = 0;
    /// The shell_key namespace as defined in shell.te and keystore_key_contexts of the
    /// SePolicy (system/sepolicy).
    const SHELL_KEY_NAMESPACE: i32 = 1;

    pub fn test_getcon() -> Result<Context> {
        Context::new("u:object_r:keystore:s0")
    }

    // This macro evaluates the given expression and checks that
    // a) evaluated to Result::Err() and that
    // b) the wrapped error is selinux::Error::perm() (permission denied).
    // We use a macro here because a function would mask which invocation caused the failure.
    //
    // TODO b/164121720 Replace this macro with a function when `track_caller` is available.
    macro_rules! assert_perm_failed {
        ($test_function:expr) => {
            let result = $test_function;
            assert!(result.is_err(), "Permission check should have failed.");
            assert_eq!(
                Some(&selinux::Error::perm()),
                result.err().unwrap().root_cause().downcast_ref::<selinux::Error>()
            );
        };
    }

    fn check_context() -> Result<(selinux::Context, i32, bool)> {
        // Calling the non mocked selinux::getcon here intended.
        let context = selinux::getcon()?;
        match context.to_str().unwrap() {
            "u:r:su:s0" => Ok((context, SU_KEY_NAMESPACE, true)),
            "u:r:shell:s0" => Ok((context, SHELL_KEY_NAMESPACE, false)),
            c => Err(anyhow!(format!(
                "This test must be run as \"su\" or \"shell\". Current context: \"{}\"",
                c
            ))),
        }
    }

    #[test]
    fn check_keystore_permission_test() -> Result<()> {
        let system_server_ctx = Context::new("u:r:system_server:s0")?;
        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::add_auth()).is_ok());
        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::clear_ns()).is_ok());
        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::get_state()).is_ok());
        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::lock()).is_ok());
        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::reset()).is_ok());
        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::unlock()).is_ok());
        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::change_user()).is_ok());
        assert!(
            check_keystore_permission(&system_server_ctx, KeystorePerm::change_password()).is_ok()
        );
        assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::clear_uid()).is_ok());
        let shell_ctx = Context::new("u:r:shell:s0")?;
        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::add_auth()));
        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::clear_ns()));
        assert!(check_keystore_permission(&shell_ctx, KeystorePerm::get_state()).is_ok());
        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::list()));
        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::lock()));
        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::reset()));
        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::unlock()));
        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::change_user()));
        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::change_password()));
        assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::clear_uid()));
        Ok(())
    }

    #[test]
    fn check_grant_permission_app() -> Result<()> {
        let system_server_ctx = Context::new("u:r:system_server:s0")?;
        let shell_ctx = Context::new("u:r:shell:s0")?;
        let key = KeyDescriptor { domain: Domain::APP, nspace: 0, alias: None, blob: None };
        check_grant_permission(&system_server_ctx, SYSTEM_SERVER_PERMISSIONS_NO_GRANT, &key)
            .expect("Grant permission check failed.");

        // attempts to grant the grant permission must always fail even when privileged.
        assert_perm_failed!(check_grant_permission(
            &system_server_ctx,
            KeyPerm::grant().into(),
            &key
        ));
        // unprivileged grant attempts always fail. shell does not have the grant permission.
        assert_perm_failed!(check_grant_permission(&shell_ctx, UNPRIV_PERMS, &key));
        Ok(())
    }

    #[test]
    fn check_grant_permission_selinux() -> Result<()> {
        let (sctx, namespace, is_su) = check_context()?;
        let key = KeyDescriptor {
            domain: Domain::SELINUX,
            nspace: namespace as i64,
            alias: None,
            blob: None,
        };
        if is_su {
            assert!(check_grant_permission(&sctx, NOT_GRANT_PERMS, &key).is_ok());
            // attempts to grant the grant permission must always fail even when privileged.
            assert_perm_failed!(check_grant_permission(&sctx, KeyPerm::grant().into(), &key));
        } else {
            // unprivileged grant attempts always fail. shell does not have the grant permission.
            assert_perm_failed!(check_grant_permission(&sctx, UNPRIV_PERMS, &key));
        }
        Ok(())
    }

    #[test]
    fn check_key_permission_domain_grant() -> Result<()> {
        let key = KeyDescriptor { domain: Domain::GRANT, nspace: 0, alias: None, blob: None };

        assert_perm_failed!(check_key_permission(
            0,
            &selinux::Context::new("ignored").unwrap(),
            KeyPerm::grant(),
            &key,
            &Some(UNPRIV_PERMS)
        ));

        check_key_permission(
            0,
            &selinux::Context::new("ignored").unwrap(),
            KeyPerm::use_(),
            &key,
            &Some(ALL_PERMS),
        )
    }

    #[test]
    fn check_key_permission_domain_app() -> Result<()> {
        let system_server_ctx = Context::new("u:r:system_server:s0")?;
        let shell_ctx = Context::new("u:r:shell:s0")?;
        let gmscore_app = Context::new("u:r:gmscore_app:s0")?;

        let key = KeyDescriptor { domain: Domain::APP, nspace: 0, alias: None, blob: None };

        assert!(check_key_permission(0, &system_server_ctx, KeyPerm::use_(), &key, &None).is_ok());
        assert!(check_key_permission(0, &system_server_ctx, KeyPerm::delete(), &key, &None).is_ok());
        assert!(
            check_key_permission(0, &system_server_ctx, KeyPerm::get_info(), &key, &None).is_ok()
        );
        assert!(check_key_permission(0, &system_server_ctx, KeyPerm::rebind(), &key, &None).is_ok());
        assert!(check_key_permission(0, &system_server_ctx, KeyPerm::update(), &key, &None).is_ok());
        assert!(check_key_permission(0, &system_server_ctx, KeyPerm::grant(), &key, &None).is_ok());
        assert!(
            check_key_permission(0, &system_server_ctx, KeyPerm::use_dev_id(), &key, &None).is_ok()
        );
        assert!(
            check_key_permission(0, &gmscore_app, KeyPerm::gen_unique_id(), &key, &None).is_ok()
        );

        assert!(check_key_permission(0, &shell_ctx, KeyPerm::use_(), &key, &None).is_ok());
        assert!(check_key_permission(0, &shell_ctx, KeyPerm::delete(), &key, &None).is_ok());
        assert!(check_key_permission(0, &shell_ctx, KeyPerm::get_info(), &key, &None).is_ok());
        assert!(check_key_permission(0, &shell_ctx, KeyPerm::rebind(), &key, &None).is_ok());
        assert!(check_key_permission(0, &shell_ctx, KeyPerm::update(), &key, &None).is_ok());
        assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::grant(), &key, &None));
        assert_perm_failed!(check_key_permission(
            0,
            &shell_ctx,
            KeyPerm::req_forced_op(),
            &key,
            &None
        ));
        assert_perm_failed!(check_key_permission(
            0,
            &shell_ctx,
            KeyPerm::manage_blob(),
            &key,
            &None
        ));
        assert_perm_failed!(check_key_permission(
            0,
            &shell_ctx,
            KeyPerm::use_dev_id(),
            &key,
            &None
        ));
        assert_perm_failed!(check_key_permission(
            0,
            &shell_ctx,
            KeyPerm::gen_unique_id(),
            &key,
            &None
        ));

        // Also make sure that the permission fails if the caller is not the owner.
        assert_perm_failed!(check_key_permission(
            1, // the owner is 0
            &system_server_ctx,
            KeyPerm::use_(),
            &key,
            &None
        ));
        // Unless there was a grant.
        assert!(check_key_permission(
            1,
            &system_server_ctx,
            KeyPerm::use_(),
            &key,
            &Some(key_perm_set![KeyPerm::use_()])
        )
        .is_ok());
        // But fail if the grant did not cover the requested permission.
        assert_perm_failed!(check_key_permission(
            1,
            &system_server_ctx,
            KeyPerm::use_(),
            &key,
            &Some(key_perm_set![KeyPerm::get_info()])
        ));

        Ok(())
    }

    #[test]
    fn check_key_permission_domain_selinux() -> Result<()> {
        let (sctx, namespace, is_su) = check_context()?;
        let key = KeyDescriptor {
            domain: Domain::SELINUX,
            nspace: namespace as i64,
            alias: None,
            blob: None,
        };

        if is_su {
            assert!(check_key_permission(0, &sctx, KeyPerm::use_(), &key, &None).is_ok());
            assert!(check_key_permission(0, &sctx, KeyPerm::delete(), &key, &None).is_ok());
            assert!(check_key_permission(0, &sctx, KeyPerm::get_info(), &key, &None).is_ok());
            assert!(check_key_permission(0, &sctx, KeyPerm::rebind(), &key, &None).is_ok());
            assert!(check_key_permission(0, &sctx, KeyPerm::update(), &key, &None).is_ok());
            assert!(check_key_permission(0, &sctx, KeyPerm::grant(), &key, &None).is_ok());
            assert!(check_key_permission(0, &sctx, KeyPerm::manage_blob(), &key, &None).is_ok());
            assert!(check_key_permission(0, &sctx, KeyPerm::use_dev_id(), &key, &None).is_ok());
            assert!(check_key_permission(0, &sctx, KeyPerm::gen_unique_id(), &key, &None).is_ok());
            assert!(check_key_permission(0, &sctx, KeyPerm::req_forced_op(), &key, &None).is_ok());
        } else {
            assert!(check_key_permission(0, &sctx, KeyPerm::use_(), &key, &None).is_ok());
            assert!(check_key_permission(0, &sctx, KeyPerm::delete(), &key, &None).is_ok());
            assert!(check_key_permission(0, &sctx, KeyPerm::get_info(), &key, &None).is_ok());
            assert!(check_key_permission(0, &sctx, KeyPerm::rebind(), &key, &None).is_ok());
            assert!(check_key_permission(0, &sctx, KeyPerm::update(), &key, &None).is_ok());
            assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::grant(), &key, &None));
            assert_perm_failed!(check_key_permission(
                0,
                &sctx,
                KeyPerm::req_forced_op(),
                &key,
                &None
            ));
            assert_perm_failed!(check_key_permission(
                0,
                &sctx,
                KeyPerm::manage_blob(),
                &key,
                &None
            ));
            assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::use_dev_id(), &key, &None));
            assert_perm_failed!(check_key_permission(
                0,
                &sctx,
                KeyPerm::gen_unique_id(),
                &key,
                &None
            ));
        }
        Ok(())
    }

    #[test]
    fn check_key_permission_domain_blob() -> Result<()> {
        let (sctx, namespace, is_su) = check_context()?;
        let key = KeyDescriptor {
            domain: Domain::BLOB,
            nspace: namespace as i64,
            alias: None,
            blob: None,
        };

        if is_su {
            check_key_permission(0, &sctx, KeyPerm::use_(), &key, &None)
        } else {
            assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::use_(), &key, &None));
            Ok(())
        }
    }

    #[test]
    fn check_key_permission_domain_key_id() -> Result<()> {
        let key = KeyDescriptor { domain: Domain::KEY_ID, nspace: 0, alias: None, blob: None };

        assert_eq!(
            Some(&KsError::sys()),
            check_key_permission(
                0,
                &selinux::Context::new("ignored").unwrap(),
                KeyPerm::use_(),
                &key,
                &None
            )
            .err()
            .unwrap()
            .root_cause()
            .downcast_ref::<KsError>()
        );
        Ok(())
    }

    #[test]
    fn key_perm_set_all_test() {
        let v = key_perm_set![
            KeyPerm::manage_blob(),
            KeyPerm::delete(),
            KeyPerm::use_dev_id(),
            KeyPerm::req_forced_op(),
            KeyPerm::gen_unique_id(),
            KeyPerm::grant(),
            KeyPerm::get_info(),
            KeyPerm::rebind(),
            KeyPerm::update(),
            KeyPerm::use_() // Test if the macro accepts missing comma at the end of the list.
        ];
        let mut i = v.into_iter();
        assert_eq!(i.next().unwrap().to_selinux(), "delete");
        assert_eq!(i.next().unwrap().to_selinux(), "gen_unique_id");
        assert_eq!(i.next().unwrap().to_selinux(), "get_info");
        assert_eq!(i.next().unwrap().to_selinux(), "grant");
        assert_eq!(i.next().unwrap().to_selinux(), "manage_blob");
        assert_eq!(i.next().unwrap().to_selinux(), "rebind");
        assert_eq!(i.next().unwrap().to_selinux(), "req_forced_op");
        assert_eq!(i.next().unwrap().to_selinux(), "update");
        assert_eq!(i.next().unwrap().to_selinux(), "use");
        assert_eq!(i.next().unwrap().to_selinux(), "use_dev_id");
        assert_eq!(None, i.next());
    }
    #[test]
    fn key_perm_set_sparse_test() {
        let v = key_perm_set![
            KeyPerm::manage_blob(),
            KeyPerm::req_forced_op(),
            KeyPerm::gen_unique_id(),
            KeyPerm::update(),
            KeyPerm::use_(), // Test if macro accepts the comma at the end of the list.
        ];
        let mut i = v.into_iter();
        assert_eq!(i.next().unwrap().to_selinux(), "gen_unique_id");
        assert_eq!(i.next().unwrap().to_selinux(), "manage_blob");
        assert_eq!(i.next().unwrap().to_selinux(), "req_forced_op");
        assert_eq!(i.next().unwrap().to_selinux(), "update");
        assert_eq!(i.next().unwrap().to_selinux(), "use");
        assert_eq!(None, i.next());
    }
    #[test]
    fn key_perm_set_empty_test() {
        let v = key_perm_set![];
        let mut i = v.into_iter();
        assert_eq!(None, i.next());
    }
    #[test]
    fn key_perm_set_include_subset_test() {
        let v1 = key_perm_set![
            KeyPerm::manage_blob(),
            KeyPerm::delete(),
            KeyPerm::use_dev_id(),
            KeyPerm::req_forced_op(),
            KeyPerm::gen_unique_id(),
            KeyPerm::grant(),
            KeyPerm::get_info(),
            KeyPerm::rebind(),
            KeyPerm::update(),
            KeyPerm::use_(),
        ];
        let v2 = key_perm_set![
            KeyPerm::manage_blob(),
            KeyPerm::delete(),
            KeyPerm::rebind(),
            KeyPerm::update(),
            KeyPerm::use_(),
        ];
        assert!(v1.includes(v2));
        assert!(!v2.includes(v1));
    }
    #[test]
    fn key_perm_set_include_equal_test() {
        let v1 = key_perm_set![
            KeyPerm::manage_blob(),
            KeyPerm::delete(),
            KeyPerm::rebind(),
            KeyPerm::update(),
            KeyPerm::use_(),
        ];
        let v2 = key_perm_set![
            KeyPerm::manage_blob(),
            KeyPerm::delete(),
            KeyPerm::rebind(),
            KeyPerm::update(),
            KeyPerm::use_(),
        ];
        assert!(v1.includes(v2));
        assert!(v2.includes(v1));
    }
    #[test]
    fn key_perm_set_include_overlap_test() {
        let v1 = key_perm_set![
            KeyPerm::manage_blob(),
            KeyPerm::delete(),
            KeyPerm::grant(), // only in v1
            KeyPerm::rebind(),
            KeyPerm::update(),
            KeyPerm::use_(),
        ];
        let v2 = key_perm_set![
            KeyPerm::manage_blob(),
            KeyPerm::delete(),
            KeyPerm::req_forced_op(), // only in v2
            KeyPerm::rebind(),
            KeyPerm::update(),
            KeyPerm::use_(),
        ];
        assert!(!v1.includes(v2));
        assert!(!v2.includes(v1));
    }
    #[test]
    fn key_perm_set_include_no_overlap_test() {
        let v1 = key_perm_set![KeyPerm::manage_blob(), KeyPerm::delete(), KeyPerm::grant(),];
        let v2 = key_perm_set![
            KeyPerm::req_forced_op(),
            KeyPerm::rebind(),
            KeyPerm::update(),
            KeyPerm::use_(),
        ];
        assert!(!v1.includes(v2));
        assert!(!v2.includes(v1));
    }
}
