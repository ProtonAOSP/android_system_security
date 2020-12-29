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

//! Key parameters are declared by KeyMint to describe properties of keys and operations.
//! During key generation and import, key parameters are used to characterize a key, its usage
//! restrictions, and additional parameters for attestation. During the lifetime of the key,
//! the key characteristics are expressed as set of key parameters. During cryptographic
//! operations, clients may specify additional operation specific parameters.
//! This module provides a Keystore 2.0 internal representation for key parameters and
//! implements traits to convert it from and into KeyMint KeyParameters and store it in
//! the SQLite database.
//!
//! ## Synopsis
//!
//! enum KeyParameterValue {
//!     Invalid,
//!     Algorithm(Algorithm),
//!     ...
//! }
//!
//! impl KeyParameterValue {
//!     pub fn get_tag(&self) -> Tag;
//!     pub fn new_from_sql(tag: Tag, data: &SqlField) -> Result<Self>;
//!     pub fn new_from_tag_primitive_pair<T: Into<Primitive>>(tag: Tag, v: T)
//!        -> Result<Self, PrimitiveError>;
//!     fn to_sql(&self) -> SqlResult<ToSqlOutput>
//! }
//!
//! use ...::keymint::KeyParameter as KmKeyParameter;
//! impl Into<KmKeyParameter> for KeyParameterValue {}
//! impl From<KmKeyParameter> for KeyParameterValue {}
//!
//! ## Implementation
//! Each of the six functions is implemented as match statement over each key parameter variant.
//! We bootstrap these function as well as the KeyParameterValue enum itself from a single list
//! of key parameters, that needs to be kept in sync with the KeyMint AIDL specification.
//!
//! The list resembles an enum declaration with a few extra fields.
//! enum KeyParameterValue {
//!    Invalid with tag INVALID and field Invalid,
//!    Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
//!    ...
//! }
//! The tag corresponds to the variant of the keymint::Tag, and the field corresponds to the
//! variant of the keymint::KeyParameterValue union. There is no one to one mapping between
//! tags and union fields, e.g., the values of both tags BOOT_PATCHLEVEL and VENDOR_PATCHLEVEL
//! are stored in the Integer field.
//!
//! The macros interpreting them all follow a similar pattern and follow the following fragment
//! naming scheme:
//!
//!    Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
//!    $vname $(($vtype ))? with tag $tag_name and field $field_name,
//!
//! Further, KeyParameterValue appears in the macro as $enum_name.
//! Note that $vtype is optional to accommodate variants like Invalid which don't wrap a value.
//!
//! In some cases $vtype is not part of the expansion, but we still have to modify the expansion
//! depending on the presence of $vtype. In these cases we recurse through the list following the
//! following pattern:
//!
//! (@<marker> <non repeating args>, [<out list>], [<in list>])
//!
//! These macros usually have four rules:
//!  * Two main recursive rules, of the form:
//!    (
//!        @<marker>
//!        <non repeating args>,
//!        [<out list>],
//!        [<one element pattern> <in tail>]
//!    ) => {
//!        macro!{@<marker> <non repeating args>, [<out list>
//!            <one element expansion>
//!        ], [<in tail>]}
//!    };
//!    They pop one element off the <in list> and add one expansion to the out list.
//!    The element expansion is kept on a separate line (or lines) for better readability.
//!    The two variants differ in whether or not $vtype is expected.
//!  * The termination condition which has an empty in list.
//!  * The public interface, which does not have @marker and calls itself with an empty out list.

use std::convert::TryInto;

use crate::db_utils::SqlField;
use crate::error::Error as KeystoreError;
use crate::error::ResponseCode;

pub use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    HardwareAuthenticatorType::HardwareAuthenticatorType, KeyOrigin::KeyOrigin,
    KeyParameter::KeyParameter as KmKeyParameter,
    KeyParameterValue::KeyParameterValue as KmKeyParameterValue, KeyPurpose::KeyPurpose,
    PaddingMode::PaddingMode, SecurityLevel::SecurityLevel, Tag::Tag,
};
use android_system_keystore2::aidl::android::system::keystore2::Authorization::Authorization;
use anyhow::{Context, Result};
use rusqlite::types::{Null, ToSql, ToSqlOutput};
use rusqlite::Result as SqlResult;

/// This trait is used to associate a primitive to any type that can be stored inside a
/// KeyParameterValue, especially the AIDL enum types, e.g., keymint::{Algorithm, Digest, ...}.
/// This allows for simplifying the macro rules, e.g., for reading from the SQL database.
/// An expression like `KeyParameterValue::Algorithm(row.get(0))` would not work because
/// a type of `Algorithm` is expected which does not implement `FromSql` and we cannot
/// implement it because we own neither the type nor the trait.
/// With AssociatePrimitive we can write an expression
/// `KeyParameter::Algorithm(<Algorithm>::from_primitive(row.get(0)))` to inform `get`
/// about the expected primitive type that it can convert into. By implementing this
/// trait for all inner types we can write a single rule to cover all cases (except where
/// there is no wrapped type):
/// `KeyParameterValue::$vname(<$vtype>::from_primitive(row.get(0)))`
trait AssociatePrimitive {
    type Primitive;

    fn from_primitive(v: Self::Primitive) -> Self;
    fn to_primitive(&self) -> Self::Primitive;
}

/// Associates the given type with i32. The macro assumes that the given type is actually a
/// tuple struct wrapping i32, such as AIDL enum types.
macro_rules! implement_associate_primitive_for_aidl_enum {
    ($t:ty) => {
        impl AssociatePrimitive for $t {
            type Primitive = i32;

            fn from_primitive(v: Self::Primitive) -> Self {
                Self(v)
            }
            fn to_primitive(&self) -> Self::Primitive {
                self.0
            }
        }
    };
}

/// Associates the given type with itself.
macro_rules! implement_associate_primitive_identity {
    ($t:ty) => {
        impl AssociatePrimitive for $t {
            type Primitive = $t;

            fn from_primitive(v: Self::Primitive) -> Self {
                v
            }
            fn to_primitive(&self) -> Self::Primitive {
                self.clone()
            }
        }
    };
}

implement_associate_primitive_for_aidl_enum! {Algorithm}
implement_associate_primitive_for_aidl_enum! {BlockMode}
implement_associate_primitive_for_aidl_enum! {Digest}
implement_associate_primitive_for_aidl_enum! {EcCurve}
implement_associate_primitive_for_aidl_enum! {HardwareAuthenticatorType}
implement_associate_primitive_for_aidl_enum! {KeyOrigin}
implement_associate_primitive_for_aidl_enum! {KeyPurpose}
implement_associate_primitive_for_aidl_enum! {PaddingMode}
implement_associate_primitive_for_aidl_enum! {SecurityLevel}

implement_associate_primitive_identity! {Vec<u8>}
implement_associate_primitive_identity! {i64}
implement_associate_primitive_identity! {i32}

/// This enum allows passing a primitive value to `KeyParameterValue::new_from_tag_primitive_pair`
/// Usually, it is not necessary to use this type directly because the function uses
/// `Into<Primitive>` as a trait bound.
pub enum Primitive {
    /// Wraps an i64.
    I64(i64),
    /// Wraps an i32.
    I32(i32),
    /// Wraps a Vec<u8>.
    Vec(Vec<u8>),
}

impl From<i64> for Primitive {
    fn from(v: i64) -> Self {
        Self::I64(v)
    }
}
impl From<i32> for Primitive {
    fn from(v: i32) -> Self {
        Self::I32(v)
    }
}
impl From<Vec<u8>> for Primitive {
    fn from(v: Vec<u8>) -> Self {
        Self::Vec(v)
    }
}

/// This error is returned by `KeyParameterValue::new_from_tag_primitive_pair`.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrimitiveError {
    /// Returned if this primitive is unsuitable for the given tag type.
    #[error("Primitive does not match the expected tag type.")]
    TypeMismatch,
    /// Return if the tag type is unknown.
    #[error("Unknown tag.")]
    UnknownTag,
}

impl TryInto<i64> for Primitive {
    type Error = PrimitiveError;

    fn try_into(self) -> Result<i64, Self::Error> {
        match self {
            Self::I64(v) => Ok(v),
            _ => Err(Self::Error::TypeMismatch),
        }
    }
}
impl TryInto<i32> for Primitive {
    type Error = PrimitiveError;

    fn try_into(self) -> Result<i32, Self::Error> {
        match self {
            Self::I32(v) => Ok(v),
            _ => Err(Self::Error::TypeMismatch),
        }
    }
}
impl TryInto<Vec<u8>> for Primitive {
    type Error = PrimitiveError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::Vec(v) => Ok(v),
            _ => Err(Self::Error::TypeMismatch),
        }
    }
}

/// Expands the list of KeyParameterValue variants as follows:
///
/// Input:
/// Invalid with tag INVALID and field Invalid,
/// Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
///
/// Output:
/// ```
/// pub fn new_from_tag_primitive_pair<T: Into<Primitive>>(
///     tag: Tag,
///     v: T
/// ) -> Result<KeyParameterValue, PrimitiveError> {
///     let p: Primitive = v.into();
///     Ok(match tag {
///         Tag::INVALID => KeyParameterValue::Invalid,
///         Tag::ALGORITHM => KeyParameterValue::Algorithm(
///             <Algorithm>::from_primitive(p.try_into()?)
///         ),
///         _ => return Err(PrimitiveError::UnknownTag),
///     })
/// }
/// ```
macro_rules! implement_from_tag_primitive_pair {
    ($enum_name:ident; $($vname:ident$(($vtype:ty))? $tag_name:ident),*) => {
        /// Returns the an instance of $enum_name or an error if the given primitive does not match
        /// the tag type or the tag is unknown.
        pub fn new_from_tag_primitive_pair<T: Into<Primitive>>(
            tag: Tag,
            v: T
        ) -> Result<$enum_name, PrimitiveError> {
            let p: Primitive = v.into();
            Ok(match tag {
                $(Tag::$tag_name => $enum_name::$vname$((
                    <$vtype>::from_primitive(p.try_into()?)
                ))?,)*
                _ => return Err(PrimitiveError::UnknownTag),
            })
        }
    };
}

/// Expands the list of KeyParameterValue variants as follows:
///
/// Input:
/// pub enum KeyParameterValue {
///     Invalid with tag INVALID and field Invalid,
///     Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
/// }
///
/// Output:
/// ```
/// pub enum KeyParameterValue {
///     Invalid,
///     Algorithm(Algorithm),
/// }
/// ```
macro_rules! implement_enum {
    (
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
             $($(#[$emeta:meta])* $vname:ident$(($vtype:ty))?),* $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        $enum_vis enum $enum_name {
            $(
                $(#[$emeta])*
                $vname$(($vtype))?
            ),*
        }
    };
}

/// Expands the list of KeyParameterValue variants as follows:
///
/// Input:
/// Invalid with tag INVALID and field Invalid,
/// Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
///
/// Output:
/// ```
/// pub fn get_tag(&self) -> Tag {
///     match self {
///         KeyParameterValue::Invalid => Tag::INVALID,
///         KeyParameterValue::Algorithm(_) => Tag::ALGORITHM,
///     }
/// }
/// ```
macro_rules! implement_get_tag {
    (
        @replace_type_spec
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident($vtype:ty) $tag_name:ident, $($in:tt)*]
    ) => {
        implement_get_tag!{@replace_type_spec $enum_name, [$($out)*
            $enum_name::$vname(_) => Tag::$tag_name,
        ], [$($in)*]}
    };
    (
        @replace_type_spec
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident $tag_name:ident, $($in:tt)*]
    ) => {
        implement_get_tag!{@replace_type_spec $enum_name, [$($out)*
            $enum_name::$vname => Tag::$tag_name,
        ], [$($in)*]}
    };
    (@replace_type_spec $enum_name:ident, [$($out:tt)*], []) => {
        /// Returns the tag of the given instance.
        pub fn get_tag(&self) -> Tag {
            match self {
                $($out)*
            }
        }
    };

    ($enum_name:ident; $($vname:ident$(($vtype:ty))? $tag_name:ident),*) => {
        implement_get_tag!{@replace_type_spec $enum_name, [], [$($vname$(($vtype))? $tag_name,)*]}
    };
}

/// Expands the list of KeyParameterValue variants as follows:
///
/// Input:
/// Invalid with tag INVALID and field Invalid,
/// Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
///
/// Output:
/// ```
/// fn to_sql(&self) -> SqlResult<ToSqlOutput> {
///     match self {
///         KeyParameterValue::Invalid => Ok(ToSqlOutput::from(Null)),
///         KeyParameterValue::Algorithm(v) => Ok(ToSqlOutput::from(v.to_primitive())),
///     }
/// }
/// ```
macro_rules! implement_to_sql {
    (
        @replace_type_spec
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident($vtype:ty), $($in:tt)*]
    ) => {
        implement_to_sql!{@replace_type_spec $enum_name, [ $($out)*
            $enum_name::$vname(v) => Ok(ToSqlOutput::from(v.to_primitive())),
        ], [$($in)*]}
    };
    (
        @replace_type_spec
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident, $($in:tt)*]
    ) => {
        implement_to_sql!{@replace_type_spec $enum_name, [ $($out)*
            $enum_name::$vname => Ok(ToSqlOutput::from(Null)),
        ], [$($in)*]}
    };
    (@replace_type_spec $enum_name:ident, [$($out:tt)*], []) => {
        /// Converts $enum_name to be stored in a rusqlite database.
        fn to_sql(&self) -> SqlResult<ToSqlOutput> {
            match self {
                $($out)*
            }
        }
    };


    ($enum_name:ident; $($vname:ident$(($vtype:ty))?),*) => {
        impl ToSql for $enum_name {
            implement_to_sql!{@replace_type_spec $enum_name, [], [$($vname$(($vtype))?,)*]}
        }

    }
}

/// Expands the list of KeyParameterValue variants as follows:
///
/// Input:
/// Invalid with tag INVALID and field Invalid,
/// Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
///
/// Output:
/// ```
/// pub fn new_from_sql(
///     tag: Tag,
///     data: &SqlField,
/// ) -> Result<Self> {
///     Ok(match self {
///         Tag::Invalid => KeyParameterValue::Invalid,
///         Tag::ALGORITHM => {
///             KeyParameterValue::Algorithm(<Algorithm>::from_primitive(data
///                 .get()
///                 .map_err(|_| KeystoreError::Rc(ResponseCode::VALUE_CORRUPTED))
///                 .context(concat!("Failed to read sql data for tag: ", "ALGORITHM", "."))?
///             ))
///         },
///     })
/// }
/// ```
macro_rules! implement_new_from_sql {
    ($enum_name:ident; $($vname:ident$(($vtype:ty))? $tag_name:ident),*) => {
        /// Takes a tag and an SqlField and attempts to construct a KeyParameter value.
        /// This function may fail if the parameter value cannot be extracted from the
        /// database cell.
        pub fn new_from_sql(
            tag: Tag,
            data: &SqlField,
        ) -> Result<Self> {
            Ok(match tag {
                $(
                    Tag::$tag_name => {
                        $enum_name::$vname$((<$vtype>::from_primitive(data
                            .get()
                            .map_err(|_| KeystoreError::Rc(ResponseCode::VALUE_CORRUPTED))
                            .context(concat!(
                                "Failed to read sql data for tag: ",
                                stringify!($tag_name),
                                "."
                            ))?
                        )))?
                    },
                )*
                _ => $enum_name::Invalid,
            })
        }
    };
}

/// This key parameter default is used during the conversion from KeyParameterValue
/// to keymint::KeyParameterValue. Keystore's version does not have wrapped types
/// for boolean tags and the tag Invalid. The AIDL version uses bool and integer
/// variants respectively. This default function is invoked in these cases to
/// homogenize the rules for boolean and invalid tags.
/// The bool variant returns true because boolean parameters are implicitly true
/// if present.
trait KpDefault {
    fn default() -> Self;
}

impl KpDefault for i32 {
    fn default() -> Self {
        0
    }
}

impl KpDefault for bool {
    fn default() -> Self {
        true
    }
}

/// Expands the list of KeyParameterValue variants as follows:
///
/// Input:
/// Invalid with tag INVALID and field Invalid,
/// Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
///
/// Output:
/// ```
/// impl From<KmKeyParameter> for KeyParameterValue {
///     fn from(kp: KmKeyParameter) -> Self {
///         match kp {
///             KmKeyParameter { tag: Tag::INVALID, value: KmKeyParameterValue::Invalid(_) }
///                 => $enum_name::$vname,
///             KmKeyParameter { tag: Tag::Algorithm, value: KmKeyParameterValue::Algorithm(v) }
///                 => $enum_name::Algorithm(v),
///             _ => $enum_name::Invalid,
///         }
///     }
/// }
///
/// impl Into<KmKeyParameter> for KeyParameterValue {
///     fn into(self) -> KmKeyParameter {
///         match self {
///             KeyParameterValue::Invalid => KmKeyParameter {
///                 tag: Tag::INVALID,
///                 value: KmKeyParameterValue::Invalid(KpDefault::default())
///             },
///             KeyParameterValue::Algorithm(v) => KmKeyParameter {
///                 tag: Tag::ALGORITHM,
///                 value: KmKeyParameterValue::Algorithm(v)
///             },
///         }
///     }
/// }
/// ```
macro_rules! implement_try_from_to_km_parameter {
    // The first three rules expand From<KmKeyParameter>.
    (
        @from
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident($vtype:ty) $tag_name:ident $field_name:ident, $($in:tt)*]
    ) => {
        implement_try_from_to_km_parameter!{@from $enum_name, [$($out)*
            KmKeyParameter {
                tag: Tag::$tag_name,
                value: KmKeyParameterValue::$field_name(v)
            } => $enum_name::$vname(v),
        ], [$($in)*]
    }};
    (
        @from
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident $tag_name:ident $field_name:ident, $($in:tt)*]
    ) => {
        implement_try_from_to_km_parameter!{@from $enum_name, [$($out)*
            KmKeyParameter {
                tag: Tag::$tag_name,
                value: KmKeyParameterValue::$field_name(_)
            } => $enum_name::$vname,
        ], [$($in)*]
    }};
    (@from $enum_name:ident, [$($out:tt)*], []) => {
        impl From<KmKeyParameter> for $enum_name {
            fn from(kp: KmKeyParameter) -> Self {
                match kp {
                    $($out)*
                    _ => $enum_name::Invalid,
                }
            }
        }
    };

    // The next three rules expand Into<KmKeyParameter>.
    (
        @into
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident($vtype:ty) $tag_name:ident $field_name:ident, $($in:tt)*]
    ) => {
        implement_try_from_to_km_parameter!{@into $enum_name, [$($out)*
            $enum_name::$vname(v) => KmKeyParameter {
                tag: Tag::$tag_name,
                value: KmKeyParameterValue::$field_name(v)
            },
        ], [$($in)*]
    }};
    (
        @into
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident $tag_name:ident $field_name:ident, $($in:tt)*]
    ) => {
        implement_try_from_to_km_parameter!{@into $enum_name, [$($out)*
            $enum_name::$vname => KmKeyParameter {
                tag: Tag::$tag_name,
                value: KmKeyParameterValue::$field_name(KpDefault::default())
            },
        ], [$($in)*]
    }};
    (@into $enum_name:ident, [$($out:tt)*], []) => {
        impl Into<KmKeyParameter> for $enum_name {
            fn into(self) -> KmKeyParameter {
                match self {
                    $($out)*
                }
            }
        }
    };


    ($enum_name:ident; $($vname:ident$(($vtype:ty))? $tag_name:ident $field_name:ident),*) => {
        implement_try_from_to_km_parameter!(
            @from $enum_name,
            [],
            [$($vname$(($vtype))? $tag_name $field_name,)*]
        );
        implement_try_from_to_km_parameter!(
            @into $enum_name,
            [],
            [$($vname$(($vtype))? $tag_name $field_name,)*]
        );
    };
}

/// This is the top level macro. While the other macros do most of the heavy lifting, this takes
/// the key parameter list and passes it on to the other macros to generate all of the conversion
/// functions. In addition, it generates an important test vector for verifying that tag type of the
/// keymint tag matches the associated keymint KeyParameterValue field.
macro_rules! implement_key_parameter_value {
    (
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $(
                 $(#[$emeta:meta])*
                $vname:ident$(($vtype:ty))? with tag $tag_name:ident and field $field_name:ident
            ),* $(,)?
        }
    ) => {
        implement_enum!(
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
            $(
                $(#[$emeta])*
                $vname$(($vtype))?
            ),*
        });

        impl $enum_name {
            implement_new_from_sql!($enum_name; $($vname$(($vtype))? $tag_name),*);
            implement_get_tag!($enum_name; $($vname$(($vtype))? $tag_name),*);
            implement_from_tag_primitive_pair!($enum_name; $($vname$(($vtype))? $tag_name),*);

            #[cfg(test)]
            fn make_field_matches_tag_type_test_vector() -> Vec<KmKeyParameter> {
                vec![$(KmKeyParameter{
                    tag: Tag::$tag_name,
                    value: KmKeyParameterValue::$field_name(Default::default())}
                ),*]
            }
        }

        implement_try_from_to_km_parameter!(
            $enum_name;
            $($vname$(($vtype))? $tag_name $field_name),*
        );

        implement_to_sql!($enum_name; $($vname$(($vtype))?),*);
    };
}

implement_key_parameter_value! {
/// KeyParameterValue holds a value corresponding to one of the Tags defined in
/// the AIDL spec at hardware/interfaces/keymint
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum KeyParameterValue {
    /// Associated with Tag:INVALID
    Invalid with tag INVALID and field Invalid,
    /// Set of purposes for which the key may be used
    KeyPurpose(KeyPurpose) with tag PURPOSE and field KeyPurpose,
    /// Cryptographic algorithm with which the key is used
    Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
    /// Size of the key , in bits
    KeySize(i32) with tag KEY_SIZE and field Integer,
    /// Block cipher mode(s) with which the key may be used
    BlockMode(BlockMode) with tag BLOCK_MODE and field BlockMode,
    /// Digest algorithms that may be used with the key to perform signing and verification
    Digest(Digest) with tag DIGEST and field Digest,
    /// Padding modes that may be used with the key.  Relevant to RSA, AES and 3DES keys.
    PaddingMode(PaddingMode) with tag PADDING and field PaddingMode,
    /// Can the caller provide a nonce for nonce-requiring operations
    CallerNonce with tag CALLER_NONCE and field BoolValue,
    /// Minimum length of MAC for HMAC keys and AES keys that support GCM mode
    MinMacLength(i32) with tag MIN_MAC_LENGTH and field Integer,
    /// The elliptic curve
    EcCurve(EcCurve) with tag EC_CURVE and field EcCurve,
    /// Value of the public exponent for an RSA key pair
    RSAPublicExponent(i64) with tag RSA_PUBLIC_EXPONENT and field LongInteger,
    /// An attestation certificate for the generated key should contain an application-scoped
    /// and time-bounded device-unique ID
    IncludeUniqueID with tag INCLUDE_UNIQUE_ID and field BoolValue,
    //TODO: find out about this
    // /// Necessary system environment conditions for the generated key to be used
    // KeyBlobUsageRequirements(KeyBlobUsageRequirements),
    /// Only the boot loader can use the key
    BootLoaderOnly with tag BOOTLOADER_ONLY and field BoolValue,
    /// When deleted, the key is guaranteed to be permanently deleted and unusable
    RollbackResistance with tag ROLLBACK_RESISTANCE and field BoolValue,
    /// The date and time at which the key becomes active
    ActiveDateTime(i64) with tag ACTIVE_DATETIME and field DateTime,
    /// The date and time at which the key expires for signing and encryption
    OriginationExpireDateTime(i64) with tag ORIGINATION_EXPIRE_DATETIME and field DateTime,
    /// The date and time at which the key expires for verification and decryption
    UsageExpireDateTime(i64) with tag USAGE_EXPIRE_DATETIME and field DateTime,
    /// Minimum amount of time that elapses between allowed operations
    MinSecondsBetweenOps(i32) with tag MIN_SECONDS_BETWEEN_OPS and field Integer,
    /// Maximum number of times that a key may be used between system reboots
    MaxUsesPerBoot(i32) with tag MAX_USES_PER_BOOT and field Integer,
    /// ID of the Android user that is permitted to use the key
    UserID(i32) with tag USER_ID and field Integer,
    /// A key may only be used under a particular secure user authentication state
    UserSecureID(i64) with tag USER_SECURE_ID and field LongInteger,
    /// No authentication is required to use this key
    NoAuthRequired with tag NO_AUTH_REQUIRED and field BoolValue,
    /// The types of user authenticators that may be used to authorize this key
    HardwareAuthenticatorType(HardwareAuthenticatorType) with tag USER_AUTH_TYPE and field HardwareAuthenticatorType,
    /// The time in seconds for which the key is authorized for use, after user authentication
    AuthTimeout(i32) with tag AUTH_TIMEOUT and field Integer,
    /// The key may be used after authentication timeout if device is still on-body
    AllowWhileOnBody with tag ALLOW_WHILE_ON_BODY and field BoolValue,
    /// The key must be unusable except when the user has provided proof of physical presence
    TrustedUserPresenceRequired with tag TRUSTED_USER_PRESENCE_REQUIRED and field BoolValue,
    /// Applicable to keys with KeyPurpose SIGN, and specifies that this key must not be usable
    /// unless the user provides confirmation of the data to be signed
    TrustedConfirmationRequired with tag TRUSTED_CONFIRMATION_REQUIRED and field BoolValue,
    /// The key may only be used when the device is unlocked
    UnlockedDeviceRequired with tag UNLOCKED_DEVICE_REQUIRED and field BoolValue,
    /// When provided to generateKey or importKey, this tag specifies data
    /// that is necessary during all uses of the key
    ApplicationID(Vec<u8>) with tag APPLICATION_ID and field Blob,
    /// When provided to generateKey or importKey, this tag specifies data
    /// that is necessary during all uses of the key
    ApplicationData(Vec<u8>) with tag APPLICATION_DATA and field Blob,
    /// Specifies the date and time the key was created
    CreationDateTime(i64) with tag CREATION_DATETIME and field DateTime,
    /// Specifies where the key was created, if known
    KeyOrigin(KeyOrigin) with tag ORIGIN and field Origin,
    /// The key used by verified boot to validate the operating system booted
    RootOfTrust(Vec<u8>) with tag ROOT_OF_TRUST and field Blob,
    /// System OS version with which the key may be used
    OSVersion(i32) with tag OS_VERSION and field Integer,
    /// Specifies the system security patch level with which the key may be used
    OSPatchLevel(i32) with tag OS_PATCHLEVEL and field Integer,
    /// Specifies a unique, time-based identifier
    UniqueID(Vec<u8>) with tag UNIQUE_ID and field Blob,
    /// Used to deliver a "challenge" value to the attestKey() method
    AttestationChallenge(Vec<u8>) with tag ATTESTATION_CHALLENGE and field Blob,
    /// The set of applications which may use a key, used only with attestKey()
    AttestationApplicationID(Vec<u8>) with tag ATTESTATION_APPLICATION_ID and field Blob,
    /// Provides the device's brand name, to attestKey()
    AttestationIdBrand(Vec<u8>) with tag ATTESTATION_ID_BRAND and field Blob,
    /// Provides the device's device name, to attestKey()
    AttestationIdDevice(Vec<u8>) with tag ATTESTATION_ID_DEVICE and field Blob,
    /// Provides the device's product name, to attestKey()
    AttestationIdProduct(Vec<u8>) with tag ATTESTATION_ID_PRODUCT and field Blob,
    /// Provides the device's serial number, to attestKey()
    AttestationIdSerial(Vec<u8>) with tag ATTESTATION_ID_SERIAL and field Blob,
    /// Provides the IMEIs for all radios on the device, to attestKey()
    AttestationIdIMEI(Vec<u8>) with tag ATTESTATION_ID_IMEI and field Blob,
    /// Provides the MEIDs for all radios on the device, to attestKey()
    AttestationIdMEID(Vec<u8>) with tag ATTESTATION_ID_MEID and field Blob,
    /// Provides the device's manufacturer name, to attestKey()
    AttestationIdManufacturer(Vec<u8>) with tag ATTESTATION_ID_MANUFACTURER and field Blob,
    /// Provides the device's model name, to attestKey()
    AttestationIdModel(Vec<u8>) with tag ATTESTATION_ID_MODEL and field Blob,
    /// Specifies the vendor image security patch level with which the key may be used
    VendorPatchLevel(i32) with tag VENDOR_PATCHLEVEL and field Integer,
    /// Specifies the boot image (kernel) security patch level with which the key may be used
    BootPatchLevel(i32) with tag BOOT_PATCHLEVEL and field Integer,
    /// Provides "associated data" for AES-GCM encryption or decryption
    AssociatedData(Vec<u8>) with tag ASSOCIATED_DATA and field Blob,
    /// Provides or returns a nonce or Initialization Vector (IV) for AES-GCM,
    /// AES-CBC, AES-CTR, or 3DES-CBC encryption or decryption
    Nonce(Vec<u8>) with tag NONCE and field Blob,
    /// Provides the requested length of a MAC or GCM authentication tag, in bits
    MacLength(i32) with tag MAC_LENGTH and field Integer,
    /// Specifies whether the device has been factory reset since the
    /// last unique ID rotation.  Used for key attestation
    ResetSinceIdRotation with tag RESET_SINCE_ID_ROTATION and field BoolValue,
    /// Used to deliver a cryptographic token proving that the user
    ///  confirmed a signing request
    ConfirmationToken(Vec<u8>) with tag CONFIRMATION_TOKEN and field Blob,
}
}

impl From<&KmKeyParameter> for KeyParameterValue {
    fn from(kp: &KmKeyParameter) -> Self {
        kp.clone().into()
    }
}

/// KeyParameter wraps the KeyParameterValue and the security level at which it is enforced.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyParameter {
    value: KeyParameterValue,
    security_level: SecurityLevel,
}

impl KeyParameter {
    /// Create an instance of KeyParameter, given the value and the security level.
    pub fn new(value: KeyParameterValue, security_level: SecurityLevel) -> Self {
        KeyParameter { value, security_level }
    }

    /// Construct a KeyParameter from the data from a rusqlite row.
    /// Note that following variants of KeyParameterValue should not be stored:
    /// IncludeUniqueID, ApplicationID, ApplicationData, RootOfTrust, UniqueID,
    /// Attestation*, AssociatedData, Nonce, MacLength, ResetSinceIdRotation, ConfirmationToken.
    /// This filtering is enforced at a higher level and here we support conversion for all the
    /// variants.
    pub fn new_from_sql(
        tag_val: Tag,
        data: &SqlField,
        security_level_val: SecurityLevel,
    ) -> Result<Self> {
        Ok(Self {
            value: KeyParameterValue::new_from_sql(tag_val, data)?,
            security_level: security_level_val,
        })
    }

    /// Get the KeyMint Tag of this this key parameter.
    pub fn get_tag(&self) -> Tag {
        self.value.get_tag()
    }

    /// Returns key parameter value.
    pub fn key_parameter_value(&self) -> &KeyParameterValue {
        &self.value
    }

    /// Returns the security level of this key parameter.
    pub fn security_level(&self) -> &SecurityLevel {
        &self.security_level
    }

    /// An authorization is a KeyParameter with an associated security level that is used
    /// to convey the key characteristics to keystore clients. This function consumes
    /// an internal KeyParameter representation to produce the Authorization wire type.
    pub fn into_authorization(self) -> Authorization {
        Authorization { securityLevel: self.security_level, keyParameter: self.value.into() }
    }
}

#[cfg(test)]
mod generated_key_parameter_tests {
    use super::*;
    use android_hardware_security_keymint::aidl::android::hardware::security::keymint::TagType::TagType;

    fn get_field_by_tag_type(tag: Tag) -> KmKeyParameterValue {
        let tag_type = TagType((tag.0 as u32 & 0xF0000000) as i32);
        match tag {
            Tag::ALGORITHM => return KmKeyParameterValue::Algorithm(Default::default()),
            Tag::BLOCK_MODE => return KmKeyParameterValue::BlockMode(Default::default()),
            Tag::PADDING => return KmKeyParameterValue::PaddingMode(Default::default()),
            Tag::DIGEST => return KmKeyParameterValue::Digest(Default::default()),
            Tag::EC_CURVE => return KmKeyParameterValue::EcCurve(Default::default()),
            Tag::ORIGIN => return KmKeyParameterValue::Origin(Default::default()),
            Tag::PURPOSE => return KmKeyParameterValue::KeyPurpose(Default::default()),
            Tag::USER_AUTH_TYPE => {
                return KmKeyParameterValue::HardwareAuthenticatorType(Default::default())
            }
            Tag::HARDWARE_TYPE => return KmKeyParameterValue::SecurityLevel(Default::default()),
            _ => {}
        }
        match tag_type {
            TagType::INVALID => return KmKeyParameterValue::Invalid(Default::default()),
            TagType::ENUM | TagType::ENUM_REP => {}
            TagType::UINT | TagType::UINT_REP => {
                return KmKeyParameterValue::Integer(Default::default())
            }
            TagType::ULONG | TagType::ULONG_REP => {
                return KmKeyParameterValue::LongInteger(Default::default())
            }
            TagType::DATE => return KmKeyParameterValue::DateTime(Default::default()),
            TagType::BOOL => return KmKeyParameterValue::BoolValue(Default::default()),
            TagType::BIGNUM | TagType::BYTES => {
                return KmKeyParameterValue::Blob(Default::default())
            }
            _ => {}
        }
        panic!("Unknown tag/tag_type: {:?} {:?}", tag, tag_type);
    }

    fn check_field_matches_tag_type(list_o_parameters: &[KmKeyParameter]) {
        for kp in list_o_parameters.iter() {
            match (&kp.value, get_field_by_tag_type(kp.tag)) {
                (&KmKeyParameterValue::Algorithm(_), KmKeyParameterValue::Algorithm(_))
                | (&KmKeyParameterValue::BlockMode(_), KmKeyParameterValue::BlockMode(_))
                | (&KmKeyParameterValue::PaddingMode(_), KmKeyParameterValue::PaddingMode(_))
                | (&KmKeyParameterValue::Digest(_), KmKeyParameterValue::Digest(_))
                | (&KmKeyParameterValue::EcCurve(_), KmKeyParameterValue::EcCurve(_))
                | (&KmKeyParameterValue::Origin(_), KmKeyParameterValue::Origin(_))
                | (&KmKeyParameterValue::KeyPurpose(_), KmKeyParameterValue::KeyPurpose(_))
                | (
                    &KmKeyParameterValue::HardwareAuthenticatorType(_),
                    KmKeyParameterValue::HardwareAuthenticatorType(_),
                )
                | (&KmKeyParameterValue::SecurityLevel(_), KmKeyParameterValue::SecurityLevel(_))
                | (&KmKeyParameterValue::Invalid(_), KmKeyParameterValue::Invalid(_))
                | (&KmKeyParameterValue::Integer(_), KmKeyParameterValue::Integer(_))
                | (&KmKeyParameterValue::LongInteger(_), KmKeyParameterValue::LongInteger(_))
                | (&KmKeyParameterValue::DateTime(_), KmKeyParameterValue::DateTime(_))
                | (&KmKeyParameterValue::BoolValue(_), KmKeyParameterValue::BoolValue(_))
                | (&KmKeyParameterValue::Blob(_), KmKeyParameterValue::Blob(_)) => {}
                (actual, expected) => panic!(
                    "Tag {:?} associated with variant {:?} expected {:?}",
                    kp.tag, actual, expected
                ),
            }
        }
    }

    #[test]
    fn key_parameter_value_field_matches_tag_type() {
        check_field_matches_tag_type(&KeyParameterValue::make_field_matches_tag_type_test_vector());
    }
}

#[cfg(test)]
mod basic_tests {
    use crate::key_parameter::*;

    // Test basic functionality of KeyParameter.
    #[test]
    fn test_key_parameter() {
        let key_parameter = KeyParameter::new(
            KeyParameterValue::Algorithm(Algorithm::RSA),
            SecurityLevel::STRONGBOX,
        );

        assert_eq!(key_parameter.get_tag(), Tag::ALGORITHM);

        assert_eq!(
            *key_parameter.key_parameter_value(),
            KeyParameterValue::Algorithm(Algorithm::RSA)
        );

        assert_eq!(*key_parameter.security_level(), SecurityLevel::STRONGBOX);
    }
}

/// The storage_tests module first tests the 'new_from_sql' method for KeyParameters of different
/// data types and then tests 'to_sql' method for KeyParameters of those
/// different data types. The five different data types for KeyParameter values are:
/// i) enums of u32
/// ii) u32
/// iii) u64
/// iv) Vec<u8>
/// v) bool
#[cfg(test)]
mod storage_tests {
    use crate::error::*;
    use crate::key_parameter::*;
    use anyhow::Result;
    use rusqlite::types::ToSql;
    use rusqlite::{params, Connection, NO_PARAMS};

    /// Test initializing a KeyParameter (with key parameter value corresponding to an enum of i32)
    /// from a database table row.
    #[test]
    fn test_new_from_sql_enum_i32() -> Result<()> {
        let db = init_db()?;
        insert_into_keyparameter(
            &db,
            1,
            Tag::ALGORITHM.0,
            &Algorithm::RSA.0,
            SecurityLevel::STRONGBOX.0,
        )?;
        let key_param = query_from_keyparameter(&db)?;
        assert_eq!(Tag::ALGORITHM, key_param.get_tag());
        assert_eq!(*key_param.key_parameter_value(), KeyParameterValue::Algorithm(Algorithm::RSA));
        assert_eq!(*key_param.security_level(), SecurityLevel::STRONGBOX);
        Ok(())
    }

    /// Test initializing a KeyParameter (with key parameter value which is of i32)
    /// from a database table row.
    #[test]
    fn test_new_from_sql_i32() -> Result<()> {
        let db = init_db()?;
        insert_into_keyparameter(&db, 1, Tag::KEY_SIZE.0, &1024, SecurityLevel::STRONGBOX.0)?;
        let key_param = query_from_keyparameter(&db)?;
        assert_eq!(Tag::KEY_SIZE, key_param.get_tag());
        assert_eq!(*key_param.key_parameter_value(), KeyParameterValue::KeySize(1024));
        Ok(())
    }

    /// Test initializing a KeyParameter (with key parameter value which is of i64)
    /// from a database table row.
    #[test]
    fn test_new_from_sql_i64() -> Result<()> {
        let db = init_db()?;
        // max value for i64, just to test corner cases
        insert_into_keyparameter(
            &db,
            1,
            Tag::RSA_PUBLIC_EXPONENT.0,
            &(i64::MAX),
            SecurityLevel::STRONGBOX.0,
        )?;
        let key_param = query_from_keyparameter(&db)?;
        assert_eq!(Tag::RSA_PUBLIC_EXPONENT, key_param.get_tag());
        assert_eq!(
            *key_param.key_parameter_value(),
            KeyParameterValue::RSAPublicExponent(i64::MAX)
        );
        Ok(())
    }

    /// Test initializing a KeyParameter (with key parameter value which is of bool)
    /// from a database table row.
    #[test]
    fn test_new_from_sql_bool() -> Result<()> {
        let db = init_db()?;
        insert_into_keyparameter(&db, 1, Tag::CALLER_NONCE.0, &Null, SecurityLevel::STRONGBOX.0)?;
        let key_param = query_from_keyparameter(&db)?;
        assert_eq!(Tag::CALLER_NONCE, key_param.get_tag());
        assert_eq!(*key_param.key_parameter_value(), KeyParameterValue::CallerNonce);
        Ok(())
    }

    /// Test initializing a KeyParameter (with key parameter value which is of Vec<u8>)
    /// from a database table row.
    #[test]
    fn test_new_from_sql_vec_u8() -> Result<()> {
        let db = init_db()?;
        let app_id = String::from("MyAppID");
        let app_id_bytes = app_id.into_bytes();
        insert_into_keyparameter(
            &db,
            1,
            Tag::APPLICATION_ID.0,
            &app_id_bytes,
            SecurityLevel::STRONGBOX.0,
        )?;
        let key_param = query_from_keyparameter(&db)?;
        assert_eq!(Tag::APPLICATION_ID, key_param.get_tag());
        assert_eq!(
            *key_param.key_parameter_value(),
            KeyParameterValue::ApplicationID(app_id_bytes)
        );
        Ok(())
    }

    /// Test storing a KeyParameter (with key parameter value which corresponds to an enum of i32)
    /// in the database
    #[test]
    fn test_to_sql_enum_i32() -> Result<()> {
        let db = init_db()?;
        let kp = KeyParameter::new(
            KeyParameterValue::Algorithm(Algorithm::RSA),
            SecurityLevel::STRONGBOX,
        );
        store_keyparameter(&db, 1, &kp)?;
        let key_param = query_from_keyparameter(&db)?;
        assert_eq!(kp.get_tag(), key_param.get_tag());
        assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
        assert_eq!(kp.security_level(), key_param.security_level());
        Ok(())
    }

    /// Test storing a KeyParameter (with key parameter value which is of i32) in the database
    #[test]
    fn test_to_sql_i32() -> Result<()> {
        let db = init_db()?;
        let kp = KeyParameter::new(KeyParameterValue::KeySize(1024), SecurityLevel::STRONGBOX);
        store_keyparameter(&db, 1, &kp)?;
        let key_param = query_from_keyparameter(&db)?;
        assert_eq!(kp.get_tag(), key_param.get_tag());
        assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
        assert_eq!(kp.security_level(), key_param.security_level());
        Ok(())
    }

    /// Test storing a KeyParameter (with key parameter value which is of i64) in the database
    #[test]
    fn test_to_sql_i64() -> Result<()> {
        let db = init_db()?;
        // max value for i64, just to test corner cases
        let kp = KeyParameter::new(
            KeyParameterValue::RSAPublicExponent(i64::MAX),
            SecurityLevel::STRONGBOX,
        );
        store_keyparameter(&db, 1, &kp)?;
        let key_param = query_from_keyparameter(&db)?;
        assert_eq!(kp.get_tag(), key_param.get_tag());
        assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
        assert_eq!(kp.security_level(), key_param.security_level());
        Ok(())
    }

    /// Test storing a KeyParameter (with key parameter value which is of Vec<u8>) in the database
    #[test]
    fn test_to_sql_vec_u8() -> Result<()> {
        let db = init_db()?;
        let kp = KeyParameter::new(
            KeyParameterValue::ApplicationID(String::from("MyAppID").into_bytes()),
            SecurityLevel::STRONGBOX,
        );
        store_keyparameter(&db, 1, &kp)?;
        let key_param = query_from_keyparameter(&db)?;
        assert_eq!(kp.get_tag(), key_param.get_tag());
        assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
        assert_eq!(kp.security_level(), key_param.security_level());
        Ok(())
    }

    /// Test storing a KeyParameter (with key parameter value which is of i32) in the database
    #[test]
    fn test_to_sql_bool() -> Result<()> {
        let db = init_db()?;
        let kp = KeyParameter::new(KeyParameterValue::CallerNonce, SecurityLevel::STRONGBOX);
        store_keyparameter(&db, 1, &kp)?;
        let key_param = query_from_keyparameter(&db)?;
        assert_eq!(kp.get_tag(), key_param.get_tag());
        assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
        assert_eq!(kp.security_level(), key_param.security_level());
        Ok(())
    }

    #[test]
    /// Test Tag::Invalid
    fn test_invalid_tag() -> Result<()> {
        let db = init_db()?;
        insert_into_keyparameter(&db, 1, 0, &123, 1)?;
        let key_param = query_from_keyparameter(&db)?;
        assert_eq!(Tag::INVALID, key_param.get_tag());
        Ok(())
    }

    #[test]
    fn test_non_existing_enum_variant() -> Result<()> {
        let db = init_db()?;
        insert_into_keyparameter(&db, 1, 100, &123, 1)?;
        let key_param = query_from_keyparameter(&db)?;
        assert_eq!(Tag::INVALID, key_param.get_tag());
        Ok(())
    }

    #[test]
    fn test_invalid_conversion_from_sql() -> Result<()> {
        let db = init_db()?;
        insert_into_keyparameter(&db, 1, Tag::ALGORITHM.0, &Null, 1)?;
        tests::check_result_contains_error_string(
            query_from_keyparameter(&db),
            "Failed to read sql data for tag: ALGORITHM.",
        );
        Ok(())
    }

    /// Helper method to init database table for key parameter
    fn init_db() -> Result<Connection> {
        let db = Connection::open_in_memory().context("Failed to initialize sqlite connection.")?;
        db.execute("ATTACH DATABASE ? as 'persistent';", params![""])
            .context("Failed to attach databases.")?;
        db.execute(
            "CREATE TABLE IF NOT EXISTS persistent.keyparameter (
                                keyentryid INTEGER,
                                tag INTEGER,
                                data ANY,
                                security_level INTEGER);",
            NO_PARAMS,
        )
        .context("Failed to initialize \"keyparameter\" table.")?;
        Ok(db)
    }

    /// Helper method to insert an entry into key parameter table, with individual parameters
    fn insert_into_keyparameter<T: ToSql>(
        db: &Connection,
        key_id: i64,
        tag: i32,
        value: &T,
        security_level: i32,
    ) -> Result<()> {
        db.execute(
            "INSERT into persistent.keyparameter (keyentryid, tag, data, security_level)
                VALUES(?, ?, ?, ?);",
            params![key_id, tag, *value, security_level],
        )?;
        Ok(())
    }

    /// Helper method to store a key parameter instance.
    fn store_keyparameter(db: &Connection, key_id: i64, kp: &KeyParameter) -> Result<()> {
        db.execute(
            "INSERT into persistent.keyparameter (keyentryid, tag, data, security_level)
                VALUES(?, ?, ?, ?);",
            params![key_id, kp.get_tag().0, kp.key_parameter_value(), kp.security_level().0],
        )?;
        Ok(())
    }

    /// Helper method to query a row from keyparameter table
    fn query_from_keyparameter(db: &Connection) -> Result<KeyParameter> {
        let mut stmt =
            db.prepare("SELECT tag, data, security_level FROM persistent.keyparameter")?;
        let mut rows = stmt.query(NO_PARAMS)?;
        let row = rows.next()?.unwrap();
        Ok(KeyParameter::new_from_sql(
            Tag(row.get(0)?),
            &SqlField::new(1, row),
            SecurityLevel(row.get(2)?),
        )?)
    }
}

/// The wire_tests module tests the 'convert_to_wire' and 'convert_from_wire' methods for
/// KeyParameter, for the four different types used in KmKeyParameter, in addition to Invalid
/// key parameter.
/// i) bool
/// ii) integer
/// iii) longInteger
/// iv) blob
#[cfg(test)]
mod wire_tests {
    use crate::key_parameter::*;
    /// unit tests for to conversions
    #[test]
    fn test_convert_to_wire_invalid() {
        let kp = KeyParameter::new(KeyParameterValue::Invalid, SecurityLevel::STRONGBOX);
        assert_eq!(
            KmKeyParameter { tag: Tag::INVALID, value: KmKeyParameterValue::Invalid(0) },
            kp.value.into()
        );
    }
    #[test]
    fn test_convert_to_wire_bool() {
        let kp = KeyParameter::new(KeyParameterValue::CallerNonce, SecurityLevel::STRONGBOX);
        assert_eq!(
            KmKeyParameter { tag: Tag::CALLER_NONCE, value: KmKeyParameterValue::BoolValue(true) },
            kp.value.into()
        );
    }
    #[test]
    fn test_convert_to_wire_integer() {
        let kp = KeyParameter::new(
            KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
            SecurityLevel::STRONGBOX,
        );
        assert_eq!(
            KmKeyParameter {
                tag: Tag::PURPOSE,
                value: KmKeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT)
            },
            kp.value.into()
        );
    }
    #[test]
    fn test_convert_to_wire_long_integer() {
        let kp =
            KeyParameter::new(KeyParameterValue::UserSecureID(i64::MAX), SecurityLevel::STRONGBOX);
        assert_eq!(
            KmKeyParameter {
                tag: Tag::USER_SECURE_ID,
                value: KmKeyParameterValue::LongInteger(i64::MAX)
            },
            kp.value.into()
        );
    }
    #[test]
    fn test_convert_to_wire_blob() {
        let kp = KeyParameter::new(
            KeyParameterValue::ConfirmationToken(String::from("ConfirmationToken").into_bytes()),
            SecurityLevel::STRONGBOX,
        );
        assert_eq!(
            KmKeyParameter {
                tag: Tag::CONFIRMATION_TOKEN,
                value: KmKeyParameterValue::Blob(String::from("ConfirmationToken").into_bytes())
            },
            kp.value.into()
        );
    }

    /// unit tests for from conversion
    #[test]
    fn test_convert_from_wire_invalid() {
        let aidl_kp = KmKeyParameter { tag: Tag::INVALID, ..Default::default() };
        assert_eq!(KeyParameterValue::Invalid, aidl_kp.into());
    }
    #[test]
    fn test_convert_from_wire_bool() {
        let aidl_kp =
            KmKeyParameter { tag: Tag::CALLER_NONCE, value: KmKeyParameterValue::BoolValue(true) };
        assert_eq!(KeyParameterValue::CallerNonce, aidl_kp.into());
    }
    #[test]
    fn test_convert_from_wire_integer() {
        let aidl_kp = KmKeyParameter {
            tag: Tag::PURPOSE,
            value: KmKeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
        };
        assert_eq!(KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT), aidl_kp.into());
    }
    #[test]
    fn test_convert_from_wire_long_integer() {
        let aidl_kp = KmKeyParameter {
            tag: Tag::USER_SECURE_ID,
            value: KmKeyParameterValue::LongInteger(i64::MAX),
        };
        assert_eq!(KeyParameterValue::UserSecureID(i64::MAX), aidl_kp.into());
    }
    #[test]
    fn test_convert_from_wire_blob() {
        let aidl_kp = KmKeyParameter {
            tag: Tag::CONFIRMATION_TOKEN,
            value: KmKeyParameterValue::Blob(String::from("ConfirmationToken").into_bytes()),
        };
        assert_eq!(
            KeyParameterValue::ConfirmationToken(String::from("ConfirmationToken").into_bytes()),
            aidl_kp.into()
        );
    }
}
