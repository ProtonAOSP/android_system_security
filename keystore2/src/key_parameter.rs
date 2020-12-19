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

//! KeyParameter is used to express different characteristics of a key requested by the user
//! and enforced by the OEMs. This module implements the internal representation of KeyParameter
//! and the methods to work with KeyParameter.

use crate::db_utils::SqlField;
use crate::error::Error as KeystoreError;
use crate::error::ResponseCode;

pub use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    HardwareAuthenticatorType::HardwareAuthenticatorType, KeyOrigin::KeyOrigin,
    KeyParameter::KeyParameter as KmKeyParameter, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    SecurityLevel::SecurityLevel, Tag::Tag,
};
use android_system_keystore2::aidl::android::system::keystore2::Authorization::Authorization;
use anyhow::{Context, Result};
use rusqlite::types::{Null, ToSql, ToSqlOutput};
use rusqlite::Result as SqlResult;

/// KeyParameter wraps the KeyParameterValue and the security level at which it is enforced.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyParameter {
    key_parameter_value: KeyParameterValue,
    security_level: SecurityLevel,
}

/// KeyParameterValue holds a value corresponding to one of the Tags defined in
/// the AIDL spec at hardware/interfaces/keymint
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum KeyParameterValue {
    /// Associated with Tag:INVALID
    Invalid,
    /// Set of purposes for which the key may be used
    KeyPurpose(KeyPurpose),
    /// Cryptographic algorithm with which the key is used
    Algorithm(Algorithm),
    /// Size of the key , in bits
    KeySize(i32),
    /// Block cipher mode(s) with which the key may be used
    BlockMode(BlockMode),
    /// Digest algorithms that may be used with the key to perform signing and verification
    Digest(Digest),
    /// Padding modes that may be used with the key.  Relevant to RSA, AES and 3DES keys.
    PaddingMode(PaddingMode),
    /// Can the caller provide a nonce for nonce-requiring operations
    CallerNonce,
    /// Minimum length of MAC for HMAC keys and AES keys that support GCM mode
    MinMacLength(i32),
    /// The elliptic curve
    EcCurve(EcCurve),
    /// Value of the public exponent for an RSA key pair
    RSAPublicExponent(i64),
    /// An attestation certificate for the generated key should contain an application-scoped
    /// and time-bounded device-unique ID
    IncludeUniqueID,
    //TODO: find out about this
    // /// Necessary system environment conditions for the generated key to be used
    // KeyBlobUsageRequirements(KeyBlobUsageRequirements),
    /// Only the boot loader can use the key
    BootLoaderOnly,
    /// When deleted, the key is guaranteed to be permanently deleted and unusable
    RollbackResistance,
    /// The date and time at which the key becomes active
    ActiveDateTime(i64),
    /// The date and time at which the key expires for signing and encryption
    OriginationExpireDateTime(i64),
    /// The date and time at which the key expires for verification and decryption
    UsageExpireDateTime(i64),
    /// Minimum amount of time that elapses between allowed operations
    MinSecondsBetweenOps(i32),
    /// Maximum number of times that a key may be used between system reboots
    MaxUsesPerBoot(i32),
    /// ID of the Android user that is permitted to use the key
    UserID(i32),
    /// A key may only be used under a particular secure user authentication state
    UserSecureID(i64),
    /// No authentication is required to use this key
    NoAuthRequired,
    /// The types of user authenticators that may be used to authorize this key
    HardwareAuthenticatorType(HardwareAuthenticatorType),
    /// The time in seconds for which the key is authorized for use, after user authentication
    AuthTimeout(i32),
    /// The key may be used after authentication timeout if device is still on-body
    AllowWhileOnBody,
    /// The key must be unusable except when the user has provided proof of physical presence
    TrustedUserPresenceRequired,
    /// Applicable to keys with KeyPurpose SIGN, and specifies that this key must not be usable
    /// unless the user provides confirmation of the data to be signed
    TrustedConfirmationRequired,
    /// The key may only be used when the device is unlocked
    UnlockedDeviceRequired,
    /// When provided to generateKey or importKey, this tag specifies data
    /// that is necessary during all uses of the key
    ApplicationID(Vec<u8>),
    /// When provided to generateKey or importKey, this tag specifies data
    /// that is necessary during all uses of the key
    ApplicationData(Vec<u8>),
    /// Specifies the date and time the key was created
    CreationDateTime(i64),
    /// Specifies where the key was created, if known
    KeyOrigin(KeyOrigin),
    /// The key used by verified boot to validate the operating system booted
    RootOfTrust(Vec<u8>),
    /// System OS version with which the key may be used
    OSVersion(i32),
    /// Specifies the system security patch level with which the key may be used
    OSPatchLevel(i32),
    /// Specifies a unique, time-based identifier
    UniqueID(Vec<u8>),
    /// Used to deliver a "challenge" value to the attestKey() method
    AttestationChallenge(Vec<u8>),
    /// The set of applications which may use a key, used only with attestKey()
    AttestationApplicationID(Vec<u8>),
    /// Provides the device's brand name, to attestKey()
    AttestationIdBrand(Vec<u8>),
    /// Provides the device's device name, to attestKey()
    AttestationIdDevice(Vec<u8>),
    /// Provides the device's product name, to attestKey()
    AttestationIdProduct(Vec<u8>),
    /// Provides the device's serial number, to attestKey()
    AttestationIdSerial(Vec<u8>),
    /// Provides the IMEIs for all radios on the device, to attestKey()
    AttestationIdIMEI(Vec<u8>),
    /// Provides the MEIDs for all radios on the device, to attestKey()
    AttestationIdMEID(Vec<u8>),
    /// Provides the device's manufacturer name, to attestKey()
    AttestationIdManufacturer(Vec<u8>),
    /// Provides the device's model name, to attestKey()
    AttestationIdModel(Vec<u8>),
    /// Specifies the vendor image security patch level with which the key may be used
    VendorPatchLevel(i32),
    /// Specifies the boot image (kernel) security patch level with which the key may be used
    BootPatchLevel(i32),
    /// Provides "associated data" for AES-GCM encryption or decryption
    AssociatedData(Vec<u8>),
    /// Provides or returns a nonce or Initialization Vector (IV) for AES-GCM,
    /// AES-CBC, AES-CTR, or 3DES-CBC encryption or decryption
    Nonce(Vec<u8>),
    /// Provides the requested length of a MAC or GCM authentication tag, in bits
    MacLength(i32),
    /// Specifies whether the device has been factory reset since the
    /// last unique ID rotation.  Used for key attestation
    ResetSinceIdRotation,
    /// Used to deliver a cryptographic token proving that the user
    ///  confirmed a signing request
    ConfirmationToken(Vec<u8>),
}

impl KeyParameter {
    /// Create an instance of KeyParameter, given the value and the security level.
    pub fn new(key_parameter_value: KeyParameterValue, security_level: SecurityLevel) -> Self {
        KeyParameter { key_parameter_value, security_level }
    }

    /// Returns the tag given the KeyParameter instance.
    pub fn get_tag(&self) -> Tag {
        match self.key_parameter_value {
            KeyParameterValue::Invalid => Tag::INVALID,
            KeyParameterValue::KeyPurpose(_) => Tag::PURPOSE,
            KeyParameterValue::Algorithm(_) => Tag::ALGORITHM,
            KeyParameterValue::KeySize(_) => Tag::KEY_SIZE,
            KeyParameterValue::BlockMode(_) => Tag::BLOCK_MODE,
            KeyParameterValue::Digest(_) => Tag::DIGEST,
            KeyParameterValue::PaddingMode(_) => Tag::PADDING,
            KeyParameterValue::CallerNonce => Tag::CALLER_NONCE,
            KeyParameterValue::MinMacLength(_) => Tag::MIN_MAC_LENGTH,
            KeyParameterValue::EcCurve(_) => Tag::EC_CURVE,
            KeyParameterValue::RSAPublicExponent(_) => Tag::RSA_PUBLIC_EXPONENT,
            KeyParameterValue::IncludeUniqueID => Tag::INCLUDE_UNIQUE_ID,
            KeyParameterValue::BootLoaderOnly => Tag::BOOTLOADER_ONLY,
            KeyParameterValue::RollbackResistance => Tag::ROLLBACK_RESISTANCE,
            KeyParameterValue::ActiveDateTime(_) => Tag::ACTIVE_DATETIME,
            KeyParameterValue::OriginationExpireDateTime(_) => Tag::ORIGINATION_EXPIRE_DATETIME,
            KeyParameterValue::UsageExpireDateTime(_) => Tag::USAGE_EXPIRE_DATETIME,
            KeyParameterValue::MinSecondsBetweenOps(_) => Tag::MIN_SECONDS_BETWEEN_OPS,
            KeyParameterValue::MaxUsesPerBoot(_) => Tag::MAX_USES_PER_BOOT,
            KeyParameterValue::UserID(_) => Tag::USER_ID,
            KeyParameterValue::UserSecureID(_) => Tag::USER_SECURE_ID,
            KeyParameterValue::NoAuthRequired => Tag::NO_AUTH_REQUIRED,
            KeyParameterValue::HardwareAuthenticatorType(_) => Tag::USER_AUTH_TYPE,
            KeyParameterValue::AuthTimeout(_) => Tag::AUTH_TIMEOUT,
            KeyParameterValue::AllowWhileOnBody => Tag::ALLOW_WHILE_ON_BODY,
            KeyParameterValue::TrustedUserPresenceRequired => Tag::TRUSTED_USER_PRESENCE_REQUIRED,
            KeyParameterValue::TrustedConfirmationRequired => Tag::TRUSTED_CONFIRMATION_REQUIRED,
            KeyParameterValue::UnlockedDeviceRequired => Tag::UNLOCKED_DEVICE_REQUIRED,
            KeyParameterValue::ApplicationID(_) => Tag::APPLICATION_ID,
            KeyParameterValue::ApplicationData(_) => Tag::APPLICATION_DATA,
            KeyParameterValue::CreationDateTime(_) => Tag::CREATION_DATETIME,
            KeyParameterValue::KeyOrigin(_) => Tag::ORIGIN,
            KeyParameterValue::RootOfTrust(_) => Tag::ROOT_OF_TRUST,
            KeyParameterValue::OSVersion(_) => Tag::OS_VERSION,
            KeyParameterValue::OSPatchLevel(_) => Tag::OS_PATCHLEVEL,
            KeyParameterValue::UniqueID(_) => Tag::UNIQUE_ID,
            KeyParameterValue::AttestationChallenge(_) => Tag::ATTESTATION_CHALLENGE,
            KeyParameterValue::AttestationApplicationID(_) => Tag::ATTESTATION_APPLICATION_ID,
            KeyParameterValue::AttestationIdBrand(_) => Tag::ATTESTATION_ID_BRAND,
            KeyParameterValue::AttestationIdDevice(_) => Tag::ATTESTATION_ID_DEVICE,
            KeyParameterValue::AttestationIdProduct(_) => Tag::ATTESTATION_ID_PRODUCT,
            KeyParameterValue::AttestationIdSerial(_) => Tag::ATTESTATION_ID_SERIAL,
            KeyParameterValue::AttestationIdIMEI(_) => Tag::ATTESTATION_ID_IMEI,
            KeyParameterValue::AttestationIdMEID(_) => Tag::ATTESTATION_ID_MEID,
            KeyParameterValue::AttestationIdManufacturer(_) => Tag::ATTESTATION_ID_MANUFACTURER,
            KeyParameterValue::AttestationIdModel(_) => Tag::ATTESTATION_ID_MODEL,
            KeyParameterValue::VendorPatchLevel(_) => Tag::VENDOR_PATCHLEVEL,
            KeyParameterValue::BootPatchLevel(_) => Tag::BOOT_PATCHLEVEL,
            KeyParameterValue::AssociatedData(_) => Tag::ASSOCIATED_DATA,
            KeyParameterValue::Nonce(_) => Tag::NONCE,
            KeyParameterValue::MacLength(_) => Tag::MAC_LENGTH,
            KeyParameterValue::ResetSinceIdRotation => Tag::RESET_SINCE_ID_ROTATION,
            KeyParameterValue::ConfirmationToken(_) => Tag::CONFIRMATION_TOKEN,
        }
    }

    /// Returns key parameter value.
    pub fn key_parameter_value(&self) -> &KeyParameterValue {
        &self.key_parameter_value
    }

    /// Returns the security level of a KeyParameter.
    pub fn security_level(&self) -> &SecurityLevel {
        &self.security_level
    }

    /// An authorization is a KeyParameter with an associated security level that is used
    /// to convey the key characteristics to keystore clients. This function consumes
    /// an internal KeyParameter representation to produce the Authorization wire type.
    pub fn into_authorization(self) -> Authorization {
        Authorization {
            securityLevel: self.security_level,
            keyParameter: self.key_parameter_value.convert_to_wire(),
        }
    }
}

impl ToSql for KeyParameterValue {
    /// Converts KeyParameterValue to be stored in rusqlite database.
    /// Note that following variants of KeyParameterValue should not be stored:
    /// IncludeUniqueID, ApplicationID, ApplicationData, RootOfTrust, UniqueID,
    /// Attestation*, AssociatedData, Nonce, MacLength, ResetSinceIdRotation, ConfirmationToken.
    /// This filtering is enforced at a higher level (i.e. enforcement module) and here we support
    /// conversion for all the variants, to keep error handling simple.
    fn to_sql(&self) -> SqlResult<ToSqlOutput> {
        match self {
            KeyParameterValue::Invalid => Ok(ToSqlOutput::from(Null)),
            KeyParameterValue::KeyPurpose(k) => Ok(ToSqlOutput::from(k.0 as u32)),
            KeyParameterValue::Algorithm(a) => Ok(ToSqlOutput::from(a.0 as u32)),
            KeyParameterValue::KeySize(k) => Ok(ToSqlOutput::from(*k)),
            KeyParameterValue::BlockMode(b) => Ok(ToSqlOutput::from(b.0 as u32)),
            KeyParameterValue::Digest(d) => Ok(ToSqlOutput::from(d.0 as u32)),
            KeyParameterValue::PaddingMode(p) => Ok(ToSqlOutput::from(p.0 as u32)),
            KeyParameterValue::CallerNonce => Ok(ToSqlOutput::from(Null)),
            KeyParameterValue::MinMacLength(m) => Ok(ToSqlOutput::from(*m)),
            KeyParameterValue::EcCurve(e) => Ok(ToSqlOutput::from(e.0 as u32)),
            KeyParameterValue::RSAPublicExponent(r) => Ok(ToSqlOutput::from(*r as i64)),
            KeyParameterValue::IncludeUniqueID => Ok(ToSqlOutput::from(Null)),
            KeyParameterValue::BootLoaderOnly => Ok(ToSqlOutput::from(Null)),
            KeyParameterValue::RollbackResistance => Ok(ToSqlOutput::from(Null)),
            KeyParameterValue::ActiveDateTime(a) => Ok(ToSqlOutput::from(*a as i64)),
            KeyParameterValue::OriginationExpireDateTime(o) => Ok(ToSqlOutput::from(*o as i64)),
            KeyParameterValue::UsageExpireDateTime(u) => Ok(ToSqlOutput::from(*u as i64)),
            KeyParameterValue::MinSecondsBetweenOps(m) => Ok(ToSqlOutput::from(*m)),
            KeyParameterValue::MaxUsesPerBoot(m) => Ok(ToSqlOutput::from(*m)),
            KeyParameterValue::UserID(u) => Ok(ToSqlOutput::from(*u)),
            KeyParameterValue::UserSecureID(u) => Ok(ToSqlOutput::from(*u as i64)),
            KeyParameterValue::NoAuthRequired => Ok(ToSqlOutput::from(Null)),
            KeyParameterValue::HardwareAuthenticatorType(h) => Ok(ToSqlOutput::from(h.0 as u32)),
            KeyParameterValue::AuthTimeout(m) => Ok(ToSqlOutput::from(*m)),
            KeyParameterValue::AllowWhileOnBody => Ok(ToSqlOutput::from(Null)),
            KeyParameterValue::TrustedUserPresenceRequired => Ok(ToSqlOutput::from(Null)),
            KeyParameterValue::TrustedConfirmationRequired => Ok(ToSqlOutput::from(Null)),
            KeyParameterValue::UnlockedDeviceRequired => Ok(ToSqlOutput::from(Null)),
            KeyParameterValue::ApplicationID(a) => Ok(ToSqlOutput::from(a.to_vec())),
            KeyParameterValue::ApplicationData(a) => Ok(ToSqlOutput::from(a.to_vec())),
            KeyParameterValue::CreationDateTime(c) => Ok(ToSqlOutput::from(*c as i64)),
            KeyParameterValue::KeyOrigin(k) => Ok(ToSqlOutput::from(k.0 as u32)),
            KeyParameterValue::RootOfTrust(r) => Ok(ToSqlOutput::from(r.to_vec())),
            KeyParameterValue::OSVersion(o) => Ok(ToSqlOutput::from(*o)),
            KeyParameterValue::OSPatchLevel(o) => Ok(ToSqlOutput::from(*o)),
            KeyParameterValue::UniqueID(u) => Ok(ToSqlOutput::from(u.to_vec())),
            KeyParameterValue::AttestationChallenge(a) => Ok(ToSqlOutput::from(a.to_vec())),
            KeyParameterValue::AttestationApplicationID(a) => Ok(ToSqlOutput::from(a.to_vec())),
            KeyParameterValue::AttestationIdBrand(a) => Ok(ToSqlOutput::from(a.to_vec())),
            KeyParameterValue::AttestationIdDevice(a) => Ok(ToSqlOutput::from(a.to_vec())),
            KeyParameterValue::AttestationIdProduct(a) => Ok(ToSqlOutput::from(a.to_vec())),
            KeyParameterValue::AttestationIdSerial(a) => Ok(ToSqlOutput::from(a.to_vec())),
            KeyParameterValue::AttestationIdIMEI(a) => Ok(ToSqlOutput::from(a.to_vec())),
            KeyParameterValue::AttestationIdMEID(a) => Ok(ToSqlOutput::from(a.to_vec())),
            KeyParameterValue::AttestationIdManufacturer(a) => Ok(ToSqlOutput::from(a.to_vec())),
            KeyParameterValue::AttestationIdModel(a) => Ok(ToSqlOutput::from(a.to_vec())),
            KeyParameterValue::VendorPatchLevel(v) => Ok(ToSqlOutput::from(*v)),
            KeyParameterValue::BootPatchLevel(b) => Ok(ToSqlOutput::from(*b)),
            KeyParameterValue::AssociatedData(a) => Ok(ToSqlOutput::from(a.to_vec())),
            KeyParameterValue::Nonce(n) => Ok(ToSqlOutput::from(n.to_vec())),
            KeyParameterValue::MacLength(m) => Ok(ToSqlOutput::from(*m)),
            KeyParameterValue::ResetSinceIdRotation => Ok(ToSqlOutput::from(Null)),
            KeyParameterValue::ConfirmationToken(c) => Ok(ToSqlOutput::from(c.to_vec())),
        }
    }
}

impl KeyParameter {
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
        let key_param_value = match tag_val {
            Tag::INVALID => KeyParameterValue::Invalid,
            Tag::PURPOSE => {
                let key_purpose: i32 = data
                    .get()
                    .map_err(|_| KeystoreError::Rc(ResponseCode::VALUE_CORRUPTED))
                    .context("Failed to read sql data for tag: PURPOSE.")?;
                KeyParameterValue::KeyPurpose(KeyPurpose(key_purpose))
            }
            Tag::ALGORITHM => {
                let algorithm: i32 = data
                    .get()
                    .map_err(|_| KeystoreError::Rc(ResponseCode::VALUE_CORRUPTED))
                    .context("Failed to read sql data for tag: ALGORITHM.")?;
                KeyParameterValue::Algorithm(Algorithm(algorithm))
            }
            Tag::KEY_SIZE => {
                let key_size: i32 =
                    data.get().context("Failed to read sql data for tag: KEY_SIZE.")?;
                KeyParameterValue::KeySize(key_size)
            }
            Tag::BLOCK_MODE => {
                let block_mode: i32 = data
                    .get()
                    .map_err(|_| KeystoreError::Rc(ResponseCode::VALUE_CORRUPTED))
                    .context("Failed to read sql data for tag: BLOCK_MODE.")?;
                KeyParameterValue::BlockMode(BlockMode(block_mode))
            }
            Tag::DIGEST => {
                let digest: i32 = data
                    .get()
                    .map_err(|_| KeystoreError::Rc(ResponseCode::VALUE_CORRUPTED))
                    .context("Failed to read sql data for tag: DIGEST.")?;
                KeyParameterValue::Digest(Digest(digest))
            }
            Tag::PADDING => {
                let padding: i32 = data
                    .get()
                    .map_err(|_| KeystoreError::Rc(ResponseCode::VALUE_CORRUPTED))
                    .context("Failed to read sql data for tag: PADDING.")?;
                KeyParameterValue::PaddingMode(PaddingMode(padding))
            }
            Tag::CALLER_NONCE => KeyParameterValue::CallerNonce,
            Tag::MIN_MAC_LENGTH => {
                let min_mac_length: i32 =
                    data.get().context("Failed to read sql data for tag: MIN_MAC_LENGTH.")?;
                KeyParameterValue::MinMacLength(min_mac_length)
            }
            Tag::EC_CURVE => {
                let ec_curve: i32 = data
                    .get()
                    .map_err(|_| KeystoreError::Rc(ResponseCode::VALUE_CORRUPTED))
                    .context("Failed to read sql data for tag: EC_CURVE.")?;
                KeyParameterValue::EcCurve(EcCurve(ec_curve))
            }
            Tag::RSA_PUBLIC_EXPONENT => {
                let rsa_pub_exponent: i64 =
                    data.get().context("Failed to read sql data for tag: RSA_PUBLIC_EXPONENT.")?;

                KeyParameterValue::RSAPublicExponent(rsa_pub_exponent)
            }
            Tag::INCLUDE_UNIQUE_ID => KeyParameterValue::IncludeUniqueID,
            Tag::BOOTLOADER_ONLY => KeyParameterValue::BootLoaderOnly,
            Tag::ROLLBACK_RESISTANCE => KeyParameterValue::RollbackResistance,
            Tag::ACTIVE_DATETIME => {
                let active_datetime: i64 =
                    data.get().context("Failed to read sql data for tag: ACTIVE_DATETIME.")?;
                KeyParameterValue::ActiveDateTime(active_datetime)
            }
            Tag::ORIGINATION_EXPIRE_DATETIME => {
                let origination_expire_datetime: i64 = data
                    .get()
                    .context("Failed to read sql data for tag: ORIGINATION_EXPIRE_DATETIME.")?;
                KeyParameterValue::OriginationExpireDateTime(origination_expire_datetime)
            }
            Tag::USAGE_EXPIRE_DATETIME => {
                let usage_expire_datetime: i64 = data
                    .get()
                    .context("Failed to read sql data for tag: USAGE_EXPIRE_DATETIME.")?;
                KeyParameterValue::UsageExpireDateTime(usage_expire_datetime)
            }
            Tag::MIN_SECONDS_BETWEEN_OPS => {
                let min_secs_between_ops: i32 = data
                    .get()
                    .context("Failed to read sql data for tag: MIN_SECONDS_BETWEEN_OPS.")?;
                KeyParameterValue::MinSecondsBetweenOps(min_secs_between_ops)
            }
            Tag::MAX_USES_PER_BOOT => {
                let max_uses_per_boot: i32 =
                    data.get().context("Failed to read sql data for tag: MAX_USES_PER_BOOT.")?;
                KeyParameterValue::MaxUsesPerBoot(max_uses_per_boot)
            }
            Tag::USER_ID => {
                let user_id: i32 =
                    data.get().context("Failed to read sql data for tag: USER_ID.")?;
                KeyParameterValue::UserID(user_id)
            }
            Tag::USER_SECURE_ID => {
                let user_secure_id: i64 =
                    data.get().context("Failed to read sql data for tag: USER_SECURE_ID.")?;
                KeyParameterValue::UserSecureID(user_secure_id)
            }
            Tag::NO_AUTH_REQUIRED => KeyParameterValue::NoAuthRequired,
            Tag::USER_AUTH_TYPE => {
                let user_auth_type: i32 = data
                    .get()
                    .map_err(|_| KeystoreError::Rc(ResponseCode::VALUE_CORRUPTED))
                    .context("Failed to read sql data for tag: USER_AUTH_TYPE.")?;
                KeyParameterValue::HardwareAuthenticatorType(HardwareAuthenticatorType(
                    user_auth_type,
                ))
            }
            Tag::AUTH_TIMEOUT => {
                let auth_timeout: i32 =
                    data.get().context("Failed to read sql data for tag: AUTH_TIMEOUT.")?;
                KeyParameterValue::AuthTimeout(auth_timeout)
            }
            Tag::ALLOW_WHILE_ON_BODY => KeyParameterValue::AllowWhileOnBody,
            Tag::TRUSTED_USER_PRESENCE_REQUIRED => KeyParameterValue::TrustedUserPresenceRequired,
            Tag::TRUSTED_CONFIRMATION_REQUIRED => KeyParameterValue::TrustedConfirmationRequired,
            Tag::UNLOCKED_DEVICE_REQUIRED => KeyParameterValue::UnlockedDeviceRequired,
            Tag::APPLICATION_ID => {
                let app_id: Vec<u8> =
                    data.get().context("Failed to read sql data for tag: APPLICATION_ID.")?;
                KeyParameterValue::ApplicationID(app_id)
            }
            Tag::APPLICATION_DATA => {
                let app_data: Vec<u8> =
                    data.get().context("Failed to read sql data for tag: APPLICATION_DATA.")?;
                KeyParameterValue::ApplicationData(app_data)
            }
            Tag::CREATION_DATETIME => {
                let creation_datetime: i64 =
                    data.get().context("Failed to read sql data for tag: CREATION_DATETIME.")?;
                KeyParameterValue::CreationDateTime(creation_datetime)
            }
            Tag::ORIGIN => {
                let origin: i32 = data
                    .get()
                    .map_err(|_| KeystoreError::Rc(ResponseCode::VALUE_CORRUPTED))
                    .context("Failed to read sql data for tag: ORIGIN.")?;
                KeyParameterValue::KeyOrigin(KeyOrigin(origin))
            }
            Tag::ROOT_OF_TRUST => {
                let root_of_trust: Vec<u8> =
                    data.get().context("Failed to read sql data for tag: ROOT_OF_TRUST.")?;
                KeyParameterValue::RootOfTrust(root_of_trust)
            }
            Tag::OS_VERSION => {
                let os_version: i32 =
                    data.get().context("Failed to read sql data for tag: OS_VERSION.")?;
                KeyParameterValue::OSVersion(os_version)
            }
            Tag::OS_PATCHLEVEL => {
                let os_patch_level: i32 =
                    data.get().context("Failed to read sql data for tag: OS_PATCHLEVEL.")?;
                KeyParameterValue::OSPatchLevel(os_patch_level)
            }
            Tag::UNIQUE_ID => {
                let unique_id: Vec<u8> =
                    data.get().context("Failed to read sql data for tag: UNIQUE_ID.")?;
                KeyParameterValue::UniqueID(unique_id)
            }
            Tag::ATTESTATION_CHALLENGE => {
                let attestation_challenge: Vec<u8> = data
                    .get()
                    .context("Failed to read sql data for tag: ATTESTATION_CHALLENGE.")?;
                KeyParameterValue::AttestationChallenge(attestation_challenge)
            }
            Tag::ATTESTATION_APPLICATION_ID => {
                let attestation_app_id: Vec<u8> = data
                    .get()
                    .context("Failed to read sql data for tag: ATTESTATION_APPLICATION_ID.")?;
                KeyParameterValue::AttestationApplicationID(attestation_app_id)
            }
            Tag::ATTESTATION_ID_BRAND => {
                let attestation_id_brand: Vec<u8> =
                    data.get().context("Failed to read sql data for tag: ATTESTATION_ID_BRAND.")?;
                KeyParameterValue::AttestationIdBrand(attestation_id_brand)
            }
            Tag::ATTESTATION_ID_DEVICE => {
                let attestation_id_device: Vec<u8> = data
                    .get()
                    .context("Failed to read sql data for tag: ATTESTATION_ID_DEVICE.")?;
                KeyParameterValue::AttestationIdDevice(attestation_id_device)
            }
            Tag::ATTESTATION_ID_PRODUCT => {
                let attestation_id_product: Vec<u8> = data
                    .get()
                    .context("Failed to read sql data for tag: ATTESTATION_ID_PRODUCT.")?;
                KeyParameterValue::AttestationIdProduct(attestation_id_product)
            }
            Tag::ATTESTATION_ID_SERIAL => {
                let attestation_id_serial: Vec<u8> = data
                    .get()
                    .context("Failed to read sql data for tag: ATTESTATION_ID_SERIAL.")?;
                KeyParameterValue::AttestationIdSerial(attestation_id_serial)
            }
            Tag::ATTESTATION_ID_IMEI => {
                let attestation_id_imei: Vec<u8> =
                    data.get().context("Failed to read sql data for tag: ATTESTATION_ID_IMEI.")?;
                KeyParameterValue::AttestationIdIMEI(attestation_id_imei)
            }
            Tag::ATTESTATION_ID_MEID => {
                let attestation_id_meid: Vec<u8> =
                    data.get().context("Failed to read sql data for tag: ATTESTATION_ID_MEID.")?;
                KeyParameterValue::AttestationIdMEID(attestation_id_meid)
            }
            Tag::ATTESTATION_ID_MANUFACTURER => {
                let attestation_id_manufacturer: Vec<u8> = data
                    .get()
                    .context("Failed to read sql data for tag: ATTESTATION_ID_MANUFACTURER.")?;
                KeyParameterValue::AttestationIdManufacturer(attestation_id_manufacturer)
            }
            Tag::ATTESTATION_ID_MODEL => {
                let attestation_id_model: Vec<u8> =
                    data.get().context("Failed to read sql data for tag: ATTESTATION_ID_MODEL.")?;
                KeyParameterValue::AttestationIdModel(attestation_id_model)
            }
            Tag::VENDOR_PATCHLEVEL => {
                let vendor_patch_level: i32 =
                    data.get().context("Failed to read sql data for tag: VENDOR_PATCHLEVEL.")?;
                KeyParameterValue::VendorPatchLevel(vendor_patch_level)
            }
            Tag::BOOT_PATCHLEVEL => {
                let boot_patch_level: i32 =
                    data.get().context("Failed to read sql data for tag: BOOT_PATCHLEVEL.")?;
                KeyParameterValue::BootPatchLevel(boot_patch_level)
            }
            Tag::ASSOCIATED_DATA => {
                let associated_data: Vec<u8> =
                    data.get().context("Failed to read sql data for tag: ASSOCIATED_DATA.")?;
                KeyParameterValue::AssociatedData(associated_data)
            }
            Tag::NONCE => {
                let nonce: Vec<u8> =
                    data.get().context("Failed to read sql data for tag: NONCE.")?;
                KeyParameterValue::Nonce(nonce)
            }
            Tag::MAC_LENGTH => {
                let mac_length: i32 =
                    data.get().context("Failed to read sql data for tag: MAC_LENGTH.")?;
                KeyParameterValue::MacLength(mac_length)
            }
            Tag::RESET_SINCE_ID_ROTATION => KeyParameterValue::ResetSinceIdRotation,
            Tag::CONFIRMATION_TOKEN => {
                let confirmation_token: Vec<u8> =
                    data.get().context("Failed to read sql data for tag: CONFIRMATION_TOKEN.")?;
                KeyParameterValue::ConfirmationToken(confirmation_token)
            }
            _ => {
                return Err(KeystoreError::Rc(ResponseCode::VALUE_CORRUPTED))
                    .context("Failed to decode Tag enum from value.")?
            }
        };
        Ok(KeyParameter::new(key_param_value, security_level_val))
    }
}

/// Macro rules for converting key parameter to/from wire type.
/// This macro takes between three and four different pieces of information about each
/// of the KeyParameterValue variants:
/// 1. The KeyParameterValue variant name,
/// 2. the tag name corresponding to the variant,
/// 3. the field name in the KmKeyParameter struct, in which information about this variant is
///    stored when converted, and
/// 4. an optional enum type name when the nested value is of enum type.
/// The macro takes a set of lines corresponding to each KeyParameterValue variant and generates
/// the two conversion methods: convert_to_wire() and convert_from_wire().
/// ## Example
/// ```
/// implement_key_parameter_conversion_to_from_wire! {
///         Invalid, INVALID, na;
///         KeyPurpose, PURPOSE, integer, KeyPurpose;
///         CallerNonce, CALLER_NONCE, boolValue;
///         UserSecureID, USER_SECURE_ID, longInteger;
///         ApplicationID, APPLICATION_ID, blob;
/// }
/// ```
/// expands to:
/// ```
/// pub fn convert_to_wire(self) -> KmKeyParameter {
///         match self {
///                 KeyParameterValue::Invalid => KmKeyParameter {
///                         tag: Tag::INVALID,
///                         ..Default::default()
///                 },
///                 KeyParameterValue::KeyPurpose(v) => KmKeyParameter {
///                         tag: Tag::PURPOSE,
///                         integer: v.0,
///                         ..Default::default()
///                 },
///                 KeyParameterValue::CallerNonce => KmKeyParameter {
///                         tag: Tag::CALLER_NONCE,
///                         boolValue: true,
///                         ..Default::default()
///                 },
///                 KeyParameterValue::UserSecureID(v) => KmKeyParameter {
///                         tag: Tag::USER_SECURE_ID,
///                         longInteger: v,
///                         ..Default::default()
///                 },
///                 KeyParameterValue::ApplicationID(v) => KmKeyParameter {
///                         tag: Tag::APPLICATION_ID,
///                         blob: v,
///                         ..Default::default()
///                 },
///         }
/// }
/// ```
/// and
/// ```
/// pub fn convert_from_wire(aidl_kp: KmKeyParameter) -> KeyParameterValue {
///         match aidl_kp {
///                 KmKeyParameter {
///                         tag: Tag::INVALID,
///                         ..
///                 } => KeyParameterValue::Invalid,
///                 KmKeyParameter {
///                         tag: Tag::PURPOSE,
///                         integer: v,
///                         ..
///                 } => KeyParameterValue::KeyPurpose(KeyPurpose(v)),
///                 KmKeyParameter {
///                         tag: Tag::CALLER_NONCE,
///                         boolValue: true,
///                         ..
///                 } => KeyParameterValue::CallerNonce,
///                 KmKeyParameter {
///                          tag: Tag::USER_SECURE_ID,
///                          longInteger: v,
///                          ..
///                 } => KeyParameterValue::UserSecureID(v),
///                 KmKeyParameter {
///                          tag: Tag::APPLICATION_ID,
///                          blob: v,
///                          ..
///                 } => KeyParameterValue::ApplicationID(v),
///                 _ => KeyParameterValue::Invalid,
///         }
/// }
///
macro_rules! implement_key_parameter_conversion_to_from_wire {
    // There are three groups of rules in this macro.
    // 1. The first group contains the rule which acts as the public interface. It takes the input
    //    given to this macro and prepares it to be given as input to the two groups of rules
    //    mentioned below.
    // 2. The second group starts with the prefix @to and generates convert_to_wire() method.
    // 3. The third group starts with the prefix @from and generates convert_from_wire() method.
    //
    // Input to this macro is first handled by the first macro rule (belonging to the first
    // group above), which pre-processes the input such that rules in the other two groups
    // generate the code for the two methods, when called recursively.
    // Each of convert_to_wire() and convert_from_wire() methods are generated using a set of
    // four macro rules in the second two groups. These four rules intend to do the following
    // tasks respectively:
    // i) generates match arms related to Invalid KeyParameterValue variant.
    // ii) generates match arms related to boolValue field in KmKeyParameter struct.
    // iii) generates match arms related to all the other fields in KmKeyParameter struct.
    // iv) generates the method definition including the match arms generated from the above
    // three recursive macro rules.

    // This rule is applied on the input given to the macro invocations from outside the macro.
    ($($variant:ident, $tag_name:ident, $field_name:ident $(,$enum_type:ident)?;)*) => {
        // pre-processes input to target the rules that generate convert_to_wire() method.
        implement_key_parameter_conversion_to_from_wire! {@to
            [], $($variant, $tag_name, $field_name $(,$enum_type)?;)*
        }
        // pre-processes input to target the rules that generate convert_from_wire() method.
        implement_key_parameter_conversion_to_from_wire! {@from
            [], $($variant, $tag_name, $field_name $(,$enum_type)?;)*
        }
    };

    // Following four rules (belonging to the aforementioned second group) generate
    // convert_to_wire() conversion method.
    // -----------------------------------------------------------------------
    // This rule handles Invalid variant.
    // On an input: 'Invalid, INVALID, na;' it generates a match arm like:
    // KeyParameterValue::Invalid => KmKeyParameter {
    //                                   tag: Tag::INVALID,
    //                                   ..Default::default()
    //                               },
    (@to [$($out:tt)*], Invalid, INVALID, na; $($in:tt)*) => {
        implement_key_parameter_conversion_to_from_wire! {@to
            [$($out)*
                KeyParameterValue::Invalid => KmKeyParameter {
                    tag: Tag::INVALID,
                    ..Default::default()
                },
            ], $($in)*
        }
    };
    // This rule handles all variants that correspond to bool values.
    // On an input like: 'CallerNonce, CALLER_NONCE, boolValue;' it generates
    // a match arm like:
    // KeyParameterValue::CallerNonce => KmKeyParameter {
    //                                       tag: Tag::CALLER_NONCE,
    //                                       boolValue: true,
    //                                       ..Default::default()
    //                                   },
    (@to [$($out:tt)*], $variant:ident, $tag_val:ident, boolValue; $($in:tt)*) => {
        implement_key_parameter_conversion_to_from_wire! {@to
            [$($out)*
                KeyParameterValue::$variant => KmKeyParameter {
                    tag: Tag::$tag_val,
                    boolValue: true,
                    ..Default::default()
                },
            ], $($in)*
        }
    };
    // This rule handles all enum variants.
    // On an input like: 'KeyPurpose, PURPOSE, integer, KeyPurpose;' it generates a match arm
    // like: KeyParameterValue::KeyPurpose(v) => KmKeyParameter {
    //                                               tag: Tag::PURPOSE,
    //                                               integer: v.0,
    //                                               ..Default::default(),
    //                                           },
    (@to [$($out:tt)*], $variant:ident, $tag_val:ident, $field:ident, $enum_type:ident; $($in:tt)*) => {
       implement_key_parameter_conversion_to_from_wire! {@to
           [$($out)*
               KeyParameterValue::$variant(v) => KmKeyParameter {
                   tag: Tag::$tag_val,
                   $field: v.0,
                   ..Default::default()
               },
           ], $($in)*
       }
    };
    // This rule handles all variants that are neither invalid nor bool values nor enums
    // (i.e. all variants which correspond to integer, longInteger, and blob fields in
    // KmKeyParameter).
    // On an input like: 'ConfirmationToken, CONFIRMATION_TOKEN, blob;' it generates a match arm
    // like: KeyParameterValue::ConfirmationToken(v) => KmKeyParameter {
    //                                                      tag: Tag::CONFIRMATION_TOKEN,
    //                                                      blob: v,
    //                                                      ..Default::default(),
    //                                                  },
    (@to [$($out:tt)*], $variant:ident, $tag_val:ident, $field:ident; $($in:tt)*) => {
        implement_key_parameter_conversion_to_from_wire! {@to
            [$($out)*
                KeyParameterValue::$variant(v) => KmKeyParameter {
                    tag: Tag::$tag_val,
                    $field: v,
                    ..Default::default()
                },
            ], $($in)*
        }
    };
    // After all the match arms are generated by the above three rules, this rule combines them
    // into the convert_to_wire() method.
    (@to [$($out:tt)*], ) => {
        /// Conversion of key parameter to wire type
        pub fn convert_to_wire(self) -> KmKeyParameter {
            match self {
                $($out)*
            }
        }
    };

    // Following four rules (belonging to the aforementioned third group) generate
    // convert_from_wire() conversion method.
    // ------------------------------------------------------------------------
    // This rule handles Invalid variant.
    // On an input: 'Invalid, INVALID, na;' it generates a match arm like:
    // KmKeyParameter { tag: Tag::INVALID, .. } => KeyParameterValue::Invalid,
    (@from [$($out:tt)*], Invalid, INVALID, na; $($in:tt)*) => {
        implement_key_parameter_conversion_to_from_wire! {@from
            [$($out)*
                KmKeyParameter {
                    tag: Tag::INVALID,
                    ..
                } => KeyParameterValue::Invalid,
            ], $($in)*
        }
    };
    // This rule handles all variants that correspond to bool values.
    // On an input like: 'CallerNonce, CALLER_NONCE, boolValue;' it generates a match arm like:
    // KmKeyParameter {
    //      tag: Tag::CALLER_NONCE,
    //      boolValue: true,
    //      ..
    // } => KeyParameterValue::CallerNonce,
    (@from [$($out:tt)*], $variant:ident, $tag_val:ident, boolValue; $($in:tt)*) => {
        implement_key_parameter_conversion_to_from_wire! {@from
            [$($out)*
                KmKeyParameter {
                    tag: Tag::$tag_val,
                    boolValue: true,
                    ..
                } => KeyParameterValue::$variant,
            ], $($in)*
        }
    };
    // This rule handles all enum variants.
    // On an input like: 'KeyPurpose, PURPOSE, integer, KeyPurpose;' it generates a match arm
    // like:
    // KmKeyParameter {
    //         tag: Tag::PURPOSE,
    //         integer: v,
    //         ..,
    // } => KeyParameterValue::KeyPurpose(KeyPurpose(v)),
    (@from [$($out:tt)*], $variant:ident, $tag_val:ident, $field:ident, $enum_type:ident; $($in:tt)*) => {
        implement_key_parameter_conversion_to_from_wire! {@from
            [$($out)*
                KmKeyParameter {
                    tag: Tag::$tag_val,
                    $field: v,
                    ..
                } => KeyParameterValue::$variant($enum_type(v)),
            ], $($in)*
        }
    };
    // This rule handles all variants that are neither invalid nor bool values nor enums
    // (i.e. all variants which correspond to integer, longInteger, and blob fields in
    // KmKeyParameter).
    // On an input like: 'ConfirmationToken, CONFIRMATION_TOKEN, blob;' it generates a match arm
    // like:
    // KmKeyParameter {
    //         tag: Tag::CONFIRMATION_TOKEN,
    //         blob: v,
    //         ..,
    // } => KeyParameterValue::ConfirmationToken(v),
    (@from [$($out:tt)*], $variant:ident, $tag_val:ident, $field:ident; $($in:tt)*) => {
        implement_key_parameter_conversion_to_from_wire! {@from
            [$($out)*
                KmKeyParameter {
                    tag: Tag::$tag_val,
                    $field: v,
                    ..
                } => KeyParameterValue::$variant(v),
            ], $($in)*
        }
    };
    // After all the match arms are generated by the above three rules, this rule combines them
    // into the convert_from_wire() method.
    (@from [$($out:tt)*], ) => {
        /// Conversion of key parameter from wire type
        pub fn convert_from_wire(aidl_kp: KmKeyParameter) -> KeyParameterValue {
            match aidl_kp {
                $($out)*
                _ => KeyParameterValue::Invalid,
            }
        }
    };
}

impl KeyParameterValue {
    // Invoke the macro that generates the code for key parameter conversion to/from wire type
    // with all possible variants of KeyParameterValue. Each line corresponding to a variant
    // contains: variant identifier, tag value, and the related field name (i.e.
    // boolValue/integer/longInteger/blob) in the KmKeyParameter.
    implement_key_parameter_conversion_to_from_wire! {
        Invalid, INVALID, na;
        KeyPurpose, PURPOSE, integer, KeyPurpose;
        Algorithm, ALGORITHM, integer, Algorithm;
        KeySize, KEY_SIZE, integer;
        BlockMode, BLOCK_MODE, integer, BlockMode;
        Digest, DIGEST, integer, Digest;
        PaddingMode, PADDING, integer, PaddingMode;
        CallerNonce, CALLER_NONCE, boolValue;
        MinMacLength, MIN_MAC_LENGTH, integer;
        EcCurve, EC_CURVE, integer, EcCurve;
        RSAPublicExponent, RSA_PUBLIC_EXPONENT, longInteger;
        IncludeUniqueID, INCLUDE_UNIQUE_ID, boolValue;
        BootLoaderOnly, BOOTLOADER_ONLY, boolValue;
        RollbackResistance, ROLLBACK_RESISTANCE, boolValue;
        ActiveDateTime, ACTIVE_DATETIME, longInteger;
        OriginationExpireDateTime, ORIGINATION_EXPIRE_DATETIME, longInteger;
        UsageExpireDateTime, USAGE_EXPIRE_DATETIME, longInteger;
        MinSecondsBetweenOps, MIN_SECONDS_BETWEEN_OPS, integer;
        MaxUsesPerBoot, MAX_USES_PER_BOOT, integer;
        UserID, USER_ID, integer;
        UserSecureID, USER_SECURE_ID, longInteger;
        NoAuthRequired, NO_AUTH_REQUIRED, boolValue;
        HardwareAuthenticatorType, USER_AUTH_TYPE, integer, HardwareAuthenticatorType;
        AuthTimeout, AUTH_TIMEOUT, integer;
        AllowWhileOnBody, ALLOW_WHILE_ON_BODY, boolValue;
        TrustedUserPresenceRequired, TRUSTED_USER_PRESENCE_REQUIRED, boolValue;
        TrustedConfirmationRequired, TRUSTED_CONFIRMATION_REQUIRED, boolValue;
        UnlockedDeviceRequired, UNLOCKED_DEVICE_REQUIRED, boolValue;
        ApplicationID, APPLICATION_ID, blob;
        ApplicationData, APPLICATION_DATA, blob;
        CreationDateTime, CREATION_DATETIME, longInteger;
        KeyOrigin, ORIGIN, integer, KeyOrigin;
        RootOfTrust, ROOT_OF_TRUST, blob;
        OSVersion, OS_VERSION, integer;
        OSPatchLevel, OS_PATCHLEVEL, integer;
        UniqueID, UNIQUE_ID, blob;
        AttestationChallenge, ATTESTATION_CHALLENGE, blob;
        AttestationApplicationID, ATTESTATION_APPLICATION_ID, blob;
        AttestationIdBrand, ATTESTATION_ID_BRAND, blob;
        AttestationIdDevice, ATTESTATION_ID_DEVICE, blob;
        AttestationIdProduct, ATTESTATION_ID_PRODUCT, blob;
        AttestationIdSerial, ATTESTATION_ID_SERIAL, blob;
        AttestationIdIMEI, ATTESTATION_ID_IMEI, blob;
        AttestationIdMEID, ATTESTATION_ID_MEID, blob;
        AttestationIdManufacturer, ATTESTATION_ID_MANUFACTURER, blob;
        AttestationIdModel, ATTESTATION_ID_MODEL, blob;
        VendorPatchLevel, VENDOR_PATCHLEVEL, integer;
        BootPatchLevel, BOOT_PATCHLEVEL, integer;
        AssociatedData, ASSOCIATED_DATA, blob;
        Nonce, NONCE, blob;
        MacLength, MAC_LENGTH, integer;
        ResetSinceIdRotation, RESET_SINCE_ID_ROTATION, boolValue;
        ConfirmationToken, CONFIRMATION_TOKEN, blob;
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
        tests::check_result_contains_error_string(
            query_from_keyparameter(&db),
            "Failed to decode Tag enum from value.",
        );
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
        let actual = KeyParameterValue::convert_to_wire(kp.key_parameter_value);
        assert_eq!(Tag::INVALID, actual.tag);
    }
    #[test]
    fn test_convert_to_wire_bool() {
        let kp = KeyParameter::new(KeyParameterValue::CallerNonce, SecurityLevel::STRONGBOX);
        let actual = KeyParameterValue::convert_to_wire(kp.key_parameter_value);
        assert_eq!(Tag::CALLER_NONCE, actual.tag);
        assert_eq!(true, actual.boolValue);
    }
    #[test]
    fn test_convert_to_wire_integer() {
        let kp = KeyParameter::new(
            KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
            SecurityLevel::STRONGBOX,
        );
        let actual = KeyParameterValue::convert_to_wire(kp.key_parameter_value);
        assert_eq!(Tag::PURPOSE, actual.tag);
        assert_eq!(KeyPurpose::ENCRYPT.0, actual.integer);
    }
    #[test]
    fn test_convert_to_wire_long_integer() {
        let kp =
            KeyParameter::new(KeyParameterValue::UserSecureID(i64::MAX), SecurityLevel::STRONGBOX);
        let actual = KeyParameterValue::convert_to_wire(kp.key_parameter_value);
        assert_eq!(Tag::USER_SECURE_ID, actual.tag);
        assert_eq!(i64::MAX, actual.longInteger);
    }
    #[test]
    fn test_convert_to_wire_blob() {
        let kp = KeyParameter::new(
            KeyParameterValue::ConfirmationToken(String::from("ConfirmationToken").into_bytes()),
            SecurityLevel::STRONGBOX,
        );
        let actual = KeyParameterValue::convert_to_wire(kp.key_parameter_value);
        assert_eq!(Tag::CONFIRMATION_TOKEN, actual.tag);
        assert_eq!(String::from("ConfirmationToken").into_bytes(), actual.blob);
    }

    /// unit tests for from conversion
    #[test]
    fn test_convert_from_wire_invalid() {
        let aidl_kp = KmKeyParameter { tag: Tag::INVALID, ..Default::default() };
        let actual = KeyParameterValue::convert_from_wire(aidl_kp);
        assert_eq!(KeyParameterValue::Invalid, actual);
    }
    #[test]
    fn test_convert_from_wire_bool() {
        let aidl_kp =
            KmKeyParameter { tag: Tag::CALLER_NONCE, boolValue: true, ..Default::default() };
        let actual = KeyParameterValue::convert_from_wire(aidl_kp);
        assert_eq!(KeyParameterValue::CallerNonce, actual);
    }
    #[test]
    fn test_convert_from_wire_integer() {
        let aidl_kp = KmKeyParameter {
            tag: Tag::PURPOSE,
            integer: KeyPurpose::ENCRYPT.0,
            ..Default::default()
        };
        let actual = KeyParameterValue::convert_from_wire(aidl_kp);
        assert_eq!(KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT), actual);
    }
    #[test]
    fn test_convert_from_wire_long_integer() {
        let aidl_kp = KmKeyParameter {
            tag: Tag::USER_SECURE_ID,
            longInteger: i64::MAX,
            ..Default::default()
        };
        let actual = KeyParameterValue::convert_from_wire(aidl_kp);
        assert_eq!(KeyParameterValue::UserSecureID(i64::MAX), actual);
    }
    #[test]
    fn test_convert_from_wire_blob() {
        let aidl_kp = KmKeyParameter {
            tag: Tag::CONFIRMATION_TOKEN,
            blob: String::from("ConfirmationToken").into_bytes(),
            ..Default::default()
        };
        let actual = KeyParameterValue::convert_from_wire(aidl_kp);
        assert_eq!(
            KeyParameterValue::ConfirmationToken(String::from("ConfirmationToken").into_bytes()),
            actual
        );
    }
}
