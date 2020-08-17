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

use crate::keymint_definitions::{
    Algorithm, BlockMode, Digest, EcCurve, HardwareAuthenticatorType, KeyBlobUsageRequirements,
    KeyOrigin, KeyPurpose, PaddingMode, SecurityLevel, Tag,
};

/// KeyParameter wraps the KeyParameterValue and the security level at which it is enforced.
pub struct KeyParameter {
    key_parameter_value: KeyParameterValue,
    security_level: SecurityLevel,
}

/// KeyParameterValue holds a value corresponding to one of the Tags defined in
/// the AIDL spec at hardware/interfaces/keymint
#[derive(PartialEq, Debug)]
pub enum KeyParameterValue {
    /// Associated with Tag:INVALID
    Invalid,
    /// Set of purposes for which the key may be used
    KeyPurpose(KeyPurpose),
    /// Cryptographic algorithm with which the key is used
    Algorithm(Algorithm),
    /// Size of the key , in bits
    KeySize(u32),
    /// Block cipher mode(s) with which the key may be used
    BlockMode(BlockMode),
    /// Digest algorithms that may be used with the key to perform signing and verification
    Digest(Digest),
    /// Padding modes that may be used with the key.  Relevant to RSA, AES and 3DES keys.
    PaddingMode(PaddingMode),
    /// Can the caller provide a nonce for nonce-requiring operations
    CallerNonce,
    /// Minimum length of MAC for HMAC keys and AES keys that support GCM mode
    MinMacLength(u32),
    /// The elliptic curve
    EcCurve(EcCurve),
    /// Value of the public exponent for an RSA key pair
    RSAPublicExponent(u64),
    /// An attestation certificate for the generated key should contain an application-scoped
    /// and time-bounded device-unique ID
    IncludeUniqueID,
    /// Necessary system environment conditions for the generated key to be used
    KeyBlobUsageRequirements(KeyBlobUsageRequirements),
    /// Only the boot loader can use the key
    BootLoaderOnly,
    /// When deleted, the key is guaranteed to be permanently deleted and unusable
    RollbackResistance,
    //TODO: HARDWARE_TYPE reserved for future use
    /// The date and time at which the key becomes active
    ActiveDateTime(u64),
    /// The date and time at which the key expires for signing and encryption
    OriginationExpireDateTime(u64),
    /// The date and time at which the key expires for verification and decryption
    UsageExpireDateTime(u64),
    /// Minimum amount of time that elapses between allowed operations
    MinSecondsBetweenOps(u32),
    /// Maximum number of times that a key may be used between system reboots
    MaxUsesPerBoot(u32),
    /// ID of the Android user that is permitted to use the key
    UserID(u32),
    /// A key may only be used under a particular secure user authentication state
    UserSecureID(u64),
    /// No authentication is required to use this key
    NoAuthRequired,
    /// The types of user authenticators that may be used to authorize this key
    HardwareAuthenticatorType(HardwareAuthenticatorType),
    /// The time in seconds for which the key is authorized for use, after user authentication
    AuthTimeout(u32),
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
    CreationDateTime(u64),
    /// Specifies where the key was created, if known
    KeyOrigin(KeyOrigin),
    /// The key used by verified boot to validate the operating system booted
    RootOfTrust(Vec<u8>),
    /// System OS version with which the key may be used
    OSVersion(u32),
    /// Specifies the system security patch level with which the key may be used
    OSPatchLevel(u32),
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
    VendorPatchLevel(u32),
    /// Specifies the boot image (kernel) security patch level with which the key may be used
    BootPatchLevel(u32),
    /// Provides "associated data" for AES-GCM encryption or decryption
    AssociatedData(Vec<u8>),
    /// Provides or returns a nonce or Initialization Vector (IV) for AES-GCM,
    /// AES-CBC, AES-CTR, or 3DES-CBC encryption or decryption
    Nonce(Vec<u8>),
    /// Provides the requested length of a MAC or GCM authentication tag, in bits
    MacLength(u32),
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
            KeyParameterValue::KeyBlobUsageRequirements(_) => Tag::BLOB_USAGE_REQUIREMENTS,
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
}

#[cfg(test)]
mod basic_tests {
    use crate::key_parameter::*;
    use crate::keymint_definitions::{SecurityLevel, Tag};

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
