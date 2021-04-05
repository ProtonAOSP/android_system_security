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

//! This module provides convenience functions for keystore2 logging.
use crate::error::get_error_code;
use crate::key_parameter::KeyParameterValue as KsKeyParamValue;
use crate::operation::Outcome;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    HardwareAuthenticatorType::HardwareAuthenticatorType, KeyOrigin::KeyOrigin,
    KeyParameter::KeyParameter, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    SecurityLevel::SecurityLevel,
};
use statslog_rust::keystore2_key_creation_event_reported::{
    Algorithm as StatsdAlgorithm, EcCurve as StatsdEcCurve, KeyOrigin as StatsdKeyOrigin,
    Keystore2KeyCreationEventReported, SecurityLevel as StatsdKeyCreationSecurityLevel,
    UserAuthType as StatsdUserAuthType,
};
use statslog_rust::keystore2_key_operation_event_reported::{
    Keystore2KeyOperationEventReported, Outcome as StatsdOutcome, Purpose as StatsdKeyPurpose,
    SecurityLevel as StatsdKeyOperationSecurityLevel,
};

fn create_default_key_creation_atom() -> Keystore2KeyCreationEventReported {
    // If a value is not present, fields represented by bitmaps and i32 fields
    // will take 0, except error_code which defaults to 1 indicating NO_ERROR and key_size,
    // and auth_time_out which default to -1.
    // The boolean fields are set to false by default.
    // Some keymint enums do have 0 as an enum variant value. In such cases, the corresponding
    // enum variant value in atoms.proto is incremented by 1, in order to have 0 as the reserved
    // value for unspecified fields.
    Keystore2KeyCreationEventReported {
        algorithm: StatsdAlgorithm::AlgorithmUnspecified,
        key_size: -1,
        key_origin: StatsdKeyOrigin::OriginUnspecified,
        user_auth_type: StatsdUserAuthType::AuthTypeUnspecified,
        user_auth_key_timeout_seconds: -1,
        padding_mode_bitmap: 0,
        digest_bitmap: 0,
        block_mode_bitmap: 0,
        purpose_bitmap: 0,
        ec_curve: StatsdEcCurve::EcCurveUnspecified,
        // as per keystore2/ResponseCode.aidl, 1 is reserved for NO_ERROR
        error_code: 1,
        attestation_requested: false,
        security_level: StatsdKeyCreationSecurityLevel::SecurityLevelUnspecified,
    }
}

fn create_default_key_operation_atom() -> Keystore2KeyOperationEventReported {
    Keystore2KeyOperationEventReported {
        purpose: StatsdKeyPurpose::KeyPurposeUnspecified,
        padding_mode_bitmap: 0,
        digest_bitmap: 0,
        block_mode_bitmap: 0,
        outcome: StatsdOutcome::OutcomeUnspecified,
        error_code: 1,
        key_upgraded: false,
        security_level: StatsdKeyOperationSecurityLevel::SecurityLevelUnspecified,
    }
}

/// Log key creation events via statsd API.
pub fn log_key_creation_event_stats<U>(
    sec_level: SecurityLevel,
    key_params: &[KeyParameter],
    result: &anyhow::Result<U>,
) {
    let key_creation_event_stats =
        construct_key_creation_event_stats(sec_level, key_params, result);

    let logging_result = key_creation_event_stats.stats_write();

    if let Err(e) = logging_result {
        log::error!(
            "In log_key_creation_event_stats. Error in logging key creation event. {:?}",
            e
        );
    }
}

/// Log key operation events via statsd API.
pub fn log_key_operation_event_stats(
    sec_level: SecurityLevel,
    key_purpose: KeyPurpose,
    op_params: &[KeyParameter],
    op_outcome: &Outcome,
    key_upgraded: bool,
) {
    let key_operation_event_stats = construct_key_operation_event_stats(
        sec_level,
        key_purpose,
        op_params,
        op_outcome,
        key_upgraded,
    );

    let logging_result = key_operation_event_stats.stats_write();

    if let Err(e) = logging_result {
        log::error!(
            "In log_key_operation_event_stats. Error in logging key operation event. {:?}",
            e
        );
    }
}

fn construct_key_creation_event_stats<U>(
    sec_level: SecurityLevel,
    key_params: &[KeyParameter],
    result: &anyhow::Result<U>,
) -> Keystore2KeyCreationEventReported {
    let mut key_creation_event_atom = create_default_key_creation_atom();

    if let Err(ref e) = result {
        key_creation_event_atom.error_code = get_error_code(e);
    }

    key_creation_event_atom.security_level = match sec_level {
        SecurityLevel::SOFTWARE => StatsdKeyCreationSecurityLevel::SecurityLevelSoftware,
        SecurityLevel::TRUSTED_ENVIRONMENT => {
            StatsdKeyCreationSecurityLevel::SecurityLevelTrustedEnvironment
        }
        SecurityLevel::STRONGBOX => StatsdKeyCreationSecurityLevel::SecurityLevelStrongbox,
        //KEYSTORE is not a valid variant here
        _ => StatsdKeyCreationSecurityLevel::SecurityLevelUnspecified,
    };

    for key_param in key_params.iter().map(KsKeyParamValue::from) {
        match key_param {
            KsKeyParamValue::Algorithm(a) => {
                key_creation_event_atom.algorithm = match a {
                    Algorithm::RSA => StatsdAlgorithm::Rsa,
                    Algorithm::EC => StatsdAlgorithm::Ec,
                    Algorithm::AES => StatsdAlgorithm::Aes,
                    Algorithm::TRIPLE_DES => StatsdAlgorithm::TripleDes,
                    Algorithm::HMAC => StatsdAlgorithm::Hmac,
                    _ => StatsdAlgorithm::AlgorithmUnspecified,
                }
            }
            KsKeyParamValue::KeySize(s) => {
                key_creation_event_atom.key_size = s;
            }
            KsKeyParamValue::KeyOrigin(o) => {
                key_creation_event_atom.key_origin = match o {
                    KeyOrigin::GENERATED => StatsdKeyOrigin::Generated,
                    KeyOrigin::DERIVED => StatsdKeyOrigin::Derived,
                    KeyOrigin::IMPORTED => StatsdKeyOrigin::Imported,
                    KeyOrigin::RESERVED => StatsdKeyOrigin::Reserved,
                    KeyOrigin::SECURELY_IMPORTED => StatsdKeyOrigin::SecurelyImported,
                    _ => StatsdKeyOrigin::OriginUnspecified,
                }
            }
            KsKeyParamValue::HardwareAuthenticatorType(a) => {
                key_creation_event_atom.user_auth_type = match a {
                    HardwareAuthenticatorType::NONE => StatsdUserAuthType::None,
                    HardwareAuthenticatorType::PASSWORD => StatsdUserAuthType::Password,
                    HardwareAuthenticatorType::FINGERPRINT => StatsdUserAuthType::Fingerprint,
                    HardwareAuthenticatorType::ANY => StatsdUserAuthType::Any,
                    _ => StatsdUserAuthType::AuthTypeUnspecified,
                }
            }
            KsKeyParamValue::AuthTimeout(t) => {
                key_creation_event_atom.user_auth_key_timeout_seconds = t;
            }
            KsKeyParamValue::PaddingMode(p) => {
                key_creation_event_atom.padding_mode_bitmap =
                    compute_padding_mode_bitmap(&key_creation_event_atom.padding_mode_bitmap, p);
            }
            KsKeyParamValue::Digest(d) => {
                key_creation_event_atom.digest_bitmap =
                    compute_digest_bitmap(&key_creation_event_atom.digest_bitmap, d);
            }
            KsKeyParamValue::BlockMode(b) => {
                key_creation_event_atom.block_mode_bitmap =
                    compute_block_mode_bitmap(&key_creation_event_atom.block_mode_bitmap, b);
            }
            KsKeyParamValue::KeyPurpose(k) => {
                key_creation_event_atom.purpose_bitmap =
                    compute_purpose_bitmap(&key_creation_event_atom.purpose_bitmap, k);
            }
            KsKeyParamValue::EcCurve(e) => {
                key_creation_event_atom.ec_curve = match e {
                    EcCurve::P_224 => StatsdEcCurve::P224,
                    EcCurve::P_256 => StatsdEcCurve::P256,
                    EcCurve::P_384 => StatsdEcCurve::P384,
                    EcCurve::P_521 => StatsdEcCurve::P521,
                    _ => StatsdEcCurve::EcCurveUnspecified,
                }
            }
            KsKeyParamValue::AttestationChallenge(_) => {
                key_creation_event_atom.attestation_requested = true;
            }
            _ => {}
        }
    }
    key_creation_event_atom
}

fn construct_key_operation_event_stats(
    sec_level: SecurityLevel,
    key_purpose: KeyPurpose,
    op_params: &[KeyParameter],
    op_outcome: &Outcome,
    key_upgraded: bool,
) -> Keystore2KeyOperationEventReported {
    let mut key_operation_event_atom = create_default_key_operation_atom();

    key_operation_event_atom.security_level = match sec_level {
        SecurityLevel::SOFTWARE => StatsdKeyOperationSecurityLevel::SecurityLevelSoftware,
        SecurityLevel::TRUSTED_ENVIRONMENT => {
            StatsdKeyOperationSecurityLevel::SecurityLevelTrustedEnvironment
        }
        SecurityLevel::STRONGBOX => StatsdKeyOperationSecurityLevel::SecurityLevelStrongbox,
        //KEYSTORE is not a valid variant here
        _ => StatsdKeyOperationSecurityLevel::SecurityLevelUnspecified,
    };

    key_operation_event_atom.key_upgraded = key_upgraded;

    key_operation_event_atom.purpose = match key_purpose {
        KeyPurpose::ENCRYPT => StatsdKeyPurpose::Encrypt,
        KeyPurpose::DECRYPT => StatsdKeyPurpose::Decrypt,
        KeyPurpose::SIGN => StatsdKeyPurpose::Sign,
        KeyPurpose::VERIFY => StatsdKeyPurpose::Verify,
        KeyPurpose::WRAP_KEY => StatsdKeyPurpose::WrapKey,
        KeyPurpose::AGREE_KEY => StatsdKeyPurpose::AgreeKey,
        KeyPurpose::ATTEST_KEY => StatsdKeyPurpose::AttestKey,
        _ => StatsdKeyPurpose::KeyPurposeUnspecified,
    };

    key_operation_event_atom.outcome = match op_outcome {
        Outcome::Unknown | Outcome::Dropped => StatsdOutcome::Dropped,
        Outcome::Success => StatsdOutcome::Success,
        Outcome::Abort => StatsdOutcome::Abort,
        Outcome::Pruned => StatsdOutcome::Pruned,
        Outcome::ErrorCode(e) => {
            key_operation_event_atom.error_code = e.0;
            StatsdOutcome::Error
        }
    };

    for key_param in op_params.iter().map(KsKeyParamValue::from) {
        match key_param {
            KsKeyParamValue::PaddingMode(p) => {
                key_operation_event_atom.padding_mode_bitmap =
                    compute_padding_mode_bitmap(&key_operation_event_atom.padding_mode_bitmap, p);
            }
            KsKeyParamValue::Digest(d) => {
                key_operation_event_atom.digest_bitmap =
                    compute_digest_bitmap(&key_operation_event_atom.digest_bitmap, d);
            }
            KsKeyParamValue::BlockMode(b) => {
                key_operation_event_atom.block_mode_bitmap =
                    compute_block_mode_bitmap(&key_operation_event_atom.block_mode_bitmap, b);
            }
            _ => {}
        }
    }

    key_operation_event_atom
}

fn compute_purpose_bitmap(purpose_bitmap: &i32, purpose: KeyPurpose) -> i32 {
    let mut bitmap = *purpose_bitmap;
    match purpose {
        KeyPurpose::ENCRYPT => {
            bitmap |= 1 << KeyPurposeBitPosition::ENCRYPT_BIT_POS as i32;
        }
        KeyPurpose::DECRYPT => {
            bitmap |= 1 << KeyPurposeBitPosition::DECRYPT_BIT_POS as i32;
        }
        KeyPurpose::SIGN => {
            bitmap |= 1 << KeyPurposeBitPosition::SIGN_BIT_POS as i32;
        }
        KeyPurpose::VERIFY => {
            bitmap |= 1 << KeyPurposeBitPosition::VERIFY_BIT_POS as i32;
        }
        KeyPurpose::WRAP_KEY => {
            bitmap |= 1 << KeyPurposeBitPosition::WRAP_KEY_BIT_POS as i32;
        }
        KeyPurpose::AGREE_KEY => {
            bitmap |= 1 << KeyPurposeBitPosition::AGREE_KEY_BIT_POS as i32;
        }
        KeyPurpose::ATTEST_KEY => {
            bitmap |= 1 << KeyPurposeBitPosition::ATTEST_KEY_BIT_POS as i32;
        }
        _ => {}
    }
    bitmap
}

fn compute_padding_mode_bitmap(padding_mode_bitmap: &i32, padding_mode: PaddingMode) -> i32 {
    let mut bitmap = *padding_mode_bitmap;
    match padding_mode {
        PaddingMode::NONE => {
            bitmap |= 1 << PaddingModeBitPosition::NONE_BIT_POSITION as i32;
        }
        PaddingMode::RSA_OAEP => {
            bitmap |= 1 << PaddingModeBitPosition::RSA_OAEP_BIT_POS as i32;
        }
        PaddingMode::RSA_PSS => {
            bitmap |= 1 << PaddingModeBitPosition::RSA_PSS_BIT_POS as i32;
        }
        PaddingMode::RSA_PKCS1_1_5_ENCRYPT => {
            bitmap |= 1 << PaddingModeBitPosition::RSA_PKCS1_1_5_ENCRYPT_BIT_POS as i32;
        }
        PaddingMode::RSA_PKCS1_1_5_SIGN => {
            bitmap |= 1 << PaddingModeBitPosition::RSA_PKCS1_1_5_SIGN_BIT_POS as i32;
        }
        PaddingMode::PKCS7 => {
            bitmap |= 1 << PaddingModeBitPosition::PKCS7_BIT_POS as i32;
        }
        _ => {}
    }
    bitmap
}

fn compute_digest_bitmap(digest_bitmap: &i32, digest: Digest) -> i32 {
    let mut bitmap = *digest_bitmap;
    match digest {
        Digest::NONE => {
            bitmap |= 1 << DigestBitPosition::NONE_BIT_POSITION as i32;
        }
        Digest::MD5 => {
            bitmap |= 1 << DigestBitPosition::MD5_BIT_POS as i32;
        }
        Digest::SHA1 => {
            bitmap |= 1 << DigestBitPosition::SHA_1_BIT_POS as i32;
        }
        Digest::SHA_2_224 => {
            bitmap |= 1 << DigestBitPosition::SHA_2_224_BIT_POS as i32;
        }
        Digest::SHA_2_256 => {
            bitmap |= 1 << DigestBitPosition::SHA_2_256_BIT_POS as i32;
        }
        Digest::SHA_2_384 => {
            bitmap |= 1 << DigestBitPosition::SHA_2_384_BIT_POS as i32;
        }
        Digest::SHA_2_512 => {
            bitmap |= 1 << DigestBitPosition::SHA_2_512_BIT_POS as i32;
        }
        _ => {}
    }
    bitmap
}

fn compute_block_mode_bitmap(block_mode_bitmap: &i32, block_mode: BlockMode) -> i32 {
    let mut bitmap = *block_mode_bitmap;
    match block_mode {
        BlockMode::ECB => {
            bitmap |= 1 << BlockModeBitPosition::ECB_BIT_POS as i32;
        }
        BlockMode::CBC => {
            bitmap |= 1 << BlockModeBitPosition::CBC_BIT_POS as i32;
        }
        BlockMode::CTR => {
            bitmap |= 1 << BlockModeBitPosition::CTR_BIT_POS as i32;
        }
        BlockMode::GCM => {
            bitmap |= 1 << BlockModeBitPosition::GCM_BIT_POS as i32;
        }
        _ => {}
    }
    bitmap
}
/// Enum defining the bit position for each padding mode. Since padding mode can be repeatable, it
/// is represented using a bitmap.
#[allow(non_camel_case_types)]
#[repr(i32)]
pub enum PaddingModeBitPosition {
    ///Bit position in the PaddingMode bitmap for NONE.
    NONE_BIT_POSITION = 0,
    ///Bit position in the PaddingMode bitmap for RSA_OAEP.
    RSA_OAEP_BIT_POS = 1,
    ///Bit position in the PaddingMode bitmap for RSA_PSS.
    RSA_PSS_BIT_POS = 2,
    ///Bit position in the PaddingMode bitmap for RSA_PKCS1_1_5_ENCRYPT.
    RSA_PKCS1_1_5_ENCRYPT_BIT_POS = 3,
    ///Bit position in the PaddingMode bitmap for RSA_PKCS1_1_5_SIGN.
    RSA_PKCS1_1_5_SIGN_BIT_POS = 4,
    ///Bit position in the PaddingMode bitmap for RSA_PKCS7.
    PKCS7_BIT_POS = 5,
}

/// Enum defining the bit position for each digest type. Since digest can be repeatable in
/// key parameters, it is represented using a bitmap.
#[allow(non_camel_case_types)]
#[repr(i32)]
pub enum DigestBitPosition {
    ///Bit position in the Digest bitmap for NONE.
    NONE_BIT_POSITION = 0,
    ///Bit position in the Digest bitmap for MD5.
    MD5_BIT_POS = 1,
    ///Bit position in the Digest bitmap for SHA1.
    SHA_1_BIT_POS = 2,
    ///Bit position in the Digest bitmap for SHA_2_224.
    SHA_2_224_BIT_POS = 3,
    ///Bit position in the Digest bitmap for SHA_2_256.
    SHA_2_256_BIT_POS = 4,
    ///Bit position in the Digest bitmap for SHA_2_384.
    SHA_2_384_BIT_POS = 5,
    ///Bit position in the Digest bitmap for SHA_2_512.
    SHA_2_512_BIT_POS = 6,
}

/// Enum defining the bit position for each block mode type. Since block mode can be repeatable in
/// key parameters, it is represented using a bitmap.
#[allow(non_camel_case_types)]
#[repr(i32)]
enum BlockModeBitPosition {
    ///Bit position in the BlockMode bitmap for ECB.
    ECB_BIT_POS = 1,
    ///Bit position in the BlockMode bitmap for CBC.
    CBC_BIT_POS = 2,
    ///Bit position in the BlockMode bitmap for CTR.
    CTR_BIT_POS = 3,
    ///Bit position in the BlockMode bitmap for GCM.
    GCM_BIT_POS = 4,
}

/// Enum defining the bit position for each key purpose. Since key purpose can be repeatable in
/// key parameters, it is represented using a bitmap.
#[allow(non_camel_case_types)]
#[repr(i32)]
enum KeyPurposeBitPosition {
    ///Bit position in the KeyPurpose bitmap for Encrypt.
    ENCRYPT_BIT_POS = 1,
    ///Bit position in the KeyPurpose bitmap for Decrypt.
    DECRYPT_BIT_POS = 2,
    ///Bit position in the KeyPurpose bitmap for Sign.
    SIGN_BIT_POS = 3,
    ///Bit position in the KeyPurpose bitmap for Verify.
    VERIFY_BIT_POS = 4,
    ///Bit position in the KeyPurpose bitmap for Wrap Key.
    WRAP_KEY_BIT_POS = 5,
    ///Bit position in the KeyPurpose bitmap for Agree Key.
    AGREE_KEY_BIT_POS = 6,
    ///Bit position in the KeyPurpose bitmap for Attest Key.
    ATTEST_KEY_BIT_POS = 7,
}
