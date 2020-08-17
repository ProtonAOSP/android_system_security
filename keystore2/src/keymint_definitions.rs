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

#![allow(non_camel_case_types)]
#![allow(missing_docs)]

/// This is the current interface for the code to-be-generated from the keymint AIDL.
/// The AIDL spec is at" hardware/interfaces/keymint
#[repr(u32)]
#[derive(PartialEq, Debug)]
pub enum TagType {
    INVALID = 0 << 28,
    ENUM = 1 << 28,
    ENUM_REP = 2 << 28,
    UINT = 3 << 28,
    UINT_REP = 4 << 28,
    ULONG = 5 << 28,
    DATE = 6 << 28,
    BOOL = 7 << 28,
    BIGNUM = 8 << 28,
    BYTES = 9 << 28,
    ULONG_REP = 10 << 28,
}
#[repr(u32)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Tag {
    INVALID = TagType::INVALID as u32,
    PURPOSE = TagType::ENUM_REP as u32 | 1,
    ALGORITHM = TagType::ENUM as u32 | 2,
    KEY_SIZE = TagType::UINT as u32 | 3,
    BLOCK_MODE = TagType::ENUM_REP as u32 | 4,
    DIGEST = TagType::ENUM_REP as u32 | 5,
    PADDING = TagType::ENUM_REP as u32 | 6,
    CALLER_NONCE = TagType::BOOL as u32 | 7,
    MIN_MAC_LENGTH = TagType::UINT as u32 | 8,
    EC_CURVE = TagType::ENUM as u32 | 10,
    RSA_PUBLIC_EXPONENT = TagType::ULONG as u32 | 200,
    INCLUDE_UNIQUE_ID = TagType::BOOL as u32 | 202,
    BLOB_USAGE_REQUIREMENTS = TagType::ENUM as u32 | 301,
    BOOTLOADER_ONLY = TagType::BOOL as u32 | 302,
    ROLLBACK_RESISTANCE = TagType::BOOL as u32 | 303,
    ACTIVE_DATETIME = TagType::DATE as u32 | 400,
    ORIGINATION_EXPIRE_DATETIME = TagType::DATE as u32 | 401,
    USAGE_EXPIRE_DATETIME = TagType::DATE as u32 | 402,
    MIN_SECONDS_BETWEEN_OPS = TagType::UINT as u32 | 403,
    MAX_USES_PER_BOOT = TagType::UINT as u32 | 404,
    USER_ID = TagType::UINT as u32 | 501,
    USER_SECURE_ID = TagType::ULONG_REP as u32 | 502,
    NO_AUTH_REQUIRED = TagType::BOOL as u32 | 503,
    USER_AUTH_TYPE = TagType::ENUM as u32 | 504,
    AUTH_TIMEOUT = TagType::UINT as u32 | 505,
    ALLOW_WHILE_ON_BODY = TagType::BOOL as u32 | 506,
    TRUSTED_USER_PRESENCE_REQUIRED = TagType::BOOL as u32 | 507,
    TRUSTED_CONFIRMATION_REQUIRED = TagType::BOOL as u32 | 508,
    UNLOCKED_DEVICE_REQUIRED = TagType::BOOL as u32 | 509,
    APPLICATION_ID = TagType::BYTES as u32 | 601,
    APPLICATION_DATA = TagType::BYTES as u32 | 700,
    CREATION_DATETIME = TagType::DATE as u32 | 701,
    ORIGIN = TagType::ENUM as u32 | 702,
    ROOT_OF_TRUST = TagType::BYTES as u32 | 704,
    OS_VERSION = TagType::UINT as u32 | 705,
    OS_PATCHLEVEL = TagType::UINT as u32 | 706,
    UNIQUE_ID = TagType::BYTES as u32 | 707,
    ATTESTATION_CHALLENGE = TagType::BYTES as u32 | 708,
    ATTESTATION_APPLICATION_ID = TagType::BYTES as u32 | 709,
    ATTESTATION_ID_BRAND = TagType::BYTES as u32 | 710,
    ATTESTATION_ID_DEVICE = TagType::BYTES as u32 | 711,
    ATTESTATION_ID_PRODUCT = TagType::BYTES as u32 | 712,
    ATTESTATION_ID_SERIAL = TagType::BYTES as u32 | 713,
    ATTESTATION_ID_IMEI = TagType::BYTES as u32 | 714,
    ATTESTATION_ID_MEID = TagType::BYTES as u32 | 715,
    ATTESTATION_ID_MANUFACTURER = TagType::BYTES as u32 | 716,
    ATTESTATION_ID_MODEL = TagType::BYTES as u32 | 717,
    VENDOR_PATCHLEVEL = TagType::UINT as u32 | 718,
    BOOT_PATCHLEVEL = TagType::UINT as u32 | 719,
    ASSOCIATED_DATA = TagType::BYTES as u32 | 1000,
    NONCE = TagType::BYTES as u32 | 1001,
    MAC_LENGTH = TagType::UINT as u32 | 1003,
    RESET_SINCE_ID_ROTATION = TagType::BOOL as u32 | 1004,
    CONFIRMATION_TOKEN = TagType::BYTES as u32 | 1005,
}
#[repr(u32)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Algorithm {
    RSA = 1,
    EC = 3,
    AES = 32,
    TRIPLE_DES = 33,
    HMAC = 128,
}
#[repr(u32)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum BlockMode {
    ECB = 1,
    CBC = 2,
    CTR = 3,
    GCM = 32,
}
#[repr(u32)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum PaddingMode {
    NONE = 1,
    RSA_OAEP = 2,
    RSA_PSS = 3,
    RSA_PKCS1_1_5_ENCRYPT = 4,
    RSA_PKCS1_1_5_SIGN = 5,
    PKCS7 = 64,
}
#[repr(u32)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Digest {
    NONE = 0,
    MD5 = 1,
    SHA1 = 2,
    SHA_2_224 = 3,
    SHA_2_256 = 4,
    SHA_2_384 = 5,
    SHA_2_512 = 6,
}
#[repr(u32)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum EcCurve {
    P_224 = 0,
    P_256 = 1,
    P_384 = 2,
    P_521 = 3,
}
#[repr(u32)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum KeyOrigin {
    GENERATED = 0,
    DERIVED = 1,
    IMPORTED = 2,
    UNKNOWN = 3,
    SECURELY_IMPORTED = 4,
}
#[repr(u32)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum KeyBlobUsageRequirements {
    STANDALONE = 0,
    REQUIRES_FILE_SYSTEM = 1,
}
#[repr(u32)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum KeyPurpose {
    ENCRYPT = 0,
    DECRYPT = 1,
    SIGN = 2,
    VERIFY = 3,
    WRAP_KEY = 5,
}
#[repr(u32)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum HardwareAuthenticatorType {
    NONE = 0,
    PASSWORD = 1,
    FINGERPRINT = 1 << 1,
    ANY = (0xFFFFFFFF as u32) as u32,
}
#[repr(u32)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum SecurityLevel {
    SOFTWARE = 0,
    TRUSTED_ENVIRONMENT = 1,
    STRONGBOX = 2,
}
