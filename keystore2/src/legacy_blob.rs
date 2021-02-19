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

//! This module implements methods to load legacy keystore key blob files.

use crate::{
    error::{Error as KsError, ResponseCode},
    key_parameter::{KeyParameter, KeyParameterValue},
    super_key::SuperKeyManager,
    utils::uid_to_android_user,
};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    SecurityLevel::SecurityLevel, Tag::Tag, TagType::TagType,
};
use anyhow::{Context, Result};
use keystore2_crypto::{aes_gcm_decrypt, derive_key_from_password, ZVec};
use std::{convert::TryInto, fs::File, path::Path, path::PathBuf};
use std::{
    fs,
    io::{ErrorKind, Read, Result as IoResult},
};

const SUPPORTED_LEGACY_BLOB_VERSION: u8 = 3;

mod flags {
    /// This flag is deprecated. It is here to support keys that have been written with this flag
    /// set, but we don't create any new keys with this flag.
    pub const ENCRYPTED: u8 = 1 << 0;
    /// This flag is deprecated. It indicates that the blob was generated and thus owned by a
    /// software fallback Keymaster implementation. Keymaster 1.0 was the last Keymaster version
    /// that could be accompanied by a software fallback. With the removal of Keymaster 1.0
    /// support, this flag is obsolete.
    pub const FALLBACK: u8 = 1 << 1;
    /// KEYSTORE_FLAG_SUPER_ENCRYPTED is for blobs that are already encrypted by KM but have
    /// an additional layer of password-based encryption applied. The same encryption scheme is used
    /// as KEYSTORE_FLAG_ENCRYPTED. The latter is deprecated.
    pub const SUPER_ENCRYPTED: u8 = 1 << 2;
    /// KEYSTORE_FLAG_CRITICAL_TO_DEVICE_ENCRYPTION is for blobs that are part of device encryption
    /// flow so it receives special treatment from keystore. For example this blob will not be super
    /// encrypted, and it will be stored separately under a unique UID instead. This flag should
    /// only be available to system uid.
    pub const CRITICAL_TO_DEVICE_ENCRYPTION: u8 = 1 << 3;
    /// The blob is associated with the security level Strongbox as opposed to TEE.
    pub const STRONGBOX: u8 = 1 << 4;
}

/// Lagacy key blob types.
mod blob_types {
    /// A generic blob used for non sensitive unstructured blobs.
    pub const GENERIC: u8 = 1;
    /// This key is a super encryption key encrypted with AES128
    /// and a password derived key.
    pub const SUPER_KEY: u8 = 2;
    // Used to be the KEY_PAIR type.
    const _RESERVED: u8 = 3;
    /// A KM key blob.
    pub const KM_BLOB: u8 = 4;
    /// A legacy key characteristics file. This has only a single list of Authorizations.
    pub const KEY_CHARACTERISTICS: u8 = 5;
    /// A key characteristics cache has both a hardware enforced and a software enforced list
    /// of authorizations.
    pub const KEY_CHARACTERISTICS_CACHE: u8 = 6;
    /// Like SUPER_KEY but encrypted with AES256.
    pub const SUPER_KEY_AES256: u8 = 7;
}

/// Error codes specific to the legacy blob module.
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum Error {
    /// Returned by the legacy blob module functions if an input stream
    /// did not have enough bytes to read.
    #[error("Input stream had insufficient bytes to read.")]
    BadLen,
    /// This error code is returned by `Blob::decode_alias` if it encounters
    /// an invalid alias filename encoding.
    #[error("Invalid alias filename encoding.")]
    BadEncoding,
}

/// The blob payload, optionally with all information required to decrypt it.
#[derive(Debug, Eq, PartialEq)]
pub enum BlobValue {
    /// A generic blob used for non sensitive unstructured blobs.
    Generic(Vec<u8>),
    /// A legacy key characteristics file. This has only a single list of Authorizations.
    Characteristics(Vec<u8>),
    /// A key characteristics cache has both a hardware enforced and a software enforced list
    /// of authorizations.
    CharacteristicsCache(Vec<u8>),
    /// A password encrypted blob. Includes the initialization vector, the aead tag, the
    /// ciphertext data, a salt, and a key size. The latter two are used for key derivation.
    PwEncrypted {
        /// Initialization vector.
        iv: Vec<u8>,
        /// Aead tag for integrity verification.
        tag: Vec<u8>,
        /// Ciphertext.
        data: Vec<u8>,
        /// Salt for key derivation.
        salt: Vec<u8>,
        /// Key sise for key derivation. This selects between AES128 GCM and AES256 GCM.
        key_size: usize,
    },
    /// An encrypted blob. Includes the initialization vector, the aead tag, and the
    /// ciphertext data. The key can be selected from context, i.e., the owner of the key
    /// blob.
    Encrypted {
        /// Initialization vector.
        iv: Vec<u8>,
        /// Aead tag for integrity verification.
        tag: Vec<u8>,
        /// Ciphertext.
        data: Vec<u8>,
    },
    /// Holds the plaintext key blob either after unwrapping an encrypted blob or when the
    /// blob was stored in "plaintext" on disk. The "plaintext" of a key blob is not actual
    /// plaintext because all KeyMint blobs are encrypted with a device bound key. The key
    /// blob in this Variant is decrypted only with respect to any extra layer of encryption
    /// that Keystore added.
    Decrypted(ZVec),
}

/// Represents a loaded legacy key blob file.
#[derive(Debug, Eq, PartialEq)]
pub struct Blob {
    flags: u8,
    value: BlobValue,
}

/// This object represents a path that holds a legacy Keystore blob database.
pub struct LegacyBlobLoader {
    path: PathBuf,
}

fn read_bool(stream: &mut dyn Read) -> Result<bool> {
    const SIZE: usize = std::mem::size_of::<bool>();
    let mut buffer: [u8; SIZE] = [0; SIZE];
    stream.read_exact(&mut buffer).map(|_| buffer[0] != 0).context("In read_ne_bool.")
}

fn read_ne_u32(stream: &mut dyn Read) -> Result<u32> {
    const SIZE: usize = std::mem::size_of::<u32>();
    let mut buffer: [u8; SIZE] = [0; SIZE];
    stream.read_exact(&mut buffer).map(|_| u32::from_ne_bytes(buffer)).context("In read_ne_u32.")
}

fn read_ne_i32(stream: &mut dyn Read) -> Result<i32> {
    const SIZE: usize = std::mem::size_of::<i32>();
    let mut buffer: [u8; SIZE] = [0; SIZE];
    stream.read_exact(&mut buffer).map(|_| i32::from_ne_bytes(buffer)).context("In read_ne_i32.")
}

fn read_ne_i64(stream: &mut dyn Read) -> Result<i64> {
    const SIZE: usize = std::mem::size_of::<i64>();
    let mut buffer: [u8; SIZE] = [0; SIZE];
    stream.read_exact(&mut buffer).map(|_| i64::from_ne_bytes(buffer)).context("In read_ne_i64.")
}

impl Blob {
    /// This blob was generated with a fallback software KM device.
    pub fn is_fallback(&self) -> bool {
        self.flags & flags::FALLBACK != 0
    }

    /// This blob is encrypted and needs to be decrypted with the user specific master key
    /// before use.
    pub fn is_encrypted(&self) -> bool {
        self.flags & (flags::SUPER_ENCRYPTED | flags::ENCRYPTED) != 0
    }

    /// This blob is critical to device encryption. It cannot be encrypted with the super key
    /// because it is itself part of the key derivation process for the key encrypting the
    /// super key.
    pub fn is_critical_to_device_encryption(&self) -> bool {
        self.flags & flags::CRITICAL_TO_DEVICE_ENCRYPTION != 0
    }

    /// This blob is associated with the Strongbox security level.
    pub fn is_strongbox(&self) -> bool {
        self.flags & flags::STRONGBOX != 0
    }

    /// Returns the payload data of this blob file.
    pub fn value(&self) -> &BlobValue {
        &self.value
    }

    /// Consume this blob structure and extract the payload.
    pub fn take_value(self) -> BlobValue {
        self.value
    }
}

impl LegacyBlobLoader {
    const IV_SIZE: usize = keystore2_crypto::IV_LENGTH;
    const GCM_TAG_LENGTH: usize = keystore2_crypto::TAG_LENGTH;
    const SALT_SIZE: usize = keystore2_crypto::SALT_LENGTH;

    // The common header has the following structure:
    // version (1 Byte)
    // blob_type (1 Byte)
    // flags (1 Byte)
    // info (1 Byte)
    // initialization_vector (16 Bytes)
    // integrity (MD5 digest or gcb tag) (16 Bytes)
    // length (4 Bytes)
    const COMMON_HEADER_SIZE: usize = 4 + Self::IV_SIZE + Self::GCM_TAG_LENGTH + 4;

    const VERSION_OFFSET: usize = 0;
    const TYPE_OFFSET: usize = 1;
    const FLAGS_OFFSET: usize = 2;
    const SALT_SIZE_OFFSET: usize = 3;
    const LENGTH_OFFSET: usize = 4 + Self::IV_SIZE + Self::GCM_TAG_LENGTH;
    const IV_OFFSET: usize = 4;
    const AEAD_TAG_OFFSET: usize = Self::IV_OFFSET + Self::IV_SIZE;
    const DIGEST_OFFSET: usize = Self::IV_OFFSET + Self::IV_SIZE;

    /// Construct a new LegacyBlobLoader with a root path of `path` relative to which it will
    /// expect legacy key blob files.
    pub fn new(path: &Path) -> Self {
        Self { path: path.to_owned() }
    }

    /// Encodes an alias string as ascii character sequence in the range
    /// ['+' .. '.'] and ['0' .. '~'].
    /// Bytes with values in the range ['0' .. '~'] are represented as they are.
    /// All other bytes are split into two characters as follows:
    ///
    ///      msb a a | b b b b b b
    ///
    /// The most significant bits (a) are encoded:
    ///   a a  character
    ///   0 0     '+'
    ///   0 1     ','
    ///   1 0     '-'
    ///   1 1     '.'
    ///
    /// The 6 lower bits are represented with the range ['0' .. 'o']:
    ///   b(hex)  character
    ///   0x00     '0'
    ///       ...
    ///   0x3F     'o'
    ///
    /// The function cannot fail because we have a representation for each
    /// of the 256 possible values of each byte.
    pub fn encode_alias(name: &str) -> String {
        let mut acc = String::new();
        for c in name.bytes() {
            match c {
                b'0'..=b'~' => {
                    acc.push(c as char);
                }
                c => {
                    acc.push((b'+' + (c as u8 >> 6)) as char);
                    acc.push((b'0' + (c & 0x3F)) as char);
                }
            };
        }
        acc
    }

    /// This function reverses the encoding described in `encode_alias`.
    /// This function can fail, because not all possible character
    /// sequences are valid code points. And even if the encoding is valid,
    /// the result may not be a valid UTF-8 sequence.
    pub fn decode_alias(name: &str) -> Result<String> {
        let mut multi: Option<u8> = None;
        let mut s = Vec::<u8>::new();
        for c in name.bytes() {
            multi = match (c, multi) {
                // m is set, we are processing the second part of a multi byte sequence
                (b'0'..=b'o', Some(m)) => {
                    s.push(m | (c - b'0'));
                    None
                }
                (b'+'..=b'.', None) => Some((c - b'+') << 6),
                (b'0'..=b'~', None) => {
                    s.push(c);
                    None
                }
                _ => {
                    return Err(Error::BadEncoding)
                        .context("In decode_alias: could not decode filename.")
                }
            };
        }
        if multi.is_some() {
            return Err(Error::BadEncoding).context("In decode_alias: could not decode filename.");
        }

        String::from_utf8(s).context("In decode_alias: encoded alias was not valid UTF-8.")
    }

    fn new_from_stream(stream: &mut dyn Read) -> Result<Blob> {
        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).context("In new_from_stream.")?;

        if buffer.len() < Self::COMMON_HEADER_SIZE {
            return Err(Error::BadLen).context("In new_from_stream.")?;
        }

        let version: u8 = buffer[Self::VERSION_OFFSET];

        let flags: u8 = buffer[Self::FLAGS_OFFSET];
        let blob_type: u8 = buffer[Self::TYPE_OFFSET];
        let is_encrypted = flags & (flags::ENCRYPTED | flags::SUPER_ENCRYPTED) != 0;
        let salt = match buffer[Self::SALT_SIZE_OFFSET] as usize {
            Self::SALT_SIZE => Some(&buffer[buffer.len() - Self::SALT_SIZE..buffer.len()]),
            _ => None,
        };

        if version != SUPPORTED_LEGACY_BLOB_VERSION {
            return Err(KsError::Rc(ResponseCode::VALUE_CORRUPTED))
                .context(format!("In new_from_stream: Unknown blob version: {}.", version));
        }

        let length = u32::from_be_bytes(
            buffer[Self::LENGTH_OFFSET..Self::LENGTH_OFFSET + 4].try_into().unwrap(),
        ) as usize;
        if buffer.len() < Self::COMMON_HEADER_SIZE + length {
            return Err(Error::BadLen).context(format!(
                "In new_from_stream. Expected: {} got: {}.",
                Self::COMMON_HEADER_SIZE + length,
                buffer.len()
            ));
        }
        let value = &buffer[Self::COMMON_HEADER_SIZE..Self::COMMON_HEADER_SIZE + length];
        let iv = &buffer[Self::IV_OFFSET..Self::IV_OFFSET + Self::IV_SIZE];
        let tag = &buffer[Self::AEAD_TAG_OFFSET..Self::AEAD_TAG_OFFSET + Self::GCM_TAG_LENGTH];

        match (blob_type, is_encrypted, salt) {
            (blob_types::GENERIC, _, _) => {
                Ok(Blob { flags, value: BlobValue::Generic(value.to_vec()) })
            }
            (blob_types::KEY_CHARACTERISTICS, _, _) => {
                Ok(Blob { flags, value: BlobValue::Characteristics(value.to_vec()) })
            }
            (blob_types::KEY_CHARACTERISTICS_CACHE, _, _) => {
                Ok(Blob { flags, value: BlobValue::CharacteristicsCache(value.to_vec()) })
            }
            (blob_types::SUPER_KEY, _, Some(salt)) => Ok(Blob {
                flags,
                value: BlobValue::PwEncrypted {
                    iv: iv.to_vec(),
                    tag: tag.to_vec(),
                    data: value.to_vec(),
                    key_size: keystore2_crypto::AES_128_KEY_LENGTH,
                    salt: salt.to_vec(),
                },
            }),
            (blob_types::SUPER_KEY_AES256, _, Some(salt)) => Ok(Blob {
                flags,
                value: BlobValue::PwEncrypted {
                    iv: iv.to_vec(),
                    tag: tag.to_vec(),
                    data: value.to_vec(),
                    key_size: keystore2_crypto::AES_256_KEY_LENGTH,
                    salt: salt.to_vec(),
                },
            }),
            (blob_types::KM_BLOB, true, _) => Ok(Blob {
                flags,
                value: BlobValue::Encrypted {
                    iv: iv.to_vec(),
                    tag: tag.to_vec(),
                    data: value.to_vec(),
                },
            }),
            (blob_types::KM_BLOB, false, _) => Ok(Blob {
                flags,
                value: BlobValue::Decrypted(value.try_into().context("In new_from_stream.")?),
            }),
            (blob_types::SUPER_KEY, _, None) | (blob_types::SUPER_KEY_AES256, _, None) => {
                Err(KsError::Rc(ResponseCode::VALUE_CORRUPTED))
                    .context("In new_from_stream: Super key without salt for key derivation.")
            }
            _ => Err(KsError::Rc(ResponseCode::VALUE_CORRUPTED)).context(format!(
                "In new_from_stream: Unknown blob type. {} {}",
                blob_type, is_encrypted
            )),
        }
    }

    /// Parses a legacy key blob file read from `stream`. A `decrypt` closure
    /// must be supplied, that is primed with the appropriate key.
    /// The callback takes the following arguments:
    ///  * ciphertext: &[u8] - The to-be-deciphered message.
    ///  * iv: &[u8] - The initialization vector.
    ///  * tag: Option<&[u8]> - AEAD tag if AES GCM is selected.
    ///  * salt: Option<&[u8]> - An optional salt. Used for password key derivation.
    ///  * key_size: Option<usize> - An optional key size. Used for pw key derivation.
    ///
    /// If no super key is available, the callback must return
    /// `Err(KsError::Rc(ResponseCode::LOCKED))`. The callback is only called
    /// if the to-be-read blob is encrypted.
    pub fn new_from_stream_decrypt_with<F>(mut stream: impl Read, decrypt: F) -> Result<Blob>
    where
        F: FnOnce(&[u8], &[u8], &[u8], Option<&[u8]>, Option<usize>) -> Result<ZVec>,
    {
        let blob =
            Self::new_from_stream(&mut stream).context("In new_from_stream_decrypt_with.")?;

        match blob.value() {
            BlobValue::Encrypted { iv, tag, data } => Ok(Blob {
                flags: blob.flags,
                value: BlobValue::Decrypted(
                    decrypt(&data, &iv, &tag, None, None)
                        .context("In new_from_stream_decrypt_with.")?,
                ),
            }),
            BlobValue::PwEncrypted { iv, tag, data, salt, key_size } => Ok(Blob {
                flags: blob.flags,
                value: BlobValue::Decrypted(
                    decrypt(&data, &iv, &tag, Some(salt), Some(*key_size))
                        .context("In new_from_stream_decrypt_with.")?,
                ),
            }),
            _ => Ok(blob),
        }
    }

    fn tag_type(tag: Tag) -> TagType {
        TagType((tag.0 as u32 & 0xFF000000u32) as i32)
    }

    /// Read legacy key parameter file content.
    /// Depending on the file type a key characteristics file stores one (TYPE_KEY_CHARACTERISTICS)
    /// or two (TYPE_KEY_CHARACTERISTICS_CACHE) key parameter lists. The format of the list is as
    /// follows:
    ///
    /// +------------------------------+
    /// | 32 bit indirect_size         |
    /// +------------------------------+
    /// | indirect_size bytes of data  |     This is where the blob data is stored
    /// +------------------------------+
    /// | 32 bit element_count         |     Number of key parameter entries.
    /// | 32 bit elements_size         |     Total bytes used by entries.
    /// +------------------------------+
    /// | elements_size bytes of data  |     This is where the elements are stored.
    /// +------------------------------+
    ///
    /// Elements have a 32 bit header holding the tag with a tag type encoded in the
    /// four most significant bits (see android/hardware/secruity/keymint/TagType.aidl).
    /// The header is immediately followed by the payload. The payload size depends on
    /// the encoded tag type in the header:
    ///      BOOLEAN                          :    1 byte
    ///      ENUM, ENUM_REP, UINT, UINT_REP   :    4 bytes
    ///      ULONG, ULONG_REP, DATETIME       :    8 bytes
    ///      BLOB, BIGNUM                     :    8 bytes see below.
    ///
    /// Bignum and blob payload format:
    /// +------------------------+
    /// | 32 bit blob_length     |    Length of the indirect payload in bytes.
    /// | 32 bit indirect_offset |    Offset from the beginning of the indirect section.
    /// +------------------------+
    pub fn read_key_parameters(stream: &mut &[u8]) -> Result<Vec<KeyParameterValue>> {
        let indirect_size =
            read_ne_u32(stream).context("In read_key_parameters: While reading indirect size.")?;

        let indirect_buffer = stream
            .get(0..indirect_size as usize)
            .ok_or(KsError::Rc(ResponseCode::VALUE_CORRUPTED))
            .context("In read_key_parameters: While reading indirect buffer.")?;

        // update the stream position.
        *stream = &stream[indirect_size as usize..];

        let element_count =
            read_ne_u32(stream).context("In read_key_parameters: While reading element count.")?;
        let element_size =
            read_ne_u32(stream).context("In read_key_parameters: While reading element size.")?;

        let elements_buffer = stream
            .get(0..element_size as usize)
            .ok_or(KsError::Rc(ResponseCode::VALUE_CORRUPTED))
            .context("In read_key_parameters: While reading elements buffer.")?;

        // update the stream position.
        *stream = &stream[element_size as usize..];

        let mut element_stream = &elements_buffer[..];

        let mut params: Vec<KeyParameterValue> = Vec::new();
        for _ in 0..element_count {
            let tag = Tag(read_ne_i32(&mut element_stream).context("In read_key_parameters.")?);
            let param = match Self::tag_type(tag) {
                TagType::ENUM | TagType::ENUM_REP | TagType::UINT | TagType::UINT_REP => {
                    KeyParameterValue::new_from_tag_primitive_pair(
                        tag,
                        read_ne_i32(&mut element_stream).context("While reading integer.")?,
                    )
                    .context("Trying to construct integer/enum KeyParameterValue.")
                }
                TagType::ULONG | TagType::ULONG_REP | TagType::DATE => {
                    KeyParameterValue::new_from_tag_primitive_pair(
                        tag,
                        read_ne_i64(&mut element_stream).context("While reading long integer.")?,
                    )
                    .context("Trying to construct long KeyParameterValue.")
                }
                TagType::BOOL => {
                    if read_bool(&mut element_stream).context("While reading long integer.")? {
                        KeyParameterValue::new_from_tag_primitive_pair(tag, 1)
                            .context("Trying to construct boolean KeyParameterValue.")
                    } else {
                        Err(anyhow::anyhow!("Invalid."))
                    }
                }
                TagType::BYTES | TagType::BIGNUM => {
                    let blob_size = read_ne_u32(&mut element_stream)
                        .context("While reading blob size.")?
                        as usize;
                    let indirect_offset = read_ne_u32(&mut element_stream)
                        .context("While reading indirect offset.")?
                        as usize;
                    KeyParameterValue::new_from_tag_primitive_pair(
                        tag,
                        indirect_buffer
                            .get(indirect_offset..indirect_offset + blob_size)
                            .context("While reading blob value.")?
                            .to_vec(),
                    )
                    .context("Trying to construct blob KeyParameterValue.")
                }
                TagType::INVALID => Err(anyhow::anyhow!("Invalid.")),
                _ => {
                    return Err(KsError::Rc(ResponseCode::VALUE_CORRUPTED))
                        .context("In read_key_parameters: Encountered bogus tag type.");
                }
            };
            if let Ok(p) = param {
                params.push(p);
            }
        }

        Ok(params)
    }

    fn read_characteristics_file(
        &self,
        uid: u32,
        prefix: &str,
        alias: &str,
        hw_sec_level: SecurityLevel,
    ) -> Result<Vec<KeyParameter>> {
        let blob = Self::read_generic_blob(&self.make_chr_filename(uid, alias, prefix))
            .context("In read_characteristics_file")?;

        let blob = match blob {
            None => return Ok(Vec::new()),
            Some(blob) => blob,
        };

        let mut stream = match blob.value() {
            BlobValue::Characteristics(data) => &data[..],
            BlobValue::CharacteristicsCache(data) => &data[..],
            _ => {
                return Err(KsError::Rc(ResponseCode::VALUE_CORRUPTED)).context(concat!(
                    "In read_characteristics_file: ",
                    "Characteristics file does not hold key characteristics."
                ))
            }
        };

        let hw_list = match blob.value() {
            // The characteristics cache file has two lists and the first is
            // the hardware enforced list.
            BlobValue::CharacteristicsCache(_) => Some(
                Self::read_key_parameters(&mut stream)
                    .context("In read_characteristics_file.")?
                    .into_iter()
                    .map(|value| KeyParameter::new(value, hw_sec_level)),
            ),
            _ => None,
        };

        let sw_list = Self::read_key_parameters(&mut stream)
            .context("In read_characteristics_file.")?
            .into_iter()
            .map(|value| KeyParameter::new(value, SecurityLevel::KEYSTORE));

        Ok(hw_list.into_iter().flatten().chain(sw_list).collect())
    }

    // This is a list of known prefixes that the Keystore 1.0 SPI used to use.
    //  * USRPKEY was used for private and secret key material, i.e., KM blobs.
    //  * USRSKEY was used for secret key material, i.e., KM blobs, before Android P.
    //  * CACERT  was used for key chains or free standing public certificates.
    //  * USRCERT was used for public certificates of USRPKEY entries. But KeyChain also
    //            used this for user installed certificates without private key material.

    fn read_km_blob_file(&self, uid: u32, alias: &str) -> Result<Option<(Blob, String)>> {
        let mut iter = ["USRPKEY", "USRSKEY"].iter();

        let (blob, prefix) = loop {
            if let Some(prefix) = iter.next() {
                if let Some(blob) =
                    Self::read_generic_blob(&self.make_blob_filename(uid, alias, prefix))
                        .context("In read_km_blob_file.")?
                {
                    break (blob, prefix);
                }
            } else {
                return Ok(None);
            }
        };

        Ok(Some((blob, prefix.to_string())))
    }

    fn read_generic_blob(path: &Path) -> Result<Option<Blob>> {
        let mut file = match Self::with_retry_interrupted(|| File::open(path)) {
            Ok(file) => file,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => return Ok(None),
                _ => return Err(e).context("In read_generic_blob."),
            },
        };

        Ok(Some(Self::new_from_stream(&mut file).context("In read_generic_blob.")?))
    }

    /// This function constructs the blob file name which has the form:
    /// user_<android user id>/<uid>_<alias>.
    fn make_blob_filename(&self, uid: u32, alias: &str, prefix: &str) -> PathBuf {
        let user_id = uid_to_android_user(uid);
        let encoded_alias = Self::encode_alias(&format!("{}_{}", prefix, alias));
        let mut path = self.make_user_path_name(user_id);
        path.push(format!("{}_{}", uid, encoded_alias));
        path
    }

    /// This function constructs the characteristics file name which has the form:
    /// user_<android user id>/.<uid>_chr_<prefix>_<alias>.
    fn make_chr_filename(&self, uid: u32, alias: &str, prefix: &str) -> PathBuf {
        let user_id = uid_to_android_user(uid);
        let encoded_alias = Self::encode_alias(&format!("{}_{}", prefix, alias));
        let mut path = self.make_user_path_name(user_id);
        path.push(format!(".{}_chr_{}", uid, encoded_alias));
        path
    }

    fn make_super_key_filename(&self, user_id: u32) -> PathBuf {
        let mut path = self.make_user_path_name(user_id);
        path.push(".masterkey");
        path
    }

    fn make_user_path_name(&self, user_id: u32) -> PathBuf {
        let mut path = self.path.clone();
        path.push(&format!("user_{}", user_id));
        path
    }

    /// Returns if the legacy blob database is empty, i.e., there are no entries matching "user_*"
    /// in the database dir.
    pub fn is_empty(&self) -> Result<bool> {
        let dir = Self::with_retry_interrupted(|| fs::read_dir(self.path.as_path()))
            .context("In is_empty: Failed to open legacy blob database.")?;
        for entry in dir {
            if (*entry.context("In is_empty: Trying to access dir entry")?.file_name())
                .to_str()
                .map_or(false, |f| f.starts_with("user_"))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Returns if the legacy blob database is empty for a given user, i.e., there are no entries
    /// matching "user_*" in the database dir.
    pub fn is_empty_user(&self, user_id: u32) -> Result<bool> {
        let mut user_path = self.path.clone();
        user_path.push(format!("user_{}", user_id));
        if !user_path.as_path().is_dir() {
            return Ok(true);
        }
        Ok(Self::with_retry_interrupted(|| user_path.read_dir())
            .context("In is_empty_user: Failed to open legacy user dir.")?
            .next()
            .is_none())
    }

    fn extract_alias(encoded_alias: &str) -> Option<String> {
        // We can check the encoded alias because the prefixes we are interested
        // in are all in the printable range that don't get mangled.
        for prefix in &["USRPKEY_", "USRSKEY_", "USRCERT_", "CACERT_"] {
            if let Some(alias) = encoded_alias.strip_prefix(prefix) {
                return Self::decode_alias(&alias).ok();
            }
        }
        None
    }

    /// List all entries for a given user. The strings are unchanged file names, i.e.,
    /// encoded with UID prefix.
    fn list_user(&self, user_id: u32) -> Result<Vec<String>> {
        let path = self.make_user_path_name(user_id);
        let dir =
            Self::with_retry_interrupted(|| fs::read_dir(path.as_path())).with_context(|| {
                format!("In list_user: Failed to open legacy blob database. {:?}", path)
            })?;
        let mut result: Vec<String> = Vec::new();
        for entry in dir {
            let file_name = entry.context("In list_user: Trying to access dir entry")?.file_name();
            if let Some(f) = file_name.to_str() {
                result.push(f.to_string())
            }
        }
        Ok(result)
    }

    /// List all keystore entries belonging to the given uid.
    pub fn list_keystore_entries_for_uid(&self, uid: u32) -> Result<Vec<String>> {
        let user_id = uid_to_android_user(uid);

        let user_entries = self
            .list_user(user_id)
            .context("In list_keystore_entries_for_uid: Trying to list user.")?;

        let uid_str = format!("{}_", uid);

        let mut result: Vec<String> = user_entries
            .into_iter()
            .filter_map(|v| {
                if !v.starts_with(&uid_str) {
                    return None;
                }
                let encoded_alias = &v[uid_str.len()..];
                Self::extract_alias(encoded_alias)
            })
            .collect();

        result.sort_unstable();
        result.dedup();
        Ok(result)
    }

    fn with_retry_interrupted<F, T>(f: F) -> IoResult<T>
    where
        F: Fn() -> IoResult<T>,
    {
        loop {
            match f() {
                Ok(v) => return Ok(v),
                Err(e) => match e.kind() {
                    ErrorKind::Interrupted => continue,
                    _ => return Err(e),
                },
            }
        }
    }

    /// Deletes a keystore entry. Also removes the user_<uid> directory on the
    /// last migration.
    pub fn remove_keystore_entry(&self, uid: u32, alias: &str) -> Result<bool> {
        let mut something_was_deleted = false;
        let prefixes = ["USRPKEY", "USRSKEY"];
        for prefix in &prefixes {
            let path = self.make_blob_filename(uid, alias, prefix);
            if let Err(e) = Self::with_retry_interrupted(|| fs::remove_file(path.as_path())) {
                match e.kind() {
                    // Only a subset of keys are expected.
                    ErrorKind::NotFound => continue,
                    // Log error but ignore.
                    _ => log::error!("Error while deleting key blob entries. {:?}", e),
                }
            }
            let path = self.make_chr_filename(uid, alias, prefix);
            if let Err(e) = Self::with_retry_interrupted(|| fs::remove_file(path.as_path())) {
                match e.kind() {
                    ErrorKind::NotFound => {
                        log::info!("No characteristics file found for legacy key blob.")
                    }
                    // Log error but ignore.
                    _ => log::error!("Error while deleting key blob entries. {:?}", e),
                }
            }
            something_was_deleted = true;
            // Only one of USRPKEY and USRSKEY can be present. So we can end the loop
            // if we reach this point.
            break;
        }

        let prefixes = ["USRCERT", "CACERT"];
        for prefix in &prefixes {
            let path = self.make_blob_filename(uid, alias, prefix);
            if let Err(e) = Self::with_retry_interrupted(|| fs::remove_file(path.as_path())) {
                match e.kind() {
                    // USRCERT and CACERT are optional either or both may or may not be present.
                    ErrorKind::NotFound => continue,
                    // Log error but ignore.
                    _ => log::error!("Error while deleting key blob entries. {:?}", e),
                }
                something_was_deleted = true;
            }
        }

        if something_was_deleted {
            let user_id = uid_to_android_user(uid);
            if self
                .is_empty_user(user_id)
                .context("In remove_keystore_entry: Trying to check for empty user dir.")?
            {
                let user_path = self.make_user_path_name(user_id);
                Self::with_retry_interrupted(|| fs::remove_dir(user_path.as_path())).ok();
            }
        }

        Ok(something_was_deleted)
    }

    /// Load a legacy key blob entry by uid and alias.
    pub fn load_by_uid_alias(
        &self,
        uid: u32,
        alias: &str,
        key_manager: Option<&SuperKeyManager>,
    ) -> Result<(Option<(Blob, Vec<KeyParameter>)>, Option<Vec<u8>>, Option<Vec<u8>>)> {
        let km_blob = self.read_km_blob_file(uid, alias).context("In load_by_uid_alias.")?;

        let km_blob = match km_blob {
            Some((km_blob, prefix)) => {
                let km_blob = match km_blob {
                    Blob { flags: _, value: BlobValue::Decrypted(_) } => km_blob,
                    // Unwrap the key blob if required and if we have key_manager.
                    Blob { flags, value: BlobValue::Encrypted { ref iv, ref tag, ref data } } => {
                        if let Some(key_manager) = key_manager {
                            let decrypted = match key_manager
                                .get_per_boot_key_by_user_id(uid_to_android_user(uid))
                            {
                                Some(key) => aes_gcm_decrypt(data, iv, tag, &(key.get_key()))
                                    .context(
                                    "In load_by_uid_alias: while trying to decrypt legacy blob.",
                                )?,
                                None => {
                                    return Err(KsError::Rc(ResponseCode::LOCKED)).context(format!(
                                        concat!(
                                            "In load_by_uid_alias: ",
                                            "User {} has not unlocked the keystore yet.",
                                        ),
                                        uid_to_android_user(uid)
                                    ))
                                }
                            };
                            Blob { flags, value: BlobValue::Decrypted(decrypted) }
                        } else {
                            km_blob
                        }
                    }
                    _ => {
                        return Err(KsError::Rc(ResponseCode::VALUE_CORRUPTED)).context(
                            "In load_by_uid_alias: Found wrong blob type in legacy key blob file.",
                        )
                    }
                };

                let hw_sec_level = match km_blob.is_strongbox() {
                    true => SecurityLevel::STRONGBOX,
                    false => SecurityLevel::TRUSTED_ENVIRONMENT,
                };
                let key_parameters = self
                    .read_characteristics_file(uid, &prefix, alias, hw_sec_level)
                    .context("In load_by_uid_alias.")?;
                Some((km_blob, key_parameters))
            }
            None => None,
        };

        let user_cert =
            match Self::read_generic_blob(&self.make_blob_filename(uid, alias, "USRCERT"))
                .context("In load_by_uid_alias: While loading user cert.")?
            {
                Some(Blob { value: BlobValue::Generic(data), .. }) => Some(data),
                None => None,
                _ => {
                    return Err(KsError::Rc(ResponseCode::VALUE_CORRUPTED)).context(
                        "In load_by_uid_alias: Found unexpected blob type in USRCERT file",
                    )
                }
            };

        let ca_cert = match Self::read_generic_blob(&self.make_blob_filename(uid, alias, "CACERT"))
            .context("In load_by_uid_alias: While loading ca cert.")?
        {
            Some(Blob { value: BlobValue::Generic(data), .. }) => Some(data),
            None => None,
            _ => {
                return Err(KsError::Rc(ResponseCode::VALUE_CORRUPTED))
                    .context("In load_by_uid_alias: Found unexpected blob type in CACERT file")
            }
        };

        Ok((km_blob, user_cert, ca_cert))
    }

    /// Returns true if the given user has a super key.
    pub fn has_super_key(&self, user_id: u32) -> bool {
        self.make_super_key_filename(user_id).is_file()
    }

    /// Load and decrypt legacy super key blob.
    pub fn load_super_key(&self, user_id: u32, pw: &[u8]) -> Result<Option<ZVec>> {
        let path = self.make_super_key_filename(user_id);
        let blob = Self::read_generic_blob(&path)
            .context("In load_super_key: While loading super key.")?;

        let blob = match blob {
            Some(blob) => match blob {
                Blob {
                    value: BlobValue::PwEncrypted { iv, tag, data, salt, key_size }, ..
                } => {
                    let key = derive_key_from_password(pw, Some(&salt), key_size)
                        .context("In load_super_key: Failed to derive key from password.")?;
                    let blob = aes_gcm_decrypt(&data, &iv, &tag, &key).context(
                        "In load_super_key: while trying to decrypt legacy super key blob.",
                    )?;
                    Some(blob)
                }
                _ => {
                    return Err(KsError::Rc(ResponseCode::VALUE_CORRUPTED)).context(
                        "In load_super_key: Found wrong blob type in legacy super key blob file.",
                    )
                }
            },
            None => None,
        };

        Ok(blob)
    }

    /// Removes the super key for the given user from the legacy database.
    /// If this was the last entry in the user's database, this function removes
    /// the user_<uid> directory as well.
    pub fn remove_super_key(&self, user_id: u32) {
        let path = self.make_super_key_filename(user_id);
        Self::with_retry_interrupted(|| fs::remove_file(path.as_path())).ok();
        if self.is_empty_user(user_id).ok().unwrap_or(false) {
            let path = self.make_user_path_name(user_id);
            Self::with_retry_interrupted(|| fs::remove_dir(path.as_path())).ok();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::anyhow;
    use keystore2_crypto::aes_gcm_decrypt;
    use rand::Rng;
    use std::string::FromUtf8Error;
    mod legacy_blob_test_vectors;
    use crate::error;
    use crate::legacy_blob::test::legacy_blob_test_vectors::*;
    use keystore2_test_utils::TempDir;

    #[test]
    fn decode_encode_alias_test() {
        static ALIAS: &str = "#({}test[])😗";
        static ENCODED_ALIAS: &str = "+S+X{}test[]+Y.`-O-H-G";
        // Second multi byte out of range ------v
        static ENCODED_ALIAS_ERROR1: &str = "+S+{}test[]+Y";
        // Incomplete multi byte ------------------------v
        static ENCODED_ALIAS_ERROR2: &str = "+S+X{}test[]+";
        // Our encoding: ".`-O-H-G"
        // is UTF-8: 0xF0 0x9F 0x98 0x97
        // is UNICODE: U+1F617
        // is 😗
        // But +H below is a valid encoding for 0x18 making this sequence invalid UTF-8.
        static ENCODED_ALIAS_ERROR_UTF8: &str = ".`-O+H-G";

        assert_eq!(ENCODED_ALIAS, &LegacyBlobLoader::encode_alias(ALIAS));
        assert_eq!(ALIAS, &LegacyBlobLoader::decode_alias(ENCODED_ALIAS).unwrap());
        assert_eq!(
            Some(&Error::BadEncoding),
            LegacyBlobLoader::decode_alias(ENCODED_ALIAS_ERROR1)
                .unwrap_err()
                .root_cause()
                .downcast_ref::<Error>()
        );
        assert_eq!(
            Some(&Error::BadEncoding),
            LegacyBlobLoader::decode_alias(ENCODED_ALIAS_ERROR2)
                .unwrap_err()
                .root_cause()
                .downcast_ref::<Error>()
        );
        assert!(LegacyBlobLoader::decode_alias(ENCODED_ALIAS_ERROR_UTF8)
            .unwrap_err()
            .root_cause()
            .downcast_ref::<FromUtf8Error>()
            .is_some());

        for _i in 0..100 {
            // Any valid UTF-8 string should be en- and decoded without loss.
            let alias_str = rand::thread_rng().gen::<[char; 20]>().iter().collect::<String>();
            let random_alias = alias_str.as_bytes();
            let encoded = LegacyBlobLoader::encode_alias(&alias_str);
            let decoded = match LegacyBlobLoader::decode_alias(&encoded) {
                Ok(d) => d,
                Err(_) => panic!(format!("random_alias: {:x?}\nencoded {}", random_alias, encoded)),
            };
            assert_eq!(random_alias.to_vec(), decoded.bytes().collect::<Vec<u8>>());
        }
    }

    #[test]
    fn read_golden_key_blob_test() -> anyhow::Result<()> {
        let blob = LegacyBlobLoader::new_from_stream_decrypt_with(&mut &*BLOB, |_, _, _, _, _| {
            Err(anyhow!("should not be called"))
        })?;
        assert!(!blob.is_encrypted());
        assert!(!blob.is_fallback());
        assert!(!blob.is_strongbox());
        assert!(!blob.is_critical_to_device_encryption());
        assert_eq!(blob.value(), &BlobValue::Generic([0xde, 0xed, 0xbe, 0xef].to_vec()));

        let blob = LegacyBlobLoader::new_from_stream_decrypt_with(
            &mut &*REAL_LEGACY_BLOB,
            |_, _, _, _, _| Err(anyhow!("should not be called")),
        )?;
        assert!(!blob.is_encrypted());
        assert!(!blob.is_fallback());
        assert!(!blob.is_strongbox());
        assert!(!blob.is_critical_to_device_encryption());
        assert_eq!(
            blob.value(),
            &BlobValue::Decrypted(REAL_LEGACY_BLOB_PAYLOAD.try_into().unwrap())
        );
        Ok(())
    }

    #[test]
    fn read_aes_gcm_encrypted_key_blob_test() {
        let blob = LegacyBlobLoader::new_from_stream_decrypt_with(
            &mut &*AES_GCM_ENCRYPTED_BLOB,
            |d, iv, tag, salt, key_size| {
                assert_eq!(salt, None);
                assert_eq!(key_size, None);
                assert_eq!(
                    iv,
                    &[
                        0xbd, 0xdb, 0x8d, 0x69, 0x72, 0x56, 0xf0, 0xf5, 0xa4, 0x02, 0x88, 0x7f,
                        0x00, 0x00, 0x00, 0x00,
                    ]
                );
                assert_eq!(
                    tag,
                    &[
                        0x50, 0xd9, 0x97, 0x95, 0x37, 0x6e, 0x28, 0x6a, 0x28, 0x9d, 0x51, 0xb9,
                        0xb9, 0xe0, 0x0b, 0xc3
                    ][..]
                );
                aes_gcm_decrypt(d, iv, tag, AES_KEY).context("Trying to decrypt blob.")
            },
        )
        .unwrap();
        assert!(blob.is_encrypted());
        assert!(!blob.is_fallback());
        assert!(!blob.is_strongbox());
        assert!(!blob.is_critical_to_device_encryption());

        assert_eq!(blob.value(), &BlobValue::Decrypted(DECRYPTED_PAYLOAD.try_into().unwrap()));
    }

    #[test]
    fn read_golden_key_blob_too_short_test() {
        let error =
            LegacyBlobLoader::new_from_stream_decrypt_with(&mut &BLOB[0..15], |_, _, _, _, _| {
                Err(anyhow!("should not be called"))
            })
            .unwrap_err();
        assert_eq!(Some(&Error::BadLen), error.root_cause().downcast_ref::<Error>());
    }

    #[test]
    fn test_is_empty() {
        let temp_dir = TempDir::new("test_is_empty").expect("Failed to create temp dir.");
        let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());

        assert!(legacy_blob_loader.is_empty().expect("Should succeed and be empty."));

        let _db = crate::database::KeystoreDB::new(temp_dir.path(), None)
            .expect("Failed to open database.");

        assert!(legacy_blob_loader.is_empty().expect("Should succeed and still be empty."));

        std::fs::create_dir(&*temp_dir.build().push("user_0")).expect("Failed to create user_0.");

        assert!(!legacy_blob_loader.is_empty().expect("Should succeed but not be empty."));

        std::fs::create_dir(&*temp_dir.build().push("user_10")).expect("Failed to create user_10.");

        assert!(!legacy_blob_loader.is_empty().expect("Should succeed but still not be empty."));

        std::fs::remove_dir_all(&*temp_dir.build().push("user_0"))
            .expect("Failed to remove user_0.");

        assert!(!legacy_blob_loader.is_empty().expect("Should succeed but still not be empty."));

        std::fs::remove_dir_all(&*temp_dir.build().push("user_10"))
            .expect("Failed to remove user_10.");

        assert!(legacy_blob_loader.is_empty().expect("Should succeed and be empty again."));
    }

    #[test]
    fn test_legacy_blobs() -> anyhow::Result<()> {
        let temp_dir = TempDir::new("legacy_blob_test")?;
        std::fs::create_dir(&*temp_dir.build().push("user_0"))?;

        std::fs::write(&*temp_dir.build().push("user_0").push(".masterkey"), SUPERKEY)?;

        std::fs::write(
            &*temp_dir.build().push("user_0").push("10223_USRPKEY_authbound"),
            USRPKEY_AUTHBOUND,
        )?;
        std::fs::write(
            &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_authbound"),
            USRPKEY_AUTHBOUND_CHR,
        )?;
        std::fs::write(
            &*temp_dir.build().push("user_0").push("10223_USRCERT_authbound"),
            USRCERT_AUTHBOUND,
        )?;
        std::fs::write(
            &*temp_dir.build().push("user_0").push("10223_CACERT_authbound"),
            CACERT_AUTHBOUND,
        )?;

        std::fs::write(
            &*temp_dir.build().push("user_0").push("10223_USRPKEY_non_authbound"),
            USRPKEY_NON_AUTHBOUND,
        )?;
        std::fs::write(
            &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_non_authbound"),
            USRPKEY_NON_AUTHBOUND_CHR,
        )?;
        std::fs::write(
            &*temp_dir.build().push("user_0").push("10223_USRCERT_non_authbound"),
            USRCERT_NON_AUTHBOUND,
        )?;
        std::fs::write(
            &*temp_dir.build().push("user_0").push("10223_CACERT_non_authbound"),
            CACERT_NON_AUTHBOUND,
        )?;

        let key_manager = crate::super_key::SuperKeyManager::new();
        let mut db = crate::database::KeystoreDB::new(temp_dir.path(), None)?;
        let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());

        assert_eq!(
            legacy_blob_loader
                .load_by_uid_alias(10223, "authbound", Some(&key_manager))
                .unwrap_err()
                .root_cause()
                .downcast_ref::<error::Error>(),
            Some(&error::Error::Rc(ResponseCode::LOCKED))
        );

        key_manager.unlock_user_key(&mut db, 0, PASSWORD, &legacy_blob_loader)?;

        if let (Some((Blob { flags, value: _ }, _params)), Some(cert), Some(chain)) =
            legacy_blob_loader.load_by_uid_alias(10223, "authbound", Some(&key_manager))?
        {
            assert_eq!(flags, 4);
            //assert_eq!(value, BlobValue::Encrypted(..));
            assert_eq!(&cert[..], LOADED_CERT_AUTHBOUND);
            assert_eq!(&chain[..], LOADED_CACERT_AUTHBOUND);
        } else {
            panic!("");
        }
        if let (Some((Blob { flags, value }, _params)), Some(cert), Some(chain)) =
            legacy_blob_loader.load_by_uid_alias(10223, "non_authbound", Some(&key_manager))?
        {
            assert_eq!(flags, 0);
            assert_eq!(value, BlobValue::Decrypted(LOADED_USRPKEY_NON_AUTHBOUND.try_into()?));
            assert_eq!(&cert[..], LOADED_CERT_NON_AUTHBOUND);
            assert_eq!(&chain[..], LOADED_CACERT_NON_AUTHBOUND);
        } else {
            panic!("");
        }

        legacy_blob_loader.remove_keystore_entry(10223, "authbound").expect("This should succeed.");
        legacy_blob_loader
            .remove_keystore_entry(10223, "non_authbound")
            .expect("This should succeed.");

        assert_eq!(
            (None, None, None),
            legacy_blob_loader.load_by_uid_alias(10223, "authbound", Some(&key_manager))?
        );
        assert_eq!(
            (None, None, None),
            legacy_blob_loader.load_by_uid_alias(10223, "non_authbound", Some(&key_manager))?
        );

        // The database should not be empty due to the super key.
        assert!(!legacy_blob_loader.is_empty()?);
        assert!(!legacy_blob_loader.is_empty_user(0)?);

        // The database should be considered empty for user 1.
        assert!(legacy_blob_loader.is_empty_user(1)?);

        legacy_blob_loader.remove_super_key(0);

        // Now it should be empty.
        assert!(legacy_blob_loader.is_empty_user(0)?);
        assert!(legacy_blob_loader.is_empty()?);

        Ok(())
    }
}
