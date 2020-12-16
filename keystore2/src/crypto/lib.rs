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

//! This module implements safe wrappers for some crypto operations required by
//! Keystore 2.0.

mod error;
mod zvec;
pub use error::Error;
use keystore2_crypto_bindgen::{
    generateKeyFromPassword, randomBytes, size_t, AES_gcm_decrypt, AES_gcm_encrypt,
};
pub use zvec::ZVec;

/// Length of the expected initialization vector.
pub const IV_LENGTH: usize = 16;
/// Length of the expected AEAD TAG.
pub const TAG_LENGTH: usize = 16;
/// Length of an AES 256 key in bytes.
pub const AES_256_KEY_LENGTH: usize = 32;
/// Length of an AES 128 key in bytes.
pub const AES_128_KEY_LENGTH: usize = 16;
/// Length of the expected salt for key from password generation.
pub const SALT_LENGTH: usize = 16;

// This is the number of bytes of the GCM IV that is expected to be initialized
// with random bytes.
const GCM_IV_LENGTH: usize = 12;

/// Generate an AES256 key, essentially 32 random bytes from the underlying
/// boringssl library discretely stuffed into a ZVec.
pub fn generate_aes256_key() -> Result<ZVec, Error> {
    // Safety: key has the same length as the requested number of random bytes.
    let mut key = ZVec::new(AES_256_KEY_LENGTH)?;
    if unsafe { randomBytes(key.as_mut_ptr(), AES_256_KEY_LENGTH as size_t) } {
        Ok(key)
    } else {
        Err(Error::RandomNumberGenerationFailed)
    }
}

/// Generate a salt.
pub fn generate_salt() -> Result<Vec<u8>, Error> {
    // Safety: salt has the same length as the requested number of random bytes.
    let mut salt = vec![0; SALT_LENGTH];
    if unsafe { randomBytes(salt.as_mut_ptr(), SALT_LENGTH as size_t) } {
        Ok(salt)
    } else {
        Err(Error::RandomNumberGenerationFailed)
    }
}

/// Uses AES GCM to decipher a message given an initialization vector, aead tag, and key.
/// This function accepts 128 and 256-bit keys and uses AES128 and AES256 respectively based
/// on the key length.
/// This function returns the plaintext message in a ZVec because it is assumed that
/// it contains sensitive information that should be zeroed from memory before its buffer is
/// freed. Input key is taken as a slice for flexibility, but it is recommended that it is held
/// in a ZVec as well.
pub fn aes_gcm_decrypt(data: &[u8], iv: &[u8], tag: &[u8], key: &[u8]) -> Result<ZVec, Error> {
    if iv.len() != IV_LENGTH {
        return Err(Error::InvalidIvLength);
    }

    if tag.len() != TAG_LENGTH {
        return Err(Error::InvalidAeadTagLength);
    }

    match key.len() {
        AES_128_KEY_LENGTH | AES_256_KEY_LENGTH => {}
        _ => return Err(Error::InvalidKeyLength),
    }

    let mut result = ZVec::new(data.len())?;

    // Safety: The first two arguments must point to buffers with a size given by the third
    // argument. The key must have a size of 16 or 32 bytes which we check above.
    // The iv and tag arguments must be 16 bytes, which we also check above.
    match unsafe {
        AES_gcm_decrypt(
            data.as_ptr(),
            result.as_mut_ptr(),
            data.len() as size_t,
            key.as_ptr(),
            key.len() as size_t,
            iv.as_ptr(),
            tag.as_ptr(),
        )
    } {
        true => Ok(result),
        false => Err(Error::DecryptionFailed),
    }
}

/// Uses AES GCM to encrypt a message given a key.
/// This function accepts 128 and 256-bit keys and uses AES128 and AES256 respectively based on
/// the key length. The function generates an initialization vector. The return value is a tuple
/// of `(ciphertext, iv, tag)`.
pub fn aes_gcm_encrypt(data: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
    let mut iv = vec![0; IV_LENGTH];
    // Safety: iv is longer than GCM_IV_LENGTH, which is 12 while IV_LENGTH is 16.
    // The iv needs to be 16 bytes long, but the last 4 bytes remain zeroed.
    if !unsafe { randomBytes(iv.as_mut_ptr(), GCM_IV_LENGTH as size_t) } {
        return Err(Error::RandomNumberGenerationFailed);
    }

    match key.len() {
        AES_128_KEY_LENGTH | AES_256_KEY_LENGTH => {}
        _ => return Err(Error::InvalidKeyLength),
    }

    let mut result: Vec<u8> = vec![0; data.len()];
    let mut tag: Vec<u8> = vec![0; TAG_LENGTH];
    match unsafe {
        AES_gcm_encrypt(
            data.as_ptr(),
            result.as_mut_ptr(),
            data.len() as size_t,
            key.as_ptr(),
            key.len() as size_t,
            iv.as_ptr(),
            tag.as_mut_ptr(),
        )
    } {
        true => Ok((result, iv, tag)),
        false => Err(Error::EncryptionFailed),
    }
}

/// Generates a key from the given password and salt.
/// The salt must be exactly 16 bytes long.
/// Two key sizes are accepted: 16 and 32 bytes.
pub fn derive_key_from_password(
    pw: &[u8],
    salt: Option<&[u8]>,
    key_length: usize,
) -> Result<ZVec, Error> {
    let salt: *const u8 = match salt {
        Some(s) => {
            if s.len() != SALT_LENGTH {
                return Err(Error::InvalidSaltLength);
            }
            s.as_ptr()
        }
        None => std::ptr::null(),
    };

    match key_length {
        AES_128_KEY_LENGTH | AES_256_KEY_LENGTH => {}
        _ => return Err(Error::InvalidKeyLength),
    }

    let mut result = ZVec::new(key_length)?;

    unsafe {
        generateKeyFromPassword(
            result.as_mut_ptr(),
            result.len() as size_t,
            pw.as_ptr() as *const std::os::raw::c_char,
            pw.len() as size_t,
            salt,
        )
    };

    Ok(result)
}

#[cfg(test)]
mod tests {

    use super::*;
    use keystore2_crypto_bindgen::{
        generateKeyFromPassword, AES_gcm_decrypt, AES_gcm_encrypt, CreateKeyId,
    };

    #[test]
    fn test_wrapper_roundtrip() {
        let key = generate_aes256_key().unwrap();
        let message = b"totally awesome message";
        let (cipher_text, iv, tag) = aes_gcm_encrypt(message, &key).unwrap();
        let message2 = aes_gcm_decrypt(&cipher_text, &iv, &tag, &key).unwrap();
        assert_eq!(message[..], message2[..])
    }

    #[test]
    fn test_encrypt_decrypt() {
        let input = vec![0; 16];
        let mut out = vec![0; 16];
        let mut out2 = vec![0; 16];
        let key = vec![0; 16];
        let iv = vec![0; 12];
        let mut tag = vec![0; 16];
        unsafe {
            let res = AES_gcm_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                16,
                key.as_ptr(),
                16,
                iv.as_ptr(),
                tag.as_mut_ptr(),
            );
            assert!(res);
            assert_ne!(out, input);
            assert_ne!(tag, input);
            let res = AES_gcm_decrypt(
                out.as_ptr(),
                out2.as_mut_ptr(),
                16,
                key.as_ptr(),
                16,
                iv.as_ptr(),
                tag.as_ptr(),
            );
            assert!(res);
            assert_eq!(out2, input);
        }
    }

    #[test]
    fn test_create_key_id() {
        let blob = vec![0; 16];
        let mut out: u64 = 0;
        unsafe {
            let res = CreateKeyId(blob.as_ptr(), 16, &mut out);
            assert!(res);
            assert_ne!(out, 0);
        }
    }

    #[test]
    fn test_generate_key_from_password() {
        let mut key = vec![0; 16];
        let pw = vec![0; 16];
        let mut salt = vec![0; 16];
        unsafe {
            generateKeyFromPassword(key.as_mut_ptr(), 16, pw.as_ptr(), 16, salt.as_mut_ptr());
        }
        assert_ne!(key, vec![0; 16]);
    }
}
