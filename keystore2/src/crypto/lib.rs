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
    extractSubjectFromCertificate, generateKeyFromPassword, randomBytes, AES_gcm_decrypt,
    AES_gcm_encrypt, ECDHComputeKey, ECKEYDeriveFromSecret, ECKEYGenerateKey, ECPOINTOct2Point,
    ECPOINTPoint2Oct, EC_KEY_free, EC_KEY_get0_public_key, EC_POINT_free, HKDFExpand, HKDFExtract,
    EC_KEY, EC_MAX_BYTES, EC_POINT, EVP_MAX_MD_SIZE,
};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::marker::PhantomData;
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
    if unsafe { randomBytes(key.as_mut_ptr(), AES_256_KEY_LENGTH) } {
        Ok(key)
    } else {
        Err(Error::RandomNumberGenerationFailed)
    }
}

/// Generate a salt.
pub fn generate_salt() -> Result<Vec<u8>, Error> {
    // Safety: salt has the same length as the requested number of random bytes.
    let mut salt = vec![0; SALT_LENGTH];
    if unsafe { randomBytes(salt.as_mut_ptr(), SALT_LENGTH) } {
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
            data.len(),
            key.as_ptr(),
            key.len(),
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
    if !unsafe { randomBytes(iv.as_mut_ptr(), GCM_IV_LENGTH) } {
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
            data.len(),
            key.as_ptr(),
            key.len(),
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
            result.len(),
            pw.as_ptr() as *const std::os::raw::c_char,
            pw.len(),
            salt,
        )
    };

    Ok(result)
}

/// Calls the boringssl HKDF_extract function.
pub fn hkdf_extract(secret: &[u8], salt: &[u8]) -> Result<ZVec, Error> {
    let max_size: usize = EVP_MAX_MD_SIZE.try_into().unwrap();
    let mut buf = ZVec::new(max_size)?;
    let mut out_len = 0;
    // Safety: HKDF_extract writes at most EVP_MAX_MD_SIZE bytes.
    // Secret and salt point to valid buffers.
    let result = unsafe {
        HKDFExtract(
            buf.as_mut_ptr(),
            &mut out_len,
            secret.as_ptr(),
            secret.len(),
            salt.as_ptr(),
            salt.len(),
        )
    };
    if !result {
        return Err(Error::HKDFExtractFailed);
    }
    // According to the boringssl API, this should never happen.
    if out_len > max_size {
        return Err(Error::HKDFExtractFailed);
    }
    // HKDF_extract may write fewer than the maximum number of bytes, so we
    // truncate the buffer.
    buf.reduce_len(out_len);
    Ok(buf)
}

/// Calls the boringssl HKDF_expand function.
pub fn hkdf_expand(out_len: usize, prk: &[u8], info: &[u8]) -> Result<ZVec, Error> {
    let mut buf = ZVec::new(out_len)?;
    // Safety: HKDF_expand writes out_len bytes to the buffer.
    // prk and info are valid buffers.
    let result = unsafe {
        HKDFExpand(buf.as_mut_ptr(), out_len, prk.as_ptr(), prk.len(), info.as_ptr(), info.len())
    };
    if !result {
        return Err(Error::HKDFExpandFailed);
    }
    Ok(buf)
}

/// A wrapper around the boringssl EC_KEY type that frees it on drop.
pub struct ECKey(*mut EC_KEY);

impl Drop for ECKey {
    fn drop(&mut self) {
        // Safety: We only create ECKey objects for valid EC_KEYs
        // and they are the sole owners of those keys.
        unsafe { EC_KEY_free(self.0) };
    }
}

// Wrappers around the boringssl EC_POINT type.
// The EC_POINT can either be owned (and therefore mutable) or a pointer to an
// EC_POINT owned by someone else (and thus immutable).  The former are freed
// on drop.

/// An owned EC_POINT object.
pub struct OwnedECPoint(*mut EC_POINT);

/// A pointer to an EC_POINT object.
pub struct BorrowedECPoint<'a> {
    data: *const EC_POINT,
    phantom: PhantomData<&'a EC_POINT>,
}

impl OwnedECPoint {
    /// Get the wrapped EC_POINT object.
    pub fn get_point(&self) -> &EC_POINT {
        // Safety: We only create OwnedECPoint objects for valid EC_POINTs.
        unsafe { self.0.as_ref().unwrap() }
    }
}

impl<'a> BorrowedECPoint<'a> {
    /// Get the wrapped EC_POINT object.
    pub fn get_point(&self) -> &EC_POINT {
        // Safety: We only create BorrowedECPoint objects for valid EC_POINTs.
        unsafe { self.data.as_ref().unwrap() }
    }
}

impl Drop for OwnedECPoint {
    fn drop(&mut self) {
        // Safety: We only create OwnedECPoint objects for valid
        // EC_POINTs and they are the sole owners of those points.
        unsafe { EC_POINT_free(self.0) };
    }
}

/// Calls the boringssl ECDH_compute_key function.
pub fn ecdh_compute_key(pub_key: &EC_POINT, priv_key: &ECKey) -> Result<ZVec, Error> {
    let mut buf = ZVec::new(EC_MAX_BYTES)?;
    // Safety: Our ECDHComputeKey wrapper passes EC_MAX_BYES to ECDH_compute_key, which
    // writes at most that many bytes to the output.
    // The two keys are valid objects.
    let result =
        unsafe { ECDHComputeKey(buf.as_mut_ptr() as *mut std::ffi::c_void, pub_key, priv_key.0) };
    if result == -1 {
        return Err(Error::ECDHComputeKeyFailed);
    }
    let out_len = result.try_into().unwrap();
    // According to the boringssl API, this should never happen.
    if out_len > buf.len() {
        return Err(Error::ECDHComputeKeyFailed);
    }
    // ECDH_compute_key may write fewer than the maximum number of bytes, so we
    // truncate the buffer.
    buf.reduce_len(out_len);
    Ok(buf)
}

/// Calls the boringssl EC_KEY_generate_key function.
pub fn ec_key_generate_key() -> Result<ECKey, Error> {
    // Safety: Creates a new key on its own.
    let key = unsafe { ECKEYGenerateKey() };
    if key.is_null() {
        return Err(Error::ECKEYGenerateKeyFailed);
    }
    Ok(ECKey(key))
}

/// Calls the boringssl EC_KEY_derive_from_secret function.
pub fn ec_key_derive_from_secret(secret: &[u8]) -> Result<ECKey, Error> {
    // Safety: secret is a valid buffer.
    let result = unsafe { ECKEYDeriveFromSecret(secret.as_ptr(), secret.len()) };
    if result.is_null() {
        return Err(Error::ECKEYDeriveFailed);
    }
    Ok(ECKey(result))
}

/// Calls the boringssl EC_KEY_get0_public_key function.
pub fn ec_key_get0_public_key(key: &ECKey) -> BorrowedECPoint {
    // Safety: The key is valid.
    // This returns a pointer to a key, so we create an immutable variant.
    BorrowedECPoint { data: unsafe { EC_KEY_get0_public_key(key.0) }, phantom: PhantomData }
}

/// Calls the boringssl EC_POINT_point2oct.
pub fn ec_point_point_to_oct(point: &EC_POINT) -> Result<Vec<u8>, Error> {
    // We fix the length to 65 (1 + 2 * field_elem_size), as we get an error if it's too small.
    let len = 65;
    let mut buf = vec![0; len];
    // Safety: EC_POINT_point2oct writes at most len bytes. The point is valid.
    let result = unsafe { ECPOINTPoint2Oct(point, buf.as_mut_ptr(), len) };
    if result == 0 {
        return Err(Error::ECPoint2OctFailed);
    }
    // According to the boringssl API, this should never happen.
    if result > len {
        return Err(Error::ECPoint2OctFailed);
    }
    buf.resize(result, 0);
    Ok(buf)
}

/// Calls the boringssl EC_POINT_oct2point function.
pub fn ec_point_oct_to_point(buf: &[u8]) -> Result<OwnedECPoint, Error> {
    // Safety: The buffer is valid.
    let result = unsafe { ECPOINTOct2Point(buf.as_ptr(), buf.len()) };
    if result.is_null() {
        return Err(Error::ECPoint2OctFailed);
    }
    // Our C wrapper creates a new EC_POINT, so we mark this mutable and free
    // it on drop.
    Ok(OwnedECPoint(result))
}

/// Uses BoringSSL to extract the DER-encoded subject from a DER-encoded X.509 certificate.
pub fn parse_subject_from_certificate(cert_buf: &[u8]) -> Result<Vec<u8>, Error> {
    // Try with a 200-byte output buffer, should be enough in all but bizarre cases.
    let mut retval = vec![0; 200];

    // Safety: extractSubjectFromCertificate reads at most cert_buf.len() bytes from cert_buf and
    // writes at most retval.len() bytes to retval.
    let mut size = unsafe {
        extractSubjectFromCertificate(
            cert_buf.as_ptr(),
            cert_buf.len(),
            retval.as_mut_ptr(),
            retval.len(),
        )
    };

    if size == 0 {
        return Err(Error::ExtractSubjectFailed);
    }

    if size < 0 {
        // Our buffer wasn't big enough.  Make one that is just the right size and try again.
        let negated_size = usize::try_from(-size).map_err(|_e| Error::ExtractSubjectFailed)?;
        retval = vec![0; negated_size];

        // Safety: extractSubjectFromCertificate reads at most cert_buf.len() bytes from cert_buf
        // and writes at most retval.len() bytes to retval.
        size = unsafe {
            extractSubjectFromCertificate(
                cert_buf.as_ptr(),
                cert_buf.len(),
                retval.as_mut_ptr(),
                retval.len(),
            )
        };

        if size <= 0 {
            return Err(Error::ExtractSubjectFailed);
        }
    }

    // Reduce buffer size to the amount written.
    let safe_size = usize::try_from(size).map_err(|_e| Error::ExtractSubjectFailed)?;
    retval.truncate(safe_size);

    Ok(retval)
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

    #[test]
    fn test_hkdf() {
        let result = hkdf_extract(&[0; 16], &[0; 16]);
        assert!(result.is_ok());
        for out_len in 4..=8 {
            let result = hkdf_expand(out_len, &[0; 16], &[0; 16]);
            assert!(result.is_ok());
            assert_eq!(result.unwrap().len(), out_len);
        }
    }

    #[test]
    fn test_ec() {
        let key = ec_key_generate_key();
        assert!(key.is_ok());
        assert!(!key.unwrap().0.is_null());

        let key = ec_key_derive_from_secret(&[42; 16]);
        assert!(key.is_ok());
        let key = key.unwrap();
        assert!(!key.0.is_null());

        let point = ec_key_get0_public_key(&key);

        let result = ecdh_compute_key(point.get_point(), &key);
        assert!(result.is_ok());

        let oct = ec_point_point_to_oct(point.get_point());
        assert!(oct.is_ok());
        let oct = oct.unwrap();

        let point2 = ec_point_oct_to_point(oct.as_slice());
        assert!(point2.is_ok());
    }
}
