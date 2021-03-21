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

//! Implement ECDH-based encryption.

use anyhow::{Context, Result};
use keystore2_crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, ec_key_generate_key, ec_key_get0_public_key,
    ec_key_marshal_private_key, ec_key_parse_private_key, ec_point_oct_to_point,
    ec_point_point_to_oct, ecdh_compute_key, generate_salt, hkdf_expand, hkdf_extract, ECKey, ZVec,
    AES_256_KEY_LENGTH,
};

/// Private key for ECDH encryption.
pub struct ECDHPrivateKey(ECKey);

impl ECDHPrivateKey {
    /// Randomly generate a fresh keypair.
    pub fn generate() -> Result<ECDHPrivateKey> {
        ec_key_generate_key()
            .map(ECDHPrivateKey)
            .context("In ECDHPrivateKey::generate: generation failed")
    }

    /// Deserialize bytes into an ECDH keypair
    pub fn from_private_key(buf: &[u8]) -> Result<ECDHPrivateKey> {
        ec_key_parse_private_key(buf)
            .map(ECDHPrivateKey)
            .context("In ECDHPrivateKey::from_private_key: parsing failed")
    }

    /// Serialize the ECDH key into bytes
    pub fn private_key(&self) -> Result<ZVec> {
        ec_key_marshal_private_key(&self.0)
            .context("In ECDHPrivateKey::private_key: marshalling failed")
    }

    /// Generate the serialization of the corresponding public key
    pub fn public_key(&self) -> Result<Vec<u8>> {
        let point = ec_key_get0_public_key(&self.0);
        ec_point_point_to_oct(point.get_point())
            .context("In ECDHPrivateKey::public_key: marshalling failed")
    }

    /// Use ECDH to agree an AES key with another party whose public key we have.
    /// Sender and recipient public keys are passed separately because they are
    /// switched in encryption vs decryption.
    fn agree_key(
        &self,
        salt: &[u8],
        other_public_key: &[u8],
        sender_public_key: &[u8],
        recipient_public_key: &[u8],
    ) -> Result<ZVec> {
        let hkdf = hkdf_extract(sender_public_key, salt)
            .context("In ECDHPrivateKey::agree_key: hkdf_extract on sender_public_key failed")?;
        let hkdf = hkdf_extract(recipient_public_key, &hkdf)
            .context("In ECDHPrivateKey::agree_key: hkdf_extract on recipient_public_key failed")?;
        let other_public_key = ec_point_oct_to_point(other_public_key)
            .context("In ECDHPrivateKey::agree_key: ec_point_oct_to_point failed")?;
        let secret = ecdh_compute_key(other_public_key.get_point(), &self.0)
            .context("In ECDHPrivateKey::agree_key: ecdh_compute_key failed")?;
        let prk = hkdf_extract(&secret, &hkdf)
            .context("In ECDHPrivateKey::agree_key: hkdf_extract on secret failed")?;

        let aes_key = hkdf_expand(AES_256_KEY_LENGTH, &prk, b"AES-256-GCM key")
            .context("In ECDHPrivateKey::agree_key: hkdf_expand failed")?;
        Ok(aes_key)
    }

    /// Encrypt a message to the party with the given public key
    pub fn encrypt_message(
        recipient_public_key: &[u8],
        message: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let sender_key =
            Self::generate().context("In ECDHPrivateKey::encrypt_message: generate failed")?;
        let sender_public_key = sender_key
            .public_key()
            .context("In ECDHPrivateKey::encrypt_message: public_key failed")?;
        let salt =
            generate_salt().context("In ECDHPrivateKey::encrypt_message: generate_salt failed")?;
        let aes_key = sender_key
            .agree_key(&salt, recipient_public_key, &sender_public_key, recipient_public_key)
            .context("In ECDHPrivateKey::encrypt_message: agree_key failed")?;
        let (ciphertext, iv, tag) = aes_gcm_encrypt(message, &aes_key)
            .context("In ECDHPrivateKey::encrypt_message: aes_gcm_encrypt failed")?;
        Ok((sender_public_key, salt, iv, ciphertext, tag))
    }

    /// Decrypt a message sent to us
    pub fn decrypt_message(
        &self,
        sender_public_key: &[u8],
        salt: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<ZVec> {
        let recipient_public_key = self.public_key()?;
        let aes_key = self
            .agree_key(salt, sender_public_key, sender_public_key, &recipient_public_key)
            .context("In ECDHPrivateKey::decrypt_message: agree_key failed")?;
        aes_gcm_decrypt(ciphertext, iv, tag, &aes_key)
            .context("In ECDHPrivateKey::decrypt_message: aes_gcm_decrypt failed")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_crypto_roundtrip() -> Result<()> {
        let message = b"Hello world";
        let recipient = ECDHPrivateKey::generate()?;
        let (sender_public_key, salt, iv, ciphertext, tag) =
            ECDHPrivateKey::encrypt_message(&recipient.public_key()?, message)?;
        let recipient = ECDHPrivateKey::from_private_key(&recipient.private_key()?)?;
        let decrypted =
            recipient.decrypt_message(&sender_public_key, &salt, &iv, &ciphertext, &tag)?;
        let dc: &[u8] = &decrypted;
        assert_eq!(message, dc);
        Ok(())
    }
}
