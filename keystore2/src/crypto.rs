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

#[cfg(test)]
mod tests {

    use keystore2_crypto_bindgen::{
        generateKeyFromPassword, AES_gcm_decrypt, AES_gcm_encrypt, CreateKeyId,
    };

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
