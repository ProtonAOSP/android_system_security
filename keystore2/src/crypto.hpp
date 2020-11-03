/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

extern "C" {
  bool AES_gcm_encrypt(const uint8_t* in, uint8_t* out, size_t len,
                       const uint8_t* key, size_t key_size, const uint8_t* iv, uint8_t* tag);
  bool AES_gcm_decrypt(const uint8_t* in, uint8_t* out, size_t len,
                       const uint8_t* key, size_t key_size, const uint8_t* iv,
                       const uint8_t* tag);

  // Copied from system/security/keystore/keymaster_enforcement.h.
  typedef uint64_t km_id_t;

  bool CreateKeyId(const uint8_t* key_blob, size_t len, km_id_t* out_id);

  void generateKeyFromPassword(uint8_t* key, size_t key_len, const char* pw,
                               size_t pw_len, uint8_t* salt);
}

#endif  //  __CRYPTO_H__
