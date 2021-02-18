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
  bool randomBytes(uint8_t* out, size_t len);
  bool AES_gcm_encrypt(const uint8_t* in, uint8_t* out, size_t len,
                       const uint8_t* key, size_t key_size, const uint8_t* iv, uint8_t* tag);
  bool AES_gcm_decrypt(const uint8_t* in, uint8_t* out, size_t len,
                       const uint8_t* key, size_t key_size, const uint8_t* iv,
                       const uint8_t* tag);

  // Copied from system/security/keystore/keymaster_enforcement.h.
  typedef uint64_t km_id_t;

  bool CreateKeyId(const uint8_t* key_blob, size_t len, km_id_t* out_id);

  void generateKeyFromPassword(uint8_t* key, size_t key_len, const char* pw,
                               size_t pw_len, const uint8_t* salt);

  #include "openssl/digest.h"
  #include "openssl/ec_key.h"

  bool HKDFExtract(uint8_t *out_key, size_t *out_len,
                   const uint8_t *secret, size_t secret_len,
                   const uint8_t *salt, size_t salt_len);

  bool HKDFExpand(uint8_t *out_key, size_t out_len,
                  const uint8_t *prk, size_t prk_len,
                  const uint8_t *info, size_t info_len);

  // We define this as field_elem_size.
  static const size_t EC_MAX_BYTES = 32;

  int ECDHComputeKey(void *out, const EC_POINT *pub_key, const EC_KEY *priv_key);

  EC_KEY* ECKEYGenerateKey();

  EC_KEY* ECKEYDeriveFromSecret(const uint8_t *secret, size_t secret_len);

  size_t ECPOINTPoint2Oct(const EC_POINT *point, uint8_t *buf, size_t len);

  EC_POINT* ECPOINTOct2Point(const uint8_t *buf, size_t len);

}

// Parse a DER-encoded X.509 certificate contained in cert_buf, with length
// cert_len, extract the subject, DER-encode it and write the result to
// subject_buf, which has subject_buf_len capacity.
//
// Because the length of the issuer is unknown, and becaue we'd like to (a) be
// able to handle subjects of any size and (b) avoid parsing the certificate
// twice most of the time, once to discover the length and once to parse it, the
// return value is overloaded.
//
// If the return value > 0 it specifies the number of bytes written into
// subject_buf; the operation was successful.
//
// If the return value == 0, certificate parsing failed unrecoverably.  The
// reason will be logged.
//
// If the return value < 0, the operation failed because the subject size >
// subject_buf_len.  The return value is -(subject_size), where subject_size is
// the size of the extracted DER-encoded subject field.  Call
// extractSubjectFromCertificate again with a sufficiently-large buffer.
int extractSubjectFromCertificate(const uint8_t* cert_buf, size_t cert_len,
                                  uint8_t* subject_buf, size_t subject_buf_len);

#endif  //  __CRYPTO_H__
