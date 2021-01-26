/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdint.h>

#include <memory>
#include <optional>
#include <variant>

namespace keystore {
// We use boringssl error codes. Error codes that we add are folded into LIB_USER.
// The CertificateUtilsInternallErrorCodes enum should not be used by callers, instead use the
// BoringSslError constant definitions below for error codes.
using BoringSslError = unsigned long;

#define DEFINE_OPENSSL_OBJECT_POINTER(name) using name##_Ptr = bssl::UniquePtr<name>

DEFINE_OPENSSL_OBJECT_POINTER(ASN1_BIT_STRING);
DEFINE_OPENSSL_OBJECT_POINTER(ASN1_STRING);
DEFINE_OPENSSL_OBJECT_POINTER(ASN1_INTEGER);
DEFINE_OPENSSL_OBJECT_POINTER(ASN1_OCTET_STRING);
DEFINE_OPENSSL_OBJECT_POINTER(ASN1_TIME);
DEFINE_OPENSSL_OBJECT_POINTER(EVP_PKEY);
DEFINE_OPENSSL_OBJECT_POINTER(X509);
DEFINE_OPENSSL_OBJECT_POINTER(X509_EXTENSION);
DEFINE_OPENSSL_OBJECT_POINTER(X509_NAME);
DEFINE_OPENSSL_OBJECT_POINTER(EVP_PKEY_CTX);

class CertUtilsError {
  public:
    enum Error {
        Ok = 0,
        BoringSsl,
        Encoding,
        MemoryAllocation,
        InvalidArgument,
        UnexpectedNullPointer,
        SignatureFailed,
    };

  private:
    Error e_;

  public:
    constexpr CertUtilsError(Error e) : e_(e) {}
    explicit constexpr operator bool() const { return e_ != Ok; }
};

struct KeyUsageExtension {
    bool isSigningKey;
    bool isEncryptionKey;
    bool isCertificationKey;
};

struct BasicConstraintsExtension {
    bool isCa;
    std::optional<int> pathLength;
};

/**
 * This function allocates and prepares an X509 certificate structure with all of the information
 * given. Next steps would be to set an Issuer with `setIssuer` and sign it with either
 * `signCert` or `signCertWith`.
 * @param evp_pkey The public key that the certificate is issued for.
 * @param serial The certificate serial number.
 * @param subject The subject common name.
 * @param activeDateTimeMilliSeconds The not before date in epoch milliseconds.
 * @param usageExpireDateTimeMilliSeconds The not after date in epoch milliseconds.
 * @param addSubjectKeyIdEx If true, adds the subject key id extension.
 * @param keyUsageEx If given adds, the key usage extension with the given flags.
 * @param basicConstraints If given, adds the basic constraints extension with the given data.
 * @return CertUtilsError::Ok on success.
 */
std::variant<CertUtilsError, X509_Ptr>
makeCert(const EVP_PKEY* evp_pkey,                                    //
         const uint32_t serial,                                       //
         const char subject[],                                        //
         const uint64_t activeDateTimeMilliSeconds,                   //
         const uint64_t usageExpireDateTimeMilliSeconds,              //
         bool addSubjectKeyIdEx,                                      //
         std::optional<KeyUsageExtension> keyUsageEx,                 //
         std::optional<BasicConstraintsExtension> basicConstraints);  //

/**
 * Takes the subject name from `signingCert` and sets it as issuer name in `cert`.
 * if `addAuthKeyExt` is true it also generates the digest of the signing certificates's public key
 * and sets it as authority key id extension in `cert`.
 * For self signed certificates pass the same pointer to both `cert` and `signingCert`.
 *
 * @param cert
 * @param signingCert
 * @param addAuthKeyExt
 * @return CertUtilsError::Ok on success.
 */
CertUtilsError setIssuer(X509* cert, const X509* signingCert, bool addAuthKeyExt);

/**
 * Takes a certificate, and private signing_key.
 * Signs the certificate with the latter.
 */
CertUtilsError signCert(X509* certificate, EVP_PKEY* signing_key);

enum class Digest {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
};

enum class Algo {
    ECDSA,
    RSA,
};

enum class Padding {
    Ignored,
    PKCS1_5,
    PSS,
};

/**
 * Sets the signature specifier of the certificate and the signature according to the parameters
 * c. Then it signs the certificate with the `sign` callback.
 * IMPORTANT: The parameters `algo`, `padding`, and `digest` do not control the actual signing
 * algorithm. The caller is responsible to provide a callback that actually performs the signature
 * as described by this triplet.
 * The `padding` argument is ignored if `algo` is Algo::EC.
 * The `digest` field controls the message digest used, and, in case of RSA with PSS padding,
 *              also the MGF1 digest.
 *
 * @param certificate X509 certificate structure to be signed.
 * @param sign Callback function used to digest and sign the DER encoded to-be-signed certificate.
 * @param algo Algorithm specifier used to encode the signing algorithm id of the X509 certificate.
 * @param padding Padding specifier used to encode the signing algorithm id of the X509 certificate.
 * @param digest Digest specifier used to encode the signing algorithm id of the X509 certificate.
 * @return CertUtilsError::Ok on success.
 */
CertUtilsError signCertWith(X509* certificate,
                            std::function<std::vector<uint8_t>(const uint8_t*, size_t)> sign,
                            Algo algo, Padding padding, Digest digest);

/**
 * Generates the DER representation of the given signed X509 certificate structure.
 * @param certificate
 * @return std::vector<uint8_t> with the DER encoded certificate on success. An error code
 *         otherwise.
 */
std::variant<CertUtilsError, std::vector<uint8_t>> encodeCert(X509* certificate);

}  // namespace keystore
