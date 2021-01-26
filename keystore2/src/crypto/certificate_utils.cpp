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

#include <certificate_utils.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/x509v3.h>

#include <functional>
#include <limits>
#include <string>
#include <variant>
#include <vector>

namespace keystore {

namespace {

constexpr int kDigitalSignatureKeyUsageBit = 0;
constexpr int kKeyEnciphermentKeyUsageBit = 2;
constexpr int kDataEnciphermentKeyUsageBit = 3;
constexpr int kKeyCertSignBit = 5;
constexpr int kMaxKeyUsageBit = 8;

DEFINE_OPENSSL_OBJECT_POINTER(ASN1_STRING);
DEFINE_OPENSSL_OBJECT_POINTER(RSA_PSS_PARAMS);
DEFINE_OPENSSL_OBJECT_POINTER(AUTHORITY_KEYID);
DEFINE_OPENSSL_OBJECT_POINTER(BASIC_CONSTRAINTS);
DEFINE_OPENSSL_OBJECT_POINTER(X509_ALGOR);

}  // namespace

std::variant<CertUtilsError, X509_NAME_Ptr> makeCommonName(const std::string& name) {
    X509_NAME_Ptr x509_name(X509_NAME_new());
    if (!x509_name) {
        return CertUtilsError::BoringSsl;
    }
    if (!X509_NAME_add_entry_by_txt(x509_name.get(), "CN", MBSTRING_ASC,
                                    reinterpret_cast<const uint8_t*>(name.c_str()), name.length(),
                                    -1 /* loc */, 0 /* set */)) {
        return CertUtilsError::BoringSsl;
    }
    return x509_name;
}

std::variant<CertUtilsError, std::vector<uint8_t>> makeKeyId(const X509* cert) {
    std::vector<uint8_t> keyid(20);
    unsigned int len;
    if (!X509_pubkey_digest(cert, EVP_sha1(), keyid.data(), &len)) {
        return CertUtilsError::Encoding;
    }
    return keyid;
}

std::variant<CertUtilsError, AUTHORITY_KEYID_Ptr>
makeAuthorityKeyExtension(const std::vector<uint8_t>& keyid) {
    AUTHORITY_KEYID_Ptr auth_key(AUTHORITY_KEYID_new());
    if (!auth_key) {
        return CertUtilsError::MemoryAllocation;
    }

    auth_key->keyid = ASN1_OCTET_STRING_new();
    if (auth_key->keyid == nullptr) {
        return CertUtilsError::MemoryAllocation;
    }

    if (!ASN1_OCTET_STRING_set(auth_key->keyid, keyid.data(), keyid.size())) {
        return CertUtilsError::BoringSsl;
    }

    return auth_key;
}

std::variant<CertUtilsError, ASN1_OCTET_STRING_Ptr>
makeSubjectKeyExtension(const std::vector<uint8_t>& keyid) {

    // Build OCTET_STRING
    ASN1_OCTET_STRING_Ptr keyid_str(ASN1_OCTET_STRING_new());
    if (!keyid_str || !ASN1_OCTET_STRING_set(keyid_str.get(), keyid.data(), keyid.size())) {
        return CertUtilsError::BoringSsl;
    }

    return keyid_str;
}

std::variant<CertUtilsError, BASIC_CONSTRAINTS_Ptr>
makeBasicConstraintsExtension(bool is_ca, std::optional<int> path_length) {

    BASIC_CONSTRAINTS_Ptr bcons(BASIC_CONSTRAINTS_new());
    if (!bcons) {
        return CertUtilsError::MemoryAllocation;
    }

    bcons->ca = is_ca;
    bcons->pathlen = nullptr;
    if (path_length) {
        bcons->pathlen = ASN1_INTEGER_new();
        if (bcons->pathlen == nullptr || !ASN1_INTEGER_set(bcons->pathlen, *path_length)) {
            return CertUtilsError::BoringSsl;
        }
    }

    return bcons;
}

std::variant<CertUtilsError, ASN1_BIT_STRING_Ptr>
makeKeyUsageExtension(bool is_signing_key, bool is_encryption_key, bool is_cert_key) {
    // Build BIT_STRING with correct contents.
    ASN1_BIT_STRING_Ptr key_usage(ASN1_BIT_STRING_new());
    if (!key_usage) {
        return CertUtilsError::BoringSsl;
    }

    for (size_t i = 0; i <= kMaxKeyUsageBit; ++i) {
        if (!ASN1_BIT_STRING_set_bit(key_usage.get(), i, 0)) {
            return CertUtilsError::BoringSsl;
        }
    }

    if (is_signing_key) {
        if (!ASN1_BIT_STRING_set_bit(key_usage.get(), kDigitalSignatureKeyUsageBit, 1)) {
            return CertUtilsError::BoringSsl;
        }
    }

    if (is_encryption_key) {
        if (!ASN1_BIT_STRING_set_bit(key_usage.get(), kKeyEnciphermentKeyUsageBit, 1) ||
            !ASN1_BIT_STRING_set_bit(key_usage.get(), kDataEnciphermentKeyUsageBit, 1)) {
            return CertUtilsError::BoringSsl;
        }
    }

    if (is_cert_key) {
        if (!ASN1_BIT_STRING_set_bit(key_usage.get(), kKeyCertSignBit, 1)) {
            return CertUtilsError::BoringSsl;
        }
    }

    return key_usage;
}

// Creates a rump certificate structure with serial, subject and issuer names, as well as
// activation and expiry date.
// Callers should pass an empty X509_Ptr and check the return value for CertUtilsError::Ok (0)
// before accessing the result.
std::variant<CertUtilsError, X509_Ptr>
makeCertRump(const uint32_t serial, const char subject[], const uint64_t activeDateTimeMilliSeconds,
             const uint64_t usageExpireDateTimeMilliSeconds) {

    // Sanitize pointer arguments.
    if (!subject || strlen(subject) == 0) {
        return CertUtilsError::InvalidArgument;
    }

    // Create certificate structure.
    X509_Ptr certificate(X509_new());
    if (!certificate) {
        return CertUtilsError::BoringSsl;
    }

    // Set the X509 version.
    if (!X509_set_version(certificate.get(), 2 /* version 3, but zero-based */)) {
        return CertUtilsError::BoringSsl;
    }

    // Set the certificate serialNumber
    ASN1_INTEGER_Ptr serialNumber(ASN1_INTEGER_new());
    if (!serialNumber || !ASN1_INTEGER_set(serialNumber.get(), serial) ||
        !X509_set_serialNumber(certificate.get(), serialNumber.get() /* Don't release; copied */))
        return CertUtilsError::BoringSsl;

    // Set Subject Name
    auto subjectName = makeCommonName(subject);
    if (auto x509_subject = std::get_if<X509_NAME_Ptr>(&subjectName)) {
        if (!X509_set_subject_name(certificate.get(), x509_subject->get() /* copied */)) {
            return CertUtilsError::BoringSsl;
        }
    } else {
        return std::get<CertUtilsError>(subjectName);
    }

    // Set activation date.
    ASN1_TIME_Ptr notBefore(ASN1_TIME_new());
    if (!notBefore || !ASN1_TIME_set(notBefore.get(), activeDateTimeMilliSeconds / 1000) ||
        !X509_set_notBefore(certificate.get(), notBefore.get() /* Don't release; copied */))
        return CertUtilsError::BoringSsl;

    // Set expiration date.
    time_t notAfterTime;
    notAfterTime = (time_t)std::min((uint64_t)std::numeric_limits<time_t>::max(),
                                    usageExpireDateTimeMilliSeconds / 1000);

    ASN1_TIME_Ptr notAfter(ASN1_TIME_new());
    if (!notAfter || !ASN1_TIME_set(notAfter.get(), notAfterTime) ||
        !X509_set_notAfter(certificate.get(), notAfter.get() /* Don't release; copied */)) {
        return CertUtilsError::BoringSsl;
    }

    return certificate;
}

std::variant<CertUtilsError, X509_Ptr>
makeCert(const EVP_PKEY* evp_pkey, const uint32_t serial, const char subject[],
         const uint64_t activeDateTimeMilliSeconds, const uint64_t usageExpireDateTimeMilliSeconds,
         bool addSubjectKeyIdEx, std::optional<KeyUsageExtension> keyUsageEx,
         std::optional<BasicConstraintsExtension> basicConstraints) {

    // Make the rump certificate with serial, subject, not before and not after dates.
    auto certificateV =
        makeCertRump(serial, subject, activeDateTimeMilliSeconds, usageExpireDateTimeMilliSeconds);
    if (auto error = std::get_if<CertUtilsError>(&certificateV)) {
        return *error;
    }
    auto certificate = std::move(std::get<X509_Ptr>(certificateV));

    // Set the public key.
    if (!X509_set_pubkey(certificate.get(), const_cast<EVP_PKEY*>(evp_pkey))) {
        return CertUtilsError::BoringSsl;
    }

    if (keyUsageEx) {
        // Make and add the key usage extension.
        auto key_usage_extensionV = makeKeyUsageExtension(
            keyUsageEx->isSigningKey, keyUsageEx->isEncryptionKey, keyUsageEx->isCertificationKey);
        if (auto error = std::get_if<CertUtilsError>(&key_usage_extensionV)) {
            return *error;
        }
        auto key_usage_extension = std::move(std::get<ASN1_BIT_STRING_Ptr>(key_usage_extensionV));
        if (!X509_add1_ext_i2d(certificate.get(), NID_key_usage,
                               key_usage_extension.get() /* Don't release; copied */,
                               true /* critical */, 0 /* flags */)) {
            return CertUtilsError::BoringSsl;
        }
    }

    if (basicConstraints) {
        // Make and add basic constraints
        auto basic_constraints_extensionV =
            makeBasicConstraintsExtension(basicConstraints->isCa, basicConstraints->pathLength);
        if (auto error = std::get_if<CertUtilsError>(&basic_constraints_extensionV)) {
            return *error;
        }
        auto basic_constraints_extension =
            std::move(std::get<BASIC_CONSTRAINTS_Ptr>(basic_constraints_extensionV));
        if (!X509_add1_ext_i2d(certificate.get(), NID_basic_constraints,
                               basic_constraints_extension.get() /* Don't release; copied */,
                               true /* critical */, 0 /* flags */)) {
            return CertUtilsError::BoringSsl;
        }
    }

    if (addSubjectKeyIdEx) {
        // Make and add subject key id extension.
        auto keyidV = makeKeyId(certificate.get());
        if (auto error = std::get_if<CertUtilsError>(&keyidV)) {
            return *error;
        }
        auto& keyid = std::get<std::vector<uint8_t>>(keyidV);

        auto subject_key_extensionV = makeSubjectKeyExtension(keyid);
        if (auto error = std::get_if<CertUtilsError>(&subject_key_extensionV)) {
            return *error;
        }
        auto subject_key_extension =
            std::move(std::get<ASN1_OCTET_STRING_Ptr>(subject_key_extensionV));
        if (!X509_add1_ext_i2d(certificate.get(), NID_subject_key_identifier,
                               subject_key_extension.get() /* Don't release; copied */,
                               false /* critical */, 0 /* flags */)) {
            return CertUtilsError::BoringSsl;
        }
    }

    return certificate;
}

CertUtilsError setIssuer(X509* cert, const X509* signingCert, bool addAuthKeyExt) {

    X509_NAME* issuerName(X509_get_subject_name(signingCert));

    // Set Issuer Name
    if (issuerName) {
        if (!X509_set_issuer_name(cert, issuerName /* copied */)) {
            return CertUtilsError::BoringSsl;
        }
    } else {
        return CertUtilsError::Encoding;
    }

    if (addAuthKeyExt) {
        // Make and add authority key extension - self signed.
        auto keyidV = makeKeyId(signingCert);
        if (auto error = std::get_if<CertUtilsError>(&keyidV)) {
            return *error;
        }
        auto& keyid = std::get<std::vector<uint8_t>>(keyidV);

        auto auth_key_extensionV = makeAuthorityKeyExtension(keyid);
        if (auto error = std::get_if<CertUtilsError>(&auth_key_extensionV)) {
            return *error;
        }
        auto auth_key_extension = std::move(std::get<AUTHORITY_KEYID_Ptr>(auth_key_extensionV));
        if (!X509_add1_ext_i2d(cert, NID_authority_key_identifier, auth_key_extension.get(), false,
                               0)) {
            return CertUtilsError::BoringSsl;
        }
    }
    return CertUtilsError::Ok;
}

// Takes a certificate a signing certificate and the raw private signing_key. And signs
// the certificate with the latter.
CertUtilsError signCert(X509* certificate, EVP_PKEY* signing_key) {

    if (certificate == nullptr) {
        return CertUtilsError::UnexpectedNullPointer;
    }

    if (!X509_sign(certificate, signing_key, EVP_sha256())) {
        return CertUtilsError::BoringSsl;
    }

    return CertUtilsError::Ok;
}

std::variant<CertUtilsError, std::vector<uint8_t>> encodeCert(X509* certificate) {
    int len = i2d_X509(certificate, nullptr);
    if (len < 0) {
        return CertUtilsError::BoringSsl;
    }

    auto result = std::vector<uint8_t>(len);
    uint8_t* p = result.data();

    if (i2d_X509(certificate, &p) < 0) {
        return CertUtilsError::BoringSsl;
    }
    return result;
}

CertUtilsError setRsaDigestAlgorField(X509_ALGOR** alg_ptr, const EVP_MD* digest) {
    if (alg_ptr == nullptr || digest == nullptr) {
        return CertUtilsError::UnexpectedNullPointer;
    }
    *alg_ptr = X509_ALGOR_new();
    if (*alg_ptr == nullptr) {
        return CertUtilsError::MemoryAllocation;
    }
    X509_ALGOR_set_md(*alg_ptr, digest);
    return CertUtilsError::Ok;
}

CertUtilsError setPssMaskGeneratorField(X509_ALGOR** alg_ptr, const EVP_MD* digest) {
    X509_ALGOR* mgf1_digest = nullptr;
    if (auto error = setRsaDigestAlgorField(&mgf1_digest, digest)) {
        return error;
    }
    X509_ALGOR_Ptr mgf1_digest_ptr(mgf1_digest);

    ASN1_OCTET_STRING* mgf1_digest_algor_str = nullptr;
    if (!ASN1_item_pack(mgf1_digest, ASN1_ITEM_rptr(X509_ALGOR), &mgf1_digest_algor_str)) {
        return CertUtilsError::Encoding;
    }
    ASN1_OCTET_STRING_Ptr mgf1_digest_algor_str_ptr(mgf1_digest_algor_str);

    *alg_ptr = X509_ALGOR_new();
    if (*alg_ptr == nullptr) {
        return CertUtilsError::MemoryAllocation;
    }
    X509_ALGOR_set0(*alg_ptr, OBJ_nid2obj(NID_mgf1), V_ASN1_SEQUENCE, mgf1_digest_algor_str);
    // *alg_ptr took ownership of the octet string
    mgf1_digest_algor_str_ptr.release();
    return CertUtilsError::Ok;
}

static CertUtilsError setSaltLength(RSA_PSS_PARAMS* pss_params, unsigned length) {
    pss_params->saltLength = ASN1_INTEGER_new();
    if (pss_params->saltLength == nullptr) {
        return CertUtilsError::MemoryAllocation;
    }
    if (!ASN1_INTEGER_set(pss_params->saltLength, length)) {
        return CertUtilsError::Encoding;
    };
    return CertUtilsError::Ok;
}

std::variant<CertUtilsError, ASN1_STRING_Ptr> buildRsaPssParameter(Digest digest) {
    RSA_PSS_PARAMS_Ptr pss(RSA_PSS_PARAMS_new());
    if (!pss) {
        return CertUtilsError::MemoryAllocation;
    }

    const EVP_MD* md = nullptr;

    switch (digest) {
    case Digest::SHA1:
        break;
    case Digest::SHA224:
        md = EVP_sha224();
        break;
    case Digest::SHA256:
        md = EVP_sha256();
        break;
    case Digest::SHA384:
        md = EVP_sha384();
        break;
    case Digest::SHA512:
        md = EVP_sha512();
        break;
    default:
        return CertUtilsError::InvalidArgument;
    }

    if (md != nullptr) {
        if (auto error = setSaltLength(pss.get(), EVP_MD_size(md))) {
            return error;
        }
        if (auto error = setRsaDigestAlgorField(&pss->hashAlgorithm, md)) {
            return error;
        }
        if (auto error = setPssMaskGeneratorField(&pss->maskGenAlgorithm, md)) {
            return error;
        }
    }

    ASN1_STRING* algo_str = nullptr;
    if (!ASN1_item_pack(pss.get(), ASN1_ITEM_rptr(RSA_PSS_PARAMS), &algo_str)) {
        return CertUtilsError::BoringSsl;
    }

    return ASN1_STRING_Ptr(algo_str);
}

CertUtilsError makeAndSetAlgo(X509_ALGOR* algo_field, Algo algo, Padding padding, Digest digest) {
    if (algo_field == nullptr) {
        return CertUtilsError::UnexpectedNullPointer;
    }
    ASN1_STRING_Ptr param;
    int param_type = V_ASN1_UNDEF;
    int nid = 0;
    switch (algo) {
    case Algo::ECDSA:
        switch (digest) {
        case Digest::SHA1:
            nid = NID_ecdsa_with_SHA1;
            break;
        case Digest::SHA224:
            nid = NID_ecdsa_with_SHA224;
            break;
        case Digest::SHA256:
            nid = NID_ecdsa_with_SHA256;
            break;
        case Digest::SHA384:
            nid = NID_ecdsa_with_SHA384;
            break;
        case Digest::SHA512:
            nid = NID_ecdsa_with_SHA512;
            break;
        default:
            return CertUtilsError::InvalidArgument;
        }
        break;
    case Algo::RSA:
        switch (padding) {
        case Padding::PKCS1_5:
            param_type = V_ASN1_NULL;
            switch (digest) {
            case Digest::SHA1:
                nid = NID_sha1WithRSAEncryption;
                break;
            case Digest::SHA224:
                nid = NID_sha224WithRSAEncryption;
                break;
            case Digest::SHA256:
                nid = NID_sha256WithRSAEncryption;
                break;
            case Digest::SHA384:
                nid = NID_sha384WithRSAEncryption;
                break;
            case Digest::SHA512:
                nid = NID_sha512WithRSAEncryption;
                break;
            default:
                return CertUtilsError::InvalidArgument;
            }
            break;
        case Padding::PSS: {
            auto v = buildRsaPssParameter(digest);
            if (auto param_str = std::get_if<ASN1_STRING_Ptr>(&v)) {
                param = std::move(*param_str);
                param_type = V_ASN1_SEQUENCE;
                nid = NID_rsassaPss;
            } else {
                return std::get<CertUtilsError>(v);
            }
            break;
        }
        default:
            return CertUtilsError::InvalidArgument;
        }
        break;
    default:
        return CertUtilsError::InvalidArgument;
    }

    if (!X509_ALGOR_set0(algo_field, OBJ_nid2obj(nid), param_type, param.get())) {
        return CertUtilsError::Encoding;
    }
    // The X509 struct took ownership.
    param.release();
    return CertUtilsError::Ok;
}

// This function allows for signing a
CertUtilsError signCertWith(X509* certificate,
                            std::function<std::vector<uint8_t>(const uint8_t*, size_t)> sign,
                            Algo algo, Padding padding, Digest digest) {
    if (auto error = makeAndSetAlgo(certificate->sig_alg, algo, padding, digest)) {
        return error;
    }
    if (auto error = makeAndSetAlgo(certificate->cert_info->signature, algo, padding, digest)) {
        return error;
    }

    uint8_t* cert_buf = nullptr;
    int buf_len = i2d_re_X509_tbs(certificate, &cert_buf);
    if (buf_len < 0) {
        return CertUtilsError::Encoding;
    }

    bssl::UniquePtr<uint8_t> free_cert_buf(cert_buf);
    auto signature = sign(cert_buf, buf_len);
    if (signature.empty()) {
        return CertUtilsError::SignatureFailed;
    }

    if (!ASN1_STRING_set(certificate->signature, signature.data(), signature.size())) {
        return CertUtilsError::BoringSsl;
    }

    certificate->signature->flags &= ~(0x07);
    certificate->signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    return CertUtilsError::Ok;
}

}  // namespace keystore
