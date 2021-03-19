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

#include <android-base/logging.h>
#include <android-base/result.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/pkcs7.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <fcntl.h>
#include <vector>

#include "KeyConstants.h"

const char kBasicConstraints[] = "CA:TRUE";
const char kKeyUsage[] = "critical,keyCertSign,cRLSign,digitalSignature";
const char kSubjectKeyIdentifier[] = "hash";
constexpr int kCertLifetimeSeconds = 10 * 365 * 24 * 60 * 60;

using android::base::Result;
// using android::base::ErrnoError;
using android::base::Error;

static bool add_ext(X509* cert, int nid, const char* value) {
    size_t len = strlen(value) + 1;
    std::vector<char> mutableValue(value, value + len);
    X509V3_CTX context;

    X509V3_set_ctx_nodb(&context);

    X509V3_set_ctx(&context, cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ex = X509V3_EXT_nconf_nid(nullptr, &context, nid, mutableValue.data());
    if (!ex) {
        return false;
    }

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return true;
}

Result<bssl::UniquePtr<RSA>> getRsa(const std::vector<uint8_t>& publicKey) {
    bssl::UniquePtr<RSA> rsaPubkey(RSA_new());
    rsaPubkey->n = BN_new();
    rsaPubkey->e = BN_new();

    BN_bin2bn(publicKey.data(), publicKey.size(), rsaPubkey->n);
    BN_set_word(rsaPubkey->e, kRsaKeyExponent);

    return rsaPubkey;
}

Result<void> verifySignature(const std::string& message, const std::string& signature,
                             const std::vector<uint8_t>& publicKey) {
    auto rsaKey = getRsa(publicKey);
    uint8_t hashBuf[SHA256_DIGEST_LENGTH];
    SHA256(const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(message.c_str())),
           message.length(), hashBuf);

    bool success = RSA_verify(NID_sha256, hashBuf, sizeof(hashBuf),
                              (const uint8_t*)signature.c_str(), signature.length(), rsaKey->get());

    if (!success) {
        return Error() << "Failed to verify signature.";
    }
    return {};
}

Result<void> createSelfSignedCertificate(
    const std::vector<uint8_t>& publicKey,
    const std::function<Result<std::string>(const std::string&)>& signFunction,
    const std::string& path) {
    bssl::UniquePtr<X509> x509(X509_new());
    if (!x509) {
        return Error() << "Unable to allocate x509 container";
    }
    X509_set_version(x509.get(), 2);

    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);
    X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x509.get()), kCertLifetimeSeconds);

    // "publicKey" corresponds to the raw public key bytes - need to create
    // a new RSA key with the correct exponent.
    auto rsaPubkey = getRsa(publicKey);

    EVP_PKEY* public_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(public_key, rsaPubkey->release());

    if (!X509_set_pubkey(x509.get(), public_key)) {
        return Error() << "Unable to set x509 public key";
    }

    X509_NAME* name = X509_get_subject_name(x509.get());
    if (!name) {
        return Error() << "Unable to get x509 subject name";
    }
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("US"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("Android"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("ODS"), -1, -1, 0);
    if (!X509_set_issuer_name(x509.get(), name)) {
        return Error() << "Unable to set x509 issuer name";
    }

    add_ext(x509.get(), NID_basic_constraints, kBasicConstraints);
    add_ext(x509.get(), NID_key_usage, kKeyUsage);
    add_ext(x509.get(), NID_subject_key_identifier, kSubjectKeyIdentifier);
    add_ext(x509.get(), NID_authority_key_identifier, "keyid:always");

    X509_ALGOR_set0(x509->cert_info->signature, OBJ_nid2obj(NID_sha256WithRSAEncryption),
                    V_ASN1_NULL, NULL);
    X509_ALGOR_set0(x509->sig_alg, OBJ_nid2obj(NID_sha256WithRSAEncryption), V_ASN1_NULL, NULL);

    // Get the data to be signed
    char* to_be_signed_buf(nullptr);
    size_t to_be_signed_length = i2d_re_X509_tbs(x509.get(), (unsigned char**)&to_be_signed_buf);

    auto signed_data = signFunction(std::string(to_be_signed_buf, to_be_signed_length));
    if (!signed_data.ok()) {
        return signed_data.error();
    }

    // This is the only part that doesn't use boringssl default functions - we manually copy in the
    // signature that was provided to us.
    x509->signature->data = (unsigned char*)OPENSSL_malloc(signed_data->size());
    memcpy(x509->signature->data, signed_data->c_str(), signed_data->size());
    x509->signature->length = signed_data->size();

    x509->signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    x509->signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    auto f = fopen(path.c_str(), "wbe");
    if (f == nullptr) {
        return Error() << "Failed to open " << path;
    }
    i2d_X509_fp(f, x509.get());
    fclose(f);

    EVP_PKEY_free(public_key);
    return {};
}

Result<std::vector<uint8_t>> extractPublicKey(EVP_PKEY* pkey) {
    if (pkey == nullptr) {
        return Error() << "Failed to extract public key from x509 cert";
    }

    if (EVP_PKEY_type(pkey->type) != EVP_PKEY_RSA) {
        return Error() << "The public key is not an RSA key";
    }

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    auto num_bytes = BN_num_bytes(rsa->n);
    std::vector<uint8_t> pubKey(num_bytes);
    int res = BN_bn2bin(rsa->n, pubKey.data());
    RSA_free(rsa);

    if (!res) {
        return Error() << "Failed to convert public key to bytes";
    }

    return pubKey;
}

Result<std::vector<uint8_t>>
extractPublicKeyFromSubjectPublicKeyInfo(const std::vector<uint8_t>& keyData) {
    auto keyDataBytes = keyData.data();
    EVP_PKEY* public_key = d2i_PUBKEY(nullptr, &keyDataBytes, keyData.size());

    return extractPublicKey(public_key);
}

Result<std::vector<uint8_t>> extractPublicKeyFromX509(const std::vector<uint8_t>& keyData) {
    auto keyDataBytes = keyData.data();
    bssl::UniquePtr<X509> decoded_cert(d2i_X509(nullptr, &keyDataBytes, keyData.size()));
    if (decoded_cert.get() == nullptr) {
        return Error() << "Failed to decode X509 certificate.";
    }
    bssl::UniquePtr<EVP_PKEY> decoded_pkey(X509_get_pubkey(decoded_cert.get()));

    return extractPublicKey(decoded_pkey.get());
}

Result<std::vector<uint8_t>> extractPublicKeyFromX509(const std::string& path) {
    X509* cert;
    auto f = fopen(path.c_str(), "re");
    if (f == nullptr) {
        return Error() << "Failed to open " << path;
    }
    if (!d2i_X509_fp(f, &cert)) {
        fclose(f);
        return Error() << "Unable to decode x509 cert at " << path;
    }

    fclose(f);
    return extractPublicKey(X509_get_pubkey(cert));
}

Result<std::vector<uint8_t>> createPkcs7(const std::vector<uint8_t>& signed_digest) {
    CBB out, outer_seq, wrapped_seq, seq, digest_algos_set, digest_algo, null;
    CBB content_info, issuer_and_serial, signer_infos, signer_info, sign_algo, signature;
    uint8_t *pkcs7_data, *name_der;
    size_t pkcs7_data_len, name_der_len;
    BIGNUM* serial = BN_new();
    int sig_nid = NID_rsaEncryption;

    X509_NAME* name = X509_NAME_new();
    if (!name) {
        return Error() << "Unable to get x509 subject name";
    }
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("US"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("Android"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("ODS"), -1, -1, 0);

    BN_set_word(serial, 1);
    name_der_len = i2d_X509_NAME(name, &name_der);
    CBB_init(&out, 1024);

    if (!CBB_add_asn1(&out, &outer_seq, CBS_ASN1_SEQUENCE) ||
        !OBJ_nid2cbb(&outer_seq, NID_pkcs7_signed) ||
        !CBB_add_asn1(&outer_seq, &wrapped_seq,
                      CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
        // See https://tools.ietf.org/html/rfc2315#section-9.1
        !CBB_add_asn1(&wrapped_seq, &seq, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1_uint64(&seq, 1 /* version */) ||
        !CBB_add_asn1(&seq, &digest_algos_set, CBS_ASN1_SET) ||
        !CBB_add_asn1(&digest_algos_set, &digest_algo, CBS_ASN1_SEQUENCE) ||
        !OBJ_nid2cbb(&digest_algo, NID_sha256) ||
        !CBB_add_asn1(&digest_algo, &null, CBS_ASN1_NULL) ||
        !CBB_add_asn1(&seq, &content_info, CBS_ASN1_SEQUENCE) ||
        !OBJ_nid2cbb(&content_info, NID_pkcs7_data) ||
        !CBB_add_asn1(&seq, &signer_infos, CBS_ASN1_SET) ||
        !CBB_add_asn1(&signer_infos, &signer_info, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1_uint64(&signer_info, 1 /* version */) ||
        !CBB_add_asn1(&signer_info, &issuer_and_serial, CBS_ASN1_SEQUENCE) ||
        !CBB_add_bytes(&issuer_and_serial, name_der, name_der_len) ||
        !BN_marshal_asn1(&issuer_and_serial, serial) ||
        !CBB_add_asn1(&signer_info, &digest_algo, CBS_ASN1_SEQUENCE) ||
        !OBJ_nid2cbb(&digest_algo, NID_sha256) ||
        !CBB_add_asn1(&digest_algo, &null, CBS_ASN1_NULL) ||
        !CBB_add_asn1(&signer_info, &sign_algo, CBS_ASN1_SEQUENCE) ||
        !OBJ_nid2cbb(&sign_algo, sig_nid) || !CBB_add_asn1(&sign_algo, &null, CBS_ASN1_NULL) ||
        !CBB_add_asn1(&signer_info, &signature, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&signature, signed_digest.data(), signed_digest.size()) ||
        !CBB_finish(&out, &pkcs7_data, &pkcs7_data_len)) {
        return Error() << "Failed to create PKCS7 certificate.";
    }

    return std::vector<uint8_t>(&pkcs7_data[0], &pkcs7_data[pkcs7_data_len]);
}
