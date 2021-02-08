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

#include <gtest/gtest.h>

#include "certificate_utils.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>

#include <iomanip>
#include <iostream>
#include <sstream>
#include <variant>

#include "test_keys.h"

using namespace keystore;

// I leave these here in case they are needed for debugging.
namespace debug_utils {

void log_ssl_error() {
    unsigned long error = ERR_peek_last_error();

    char buf[128];
    ERR_error_string_n(error, buf, sizeof(buf));
    std::cout << "BoringSslError: " << buf << std::endl;
}

std::string hexdump(const std::vector<uint8_t>& data) {
    std::stringstream s;
    size_t column_count = 0;
    for (auto& c : data) {
        s << std::setw(2) << std::setfill('0') << std::hex << (unsigned int)c;
        if (++column_count % 40 == 0) s << "\n";
    }
    return s.str();
}

}  // namespace debug_utils

constexpr uint64_t kValidity = 24 * 60 * 60 * 1000;  // 24 hours in milliseconds

const EVP_MD* getMD(Digest digest) {
    switch (digest) {
    case Digest::SHA1:
        return EVP_sha1();
    case Digest::SHA224:
        return EVP_sha224();
    case Digest::SHA256:
        return EVP_sha256();
    case Digest::SHA384:
        return EVP_sha384();
    case Digest::SHA512:
        return EVP_sha512();
    }
}

std::array<Digest, 5> digests = {
    Digest::SHA1, Digest::SHA224, Digest::SHA256, Digest::SHA384, Digest::SHA512,
};

static const char* toString(Digest d) {
    switch (d) {
    case Digest::SHA1:
        return "SHA1";
    case Digest::SHA224:
        return "SHA224";
    case Digest::SHA256:
        return "SHA256";
    case Digest::SHA384:
        return "SHA384";
    case Digest::SHA512:
        return "SHA512";
    }
}

std::array<Padding, 2> rsa_paddings = {
    Padding::PSS,
    Padding::PKCS1_5,
};

enum class EcCurve {
    P224,
    P256,
    P384,
    P521,
};

std::array<int, 4> ec_curves = {
    NID_secp224r1,
    NID_X9_62_prime256v1,
    NID_secp384r1,
    NID_secp521r1,
};

static const char* curveNidToString(int nid) {
    switch (nid) {
    case NID_secp224r1:
        return "P224";
    case NID_X9_62_prime256v1:
        return "P256";
    case NID_secp384r1:
        return "P384";
    case NID_secp521r1:
        return "P521";
    default:
        return "Unknown";
    }
}

std::array<long, 2> rsa_key_sizes = {
    2048,
    4096,
};

using EcParam = std::tuple<int /* EC curve NID */, Digest>;

class CertificateUtilsWithEcCurve : public testing::TestWithParam<EcParam> {};

static std::string paramToStringEc(testing::TestParamInfo<EcParam> param) {
    std::stringstream s;
    auto [curve_nid, digest] = param.param;
    s << param.index << "_" << curveNidToString(curve_nid) << "_" << toString(digest);
    return s.str();
}

INSTANTIATE_TEST_SUITE_P(CertSigningWithCallbackEC, CertificateUtilsWithEcCurve,
                         testing::Combine(testing::ValuesIn(ec_curves), testing::ValuesIn(digests)),
                         paramToStringEc);

TEST_P(CertificateUtilsWithEcCurve, CertSigningWithCallbackEC) {
    // Structured decomposition (e.g.: auto [a, b, c] = ...) does not work here because
    // names bound this way cannot be captured in lambda expressions so we use std::tie instead.
    int curve_nid;
    Digest digest;
    std::tie(curve_nid, digest) = GetParam();
    EVP_PKEY_CTX_Ptr pkey_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));
    ASSERT_TRUE((bool)pkey_ctx);
    ASSERT_TRUE(EVP_PKEY_keygen_init(pkey_ctx.get()));
    ASSERT_TRUE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx.get(), curve_nid));

    EVP_PKEY* pkey_ptr = nullptr;
    ASSERT_TRUE(EVP_PKEY_keygen(pkey_ctx.get(), &pkey_ptr));
    EVP_PKEY_Ptr pkey(pkey_ptr);
    ASSERT_TRUE(pkey);

    uint64_t now_ms = (uint64_t)time(nullptr) * 1000;

    BasicConstraintsExtension bcons{
        .isCa = true,
        .pathLength = {},
    };

    KeyUsageExtension keyUsage{
        .isSigningKey = true,
        .isEncryptionKey = false,
        .isCertificationKey = true,
    };

    auto certV = makeCert(pkey.get(), std::nullopt, std::nullopt, now_ms - kValidity,
                          now_ms + kValidity, true /* subject key id extension */, keyUsage, bcons);
    ASSERT_TRUE(std::holds_alternative<X509_Ptr>(certV));
    auto& cert = std::get<X509_Ptr>(certV);
    ASSERT_TRUE(!setIssuer(cert.get(), cert.get(), true));

    ASSERT_TRUE(!signCertWith(
        cert.get(),
        [&](const uint8_t* data, size_t len) {
            bssl::ScopedEVP_MD_CTX sign_ctx;
            EXPECT_TRUE(
                EVP_DigestSignInit(sign_ctx.get(), nullptr, getMD(digest), nullptr, pkey.get()));

            std::vector<uint8_t> sig_buf(512);
            size_t sig_len = 512;
            EVP_DigestSign(sign_ctx.get(), sig_buf.data(), &sig_len, data, len);
            sig_buf.resize(sig_len);
            return sig_buf;
        },
        Algo::ECDSA, Padding::Ignored, digest));

    auto encCertV = encodeCert(cert.get());
    ASSERT_TRUE(std::holds_alternative<std::vector<uint8_t>>(encCertV));

    auto& encCert = std::get<1>(encCertV);
    // Uncomment the next line to dump the DER encoded signed certificate as hex string.
    // You can pipe this dump into  "xxd -r -p | openssl x509 -inform der -text -noout"
    // to inspect the certificate.
    // std::cout << "DER encoded cert:\n" << debug_utils::hexdump(encCert) << std::endl;

    const uint8_t* p = encCert.data();
    X509_Ptr decoded_cert(d2i_X509(nullptr, &p, (long)encCert.size()));
    EVP_PKEY_Ptr decoded_pkey(X509_get_pubkey(decoded_cert.get()));
    ASSERT_TRUE(X509_verify(decoded_cert.get(), decoded_pkey.get()));
}

using RsaParams = std::tuple<long /* key size */, Padding, Digest>;

class CertificateUtilsWithRsa : public testing::TestWithParam<RsaParams> {};

static std::string paramsToStringRsa(testing::TestParamInfo<RsaParams> param) {
    std::stringstream s;
    auto [key_size, padding, digest] = param.param;
    s << param.index << "_" << key_size << "_";
    switch (padding) {
    case Padding::PSS:
        s << "PSS";
        break;
    case Padding::PKCS1_5:
        s << "PKCS1_5";
        break;
    case Padding::Ignored:
        s << "Ignored";
    }
    s << "_" << toString(digest);
    return s.str();
}

INSTANTIATE_TEST_SUITE_P(CertSigningWithCallbackRsa, CertificateUtilsWithRsa,
                         testing::Combine(testing::ValuesIn(rsa_key_sizes),
                                          testing::ValuesIn(rsa_paddings),
                                          testing::ValuesIn(digests)),
                         paramsToStringRsa);

TEST_P(CertificateUtilsWithRsa, CertSigningWithCallbackRsa) {
    // Structured decomposition (e.g.: auto [a, b, c] = ...) does not work here because
    // names bound this way cannot be captured in lambda expressions so we use std::tie instead.
    long key_size;
    Padding padding;
    Digest digest;
    std::tie(key_size, padding, digest) = GetParam();

    CBS cbs;
    switch (key_size) {
    case 2048:
        CBS_init(&cbs, rsa_key_2k, rsa_key_2k_len);
        break;
    case 4096:
        CBS_init(&cbs, rsa_key_4k, rsa_key_4k_len);
        break;
    default:
        FAIL();
    }
    EVP_PKEY_Ptr pkey(EVP_parse_private_key(&cbs));
    ASSERT_TRUE(pkey);

    uint64_t now_ms = (uint64_t)time(nullptr) * 1000;

    BasicConstraintsExtension bcons{
        .isCa = true,
        .pathLength = 0,
    };

    KeyUsageExtension keyUsage{
        .isSigningKey = true,
        .isEncryptionKey = false,
        .isCertificationKey = true,
    };

    auto certV = makeCert(pkey.get(), std::nullopt, std::nullopt, now_ms - kValidity,
                          now_ms + kValidity, true /* subject key id extension */, keyUsage, bcons);
    ASSERT_TRUE(std::holds_alternative<X509_Ptr>(certV));
    auto& cert = std::get<X509_Ptr>(certV);
    ASSERT_TRUE(!setIssuer(cert.get(), cert.get(), true));

    ASSERT_TRUE(!signCertWith(
        cert.get(),
        [&](const uint8_t* data, size_t len) {
            bssl::ScopedEVP_MD_CTX sign_ctx;
            EVP_PKEY_CTX* pkey_sign_ctx_ptr;
            EXPECT_TRUE(EVP_DigestSignInit(sign_ctx.get(), &pkey_sign_ctx_ptr, getMD(digest),
                                           nullptr, pkey.get()));

            if (padding == Padding::PSS) {
                EXPECT_TRUE(EVP_PKEY_CTX_set_rsa_padding(pkey_sign_ctx_ptr, RSA_PKCS1_PSS_PADDING));
                EXPECT_TRUE(EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_sign_ctx_ptr, -1));
            } else {
                EXPECT_TRUE(EVP_PKEY_CTX_set_rsa_padding(pkey_sign_ctx_ptr, RSA_PKCS1_PADDING));
            }

            std::vector<uint8_t> sig_buf(1024);
            size_t sig_len = 1024;
            EVP_DigestSign(sign_ctx.get(), sig_buf.data(), &sig_len, data, len);
            sig_buf.resize(sig_len);
            return sig_buf;
        },
        Algo::RSA, padding, digest));

    auto encCertV = encodeCert(cert.get());
    ASSERT_TRUE(std::holds_alternative<std::vector<uint8_t>>(encCertV));

    auto& encCert = std::get<1>(encCertV);
    // Uncomment the next line to dump the DER encoded signed certificate as hex string.
    // You can pipe this dump into  "xxd -r -p | openssl x509 -inform der -text -noout"
    // to inspect the certificate.
    // std::cout << "DER encoded cert:\n" << debug_utils::hexdump(encCert) << std::endl;

    const uint8_t* p = encCert.data();
    X509_Ptr decoded_cert(d2i_X509(nullptr, &p, (long)encCert.size()));
    EVP_PKEY_Ptr decoded_pkey(X509_get_pubkey(decoded_cert.get()));
    ASSERT_TRUE(X509_verify(decoded_cert.get(), decoded_pkey.get()));
}
