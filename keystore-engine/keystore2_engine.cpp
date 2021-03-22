/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "keystore2_engine.h"

#include <aidl/android/system/keystore2/IKeystoreService.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android/binder_manager.h>

#include <private/android_filesystem_config.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#define AT __func__ << ":" << __LINE__ << " "

constexpr const char keystore2_service_name[] = "android.system.keystore2.IKeystoreService/default";
const std::string keystore2_grant_id_prefix("ks2_keystore-engine_grant_id:");

/**
 * Keystore 2.0 namespace identifiers.
 * Keep in sync with system/sepolicy/private/keystore2_key_contexts.
 */
constexpr const int64_t KS2_NAMESPACE_WIFI = 102;

namespace ks2 = ::aidl::android::system::keystore2;
namespace KMV1 = ::aidl::android::hardware::security::keymint;

namespace {

int64_t getNamespaceforCurrentUid() {
    auto uid = getuid();
    switch (uid) {
    case AID_WIFI:
        return KS2_NAMESPACE_WIFI;
    // 0 is the super user namespace, and nothing has access to this namespace on user builds.
    // So this will always fail.
    default:
        return 0;
    }
}

struct Keystore2KeyBackend {
    ks2::KeyDescriptor descriptor_;
    std::shared_ptr<ks2::IKeystoreSecurityLevel> i_keystore_security_level_;
};

/* key_backend_dup is called when one of the RSA or EC_KEY objects is duplicated. */
extern "C" int key_backend_dup(CRYPTO_EX_DATA* /* to */, const CRYPTO_EX_DATA* /* from */,
                               void** from_d, int /* index */, long /* argl */, void* /* argp */) {
    auto key_backend = reinterpret_cast<std::shared_ptr<Keystore2KeyBackend>*>(*from_d);
    if (key_backend != nullptr) {
        *from_d = new std::shared_ptr<Keystore2KeyBackend>(*key_backend);
    }
    return 1;
}

/* key_backend_free is called when one of the RSA, DSA or EC_KEY object is freed. */
extern "C" void key_backend_free(void* /* parent */, void* ptr, CRYPTO_EX_DATA* /* ad */,
                                 int /* index */, long /* argl */, void* /* argp */) {
    delete reinterpret_cast<std::shared_ptr<Keystore2KeyBackend>*>(ptr);
}

extern "C" int rsa_private_transform(RSA* rsa, uint8_t* out, const uint8_t* in, size_t len);
extern "C" int ecdsa_sign(const uint8_t* digest, size_t digest_len, uint8_t* sig,
                          unsigned int* sig_len, EC_KEY* ec_key);
/* KeystoreEngine is a BoringSSL ENGINE that implements RSA and ECDSA by
 * forwarding the requested operations to Keystore. */
class Keystore2Engine {
  public:
    Keystore2Engine()
        : rsa_index_(RSA_get_ex_new_index(0 /* argl */, nullptr /* argp */, nullptr /* new_func */,
                                          key_backend_dup, key_backend_free)),
          ec_key_index_(EC_KEY_get_ex_new_index(0 /* argl */, nullptr /* argp */,
                                                nullptr /* new_func */, key_backend_dup,
                                                key_backend_free)),
          engine_(ENGINE_new()) {
        memset(&rsa_method_, 0, sizeof(rsa_method_));
        rsa_method_.common.is_static = 1;
        rsa_method_.private_transform = rsa_private_transform;
        rsa_method_.flags = RSA_FLAG_OPAQUE;
        ENGINE_set_RSA_method(engine_, &rsa_method_, sizeof(rsa_method_));

        memset(&ecdsa_method_, 0, sizeof(ecdsa_method_));
        ecdsa_method_.common.is_static = 1;
        ecdsa_method_.sign = ecdsa_sign;
        ecdsa_method_.flags = ECDSA_FLAG_OPAQUE;
        ENGINE_set_ECDSA_method(engine_, &ecdsa_method_, sizeof(ecdsa_method_));
    }

    int rsa_ex_index() const { return rsa_index_; }
    int ec_key_ex_index() const { return ec_key_index_; }

    const ENGINE* engine() const { return engine_; }

    static const Keystore2Engine& get() {
        static Keystore2Engine engine;
        return engine;
    }

  private:
    const int rsa_index_;
    const int ec_key_index_;
    RSA_METHOD rsa_method_;
    ECDSA_METHOD ecdsa_method_;
    ENGINE* const engine_;
};

#define OWNERSHIP_TRANSFERRED(x) x.release()

/* wrap_rsa returns an |EVP_PKEY| that contains an RSA key where the public
 * part is taken from |public_rsa| and the private operations are forwarded to
 * KeyStore and operate on the key named |key_id|. */
bssl::UniquePtr<EVP_PKEY> wrap_rsa(std::shared_ptr<Keystore2KeyBackend> key_backend,
                                   const RSA* public_rsa) {
    bssl::UniquePtr<RSA> rsa(RSA_new_method(Keystore2Engine::get().engine()));
    if (rsa.get() == nullptr) {
        return nullptr;
    }

    auto key_backend_copy = new decltype(key_backend)(key_backend);

    if (!RSA_set_ex_data(rsa.get(), Keystore2Engine::get().rsa_ex_index(), key_backend_copy)) {
        delete key_backend_copy;
        return nullptr;
    }

    rsa->n = BN_dup(public_rsa->n);
    rsa->e = BN_dup(public_rsa->e);
    if (rsa->n == nullptr || rsa->e == nullptr) {
        return nullptr;
    }

    bssl::UniquePtr<EVP_PKEY> result(EVP_PKEY_new());
    if (result.get() == nullptr || !EVP_PKEY_assign_RSA(result.get(), rsa.get())) {
        return nullptr;
    }
    OWNERSHIP_TRANSFERRED(rsa);

    return result;
}

/* wrap_ecdsa returns an |EVP_PKEY| that contains an ECDSA key where the public
 * part is taken from |public_rsa| and the private operations are forwarded to
 * KeyStore and operate on the key named |key_id|. */
bssl::UniquePtr<EVP_PKEY> wrap_ecdsa(std::shared_ptr<Keystore2KeyBackend> key_backend,
                                     const EC_KEY* public_ecdsa) {
    bssl::UniquePtr<EC_KEY> ec(EC_KEY_new_method(Keystore2Engine::get().engine()));
    if (ec.get() == nullptr) {
        return nullptr;
    }

    if (!EC_KEY_set_group(ec.get(), EC_KEY_get0_group(public_ecdsa)) ||
        !EC_KEY_set_public_key(ec.get(), EC_KEY_get0_public_key(public_ecdsa))) {
        return nullptr;
    }

    auto key_backend_copy = new decltype(key_backend)(key_backend);

    if (!EC_KEY_set_ex_data(ec.get(), Keystore2Engine::get().ec_key_ex_index(), key_backend_copy)) {
        delete key_backend_copy;
        return nullptr;
    }

    bssl::UniquePtr<EVP_PKEY> result(EVP_PKEY_new());
    if (result.get() == nullptr || !EVP_PKEY_assign_EC_KEY(result.get(), ec.get())) {
        return nullptr;
    }
    OWNERSHIP_TRANSFERRED(ec);

    return result;
}

std::optional<std::vector<uint8_t>> keystore2_sign(const Keystore2KeyBackend& key_backend,
                                                   std::vector<uint8_t> input,
                                                   KMV1::Algorithm algorithm) {
    auto sec_level = key_backend.i_keystore_security_level_;
    ks2::CreateOperationResponse response;

    std::vector<KMV1::KeyParameter> op_params(4);
    op_params[0] = KMV1::KeyParameter{
        .tag = KMV1::Tag::PURPOSE,
        .value = KMV1::KeyParameterValue::make<KMV1::KeyParameterValue::keyPurpose>(
            KMV1::KeyPurpose::SIGN)};
    op_params[1] = KMV1::KeyParameter{
        .tag = KMV1::Tag::ALGORITHM,
        .value = KMV1::KeyParameterValue::make<KMV1::KeyParameterValue::algorithm>(algorithm)};
    op_params[2] = KMV1::KeyParameter{
        .tag = KMV1::Tag::PADDING,
        .value = KMV1::KeyParameterValue::make<KMV1::KeyParameterValue::paddingMode>(
            KMV1::PaddingMode::NONE)};
    op_params[3] =
        KMV1::KeyParameter{.tag = KMV1::Tag::DIGEST,
                           .value = KMV1::KeyParameterValue::make<KMV1::KeyParameterValue::digest>(
                               KMV1::Digest::NONE)};

    auto rc = sec_level->createOperation(key_backend.descriptor_, op_params, false /* forced */,
                                         &response);
    if (!rc.isOk()) {
        auto exception_code = rc.getExceptionCode();
        if (exception_code == EX_SERVICE_SPECIFIC) {
            LOG(ERROR) << AT << "Keystore createOperation returned service specific error: "
                       << rc.getServiceSpecificError();
        } else {
            LOG(ERROR) << AT << "Communication with Keystore createOperation failed error: "
                       << exception_code;
        }
        return std::nullopt;
    }

    auto op = response.iOperation;

    std::optional<std::vector<uint8_t>> output = std::nullopt;
    rc = op->finish(std::move(input), {}, &output);
    if (!rc.isOk()) {
        auto exception_code = rc.getExceptionCode();
        if (exception_code == EX_SERVICE_SPECIFIC) {
            LOG(ERROR) << AT << "Keystore finish returned service specific error: "
                       << rc.getServiceSpecificError();
        } else {
            LOG(ERROR) << AT
                       << "Communication with Keystore finish failed error: " << exception_code;
        }
        return std::nullopt;
    }

    if (!output) {
        LOG(ERROR) << AT << "We did not get a signature from Keystore.";
    }

    return output;
}

/* rsa_private_transform takes a big-endian integer from |in|, calculates the
 * d'th power of it, modulo the RSA modulus, and writes the result as a
 * big-endian integer to |out|. Both |in| and |out| are |len| bytes long. It
 * returns one on success and zero otherwise. */
extern "C" int rsa_private_transform(RSA* rsa, uint8_t* out, const uint8_t* in, size_t len) {
    auto key_backend = reinterpret_cast<std::shared_ptr<Keystore2KeyBackend>*>(
        RSA_get_ex_data(rsa, Keystore2Engine::get().rsa_ex_index()));

    if (key_backend == nullptr) {
        LOG(ERROR) << AT << "Invalid key.";
        return 0;
    }

    auto output =
        keystore2_sign(**key_backend, std::vector<uint8_t>(in, in + len), KMV1::Algorithm::RSA);
    if (!output) {
        return 0;
    }

    if (output->size() > len) {
        /* The result of the RSA operation can never be larger than the size of
         * the modulus so we assume that the result has extra zeros on the
         * left. This provides attackers with an oracle, but there's nothing
         * that we can do about it here. */
        LOG(WARNING) << "Reply len " << output->size() << " greater than expected " << len;
        memcpy(out, &output->data()[output->size() - len], len);
    } else if (output->size() < len) {
        /* If the Keystore implementation returns a short value we assume that
         * it's because it removed leading zeros from the left side. This is
         * bad because it provides attackers with an oracle but we cannot do
         * anything about a broken Keystore implementation here. */
        LOG(WARNING) << "Reply len " << output->size() << " less than expected " << len;
        memset(out, 0, len);
        memcpy(out + len - output->size(), output->data(), output->size());
    } else {
        memcpy(out, output->data(), len);
    }

    return 1;
}

/* ecdsa_sign signs |digest_len| bytes from |digest| with |ec_key| and writes
 * the resulting signature (an ASN.1 encoded blob) to |sig|. It returns one on
 * success and zero otherwise. */
extern "C" int ecdsa_sign(const uint8_t* digest, size_t digest_len, uint8_t* sig,
                          unsigned int* sig_len, EC_KEY* ec_key) {
    auto key_backend = reinterpret_cast<std::shared_ptr<Keystore2KeyBackend>*>(
        EC_KEY_get_ex_data(ec_key, Keystore2Engine::get().ec_key_ex_index()));

    if (key_backend == nullptr) {
        LOG(ERROR) << AT << "Invalid key.";
        return 0;
    }

    size_t ecdsa_size = ECDSA_size(ec_key);

    auto output = keystore2_sign(**key_backend, std::vector<uint8_t>(digest, digest + digest_len),
                                 KMV1::Algorithm::EC);
    if (!output) {
        LOG(ERROR) << "There was an error during ecdsa_sign.";
        return 0;
    }

    if (output->size() == 0) {
        LOG(ERROR) << "No valid signature returned";
        return 0;
    } else if (output->size() > ecdsa_size) {
        LOG(ERROR) << "Signature is too large";
        return 0;
    }

    memcpy(sig, output->data(), output->size());
    *sig_len = output->size();

    return 1;
}

}  // namespace

/* EVP_PKEY_from_keystore returns an |EVP_PKEY| that contains either an RSA or
 * ECDSA key where the public part of the key reflects the value of the key
 * named |key_id| in Keystore and the private operations are forwarded onto
 * KeyStore. */
extern "C" EVP_PKEY* EVP_PKEY_from_keystore2(const char* key_id) {
    ::ndk::SpAIBinder keystoreBinder(AServiceManager_checkService(keystore2_service_name));
    auto keystore2 = ks2::IKeystoreService::fromBinder(keystoreBinder);

    if (!keystore2) {
        LOG(ERROR) << AT << "Unable to connect to Keystore 2.0.";
        return nullptr;
    }

    std::string alias = key_id;
    if (android::base::StartsWith(alias, "USRPKEY_")) {
        LOG(WARNING) << AT << "Keystore backend used with legacy alias prefix - ignoring.";
        alias = alias.substr(8);
    }

    ks2::KeyDescriptor descriptor = {
        .domain = ks2::Domain::SELINUX,
        .nspace = getNamespaceforCurrentUid(),
        .alias = alias,
        .blob = std::nullopt,
    };

    // If the key_id starts with the grant id prefix, we parse the following string as numeric
    // grant id. We can then use the grant domain without alias to load the designated key.
    if (alias.find(keystore2_grant_id_prefix) == 0) {
        std::stringstream s(alias.substr(keystore2_grant_id_prefix.size()));
        s >> std::hex >> reinterpret_cast<uint64_t&>(descriptor.nspace);
        descriptor.domain = ks2::Domain::GRANT;
        descriptor.alias = std::nullopt;
    }

    ks2::KeyEntryResponse response;
    auto rc = keystore2->getKeyEntry(descriptor, &response);
    if (!rc.isOk()) {
        auto exception_code = rc.getExceptionCode();
        if (exception_code == EX_SERVICE_SPECIFIC) {
            LOG(ERROR) << AT << "Keystore getKeyEntry returned service specific error: "
                       << rc.getServiceSpecificError();
        } else {
            LOG(ERROR) << AT << "Communication with Keystore getKeyEntry failed error: "
                       << exception_code;
        }
        return nullptr;
    }

    if (!response.metadata.certificate) {
        LOG(ERROR) << AT << "No public key found.";
        return nullptr;
    }

    const uint8_t* p = response.metadata.certificate->data();
    bssl::UniquePtr<X509> x509(d2i_X509(nullptr, &p, response.metadata.certificate->size()));
    if (!x509) {
        LOG(ERROR) << AT << "Failed to parse x509 certificate.";
        return nullptr;
    }
    bssl::UniquePtr<EVP_PKEY> pkey(X509_get_pubkey(x509.get()));
    if (!pkey) {
        LOG(ERROR) << AT << "Failed to extract public key.";
        return nullptr;
    }

    auto key_backend = std::make_shared<Keystore2KeyBackend>(
        Keystore2KeyBackend{response.metadata.key, response.iSecurityLevel});

    bssl::UniquePtr<EVP_PKEY> result;
    switch (EVP_PKEY_type(pkey->type)) {
    case EVP_PKEY_RSA: {
        bssl::UniquePtr<RSA> public_rsa(EVP_PKEY_get1_RSA(pkey.get()));
        result = wrap_rsa(key_backend, public_rsa.get());
        break;
    }
    case EVP_PKEY_EC: {
        bssl::UniquePtr<EC_KEY> public_ecdsa(EVP_PKEY_get1_EC_KEY(pkey.get()));
        result = wrap_ecdsa(key_backend, public_ecdsa.get());
        break;
    }
    default:
        LOG(ERROR) << AT << "Unsupported key type " << EVP_PKEY_type(pkey->type);
        return nullptr;
    }

    return result.release();
}
