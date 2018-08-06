/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "keystore"

#include "KeyStore.h"

#include <dirent.h>
#include <fcntl.h>

#include <openssl/bio.h>

#include <utils/String16.h>
#include <utils/String8.h>

#include <android-base/scopeguard.h>
#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>
#include <android/security/IKeystoreService.h>
#include <log/log_event_list.h>

#include <private/android_logger.h>

#include "keystore_utils.h"
#include "permissions.h"
#include <keystore/keystore_hidl_support.h>

namespace keystore {

const char* KeyStore::kOldMasterKey = ".masterkey";
const char* KeyStore::kMetaDataFile = ".metadata";

const android::String16 KeyStore::kRsaKeyType("RSA");
const android::String16 KeyStore::kEcKeyType("EC");

using android::String8;

sp<Keymaster>& KeymasterDevices::operator[](SecurityLevel secLevel) {
    static_assert(uint32_t(SecurityLevel::SOFTWARE) == 0 &&
                      uint32_t(SecurityLevel::TRUSTED_ENVIRONMENT) == 1 &&
                      uint32_t(SecurityLevel::STRONGBOX) == 2,
                  "Numeric values of security levels have changed");
    return at(static_cast<uint32_t>(secLevel));
}

sp<Keymaster> KeymasterDevices::operator[](SecurityLevel secLevel) const {
    if (static_cast<uint32_t>(secLevel) > static_cast<uint32_t>(SecurityLevel::STRONGBOX)) {
        LOG(ERROR) << "Invalid security level requested";
        return nullptr;
    }
    return (*const_cast<KeymasterDevices*>(this))[secLevel];
}

KeyStore::KeyStore(Entropy* entropy, const KeymasterDevices& kmDevices,
                   SecurityLevel minimalAllowedSecurityLevelForNewKeys)
    : mEntropy(entropy), mKmDevices(kmDevices),
      mAllowNewFallback(minimalAllowedSecurityLevelForNewKeys == SecurityLevel::SOFTWARE) {
    memset(&mMetaData, '\0', sizeof(mMetaData));
}

KeyStore::~KeyStore() {
    for (android::Vector<UserState*>::iterator it(mMasterKeys.begin()); it != mMasterKeys.end();
         it++) {
        delete *it;
    }
    mMasterKeys.clear();
}

ResponseCode KeyStore::initialize() {
    readMetaData();
    if (upgradeKeystore()) {
        writeMetaData();
    }

    return ResponseCode::NO_ERROR;
}

ResponseCode KeyStore::initializeUser(const android::String8& pw, uid_t userId) {
    UserState* userState = getUserState(userId);
    return userState->initialize(pw, mEntropy);
}

ResponseCode KeyStore::copyMasterKey(uid_t srcUser, uid_t dstUser) {
    UserState* userState = getUserState(dstUser);
    UserState* initState = getUserState(srcUser);
    return userState->copyMasterKey(initState);
}

ResponseCode KeyStore::writeMasterKey(const android::String8& pw, uid_t userId) {
    UserState* userState = getUserState(userId);
    return userState->writeMasterKey(pw, mEntropy);
}

ResponseCode KeyStore::readMasterKey(const android::String8& pw, uid_t userId) {
    UserState* userState = getUserState(userId);
    return userState->readMasterKey(pw, mEntropy);
}

/* Here is the encoding of keys. This is necessary in order to allow arbitrary
 * characters in keys. Characters in [0-~] are not encoded. Others are encoded
 * into two bytes. The first byte is one of [+-.] which represents the first
 * two bits of the character. The second byte encodes the rest of the bits into
 * [0-o]. Therefore in the worst case the length of a key gets doubled. Note
 * that Base64 cannot be used here due to the need of prefix match on keys. */

static size_t encode_key_length(const android::String8& keyName) {
    const uint8_t* in = reinterpret_cast<const uint8_t*>(keyName.string());
    size_t length = keyName.length();
    for (int i = length; i > 0; --i, ++in) {
        if (*in < '0' || *in > '~') {
            ++length;
        }
    }
    return length;
}

static int encode_key(char* out, const android::String8& keyName) {
    const uint8_t* in = reinterpret_cast<const uint8_t*>(keyName.string());
    size_t length = keyName.length();
    for (int i = length; i > 0; --i, ++in, ++out) {
        if (*in < '0' || *in > '~') {
            *out = '+' + (*in >> 6);
            *++out = '0' + (*in & 0x3F);
            ++length;
        } else {
            *out = *in;
        }
    }
    *out = '\0';
    return length;
}

android::String8 KeyStore::getKeyName(const android::String8& keyName, const BlobType type) {
    std::vector<char> encoded(encode_key_length(keyName) + 1);  // add 1 for null char
    encode_key(encoded.data(), keyName);
    if (type == TYPE_KEY_CHARACTERISTICS) {
        return android::String8::format(".chr_%s", encoded.data());
    } else {
        return android::String8(encoded.data());
    }
}

android::String8 KeyStore::getKeyNameForUid(const android::String8& keyName, uid_t uid,
                                            const BlobType type) {
    std::vector<char> encoded(encode_key_length(keyName) + 1);  // add 1 for null char
    encode_key(encoded.data(), keyName);
    if (type == TYPE_KEY_CHARACTERISTICS) {
        return android::String8::format(".%u_chr_%s", uid, encoded.data());
    } else {
        return android::String8::format("%u_%s", uid, encoded.data());
    }
}

android::String8 KeyStore::getKeyNameForUidWithDir(const android::String8& keyName, uid_t uid,
                                                   const BlobType type) {
    std::vector<char> encoded(encode_key_length(keyName) + 1);  // add 1 for null char
    encode_key(encoded.data(), keyName);

    if (type == TYPE_KEY_CHARACTERISTICS) {
        return android::String8::format("%s/.%u_chr_%s", getUserStateByUid(uid)->getUserDirName(),
                                        uid, encoded.data());
    } else {
        return android::String8::format("%s/%u_%s", getUserStateByUid(uid)->getUserDirName(), uid,
                                        encoded.data());
    }
}

NullOr<android::String8> KeyStore::getBlobFileNameIfExists(const android::String8& alias, uid_t uid,
                                                           const BlobType type) {
    android::String8 filepath8(getKeyNameForUidWithDir(alias, uid, type));

    if (!access(filepath8.string(), R_OK | W_OK)) return filepath8;

    // If this is one of the legacy UID->UID mappings, use it.
    uid_t euid = get_keystore_euid(uid);
    if (euid != uid) {
        filepath8 = getKeyNameForUidWithDir(alias, euid, type);
        if (!access(filepath8.string(), R_OK | W_OK)) return filepath8;
    }

    // They might be using a granted key.
    auto grant = mGrants.get(uid, alias.string());
    if (grant) {
        filepath8 = String8::format(
            "%s/%s", grant->owner_dir_name_.c_str(),
            getKeyNameForUid(String8(grant->alias_.c_str()), grant->owner_uid_, type).c_str());
        if (!access(filepath8.string(), R_OK | W_OK)) return filepath8;
    }
    return {};
}

void KeyStore::resetUser(uid_t userId, bool keepUnenryptedEntries) {
    android::String8 prefix("");
    android::Vector<android::String16> aliases;
    UserState* userState = getUserState(userId);
    if (list(prefix, &aliases, userId) != ResponseCode::NO_ERROR) {
        return;
    }
    for (uint32_t i = 0; i < aliases.size(); i++) {
        android::String8 filename(aliases[i]);
        filename = android::String8::format("%s/%s", userState->getUserDirName(),
                                            getKeyName(filename, TYPE_ANY).string());
        bool shouldDelete = true;
        if (keepUnenryptedEntries) {
            Blob blob;
            ResponseCode rc = get(filename, &blob, ::TYPE_ANY, userId);

            switch (rc) {
            case ResponseCode::SYSTEM_ERROR:
            case ResponseCode::VALUE_CORRUPTED:
                // If we can't read blobs, delete them.
                shouldDelete = true;
                break;

            case ResponseCode::NO_ERROR:
            case ResponseCode::LOCKED:
                // Delete encrypted blobs but keep unencrypted blobs and super-encrypted blobs.  We
                // need to keep super-encrypted blobs so we can report that the user is
                // unauthenticated if a caller tries to use them, rather than reporting that they
                // don't exist.
                shouldDelete = blob.isEncrypted();
                break;

            default:
                ALOGE("Got unexpected return code %d from KeyStore::get()", rc);
                // This shouldn't happen.  To be on the safe side, delete it.
                shouldDelete = true;
                break;
            }
        }
        if (shouldDelete) {
            del(filename, ::TYPE_ANY, userId);

            // del() will fail silently if no cached characteristics are present for this alias.
            android::String8 chr_filename(aliases[i]);
            chr_filename = android::String8::format(
                "%s/%s", userState->getUserDirName(),
                getKeyName(chr_filename, TYPE_KEY_CHARACTERISTICS).string());
            del(chr_filename, ::TYPE_KEY_CHARACTERISTICS, userId);
        }
    }
    if (!userState->deleteMasterKey()) {
        ALOGE("Failed to delete user %d's master key", userId);
    }
    if (!keepUnenryptedEntries) {
        if (!userState->reset()) {
            ALOGE("Failed to remove user %d's directory", userId);
        }
    }
}

bool KeyStore::isEmpty(uid_t userId) const {
    const UserState* userState = getUserState(userId);
    if (userState == nullptr) {
        return true;
    }

    DIR* dir = opendir(userState->getUserDirName());
    if (!dir) {
        return true;
    }

    bool result = true;
    struct dirent* file;
    while ((file = readdir(dir)) != nullptr) {
        // We only care about files.
        if (file->d_type != DT_REG) {
            continue;
        }

        // Skip anything that starts with a "."
        if (file->d_name[0] == '.') {
            continue;
        }

        result = false;
        break;
    }
    closedir(dir);
    return result;
}

void KeyStore::lock(uid_t userId) {
    UserState* userState = getUserState(userId);
    userState->zeroizeMasterKeysInMemory();
    userState->setState(STATE_LOCKED);
}

static void maybeLogKeyIntegrityViolation(const char* filename, const BlobType type);

ResponseCode KeyStore::get(const char* filename, Blob* keyBlob, const BlobType type, uid_t userId) {
    UserState* userState = getUserState(userId);
    ResponseCode rc;

    auto logOnScopeExit = android::base::make_scope_guard([&] {
        if (rc == ResponseCode::VALUE_CORRUPTED) {
            maybeLogKeyIntegrityViolation(filename, type);
        }
    });

    rc = keyBlob->readBlob(filename, userState->getEncryptionKey(), userState->getState());
    if (rc != ResponseCode::NO_ERROR) {
        return rc;
    }

    const uint8_t version = keyBlob->getVersion();
    if (version < CURRENT_BLOB_VERSION) {
        /* If we upgrade the key, we need to write it to disk again. Then
         * it must be read it again since the blob is encrypted each time
         * it's written.
         */
        if (upgradeBlob(filename, keyBlob, version, type, userId)) {
            if ((rc = this->put(filename, keyBlob, userId)) != ResponseCode::NO_ERROR ||
                (rc = keyBlob->readBlob(filename, userState->getEncryptionKey(),
                                        userState->getState())) != ResponseCode::NO_ERROR) {
                return rc;
            }
        }
    }

    /*
     * This will upgrade software-backed keys to hardware-backed keys.
     */
    if (rc == ResponseCode::NO_ERROR && type == TYPE_KEY_PAIR && keyBlob->isFallback()) {
        ResponseCode imported =
            importKey(keyBlob->getValue(), keyBlob->getLength(), filename, userId,
                      keyBlob->isEncrypted() ? KEYSTORE_FLAG_ENCRYPTED : KEYSTORE_FLAG_NONE);

        // The HAL allowed the import, reget the key to have the "fresh" version.
        if (imported == ResponseCode::NO_ERROR) {
            rc = get(filename, keyBlob, TYPE_KEY_PAIR, userId);
        }
    }

    // Keymaster 0.3 keys are valid keymaster 1.0 keys, so silently upgrade.
    if (keyBlob->getType() == TYPE_KEY_PAIR) {
        keyBlob->setType(TYPE_KEYMASTER_10);
        rc = this->put(filename, keyBlob, userId);
    }

    if (type != TYPE_ANY && keyBlob->getType() != type) {
        ALOGW("key found but type doesn't match: %d vs %d", keyBlob->getType(), type);
        return ResponseCode::KEY_NOT_FOUND;
    }

    return rc;
}

ResponseCode KeyStore::put(const char* filename, Blob* keyBlob, uid_t userId) {
    UserState* userState = getUserState(userId);
    return keyBlob->writeBlob(filename, userState->getEncryptionKey(), userState->getState(),
                              mEntropy);
}

static NullOr<std::tuple<uid_t, std::string>> filename2UidAlias(const std::string& filename);

ResponseCode KeyStore::del(const char* filename, const BlobType type, uid_t userId) {
    Blob keyBlob;
    auto uidAlias = filename2UidAlias(filename);
    uid_t uid;
    std::string alias;
    if (uidAlias.isOk()) {
        std::tie(uid, alias) = std::move(uidAlias).value();
    }
    ResponseCode rc = get(filename, &keyBlob, type, userId);
    if (rc == ResponseCode::VALUE_CORRUPTED) {
        // The file is corrupt, the best we can do is rm it.
        if (uidAlias.isOk()) {
            // remove possible grants
            mGrants.removeAllGrantsToKey(uid, alias);
        }
        return (unlink(filename) && errno != ENOENT) ? ResponseCode::SYSTEM_ERROR
                                                     : ResponseCode::NO_ERROR;
    }
    if (rc != ResponseCode::NO_ERROR) {
        return rc;
    }

    auto dev = getDevice(keyBlob);

    if (keyBlob.getType() == ::TYPE_KEY_PAIR || keyBlob.getType() == ::TYPE_KEYMASTER_10) {
        auto ret = KS_HANDLE_HIDL_ERROR(dev->deleteKey(blob2hidlVec(keyBlob)));

        // A device doesn't have to implement delete_key.
        bool success = ret == ErrorCode::OK || ret == ErrorCode::UNIMPLEMENTED;
        if (__android_log_security() && uidAlias.isOk()) {
            android_log_event_list(SEC_TAG_KEY_DESTROYED)
                << int32_t(success) << alias << int32_t(uid) << LOG_ID_SECURITY;
        }
        if (!success) return ResponseCode::SYSTEM_ERROR;
    }

    rc =
        (unlink(filename) && errno != ENOENT) ? ResponseCode::SYSTEM_ERROR : ResponseCode::NO_ERROR;

    if (rc == ResponseCode::NO_ERROR && keyBlob.getType() != ::TYPE_KEY_CHARACTERISTICS) {
        // now that we have successfully deleted a key, let's make sure there are no stale grants
        if (uidAlias.isOk()) {
            mGrants.removeAllGrantsToKey(uid, alias);
        }
    }
    return rc;
}

/*
 * Converts from the "escaped" format on disk to actual name.
 * This will be smaller than the input string.
 *
 * Characters that should combine with the next at the end will be truncated.
 */
static size_t decode_key_length(const char* in, size_t length) {
    size_t outLength = 0;

    for (const char* end = in + length; in < end; in++) {
        /* This combines with the next character. */
        if (*in < '0' || *in > '~') {
            continue;
        }

        outLength++;
    }
    return outLength;
}

static void decode_key(char* out, const char* in, size_t length) {
    for (const char* end = in + length; in < end; in++) {
        if (*in < '0' || *in > '~') {
            /* Truncate combining characters at the end. */
            if (in + 1 >= end) {
                break;
            }

            *out = (*in++ - '+') << 6;
            *out++ |= (*in - '0') & 0x3F;
        } else {
            *out++ = *in;
        }
    }
    *out = '\0';
}

static NullOr<std::tuple<uid_t, std::string>> filename2UidAlias(const std::string& filepath) {
    auto filenamebase = filepath.find_last_of('/');
    std::string filename =
        filenamebase == std::string::npos ? filepath : filepath.substr(filenamebase + 1);

    if (filename[0] == '.') return {};

    auto sep = filename.find('_');
    if (sep == std::string::npos) return {};

    std::stringstream s(filename.substr(0, sep));
    uid_t uid;
    s >> uid;
    if (!s) return {};

    auto alias = filename.substr(sep + 1);

    std::vector<char> alias_buffer(decode_key_length(alias.c_str(), alias.size()) + 1);

    decode_key(alias_buffer.data(), alias.c_str(), alias.size());
    return std::tuple<uid_t, std::string>(uid, alias_buffer.data());
}

ResponseCode KeyStore::list(const android::String8& prefix,
                            android::Vector<android::String16>* matches, uid_t userId) {

    UserState* userState = getUserState(userId);
    size_t n = prefix.length();

    DIR* dir = opendir(userState->getUserDirName());
    if (!dir) {
        ALOGW("can't open directory for user: %s", strerror(errno));
        return ResponseCode::SYSTEM_ERROR;
    }

    struct dirent* file;
    while ((file = readdir(dir)) != nullptr) {
        // We only care about files.
        if (file->d_type != DT_REG) {
            continue;
        }

        // Skip anything that starts with a "."
        if (file->d_name[0] == '.') {
            continue;
        }

        if (!strncmp(prefix.string(), file->d_name, n)) {
            const char* p = &file->d_name[n];
            size_t plen = strlen(p);

            size_t extra = decode_key_length(p, plen);
            char* match = (char*)malloc(extra + 1);
            if (match != nullptr) {
                decode_key(match, p, plen);
                matches->push(android::String16(match, extra));
                free(match);
            } else {
                ALOGW("could not allocate match of size %zd", extra);
            }
        }
    }
    closedir(dir);
    return ResponseCode::NO_ERROR;
}

std::string KeyStore::addGrant(const char* alias, uid_t granterUid, uid_t granteeUid) {
    return mGrants.put(granteeUid, alias, getUserStateByUid(granterUid)->getUserDirName(),
                       granterUid);
}

bool KeyStore::removeGrant(const char* alias, const uid_t granterUid, const uid_t granteeUid) {
    return mGrants.removeByFileAlias(granteeUid, granterUid, alias);
}
void KeyStore::removeAllGrantsToUid(const uid_t granteeUid) {
    mGrants.removeAllGrantsToUid(granteeUid);
}

ResponseCode KeyStore::importKey(const uint8_t* key, size_t keyLen, const char* filename,
                                 uid_t userId, int32_t flags) {
    Unique_PKCS8_PRIV_KEY_INFO pkcs8(d2i_PKCS8_PRIV_KEY_INFO(nullptr, &key, keyLen));
    if (!pkcs8.get()) {
        return ResponseCode::SYSTEM_ERROR;
    }
    Unique_EVP_PKEY pkey(EVP_PKCS82PKEY(pkcs8.get()));
    if (!pkey.get()) {
        return ResponseCode::SYSTEM_ERROR;
    }
    int type = EVP_PKEY_type(pkey->type);
    AuthorizationSet params;
    add_legacy_key_authorizations(type, &params);
    switch (type) {
    case EVP_PKEY_RSA:
        params.push_back(TAG_ALGORITHM, Algorithm::RSA);
        break;
    case EVP_PKEY_EC:
        params.push_back(TAG_ALGORITHM, Algorithm::EC);
        break;
    default:
        ALOGW("Unsupported key type %d", type);
        return ResponseCode::SYSTEM_ERROR;
    }

    AuthorizationSet opParams(params);
    hidl_vec<uint8_t> blob;

    ErrorCode error;
    auto hidlCb = [&](ErrorCode ret, const hidl_vec<uint8_t>& keyBlob,
                      const KeyCharacteristics& /* ignored */) {
        error = ret;
        if (error != ErrorCode::OK) return;
        blob = keyBlob;
    };
    auto input = blob2hidlVec(key, keyLen);

    SecurityLevel securityLevel = flagsToSecurityLevel(flags);
    auto kmDevice = getDevice(securityLevel);
    if (!kmDevice) {
        // As of this writing the only caller is KeyStore::get in an attempt to import legacy
        // software keys. It only ever requests TEE as target which must always be present.
        // If we see this error, we probably have a new and unanticipated caller.
        ALOGE("No implementation for security level %d. Cannot import key.", securityLevel);
        return ResponseCode::SYSTEM_ERROR;
    }

    ErrorCode rc = KS_HANDLE_HIDL_ERROR(
        kmDevice->importKey(params.hidl_data(), KeyFormat::PKCS8, input, hidlCb));
    if (rc != ErrorCode::OK) return ResponseCode::SYSTEM_ERROR;
    if (error != ErrorCode::OK) {
        ALOGE("Keymaster error %d importing key pair", error);
        return ResponseCode::SYSTEM_ERROR;
    }

    Blob keyBlob(&blob[0], blob.size(), nullptr, 0, TYPE_KEYMASTER_10);

    keyBlob.setEncrypted(flags & KEYSTORE_FLAG_ENCRYPTED);
    keyBlob.setSecurityLevel(securityLevel);

    return put(filename, &keyBlob, userId);
}

bool KeyStore::isHardwareBacked(const android::String16& keyType) const {
    // if strongbox device is present TEE must also be present and of sufficiently high version
    // to support all keys in hardware
    if (getDevice(SecurityLevel::STRONGBOX)) return true;
    if (!getDevice(SecurityLevel::TRUSTED_ENVIRONMENT)) {
        ALOGW("can't get keymaster device");
        return false;
    }

    auto version = getDevice(SecurityLevel::TRUSTED_ENVIRONMENT)->halVersion();
    if (keyType == kRsaKeyType) return true;  // All versions support RSA
    return keyType == kEcKeyType && version.supportsEc;
}

ResponseCode KeyStore::getKeyForName(Blob* keyBlob, const android::String8& keyName,
                                     const uid_t uid, const BlobType type) {
    auto filepath8 = getBlobFileNameIfExists(keyName, uid, type);
    uid_t userId = get_user_id(uid);

    if (filepath8.isOk()) return get(filepath8.value().string(), keyBlob, type, userId);

    return ResponseCode::KEY_NOT_FOUND;
}

UserState* KeyStore::getUserState(uid_t userId) {
    for (android::Vector<UserState*>::iterator it(mMasterKeys.begin()); it != mMasterKeys.end();
         it++) {
        UserState* state = *it;
        if (state->getUserId() == userId) {
            return state;
        }
    }

    UserState* userState = new UserState(userId);
    if (!userState->initialize()) {
        /* There's not much we can do if initialization fails. Trying to
         * unlock the keystore for that user will fail as well, so any
         * subsequent request for this user will just return SYSTEM_ERROR.
         */
        ALOGE("User initialization failed for %u; subsuquent operations will fail", userId);
    }
    mMasterKeys.add(userState);
    return userState;
}

UserState* KeyStore::getUserStateByUid(uid_t uid) {
    uid_t userId = get_user_id(uid);
    return getUserState(userId);
}

const UserState* KeyStore::getUserState(uid_t userId) const {
    for (android::Vector<UserState*>::const_iterator it(mMasterKeys.begin());
         it != mMasterKeys.end(); it++) {
        UserState* state = *it;
        if (state->getUserId() == userId) {
            return state;
        }
    }

    return nullptr;
}

const UserState* KeyStore::getUserStateByUid(uid_t uid) const {
    uid_t userId = get_user_id(uid);
    return getUserState(userId);
}

bool KeyStore::upgradeBlob(const char* filename, Blob* blob, const uint8_t oldVersion,
                           const BlobType type, uid_t userId) {
    bool updated = false;
    uint8_t version = oldVersion;

    /* From V0 -> V1: All old types were unknown */
    if (version == 0) {
        ALOGV("upgrading to version 1 and setting type %d", type);

        blob->setType(type);
        if (type == TYPE_KEY_PAIR) {
            importBlobAsKey(blob, filename, userId);
        }
        version = 1;
        updated = true;
    }

    /* From V1 -> V2: All old keys were encrypted */
    if (version == 1) {
        ALOGV("upgrading to version 2");

        blob->setEncrypted(true);
        version = 2;
        updated = true;
    }

    /*
     * If we've updated, set the key blob to the right version
     * and write it.
     */
    if (updated) {
        ALOGV("updated and writing file %s", filename);
        blob->setVersion(version);
    }

    return updated;
}

struct BIO_Delete {
    void operator()(BIO* p) const { BIO_free(p); }
};
typedef std::unique_ptr<BIO, BIO_Delete> Unique_BIO;

ResponseCode KeyStore::importBlobAsKey(Blob* blob, const char* filename, uid_t userId) {
    // We won't even write to the blob directly with this BIO, so const_cast is okay.
    Unique_BIO b(BIO_new_mem_buf(const_cast<uint8_t*>(blob->getValue()), blob->getLength()));
    if (b.get() == nullptr) {
        ALOGE("Problem instantiating BIO");
        return ResponseCode::SYSTEM_ERROR;
    }

    Unique_EVP_PKEY pkey(PEM_read_bio_PrivateKey(b.get(), nullptr, nullptr, nullptr));
    if (pkey.get() == nullptr) {
        ALOGE("Couldn't read old PEM file");
        return ResponseCode::SYSTEM_ERROR;
    }

    Unique_PKCS8_PRIV_KEY_INFO pkcs8(EVP_PKEY2PKCS8(pkey.get()));
    int len = i2d_PKCS8_PRIV_KEY_INFO(pkcs8.get(), nullptr);
    if (len < 0) {
        ALOGE("Couldn't measure PKCS#8 length");
        return ResponseCode::SYSTEM_ERROR;
    }

    std::unique_ptr<unsigned char[]> pkcs8key(new unsigned char[len]);
    uint8_t* tmp = pkcs8key.get();
    if (i2d_PKCS8_PRIV_KEY_INFO(pkcs8.get(), &tmp) != len) {
        ALOGE("Couldn't convert to PKCS#8");
        return ResponseCode::SYSTEM_ERROR;
    }

    ResponseCode rc = importKey(pkcs8key.get(), len, filename, userId,
                                blob->isEncrypted() ? KEYSTORE_FLAG_ENCRYPTED : KEYSTORE_FLAG_NONE);
    if (rc != ResponseCode::NO_ERROR) {
        return rc;
    }

    return get(filename, blob, TYPE_KEY_PAIR, userId);
}

void KeyStore::readMetaData() {
    int in = TEMP_FAILURE_RETRY(open(kMetaDataFile, O_RDONLY));
    if (in < 0) {
        return;
    }
    size_t fileLength = readFully(in, (uint8_t*)&mMetaData, sizeof(mMetaData));
    if (fileLength != sizeof(mMetaData)) {
        ALOGI("Metadata file is %zd bytes (%zd experted); upgrade?", fileLength, sizeof(mMetaData));
    }
    close(in);
}

void KeyStore::writeMetaData() {
    const char* tmpFileName = ".metadata.tmp";
    int out =
        TEMP_FAILURE_RETRY(open(tmpFileName, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR));
    if (out < 0) {
        ALOGE("couldn't write metadata file: %s", strerror(errno));
        return;
    }
    size_t fileLength = writeFully(out, (uint8_t*)&mMetaData, sizeof(mMetaData));
    if (fileLength != sizeof(mMetaData)) {
        ALOGI("Could only write %zd bytes to metadata file (%zd expected)", fileLength,
              sizeof(mMetaData));
    }
    close(out);
    rename(tmpFileName, kMetaDataFile);
}

bool KeyStore::upgradeKeystore() {
    bool upgraded = false;

    if (mMetaData.version == 0) {
        UserState* userState = getUserStateByUid(0);

        // Initialize first so the directory is made.
        userState->initialize();

        // Migrate the old .masterkey file to user 0.
        if (access(kOldMasterKey, R_OK) == 0) {
            if (rename(kOldMasterKey, userState->getMasterKeyFileName()) < 0) {
                ALOGE("couldn't migrate old masterkey: %s", strerror(errno));
                return false;
            }
        }

        // Initialize again in case we had a key.
        userState->initialize();

        // Try to migrate existing keys.
        DIR* dir = opendir(".");
        if (!dir) {
            // Give up now; maybe we can upgrade later.
            ALOGE("couldn't open keystore's directory; something is wrong");
            return false;
        }

        struct dirent* file;
        while ((file = readdir(dir)) != nullptr) {
            // We only care about files.
            if (file->d_type != DT_REG) {
                continue;
            }

            // Skip anything that starts with a "."
            if (file->d_name[0] == '.') {
                continue;
            }

            // Find the current file's user.
            char* end;
            unsigned long thisUid = strtoul(file->d_name, &end, 10);
            if (end[0] != '_' || end[1] == 0) {
                continue;
            }
            UserState* otherUser = getUserStateByUid(thisUid);
            if (otherUser->getUserId() != 0) {
                unlinkat(dirfd(dir), file->d_name, 0);
            }

            // Rename the file into user directory.
            DIR* otherdir = opendir(otherUser->getUserDirName());
            if (otherdir == nullptr) {
                ALOGW("couldn't open user directory for rename");
                continue;
            }
            if (renameat(dirfd(dir), file->d_name, dirfd(otherdir), file->d_name) < 0) {
                ALOGW("couldn't rename blob: %s: %s", file->d_name, strerror(errno));
            }
            closedir(otherdir);
        }
        closedir(dir);

        mMetaData.version = 1;
        upgraded = true;
    }

    return upgraded;
}

static void maybeLogKeyIntegrityViolation(const char* filename, const BlobType type) {
    if (!__android_log_security() || (type != TYPE_KEY_PAIR && type != TYPE_KEYMASTER_10)) return;

    auto uidAlias = filename2UidAlias(filename);
    uid_t uid = -1;
    std::string alias;

    if (uidAlias.isOk()) std::tie(uid, alias) = std::move(uidAlias).value();

    log_key_integrity_violation(alias.c_str(), uid);
}

}  // namespace keystore
