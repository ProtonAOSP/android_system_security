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

#include "keystore.h"

#include <dirent.h>
#include <fcntl.h>

#include <openssl/bio.h>

#include <utils/String16.h>

#include <keystore/IKeystoreService.h>

#include "keystore_utils.h"
#include "permissions.h"

const char* KeyStore::sOldMasterKey = ".masterkey";
const char* KeyStore::sMetaDataFile = ".metadata";

const android::String16 KeyStore::sRSAKeyType("RSA");

KeyStore::KeyStore(Entropy* entropy, keymaster2_device_t* device, keymaster2_device_t* fallback)
    : mEntropy(entropy), mDevice(device), mFallbackDevice(fallback) {
    memset(&mMetaData, '\0', sizeof(mMetaData));
}

KeyStore::~KeyStore() {
    for (android::Vector<grant_t*>::iterator it(mGrants.begin()); it != mGrants.end(); it++) {
        delete *it;
    }
    mGrants.clear();

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

    return ::NO_ERROR;
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
    char encoded[encode_key_length(keyName) + 1];  // add 1 for null char
    encode_key(encoded, keyName);
    if (type == TYPE_KEY_CHARACTERISTICS) {
        return android::String8::format(".chr_%s", encoded);
    } else {
        return android::String8(encoded);
    }
}

android::String8 KeyStore::getKeyNameForUid(
    const android::String8& keyName, uid_t uid, const BlobType type) {
    char encoded[encode_key_length(keyName) + 1];  // add 1 for null char
    encode_key(encoded, keyName);
    if (type == TYPE_KEY_CHARACTERISTICS) {
        return android::String8::format(".%u_chr_%s", uid, encoded);
    } else {
        return android::String8::format("%u_%s", uid, encoded);
    }
}

android::String8 KeyStore::getKeyNameForUidWithDir(
    const android::String8& keyName, uid_t uid, const BlobType type) {
    char encoded[encode_key_length(keyName) + 1];  // add 1 for null char
    encode_key(encoded, keyName);

    if (type == TYPE_KEY_CHARACTERISTICS) {
        return android::String8::format("%s/.%u_chr_%s", getUserStateByUid(uid)->getUserDirName(),
                                        uid, encoded);
    } else {
        return android::String8::format("%s/%u_%s", getUserStateByUid(uid)->getUserDirName(), uid,
                                        encoded);
    }
}

void KeyStore::resetUser(uid_t userId, bool keepUnenryptedEntries) {
    android::String8 prefix("");
    android::Vector<android::String16> aliases;
    UserState* userState = getUserState(userId);
    if (list(prefix, &aliases, userId) != ::NO_ERROR) {
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

            /* get can fail if the blob is encrypted and the state is
             * not unlocked, only skip deleting blobs that were loaded and
             * who are not encrypted. If there are blobs we fail to read for
             * other reasons err on the safe side and delete them since we
             * can't tell if they're encrypted.
             */
            shouldDelete = !(rc == ::NO_ERROR && !blob.isEncrypted());
        }
        if (shouldDelete) {
            del(filename, ::TYPE_ANY, userId);

            // del() will fail silently if no cached characteristics are present for this alias.
            android::String8 chr_filename(aliases[i]);
            chr_filename = android::String8::format("%s/%s", userState->getUserDirName(),
                                            getKeyName(chr_filename,
                                                TYPE_KEY_CHARACTERISTICS).string());
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
    if (userState == NULL) {
        return true;
    }

    DIR* dir = opendir(userState->getUserDirName());
    if (!dir) {
        return true;
    }

    bool result = true;
    struct dirent* file;
    while ((file = readdir(dir)) != NULL) {
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

ResponseCode KeyStore::get(const char* filename, Blob* keyBlob, const BlobType type, uid_t userId) {
    UserState* userState = getUserState(userId);
    ResponseCode rc =
        keyBlob->readBlob(filename, userState->getDecryptionKey(), userState->getState());
    if (rc != NO_ERROR) {
        return rc;
    }

    const uint8_t version = keyBlob->getVersion();
    if (version < CURRENT_BLOB_VERSION) {
        /* If we upgrade the key, we need to write it to disk again. Then
         * it must be read it again since the blob is encrypted each time
         * it's written.
         */
        if (upgradeBlob(filename, keyBlob, version, type, userId)) {
            if ((rc = this->put(filename, keyBlob, userId)) != NO_ERROR ||
                (rc = keyBlob->readBlob(filename, userState->getDecryptionKey(),
                                        userState->getState())) != NO_ERROR) {
                return rc;
            }
        }
    }

    /*
     * This will upgrade software-backed keys to hardware-backed keys when
     * the HAL for the device supports the newer key types.
     */
    if (rc == NO_ERROR && type == TYPE_KEY_PAIR &&
        mDevice->common.module->module_api_version >= KEYMASTER_MODULE_API_VERSION_0_2 &&
        keyBlob->isFallback()) {
        ResponseCode imported =
            importKey(keyBlob->getValue(), keyBlob->getLength(), filename, userId,
                      keyBlob->isEncrypted() ? KEYSTORE_FLAG_ENCRYPTED : KEYSTORE_FLAG_NONE);

        // The HAL allowed the import, reget the key to have the "fresh"
        // version.
        if (imported == NO_ERROR) {
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
        return KEY_NOT_FOUND;
    }

    return rc;
}

ResponseCode KeyStore::put(const char* filename, Blob* keyBlob, uid_t userId) {
    UserState* userState = getUserState(userId);
    return keyBlob->writeBlob(filename, userState->getEncryptionKey(), userState->getState(),
                              mEntropy);
}

ResponseCode KeyStore::del(const char* filename, const BlobType type, uid_t userId) {
    Blob keyBlob;
    ResponseCode rc = get(filename, &keyBlob, type, userId);
    if (rc == ::VALUE_CORRUPTED) {
        // The file is corrupt, the best we can do is rm it.
        return (unlink(filename) && errno != ENOENT) ? ::SYSTEM_ERROR : ::NO_ERROR;
    }
    if (rc != ::NO_ERROR) {
        return rc;
    }

    if (keyBlob.getType() == ::TYPE_KEY_PAIR) {
        // A device doesn't have to implement delete_key.
        if (mDevice->delete_key != NULL && !keyBlob.isFallback()) {
            keymaster_key_blob_t blob = {keyBlob.getValue(),
                                         static_cast<size_t>(keyBlob.getLength())};
            if (mDevice->delete_key(mDevice, &blob)) {
                rc = ::SYSTEM_ERROR;
            }
        }
    }
    if (keyBlob.getType() == ::TYPE_KEYMASTER_10) {
        auto* dev = getDeviceForBlob(keyBlob);
        if (dev->delete_key) {
            keymaster_key_blob_t blob;
            blob.key_material = keyBlob.getValue();
            blob.key_material_size = keyBlob.getLength();
            dev->delete_key(dev, &blob);
        }
    }
    if (rc != ::NO_ERROR) {
        return rc;
    }

    return (unlink(filename) && errno != ENOENT) ? ::SYSTEM_ERROR : ::NO_ERROR;
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

ResponseCode KeyStore::list(const android::String8& prefix,
                            android::Vector<android::String16>* matches, uid_t userId) {

    UserState* userState = getUserState(userId);
    size_t n = prefix.length();

    DIR* dir = opendir(userState->getUserDirName());
    if (!dir) {
        ALOGW("can't open directory for user: %s", strerror(errno));
        return ::SYSTEM_ERROR;
    }

    struct dirent* file;
    while ((file = readdir(dir)) != NULL) {
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
            if (match != NULL) {
                decode_key(match, p, plen);
                matches->push(android::String16(match, extra));
                free(match);
            } else {
                ALOGW("could not allocate match of size %zd", extra);
            }
        }
    }
    closedir(dir);
    return ::NO_ERROR;
}

void KeyStore::addGrant(const char* filename, uid_t granteeUid) {
    const grant_t* existing = getGrant(filename, granteeUid);
    if (existing == NULL) {
        grant_t* grant = new grant_t;
        grant->uid = granteeUid;
        grant->filename = reinterpret_cast<const uint8_t*>(strdup(filename));
        mGrants.add(grant);
    }
}

bool KeyStore::removeGrant(const char* filename, uid_t granteeUid) {
    for (android::Vector<grant_t*>::iterator it(mGrants.begin()); it != mGrants.end(); it++) {
        grant_t* grant = *it;
        if (grant->uid == granteeUid &&
            !strcmp(reinterpret_cast<const char*>(grant->filename), filename)) {
            mGrants.erase(it);
            return true;
        }
    }
    return false;
}

ResponseCode KeyStore::importKey(const uint8_t* key, size_t keyLen, const char* filename,
                                 uid_t userId, int32_t flags) {
    Unique_PKCS8_PRIV_KEY_INFO pkcs8(d2i_PKCS8_PRIV_KEY_INFO(NULL, &key, keyLen));
    if (!pkcs8.get()) {
        return ::SYSTEM_ERROR;
    }
    Unique_EVP_PKEY pkey(EVP_PKCS82PKEY(pkcs8.get()));
    if (!pkey.get()) {
        return ::SYSTEM_ERROR;
    }
    int type = EVP_PKEY_type(pkey->type);
    android::KeymasterArguments params;
    add_legacy_key_authorizations(type, &params.params);
    switch (type) {
    case EVP_PKEY_RSA:
        params.params.push_back(keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA));
        break;
    case EVP_PKEY_EC:
        params.params.push_back(keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_EC));
        break;
    default:
        ALOGW("Unsupported key type %d", type);
        return ::SYSTEM_ERROR;
    }

    std::vector<keymaster_key_param_t> opParams(params.params);
    const keymaster_key_param_set_t inParams = {opParams.data(), opParams.size()};
    keymaster_blob_t input = {key, keyLen};
    keymaster_key_blob_t blob = {nullptr, 0};
    bool isFallback = false;
    keymaster_error_t error = mDevice->import_key(mDevice, &inParams, KM_KEY_FORMAT_PKCS8, &input,
                                                  &blob, NULL /* characteristics */);
    if (error != KM_ERROR_OK) {
        ALOGE("Keymaster error %d importing key pair, falling back", error);

        /*
         * There should be no way to get here.  Fallback shouldn't ever really happen
         * because the main device may be many (SW, KM0/SW hybrid, KM1/SW hybrid), but it must
         * provide full support of the API.  In any case, we'll do the fallback just for
         * consistency... and I suppose to cover for broken HW implementations.
         */
        error = mFallbackDevice->import_key(mFallbackDevice, &inParams, KM_KEY_FORMAT_PKCS8, &input,
                                            &blob, NULL /* characteristics */);
        isFallback = true;

        if (error) {
            ALOGE("Keymaster error while importing key pair with fallback: %d", error);
            return SYSTEM_ERROR;
        }
    }

    Blob keyBlob(blob.key_material, blob.key_material_size, NULL, 0, TYPE_KEYMASTER_10);
    free(const_cast<uint8_t*>(blob.key_material));

    keyBlob.setEncrypted(flags & KEYSTORE_FLAG_ENCRYPTED);
    keyBlob.setFallback(isFallback);

    return put(filename, &keyBlob, userId);
}

bool KeyStore::isHardwareBacked(const android::String16& keyType) const {
    if (mDevice == NULL) {
        ALOGW("can't get keymaster device");
        return false;
    }

    if (sRSAKeyType == keyType) {
        return (mDevice->flags & KEYMASTER_SOFTWARE_ONLY) == 0;
    } else {
        return (mDevice->flags & KEYMASTER_SOFTWARE_ONLY) == 0 &&
               (mDevice->common.module->module_api_version >= KEYMASTER_MODULE_API_VERSION_0_2);
    }
}

ResponseCode KeyStore::getKeyForName(Blob* keyBlob, const android::String8& keyName,
                                     const uid_t uid, const BlobType type) {
    android::String8 filepath8(getKeyNameForUidWithDir(keyName, uid, type));
    uid_t userId = get_user_id(uid);

    ResponseCode responseCode = get(filepath8.string(), keyBlob, type, userId);
    if (responseCode == NO_ERROR) {
        return responseCode;
    }

    // If this is one of the legacy UID->UID mappings, use it.
    uid_t euid = get_keystore_euid(uid);
    if (euid != uid) {
        filepath8 = getKeyNameForUidWithDir(keyName, euid, type);
        responseCode = get(filepath8.string(), keyBlob, type, userId);
        if (responseCode == NO_ERROR) {
            return responseCode;
        }
    }

    // They might be using a granted key.
    android::String8 filename8 = getKeyName(keyName, type);
    char* end;
    strtoul(filename8.string(), &end, 10);
    if (end[0] != '_' || end[1] == 0) {
        return KEY_NOT_FOUND;
    }
    filepath8 = android::String8::format("%s/%s", getUserState(userId)->getUserDirName(),
                                         filename8.string());
    if (!hasGrant(filepath8.string(), uid)) {
        return responseCode;
    }

    // It is a granted key. Try to load it.
    return get(filepath8.string(), keyBlob, type, userId);
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

    return NULL;
}

const UserState* KeyStore::getUserStateByUid(uid_t uid) const {
    uid_t userId = get_user_id(uid);
    return getUserState(userId);
}

const grant_t* KeyStore::getGrant(const char* filename, uid_t uid) const {
    for (android::Vector<grant_t*>::const_iterator it(mGrants.begin()); it != mGrants.end(); it++) {
        grant_t* grant = *it;
        if (grant->uid == uid &&
            !strcmp(reinterpret_cast<const char*>(grant->filename), filename)) {
            return grant;
        }
    }
    return NULL;
}

bool KeyStore::upgradeBlob(const char* filename, Blob* blob, const uint8_t oldVersion,
                           const BlobType type, uid_t uid) {
    bool updated = false;
    uint8_t version = oldVersion;

    /* From V0 -> V1: All old types were unknown */
    if (version == 0) {
        ALOGV("upgrading to version 1 and setting type %d", type);

        blob->setType(type);
        if (type == TYPE_KEY_PAIR) {
            importBlobAsKey(blob, filename, uid);
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
typedef UniquePtr<BIO, BIO_Delete> Unique_BIO;

ResponseCode KeyStore::importBlobAsKey(Blob* blob, const char* filename, uid_t uid) {
    // We won't even write to the blob directly with this BIO, so const_cast is okay.
    Unique_BIO b(BIO_new_mem_buf(const_cast<uint8_t*>(blob->getValue()), blob->getLength()));
    if (b.get() == NULL) {
        ALOGE("Problem instantiating BIO");
        return SYSTEM_ERROR;
    }

    Unique_EVP_PKEY pkey(PEM_read_bio_PrivateKey(b.get(), NULL, NULL, NULL));
    if (pkey.get() == NULL) {
        ALOGE("Couldn't read old PEM file");
        return SYSTEM_ERROR;
    }

    Unique_PKCS8_PRIV_KEY_INFO pkcs8(EVP_PKEY2PKCS8(pkey.get()));
    int len = i2d_PKCS8_PRIV_KEY_INFO(pkcs8.get(), NULL);
    if (len < 0) {
        ALOGE("Couldn't measure PKCS#8 length");
        return SYSTEM_ERROR;
    }

    UniquePtr<unsigned char[]> pkcs8key(new unsigned char[len]);
    uint8_t* tmp = pkcs8key.get();
    if (i2d_PKCS8_PRIV_KEY_INFO(pkcs8.get(), &tmp) != len) {
        ALOGE("Couldn't convert to PKCS#8");
        return SYSTEM_ERROR;
    }

    ResponseCode rc = importKey(pkcs8key.get(), len, filename, get_user_id(uid),
                                blob->isEncrypted() ? KEYSTORE_FLAG_ENCRYPTED : KEYSTORE_FLAG_NONE);
    if (rc != NO_ERROR) {
        return rc;
    }

    return get(filename, blob, TYPE_KEY_PAIR, uid);
}

void KeyStore::readMetaData() {
    int in = TEMP_FAILURE_RETRY(open(sMetaDataFile, O_RDONLY));
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
    rename(tmpFileName, sMetaDataFile);
}

bool KeyStore::upgradeKeystore() {
    bool upgraded = false;

    if (mMetaData.version == 0) {
        UserState* userState = getUserStateByUid(0);

        // Initialize first so the directory is made.
        userState->initialize();

        // Migrate the old .masterkey file to user 0.
        if (access(sOldMasterKey, R_OK) == 0) {
            if (rename(sOldMasterKey, userState->getMasterKeyFileName()) < 0) {
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
        while ((file = readdir(dir)) != NULL) {
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
            if (otherdir == NULL) {
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
