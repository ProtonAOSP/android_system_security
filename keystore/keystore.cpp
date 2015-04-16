/*
 * Copyright (C) 2009 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "keystore"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/pem.h>

#include <hardware/keymaster0.h>

#include <keymaster/softkeymaster.h>
#include <keymaster/soft_keymaster_device.h>

#include <UniquePtr.h>
#include <utils/String8.h>
#include <utils/Vector.h>

#include <keystore/IKeystoreService.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

#include <cutils/log.h>
#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>

#include <keystore/keystore.h>

#include <selinux/android.h>

#include "auth_token_table.h"
#include "defaults.h"
#include "operation.h"

/* KeyStore is a secured storage for key-value pairs. In this implementation,
 * each file stores one key-value pair. Keys are encoded in file names, and
 * values are encrypted with checksums. The encryption key is protected by a
 * user-defined password. To keep things simple, buffers are always larger than
 * the maximum space we needed, so boundary checks on buffers are omitted. */

#define KEY_SIZE        ((NAME_MAX - 15) / 2)
#define VALUE_SIZE      32768
#define PASSWORD_SIZE   VALUE_SIZE


struct BIGNUM_Delete {
    void operator()(BIGNUM* p) const {
        BN_free(p);
    }
};
typedef UniquePtr<BIGNUM, BIGNUM_Delete> Unique_BIGNUM;

struct BIO_Delete {
    void operator()(BIO* p) const {
        BIO_free(p);
    }
};
typedef UniquePtr<BIO, BIO_Delete> Unique_BIO;

struct EVP_PKEY_Delete {
    void operator()(EVP_PKEY* p) const {
        EVP_PKEY_free(p);
    }
};
typedef UniquePtr<EVP_PKEY, EVP_PKEY_Delete> Unique_EVP_PKEY;

struct PKCS8_PRIV_KEY_INFO_Delete {
    void operator()(PKCS8_PRIV_KEY_INFO* p) const {
        PKCS8_PRIV_KEY_INFO_free(p);
    }
};
typedef UniquePtr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_Delete> Unique_PKCS8_PRIV_KEY_INFO;

static int keymaster_device_initialize(keymaster0_device_t** dev) {
    int rc;

    const hw_module_t* mod;
    rc = hw_get_module_by_class(KEYSTORE_HARDWARE_MODULE_ID, NULL, &mod);
    if (rc) {
        ALOGE("could not find any keystore module");
        goto out;
    }

    rc = keymaster0_open(mod, dev);
    if (rc) {
        ALOGE("could not open keymaster device in %s (%s)",
            KEYSTORE_HARDWARE_MODULE_ID, strerror(-rc));
        goto out;
    }

    return 0;

out:
    *dev = NULL;
    return rc;
}

static int fallback_keymaster_device_initialize(keymaster1_device_t** dev) {
    keymaster::SoftKeymasterDevice* softkeymaster =
            new keymaster::SoftKeymasterDevice();
    // SoftKeymasterDevice is designed to make this cast safe.
    *dev = reinterpret_cast<keymaster1_device_t*>(softkeymaster);
    return 0;
}

static void keymaster_device_release(keymaster0_device_t* dev) {
    keymaster0_close(dev);
}

/***************
 * PERMISSIONS *
 ***************/

/* Here are the permissions, actions, users, and the main function. */
typedef enum {
    P_TEST          = 1 << 0,
    P_GET           = 1 << 1,
    P_INSERT        = 1 << 2,
    P_DELETE        = 1 << 3,
    P_EXIST         = 1 << 4,
    P_SAW           = 1 << 5,
    P_RESET         = 1 << 6,
    P_PASSWORD      = 1 << 7,
    P_LOCK          = 1 << 8,
    P_UNLOCK        = 1 << 9,
    P_ZERO          = 1 << 10,
    P_SIGN          = 1 << 11,
    P_VERIFY        = 1 << 12,
    P_GRANT         = 1 << 13,
    P_DUPLICATE     = 1 << 14,
    P_CLEAR_UID     = 1 << 15,
    P_RESET_UID     = 1 << 16,
    P_SYNC_UID      = 1 << 17,
    P_PASSWORD_UID  = 1 << 18,
    P_ADD_AUTH      = 1 << 19,
} perm_t;

static struct user_euid {
    uid_t uid;
    uid_t euid;
} user_euids[] = {
    {AID_VPN, AID_SYSTEM},
    {AID_WIFI, AID_SYSTEM},
    {AID_ROOT, AID_SYSTEM},
};

/* perm_labels associcated with keystore_key SELinux class verbs. */
const char *perm_labels[] = {
    "test",
    "get",
    "insert",
    "delete",
    "exist",
    "saw",
    "reset",
    "password",
    "lock",
    "unlock",
    "zero",
    "sign",
    "verify",
    "grant",
    "duplicate",
    "clear_uid",
    "reset_uid",
    "sync_uid",
    "password_uid",
    "add_auth",
};

static struct user_perm {
    uid_t uid;
    perm_t perms;
} user_perms[] = {
    {AID_SYSTEM, static_cast<perm_t>((uint32_t)(~0)) },
    {AID_VPN,    static_cast<perm_t>(P_GET | P_SIGN | P_VERIFY) },
    {AID_WIFI,   static_cast<perm_t>(P_GET | P_SIGN | P_VERIFY) },
    {AID_ROOT,   static_cast<perm_t>(P_GET) },
};

static const perm_t DEFAULT_PERMS = static_cast<perm_t>(P_TEST | P_GET | P_INSERT | P_DELETE | P_EXIST | P_SAW | P_SIGN
        | P_VERIFY);

static char *tctx;
static int ks_is_selinux_enabled;

static const char *get_perm_label(perm_t perm) {
    unsigned int index = ffs(perm);
    if (index > 0 && index <= (sizeof(perm_labels) / sizeof(perm_labels[0]))) {
        return perm_labels[index - 1];
    } else {
        ALOGE("Keystore: Failed to retrieve permission label.\n");
        abort();
    }
}

/**
 * Returns the app ID (in the Android multi-user sense) for the current
 * UNIX UID.
 */
static uid_t get_app_id(uid_t uid) {
    return uid % AID_USER;
}

/**
 * Returns the user ID (in the Android multi-user sense) for the current
 * UNIX UID.
 */
static uid_t get_user_id(uid_t uid) {
    return uid / AID_USER;
}

static bool keystore_selinux_check_access(uid_t /*uid*/, perm_t perm, pid_t spid) {
    if (!ks_is_selinux_enabled) {
        return true;
    }

    char *sctx = NULL;
    const char *selinux_class = "keystore_key";
    const char *str_perm = get_perm_label(perm);

    if (!str_perm) {
        return false;
    }

    if (getpidcon(spid, &sctx) != 0) {
        ALOGE("SELinux: Failed to get source pid context.\n");
        return false;
    }

    bool allowed = selinux_check_access(sctx, tctx, selinux_class, str_perm,
            NULL) == 0;
    freecon(sctx);
    return allowed;
}

static bool has_permission(uid_t uid, perm_t perm, pid_t spid) {
    // All system users are equivalent for multi-user support.
    if (get_app_id(uid) == AID_SYSTEM) {
        uid = AID_SYSTEM;
    }

    for (size_t i = 0; i < sizeof(user_perms)/sizeof(user_perms[0]); i++) {
        struct user_perm user = user_perms[i];
        if (user.uid == uid) {
            return (user.perms & perm) &&
                keystore_selinux_check_access(uid, perm, spid);
        }
    }

    return (DEFAULT_PERMS & perm) &&
        keystore_selinux_check_access(uid, perm, spid);
}

/**
 * Returns the UID that the callingUid should act as. This is here for
 * legacy support of the WiFi and VPN systems and should be removed
 * when WiFi can operate in its own namespace.
 */
static uid_t get_keystore_euid(uid_t uid) {
    for (size_t i = 0; i < sizeof(user_euids)/sizeof(user_euids[0]); i++) {
        struct user_euid user = user_euids[i];
        if (user.uid == uid) {
            return user.euid;
        }
    }

    return uid;
}

/**
 * Returns true if the callingUid is allowed to interact in the targetUid's
 * namespace.
 */
static bool is_granted_to(uid_t callingUid, uid_t targetUid) {
    if (callingUid == targetUid) {
        return true;
    }
    for (size_t i = 0; i < sizeof(user_euids)/sizeof(user_euids[0]); i++) {
        struct user_euid user = user_euids[i];
        if (user.euid == callingUid && user.uid == targetUid) {
            return true;
        }
    }

    return false;
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

static size_t readFully(int fd, uint8_t* data, size_t size) {
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t n = TEMP_FAILURE_RETRY(read(fd, data, remaining));
        if (n <= 0) {
            return size - remaining;
        }
        data += n;
        remaining -= n;
    }
    return size;
}

static size_t writeFully(int fd, uint8_t* data, size_t size) {
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t n = TEMP_FAILURE_RETRY(write(fd, data, remaining));
        if (n < 0) {
            ALOGW("write failed: %s", strerror(errno));
            return size - remaining;
        }
        data += n;
        remaining -= n;
    }
    return size;
}

class Entropy {
public:
    Entropy() : mRandom(-1) {}
    ~Entropy() {
        if (mRandom >= 0) {
            close(mRandom);
        }
    }

    bool open() {
        const char* randomDevice = "/dev/urandom";
        mRandom = TEMP_FAILURE_RETRY(::open(randomDevice, O_RDONLY));
        if (mRandom < 0) {
            ALOGE("open: %s: %s", randomDevice, strerror(errno));
            return false;
        }
        return true;
    }

    bool generate_random_data(uint8_t* data, size_t size) const {
        return (readFully(mRandom, data, size) == size);
    }

private:
    int mRandom;
};

/* Here is the file format. There are two parts in blob.value, the secret and
 * the description. The secret is stored in ciphertext, and its original size
 * can be found in blob.length. The description is stored after the secret in
 * plaintext, and its size is specified in blob.info. The total size of the two
 * parts must be no more than VALUE_SIZE bytes. The first field is the version,
 * the second is the blob's type, and the third byte is flags. Fields other
 * than blob.info, blob.length, and blob.value are modified by encryptBlob()
 * and decryptBlob(). Thus they should not be accessed from outside. */

/* ** Note to future implementors of encryption: **
 * Currently this is the construction:
 *   metadata || Enc(MD5(data) || data)
 *
 * This should be the construction used for encrypting if re-implementing:
 *
 *   Derive independent keys for encryption and MAC:
 *     Kenc = AES_encrypt(masterKey, "Encrypt")
 *     Kmac = AES_encrypt(masterKey, "MAC")
 *
 *   Store this:
 *     metadata || AES_CTR_encrypt(Kenc, rand_IV, data) ||
 *             HMAC(Kmac, metadata || Enc(data))
 */
struct __attribute__((packed)) blob {
    uint8_t version;
    uint8_t type;
    uint8_t flags;
    uint8_t info;
    uint8_t vector[AES_BLOCK_SIZE];
    uint8_t encrypted[0]; // Marks offset to encrypted data.
    uint8_t digest[MD5_DIGEST_LENGTH];
    uint8_t digested[0]; // Marks offset to digested data.
    int32_t length; // in network byte order when encrypted
    uint8_t value[VALUE_SIZE + AES_BLOCK_SIZE];
};

typedef enum {
    TYPE_ANY = 0, // meta type that matches anything
    TYPE_GENERIC = 1,
    TYPE_MASTER_KEY = 2,
    TYPE_KEY_PAIR = 3,
    TYPE_KEYMASTER_10 = 4,
} BlobType;

static const uint8_t CURRENT_BLOB_VERSION = 2;

class Blob {
public:
    Blob(const uint8_t* value, int32_t valueLength, const uint8_t* info, uint8_t infoLength,
            BlobType type) {
        mBlob.length = valueLength;
        memcpy(mBlob.value, value, valueLength);

        mBlob.info = infoLength;
        memcpy(mBlob.value + valueLength, info, infoLength);

        mBlob.version = CURRENT_BLOB_VERSION;
        mBlob.type = uint8_t(type);

        if (type == TYPE_MASTER_KEY) {
            mBlob.flags = KEYSTORE_FLAG_ENCRYPTED;
        } else {
            mBlob.flags = KEYSTORE_FLAG_NONE;
        }
    }

    Blob(blob b) {
        mBlob = b;
    }

    Blob() {}

    const uint8_t* getValue() const {
        return mBlob.value;
    }

    int32_t getLength() const {
        return mBlob.length;
    }

    const uint8_t* getInfo() const {
        return mBlob.value + mBlob.length;
    }

    uint8_t getInfoLength() const {
        return mBlob.info;
    }

    uint8_t getVersion() const {
        return mBlob.version;
    }

    bool isEncrypted() const {
        if (mBlob.version < 2) {
            return true;
        }

        return mBlob.flags & KEYSTORE_FLAG_ENCRYPTED;
    }

    void setEncrypted(bool encrypted) {
        if (encrypted) {
            mBlob.flags |= KEYSTORE_FLAG_ENCRYPTED;
        } else {
            mBlob.flags &= ~KEYSTORE_FLAG_ENCRYPTED;
        }
    }

    bool isFallback() const {
        return mBlob.flags & KEYSTORE_FLAG_FALLBACK;
    }

    void setFallback(bool fallback) {
        if (fallback) {
            mBlob.flags |= KEYSTORE_FLAG_FALLBACK;
        } else {
            mBlob.flags &= ~KEYSTORE_FLAG_FALLBACK;
        }
    }

    void setVersion(uint8_t version) {
        mBlob.version = version;
    }

    BlobType getType() const {
        return BlobType(mBlob.type);
    }

    void setType(BlobType type) {
        mBlob.type = uint8_t(type);
    }

    ResponseCode writeBlob(const char* filename, AES_KEY *aes_key, State state, Entropy* entropy) {
        ALOGV("writing blob %s", filename);
        if (isEncrypted()) {
            if (state != STATE_NO_ERROR) {
                ALOGD("couldn't insert encrypted blob while not unlocked");
                return LOCKED;
            }

            if (!entropy->generate_random_data(mBlob.vector, AES_BLOCK_SIZE)) {
                ALOGW("Could not read random data for: %s", filename);
                return SYSTEM_ERROR;
            }
        }

        // data includes the value and the value's length
        size_t dataLength = mBlob.length + sizeof(mBlob.length);
        // pad data to the AES_BLOCK_SIZE
        size_t digestedLength = ((dataLength + AES_BLOCK_SIZE - 1)
                                 / AES_BLOCK_SIZE * AES_BLOCK_SIZE);
        // encrypted data includes the digest value
        size_t encryptedLength = digestedLength + MD5_DIGEST_LENGTH;
        // move info after space for padding
        memmove(&mBlob.encrypted[encryptedLength], &mBlob.value[mBlob.length], mBlob.info);
        // zero padding area
        memset(mBlob.value + mBlob.length, 0, digestedLength - dataLength);

        mBlob.length = htonl(mBlob.length);

        if (isEncrypted()) {
            MD5(mBlob.digested, digestedLength, mBlob.digest);

            uint8_t vector[AES_BLOCK_SIZE];
            memcpy(vector, mBlob.vector, AES_BLOCK_SIZE);
            AES_cbc_encrypt(mBlob.encrypted, mBlob.encrypted, encryptedLength,
                            aes_key, vector, AES_ENCRYPT);
        }

        size_t headerLength = (mBlob.encrypted - (uint8_t*) &mBlob);
        size_t fileLength = encryptedLength + headerLength + mBlob.info;

        const char* tmpFileName = ".tmp";
        int out = TEMP_FAILURE_RETRY(open(tmpFileName,
                O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR));
        if (out < 0) {
            ALOGW("could not open file: %s: %s", tmpFileName, strerror(errno));
            return SYSTEM_ERROR;
        }
        size_t writtenBytes = writeFully(out, (uint8_t*) &mBlob, fileLength);
        if (close(out) != 0) {
            return SYSTEM_ERROR;
        }
        if (writtenBytes != fileLength) {
            ALOGW("blob not fully written %zu != %zu", writtenBytes, fileLength);
            unlink(tmpFileName);
            return SYSTEM_ERROR;
        }
        if (rename(tmpFileName, filename) == -1) {
            ALOGW("could not rename blob to %s: %s", filename, strerror(errno));
            return SYSTEM_ERROR;
        }
        return NO_ERROR;
    }

    ResponseCode readBlob(const char* filename, AES_KEY *aes_key, State state) {
        ALOGV("reading blob %s", filename);
        int in = TEMP_FAILURE_RETRY(open(filename, O_RDONLY));
        if (in < 0) {
            return (errno == ENOENT) ? KEY_NOT_FOUND : SYSTEM_ERROR;
        }
        // fileLength may be less than sizeof(mBlob) since the in
        // memory version has extra padding to tolerate rounding up to
        // the AES_BLOCK_SIZE
        size_t fileLength = readFully(in, (uint8_t*) &mBlob, sizeof(mBlob));
        if (close(in) != 0) {
            return SYSTEM_ERROR;
        }

        if (isEncrypted() && (state != STATE_NO_ERROR)) {
            return LOCKED;
        }

        size_t headerLength = (mBlob.encrypted - (uint8_t*) &mBlob);
        if (fileLength < headerLength) {
            return VALUE_CORRUPTED;
        }

        ssize_t encryptedLength = fileLength - (headerLength + mBlob.info);
        if (encryptedLength < 0) {
            return VALUE_CORRUPTED;
        }

        ssize_t digestedLength;
        if (isEncrypted()) {
            if (encryptedLength % AES_BLOCK_SIZE != 0) {
                return VALUE_CORRUPTED;
            }

            AES_cbc_encrypt(mBlob.encrypted, mBlob.encrypted, encryptedLength, aes_key,
                            mBlob.vector, AES_DECRYPT);
            digestedLength = encryptedLength - MD5_DIGEST_LENGTH;
            uint8_t computedDigest[MD5_DIGEST_LENGTH];
            MD5(mBlob.digested, digestedLength, computedDigest);
            if (memcmp(mBlob.digest, computedDigest, MD5_DIGEST_LENGTH) != 0) {
                return VALUE_CORRUPTED;
            }
        } else {
            digestedLength = encryptedLength;
        }

        ssize_t maxValueLength = digestedLength - sizeof(mBlob.length);
        mBlob.length = ntohl(mBlob.length);
        if (mBlob.length < 0 || mBlob.length > maxValueLength) {
            return VALUE_CORRUPTED;
        }
        if (mBlob.info != 0) {
            // move info from after padding to after data
            memmove(&mBlob.value[mBlob.length], &mBlob.value[maxValueLength], mBlob.info);
        }
        return ::NO_ERROR;
    }

private:
    struct blob mBlob;
};

class UserState {
public:
    UserState(uid_t userId) : mUserId(userId), mRetry(MAX_RETRY) {
        asprintf(&mUserDir, "user_%u", mUserId);
        asprintf(&mMasterKeyFile, "%s/.masterkey", mUserDir);
    }

    ~UserState() {
        free(mUserDir);
        free(mMasterKeyFile);
    }

    bool initialize() {
        if ((mkdir(mUserDir, S_IRUSR | S_IWUSR | S_IXUSR) < 0) && (errno != EEXIST)) {
            ALOGE("Could not create directory '%s'", mUserDir);
            return false;
        }

        if (access(mMasterKeyFile, R_OK) == 0) {
            setState(STATE_LOCKED);
        } else {
            setState(STATE_UNINITIALIZED);
        }

        return true;
    }

    uid_t getUserId() const {
        return mUserId;
    }

    const char* getUserDirName() const {
        return mUserDir;
    }

    const char* getMasterKeyFileName() const {
        return mMasterKeyFile;
    }

    void setState(State state) {
        mState = state;
        if (mState == STATE_NO_ERROR || mState == STATE_UNINITIALIZED) {
            mRetry = MAX_RETRY;
        }
    }

    State getState() const {
        return mState;
    }

    int8_t getRetry() const {
        return mRetry;
    }

    void zeroizeMasterKeysInMemory() {
        memset(mMasterKey, 0, sizeof(mMasterKey));
        memset(mSalt, 0, sizeof(mSalt));
        memset(&mMasterKeyEncryption, 0, sizeof(mMasterKeyEncryption));
        memset(&mMasterKeyDecryption, 0, sizeof(mMasterKeyDecryption));
    }

    ResponseCode initialize(const android::String8& pw, Entropy* entropy) {
        if (!generateMasterKey(entropy)) {
            return SYSTEM_ERROR;
        }
        ResponseCode response = writeMasterKey(pw, entropy);
        if (response != NO_ERROR) {
            return response;
        }
        setupMasterKeys();
        return ::NO_ERROR;
    }

    ResponseCode copyMasterKey(UserState* src) {
        if (mState != STATE_UNINITIALIZED) {
            return ::SYSTEM_ERROR;
        }
        if (src->getState() != STATE_NO_ERROR) {
            return ::SYSTEM_ERROR;
        }
        memcpy(mMasterKey, src->mMasterKey, MASTER_KEY_SIZE_BYTES);
        setupMasterKeys();
        return ::NO_ERROR;
    }

    ResponseCode writeMasterKey(const android::String8& pw, Entropy* entropy) {
        uint8_t passwordKey[MASTER_KEY_SIZE_BYTES];
        generateKeyFromPassword(passwordKey, MASTER_KEY_SIZE_BYTES, pw, mSalt);
        AES_KEY passwordAesKey;
        AES_set_encrypt_key(passwordKey, MASTER_KEY_SIZE_BITS, &passwordAesKey);
        Blob masterKeyBlob(mMasterKey, sizeof(mMasterKey), mSalt, sizeof(mSalt), TYPE_MASTER_KEY);
        return masterKeyBlob.writeBlob(mMasterKeyFile, &passwordAesKey, STATE_NO_ERROR, entropy);
    }

    ResponseCode readMasterKey(const android::String8& pw, Entropy* entropy) {
        int in = TEMP_FAILURE_RETRY(open(mMasterKeyFile, O_RDONLY));
        if (in < 0) {
            return SYSTEM_ERROR;
        }

        // we read the raw blob to just to get the salt to generate
        // the AES key, then we create the Blob to use with decryptBlob
        blob rawBlob;
        size_t length = readFully(in, (uint8_t*) &rawBlob, sizeof(rawBlob));
        if (close(in) != 0) {
            return SYSTEM_ERROR;
        }
        // find salt at EOF if present, otherwise we have an old file
        uint8_t* salt;
        if (length > SALT_SIZE && rawBlob.info == SALT_SIZE) {
            salt = (uint8_t*) &rawBlob + length - SALT_SIZE;
        } else {
            salt = NULL;
        }
        uint8_t passwordKey[MASTER_KEY_SIZE_BYTES];
        generateKeyFromPassword(passwordKey, MASTER_KEY_SIZE_BYTES, pw, salt);
        AES_KEY passwordAesKey;
        AES_set_decrypt_key(passwordKey, MASTER_KEY_SIZE_BITS, &passwordAesKey);
        Blob masterKeyBlob(rawBlob);
        ResponseCode response = masterKeyBlob.readBlob(mMasterKeyFile, &passwordAesKey,
                STATE_NO_ERROR);
        if (response == SYSTEM_ERROR) {
            return response;
        }
        if (response == NO_ERROR && masterKeyBlob.getLength() == MASTER_KEY_SIZE_BYTES) {
            // if salt was missing, generate one and write a new master key file with the salt.
            if (salt == NULL) {
                if (!generateSalt(entropy)) {
                    return SYSTEM_ERROR;
                }
                response = writeMasterKey(pw, entropy);
            }
            if (response == NO_ERROR) {
                memcpy(mMasterKey, masterKeyBlob.getValue(), MASTER_KEY_SIZE_BYTES);
                setupMasterKeys();
            }
            return response;
        }
        if (mRetry <= 0) {
            reset();
            return UNINITIALIZED;
        }
        --mRetry;
        switch (mRetry) {
            case 0: return WRONG_PASSWORD_0;
            case 1: return WRONG_PASSWORD_1;
            case 2: return WRONG_PASSWORD_2;
            case 3: return WRONG_PASSWORD_3;
            default: return WRONG_PASSWORD_3;
        }
    }

    AES_KEY* getEncryptionKey() {
        return &mMasterKeyEncryption;
    }

    AES_KEY* getDecryptionKey() {
        return &mMasterKeyDecryption;
    }

    bool reset() {
        DIR* dir = opendir(getUserDirName());
        if (!dir) {
            ALOGW("couldn't open user directory: %s", strerror(errno));
            return false;
        }

        struct dirent* file;
        while ((file = readdir(dir)) != NULL) {
            // We only care about files.
            if (file->d_type != DT_REG) {
                continue;
            }

            // Skip anything that starts with a "."
            if (file->d_name[0] == '.' && strcmp(".masterkey", file->d_name)) {
                continue;
            }

            unlinkat(dirfd(dir), file->d_name, 0);
        }
        closedir(dir);
        return true;
    }

private:
    static const int MASTER_KEY_SIZE_BYTES = 16;
    static const int MASTER_KEY_SIZE_BITS = MASTER_KEY_SIZE_BYTES * 8;

    static const int MAX_RETRY = 4;
    static const size_t SALT_SIZE = 16;

    void generateKeyFromPassword(uint8_t* key, ssize_t keySize, const android::String8& pw,
            uint8_t* salt) {
        size_t saltSize;
        if (salt != NULL) {
            saltSize = SALT_SIZE;
        } else {
            // pre-gingerbread used this hardwired salt, readMasterKey will rewrite these when found
            salt = (uint8_t*) "keystore";
            // sizeof = 9, not strlen = 8
            saltSize = sizeof("keystore");
        }

        PKCS5_PBKDF2_HMAC_SHA1(reinterpret_cast<const char*>(pw.string()), pw.length(), salt,
                saltSize, 8192, keySize, key);
    }

    bool generateSalt(Entropy* entropy) {
        return entropy->generate_random_data(mSalt, sizeof(mSalt));
    }

    bool generateMasterKey(Entropy* entropy) {
        if (!entropy->generate_random_data(mMasterKey, sizeof(mMasterKey))) {
            return false;
        }
        if (!generateSalt(entropy)) {
            return false;
        }
        return true;
    }

    void setupMasterKeys() {
        AES_set_encrypt_key(mMasterKey, MASTER_KEY_SIZE_BITS, &mMasterKeyEncryption);
        AES_set_decrypt_key(mMasterKey, MASTER_KEY_SIZE_BITS, &mMasterKeyDecryption);
        setState(STATE_NO_ERROR);
    }

    uid_t mUserId;

    char* mUserDir;
    char* mMasterKeyFile;

    State mState;
    int8_t mRetry;

    uint8_t mMasterKey[MASTER_KEY_SIZE_BYTES];
    uint8_t mSalt[SALT_SIZE];

    AES_KEY mMasterKeyEncryption;
    AES_KEY mMasterKeyDecryption;
};

typedef struct {
    uint32_t uid;
    const uint8_t* filename;
} grant_t;

class KeyStore {
public:
    KeyStore(Entropy* entropy, keymaster1_device_t* device, keymaster1_device_t* fallback)
        : mEntropy(entropy)
        , mDevice(device)
        , mFallbackDevice(fallback)
    {
        memset(&mMetaData, '\0', sizeof(mMetaData));
    }

    ~KeyStore() {
        for (android::Vector<grant_t*>::iterator it(mGrants.begin());
                it != mGrants.end(); it++) {
            delete *it;
        }
        mGrants.clear();

        for (android::Vector<UserState*>::iterator it(mMasterKeys.begin());
                it != mMasterKeys.end(); it++) {
            delete *it;
        }
        mMasterKeys.clear();
    }

    /**
     * Depending on the hardware keymaster version is this may return a
     * keymaster0_device_t* cast to a keymaster1_device_t*. All methods from
     * keymaster0 are safe to call, calls to keymaster1_device_t methods should
     * be guarded by a check on the device's version.
     */
    keymaster1_device_t *getDevice() const {
        return mDevice;
    }

    keymaster1_device_t *getFallbackDevice() const {
        return mFallbackDevice;
    }

    keymaster1_device_t *getDeviceForBlob(const Blob& blob) const {
        return blob.isFallback() ? mFallbackDevice: mDevice;
    }

    ResponseCode initialize() {
        readMetaData();
        if (upgradeKeystore()) {
            writeMetaData();
        }

        return ::NO_ERROR;
    }

    State getState(uid_t uid) {
        return getUserState(uid)->getState();
    }

    ResponseCode initializeUser(const android::String8& pw, uid_t uid) {
        UserState* userState = getUserState(uid);
        return userState->initialize(pw, mEntropy);
    }

    ResponseCode copyMasterKey(uid_t src, uid_t uid) {
        UserState *userState = getUserState(uid);
        UserState *initState = getUserState(src);
        return userState->copyMasterKey(initState);
    }

    ResponseCode writeMasterKey(const android::String8& pw, uid_t uid) {
        UserState* userState = getUserState(uid);
        return userState->writeMasterKey(pw, mEntropy);
    }

    ResponseCode readMasterKey(const android::String8& pw, uid_t uid) {
        UserState* userState = getUserState(uid);
        return userState->readMasterKey(pw, mEntropy);
    }

    android::String8 getKeyName(const android::String8& keyName) {
        char encoded[encode_key_length(keyName) + 1];	// add 1 for null char
        encode_key(encoded, keyName);
        return android::String8(encoded);
    }

    android::String8 getKeyNameForUid(const android::String8& keyName, uid_t uid) {
        char encoded[encode_key_length(keyName) + 1];	// add 1 for null char
        encode_key(encoded, keyName);
        return android::String8::format("%u_%s", uid, encoded);
    }

    android::String8 getKeyNameForUidWithDir(const android::String8& keyName, uid_t uid) {
        char encoded[encode_key_length(keyName) + 1];	// add 1 for null char
        encode_key(encoded, keyName);
        return android::String8::format("%s/%u_%s", getUserState(uid)->getUserDirName(), uid,
                encoded);
    }

    bool reset(uid_t uid) {
        android::String8 prefix("");
        android::Vector<android::String16> aliases;
        if (saw(prefix, &aliases, uid) != ::NO_ERROR) {
            return ::SYSTEM_ERROR;
        }

        UserState* userState = getUserState(uid);
        for (uint32_t i = 0; i < aliases.size(); i++) {
            android::String8 filename(aliases[i]);
            filename = android::String8::format("%s/%s", userState->getUserDirName(),
                    getKeyName(filename).string());
            del(filename, ::TYPE_ANY, uid);
        }

        userState->zeroizeMasterKeysInMemory();
        userState->setState(STATE_UNINITIALIZED);
        return userState->reset();
    }

    bool isEmpty(uid_t uid) const {
        const UserState* userState = getUserState(uid);
        if (userState == NULL || userState->getState() == STATE_UNINITIALIZED) {
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

    void lock(uid_t uid) {
        UserState* userState = getUserState(uid);
        userState->zeroizeMasterKeysInMemory();
        userState->setState(STATE_LOCKED);
    }

    ResponseCode get(const char* filename, Blob* keyBlob, const BlobType type, uid_t uid) {
        UserState* userState = getUserState(uid);
        ResponseCode rc = keyBlob->readBlob(filename, userState->getDecryptionKey(),
                userState->getState());
        if (rc != NO_ERROR) {
            return rc;
        }

        const uint8_t version = keyBlob->getVersion();
        if (version < CURRENT_BLOB_VERSION) {
            /* If we upgrade the key, we need to write it to disk again. Then
             * it must be read it again since the blob is encrypted each time
             * it's written.
             */
            if (upgradeBlob(filename, keyBlob, version, type, uid)) {
                if ((rc = this->put(filename, keyBlob, uid)) != NO_ERROR
                        || (rc = keyBlob->readBlob(filename, userState->getDecryptionKey(),
                                userState->getState())) != NO_ERROR) {
                    return rc;
                }
            }
        }

        /*
         * This will upgrade software-backed keys to hardware-backed keys when
         * the HAL for the device supports the newer key types.
         */
        if (rc == NO_ERROR && type == TYPE_KEY_PAIR
                && mDevice->common.module->module_api_version >= KEYMASTER_MODULE_API_VERSION_0_2
                && keyBlob->isFallback()) {
            ResponseCode imported = importKey(keyBlob->getValue(), keyBlob->getLength(), filename,
                    uid, keyBlob->isEncrypted() ? KEYSTORE_FLAG_ENCRYPTED : KEYSTORE_FLAG_NONE);

            // The HAL allowed the import, reget the key to have the "fresh"
            // version.
            if (imported == NO_ERROR) {
                rc = get(filename, keyBlob, TYPE_KEY_PAIR, uid);
            }
        }

        if (type != TYPE_ANY && keyBlob->getType() != type) {
            ALOGW("key found but type doesn't match: %d vs %d", keyBlob->getType(), type);
            return KEY_NOT_FOUND;
        }

        return rc;
    }

    ResponseCode put(const char* filename, Blob* keyBlob, uid_t uid) {
        UserState* userState = getUserState(uid);
        return keyBlob->writeBlob(filename, userState->getEncryptionKey(), userState->getState(),
                mEntropy);
    }

    ResponseCode del(const char *filename, const BlobType type, uid_t uid) {
        Blob keyBlob;
        ResponseCode rc = get(filename, &keyBlob, type, uid);
        if (rc != ::NO_ERROR) {
            return rc;
        }

        if (keyBlob.getType() == ::TYPE_KEY_PAIR) {
            // A device doesn't have to implement delete_keypair.
            if (mDevice->delete_keypair != NULL && !keyBlob.isFallback()) {
                if (mDevice->delete_keypair(mDevice, keyBlob.getValue(), keyBlob.getLength())) {
                    rc = ::SYSTEM_ERROR;
                }
            }
        }
        if (keyBlob.getType() == ::TYPE_KEYMASTER_10) {
            keymaster1_device_t* dev = getDeviceForBlob(keyBlob);
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

    ResponseCode saw(const android::String8& prefix, android::Vector<android::String16> *matches,
            uid_t uid) {

        UserState* userState = getUserState(uid);
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
                char *match = (char*) malloc(extra + 1);
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

    void addGrant(const char* filename, uid_t granteeUid) {
        const grant_t* existing = getGrant(filename, granteeUid);
        if (existing == NULL) {
            grant_t* grant = new grant_t;
            grant->uid = granteeUid;
            grant->filename = reinterpret_cast<const uint8_t*>(strdup(filename));
            mGrants.add(grant);
        }
    }

    bool removeGrant(const char* filename, uid_t granteeUid) {
        for (android::Vector<grant_t*>::iterator it(mGrants.begin());
                it != mGrants.end(); it++) {
            grant_t* grant = *it;
            if (grant->uid == granteeUid
                    && !strcmp(reinterpret_cast<const char*>(grant->filename), filename)) {
                mGrants.erase(it);
                return true;
            }
        }
        return false;
    }

    bool hasGrant(const char* filename, const uid_t uid) const {
        return getGrant(filename, uid) != NULL;
    }

    ResponseCode importKey(const uint8_t* key, size_t keyLen, const char* filename, uid_t uid,
            int32_t flags) {
        uint8_t* data;
        size_t dataLength;
        int rc;

        if (mDevice->import_keypair == NULL) {
            ALOGE("Keymaster doesn't support import!");
            return SYSTEM_ERROR;
        }

        bool isFallback = false;
        rc = mDevice->import_keypair(mDevice, key, keyLen, &data, &dataLength);
        if (rc) {
            /*
             * Maybe the device doesn't support this type of key. Try to use the
             * software fallback keymaster implementation. This is a little bit
             * lazier than checking the PKCS#8 key type, but the software
             * implementation will do that anyway.
             */
            rc = mFallbackDevice->import_keypair(mFallbackDevice, key, keyLen, &data, &dataLength);
            isFallback = true;

            if (rc) {
                ALOGE("Error while importing keypair: %d", rc);
                return SYSTEM_ERROR;
            }
        }

        Blob keyBlob(data, dataLength, NULL, 0, TYPE_KEY_PAIR);
        free(data);

        keyBlob.setEncrypted(flags & KEYSTORE_FLAG_ENCRYPTED);
        keyBlob.setFallback(isFallback);

        return put(filename, &keyBlob, uid);
    }

    bool isHardwareBacked(const android::String16& keyType) const {
        if (mDevice == NULL) {
            ALOGW("can't get keymaster device");
            return false;
        }

        if (sRSAKeyType == keyType) {
            return (mDevice->flags & KEYMASTER_SOFTWARE_ONLY) == 0;
        } else {
            return (mDevice->flags & KEYMASTER_SOFTWARE_ONLY) == 0
                    && (mDevice->common.module->module_api_version
                            >= KEYMASTER_MODULE_API_VERSION_0_2);
        }
    }

    ResponseCode getKeyForName(Blob* keyBlob, const android::String8& keyName, const uid_t uid,
            const BlobType type) {
        android::String8 filepath8(getKeyNameForUidWithDir(keyName, uid));

        ResponseCode responseCode = get(filepath8.string(), keyBlob, type, uid);
        if (responseCode == NO_ERROR) {
            return responseCode;
        }

        // If this is one of the legacy UID->UID mappings, use it.
        uid_t euid = get_keystore_euid(uid);
        if (euid != uid) {
            filepath8 = getKeyNameForUidWithDir(keyName, euid);
            responseCode = get(filepath8.string(), keyBlob, type, uid);
            if (responseCode == NO_ERROR) {
                return responseCode;
            }
        }

        // They might be using a granted key.
        android::String8 filename8 = getKeyName(keyName);
        char* end;
        strtoul(filename8.string(), &end, 10);
        if (end[0] != '_' || end[1] == 0) {
            return KEY_NOT_FOUND;
        }
        filepath8 = android::String8::format("%s/%s", getUserState(uid)->getUserDirName(),
                filename8.string());
        if (!hasGrant(filepath8.string(), uid)) {
            return responseCode;
        }

        // It is a granted key. Try to load it.
        return get(filepath8.string(), keyBlob, type, uid);
    }

    /**
     * Returns any existing UserState or creates it if it doesn't exist.
     */
    UserState* getUserState(uid_t uid) {
        uid_t userId = get_user_id(uid);

        for (android::Vector<UserState*>::iterator it(mMasterKeys.begin());
                it != mMasterKeys.end(); it++) {
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

    /**
     * Returns NULL if the UserState doesn't already exist.
     */
    const UserState* getUserState(uid_t uid) const {
        uid_t userId = get_user_id(uid);

        for (android::Vector<UserState*>::const_iterator it(mMasterKeys.begin());
                it != mMasterKeys.end(); it++) {
            UserState* state = *it;
            if (state->getUserId() == userId) {
                return state;
            }
        }

        return NULL;
    }

private:
    static const char* sOldMasterKey;
    static const char* sMetaDataFile;
    static const android::String16 sRSAKeyType;
    Entropy* mEntropy;

    keymaster1_device_t* mDevice;
    keymaster1_device_t* mFallbackDevice;

    android::Vector<UserState*> mMasterKeys;

    android::Vector<grant_t*> mGrants;

    typedef struct {
        uint32_t version;
    } keystore_metadata_t;

    keystore_metadata_t mMetaData;

    const grant_t* getGrant(const char* filename, uid_t uid) const {
        for (android::Vector<grant_t*>::const_iterator it(mGrants.begin());
                it != mGrants.end(); it++) {
            grant_t* grant = *it;
            if (grant->uid == uid
                    && !strcmp(reinterpret_cast<const char*>(grant->filename), filename)) {
                return grant;
            }
        }
        return NULL;
    }

    /**
     * Upgrade code. This will upgrade the key from the current version
     * to whatever is newest.
     */
    bool upgradeBlob(const char* filename, Blob* blob, const uint8_t oldVersion,
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

    /**
     * Takes a blob that is an PEM-encoded RSA key as a byte array and
     * converts it to a DER-encoded PKCS#8 for import into a keymaster.
     * Then it overwrites the original blob with the new blob
     * format that is returned from the keymaster.
     */
    ResponseCode importBlobAsKey(Blob* blob, const char* filename, uid_t uid) {
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

        ResponseCode rc = importKey(pkcs8key.get(), len, filename, uid,
                blob->isEncrypted() ? KEYSTORE_FLAG_ENCRYPTED : KEYSTORE_FLAG_NONE);
        if (rc != NO_ERROR) {
            return rc;
        }

        return get(filename, blob, TYPE_KEY_PAIR, uid);
    }

    void readMetaData() {
        int in = TEMP_FAILURE_RETRY(open(sMetaDataFile, O_RDONLY));
        if (in < 0) {
            return;
        }
        size_t fileLength = readFully(in, (uint8_t*) &mMetaData, sizeof(mMetaData));
        if (fileLength != sizeof(mMetaData)) {
            ALOGI("Metadata file is %zd bytes (%zd experted); upgrade?", fileLength,
                    sizeof(mMetaData));
        }
        close(in);
    }

    void writeMetaData() {
        const char* tmpFileName = ".metadata.tmp";
        int out = TEMP_FAILURE_RETRY(open(tmpFileName,
                O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR));
        if (out < 0) {
            ALOGE("couldn't write metadata file: %s", strerror(errno));
            return;
        }
        size_t fileLength = writeFully(out, (uint8_t*) &mMetaData, sizeof(mMetaData));
        if (fileLength != sizeof(mMetaData)) {
            ALOGI("Could only write %zd bytes to metadata file (%zd expected)", fileLength,
                    sizeof(mMetaData));
        }
        close(out);
        rename(tmpFileName, sMetaDataFile);
    }

    bool upgradeKeystore() {
        bool upgraded = false;

        if (mMetaData.version == 0) {
            UserState* userState = getUserState(0);

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
                UserState* otherUser = getUserState(thisUid);
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
};

const char* KeyStore::sOldMasterKey = ".masterkey";
const char* KeyStore::sMetaDataFile = ".metadata";

const android::String16 KeyStore::sRSAKeyType("RSA");

namespace android {
class KeyStoreProxy : public BnKeystoreService, public IBinder::DeathRecipient {
public:
    KeyStoreProxy(KeyStore* keyStore)
        : mKeyStore(keyStore),
          mOperationMap(this)
    {
    }

    void binderDied(const wp<IBinder>& who) {
        auto operations = mOperationMap.getOperationsForToken(who.unsafe_get());
        for (auto token: operations) {
            abort(token);
        }
    }

    int32_t test() {
        if (!checkBinderPermission(P_TEST)) {
            return ::PERMISSION_DENIED;
        }

        return mKeyStore->getState(IPCThreadState::self()->getCallingUid());
    }

    int32_t get(const String16& name, uint8_t** item, size_t* itemLength) {
        if (!checkBinderPermission(P_GET)) {
            return ::PERMISSION_DENIED;
        }

        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        String8 name8(name);
        Blob keyBlob;

        ResponseCode responseCode = mKeyStore->getKeyForName(&keyBlob, name8, callingUid,
                TYPE_GENERIC);
        if (responseCode != ::NO_ERROR) {
            ALOGW("Could not read %s", name8.string());
            *item = NULL;
            *itemLength = 0;
            return responseCode;
        }

        *item = (uint8_t*) malloc(keyBlob.getLength());
        memcpy(*item, keyBlob.getValue(), keyBlob.getLength());
        *itemLength = keyBlob.getLength();

        return ::NO_ERROR;
    }

    int32_t insert(const String16& name, const uint8_t* item, size_t itemLength, int targetUid,
            int32_t flags) {
        targetUid = getEffectiveUid(targetUid);
        int32_t result = checkBinderPermissionAndKeystoreState(P_INSERT, targetUid,
                                                    flags & KEYSTORE_FLAG_ENCRYPTED);
        if (result != ::NO_ERROR) {
            return result;
        }

        String8 name8(name);
        String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, targetUid));

        Blob keyBlob(item, itemLength, NULL, 0, ::TYPE_GENERIC);
        keyBlob.setEncrypted(flags & KEYSTORE_FLAG_ENCRYPTED);

        return mKeyStore->put(filename.string(), &keyBlob, targetUid);
    }

    int32_t del(const String16& name, int targetUid) {
        targetUid = getEffectiveUid(targetUid);
        if (!checkBinderPermission(P_DELETE, targetUid)) {
            return ::PERMISSION_DENIED;
        }
        String8 name8(name);
        String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, targetUid));
        return mKeyStore->del(filename.string(), ::TYPE_ANY, targetUid);
    }

    int32_t exist(const String16& name, int targetUid) {
        targetUid = getEffectiveUid(targetUid);
        if (!checkBinderPermission(P_EXIST, targetUid)) {
            return ::PERMISSION_DENIED;
        }

        String8 name8(name);
        String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, targetUid));

        if (access(filename.string(), R_OK) == -1) {
            return (errno != ENOENT) ? ::SYSTEM_ERROR : ::KEY_NOT_FOUND;
        }
        return ::NO_ERROR;
    }

    int32_t saw(const String16& prefix, int targetUid, Vector<String16>* matches) {
        targetUid = getEffectiveUid(targetUid);
        if (!checkBinderPermission(P_SAW, targetUid)) {
            return ::PERMISSION_DENIED;
        }
        const String8 prefix8(prefix);
        String8 filename(mKeyStore->getKeyNameForUid(prefix8, targetUid));

        if (mKeyStore->saw(filename, matches, targetUid) != ::NO_ERROR) {
            return ::SYSTEM_ERROR;
        }
        return ::NO_ERROR;
    }

    int32_t reset() {
        if (!checkBinderPermission(P_RESET)) {
            return ::PERMISSION_DENIED;
        }

        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        return mKeyStore->reset(callingUid) ? ::NO_ERROR : ::SYSTEM_ERROR;
    }

    /*
     * Here is the history. To improve the security, the parameters to generate the
     * master key has been changed. To make a seamless transition, we update the
     * file using the same password when the user unlock it for the first time. If
     * any thing goes wrong during the transition, the new file will not overwrite
     * the old one. This avoids permanent damages of the existing data.
     */
    int32_t password(const String16& password) {
        if (!checkBinderPermission(P_PASSWORD)) {
            return ::PERMISSION_DENIED;
        }

        const String8 password8(password);
        uid_t callingUid = IPCThreadState::self()->getCallingUid();

        switch (mKeyStore->getState(callingUid)) {
            case ::STATE_UNINITIALIZED: {
                // generate master key, encrypt with password, write to file, initialize mMasterKey*.
                return mKeyStore->initializeUser(password8, callingUid);
            }
            case ::STATE_NO_ERROR: {
                // rewrite master key with new password.
                return mKeyStore->writeMasterKey(password8, callingUid);
            }
            case ::STATE_LOCKED: {
                // read master key, decrypt with password, initialize mMasterKey*.
                return mKeyStore->readMasterKey(password8, callingUid);
            }
        }
        return ::SYSTEM_ERROR;
    }

    int32_t lock() {
        if (!checkBinderPermission(P_LOCK)) {
            return ::PERMISSION_DENIED;
        }

        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        State state = mKeyStore->getState(callingUid);
        if (state != ::STATE_NO_ERROR) {
            ALOGD("calling lock in state: %d", state);
            return state;
        }

        mKeyStore->lock(callingUid);
        return ::NO_ERROR;
    }

    int32_t unlock(const String16& pw) {
        if (!checkBinderPermission(P_UNLOCK)) {
            return ::PERMISSION_DENIED;
        }

        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        State state = mKeyStore->getState(callingUid);
        if (state != ::STATE_LOCKED) {
            ALOGD("calling unlock when not locked");
            return state;
        }

        const String8 password8(pw);
        return password(pw);
    }

    int32_t zero() {
        if (!checkBinderPermission(P_ZERO)) {
            return -1;
        }

        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        return mKeyStore->isEmpty(callingUid) ? ::KEY_NOT_FOUND : ::NO_ERROR;
    }

    int32_t generate(const String16& name, int32_t targetUid, int32_t keyType, int32_t keySize,
            int32_t flags, Vector<sp<KeystoreArg> >* args) {
        targetUid = getEffectiveUid(targetUid);
        int32_t result = checkBinderPermissionAndKeystoreState(P_INSERT, targetUid,
                                                       flags & KEYSTORE_FLAG_ENCRYPTED);
        if (result != ::NO_ERROR) {
            return result;
        }
        uint8_t* data;
        size_t dataLength;
        int rc;
        bool isFallback = false;

        const keymaster1_device_t* device = mKeyStore->getDevice();
        const keymaster1_device_t* fallback = mKeyStore->getFallbackDevice();
        if (device == NULL) {
            return ::SYSTEM_ERROR;
        }

        if (device->generate_keypair == NULL) {
            return ::SYSTEM_ERROR;
        }

        if (keyType == EVP_PKEY_DSA) {
            keymaster_dsa_keygen_params_t dsa_params;
            memset(&dsa_params, '\0', sizeof(dsa_params));

            if (keySize == -1) {
                keySize = DSA_DEFAULT_KEY_SIZE;
            } else if ((keySize % 64) != 0 || keySize < DSA_MIN_KEY_SIZE
                    || keySize > DSA_MAX_KEY_SIZE) {
                ALOGI("invalid key size %d", keySize);
                return ::SYSTEM_ERROR;
            }
            dsa_params.key_size = keySize;

            if (args->size() == 3) {
                sp<KeystoreArg> gArg = args->itemAt(0);
                sp<KeystoreArg> pArg = args->itemAt(1);
                sp<KeystoreArg> qArg = args->itemAt(2);

                if (gArg != NULL && pArg != NULL && qArg != NULL) {
                    dsa_params.generator = reinterpret_cast<const uint8_t*>(gArg->data());
                    dsa_params.generator_len = gArg->size();

                    dsa_params.prime_p = reinterpret_cast<const uint8_t*>(pArg->data());
                    dsa_params.prime_p_len = pArg->size();

                    dsa_params.prime_q = reinterpret_cast<const uint8_t*>(qArg->data());
                    dsa_params.prime_q_len = qArg->size();
                } else {
                    ALOGI("not all DSA parameters were read");
                    return ::SYSTEM_ERROR;
                }
            } else if (args->size() != 0) {
                ALOGI("DSA args must be 3");
                return ::SYSTEM_ERROR;
            }

            if (isKeyTypeSupported(device, TYPE_DSA)) {
                rc = device->generate_keypair(device, TYPE_DSA, &dsa_params, &data, &dataLength);
            } else {
                isFallback = true;
                rc = fallback->generate_keypair(fallback, TYPE_DSA, &dsa_params, &data,
                                                &dataLength);
            }
        } else if (keyType == EVP_PKEY_EC) {
            keymaster_ec_keygen_params_t ec_params;
            memset(&ec_params, '\0', sizeof(ec_params));

            if (keySize == -1) {
                keySize = EC_DEFAULT_KEY_SIZE;
            } else if (keySize < EC_MIN_KEY_SIZE || keySize > EC_MAX_KEY_SIZE) {
                ALOGI("invalid key size %d", keySize);
                return ::SYSTEM_ERROR;
            }
            ec_params.field_size = keySize;

            if (isKeyTypeSupported(device, TYPE_EC)) {
                rc = device->generate_keypair(device, TYPE_EC, &ec_params, &data, &dataLength);
            } else {
                isFallback = true;
                rc = fallback->generate_keypair(fallback, TYPE_EC, &ec_params, &data, &dataLength);
            }
        } else if (keyType == EVP_PKEY_RSA) {
            keymaster_rsa_keygen_params_t rsa_params;
            memset(&rsa_params, '\0', sizeof(rsa_params));
            rsa_params.public_exponent = RSA_DEFAULT_EXPONENT;

            if (keySize == -1) {
                keySize = RSA_DEFAULT_KEY_SIZE;
            } else if (keySize < RSA_MIN_KEY_SIZE || keySize > RSA_MAX_KEY_SIZE) {
                ALOGI("invalid key size %d", keySize);
                return ::SYSTEM_ERROR;
            }
            rsa_params.modulus_size = keySize;

            if (args->size() > 1) {
                ALOGI("invalid number of arguments: %zu", args->size());
                return ::SYSTEM_ERROR;
            } else if (args->size() == 1) {
                sp<KeystoreArg> pubExpBlob = args->itemAt(0);
                if (pubExpBlob != NULL) {
                    Unique_BIGNUM pubExpBn(
                            BN_bin2bn(reinterpret_cast<const unsigned char*>(pubExpBlob->data()),
                                    pubExpBlob->size(), NULL));
                    if (pubExpBn.get() == NULL) {
                        ALOGI("Could not convert public exponent to BN");
                        return ::SYSTEM_ERROR;
                    }
                    unsigned long pubExp = BN_get_word(pubExpBn.get());
                    if (pubExp == 0xFFFFFFFFL) {
                        ALOGI("cannot represent public exponent as a long value");
                        return ::SYSTEM_ERROR;
                    }
                    rsa_params.public_exponent = pubExp;
                }
            }

            rc = device->generate_keypair(device, TYPE_RSA, &rsa_params, &data, &dataLength);
        } else {
            ALOGW("Unsupported key type %d", keyType);
            rc = -1;
        }

        if (rc) {
            return ::SYSTEM_ERROR;
        }

        String8 name8(name);
        String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, targetUid));

        Blob keyBlob(data, dataLength, NULL, 0, TYPE_KEY_PAIR);
        free(data);

        keyBlob.setEncrypted(flags & KEYSTORE_FLAG_ENCRYPTED);
        keyBlob.setFallback(isFallback);

        return mKeyStore->put(filename.string(), &keyBlob, targetUid);
    }

    int32_t import(const String16& name, const uint8_t* data, size_t length, int targetUid,
            int32_t flags) {
        targetUid = getEffectiveUid(targetUid);
        int32_t result = checkBinderPermissionAndKeystoreState(P_INSERT, targetUid,
                                                       flags & KEYSTORE_FLAG_ENCRYPTED);
        if (result != ::NO_ERROR) {
            return result;
        }
        String8 name8(name);
        String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, targetUid));

        return mKeyStore->importKey(data, length, filename.string(), targetUid, flags);
    }

    int32_t sign(const String16& name, const uint8_t* data, size_t length, uint8_t** out,
            size_t* outLength) {
        if (!checkBinderPermission(P_SIGN)) {
            return ::PERMISSION_DENIED;
        }

        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        Blob keyBlob;
        String8 name8(name);

        ALOGV("sign %s from uid %d", name8.string(), callingUid);

        ResponseCode responseCode = mKeyStore->getKeyForName(&keyBlob, name8, callingUid,
                ::TYPE_KEY_PAIR);
        if (responseCode != ::NO_ERROR) {
            return responseCode;
        }

        const keymaster1_device_t* device = mKeyStore->getDeviceForBlob(keyBlob);
        if (device == NULL) {
            ALOGE("no keymaster device; cannot sign");
            return ::SYSTEM_ERROR;
        }

        if (device->sign_data == NULL) {
            ALOGE("device doesn't implement signing");
            return ::SYSTEM_ERROR;
        }

        keymaster_rsa_sign_params_t params;
        params.digest_type = DIGEST_NONE;
        params.padding_type = PADDING_NONE;
        int rc = device->sign_data(device, &params, keyBlob.getValue(), keyBlob.getLength(), data,
                length, out, outLength);
        if (rc) {
            ALOGW("device couldn't sign data");
            return ::SYSTEM_ERROR;
        }

        return ::NO_ERROR;
    }

    int32_t verify(const String16& name, const uint8_t* data, size_t dataLength,
            const uint8_t* signature, size_t signatureLength) {
        if (!checkBinderPermission(P_VERIFY)) {
            return ::PERMISSION_DENIED;
        }

        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        Blob keyBlob;
        String8 name8(name);
        int rc;

        ResponseCode responseCode = mKeyStore->getKeyForName(&keyBlob, name8, callingUid,
                TYPE_KEY_PAIR);
        if (responseCode != ::NO_ERROR) {
            return responseCode;
        }

        const keymaster1_device_t* device = mKeyStore->getDeviceForBlob(keyBlob);
        if (device == NULL) {
            return ::SYSTEM_ERROR;
        }

        if (device->verify_data == NULL) {
            return ::SYSTEM_ERROR;
        }

        keymaster_rsa_sign_params_t params;
        params.digest_type = DIGEST_NONE;
        params.padding_type = PADDING_NONE;

        rc = device->verify_data(device, &params, keyBlob.getValue(), keyBlob.getLength(), data,
                dataLength, signature, signatureLength);
        if (rc) {
            return ::SYSTEM_ERROR;
        } else {
            return ::NO_ERROR;
        }
    }

    /*
     * TODO: The abstraction between things stored in hardware and regular blobs
     * of data stored on the filesystem should be moved down to keystore itself.
     * Unfortunately the Java code that calls this has naming conventions that it
     * knows about. Ideally keystore shouldn't be used to store random blobs of
     * data.
     *
     * Until that happens, it's necessary to have a separate "get_pubkey" and
     * "del_key" since the Java code doesn't really communicate what it's
     * intentions are.
     */
    int32_t get_pubkey(const String16& name, uint8_t** pubkey, size_t* pubkeyLength) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!checkBinderPermission(P_GET)) {
            ALOGW("permission denied for %d: get_pubkey", callingUid);
            return ::PERMISSION_DENIED;
        }

        Blob keyBlob;
        String8 name8(name);

        ALOGV("get_pubkey '%s' from uid %d", name8.string(), callingUid);

        ResponseCode responseCode = mKeyStore->getKeyForName(&keyBlob, name8, callingUid,
                TYPE_KEY_PAIR);
        if (responseCode != ::NO_ERROR) {
            return responseCode;
        }

        const keymaster1_device_t* device = mKeyStore->getDeviceForBlob(keyBlob);
        if (device == NULL) {
            return ::SYSTEM_ERROR;
        }

        if (device->get_keypair_public == NULL) {
            ALOGE("device has no get_keypair_public implementation!");
            return ::SYSTEM_ERROR;
        }

        int rc;
        rc = device->get_keypair_public(device, keyBlob.getValue(), keyBlob.getLength(), pubkey,
                pubkeyLength);
        if (rc) {
            return ::SYSTEM_ERROR;
        }

        return ::NO_ERROR;
    }

    int32_t del_key(const String16& name, int targetUid) {
        return del(name, targetUid);
    }

    int32_t grant(const String16& name, int32_t granteeUid) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        int32_t result = checkBinderPermissionAndKeystoreState(P_GRANT);
        if (result != ::NO_ERROR) {
            return result;
        }

        String8 name8(name);
        String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, callingUid));

        if (access(filename.string(), R_OK) == -1) {
            return (errno != ENOENT) ? ::SYSTEM_ERROR : ::KEY_NOT_FOUND;
        }

        mKeyStore->addGrant(filename.string(), granteeUid);
        return ::NO_ERROR;
    }

    int32_t ungrant(const String16& name, int32_t granteeUid) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        int32_t result = checkBinderPermissionAndKeystoreState(P_GRANT);
        if (result != ::NO_ERROR) {
            return result;
        }

        String8 name8(name);
        String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, callingUid));

        if (access(filename.string(), R_OK) == -1) {
            return (errno != ENOENT) ? ::SYSTEM_ERROR : ::KEY_NOT_FOUND;
        }

        return mKeyStore->removeGrant(filename.string(), granteeUid) ? ::NO_ERROR : ::KEY_NOT_FOUND;
    }

    int64_t getmtime(const String16& name) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!checkBinderPermission(P_GET)) {
            ALOGW("permission denied for %d: getmtime", callingUid);
            return -1L;
        }

        String8 name8(name);
        String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, callingUid));

        if (access(filename.string(), R_OK) == -1) {
            ALOGW("could not access %s for getmtime", filename.string());
            return -1L;
        }

        int fd = TEMP_FAILURE_RETRY(open(filename.string(), O_NOFOLLOW, O_RDONLY));
        if (fd < 0) {
            ALOGW("could not open %s for getmtime", filename.string());
            return -1L;
        }

        struct stat s;
        int ret = fstat(fd, &s);
        close(fd);
        if (ret == -1) {
            ALOGW("could not stat %s for getmtime", filename.string());
            return -1L;
        }

        return static_cast<int64_t>(s.st_mtime);
    }

    int32_t duplicate(const String16& srcKey, int32_t srcUid, const String16& destKey,
            int32_t destUid) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        pid_t spid = IPCThreadState::self()->getCallingPid();
        if (!has_permission(callingUid, P_DUPLICATE, spid)) {
            ALOGW("permission denied for %d: duplicate", callingUid);
            return -1L;
        }

        State state = mKeyStore->getState(callingUid);
        if (!isKeystoreUnlocked(state)) {
            ALOGD("calling duplicate in state: %d", state);
            return state;
        }

        if (srcUid == -1 || static_cast<uid_t>(srcUid) == callingUid) {
            srcUid = callingUid;
        } else if (!is_granted_to(callingUid, srcUid)) {
            ALOGD("migrate not granted from source: %d -> %d", callingUid, srcUid);
            return ::PERMISSION_DENIED;
        }

        if (destUid == -1) {
            destUid = callingUid;
        }

        if (srcUid != destUid) {
            if (static_cast<uid_t>(srcUid) != callingUid) {
                ALOGD("can only duplicate from caller to other or to same uid: "
                      "calling=%d, srcUid=%d, destUid=%d", callingUid, srcUid, destUid);
                return ::PERMISSION_DENIED;
            }

            if (!is_granted_to(callingUid, destUid)) {
                ALOGD("duplicate not granted to dest: %d -> %d", callingUid, destUid);
                return ::PERMISSION_DENIED;
            }
        }

        String8 source8(srcKey);
        String8 sourceFile(mKeyStore->getKeyNameForUidWithDir(source8, srcUid));

        String8 target8(destKey);
        String8 targetFile(mKeyStore->getKeyNameForUidWithDir(target8, destUid));

        if (access(targetFile.string(), W_OK) != -1 || errno != ENOENT) {
            ALOGD("destination already exists: %s", targetFile.string());
            return ::SYSTEM_ERROR;
        }

        Blob keyBlob;
        ResponseCode responseCode = mKeyStore->get(sourceFile.string(), &keyBlob, TYPE_ANY,
                srcUid);
        if (responseCode != ::NO_ERROR) {
            return responseCode;
        }

        return mKeyStore->put(targetFile.string(), &keyBlob, destUid);
    }

    int32_t is_hardware_backed(const String16& keyType) {
        return mKeyStore->isHardwareBacked(keyType) ? 1 : 0;
    }

    int32_t clear_uid(int64_t targetUid64) {
        uid_t targetUid = getEffectiveUid(targetUid64);
        if (!checkBinderPermission(P_CLEAR_UID, targetUid)) {
            return ::PERMISSION_DENIED;
        }

        String8 prefix = String8::format("%u_", targetUid);
        Vector<String16> aliases;
        if (mKeyStore->saw(prefix, &aliases, targetUid) != ::NO_ERROR) {
            return ::SYSTEM_ERROR;
        }

        for (uint32_t i = 0; i < aliases.size(); i++) {
            String8 name8(aliases[i]);
            String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, targetUid));
            mKeyStore->del(filename.string(), ::TYPE_ANY, targetUid);
        }
        return ::NO_ERROR;
    }

    int32_t reset_uid(int32_t targetUid) {
        targetUid = getEffectiveUid(targetUid);
        if (!checkBinderPermission(P_RESET_UID, targetUid)) {
            return ::PERMISSION_DENIED;
        }
        // Flush the auth token table to prevent stale tokens from sticking
        // around.
        mAuthTokenTable.Clear();

        return mKeyStore->reset(targetUid) ? ::NO_ERROR : ::SYSTEM_ERROR;
    }

    int32_t sync_uid(int32_t sourceUid, int32_t targetUid) {
        if (!checkBinderPermission(P_SYNC_UID, targetUid)) {
            return ::PERMISSION_DENIED;
        }

        if (sourceUid == targetUid) {
            return ::SYSTEM_ERROR;
        }

        // Initialise user keystore with existing master key held in-memory
        return mKeyStore->copyMasterKey(sourceUid, targetUid);
    }

    int32_t password_uid(const String16& pw, int32_t targetUid) {
        targetUid = getEffectiveUid(targetUid);
        if (!checkBinderPermission(P_PASSWORD, targetUid)) {
            return ::PERMISSION_DENIED;
        }
        const String8 password8(pw);

        switch (mKeyStore->getState(targetUid)) {
            case ::STATE_UNINITIALIZED: {
                // generate master key, encrypt with password, write to file, initialize mMasterKey*.
                return mKeyStore->initializeUser(password8, targetUid);
            }
            case ::STATE_NO_ERROR: {
                // rewrite master key with new password.
                return mKeyStore->writeMasterKey(password8, targetUid);
            }
            case ::STATE_LOCKED: {
                // read master key, decrypt with password, initialize mMasterKey*.
                return mKeyStore->readMasterKey(password8, targetUid);
            }
        }
        return ::SYSTEM_ERROR;
    }

    int32_t addRngEntropy(const uint8_t* data, size_t dataLength) {
        const keymaster1_device_t* device = mKeyStore->getDevice();
        const keymaster1_device_t* fallback = mKeyStore->getFallbackDevice();
        int32_t devResult = KM_ERROR_UNIMPLEMENTED;
        int32_t fallbackResult = KM_ERROR_UNIMPLEMENTED;
        if (device->common.module->module_api_version >= KEYMASTER_MODULE_API_VERSION_1_0 &&
                device->add_rng_entropy != NULL) {
            devResult = device->add_rng_entropy(device, data, dataLength);
        }
        if (fallback->add_rng_entropy) {
            fallbackResult = fallback->add_rng_entropy(fallback, data, dataLength);
        }
        if (devResult) {
            return devResult;
        }
        if (fallbackResult) {
            return fallbackResult;
        }
        return ::NO_ERROR;
    }

    int32_t generateKey(const String16& name, const KeymasterArguments& params,
                        const uint8_t* entropy, size_t entropyLength, int uid, int flags,
                        KeyCharacteristics* outCharacteristics) {
        uid = getEffectiveUid(uid);
        int rc = checkBinderPermissionAndKeystoreState(P_INSERT, uid,
                                                       flags & KEYSTORE_FLAG_ENCRYPTED);
        if (rc != ::NO_ERROR) {
            return rc;
        }

        rc = KM_ERROR_UNIMPLEMENTED;
        bool isFallback = false;
        keymaster_key_blob_t blob;
        keymaster_key_characteristics_t *out = NULL;

        const keymaster1_device_t* device = mKeyStore->getDevice();
        const keymaster1_device_t* fallback = mKeyStore->getFallbackDevice();
        if (device == NULL) {
            return ::SYSTEM_ERROR;
        }
        // TODO: Seed from Linux RNG before this.
        if (device->common.module->module_api_version >= KEYMASTER_MODULE_API_VERSION_1_0 &&
                device->generate_key != NULL) {
            if (!entropy) {
                rc = KM_ERROR_OK;
            } else if (device->add_rng_entropy) {
                rc = device->add_rng_entropy(device, entropy, entropyLength);
            } else {
                rc = KM_ERROR_UNIMPLEMENTED;
            }
            if (rc == KM_ERROR_OK) {
                rc = device->generate_key(device, params.params.data(), params.params.size(),
                                          &blob, &out);
            }
        }
        // If the HW device didn't support generate_key or generate_key failed
        // fall back to the software implementation.
        if (rc && fallback->generate_key != NULL) {
            isFallback = true;
            if (!entropy) {
                rc = KM_ERROR_OK;
            } else if (fallback->add_rng_entropy) {
                rc = fallback->add_rng_entropy(fallback, entropy, entropyLength);
            } else {
                rc = KM_ERROR_UNIMPLEMENTED;
            }
            if (rc == KM_ERROR_OK) {
                rc = fallback->generate_key(fallback, params.params.data(), params.params.size(),
                                            &blob,
                                            &out);
            }
        }

        if (out) {
            if (outCharacteristics) {
                outCharacteristics->characteristics = *out;
            } else {
                keymaster_free_characteristics(out);
            }
            free(out);
        }

        if (rc) {
            return rc;
        }

        String8 name8(name);
        String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, uid));

        Blob keyBlob(blob.key_material, blob.key_material_size, NULL, 0, ::TYPE_KEYMASTER_10);
        keyBlob.setFallback(isFallback);
        keyBlob.setEncrypted(flags & KEYSTORE_FLAG_ENCRYPTED);

        free(const_cast<uint8_t*>(blob.key_material));

        return mKeyStore->put(filename.string(), &keyBlob, uid);
    }

    int32_t getKeyCharacteristics(const String16& name,
                                  const keymaster_blob_t* clientId,
                                  const keymaster_blob_t* appData,
                                  KeyCharacteristics* outCharacteristics) {
        if (!outCharacteristics) {
            return KM_ERROR_UNEXPECTED_NULL_POINTER;
        }

        uid_t callingUid = IPCThreadState::self()->getCallingUid();

        Blob keyBlob;
        String8 name8(name);
        int rc;

        ResponseCode responseCode = mKeyStore->getKeyForName(&keyBlob, name8, callingUid,
                TYPE_KEYMASTER_10);
        if (responseCode != ::NO_ERROR) {
            return responseCode;
        }
        keymaster_key_blob_t key;
        key.key_material_size = keyBlob.getLength();
        key.key_material = keyBlob.getValue();
        keymaster1_device_t* dev = mKeyStore->getDeviceForBlob(keyBlob);
        keymaster_key_characteristics_t *out = NULL;
        if (!dev->get_key_characteristics) {
            ALOGW("device does not implement get_key_characteristics");
            return KM_ERROR_UNIMPLEMENTED;
        }
        rc = dev->get_key_characteristics(dev, &key, clientId, appData, &out);
        if (out) {
            outCharacteristics->characteristics = *out;
            free(out);
        }
        return rc ? rc : ::NO_ERROR;
    }

    int32_t importKey(const String16& name, const KeymasterArguments& params,
                                keymaster_key_format_t format, const uint8_t *keyData,
                                size_t keyLength, int uid, int flags,
                                KeyCharacteristics* outCharacteristics) {
        uid = getEffectiveUid(uid);
        int rc = checkBinderPermissionAndKeystoreState(P_INSERT, uid,
                                                       flags & KEYSTORE_FLAG_ENCRYPTED);
        if (rc != ::NO_ERROR) {
            return rc;
        }

        rc = KM_ERROR_UNIMPLEMENTED;
        bool isFallback = false;
        keymaster_key_blob_t blob;
        keymaster_key_characteristics_t *out = NULL;

        const keymaster1_device_t* device = mKeyStore->getDevice();
        const keymaster1_device_t* fallback = mKeyStore->getFallbackDevice();
        if (device == NULL) {
            return ::SYSTEM_ERROR;
        }
        if (device->common.module->module_api_version >= KEYMASTER_MODULE_API_VERSION_1_0 &&
                device->import_key != NULL) {
            rc = device->import_key(device, params.params.data(), params.params.size(),
                                    format, keyData, keyLength, &blob, &out);
        }
        if (rc && fallback->import_key != NULL) {
            isFallback = true;
            rc = fallback->import_key(fallback, params.params.data(), params.params.size(),
                                      format, keyData, keyLength, &blob, &out);
        }
        if (out) {
            if (outCharacteristics) {
                outCharacteristics->characteristics = *out;
            } else {
                keymaster_free_characteristics(out);
            }
            free(out);
        }
        if (rc) {
            return rc;
        }

        String8 name8(name);
        String8 filename(mKeyStore->getKeyNameForUidWithDir(name8, uid));

        Blob keyBlob(blob.key_material, blob.key_material_size, NULL, 0, ::TYPE_KEYMASTER_10);
        keyBlob.setFallback(isFallback);
        keyBlob.setEncrypted(flags & KEYSTORE_FLAG_ENCRYPTED);

        free((void*) blob.key_material);

        return mKeyStore->put(filename.string(), &keyBlob, uid);
    }

    void exportKey(const String16& name, keymaster_key_format_t format,
                           const keymaster_blob_t* clientId,
                           const keymaster_blob_t* appData, ExportResult* result) {

        uid_t callingUid = IPCThreadState::self()->getCallingUid();

        Blob keyBlob;
        String8 name8(name);
        int rc;

        ResponseCode responseCode = mKeyStore->getKeyForName(&keyBlob, name8, callingUid,
                TYPE_KEYMASTER_10);
        if (responseCode != ::NO_ERROR) {
            result->resultCode = responseCode;
            return;
        }
        keymaster_key_blob_t key;
        key.key_material_size = keyBlob.getLength();
        key.key_material = keyBlob.getValue();
        keymaster1_device_t* dev = mKeyStore->getDeviceForBlob(keyBlob);
        if (!dev->export_key) {
            result->resultCode = KM_ERROR_UNIMPLEMENTED;
            return;
        }
        uint8_t* ptr = NULL;
        rc = dev->export_key(dev, format, &key, clientId, appData,
                                             &ptr, &result->dataLength);
        result->exportData.reset(ptr);
        result->resultCode = rc ? rc : ::NO_ERROR;
    }

    /**
     * Check that all keymaster_key_param_t's provided by the application are
     * allowed. Any parameter that keystore adds itself should be disallowed here.
     */
    bool checkAllowedOperationParams(const std::vector<keymaster_key_param_t>& params) {
        for (auto param: params) {
            switch (param.tag) {
                case KM_TAG_AUTH_TOKEN:
                    return false;
                default:
                    break;
            }
        }
        return true;
    }

    int authorizeOperation(const keymaster_key_characteristics_t& characteristics,
                            keymaster_operation_handle_t handle,
                            std::vector<keymaster_key_param_t>* params,
                            bool failOnTokenMissing=true) {
        if (!checkAllowedOperationParams(*params)) {
            return KM_ERROR_INVALID_ARGUMENT;
        }
        std::vector<keymaster_key_param_t> allCharacteristics;
        for (size_t i = 0; i < characteristics.sw_enforced.length; i++) {
            allCharacteristics.push_back(characteristics.sw_enforced.params[i]);
        }
        for (size_t i = 0; i < characteristics.hw_enforced.length; i++) {
            allCharacteristics.push_back(characteristics.hw_enforced.params[i]);
        }
        // Check for auth token and add it to the param list if present.
        const hw_auth_token_t* authToken;
        switch (mAuthTokenTable.FindAuthorization(allCharacteristics.data(),
                                                  allCharacteristics.size(), handle, &authToken)) {
        case keymaster::AuthTokenTable::OK:
            // Auth token found.
            params->push_back(keymaster_param_blob(KM_TAG_AUTH_TOKEN,
                                                   reinterpret_cast<const uint8_t*>(authToken),
                                                   sizeof(hw_auth_token_t)));
            break;
        case keymaster::AuthTokenTable::AUTH_NOT_REQUIRED:
            return KM_ERROR_OK;
        case keymaster::AuthTokenTable::AUTH_TOKEN_NOT_FOUND:
        case keymaster::AuthTokenTable::OP_HANDLE_REQUIRED:
        case keymaster::AuthTokenTable::AUTH_TOKEN_EXPIRED:
            if (failOnTokenMissing) {
                return KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
            }
            break;
        case keymaster::AuthTokenTable::AUTH_TOKEN_WRONG_SID:
            return KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
        default:
            return KM_ERROR_INVALID_ARGUMENT;
        }
        // TODO: Enforce the rest of authorization
        return KM_ERROR_OK;
    }

    keymaster_error_t getOperationCharacteristics(const keymaster_key_blob_t& key,
                                    const keymaster1_device_t* dev,
                                    const std::vector<keymaster_key_param_t>& params,
                                    keymaster_key_characteristics_t* out) {
        UniquePtr<keymaster_blob_t> appId;
        UniquePtr<keymaster_blob_t> appData;
        for (auto param : params) {
            if (param.tag == KM_TAG_APPLICATION_ID) {
                appId.reset(new keymaster_blob_t);
                appId->data = param.blob.data;
                appId->data_length = param.blob.data_length;
            } else if (param.tag == KM_TAG_APPLICATION_DATA) {
                appData.reset(new keymaster_blob_t);
                appData->data = param.blob.data;
                appData->data_length = param.blob.data_length;
            }
        }
        keymaster_key_characteristics_t* result = NULL;
        if (!dev->get_key_characteristics) {
            return KM_ERROR_UNIMPLEMENTED;
        }
        keymaster_error_t error = dev->get_key_characteristics(dev, &key, appId.get(),
                                                               appData.get(), &result);
        if (result) {
            *out = *result;
            free(result);
        }
        return error;
    }

    void begin(const sp<IBinder>& appToken, const String16& name, keymaster_purpose_t purpose,
               bool pruneable, const KeymasterArguments& params, const uint8_t* entropy,
               size_t entropyLength, KeymasterArguments* outParams, OperationResult* result) {
        if (!result || !outParams) {
            ALOGE("Unexpected null arguments to begin()");
            return;
        }
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!pruneable && get_app_id(callingUid) != AID_SYSTEM) {
            ALOGE("Non-system uid %d trying to start non-pruneable operation", callingUid);
            result->resultCode = ::PERMISSION_DENIED;
            return;
        }
        Blob keyBlob;
        String8 name8(name);
        ResponseCode responseCode = mKeyStore->getKeyForName(&keyBlob, name8, callingUid,
                TYPE_KEYMASTER_10);
        if (responseCode != ::NO_ERROR) {
            result->resultCode = responseCode;
            return;
        }
        keymaster_key_blob_t key;
        key.key_material_size = keyBlob.getLength();
        key.key_material = keyBlob.getValue();
        keymaster_key_param_t* out;
        size_t outSize;
        keymaster_operation_handle_t handle;
        keymaster1_device_t* dev = mKeyStore->getDeviceForBlob(keyBlob);
        keymaster_error_t err = KM_ERROR_UNIMPLEMENTED;
        std::vector<keymaster_key_param_t> opParams(params.params);
        Unique_keymaster_key_characteristics characteristics;
        characteristics.reset(new keymaster_key_characteristics_t);
        err = getOperationCharacteristics(key, dev, opParams, characteristics.get());
        if (err) {
            result->resultCode = err;
            return;
        }
        // Don't require an auth token for the call to begin, authentication can
        // require an operation handle. Update and finish will require the token
        // be present and valid.
        int32_t authResult = authorizeOperation(*characteristics, 0, &opParams,
                                                /*failOnTokenMissing*/ false);
        if (authResult) {
            result->resultCode = err;
            return;
        }
        // Add entropy to the device first.
        if (entropy) {
            if (dev->add_rng_entropy) {
                err = dev->add_rng_entropy(dev, entropy, entropyLength);
            } else {
                err = KM_ERROR_UNIMPLEMENTED;
            }
            if (err) {
                result->resultCode = err;
                return;
            }
        }
        // Don't do an auth check here, we need begin to succeed for
        // per-operation auth. update/finish will be doing the auth checks.
        err = dev->begin(dev, purpose, &key, opParams.data(), opParams.size(), &out, &outSize,
                         &handle);

        // If there are too many operations abort the oldest operation that was
        // started as pruneable and try again.
        while (err == KM_ERROR_TOO_MANY_OPERATIONS && mOperationMap.hasPruneableOperation()) {
            sp<IBinder> oldest = mOperationMap.getOldestPruneableOperation();
            ALOGD("Ran out of operation handles, trying to prune %p", oldest.get());
            if (abort(oldest) != ::NO_ERROR) {
                break;
            }
            err = dev->begin(dev, purpose, &key, params.params.data(),
                             params.params.size(), &out, &outSize,
                             &handle);
        }
        if (err) {
            result->resultCode = err;
            return;
        }
        if (out) {
            outParams->params.assign(out, out + outSize);
            free(out);
        }

        sp<IBinder> operationToken = mOperationMap.addOperation(handle, dev, appToken,
                                                                characteristics.release(),
                                                                pruneable);
        result->resultCode = ::NO_ERROR;
        result->token = operationToken;
        result->handle = handle;
    }

    void update(const sp<IBinder>& token, const KeymasterArguments& params, const uint8_t* data,
                size_t dataLength, OperationResult* result) {
        const keymaster1_device_t* dev;
        keymaster_operation_handle_t handle;
        const keymaster_key_characteristics_t* characteristics;
        if (!mOperationMap.getOperation(token, &handle, &dev, &characteristics)) {
            result->resultCode = KM_ERROR_INVALID_OPERATION_HANDLE;
            return;
        }
        uint8_t* output_buf = NULL;
        size_t output_length = 0;
        size_t consumed = 0;
        std::vector<keymaster_key_param_t> opParams(params.params);
        int32_t authResult = authorizeOperation(*characteristics, handle, &opParams);
        if (authResult) {
            result->resultCode = authResult;
            return;
        }
        keymaster_error_t err = dev->update(dev, handle, opParams.data(), opParams.size(), data,
                                            dataLength, &consumed, &output_buf, &output_length);
        result->data.reset(output_buf);
        result->dataLength = output_length;
        result->inputConsumed = consumed;
        result->resultCode = err ? (int32_t) err : ::NO_ERROR;
    }

    void finish(const sp<IBinder>& token, const KeymasterArguments& params,
                const uint8_t* signature, size_t signatureLength, OperationResult* result) {
        const keymaster1_device_t* dev;
        keymaster_operation_handle_t handle;
        const keymaster_key_characteristics_t* characteristics;
        if (!mOperationMap.getOperation(token, &handle, &dev, &characteristics)) {
            result->resultCode = KM_ERROR_INVALID_OPERATION_HANDLE;
            return;
        }
        uint8_t* output_buf = NULL;
        size_t output_length = 0;
        std::vector<keymaster_key_param_t> opParams(params.params);
        int32_t authResult = authorizeOperation(*characteristics, handle, &opParams);
        if (authResult) {
            result->resultCode = authResult;
            return;
        }
        keymaster_error_t err = dev->finish(dev, handle, opParams.data(), opParams.size(),
                                            signature, signatureLength, &output_buf,
                                            &output_length);
        // Remove the operation regardless of the result
        mOperationMap.removeOperation(token);
        mAuthTokenTable.MarkCompleted(handle);
        result->data.reset(output_buf);
        result->dataLength = output_length;
        result->resultCode = err ? (int32_t) err : ::NO_ERROR;
    }

    int32_t abort(const sp<IBinder>& token) {
        const keymaster1_device_t* dev;
        keymaster_operation_handle_t handle;
        if (!mOperationMap.getOperation(token, &handle, &dev, NULL)) {
            return KM_ERROR_INVALID_OPERATION_HANDLE;
        }
        mOperationMap.removeOperation(token);
        int32_t rc;
        if (!dev->abort) {
            rc = KM_ERROR_UNIMPLEMENTED;
        } else {
            rc = dev->abort(dev, handle);
        }
        mAuthTokenTable.MarkCompleted(handle);
        if (rc) {
            return rc;
        }
        return ::NO_ERROR;
    }

    bool isOperationAuthorized(const sp<IBinder>& token) {
        const keymaster1_device_t* dev;
        keymaster_operation_handle_t handle;
        const keymaster_key_characteristics_t* characteristics;
        if (!mOperationMap.getOperation(token, &handle, &dev, &characteristics)) {
            return false;
        }
        std::vector<keymaster_key_param_t> ignored;
        int32_t authResult = authorizeOperation(*characteristics, handle, &ignored);
        return authResult == KM_ERROR_OK;
    }

    int32_t addAuthToken(const uint8_t* token, size_t length) {
        if (!checkBinderPermission(P_ADD_AUTH)) {
            ALOGW("addAuthToken: permission denied for %d",
                  IPCThreadState::self()->getCallingUid());
            return ::PERMISSION_DENIED;
        }
        if (length != sizeof(hw_auth_token_t)) {
            return KM_ERROR_INVALID_ARGUMENT;
        }
        hw_auth_token_t* authToken = new hw_auth_token_t;
        memcpy(reinterpret_cast<void*>(authToken), token, sizeof(hw_auth_token_t));
        // The table takes ownership of authToken.
        mAuthTokenTable.AddAuthenticationToken(authToken);
        return ::NO_ERROR;
    }

private:
    static const int32_t UID_SELF = -1;

    /**
     * Get the effective target uid for a binder operation that takes an
     * optional uid as the target.
     */
    inline uid_t getEffectiveUid(int32_t targetUid) {
        if (targetUid == UID_SELF) {
            return IPCThreadState::self()->getCallingUid();
        }
        return static_cast<uid_t>(targetUid);
    }

    /**
     * Check if the caller of the current binder method has the required
     * permission and if acting on other uids the grants to do so.
     */
    inline bool checkBinderPermission(perm_t permission, int32_t targetUid = UID_SELF) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        pid_t spid = IPCThreadState::self()->getCallingPid();
        if (!has_permission(callingUid, permission, spid)) {
            ALOGW("permission %s denied for %d", get_perm_label(permission), callingUid);
            return false;
        }
        if (!is_granted_to(callingUid, getEffectiveUid(targetUid))) {
            ALOGW("uid %d not granted to act for %d", callingUid, targetUid);
            return false;
        }
        return true;
    }

    /**
     * Check if the caller of the current binder method has the required
     * permission or the target of the operation is the caller's uid. This is
     * for operation where the permission is only for cross-uid activity and all
     * uids are allowed to act on their own (ie: clearing all entries for a
     * given uid).
     */
    inline bool checkBinderPermissionOrSelfTarget(perm_t permission, int32_t targetUid) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (getEffectiveUid(targetUid) == callingUid) {
            return true;
        } else {
            return checkBinderPermission(permission, targetUid);
        }
    }

    /**
     * Helper method to check that the caller has the required permission as
     * well as the keystore is in the unlocked state if checkUnlocked is true.
     *
     * Returns NO_ERROR on success, PERMISSION_DENIED on a permission error and
     * otherwise the state of keystore when not unlocked and checkUnlocked is
     * true.
     */
    inline int32_t checkBinderPermissionAndKeystoreState(perm_t permission, int32_t targetUid = -1,
                                                 bool checkUnlocked = true) {
        if (!checkBinderPermission(permission, targetUid)) {
            return ::PERMISSION_DENIED;
        }
        State state = mKeyStore->getState(getEffectiveUid(targetUid));
        if (checkUnlocked && !isKeystoreUnlocked(state)) {
            return state;
        }

        return ::NO_ERROR;

    }

    inline bool isKeystoreUnlocked(State state) {
        switch (state) {
        case ::STATE_NO_ERROR:
            return true;
        case ::STATE_UNINITIALIZED:
        case ::STATE_LOCKED:
            return false;
        }
        return false;
    }

    bool isKeyTypeSupported(const keymaster1_device_t* device, keymaster_keypair_t keyType) {
        const int32_t device_api = device->common.module->module_api_version;
        if (device_api == KEYMASTER_MODULE_API_VERSION_0_2) {
            switch (keyType) {
                case TYPE_RSA:
                case TYPE_DSA:
                case TYPE_EC:
                    return true;
                default:
                    return false;
            }
        } else if (device_api >= KEYMASTER_MODULE_API_VERSION_0_3) {
            switch (keyType) {
                case TYPE_RSA:
                    return true;
                case TYPE_DSA:
                    return device->flags & KEYMASTER_SUPPORTS_DSA;
                case TYPE_EC:
                    return device->flags & KEYMASTER_SUPPORTS_EC;
                default:
                    return false;
            }
        } else {
            return keyType == TYPE_RSA;
        }
    }

    ::KeyStore* mKeyStore;
    OperationMap mOperationMap;
    keymaster::AuthTokenTable mAuthTokenTable;
};

}; // namespace android

int main(int argc, char* argv[]) {
    if (argc < 2) {
        ALOGE("A directory must be specified!");
        return 1;
    }
    if (chdir(argv[1]) == -1) {
        ALOGE("chdir: %s: %s", argv[1], strerror(errno));
        return 1;
    }

    Entropy entropy;
    if (!entropy.open()) {
        return 1;
    }

    keymaster0_device_t* dev;
    if (keymaster_device_initialize(&dev)) {
        ALOGE("keystore keymaster could not be initialized; exiting");
        return 1;
    }

    keymaster1_device_t* fallback;
    if (fallback_keymaster_device_initialize(&fallback)) {
        ALOGE("software keymaster could not be initialized; exiting");
        return 1;
    }

    ks_is_selinux_enabled = is_selinux_enabled();
    if (ks_is_selinux_enabled) {
        union selinux_callback cb;
        cb.func_log = selinux_log_callback;
        selinux_set_callback(SELINUX_CB_LOG, cb);
        if (getcon(&tctx) != 0) {
            ALOGE("SELinux: Could not acquire target context. Aborting keystore.\n");
            return -1;
        }
    } else {
        ALOGI("SELinux: Keystore SELinux is disabled.\n");
    }

    KeyStore keyStore(&entropy, reinterpret_cast<keymaster1_device_t*>(dev), fallback);
    keyStore.initialize();
    android::sp<android::IServiceManager> sm = android::defaultServiceManager();
    android::sp<android::KeyStoreProxy> proxy = new android::KeyStoreProxy(&keyStore);
    android::status_t ret = sm->addService(android::String16("android.security.keystore"), proxy);
    if (ret != android::OK) {
        ALOGE("Couldn't register binder service!");
        return -1;
    }

    /*
     * We're the only thread in existence, so we're just going to process
     * Binder transaction as a single-threaded program.
     */
    android::IPCThreadState::self()->joinThreadPool();

    keymaster_device_release(dev);
    return 1;
}
