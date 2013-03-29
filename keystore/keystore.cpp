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
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
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

#include <hardware/keymaster.h>

#include <utils/UniquePtr.h>

#include <cutils/list.h>

#include <keystore/IKeystoreService.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

#include <cutils/log.h>
#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>

#include <keystore/keystore.h>

/* KeyStore is a secured storage for key-value pairs. In this implementation,
 * each file stores one key-value pair. Keys are encoded in file names, and
 * values are encrypted with checksums. The encryption key is protected by a
 * user-defined password. To keep things simple, buffers are always larger than
 * the maximum space we needed, so boundary checks on buffers are omitted. */

#define KEY_SIZE        ((NAME_MAX - 15) / 2)
#define VALUE_SIZE      32768
#define PASSWORD_SIZE   VALUE_SIZE


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


static int keymaster_device_initialize(keymaster_device_t** dev) {
    int rc;

    const hw_module_t* mod;
    rc = hw_get_module_by_class(KEYSTORE_HARDWARE_MODULE_ID, NULL, &mod);
    if (rc) {
        ALOGE("could not find any keystore module");
        goto out;
    }

    rc = keymaster_open(mod, dev);
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

static void keymaster_device_release(keymaster_device_t* dev) {
    keymaster_close(dev);
}

/***************
 * PERMISSIONS *
 ***************/

/* Here are the permissions, actions, users, and the main function. */
typedef enum {
    P_TEST      = 1 << 0,
    P_GET       = 1 << 1,
    P_INSERT    = 1 << 2,
    P_DELETE    = 1 << 3,
    P_EXIST     = 1 << 4,
    P_SAW       = 1 << 5,
    P_RESET     = 1 << 6,
    P_PASSWORD  = 1 << 7,
    P_LOCK      = 1 << 8,
    P_UNLOCK    = 1 << 9,
    P_ZERO      = 1 << 10,
    P_SIGN      = 1 << 11,
    P_VERIFY    = 1 << 12,
    P_GRANT     = 1 << 13,
    P_DUPLICATE = 1 << 14,
} perm_t;

static struct user_euid {
    uid_t uid;
    uid_t euid;
} user_euids[] = {
    {AID_VPN, AID_SYSTEM},
    {AID_WIFI, AID_SYSTEM},
    {AID_ROOT, AID_SYSTEM},
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

static bool has_permission(uid_t uid, perm_t perm) {
    for (size_t i = 0; i < sizeof(user_perms)/sizeof(user_perms[0]); i++) {
        struct user_perm user = user_perms[i];
        if (user.uid == uid) {
            return user.perms & perm;
        }
    }

    return DEFAULT_PERMS & perm;
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

static int encode_key(char* out, const android::String8& keyName) {
    const uint8_t* in = reinterpret_cast<const uint8_t*>(keyName.string());
    size_t length = keyName.length();
    for (int i = length; i > 0; --i, ++in, ++out) {
        if (*in >= '0' && *in <= '~') {
            *out = *in;
        } else {
            *out = '+' + (*in >> 6);
            *++out = '0' + (*in & 0x3F);
            ++length;
        }
    }
    *out = '\0';
    return length;
}

static int encode_key_for_uid(char* out, uid_t uid, const android::String8& keyName) {
    int n = snprintf(out, NAME_MAX, "%u_", uid);
    out += n;

    return n + encode_key(out, keyName);
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
 * the second is the blob's type, and the third byte is reserved. Fields other
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
    uint8_t reserved;
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
} BlobType;

static const uint8_t CURRENT_BLOB_VERSION = 1;

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

    void setVersion(uint8_t version) {
        mBlob.version = version;
    }

    BlobType getType() const {
        return BlobType(mBlob.type);
    }

    void setType(BlobType type) {
        mBlob.type = uint8_t(type);
    }

    ResponseCode encryptBlob(const char* filename, AES_KEY *aes_key, Entropy* entropy) {
        if (!entropy->generate_random_data(mBlob.vector, AES_BLOCK_SIZE)) {
            ALOGW("Could not read random data for: %s", filename);
            return SYSTEM_ERROR;
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
        MD5(mBlob.digested, digestedLength, mBlob.digest);

        uint8_t vector[AES_BLOCK_SIZE];
        memcpy(vector, mBlob.vector, AES_BLOCK_SIZE);
        AES_cbc_encrypt(mBlob.encrypted, mBlob.encrypted, encryptedLength,
                        aes_key, vector, AES_ENCRYPT);

        mBlob.reserved = 0;
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

    ResponseCode decryptBlob(const char* filename, AES_KEY *aes_key) {
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
        size_t headerLength = (mBlob.encrypted - (uint8_t*) &mBlob);
        if (fileLength < headerLength) {
            return VALUE_CORRUPTED;
        }

        ssize_t encryptedLength = fileLength - (headerLength + mBlob.info);
        if (encryptedLength < 0 || encryptedLength % AES_BLOCK_SIZE != 0) {
            return VALUE_CORRUPTED;
        }
        AES_cbc_encrypt(mBlob.encrypted, mBlob.encrypted, encryptedLength, aes_key,
                        mBlob.vector, AES_DECRYPT);
        size_t digestedLength = encryptedLength - MD5_DIGEST_LENGTH;
        uint8_t computedDigest[MD5_DIGEST_LENGTH];
        MD5(mBlob.digested, digestedLength, computedDigest);
        if (memcmp(mBlob.digest, computedDigest, MD5_DIGEST_LENGTH) != 0) {
            return VALUE_CORRUPTED;
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

typedef struct {
    uint32_t uid;
    const uint8_t* filename;

    struct listnode plist;
} grant_t;

class KeyStore {
public:
    KeyStore(Entropy* entropy, keymaster_device_t* device)
        : mEntropy(entropy)
        , mDevice(device)
        , mRetry(MAX_RETRY)
    {
        if (access(MASTER_KEY_FILE, R_OK) == 0) {
            setState(STATE_LOCKED);
        } else {
            setState(STATE_UNINITIALIZED);
        }

        list_init(&mGrants);
    }

    State getState() const {
        return mState;
    }

    int8_t getRetry() const {
        return mRetry;
    }

    keymaster_device_t* getDevice() const {
        return mDevice;
    }

    ResponseCode initialize(const android::String8& pw) {
        if (!generateMasterKey()) {
            return SYSTEM_ERROR;
        }
        ResponseCode response = writeMasterKey(pw);
        if (response != NO_ERROR) {
            return response;
        }
        setupMasterKeys();
        return ::NO_ERROR;
    }

    ResponseCode writeMasterKey(const android::String8& pw) {
        uint8_t passwordKey[MASTER_KEY_SIZE_BYTES];
        generateKeyFromPassword(passwordKey, MASTER_KEY_SIZE_BYTES, pw, mSalt);
        AES_KEY passwordAesKey;
        AES_set_encrypt_key(passwordKey, MASTER_KEY_SIZE_BITS, &passwordAesKey);
        Blob masterKeyBlob(mMasterKey, sizeof(mMasterKey), mSalt, sizeof(mSalt), TYPE_MASTER_KEY);
        return masterKeyBlob.encryptBlob(MASTER_KEY_FILE, &passwordAesKey, mEntropy);
    }

    ResponseCode readMasterKey(const android::String8& pw) {
        int in = TEMP_FAILURE_RETRY(open(MASTER_KEY_FILE, O_RDONLY));
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
        ResponseCode response = masterKeyBlob.decryptBlob(MASTER_KEY_FILE, &passwordAesKey);
        if (response == SYSTEM_ERROR) {
            return SYSTEM_ERROR;
        }
        if (response == NO_ERROR && masterKeyBlob.getLength() == MASTER_KEY_SIZE_BYTES) {
            // if salt was missing, generate one and write a new master key file with the salt.
            if (salt == NULL) {
                if (!generateSalt()) {
                    return SYSTEM_ERROR;
                }
                response = writeMasterKey(pw);
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

    bool reset() {
        clearMasterKeys();
        setState(STATE_UNINITIALIZED);

        DIR* dir = opendir(".");
        struct dirent* file;

        if (!dir) {
            return false;
        }
        while ((file = readdir(dir)) != NULL) {
            unlink(file->d_name);
        }
        closedir(dir);
        return true;
    }

    bool isEmpty() const {
        DIR* dir = opendir(".");
        struct dirent* file;
        if (!dir) {
            return true;
        }
        bool result = true;
        while ((file = readdir(dir)) != NULL) {
            if (isKeyFile(file->d_name)) {
                result = false;
                break;
            }
        }
        closedir(dir);
        return result;
    }

    void lock() {
        clearMasterKeys();
        setState(STATE_LOCKED);
    }

    ResponseCode get(const char* filename, Blob* keyBlob, const BlobType type) {
        ResponseCode rc = keyBlob->decryptBlob(filename, &mMasterKeyDecryption);
        if (rc != NO_ERROR) {
            return rc;
        }

        const uint8_t version = keyBlob->getVersion();
        if (version < CURRENT_BLOB_VERSION) {
            upgrade(filename, keyBlob, version, type);
        }

        if (type != TYPE_ANY && keyBlob->getType() != type) {
            ALOGW("key found but type doesn't match: %d vs %d", keyBlob->getType(), type);
            return KEY_NOT_FOUND;
        }

        return rc;
    }

    ResponseCode put(const char* filename, Blob* keyBlob) {
        return keyBlob->encryptBlob(filename, &mMasterKeyEncryption, mEntropy);
    }

    void addGrant(const char* filename, uid_t granteeUid) {
        grant_t *grant = getGrant(filename, granteeUid);
        if (grant == NULL) {
            grant = new grant_t;
            grant->uid = granteeUid;
            grant->filename = reinterpret_cast<const uint8_t*>(strdup(filename));
            list_add_tail(&mGrants, &grant->plist);
        }
    }

    bool removeGrant(const char* filename, uid_t granteeUid) {
        grant_t *grant = getGrant(filename, granteeUid);
        if (grant != NULL) {
            list_remove(&grant->plist);
            delete grant;
            return true;
        }

        return false;
    }

    bool hasGrant(const char* filename, const uid_t uid) const {
        return getGrant(filename, uid) != NULL;
    }

    ResponseCode importKey(const uint8_t* key, size_t keyLen, const char* filename) {
        uint8_t* data;
        size_t dataLength;
        int rc;

        if (mDevice->import_keypair == NULL) {
            ALOGE("Keymaster doesn't support import!");
            return SYSTEM_ERROR;
        }

        rc = mDevice->import_keypair(mDevice, key, keyLen, &data, &dataLength);
        if (rc) {
            ALOGE("Error while importing keypair: %d", rc);
            return SYSTEM_ERROR;
        }

        Blob keyBlob(data, dataLength, NULL, 0, TYPE_KEY_PAIR);
        free(data);

        return put(filename, &keyBlob);
    }

    bool isHardwareBacked() const {
        return (mDevice->flags & KEYMASTER_SOFTWARE_ONLY) != 0;
    }

private:
    static const char* MASTER_KEY_FILE;
    static const int MASTER_KEY_SIZE_BYTES = 16;
    static const int MASTER_KEY_SIZE_BITS = MASTER_KEY_SIZE_BYTES * 8;

    static const int MAX_RETRY = 4;
    static const size_t SALT_SIZE = 16;

    Entropy* mEntropy;

    keymaster_device_t* mDevice;

    State mState;
    int8_t mRetry;

    uint8_t mMasterKey[MASTER_KEY_SIZE_BYTES];
    uint8_t mSalt[SALT_SIZE];

    AES_KEY mMasterKeyEncryption;
    AES_KEY mMasterKeyDecryption;

    struct listnode mGrants;

    void setState(State state) {
        mState = state;
        if (mState == STATE_NO_ERROR || mState == STATE_UNINITIALIZED) {
            mRetry = MAX_RETRY;
        }
    }

    bool generateSalt() {
        return mEntropy->generate_random_data(mSalt, sizeof(mSalt));
    }

    bool generateMasterKey() {
        if (!mEntropy->generate_random_data(mMasterKey, sizeof(mMasterKey))) {
            return false;
        }
        if (!generateSalt()) {
            return false;
        }
        return true;
    }

    void setupMasterKeys() {
        AES_set_encrypt_key(mMasterKey, MASTER_KEY_SIZE_BITS, &mMasterKeyEncryption);
        AES_set_decrypt_key(mMasterKey, MASTER_KEY_SIZE_BITS, &mMasterKeyDecryption);
        setState(STATE_NO_ERROR);
    }

    void clearMasterKeys() {
        memset(mMasterKey, 0, sizeof(mMasterKey));
        memset(mSalt, 0, sizeof(mSalt));
        memset(&mMasterKeyEncryption, 0, sizeof(mMasterKeyEncryption));
        memset(&mMasterKeyDecryption, 0, sizeof(mMasterKeyDecryption));
    }

    static void generateKeyFromPassword(uint8_t* key, ssize_t keySize, const android::String8& pw,
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

    static bool isKeyFile(const char* filename) {
        return ((strcmp(filename, MASTER_KEY_FILE) != 0)
                && (strcmp(filename, ".") != 0)
                && (strcmp(filename, "..") != 0));
    }

    grant_t* getGrant(const char* filename, uid_t uid) const {
        struct listnode *node;
        grant_t *grant;

        list_for_each(node, &mGrants) {
            grant = node_to_item(node, grant_t, plist);
            if (grant->uid == uid
                    && !strcmp(reinterpret_cast<const char*>(grant->filename),
                               filename)) {
                return grant;
            }
        }

        return NULL;
    }

    /**
     * Upgrade code. This will upgrade the key from the current version
     * to whatever is newest.
     */
    void upgrade(const char* filename, Blob* blob, const uint8_t oldVersion, const BlobType type) {
        bool updated = false;
        uint8_t version = oldVersion;

        /* From V0 -> V1: All old types were unknown */
        if (version == 0) {
            ALOGV("upgrading to version 1 and setting type %d", type);

            blob->setType(type);
            if (type == TYPE_KEY_PAIR) {
                importBlobAsKey(blob, filename);
            }
            version = 1;
            updated = true;
        }

        /*
         * If we've updated, set the key blob to the right version
         * and write it.
         * */
        if (updated) {
            ALOGV("updated and writing file %s", filename);
            blob->setVersion(version);
            this->put(filename, blob);
        }
    }

    /**
     * Takes a blob that is an PEM-encoded RSA key as a byte array and
     * converts it to a DER-encoded PKCS#8 for import into a keymaster.
     * Then it overwrites the original blob with the new blob
     * format that is returned from the keymaster.
     */
    ResponseCode importBlobAsKey(Blob* blob, const char* filename) {
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

        ResponseCode rc = importKey(pkcs8key.get(), len, filename);
        if (rc != NO_ERROR) {
            return rc;
        }

        return get(filename, blob, TYPE_KEY_PAIR);
    }
};

const char* KeyStore::MASTER_KEY_FILE = ".masterkey";

static ResponseCode get_key_for_name(KeyStore* keyStore, Blob* keyBlob,
        const android::String8& keyName, const uid_t uid, const BlobType type) {
    char filename[NAME_MAX];

    encode_key_for_uid(filename, uid, keyName);
    ResponseCode responseCode = keyStore->get(filename, keyBlob, type);
    if (responseCode == NO_ERROR) {
        return responseCode;
    }

    // If this is one of the legacy UID->UID mappings, use it.
    uid_t euid = get_keystore_euid(uid);
    if (euid != uid) {
        encode_key_for_uid(filename, euid, keyName);
        responseCode = keyStore->get(filename, keyBlob, type);
        if (responseCode == NO_ERROR) {
            return responseCode;
        }
    }

    // They might be using a granted key.
    encode_key(filename, keyName);
    if (!keyStore->hasGrant(filename, uid)) {
        return responseCode;
    }

    // It is a granted key. Try to load it.
    return keyStore->get(filename, keyBlob, type);
}

namespace android {
class KeyStoreProxy : public BnKeystoreService, public IBinder::DeathRecipient {
public:
    KeyStoreProxy(KeyStore* keyStore)
        : mKeyStore(keyStore)
    {
    }

    void binderDied(const wp<IBinder>&) {
        ALOGE("binder death detected");
    }

    int32_t test() {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_TEST)) {
            ALOGW("permission denied for %d: test", callingUid);
            return ::PERMISSION_DENIED;
        }

        return mKeyStore->getState();
    }

    int32_t get(const String16& name, uint8_t** item, size_t* itemLength) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_GET)) {
            ALOGW("permission denied for %d: get", callingUid);
            return ::PERMISSION_DENIED;
        }

        State state = mKeyStore->getState();
        if (!isKeystoreUnlocked(state)) {
            ALOGD("calling get in state: %d", state);
            return state;
        }

        String8 name8(name);
        char filename[NAME_MAX];
        Blob keyBlob;

        ResponseCode responseCode = get_key_for_name(mKeyStore, &keyBlob, name8, callingUid,
                TYPE_GENERIC);
        if (responseCode != ::NO_ERROR) {
            ALOGW("Could not read %s", filename);
            *item = NULL;
            *itemLength = 0;
            return responseCode;
        }

        *item = (uint8_t*) malloc(keyBlob.getLength());
        memcpy(*item, keyBlob.getValue(), keyBlob.getLength());
        *itemLength = keyBlob.getLength();

        return ::NO_ERROR;
    }

    int32_t insert(const String16& name, const uint8_t* item, size_t itemLength, int targetUid) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_INSERT)) {
            ALOGW("permission denied for %d: insert", callingUid);
            return ::PERMISSION_DENIED;
        }

        if (targetUid == -1) {
            targetUid = callingUid;
        } else if (!is_granted_to(callingUid, targetUid)) {
            return ::PERMISSION_DENIED;
        }

        State state = mKeyStore->getState();
        if (!isKeystoreUnlocked(state)) {
            ALOGD("calling insert in state: %d", state);
            return state;
        }

        String8 name8(name);
        char filename[NAME_MAX];

        encode_key_for_uid(filename, targetUid, name8);

        Blob keyBlob(item, itemLength, NULL, 0, ::TYPE_GENERIC);
        return mKeyStore->put(filename, &keyBlob);
    }

    int32_t del(const String16& name, int targetUid) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_DELETE)) {
            ALOGW("permission denied for %d: del", callingUid);
            return ::PERMISSION_DENIED;
        }

        if (targetUid == -1) {
            targetUid = callingUid;
        } else if (!is_granted_to(callingUid, targetUid)) {
            return ::PERMISSION_DENIED;
        }

        String8 name8(name);
        char filename[NAME_MAX];

        encode_key_for_uid(filename, targetUid, name8);

        Blob keyBlob;
        ResponseCode responseCode = mKeyStore->get(filename, &keyBlob, TYPE_GENERIC);
        if (responseCode != ::NO_ERROR) {
            return responseCode;
        }
        return (unlink(filename) && errno != ENOENT) ? ::SYSTEM_ERROR : ::NO_ERROR;
    }

    int32_t exist(const String16& name, int targetUid) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_EXIST)) {
            ALOGW("permission denied for %d: exist", callingUid);
            return ::PERMISSION_DENIED;
        }

        if (targetUid == -1) {
            targetUid = callingUid;
        } else if (!is_granted_to(callingUid, targetUid)) {
            return ::PERMISSION_DENIED;
        }

        String8 name8(name);
        char filename[NAME_MAX];

        encode_key_for_uid(filename, targetUid, name8);

        if (access(filename, R_OK) == -1) {
            return (errno != ENOENT) ? ::SYSTEM_ERROR : ::KEY_NOT_FOUND;
        }
        return ::NO_ERROR;
    }

    int32_t saw(const String16& prefix, int targetUid, Vector<String16>* matches) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_SAW)) {
            ALOGW("permission denied for %d: saw", callingUid);
            return ::PERMISSION_DENIED;
        }

        if (targetUid == -1) {
            targetUid = callingUid;
        } else if (!is_granted_to(callingUid, targetUid)) {
            return ::PERMISSION_DENIED;
        }

        DIR* dir = opendir(".");
        if (!dir) {
            return ::SYSTEM_ERROR;
        }

        const String8 prefix8(prefix);
        char filename[NAME_MAX];

        int n = encode_key_for_uid(filename, targetUid, prefix8);

        struct dirent* file;
        while ((file = readdir(dir)) != NULL) {
            if (!strncmp(filename, file->d_name, n)) {
                const char* p = &file->d_name[n];
                size_t plen = strlen(p);

                size_t extra = decode_key_length(p, plen);
                char *match = (char*) malloc(extra + 1);
                if (match != NULL) {
                    decode_key(match, p, plen);
                    matches->push(String16(match, extra));
                    free(match);
                } else {
                    ALOGW("could not allocate match of size %zd", extra);
                }
            }
        }
        closedir(dir);

        return ::NO_ERROR;
    }

    int32_t reset() {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_RESET)) {
            ALOGW("permission denied for %d: reset", callingUid);
            return ::PERMISSION_DENIED;
        }

        ResponseCode rc = mKeyStore->reset() ? ::NO_ERROR : ::SYSTEM_ERROR;

        const keymaster_device_t* device = mKeyStore->getDevice();
        if (device == NULL) {
            ALOGE("No keymaster device!");
            return ::SYSTEM_ERROR;
        }

        if (device->delete_all == NULL) {
            ALOGV("keymaster device doesn't implement delete_all");
            return rc;
        }

        if (device->delete_all(device)) {
            ALOGE("Problem calling keymaster's delete_all");
            return ::SYSTEM_ERROR;
        }

        return rc;
    }

    /*
     * Here is the history. To improve the security, the parameters to generate the
     * master key has been changed. To make a seamless transition, we update the
     * file using the same password when the user unlock it for the first time. If
     * any thing goes wrong during the transition, the new file will not overwrite
     * the old one. This avoids permanent damages of the existing data.
     */
    int32_t password(const String16& password) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_PASSWORD)) {
            ALOGW("permission denied for %d: password", callingUid);
            return ::PERMISSION_DENIED;
        }

        const String8 password8(password);

        switch (mKeyStore->getState()) {
            case ::STATE_UNINITIALIZED: {
                // generate master key, encrypt with password, write to file, initialize mMasterKey*.
                return mKeyStore->initialize(password8);
            }
            case ::STATE_NO_ERROR: {
                // rewrite master key with new password.
                return mKeyStore->writeMasterKey(password8);
            }
            case ::STATE_LOCKED: {
                // read master key, decrypt with password, initialize mMasterKey*.
                return mKeyStore->readMasterKey(password8);
            }
        }
        return ::SYSTEM_ERROR;
    }

    int32_t lock() {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_LOCK)) {
            ALOGW("permission denied for %d: lock", callingUid);
            return ::PERMISSION_DENIED;
        }

        State state = mKeyStore->getState();
        if (state != ::STATE_NO_ERROR) {
            ALOGD("calling lock in state: %d", state);
            return state;
        }

        mKeyStore->lock();
        return ::NO_ERROR;
    }

    int32_t unlock(const String16& pw) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_UNLOCK)) {
            ALOGW("permission denied for %d: unlock", callingUid);
            return ::PERMISSION_DENIED;
        }

        State state = mKeyStore->getState();
        if (state != ::STATE_LOCKED) {
            ALOGD("calling unlock when not locked");
            return state;
        }

        const String8 password8(pw);
        return password(pw);
    }

    int32_t zero() {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_ZERO)) {
            ALOGW("permission denied for %d: zero", callingUid);
            return -1;
        }

        return mKeyStore->isEmpty() ? ::KEY_NOT_FOUND : ::NO_ERROR;
    }

    int32_t generate(const String16& name, int targetUid) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_INSERT)) {
            ALOGW("permission denied for %d: generate", callingUid);
            return ::PERMISSION_DENIED;
        }

        if (targetUid == -1) {
            targetUid = callingUid;
        } else if (!is_granted_to(callingUid, targetUid)) {
            return ::PERMISSION_DENIED;
        }

        State state = mKeyStore->getState();
        if (!isKeystoreUnlocked(state)) {
            ALOGD("calling generate in state: %d", state);
            return state;
        }

        String8 name8(name);
        char filename[NAME_MAX];

        uint8_t* data;
        size_t dataLength;
        int rc;

        const keymaster_device_t* device = mKeyStore->getDevice();
        if (device == NULL) {
            return ::SYSTEM_ERROR;
        }

        if (device->generate_keypair == NULL) {
            return ::SYSTEM_ERROR;
        }

        keymaster_rsa_keygen_params_t rsa_params;
        rsa_params.modulus_size = 2048;
        rsa_params.public_exponent = 0x10001;

        rc = device->generate_keypair(device, TYPE_RSA, &rsa_params, &data, &dataLength);
        if (rc) {
            return ::SYSTEM_ERROR;
        }

        encode_key_for_uid(filename, targetUid, name8);

        Blob keyBlob(data, dataLength, NULL, 0, TYPE_KEY_PAIR);
        free(data);

        return mKeyStore->put(filename, &keyBlob);
    }

    int32_t import(const String16& name, const uint8_t* data, size_t length, int targetUid) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_INSERT)) {
            ALOGW("permission denied for %d: import", callingUid);
            return ::PERMISSION_DENIED;
        }

        if (targetUid == -1) {
            targetUid = callingUid;
        } else if (!is_granted_to(callingUid, targetUid)) {
            return ::PERMISSION_DENIED;
        }

        State state = mKeyStore->getState();
        if (!isKeystoreUnlocked(state)) {
            ALOGD("calling import in state: %d", state);
            return state;
        }

        String8 name8(name);
        char filename[NAME_MAX];

        encode_key_for_uid(filename, targetUid, name8);

        return mKeyStore->importKey(data, length, filename);
    }

    int32_t sign(const String16& name, const uint8_t* data, size_t length, uint8_t** out,
            size_t* outLength) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_SIGN)) {
            ALOGW("permission denied for %d: saw", callingUid);
            return ::PERMISSION_DENIED;
        }

        State state = mKeyStore->getState();
        if (!isKeystoreUnlocked(state)) {
            ALOGD("calling sign in state: %d", state);
            return state;
        }

        Blob keyBlob;
        String8 name8(name);

        ALOGV("sign %s from uid %d", name8.string(), callingUid);
        int rc;

        ResponseCode responseCode = get_key_for_name(mKeyStore, &keyBlob, name8, callingUid,
                ::TYPE_KEY_PAIR);
        if (responseCode != ::NO_ERROR) {
            return responseCode;
        }

        const keymaster_device_t* device = mKeyStore->getDevice();
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

        rc = device->sign_data(device, &params, keyBlob.getValue(), keyBlob.getLength(),
                data, length, out, outLength);
        if (rc) {
            ALOGW("device couldn't sign data");
            return ::SYSTEM_ERROR;
        }

        return ::NO_ERROR;
    }

    int32_t verify(const String16& name, const uint8_t* data, size_t dataLength,
            const uint8_t* signature, size_t signatureLength) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_VERIFY)) {
            ALOGW("permission denied for %d: verify", callingUid);
            return ::PERMISSION_DENIED;
        }

        State state = mKeyStore->getState();
        if (!isKeystoreUnlocked(state)) {
            ALOGD("calling verify in state: %d", state);
            return state;
        }

        Blob keyBlob;
        String8 name8(name);
        int rc;

        ResponseCode responseCode = get_key_for_name(mKeyStore, &keyBlob, name8, callingUid,
                TYPE_KEY_PAIR);
        if (responseCode != ::NO_ERROR) {
            return responseCode;
        }

        const keymaster_device_t* device = mKeyStore->getDevice();
        if (device == NULL) {
            return ::SYSTEM_ERROR;
        }

        if (device->verify_data == NULL) {
            return ::SYSTEM_ERROR;
        }

        keymaster_rsa_sign_params_t params;
        params.digest_type = DIGEST_NONE;
        params.padding_type = PADDING_NONE;

        rc = device->verify_data(device, &params, keyBlob.getValue(), keyBlob.getLength(),
                data, dataLength, signature, signatureLength);
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
        if (!has_permission(callingUid, P_GET)) {
            ALOGW("permission denied for %d: get_pubkey", callingUid);
            return ::PERMISSION_DENIED;
        }

        State state = mKeyStore->getState();
        if (!isKeystoreUnlocked(state)) {
            ALOGD("calling get_pubkey in state: %d", state);
            return state;
        }

        Blob keyBlob;
        String8 name8(name);

        ALOGV("get_pubkey '%s' from uid %d", name8.string(), callingUid);

        ResponseCode responseCode = get_key_for_name(mKeyStore, &keyBlob, name8, callingUid,
                TYPE_KEY_PAIR);
        if (responseCode != ::NO_ERROR) {
            return responseCode;
        }

        const keymaster_device_t* device = mKeyStore->getDevice();
        if (device == NULL) {
            return ::SYSTEM_ERROR;
        }

        if (device->get_keypair_public == NULL) {
            ALOGE("device has no get_keypair_public implementation!");
            return ::SYSTEM_ERROR;
        }

        int rc = device->get_keypair_public(device, keyBlob.getValue(), keyBlob.getLength(), pubkey,
                pubkeyLength);
        if (rc) {
            return ::SYSTEM_ERROR;
        }

        return ::NO_ERROR;
    }

    int32_t del_key(const String16& name, int targetUid) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_DELETE)) {
            ALOGW("permission denied for %d: del_key", callingUid);
            return ::PERMISSION_DENIED;
        }

        if (targetUid == -1) {
            targetUid = callingUid;
        } else if (!is_granted_to(callingUid, targetUid)) {
            return ::PERMISSION_DENIED;
        }

        String8 name8(name);
        char filename[NAME_MAX];

        encode_key_for_uid(filename, targetUid, name8);

        Blob keyBlob;
        ResponseCode responseCode = mKeyStore->get(filename, &keyBlob, ::TYPE_KEY_PAIR);
        if (responseCode != ::NO_ERROR) {
            return responseCode;
        }

        ResponseCode rc = ::NO_ERROR;

        const keymaster_device_t* device = mKeyStore->getDevice();
        if (device == NULL) {
            rc = ::SYSTEM_ERROR;
        } else {
            // A device doesn't have to implement delete_keypair.
            if (device->delete_keypair != NULL) {
                if (device->delete_keypair(device, keyBlob.getValue(), keyBlob.getLength())) {
                    rc = ::SYSTEM_ERROR;
                }
            }
        }

        if (rc != ::NO_ERROR) {
            return rc;
        }

        return (unlink(filename) && errno != ENOENT) ? ::SYSTEM_ERROR : ::NO_ERROR;
    }

    int32_t grant(const String16& name, int32_t granteeUid) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_GRANT)) {
            ALOGW("permission denied for %d: grant", callingUid);
            return ::PERMISSION_DENIED;
        }

        State state = mKeyStore->getState();
        if (!isKeystoreUnlocked(state)) {
            ALOGD("calling grant in state: %d", state);
            return state;
        }

        String8 name8(name);
        char filename[NAME_MAX];

        encode_key_for_uid(filename, callingUid, name8);

        if (access(filename, R_OK) == -1) {
            return (errno != ENOENT) ? ::SYSTEM_ERROR : ::KEY_NOT_FOUND;
        }

        mKeyStore->addGrant(filename, granteeUid);
        return ::NO_ERROR;
    }

    int32_t ungrant(const String16& name, int32_t granteeUid) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_GRANT)) {
            ALOGW("permission denied for %d: ungrant", callingUid);
            return ::PERMISSION_DENIED;
        }

        State state = mKeyStore->getState();
        if (!isKeystoreUnlocked(state)) {
            ALOGD("calling ungrant in state: %d", state);
            return state;
        }

        String8 name8(name);
        char filename[NAME_MAX];

        encode_key_for_uid(filename, callingUid, name8);

        if (access(filename, R_OK) == -1) {
            return (errno != ENOENT) ? ::SYSTEM_ERROR : ::KEY_NOT_FOUND;
        }

        return mKeyStore->removeGrant(filename, granteeUid) ? ::NO_ERROR : ::KEY_NOT_FOUND;
    }

    int64_t getmtime(const String16& name) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_GET)) {
            ALOGW("permission denied for %d: getmtime", callingUid);
            return -1L;
        }

        String8 name8(name);
        char filename[NAME_MAX];

        encode_key_for_uid(filename, callingUid, name8);

        if (access(filename, R_OK) == -1) {
            ALOGW("could not access %s for getmtime", filename);
            return -1L;
        }

        int fd = TEMP_FAILURE_RETRY(open(filename, O_NOFOLLOW, O_RDONLY));
        if (fd < 0) {
            ALOGW("could not open %s for getmtime", filename);
            return -1L;
        }

        struct stat s;
        int ret = fstat(fd, &s);
        close(fd);
        if (ret == -1) {
            ALOGW("could not stat %s for getmtime", filename);
            return -1L;
        }

        return static_cast<int64_t>(s.st_mtime);
    }

    int32_t duplicate(const String16& srcKey, int32_t srcUid, const String16& destKey,
            int32_t destUid) {
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        if (!has_permission(callingUid, P_DUPLICATE)) {
            ALOGW("permission denied for %d: duplicate", callingUid);
            return -1L;
        }

        State state = mKeyStore->getState();
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
        char source[NAME_MAX];

        encode_key_for_uid(source, srcUid, source8);

        String8 target8(destKey);
        char target[NAME_MAX];

        encode_key_for_uid(target, destUid, target8);

        if (access(target, W_OK) != -1 || errno != ENOENT) {
            ALOGD("destination already exists: %s", target);
            return ::SYSTEM_ERROR;
        }

        Blob keyBlob;
        ResponseCode responseCode = mKeyStore->get(source, &keyBlob, TYPE_ANY);
        if (responseCode != ::NO_ERROR) {
            return responseCode;
        }

        return mKeyStore->put(target, &keyBlob);
    }

    int32_t is_hardware_backed() {
        return mKeyStore->isHardwareBacked() ? 1 : 0;
    }

private:
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

    ::KeyStore* mKeyStore;
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

    keymaster_device_t* dev;
    if (keymaster_device_initialize(&dev)) {
        ALOGE("keystore keymaster could not be initialized; exiting");
        return 1;
    }

    KeyStore keyStore(&entropy, dev);
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
