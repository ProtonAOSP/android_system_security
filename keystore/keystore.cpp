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

//#define LOG_NDEBUG 0
#define LOG_TAG "keystore"
#include <cutils/log.h>
#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>

#include "keystore.h"

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


struct Value {
    Value(const uint8_t* orig, int origLen) {
        assert(origLen <= VALUE_SIZE);
        memcpy(value, orig, origLen);
        length = origLen;
    }

    Value() {
    }

    int length;
    uint8_t value[VALUE_SIZE];
};

class ValueString {
public:
    ValueString(const Value* orig) {
        assert(length <= VALUE_SIZE);
        length = orig->length;
        value = new char[length + 1];
        memcpy(value, orig->value, length);
        value[length] = '\0';
    }

    ~ValueString() {
        delete[] value;
    }

    const char* c_str() const {
        return value;
    }

    char* release() {
        char* ret = value;
        value = NULL;
        return ret;
    }

private:
    char* value;
    size_t length;
};

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

/* Here is the encoding of keys. This is necessary in order to allow arbitrary
 * characters in keys. Characters in [0-~] are not encoded. Others are encoded
 * into two bytes. The first byte is one of [+-.] which represents the first
 * two bits of the character. The second byte encodes the rest of the bits into
 * [0-o]. Therefore in the worst case the length of a key gets doubled. Note
 * that Base64 cannot be used here due to the need of prefix match on keys. */

static int encode_key(char* out, const Value* key) {
    const uint8_t* in = key->value;
    int length = key->length;
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

static int encode_key_for_uid(char* out, uid_t uid, const Value* key) {
    int n = snprintf(out, NAME_MAX, "%u_", uid);
    out += n;

    return n + encode_key(out, key);
}

static int decode_key(uint8_t* out, const char* in, int length) {
    for (int i = 0; i < length; ++i, ++in, ++out) {
        if (*in >= '0' && *in <= '~') {
            *out = *in;
        } else {
            *out = (*in - '+') << 6;
            *out |= (*++in - '0') & 0x3F;
            --length;
        }
    }
    *out = '\0';
    return length;
}

static size_t readFully(int fd, uint8_t* data, size_t size) {
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t n = TEMP_FAILURE_RETRY(read(fd, data, size));
        if (n == -1 || n == 0) {
            return size-remaining;
        }
        data += n;
        remaining -= n;
    }
    return size;
}

static size_t writeFully(int fd, uint8_t* data, size_t size) {
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t n = TEMP_FAILURE_RETRY(write(fd, data, size));
        if (n == -1 || n == 0) {
            return size-remaining;
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
        if (mRandom != -1) {
            close(mRandom);
        }
    }

    bool open() {
        const char* randomDevice = "/dev/urandom";
        mRandom = ::open(randomDevice, O_RDONLY);
        if (mRandom == -1) {
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
    TYPE_GENERIC = 1,
    TYPE_MASTER_KEY = 2,
    TYPE_KEY_PAIR = 3,
} BlobType;

static const uint8_t CurrentBlobVersion = 1;

class Blob {
public:
    Blob(uint8_t* value, int32_t valueLength, uint8_t* info, uint8_t infoLength, BlobType type) {
        mBlob.length = valueLength;
        memcpy(mBlob.value, value, valueLength);

        mBlob.info = infoLength;
        memcpy(mBlob.value + valueLength, info, infoLength);

        mBlob.version = CurrentBlobVersion;
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
        int out = open(tmpFileName, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
        if (out == -1) {
            return SYSTEM_ERROR;
        }
        size_t writtenBytes = writeFully(out, (uint8_t*) &mBlob, fileLength);
        if (close(out) != 0) {
            return SYSTEM_ERROR;
        }
        if (writtenBytes != fileLength) {
            unlink(tmpFileName);
            return SYSTEM_ERROR;
        }
        return (rename(tmpFileName, filename) == 0) ? NO_ERROR : SYSTEM_ERROR;
    }

    ResponseCode decryptBlob(const char* filename, AES_KEY *aes_key) {
        int in = open(filename, O_RDONLY);
        if (in == -1) {
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
        return NO_ERROR;
    }

private:
    struct blob mBlob;
};

typedef struct {
    uint32_t uid;
    const uint8_t* keyName;

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

    ResponseCode initialize(Value* pw) {
        if (!generateMasterKey()) {
            return SYSTEM_ERROR;
        }
        ResponseCode response = writeMasterKey(pw);
        if (response != NO_ERROR) {
            return response;
        }
        setupMasterKeys();
        return NO_ERROR;
    }

    ResponseCode writeMasterKey(Value* pw) {
        uint8_t passwordKey[MASTER_KEY_SIZE_BYTES];
        generateKeyFromPassword(passwordKey, MASTER_KEY_SIZE_BYTES, pw, mSalt);
        AES_KEY passwordAesKey;
        AES_set_encrypt_key(passwordKey, MASTER_KEY_SIZE_BITS, &passwordAesKey);
        Blob masterKeyBlob(mMasterKey, sizeof(mMasterKey), mSalt, sizeof(mSalt), TYPE_MASTER_KEY);
        return masterKeyBlob.encryptBlob(MASTER_KEY_FILE, &passwordAesKey, mEntropy);
    }

    ResponseCode readMasterKey(Value* pw) {
        int in = open(MASTER_KEY_FILE, O_RDONLY);
        if (in == -1) {
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
        if (version < CurrentBlobVersion) {
            upgrade(filename, keyBlob, version, type);
        }

        if (keyBlob->getType() != type) {
            ALOGW("key found but type doesn't match: %d vs %d", keyBlob->getType(), type);
            return KEY_NOT_FOUND;
        }

        return rc;
    }

    ResponseCode put(const char* filename, Blob* keyBlob) {
        return keyBlob->encryptBlob(filename, &mMasterKeyEncryption, mEntropy);
    }

    void addGrant(const char* filename, const Value* uidValue) {
        uid_t uid;
        if (!convertToUid(uidValue, &uid)) {
            return;
        }

        grant_t *grant = getGrant(filename, uid);
        if (grant == NULL) {
            grant = new grant_t;
            grant->uid = uid;
            grant->keyName = reinterpret_cast<const uint8_t*>(strdup(filename));
            list_add_tail(&mGrants, &grant->plist);
        }
    }

    bool removeGrant(const Value* keyValue, const Value* uidValue) {
        uid_t uid;
        if (!convertToUid(uidValue, &uid)) {
            return false;
        }

        ValueString keyString(keyValue);

        grant_t *grant = getGrant(keyString.c_str(), uid);
        if (grant != NULL) {
            list_remove(&grant->plist);
            delete grant;
            return true;
        }

        return false;
    }

    bool hasGrant(const Value* keyValue, const uid_t uid) const {
        ValueString keyString(keyValue);
        return getGrant(keyString.c_str(), uid) != NULL;
    }

    ResponseCode importKey(const Value* key, const char* filename) {
        uint8_t* data;
        size_t dataLength;
        int rc;

        if (mDevice->import_keypair == NULL) {
            ALOGE("Keymaster doesn't support import!");
            return SYSTEM_ERROR;
        }

        rc = mDevice->import_keypair(mDevice, key->value, key->length, &data, &dataLength);
        if (rc) {
            ALOGE("Error while importing keypair: %d", rc);
            return SYSTEM_ERROR;
        }

        Blob keyBlob(data, dataLength, NULL, 0, TYPE_KEY_PAIR);
        free(data);

        return put(filename, &keyBlob);
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

    static void generateKeyFromPassword(uint8_t* key, ssize_t keySize, Value* pw, uint8_t* salt) {
        size_t saltSize;
        if (salt != NULL) {
            saltSize = SALT_SIZE;
        } else {
            // pre-gingerbread used this hardwired salt, readMasterKey will rewrite these when found
            salt = (uint8_t*) "keystore";
            // sizeof = 9, not strlen = 8
            saltSize = sizeof("keystore");
        }
        PKCS5_PBKDF2_HMAC_SHA1((char*) pw->value, pw->length, salt, saltSize, 8192, keySize, key);
    }

    static bool isKeyFile(const char* filename) {
        return ((strcmp(filename, MASTER_KEY_FILE) != 0)
                && (strcmp(filename, ".") != 0)
                && (strcmp(filename, "..") != 0));
    }

    grant_t* getGrant(const char* keyName, uid_t uid) const {
        struct listnode *node;
        grant_t *grant;

        list_for_each(node, &mGrants) {
            grant = node_to_item(node, grant_t, plist);
            if (grant->uid == uid
                    && !strcmp(reinterpret_cast<const char*>(grant->keyName),
                               keyName)) {
                return grant;
            }
        }

        return NULL;
    }

    bool convertToUid(const Value* uidValue, uid_t* uid) const {
        ValueString uidString(uidValue);
        char* end = NULL;
        *uid = strtol(uidString.c_str(), &end, 10);
        return *end == '\0';
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

        Value pkcs8key;
        pkcs8key.length = len;
        uint8_t* tmp = pkcs8key.value;
        if (i2d_PKCS8_PRIV_KEY_INFO(pkcs8.get(), &tmp) != len) {
            ALOGE("Couldn't convert to PKCS#8");
            return SYSTEM_ERROR;
        }

        ResponseCode rc = importKey(&pkcs8key, filename);
        if (rc != NO_ERROR) {
            return rc;
        }

        return get(filename, blob, TYPE_KEY_PAIR);
    }
};

const char* KeyStore::MASTER_KEY_FILE = ".masterkey";

/* Here is the protocol used in both requests and responses:
 *     code [length_1 message_1 ... length_n message_n] end-of-file
 * where code is one byte long and lengths are unsigned 16-bit integers in
 * network order. Thus the maximum length of a message is 65535 bytes. */

static int recv_code(int sock, int8_t* code) {
    return recv(sock, code, 1, 0) == 1;
}

static int recv_message(int sock, uint8_t* message, int length) {
    uint8_t bytes[2];
    if (recv(sock, &bytes[0], 1, 0) != 1 ||
        recv(sock, &bytes[1], 1, 0) != 1) {
        return -1;
    } else {
        int offset = bytes[0] << 8 | bytes[1];
        if (length < offset) {
            return -1;
        }
        length = offset;
        offset = 0;
        while (offset < length) {
            int n = recv(sock, &message[offset], length - offset, 0);
            if (n <= 0) {
                return -1;
            }
            offset += n;
        }
    }
    return length;
}

static int recv_end_of_file(int sock) {
    uint8_t byte;
    return recv(sock, &byte, 1, 0) == 0;
}

static void send_code(int sock, int8_t code) {
    send(sock, &code, 1, 0);
}

static void send_message(int sock, const uint8_t* message, int length) {
    uint16_t bytes = htons(length);
    send(sock, &bytes, 2, 0);
    send(sock, message, length, 0);
}

static ResponseCode get_key_for_name(KeyStore* keyStore, Blob* keyBlob, const Value* keyName,
        const uid_t uid, const BlobType type) {
    char filename[NAME_MAX];

    encode_key_for_uid(filename, uid, keyName);
    ResponseCode responseCode = keyStore->get(filename, keyBlob, type);
    if (responseCode == NO_ERROR) {
        return responseCode;
    }

    // If this is the Wifi or VPN user, they actually want system
    // UID keys.
    if (uid == AID_WIFI || uid == AID_VPN) {
        encode_key_for_uid(filename, AID_SYSTEM, keyName);
        responseCode = keyStore->get(filename, keyBlob, type);
        if (responseCode == NO_ERROR) {
            return responseCode;
        }
    }

    // They might be using a granted key.
    if (!keyStore->hasGrant(keyName, uid)) {
        return responseCode;
    }

    // It is a granted key. Try to load it.
    encode_key(filename, keyName);
    return keyStore->get(filename, keyBlob, type);
}

/* Here are the actions. Each of them is a function without arguments. All
 * information is defined in global variables, which are set properly before
 * performing an action. The number of parameters required by each action is
 * fixed and defined in a table. If the return value of an action is positive,
 * it will be treated as a response code and transmitted to the client. Note
 * that the lengths of parameters are checked when they are received, so
 * boundary checks on parameters are omitted. */

static const ResponseCode NO_ERROR_RESPONSE_CODE_SENT = (ResponseCode) 0;

static ResponseCode test(KeyStore* keyStore, int, uid_t, Value*, Value*, Value*) {
    return (ResponseCode) keyStore->getState();
}

static ResponseCode get(KeyStore* keyStore, int sock, uid_t uid, Value* keyName, Value*, Value*) {
    char filename[NAME_MAX];
    encode_key_for_uid(filename, uid, keyName);
    Blob keyBlob;
    ResponseCode responseCode = keyStore->get(filename, &keyBlob, TYPE_GENERIC);
    if (responseCode != NO_ERROR) {
        return responseCode;
    }
    send_code(sock, NO_ERROR);
    send_message(sock, keyBlob.getValue(), keyBlob.getLength());
    return NO_ERROR_RESPONSE_CODE_SENT;
}

static ResponseCode insert(KeyStore* keyStore, int, uid_t uid, Value* keyName, Value* val,
        Value*) {
    char filename[NAME_MAX];
    encode_key_for_uid(filename, uid, keyName);
    Blob keyBlob(val->value, val->length, NULL, 0, TYPE_GENERIC);
    return keyStore->put(filename, &keyBlob);
}

static ResponseCode del(KeyStore* keyStore, int, uid_t uid, Value* keyName, Value*, Value*) {
    char filename[NAME_MAX];
    encode_key_for_uid(filename, uid, keyName);
    Blob keyBlob;
    ResponseCode responseCode = keyStore->get(filename, &keyBlob, TYPE_GENERIC);
    if (responseCode != NO_ERROR) {
        return responseCode;
    }
    return (unlink(filename) && errno != ENOENT) ? SYSTEM_ERROR : NO_ERROR;
}

static ResponseCode exist(KeyStore*, int, uid_t uid, Value* keyName, Value*, Value*) {
    char filename[NAME_MAX];
    encode_key_for_uid(filename, uid, keyName);
    if (access(filename, R_OK) == -1) {
        return (errno != ENOENT) ? SYSTEM_ERROR : KEY_NOT_FOUND;
    }
    return NO_ERROR;
}

static ResponseCode saw(KeyStore*, int sock, uid_t uid, Value* keyPrefix, Value*, Value*) {
    DIR* dir = opendir(".");
    if (!dir) {
        return SYSTEM_ERROR;
    }
    char filename[NAME_MAX];
    int n = encode_key_for_uid(filename, uid, keyPrefix);
    send_code(sock, NO_ERROR);

    struct dirent* file;
    while ((file = readdir(dir)) != NULL) {
        if (!strncmp(filename, file->d_name, n)) {
            const char* p = &file->d_name[n];
            keyPrefix->length = decode_key(keyPrefix->value, p, strlen(p));
            send_message(sock, keyPrefix->value, keyPrefix->length);
        }
    }
    closedir(dir);
    return NO_ERROR_RESPONSE_CODE_SENT;
}

static ResponseCode reset(KeyStore* keyStore, int, uid_t, Value*, Value*, Value*) {
    ResponseCode rc = keyStore->reset() ? NO_ERROR : SYSTEM_ERROR;

    const keymaster_device_t* device = keyStore->getDevice();
    if (device == NULL) {
        ALOGE("No keymaster device!");
        return SYSTEM_ERROR;
    }

    if (device->delete_all == NULL) {
        ALOGV("keymaster device doesn't implement delete_all");
        return rc;
    }

    if (device->delete_all(device)) {
        ALOGE("Problem calling keymaster's delete_all");
        return SYSTEM_ERROR;
    }

    return rc;
}

/* Here is the history. To improve the security, the parameters to generate the
 * master key has been changed. To make a seamless transition, we update the
 * file using the same password when the user unlock it for the first time. If
 * any thing goes wrong during the transition, the new file will not overwrite
 * the old one. This avoids permanent damages of the existing data. */

static ResponseCode password(KeyStore* keyStore, int, uid_t, Value* pw, Value*, Value*) {
    switch (keyStore->getState()) {
        case STATE_UNINITIALIZED: {
            // generate master key, encrypt with password, write to file, initialize mMasterKey*.
            return keyStore->initialize(pw);
        }
        case STATE_NO_ERROR: {
            // rewrite master key with new password.
            return keyStore->writeMasterKey(pw);
        }
        case STATE_LOCKED: {
            // read master key, decrypt with password, initialize mMasterKey*.
            return keyStore->readMasterKey(pw);
        }
    }
    return SYSTEM_ERROR;
}

static ResponseCode lock(KeyStore* keyStore, int, uid_t, Value*, Value*, Value*) {
    keyStore->lock();
    return NO_ERROR;
}

static ResponseCode unlock(KeyStore* keyStore, int sock, uid_t uid, Value* pw, Value* unused,
        Value* unused2) {
    return password(keyStore, sock, uid, pw, unused, unused2);
}

static ResponseCode zero(KeyStore* keyStore, int, uid_t, Value*, Value*, Value*) {
    return keyStore->isEmpty() ? KEY_NOT_FOUND : NO_ERROR;
}

static ResponseCode generate(KeyStore* keyStore, int, uid_t uid, Value* keyName, Value*,
        Value*) {
    char filename[NAME_MAX];
    uint8_t* data;
    size_t dataLength;
    int rc;

    const keymaster_device_t* device = keyStore->getDevice();
    if (device == NULL) {
        return SYSTEM_ERROR;
    }

    if (device->generate_keypair == NULL) {
        return SYSTEM_ERROR;
    }

    keymaster_rsa_keygen_params_t rsa_params;
    rsa_params.modulus_size = 2048;
    rsa_params.public_exponent = 0x10001;

    rc = device->generate_keypair(device, TYPE_RSA, &rsa_params, &data, &dataLength);
    if (rc) {
        return SYSTEM_ERROR;
    }

    encode_key_for_uid(filename, uid, keyName);

    Blob keyBlob(data, dataLength, NULL, 0, TYPE_KEY_PAIR);
    free(data);

    return keyStore->put(filename, &keyBlob);
}

static ResponseCode import(KeyStore* keyStore, int, uid_t uid, Value* keyName, Value* key,
        Value*) {
    char filename[NAME_MAX];

    encode_key_for_uid(filename, uid, keyName);

    return keyStore->importKey(key, filename);
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
static ResponseCode get_pubkey(KeyStore* keyStore, int sock, uid_t uid, Value* keyName, Value*, Value*) {
    Blob keyBlob;
    ALOGV("get_pubkey '%s' from uid %d", ValueString(keyName).c_str(), uid);

    ResponseCode responseCode = get_key_for_name(keyStore, &keyBlob, keyName, uid, TYPE_KEY_PAIR);
    if (responseCode != NO_ERROR) {
        return responseCode;
    }

    const keymaster_device_t* device = keyStore->getDevice();
    if (device == NULL) {
        return SYSTEM_ERROR;
    }

    if (device->get_keypair_public == NULL) {
        ALOGE("device has no get_keypair_public implementation!");
        return SYSTEM_ERROR;
    }

    uint8_t* data = NULL;
    size_t dataLength;

    int rc = device->get_keypair_public(device, keyBlob.getValue(), keyBlob.getLength(), &data,
            &dataLength);
    if (rc) {
        return SYSTEM_ERROR;
    }

    send_code(sock, NO_ERROR);
    send_message(sock, data, dataLength);
    free(data);

    return NO_ERROR_RESPONSE_CODE_SENT;
}

static ResponseCode del_key(KeyStore* keyStore, int, uid_t uid, Value* keyName, Value*,
        Value*) {
    char filename[NAME_MAX];
    encode_key_for_uid(filename, uid, keyName);
    Blob keyBlob;
    ResponseCode responseCode = keyStore->get(filename, &keyBlob, TYPE_KEY_PAIR);
    if (responseCode != NO_ERROR) {
        return responseCode;
    }

    const keymaster_device_t* device = keyStore->getDevice();
    if (device == NULL) {
        return SYSTEM_ERROR;
    }

    if (device->delete_keypair == NULL) {
        ALOGE("device has no delete_keypair implementation!");
        return SYSTEM_ERROR;
    }

    int rc = device->delete_keypair(device, keyBlob.getValue(), keyBlob.getLength());

    return rc ? SYSTEM_ERROR : NO_ERROR;
}

static ResponseCode sign(KeyStore* keyStore, int sock, uid_t uid, Value* keyName, Value* data,
        Value*) {
    ALOGV("sign %s from uid %d", ValueString(keyName).c_str(), uid);
    Blob keyBlob;
    int rc;

    ResponseCode responseCode = get_key_for_name(keyStore, &keyBlob, keyName, uid, TYPE_KEY_PAIR);
    if (responseCode != NO_ERROR) {
        return responseCode;
    }

    uint8_t* signedData;
    size_t signedDataLength;

    const keymaster_device_t* device = keyStore->getDevice();
    if (device == NULL) {
        ALOGE("no keymaster device; cannot sign");
        return SYSTEM_ERROR;
    }

    if (device->sign_data == NULL) {
        ALOGE("device doesn't implement signing");
        return SYSTEM_ERROR;
    }

    keymaster_rsa_sign_params_t params;
    params.digest_type = DIGEST_NONE;
    params.padding_type = PADDING_NONE;

    rc = device->sign_data(device, &params, keyBlob.getValue(), keyBlob.getLength(),
            data->value, data->length, &signedData, &signedDataLength);
    if (rc) {
        ALOGW("device couldn't sign data");
        return SYSTEM_ERROR;
    }

    send_code(sock, NO_ERROR);
    send_message(sock, signedData, signedDataLength);
    return NO_ERROR_RESPONSE_CODE_SENT;
}

static ResponseCode verify(KeyStore* keyStore, int, uid_t uid, Value* keyName, Value* data,
        Value* signature) {
    Blob keyBlob;
    int rc;

    ResponseCode responseCode = get_key_for_name(keyStore, &keyBlob, keyName, uid, TYPE_KEY_PAIR);
    if (responseCode != NO_ERROR) {
        return responseCode;
    }

    const keymaster_device_t* device = keyStore->getDevice();
    if (device == NULL) {
        return SYSTEM_ERROR;
    }

    if (device->verify_data == NULL) {
        return SYSTEM_ERROR;
    }

    keymaster_rsa_sign_params_t params;
    params.digest_type = DIGEST_NONE;
    params.padding_type = PADDING_NONE;

    rc = device->verify_data(device, &params, keyBlob.getValue(), keyBlob.getLength(),
            data->value, data->length, signature->value, signature->length);
    if (rc) {
        return SYSTEM_ERROR;
    } else {
        return NO_ERROR;
    }
}

static ResponseCode grant(KeyStore* keyStore, int, uid_t uid, Value* keyName,
        Value* granteeData, Value*) {
    char filename[NAME_MAX];
    encode_key_for_uid(filename, uid, keyName);
    if (access(filename, R_OK) == -1) {
        return (errno != ENOENT) ? SYSTEM_ERROR : KEY_NOT_FOUND;
    }

    keyStore->addGrant(filename, granteeData);
    return NO_ERROR;
}

static ResponseCode ungrant(KeyStore* keyStore, int, uid_t uid, Value* keyName,
        Value* granteeData, Value*) {
    char filename[NAME_MAX];
    encode_key_for_uid(filename, uid, keyName);
    if (access(filename, R_OK) == -1) {
        return (errno != ENOENT) ? SYSTEM_ERROR : KEY_NOT_FOUND;
    }

    return keyStore->removeGrant(keyName, granteeData) ? NO_ERROR : KEY_NOT_FOUND;
}

/* Here are the permissions, actions, users, and the main function. */
enum perm {
    P_TEST     = 1 << TEST,
    P_GET      = 1 << GET,
    P_INSERT   = 1 << INSERT,
    P_DELETE   = 1 << DELETE,
    P_EXIST    = 1 << EXIST,
    P_SAW      = 1 << SAW,
    P_RESET    = 1 << RESET,
    P_PASSWORD = 1 << PASSWORD,
    P_LOCK     = 1 << LOCK,
    P_UNLOCK   = 1 << UNLOCK,
    P_ZERO     = 1 << ZERO,
    P_SIGN     = 1 << SIGN,
    P_VERIFY   = 1 << VERIFY,
    P_GRANT    = 1 << GRANT,
};

static const int MAX_PARAM = 3;

static const State STATE_ANY = (State) 0;

static struct action {
    ResponseCode (*run)(KeyStore* keyStore, int sock, uid_t uid, Value* param1, Value* param2,
            Value* param3);
    int8_t code;
    State state;
    uint32_t perm;
    int lengths[MAX_PARAM];
} actions[] = {
    {test,       CommandCodes[TEST],       STATE_ANY,      P_TEST,     {0, 0, 0}},
    {get,        CommandCodes[GET],        STATE_NO_ERROR, P_GET,      {KEY_SIZE, 0, 0}},
    {insert,     CommandCodes[INSERT],     STATE_NO_ERROR, P_INSERT,   {KEY_SIZE, VALUE_SIZE, 0}},
    {del,        CommandCodes[DELETE],     STATE_ANY,      P_DELETE,   {KEY_SIZE, 0, 0}},
    {exist,      CommandCodes[EXIST],      STATE_ANY,      P_EXIST,    {KEY_SIZE, 0, 0}},
    {saw,        CommandCodes[SAW],        STATE_ANY,      P_SAW,      {KEY_SIZE, 0, 0}},
    {reset,      CommandCodes[RESET],      STATE_ANY,      P_RESET,    {0, 0, 0}},
    {password,   CommandCodes[PASSWORD],   STATE_ANY,      P_PASSWORD, {PASSWORD_SIZE, 0, 0}},
    {lock,       CommandCodes[LOCK],       STATE_NO_ERROR, P_LOCK,     {0, 0, 0}},
    {unlock,     CommandCodes[UNLOCK],     STATE_LOCKED,   P_UNLOCK,   {PASSWORD_SIZE, 0, 0}},
    {zero,       CommandCodes[ZERO],       STATE_ANY,      P_ZERO,     {0, 0, 0}},
    {generate,   CommandCodes[GENERATE],   STATE_NO_ERROR, P_INSERT,   {KEY_SIZE, 0, 0}},
    {import,     CommandCodes[IMPORT],     STATE_NO_ERROR, P_INSERT,   {KEY_SIZE, VALUE_SIZE, 0}},
    {sign,       CommandCodes[SIGN],       STATE_NO_ERROR, P_SIGN,     {KEY_SIZE, VALUE_SIZE, 0}},
    {verify,     CommandCodes[VERIFY],     STATE_NO_ERROR, P_VERIFY,   {KEY_SIZE, VALUE_SIZE, VALUE_SIZE}},
    {get_pubkey, CommandCodes[GET_PUBKEY], STATE_NO_ERROR, P_GET,      {KEY_SIZE, 0, 0}},
    {del_key,    CommandCodes[DEL_KEY],    STATE_ANY,      P_DELETE,   {KEY_SIZE, 0, 0}},
    {grant,      CommandCodes[GRANT],      STATE_NO_ERROR, P_GRANT,    {KEY_SIZE, KEY_SIZE, 0}},
    {ungrant,    CommandCodes[UNGRANT],    STATE_NO_ERROR, P_GRANT,    {KEY_SIZE, KEY_SIZE, 0}},
    {NULL,       0,                        STATE_ANY,      0,          {0, 0, 0}},
};

static struct user {
    uid_t uid;
    uid_t euid;
    uint32_t perms;
} users[] = {
    {AID_SYSTEM,   ~0,         ~0},
    {AID_VPN,      AID_SYSTEM, P_GET | P_SIGN | P_VERIFY },
    {AID_WIFI,     AID_SYSTEM, P_GET | P_SIGN | P_VERIFY },
    {AID_ROOT,     AID_SYSTEM, P_GET},
    {~0,           ~0,         P_TEST | P_GET | P_INSERT | P_DELETE | P_EXIST | P_SAW |
                               P_SIGN | P_VERIFY},
};

static ResponseCode process(KeyStore* keyStore, int sock, uid_t uid, int8_t code) {
    struct user* user = users;
    struct action* action = actions;
    int i;

    while (~user->uid && user->uid != (uid % AID_USER)) {
        ++user;
    }
    while (action->code && action->code != code) {
        ++action;
    }
    if (!action->code) {
        return UNDEFINED_ACTION;
    }
    if (!(action->perm & user->perms)) {
        return PERMISSION_DENIED;
    }
    if (action->state != STATE_ANY && action->state != keyStore->getState()) {
        return (ResponseCode) keyStore->getState();
    }
    if (~user->euid) {
        uid = user->euid;
    }
    Value params[MAX_PARAM];
    for (i = 0; i < MAX_PARAM && action->lengths[i] != 0; ++i) {
        params[i].length = recv_message(sock, params[i].value, action->lengths[i]);
        if (params[i].length < 0) {
            return PROTOCOL_ERROR;
        }
    }
    if (!recv_end_of_file(sock)) {
        return PROTOCOL_ERROR;
    }
    return action->run(keyStore, sock, uid, &params[0], &params[1], &params[2]);
}

int main(int argc, char* argv[]) {
    int controlSocket = android_get_control_socket("keystore");
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

    if (listen(controlSocket, 3) == -1) {
        ALOGE("listen: %s", strerror(errno));
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    KeyStore keyStore(&entropy, dev);
    int sock;
    while ((sock = accept(controlSocket, NULL, 0)) != -1) {
        struct timeval tv;
        tv.tv_sec = 3;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct ucred cred;
        socklen_t size = sizeof(cred);
        int credResult = getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &size);
        if (credResult != 0) {
            ALOGW("getsockopt: %s", strerror(errno));
        } else {
            int8_t request;
            if (recv_code(sock, &request)) {
                State old_state = keyStore.getState();
                ResponseCode response = process(&keyStore, sock, cred.uid, request);
                if (response == NO_ERROR_RESPONSE_CODE_SENT) {
                    response = NO_ERROR;
                } else {
                    send_code(sock, response);
                }
                ALOGI("uid: %d action: %c -> %d state: %d -> %d retry: %d",
                     cred.uid,
                     request, response,
                     old_state, keyStore.getState(),
                     keyStore.getRetry());
            }
        }
        close(sock);
    }
    ALOGE("accept: %s", strerror(errno));

    keymaster_device_release(dev);

    return 1;
}
