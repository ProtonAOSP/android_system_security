/*
 * Copyright (c) 2019, The Android Open Source Project
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

#define LOG_TAG "CredentialData"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include <cppbor.h>
#include <cppbor_parse.h>

#include <android/hardware/identity/support/IdentityCredentialSupport.h>

#include "CredentialData.h"
#include "Util.h"

namespace android {
namespace security {
namespace identity {

using std::optional;

string CredentialData::calculateCredentialFileName(const string& dataPath, uid_t ownerUid,
                                                   const string& name) {
    return android::base::StringPrintf(
        "%s/%d-%s", dataPath.c_str(), (int)ownerUid,
        android::hardware::identity::support::encodeHex(name).c_str());
}

CredentialData::CredentialData(const string& dataPath, uid_t ownerUid, const string& name)
    : dataPath_(dataPath), ownerUid_(ownerUid), name_(name), secureUserId_(0) {
    fileName_ = calculateCredentialFileName(dataPath_, ownerUid_, name_);
}

void CredentialData::setSecureUserId(int64_t secureUserId) {
    secureUserId_ = secureUserId;
}

void CredentialData::setCredentialData(const vector<uint8_t>& credentialData) {
    credentialData_ = credentialData;
}

void CredentialData::setAttestationCertificate(const vector<uint8_t>& attestationCertificate) {
    attestationCertificate_ = attestationCertificate;
}

void CredentialData::addSecureAccessControlProfile(
    const SecureAccessControlProfile& secureAccessControlProfile) {
    secureAccessControlProfiles_.push_back(secureAccessControlProfile);
}

void CredentialData::addEntryData(const string& namespaceName, const string& entryName,
                                  const EntryData& data) {
    idToEncryptedChunks_[namespaceName + ":" + entryName] = data;
}

bool CredentialData::saveToDisk() const {
    cppbor::Map map;

    map.add("secureUserId", secureUserId_);

    map.add("credentialData", credentialData_);

    map.add("attestationCertificate", attestationCertificate_);

    cppbor::Array sacpArray;
    for (const SecureAccessControlProfile& sacp : secureAccessControlProfiles_) {
        cppbor::Array array;
        array.add(sacp.id);
        array.add(sacp.readerCertificate.encodedCertificate);
        array.add(sacp.userAuthenticationRequired);
        array.add(sacp.timeoutMillis);
        array.add(sacp.secureUserId);
        vector<uint8_t> mac = sacp.mac;
        array.add(mac);
        sacpArray.add(std::move(array));
    }
    map.add("secureAccessControlProfiles", std::move(sacpArray));

    cppbor::Map encryptedBlobsMap;
    for (auto const& [nsAndName, entryData] : idToEncryptedChunks_) {
        cppbor::Array encryptedChunkArray;
        for (const vector<uint8_t>& encryptedChunk : entryData.encryptedChunks) {
            encryptedChunkArray.add(encryptedChunk);
        }
        cppbor::Array entryDataArray;
        entryDataArray.add(entryData.size);
        cppbor::Array idsArray;
        for (int32_t id : entryData.accessControlProfileIds) {
            idsArray.add(id);
        }
        entryDataArray.add(std::move(idsArray));
        entryDataArray.add(std::move(encryptedChunkArray));
        encryptedBlobsMap.add(nsAndName, std::move(entryDataArray));
    }
    map.add("entryData", std::move(encryptedBlobsMap));
    map.add("authKeyCount", keyCount_);
    map.add("maxUsesPerAuthKey", maxUsesPerKey_);

    cppbor::Array authKeyDatasArray;
    for (const AuthKeyData& data : authKeyDatas_) {
        cppbor::Array array;
        array.add(data.certificate);
        array.add(data.keyBlob);
        array.add(data.staticAuthenticationData);
        array.add(data.pendingCertificate);
        array.add(data.pendingKeyBlob);
        array.add(data.useCount);
        authKeyDatasArray.add(std::move(array));
    }
    map.add("authKeyData", std::move(authKeyDatasArray));

    vector<uint8_t> credentialData = map.encode();

    return fileSetContents(fileName_, credentialData);
}

optional<SecureAccessControlProfile> parseSacp(const cppbor::Item& item) {
    const cppbor::Array* array = item.asArray();
    if (array == nullptr || array->size() < 6) {
        LOG(ERROR) << "The SACP CBOR is not an array with at least six elements (size="
                   << (array != nullptr ? array->size() : -1) << ")";
        return {};
    }
    const cppbor::Int* itemId = ((*array)[0])->asInt();
    const cppbor::Bstr* itemReaderCertificate = ((*array)[1])->asBstr();
    const cppbor::Simple* simple = ((*array)[2])->asSimple();
    const cppbor::Bool* itemUserAuthenticationRequired =
        (simple != nullptr ? (simple->asBool()) : nullptr);
    const cppbor::Int* itemTimeoutMillis = ((*array)[3])->asInt();
    const cppbor::Int* itesecureUserId_ = ((*array)[4])->asInt();
    const cppbor::Bstr* itemMac = ((*array)[5])->asBstr();
    if (itemId == nullptr || itemReaderCertificate == nullptr ||
        itemUserAuthenticationRequired == nullptr || itemTimeoutMillis == nullptr ||
        itesecureUserId_ == nullptr || itemMac == nullptr) {
        LOG(ERROR) << "One or more items SACP array in CBOR is of wrong type";
        return {};
    }
    SecureAccessControlProfile sacp;
    sacp.id = itemId->value();
    sacp.readerCertificate.encodedCertificate = itemReaderCertificate->value();
    sacp.userAuthenticationRequired = itemUserAuthenticationRequired->value();
    sacp.timeoutMillis = itemTimeoutMillis->value();
    sacp.secureUserId = itesecureUserId_->value();
    sacp.mac = itemMac->value();
    return sacp;
}

optional<AuthKeyData> parseAuthKeyData(const cppbor::Item& item) {
    const cppbor::Array* array = item.asArray();
    if (array == nullptr || array->size() < 6) {
        LOG(ERROR) << "The AuthKeyData CBOR is not an array with at least six elements";
        return {};
    }
    const cppbor::Bstr* itemCertificate = ((*array)[0])->asBstr();
    const cppbor::Bstr* itemKeyBlob = ((*array)[1])->asBstr();
    const cppbor::Bstr* itemStaticAuthenticationData = ((*array)[2])->asBstr();
    const cppbor::Bstr* itemPendingCertificate = ((*array)[3])->asBstr();
    const cppbor::Bstr* itemPendingKeyBlob = ((*array)[4])->asBstr();
    const cppbor::Int* itemUseCount = ((*array)[5])->asInt();
    if (itemCertificate == nullptr || itemKeyBlob == nullptr ||
        itemStaticAuthenticationData == nullptr || itemPendingCertificate == nullptr ||
        itemPendingKeyBlob == nullptr || itemUseCount == nullptr) {
        LOG(ERROR) << "One or more items in AuthKeyData array in CBOR is of wrong type";
        return {};
    }
    AuthKeyData authKeyData;
    authKeyData.certificate = itemCertificate->value();
    authKeyData.keyBlob = itemKeyBlob->value();
    authKeyData.staticAuthenticationData = itemStaticAuthenticationData->value();
    authKeyData.pendingCertificate = itemPendingCertificate->value();
    authKeyData.pendingKeyBlob = itemPendingKeyBlob->value();
    authKeyData.useCount = itemUseCount->value();
    return authKeyData;
}

vector<int32_t> parseAccessControlProfileIds(const cppbor::Item& item) {
    const cppbor::Array* array = item.asArray();
    if (array == nullptr) {
        LOG(ERROR) << "The accessControlProfileIds member is not an array";
        return {};
    }

    vector<int32_t> accessControlProfileIds;
    for (size_t n = 0; n < array->size(); n++) {
        const cppbor::Int* itemInt = ((*array)[n])->asInt();
        if (itemInt == nullptr) {
            LOG(ERROR) << "An item in the accessControlProfileIds array is not a bstr";
            return {};
        }
        accessControlProfileIds.push_back(itemInt->value());
    }
    return accessControlProfileIds;
}

optional<vector<vector<uint8_t>>> parseEncryptedChunks(const cppbor::Item& item) {
    const cppbor::Array* array = item.asArray();
    if (array == nullptr) {
        LOG(ERROR) << "The encryptedChunks member is not an array";
        return {};
    }

    vector<vector<uint8_t>> encryptedChunks;
    for (size_t n = 0; n < array->size(); n++) {
        const cppbor::Bstr* itemBstr = ((*array)[n])->asBstr();
        if (itemBstr == nullptr) {
            LOG(ERROR) << "An item in the encryptedChunks array is not a bstr";
            return {};
        }
        encryptedChunks.push_back(itemBstr->value());
    }
    return encryptedChunks;
}

bool CredentialData::loadFromDisk() {

    // Reset all data.
    credentialData_.clear();
    attestationCertificate_.clear();
    secureAccessControlProfiles_.clear();
    idToEncryptedChunks_.clear();
    authKeyDatas_.clear();
    keyCount_ = 0;
    maxUsesPerKey_ = 1;

    optional<vector<uint8_t>> data = fileGetContents(fileName_);
    if (!data) {
        LOG(ERROR) << "Error loading data";
        return false;
    }

    auto [item, _ /* newPos */, message] = cppbor::parse(data.value());
    if (item == nullptr) {
        LOG(ERROR) << "Data loaded from " << fileName_ << " is not valid CBOR: " << message;
        return false;
    }

    const cppbor::Map* map = item->asMap();
    if (map == nullptr) {
        LOG(ERROR) << "Top-level item is not a map";
        return false;
    }

    for (size_t n = 0; n < map->size(); n++) {
        auto [keyItem, valueItem] = (*map)[n];
        const cppbor::Tstr* tstr = keyItem->asTstr();
        if (tstr == nullptr) {
            LOG(ERROR) << "Key item in top-level map is not a tstr";
            return false;
        }
        const string& key = tstr->value();

        if (key == "secureUserId") {
            const cppbor::Int* number = valueItem->asInt();
            if (number == nullptr) {
                LOG(ERROR) << "Value for secureUserId is not a number";
                return false;
            }
            secureUserId_ = number->value();
        } else if (key == "credentialData") {
            const cppbor::Bstr* valueBstr = valueItem->asBstr();
            if (valueBstr == nullptr) {
                LOG(ERROR) << "Value for credentialData is not a bstr";
                return false;
            }
            credentialData_ = valueBstr->value();
        } else if (key == "attestationCertificate") {
            const cppbor::Bstr* valueBstr = valueItem->asBstr();
            if (valueBstr == nullptr) {
                LOG(ERROR) << "Value for attestationCertificate is not a bstr";
                return false;
            }
            attestationCertificate_ = valueBstr->value();
        } else if (key == "secureAccessControlProfiles") {
            const cppbor::Array* array = valueItem->asArray();
            if (array == nullptr) {
                LOG(ERROR) << "Value for attestationCertificate is not an array";
                return false;
            }
            for (size_t m = 0; m < array->size(); m++) {
                const std::unique_ptr<cppbor::Item>& item = (*array)[m];
                optional<SecureAccessControlProfile> sacp = parseSacp(*item);
                if (!sacp) {
                    LOG(ERROR) << "Error parsing SecureAccessControlProfile";
                    return false;
                }
                secureAccessControlProfiles_.push_back(sacp.value());
            }

        } else if (key == "entryData") {
            const cppbor::Map* map = valueItem->asMap();
            if (map == nullptr) {
                LOG(ERROR) << "Value for encryptedChunks is not an map";
                return false;
            }
            for (size_t m = 0; m < map->size(); m++) {
                auto [ecKeyItem, ecValueItem] = (*map)[m];
                const cppbor::Tstr* ecTstr = ecKeyItem->asTstr();
                if (ecTstr == nullptr) {
                    LOG(ERROR) << "Key item in encryptedChunks map is not a tstr";
                    return false;
                }
                const string& ecId = ecTstr->value();

                const cppbor::Array* ecEntryArrayItem = ecValueItem->asArray();
                if (ecEntryArrayItem == nullptr || ecEntryArrayItem->size() < 3) {
                    LOG(ERROR) << "Value item in encryptedChunks map is an array with at least two "
                                  "elements";
                    return false;
                }
                const cppbor::Int* ecEntrySizeItem = (*ecEntryArrayItem)[0]->asInt();
                if (ecEntrySizeItem == nullptr) {
                    LOG(ERROR) << "Entry size not a number";
                    return false;
                }
                uint64_t entrySize = ecEntrySizeItem->value();

                optional<vector<int32_t>> accessControlProfileIds =
                    parseAccessControlProfileIds(*(*ecEntryArrayItem)[1]);
                if (!accessControlProfileIds) {
                    LOG(ERROR) << "Error parsing access control profile ids";
                    return false;
                }

                optional<vector<vector<uint8_t>>> encryptedChunks =
                    parseEncryptedChunks(*(*ecEntryArrayItem)[2]);
                if (!encryptedChunks) {
                    LOG(ERROR) << "Error parsing encrypted chunks";
                    return false;
                }

                EntryData data;
                data.size = entrySize;
                data.accessControlProfileIds = accessControlProfileIds.value();
                data.encryptedChunks = encryptedChunks.value();
                idToEncryptedChunks_[ecId] = data;
            }

        } else if (key == "authKeyData") {
            const cppbor::Array* array = valueItem->asArray();
            if (array == nullptr) {
                LOG(ERROR) << "Value for authData is not an array";
                return false;
            }
            for (size_t m = 0; m < array->size(); m++) {
                const std::unique_ptr<cppbor::Item>& item = (*array)[m];
                optional<AuthKeyData> authKeyData = parseAuthKeyData(*item);
                if (!authKeyData) {
                    LOG(ERROR) << "Error parsing AuthKeyData";
                    return false;
                }
                authKeyDatas_.push_back(authKeyData.value());
            }

        } else if (key == "authKeyCount") {
            const cppbor::Int* number = valueItem->asInt();
            if (number == nullptr) {
                LOG(ERROR) << "Value for authKeyCount is not a number";
                return false;
            }
            keyCount_ = number->value();

        } else if (key == "maxUsesPerAuthKey") {
            const cppbor::Int* number = valueItem->asInt();
            if (number == nullptr) {
                LOG(ERROR) << "Value for maxUsesPerAuthKey is not a number";
                return false;
            }
            maxUsesPerKey_ = number->value();
        }
    }

    if (credentialData_.size() == 0) {
        LOG(ERROR) << "Missing credentialData";
        return false;
    }

    if (attestationCertificate_.size() == 0) {
        LOG(ERROR) << "Missing attestationCertificate";
        return false;
    }

    if (size_t(keyCount_) != authKeyDatas_.size()) {
        LOG(ERROR) << "keyCount_=" << keyCount_
                   << " != authKeyDatas_.size()=" << authKeyDatas_.size();
        return false;
    }

    return true;
}

const vector<uint8_t>& CredentialData::getCredentialData() const {
    return credentialData_;
}

int64_t CredentialData::getSecureUserId() {
    return secureUserId_;
}

const vector<uint8_t>& CredentialData::getAttestationCertificate() const {
    return attestationCertificate_;
}

const vector<SecureAccessControlProfile>& CredentialData::getSecureAccessControlProfiles() const {
    return secureAccessControlProfiles_;
}

bool CredentialData::hasEntryData(const string& namespaceName, const string& entryName) const {
    string id = namespaceName + ":" + entryName;
    auto iter = idToEncryptedChunks_.find(id);
    if (iter == idToEncryptedChunks_.end()) {
        return false;
    }
    return true;
}

optional<EntryData> CredentialData::getEntryData(const string& namespaceName,
                                                 const string& entryName) const {
    string id = namespaceName + ":" + entryName;
    auto iter = idToEncryptedChunks_.find(id);
    if (iter == idToEncryptedChunks_.end()) {
        return {};
    }
    return iter->second;
}

bool CredentialData::deleteCredential() {
    if (unlink(fileName_.c_str()) != 0) {
        PLOG(ERROR) << "Error deleting " << fileName_;
        return false;
    }
    return true;
}

optional<bool> CredentialData::credentialExists(const string& dataPath, uid_t ownerUid,
                                                const string& name) {
    struct stat statbuf;
    string filename = calculateCredentialFileName(dataPath, ownerUid, name);
    if (stat(filename.c_str(), &statbuf) != 0) {
        if (errno == ENOENT) {
            return false;
        }
        PLOG(ERROR) << "Error getting information about " << filename;
        return {};
    }
    return true;
}

// ---

void CredentialData::setAvailableAuthenticationKeys(int keyCount, int maxUsesPerKey) {
    keyCount_ = keyCount;
    maxUsesPerKey_ = maxUsesPerKey;

    // If growing the number of auth keys (prevKeyCount < keyCount_ case) we'll add
    // new AuthKeyData structs to |authKeyDatas_| and each struct will have empty |certificate|
    // and |pendingCertificate| fields. Those will be filled out when the
    // getAuthKeysNeedingCertification() is called.
    //
    // If shrinking, we'll just delete the AuthKeyData structs at the end. There's nothing
    // else to do, the HAL doesn't need to know we're nuking these authentication keys.
    //
    // Therefore, in either case it's as simple as just resizing the vector.
    authKeyDatas_.resize(keyCount_);
}

const vector<AuthKeyData>& CredentialData::getAuthKeyDatas() const {
    return authKeyDatas_;
}

const AuthKeyData* CredentialData::selectAuthKey(bool allowUsingExhaustedKeys) {
    AuthKeyData* candidate = nullptr;

    int n = 0;
    int candidateNum = -1;
    for (AuthKeyData& data : authKeyDatas_) {
        if (data.certificate.size() != 0) {
            if (candidate == nullptr || data.useCount < candidate->useCount) {
                candidate = &data;
                candidateNum = n;
            }
        }
        n++;
    }

    if (candidate == nullptr) {
        return nullptr;
    }

    if (candidate->useCount >= maxUsesPerKey_ && !allowUsingExhaustedKeys) {
        return nullptr;
    }

    candidate->useCount += 1;
    return candidate;
}

optional<vector<vector<uint8_t>>>
CredentialData::getAuthKeysNeedingCertification(const sp<IIdentityCredential>& halBinder) {

    vector<vector<uint8_t>> keysNeedingCert;

    for (AuthKeyData& data : authKeyDatas_) {
        bool newKeyNeeded = (data.certificate.size() == 0) || (data.useCount >= maxUsesPerKey_);
        bool certificationPending = (data.pendingCertificate.size() > 0);
        if (newKeyNeeded && !certificationPending) {
            vector<uint8_t> signingKeyBlob;
            Certificate signingKeyCertificate;
            if (!halBinder->generateSigningKeyPair(&signingKeyBlob, &signingKeyCertificate)
                     .isOk()) {
                LOG(ERROR) << "Error generating signing key-pair";
                return {};
            }
            data.pendingCertificate = signingKeyCertificate.encodedCertificate;
            data.pendingKeyBlob = signingKeyBlob;
            certificationPending = true;
        }

        if (certificationPending) {
            keysNeedingCert.push_back(data.pendingCertificate);
        }
    }
    return keysNeedingCert;
}

bool CredentialData::storeStaticAuthenticationData(const vector<uint8_t>& authenticationKey,
                                                   const vector<uint8_t>& staticAuthData) {
    for (AuthKeyData& data : authKeyDatas_) {
        if (data.pendingCertificate == authenticationKey) {
            data.certificate = data.pendingCertificate;
            data.keyBlob = data.pendingKeyBlob;
            data.staticAuthenticationData = staticAuthData;
            data.pendingCertificate.clear();
            data.pendingKeyBlob.clear();
            data.useCount = 0;
            return true;
        }
    }
    return false;
}

}  // namespace identity
}  // namespace security
}  // namespace android
