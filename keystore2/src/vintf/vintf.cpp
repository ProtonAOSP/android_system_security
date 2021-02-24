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

#include "vintf.hpp"

#include <vintf/HalManifest.h>
#include <vintf/VintfObject.h>

// Converts a set<string> into a C-style array of C strings.
static char** convert(const std::set<std::string>& names) {
    char** ret = new char*[names.size()];
    char** ptr = ret;
    for (const auto& name : names) {
        *(ptr++) = strdup(name.c_str());
    }
    return ret;
}

char** getHalNames(size_t* len) {
    auto manifest = android::vintf::VintfObject::GetDeviceHalManifest();
    const auto names = manifest->getHalNames();
    *len = names.size();
    return convert(names);
}

char** getHalNamesAndVersions(size_t* len) {
    auto manifest = android::vintf::VintfObject::GetDeviceHalManifest();
    const auto names = manifest->getHalNamesAndVersions();
    *len = names.size();
    return convert(names);
}

char** getAidlInstances(size_t* len, const char* package, size_t version,
                        const char* interfaceName) {
    auto manifest = android::vintf::VintfObject::GetDeviceHalManifest();
    const auto names = manifest->getAidlInstances(package, version, interfaceName);
    *len = names.size();
    return convert(names);
}

void freeNames(char** names, size_t len) {
    for (int i = 0; i < len; i++) {
        free(names[i]);
    }
    delete[] names;
}
