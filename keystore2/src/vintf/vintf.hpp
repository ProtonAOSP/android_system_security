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

#ifndef __VINTF_H__
#define __VINTF_H__

#include <stddef.h>

extern "C" {

char** getHalNames(size_t* len);
char** getHalNamesAndVersions(size_t* len);
char** getHidlInstances(size_t* len, const char* package, size_t major_version,
                        size_t minor_version, const char* interfaceName);
char** getAidlInstances(size_t* len, const char* package, size_t version,
                        const char* interfaceName);
void freeNames(char** names, size_t len);
}

#endif  //  __VINTF_H__
