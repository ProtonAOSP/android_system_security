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

#ifndef KEYSTORE_PERMISSIONS_H_
#define KEYSTORE_PERMISSIONS_H_

#include <unistd.h>

/* Here are the permissions, actions, users, and the main function. */
enum perm_t {
    P_GET_STATE = 1 << 0,
    P_GET = 1 << 1,
    P_INSERT = 1 << 2,
    P_DELETE = 1 << 3,
    P_EXIST = 1 << 4,
    P_LIST = 1 << 5,
    P_RESET = 1 << 6,
    P_PASSWORD = 1 << 7,
    P_LOCK = 1 << 8,
    P_UNLOCK = 1 << 9,
    P_IS_EMPTY = 1 << 10,
    P_SIGN = 1 << 11,
    P_VERIFY = 1 << 12,
    P_GRANT = 1 << 13,
    P_DUPLICATE = 1 << 14,
    P_CLEAR_UID = 1 << 15,
    P_ADD_AUTH = 1 << 16,
    P_USER_CHANGED = 1 << 17,
};

const char* get_perm_label(perm_t perm);

/**
 * Returns the UID that the callingUid should act as. This is here for
 * legacy support of the WiFi and VPN systems and should be removed
 * when WiFi can operate in its own namespace.
 */
uid_t get_keystore_euid(uid_t uid);

bool has_permission(uid_t uid, perm_t perm, pid_t spid);

/**
 * Returns true if the callingUid is allowed to interact in the targetUid's
 * namespace.
 */
bool is_granted_to(uid_t callingUid, uid_t targetUid);

int configure_selinux();

#endif  // KEYSTORE_PERMISSIONS_H_
