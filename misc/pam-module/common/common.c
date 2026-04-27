/*
 * Copyright (C) 2021 ~ 2022 Deepin Technology Co., Ltd.
 *
 * Author:     weizhixiang <weizhixiang@uniontech.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"

void *dalloc(size_t size) {
    void *p = calloc(1, size);
    if (!p) {
        abort();
    }

    return p;
}

void cleanup_data(pam_handle_t *pamh, void *data, int pam_end_status) {
    UNUSED_VALUE(pamh);
    UNUSED_VALUE(pam_end_status);
    char *d = (char *)data;
    if (!d)
        return;

    memset(d, 0, strlen(d));
    free(d);
    return;
}

struct passwd *get_pwd(pam_handle_t *pamh) {
    struct passwd *pwd = NULL;
    const char *username = NULL;

    do {
        if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_ERR, "failed to get user");
            break;
        }

        pwd = getpwnam(username);
        if (!pwd) {
            pam_syslog(pamh, LOG_ERR, "failed to getpwnam");
            break;
        }
    } while (0);

    return pwd;
}