#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "auth.h"

void da_load_user_locale(const char *username);

const char *da_success_prompt();

int da_get_lock_info(da_proxy *proxy, const char *username,
                     DA_AUTH_FLAG auth_type, bool *is_lock, char **prompt);

int da_get_fail_prompt(da_proxy *proxy, DA_AUTH_FLAG auth_flag,
                       bool with_retry_info, char **prompt);

int da_get_user_lang(const char *username, char **lang);

#ifdef __cplusplus
}
#endif
