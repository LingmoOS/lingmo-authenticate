#ifndef _UTILS_H_
#define _UTILS_H_

#include "common.h"

int resolve_verify_msg(const struct UserData *ud, const char *verify_msg, char *res_msg);

int get_authctl_property(struct UserData *ud, char *path, struct AuthSession *res);

void load_user_locale(pam_handle_t *pamh,
                      struct UserData *ud,
                      const char *username,
                      const char *locale_path);

void get_limits_info(struct UserData *ud);

int gen_rsa_pubkey(pam_handle_t *pamh, RSA **rsa, char *key);

char *load_app_type(struct UserData *ud, char *app_path);

char *gen_symmetric_key();

int rsa_encrypt_data(struct UserData *ud, char *origin_data, char **cipher_text);

int encrypt_symmtric_key(struct UserData *ud, char **cipher_text, int *cipher_len);

int aes_cbc_encrypt(const char *src,
                    int srcLen,
                    char *key,
                    int keyLen,
                    char **cipher_text,
                    int *outLen);

#endif
