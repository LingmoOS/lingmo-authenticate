#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _pub_key pub_key;

pub_key *create_pub_key();

void pub_key_free(pub_key *pk);

int gen_rsa_pubkey(pub_key *pk, char *key);

void create_symmetric_key(char **symmetric_key);

int rsa_encrypt_data(pub_key *pk, char *origin_data, char **cipher_text);

#ifdef __cplusplus
}
#endif
