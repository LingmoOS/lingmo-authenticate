#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int aes_cbc_encrypt(const char *src, int srcLen, char *key, int keyLen,
                    char **cipher_text, int *outLen);

int aes_cbc_decrypt(unsigned char *src, int src_len, unsigned char *key,
                    int key_len, char **orig_text, int *out_len);

#ifdef __cplusplus
}
#endif
