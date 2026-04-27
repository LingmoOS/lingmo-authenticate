#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <string.h>

int aes_cbc_encrypt(const char *src,
                    int srcLen,
                    char *key,
                    int keyLen,
                    char **cipher_text,
                    int *outLen)
{
    int blockCount = 0;
    int quotient = srcLen / AES_BLOCK_SIZE;
    int mod = srcLen % AES_BLOCK_SIZE;
    blockCount = quotient + 1;

    int padding = AES_BLOCK_SIZE - mod;
    char *in = (char *)malloc(AES_BLOCK_SIZE * blockCount);
    memset(in, padding, AES_BLOCK_SIZE * blockCount);
    memcpy(in, src, srcLen);

    // out
    char *out = (char *)malloc(AES_BLOCK_SIZE * blockCount);
    memset(out, 0x00, AES_BLOCK_SIZE * blockCount);
    *outLen = AES_BLOCK_SIZE * blockCount;

    //初始向量为全0
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

    //开始加密
    AES_KEY aes;
    if (AES_set_encrypt_key((unsigned char *)key, keyLen * 8, &aes) < 0)
    {
        if (in) {
            free(in);
        }
        if (out) {
            free(out);
        }
        return -1;
    }
    AES_cbc_encrypt((unsigned char *)in,
                    (unsigned char *)out,
                    AES_BLOCK_SIZE * blockCount,
                    &aes,
                    iv,
                    AES_ENCRYPT);
    free(in);
    *cipher_text = out;

    return 0;
}

int aes_cbc_decrypt(unsigned char *src, int src_len, unsigned char *key,
                    int key_len, char **orig_text, int *out_len) {
  //初始向量为全0
  unsigned char iv[AES_BLOCK_SIZE];
  memset(iv, 0x00, AES_BLOCK_SIZE);

  //开始加密
  AES_KEY aes;
  if (AES_set_decrypt_key((unsigned char *)key, key_len * 8, &aes) < 0) {
    return -1;
  }
  char *tmp = (char *)malloc(src_len);
  memset(tmp, 0x00, src_len);
  AES_cbc_encrypt((unsigned char *)src, (unsigned char *)tmp, src_len, &aes, iv,
                  AES_DECRYPT);

  // PKCS5 UNPADDING
  int unpadding = tmp[src_len - 1];
  *out_len = src_len - unpadding;
  *orig_text = (char *)malloc(*out_len);
  memcpy(*orig_text, tmp, *out_len);

  free(tmp);
  return 0;
}
