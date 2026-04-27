
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "rsa.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <glib-2.0/glib.h>

struct _pub_key
{
    int algType;
    int *flags;
    char *pubkey;
    RSA *rsa;
};

#define PKCS1_HEADER "-----BEGIN RSA PUBLIC KEY-----"
#define PKCS8_HEADER "-----BEGIN PUBLIC KEY-----"

int gen_rsa_pubkey(pub_key *pk, char *key)
{
    BIO *bio;
    int ret = 0;

    bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        ret = -1;
        goto finished;
    }

    BIO_puts(bio, key);

    if (0 == strncmp(key, PKCS8_HEADER, strlen(PKCS8_HEADER)))
    {
        PEM_read_bio_RSA_PUBKEY(bio, &pk->rsa, NULL, NULL);
    }
    else if (0 == strncmp(key, PKCS1_HEADER, strlen(PKCS1_HEADER)))
    {
        PEM_read_bio_RSAPublicKey(bio, &pk->rsa, NULL, NULL);
    }

finished:
    if (bio)
        BIO_free(bio);
    return ret;
}

void create_symmetric_key(char **symmetric_key)
{
    char *key = (char *)malloc(20);
    srand(time(NULL));
    int rand_num = (10000000 + rand() % 10000000) % 100000000;
    sprintf(key, "%d%d", rand_num, rand_num);
    *symmetric_key = g_strdup(key);

    free(key);
}

int rsa_encrypt_data(pub_key *pk, char *origin_data, char **cipher_text)
{
    if (!pk || !pk->rsa)
    {
        return -1;
    }

    int clipSize = RSA_size(pk->rsa);
    *cipher_text = (char *)malloc(clipSize);

    int ret = RSA_public_encrypt(strlen(origin_data),
                                 (const unsigned char *)origin_data,
                                 (unsigned char *)*cipher_text,
                                 pk->rsa,
                                 RSA_PKCS1_PADDING);
    return ret;
}

pub_key *create_pub_key()
{
    pub_key *pk = (pub_key *)malloc(sizeof(pub_key));
    memset(pk, 0, sizeof(pub_key));
    return pk;
}

void pub_key_free(pub_key *pk)
{
    if (pk)
    {
        if (pk->rsa)
        {
            RSA_free(pk->rsa);
        }
        free(pk);
    }
}