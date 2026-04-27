#ifndef _LIB_SHMN_SHMNOTIFIER_H_
#define _LIB_SHMN_SHMNOTIFIER_H_

#ifdef __cplusplus
extern "C" {
#endif

#define CB_NO_ERR (0)
#define CB_ERR_DISCONNETED (1)

typedef void (*DATA_UPDATE_CB)(void *user_data, void *data, int size,
                               int err_code);

typedef void (*DATA_WRITE_CB)(void *dst, void *user_data, int data_size);

typedef struct _shmn shmn;

typedef enum { SHMN_ROLE_WRITER = 1, SHMN_ROLE_READER } SHMN_ROLE;

typedef enum {
  SHMN_NO_ERR = 0,
  SHMN_ERR_EMPTY_OBJECT = -1,
  SHMN_ERR_ROLE = -2,
  SHMN_ERR_DATA_SIZE = -3,
  SHMN_ERR_UNDEFINED = -4,
  SHMN_ERR_DATA_EXIST = -5,
} SHMN_ERR;

shmn *shmn_create(SHMN_ROLE role, const char *key, char *socket_path, int size);

SHMN_ERR shmn_write(shmn *s, void *data, int len, DATA_WRITE_CB cb);

SHMN_ERR shmn_read_loop(shmn *s, DATA_UPDATE_CB cb, void *user_data);

void shmn_free(shmn *s);

SHMN_ERR shmn_enable_role_ex(shmn *s, const char *key, int size);

SHMN_ERR shmn_unlock_channel(shmn *s);

SHMN_ERR shmn_lock_channel(shmn *s);

#ifdef __cplusplus
}
#endif

#endif
