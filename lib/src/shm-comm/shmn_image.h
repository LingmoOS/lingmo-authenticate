#ifndef _LIB_SHMN_IMAGE_H_
#define _LIB_SHMN_IMAGE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "shm_notifier.h"

  struct _image_info
  {
    int wight;
    int height;
    int format;
    int depth;
    int channels;
    int data_size;
  };

  typedef struct _image_obj
  {
    struct _image_info *vi;
    void *data;
    int data_size;
  } image_obj;

  typedef struct _image_info image_info;

  typedef struct _shmn_image shmn_image;

  typedef void (*IMAGE_DATA_UPDATE_CB)(image_obj *obj, int err_code,
                                       void *userdata);

  shmn_image *shmn_image_create(SHMN_ROLE role, const char *key,
                                char *socket_path, int size);

  SHMN_ERR shmn_image_write(shmn_image *si, void *data, int size,
                            image_info *ii);

  SHMN_ERR shmn_image_read_loop(shmn_image *si, IMAGE_DATA_UPDATE_CB cb,
                                void *userdata);

  void shmn_image_free(shmn_image *si);

#ifdef __cplusplus
}
#endif

#endif