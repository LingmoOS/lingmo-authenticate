#include "shm_notifier_priv.h"

#include "shmn_image.h"

struct _shmn_image
{
    shmn *s;
    void *data;
    image_info *ii;
    image_obj *io;
    IMAGE_DATA_UPDATE_CB cb;
    void *update_cb_userdata;
};

shmn_image *shmn_image_create(SHMN_ROLE role, const char *key, char *socket_path, int size)
{
    shmn_image *shmn_i = (shmn_image *)malloc(sizeof(shmn_image));
    shmn_i->s = shmn_create(role, key, socket_path, size + sizeof(struct _image_info));
    if (role == SHMN_ROLE_READER)
    {
        shmn_i->io = (image_obj *)malloc(sizeof(image_obj));
    }

    return shmn_i;
}

static void image_data_write_cb(void *dst, void *user_data, int data_size)
{
    shmn_image *svi = (shmn_image *)user_data;
    memcpy(dst, svi->ii, sizeof(image_info));
    memcpy(dst + sizeof(image_info), svi->data, data_size - sizeof(image_info));
}

SHMN_ERR shmn_image_write(shmn_image *si, void *data, int size, image_info *ii)
{
    if (!si)
    {
        return SHMN_ERR_EMPTY_OBJECT;
    }

    if (!ii)
    {
        return SHMN_ERR_EMPTY_OBJECT;
    }

    if (!data)
    {
        return SHMN_ERR_EMPTY_OBJECT;
    }

    si->data = data;
    si->ii = ii;
    return shmn_write(si->s, si, size + sizeof(image_info), image_data_write_cb);
}

static void image_data_read_cb(void *user_data, void *data, int size,
                               int err_code)
{
    shmn_image *svi = (shmn_image *)user_data;

    svi->io->vi = data;
    svi->io->data = data + sizeof(image_info);
    svi->io->data_size = size - sizeof(image_info);

    if (svi->cb)
    {
        svi->cb(svi->io, err_code, svi->update_cb_userdata);
    }
}

SHMN_ERR shmn_image_read_loop(shmn_image *svi, IMAGE_DATA_UPDATE_CB cb, void *userdata)
{
    svi->cb = cb;
    svi->update_cb_userdata = userdata;

    return shmn_read_loop(svi->s, image_data_read_cb, (void *)svi);
}

void shmn_image_free(shmn_image *svi)
{
    shmn_free(svi->s);
}