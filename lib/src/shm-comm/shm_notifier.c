#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <string.h>
#include <sys/un.h>

#include <stdio.h>
#include <errno.h>
#include "shm_notifier_priv.h"
#include "debug.h"

#define MAX_OPEN_FD 3
#define INT_TO_STRING_MAX_LEN (10)

static void *listen_client(void *user_data)
{
    struct epoll_event epoll_ev[MAX_OPEN_FD];
    struct sockaddr_in cliaddr;
    socklen_t clilen;
    shmn *s = (shmn *)user_data;
    while (1)
    {
        ssize_t nready = epoll_wait(s->efd, (struct epoll_event *)epoll_ev, MAX_OPEN_FD, -1);
        for (int i = 0; i < nready; ++i)
        {
            // 如果是新的连接,需要把新的socket添加到efd中
            if (epoll_ev[i].data.fd == s->self_fd)
            {
                int connfd = accept(s->self_fd, (struct sockaddr *)&cliaddr, &clilen);
                g_debug("client connected");
                s->epoll_tev->events = EPOLLIN;
                s->epoll_tev->data.fd = connfd;
                epoll_ctl(s->efd, EPOLL_CTL_ADD, connfd, s->epoll_tev);

                pthread_mutex_lock(&s->list_mtx);
                s->cli_fd_list = g_list_append(s->cli_fd_list, GINT_TO_POINTER(connfd));
                pthread_mutex_unlock(&s->list_mtx);
            }
            else
            {
                char read_buffer[4];
                int n = read(epoll_ev[i].data.fd, read_buffer, 4);
                if (n == 0)
                {
                    s->cli_fd_list = g_list_remove(s->cli_fd_list, GINT_TO_POINTER(epoll_ev[i].data.fd));
                }
                else
                {
                    if (s->enable_ex)
                    {
                        // DEBUG("recv data from client");
                        int len = atoi(read_buffer);
                        s->recv_cb(s->user_data, s->rcvd_data, len, CB_NO_ERR);
                    }
                }
            }
        }
    }
    return NULL;
}

static int create_tcp_server(shmn *s, const char *socket_path)
{
    int listenfd, efd, ret;
    struct sockaddr_un servaddr;
    struct epoll_event *tep = malloc(sizeof(struct epoll_event));

    listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listenfd == -1)
    {
        return -1;
    }
    unlink(socket_path);

    servaddr.sun_family = AF_UNIX;
    strcpy(servaddr.sun_path, socket_path);
    bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    listen(listenfd, 20);

    efd = epoll_create(MAX_OPEN_FD);
    tep->events = EPOLLIN;
    tep->data.fd = listenfd;

    ret = epoll_ctl(efd, EPOLL_CTL_ADD, listenfd, tep);

    s->epoll_tev = tep;
    s->self_fd = listenfd;
    s->efd = efd;

    ret = pthread_create(&s->listen_pid, NULL, listen_client, (void *)s);

    return ret;
}

static int connect_to_tcp_server(shmn *s, const char *socket_path)
{
    int cli_fd = -1;
    struct sockaddr_un servaddr;
    socklen_t serv_len = sizeof(servaddr);
    cli_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cli_fd == -1)
    {
        return -1;
    }

    servaddr.sun_family = AF_UNIX;
    strcpy(servaddr.sun_path, socket_path);

    int ret = connect(cli_fd, (struct sockaddr *)&servaddr, serv_len);
    if (ret != 0)
    {
        g_debug("connect to server err: %s", strerror(errno));
        return -1;
    }
    s->self_fd = cli_fd;

    return 0;
}

static void *create_shm_data(const char *key, int prot G_GNUC_UNUSED, int size)
{
    int fd = shm_open(key, O_CREAT | O_RDWR, 0666);
    if (fd < 0)
    {
        return NULL;
    }

    ftruncate(fd, size);

    void *data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (!data || data == MAP_FAILED)
    {
        ftruncate(fd, 0);
        return NULL;
    }
    return data;
}

shmn *shmn_create(SHMN_ROLE role, const char *key, char *socket_path, int size)
{
    if (role != SHMN_ROLE_READER && role != SHMN_ROLE_WRITER)
    {
        return NULL;
    }
    shmn *s = (shmn *)(malloc(sizeof(shmn)));
    memset(s, 0, sizeof(shmn));

    s->real_shm_offset = sizeof(lock);
    void *data = create_shm_data(key, PROT_WRITE, size + s->real_shm_offset);
    if (!data)
    {
        free(s);
        return NULL;
    }

    s->socket_path = socket_path;
    s->role = role;

    pthread_mutex_init(&s->list_mtx, NULL);
    s->locker = (lock *)data;

    int ret = 0;
    switch (role)
    {
    case SHMN_ROLE_WRITER:
        s->send_data = data + s->real_shm_offset;
        s->sender_size = size;
        ret = create_tcp_server(s, socket_path);
        break;

    case SHMN_ROLE_READER:
        s->rcvd_data = data + s->real_shm_offset;
        s->rcvder_size = size;
        ret = connect_to_tcp_server(s, socket_path);
        break;
    }

    if (ret != 0)
    {
        g_debug("create obj error");
        shmn_free(s);
        return NULL;
    }

    return s;
}

SHMN_ERR shmn_enable_role_ex(shmn *s, const char *key, int size)
{
    if (!s)
    {
        return SHMN_ERR_EMPTY_OBJECT;
    }

    if (s->role == SHMN_ROLE_WRITER)
    {
        if (s->rcvd_data)
        {
            return SHMN_ERR_DATA_EXIST;
        }

        void *data = create_shm_data(key, PROT_READ, size);
        if (!data)
        {
            return SHMN_ERR_EMPTY_OBJECT;
        }
        s->rcvd_data = data;
        s->rcvder_size = size;
    }
    else if (s->role == SHMN_ROLE_READER)
    {
        if (s->send_data)
        {
            return SHMN_ERR_DATA_EXIST;
        }

        void *data = create_shm_data(key, PROT_WRITE, size);
        if (!data)
        {
            return SHMN_ERR_EMPTY_OBJECT;
        }
        s->send_data = data;
        s->sender_size = size;
    }
    s->enable_ex = true;

    return SHMN_NO_ERR;
}

void shmn_free(shmn *s)
{
    if (!s)
    {
        return;
    }

    if (s->send_data)
    {
        munmap(s->send_data, s->sender_size);
    }

    if (s->epoll_tev)
    {
        free(s->epoll_tev);
    }

    if (s->send_data)
    {
        munmap(s->send_data, s->sender_size);
    }

    if (s->rcvd_data)
    {
        munmap(s->rcvd_data, s->rcvder_size);
    }

    if (s->listen_pid)
    {
        pthread_cancel(s->listen_pid);
    }

    if (s->recv_loop_pid)
    {
        pthread_cancel(s->recv_loop_pid);
    }

    if (s->cli_fd_list)
    {
        g_free(s->cli_fd_list);
    }

    s = NULL;
}

void server_send_data_foreach(gpointer data, gpointer userdata)
{
    write(GPOINTER_TO_INT(data), userdata, INT_TO_STRING_MAX_LEN);
}

SHMN_ERR shmn_write(shmn *s, void *data, int len, DATA_WRITE_CB cb)
{
    if (!s)
    {
        return SHMN_ERR_EMPTY_OBJECT;
    }

    if (len > s->sender_size)
    {
        return SHMN_ERR_DATA_SIZE;
    }

    if (s->role == SHMN_ROLE_WRITER)
    {
        if (cb != NULL)
        {
            cb(s->send_data, data, len);
        }
        else
        {
            memcpy(s->send_data, data, len);
        }

        char len_str[INT_TO_STRING_MAX_LEN];
        sprintf(len_str, "%d", len);

        pthread_mutex_lock(&s->list_mtx);
        g_list_foreach(s->cli_fd_list, server_send_data_foreach, (gpointer)(len_str));
        pthread_mutex_unlock(&s->list_mtx);
    }
    else if (s->role == SHMN_ROLE_READER && s->enable_ex)
    {
        memcpy(s->send_data, data, len);

        char len_str[INT_TO_STRING_MAX_LEN];
        sprintf(len_str, "%d", len);

        write(s->self_fd, len_str, INT_TO_STRING_MAX_LEN);
    }
    return SHMN_NO_ERR;
}

static void *recv_loop(void *user_data)
{
    int n = 0;
    shmn *s = (shmn *)user_data;
    char buff[INT_TO_STRING_MAX_LEN];
    while (1)
    {
        n = read(s->self_fd, buff, INT_TO_STRING_MAX_LEN);
        if (n < 0)
        {
        }
        else if (n == 0)
        {
            s->recv_cb(s->user_data, NULL, 0, CB_ERR_DISCONNETED);
        }
        else
        {
            int len = atoi(buff);
            s->recv_cb(s->user_data, s->rcvd_data, len, CB_NO_ERR);
        }
    }
    return NULL;
}

SHMN_ERR shmn_read_loop(shmn *s, DATA_UPDATE_CB cb, void *user_data)
{
    int ret;
    s->recv_cb = cb;
    s->user_data = user_data;

    if (s->role == SHMN_ROLE_READER)
    {
        ret = pthread_create(&s->recv_loop_pid, NULL, recv_loop, (void *)s);
    }

    return ret == 0 ? SHMN_NO_ERR : SHMN_ERR_UNDEFINED;
}

SHMN_ERR shmn_lock_channel(shmn *s)
{
    if (!s)
    {
        return SHMN_ERR_EMPTY_OBJECT;
    }
    if (!s->locker)
    {
        return SHMN_ERR_EMPTY_OBJECT;
    }

    do
    {

    } while (s->locker->n != LOCK_STATE_VAL);

    s->locker->n = LOCK_STATE_VAL;

    return SHMN_NO_ERR;
}

SHMN_ERR shmn_unlock_channel(shmn *s)
{
    if (!s)
    {
        return SHMN_ERR_EMPTY_OBJECT;
    }
    if (!s->locker)
    {
        return SHMN_ERR_EMPTY_OBJECT;
    }

    s->locker->n = UNLOCK_STATE_VAL;

    return SHMN_NO_ERR;
}