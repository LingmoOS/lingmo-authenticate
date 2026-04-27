#ifndef _LIB_SHMN_SHMNOTIFIER_PRIV_H_
#define _LIB_SHMN_SHMNOTIFIER_PRIV_H_

#include "shm_notifier.h"
#include <glib-2.0/glib.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>

#define LOCK_STATE_VAL (1)
#define UNLOCK_STATE_VAL (0)
typedef struct _lock
{
  int n;
} lock;

struct _shmn
{
  SHMN_ROLE role;
  bool enable_ex;
  const char *socket_path;
  int self_fd;
  int efd;

  struct epoll_event *epoll_tev;
  GList *cli_fd_list;
  pthread_mutex_t list_mtx;

  void *send_data;
  void *rcvd_data;
  int sender_size;
  int rcvder_size;

  pthread_t listen_pid;
  pthread_t recv_loop_pid;

  DATA_UPDATE_CB recv_cb;
  void *user_data;

  lock *locker;
  int real_shm_offset;
};

#endif