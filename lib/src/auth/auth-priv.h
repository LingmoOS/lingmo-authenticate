#pragma once

#include "com.lingmo.daemon.Authenticate.h"
#include "com.lingmo.daemon.Authenticate.Session.h"
#include "../encrypt/aes.h"
#include "../encrypt/rsa.h"
#include "auth.h"

struct _auth_proxy {
    gchar *username;
    GDBusConnection *con;
    GDBusProxy *authenticate_proxy;
    GDBusProxy *session_proxy;
    gchar *session_path;
    log_cb log_callback;
    signal_limit_updated_cb sig_limit_update_cb;
    void *limit_cb_userdata;
    signal_status_cb sig_status_cb;
    void *signal_cb_userdata;

    gchar *pubkey;
    gint enc_type;
    GVariant *enc_method;
    gchar *symmetricKey;
    pub_key *key;
};

#define MAX_BUFF_SIZE (512)

#define LOG_CB(obj, fmt, args...)                                                                  \
    do {                                                                                           \
        if (obj->log_callback) obj->log_callback(fmt, ##args);                                     \
    } while (0)
