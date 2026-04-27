#include "dbus.h"
#include "common.h"
#include "utils.h"
#include <security/_pam_types.h>
#include <systemd/sd-bus.h>

int dbus_method_authenticate(struct UserData *ud,
                             const char *username,
                             int flags,
                             int app_type,
                             char *path) {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    char *buf = NULL;
    int ret = 0;
    do {
        ret = sd_bus_call_method(ud->bus,
                                 DBUS_SERVICE,
                                 DBUS_PATH,
                                 DBUS_INTERFACE,
                                 "Authenticate",
                                 &err,
                                 &reply,
                                 "sii",
                                 username,
                                 flags,
                                 app_type);
        if (ret < 0) {
            pam_syslog(ud->pamh,
                       LOG_ERR,
                       "Failed to call 'Authenticate': %s, %s",
                       err.name,
                       err.message);
            break;
        }
        ret = sd_bus_message_read(reply, "s", &buf);
        if (ret < 0) {
            D_DEBUG(ud->pamh, "Failed to read 'Authenticate' value: %s", strerror(errno));
            break;
        }
        sprintf(path, "%s", buf);
        D_DEBUG(ud->pamh, "[DEBUG] Authenticate return path: %s", buf);
    } while (0);
    sd_bus_error_free(&err);
    sd_bus_message_unref(reply);
    return ret < 0 ? 1 : 0;
}

int dbus_method_get_limits(struct UserData *ud, const char *username, char *limits) {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    char *res = NULL;
    int ret = 0;
    do {
        ret = sd_bus_call_method(ud->bus,
                                 DBUS_SERVICE,
                                 DBUS_PATH,
                                 DBUS_INTERFACE,
                                 "GetLimits",
                                 &err,
                                 &reply,
                                 "s",
                                 username);
        if (ret < 0) {
            pam_syslog(ud->pamh,
                       LOG_ERR,
                       "Failed to call 'GetLimits': %s, %s",
                       err.name,
                       err.message);
            break;
        }
        ret = sd_bus_message_read(reply, "s", &res);
        if (ret < 0) {
            D_DEBUG(ud->pamh, "Failed to read 'GetLimits' value: %s", strerror(errno));
            break;
        }
        D_DEBUG(ud->pamh, "[DEBUG] GetLimits return: %s", res);
        sprintf(limits, "%s", res);
    } while (0);
    sd_bus_error_free(&err);
    sd_bus_message_unref(reply);
    return ret < 0 ? 1 : 0;
}

int dbus_method_end(struct UserData *ud, const char *path, int flag) {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    int ret = 0;
    do {
        ret = sd_bus_call_method(ud->bus,
                                 DBUS_SERVICE,
                                 path,
                                 DBUS_AUTHCTRL_INTERFACE,
                                 "End",
                                 &err,
                                 &reply,
                                 "i",
                                 flag);
        if (ret < 0) {
            pam_syslog(ud->pamh, LOG_ERR, "Failed to call 'End': %s, %s", err.name, err.message);
            break;
        }
    } while (0);
    sd_bus_error_free(&err);
    sd_bus_message_unref(reply);
    return ret < 0 ? 1 : 0;
}

int call_setToken_cb(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
    UNUSED_VALUE(m);
    UNUSED_VALUE(userdata);
    UNUSED_VALUE(ret_error);
    return 0;
}

int dbus_method_setToken(struct UserData *ud,
                         const char *path,
                         const int auth_type,
                         const char *password) {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    sd_bus_message *m = NULL;
    sd_bus_slot *slot = NULL;
    int ret = 0;

    char *cipher_text = NULL;
    int cipher_len = 0;

    D_DEBUG(ud->pamh, "Call aes encrypt.");
    ret = aes_cbc_encrypt(password,
                          strlen(password),
                          ud->symmetric_key,
                          strlen(ud->symmetric_key),
                          &cipher_text,
                          &cipher_len);
    D_DEBUG(ud->pamh, "End aes encrypt.");
    if (ret == -1) {
        pam_syslog(ud->pamh, LOG_ERR, "Failed to call encrypt");
        goto finished;
    }

    ret = sd_bus_message_new_method_call(ud->bus,
                                         &m,
                                         DBUS_SERVICE,
                                         path,
                                         DBUS_AUTHCTRL_INTERFACE,
                                         "SetToken");
    if (ret) {
        pam_syslog(ud->pamh, LOG_ERR, "Failed to create bus_message obj");
        ret = -1;
        goto finished;
    }

    sd_bus_message_append(m, "i", auth_type);
    sd_bus_message_append_array(m, 'y', (void *)cipher_text, cipher_len);

    D_DEBUG(ud->pamh, "[DEBUG] start SetToken with path: %s, password %s", path, cipher_text);
    ret = sd_bus_call_async(ud->bus, &slot, m, &call_setToken_cb, NULL, -1);

    if (ret < 0) {
        pam_syslog(ud->pamh, LOG_ERR, "Failed to call 'SetToken': %s, %s", err.name, err.message);
        goto finished;
    }
    D_DEBUG(ud->pamh, "[DEBUG] call SetToken finished");

finished:
    if (cipher_text) free(cipher_text);
    sd_bus_error_free(&err);
    sd_bus_message_unref(reply);
    return ret >= 0 ? 1 : 0;
}

int call_getResult_cb(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
    UNUSED_VALUE(m);
    UNUSED_VALUE(ret_error);
    int ret = 0;
    int res = 0;

    struct UserData *ud = (struct UserData *)userdata;
    if (!ud || !ud->pamh) {
        ret = -1;
        goto finished;
    }
    D_DEBUG(ud->pamh, "read 'getResult' cb");

    if (!m) {
        D_DEBUG(ud->pamh, "rep is null");
        ret = -1;
        goto finished;
    }
    ret = sd_bus_message_read(m, "i", &res);
    if (ret < 0) {
        D_DEBUG(ud->pamh, "get result error:");
        ud->get_result_val = GET_RESULT_UNAVAILABLE;
        goto finished;
    }

    ud->get_result_val = res;
    D_DEBUG(ud->pamh, "get 'getResult' value: %d", res);

finished:
    ud->waiting_result = 0;

    return ret;
}

int dbus_method_getResult(struct UserData *ud, const char *path, int *res) {
    UNUSED_VALUE(res);
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    sd_bus_slot *slot = NULL;
    int ret = 0;
    do {
        D_DEBUG(ud->pamh, "try get result with path: %s", path);
        ret = sd_bus_call_method_async(ud->bus,
                                       &slot,
                                       DBUS_SERVICE,
                                       path,
                                       DBUS_AUTHCTRL_INTERFACE,
                                       "GetResult",
                                       &call_getResult_cb,
                                       ud,
                                       "");
        if (ret < 0) {
            pam_syslog(ud->pamh,
                       LOG_ERR,
                       "Failed to call 'GetResult' error: %s, %s",
                       err.name,
                       err.message);
            ud->get_result_val = GET_RESULT_UNAVAILABLE;
            break;
        }
        D_DEBUG(ud->pamh, "[DEBUG] wait auth result");
        ud->waiting_result = 1;
    } while (0);
    sd_bus_error_free(&err);
    sd_bus_message_unref(reply);
    return ret < 0 ? 1 : 0;
}

int dbus_method_preOneKeyLogin(struct UserData *ud, const char *username, char *id) {
    UNUSED_VALUE(username);
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    int ret = 0;
    char *idreq = NULL;
    do {
        D_DEBUG(ud->pamh, "[DEBUG] start PreOneKeyLogin");
        ret = sd_bus_call_method(ud->bus,
                                 DBUS_SERVICE,
                                 DBUS_PATH,
                                 DBUS_INTERFACE,
                                 "PreOneKeyLogin",
                                 &err,
                                 &reply,
                                 "i",
                                 AUTH_FLAG_USING);
        if (ret < 0) {
            pam_syslog(ud->pamh,
                       LOG_ERR,
                       "Failed to call 'PreOneKeyLogin': %s, %s",
                       err.name,
                       err.message);
            break;
        }
        ret = sd_bus_message_read(reply, "s", &idreq);
        if (ret < 0) {
            D_DEBUG(ud->pamh, "Failed to read 'Authenticate' value: %s", strerror(errno));
            break;
        }
        D_DEBUG(ud->pamh, "[DEBUG] PreOneKeyLogin return id: %s", idreq);
        sprintf(id, "%s", idreq);
    } while (0);
    sd_bus_error_free(&err);
    sd_bus_message_unref(reply);
    return ret < 0 ? 1 : 0;
}

int dbus_method_start(struct UserData *ud, const char *path, int flags, int timeout) {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    int ret = 0;
    int statu = 0;
    do {
        D_DEBUG(ud->pamh, "[DEBUG] start auth for %s", path);
        ret = sd_bus_call_method(ud->bus,
                                 DBUS_SERVICE,
                                 path,
                                 DBUS_AUTHCTRL_INTERFACE,
                                 "Start",
                                 &err,
                                 &reply,
                                 "ii",
                                 flags,
                                 timeout);
        if (ret < 0) {
            pam_syslog(ud->pamh, LOG_ERR, "Failed to call 'Start': %s, %s", err.name, err.message);
            break;
        }
        ret = sd_bus_message_read(reply, "i", &statu);
        if (ret < 0) {
            D_DEBUG(ud->pamh, "Failed to read 'Authenticate' value: %s", strerror(errno));
            break;
        }
        if (!statu) {
            D_DEBUG(ud->pamh,
                    "Unable to open all the authentication methods requested by the caller");
        }
    } while (0);
    sd_bus_error_free(&err);
    sd_bus_message_unref(reply);
    return ret < 0 ? 1 : 0;
}

int listen_dbus_signal(struct UserData *userData, sd_bus_message_handler_t cb) {
    return sd_bus_match_signal(userData->bus,
                               NULL,
                               DBUS_SERVICE,
                               userData->path,
                               DBUS_AUTHCTRL_INTERFACE,
                               AUTH_SIGNAL_STATUS,
                               cb,
                               userData);
}

static int call_encryptKey_cb(sd_bus_message *m, void *data, sd_bus_error *err) {
    uint8_t t = 0;
    size_t len = 0;
    int *flags = NULL;
    char *buf = NULL;
    struct UserData *ud = (struct UserData *)data;
    Pubkey *key = ud->key;
    int ret = 0;

    if (err && err->name) {
        // Error
        pam_syslog(ud->pamh,
                   LOG_ERR,
                   "get encryptKey result error: %s, %s",
                   err->name,
                   err->message);
        return -1;
    }

    ret = sd_bus_message_get_type(m, &t);
    if (ret) {
        pam_syslog(ud->pamh, LOG_ERR, "Failed get message type");
        return -1;
    }
    if (t != SD_BUS_MESSAGE_METHOD_RETURN) {
        // Error
        return -1;
    }
    ret = sd_bus_message_read(m, "i", &(key->algType));
    if (ret < 0) {
        pam_syslog(ud->pamh, LOG_ERR, "Failed get alg type");
        return -1;
    }
    ret = sd_bus_message_read_array(m, 'i', (const void **)&(flags), &len);
    if (ret <= 0) {
        pam_syslog(ud->pamh, LOG_ERR, "Failed get alg flags");
        return -1;
    }
    key->flags = (int *)malloc(len);
    memcpy(key->flags, flags, len);

    ret = sd_bus_message_read(m, "s", &buf);
    if (ret < 0) {
        pam_syslog(ud->pamh, LOG_ERR, "Failed get alg pubkey");
        return -1;
    }

    key->pubkey = (char *)malloc(sizeof(char) * (strlen(buf) + 1));
    memcpy(key->pubkey, buf, sizeof(char) * (strlen(buf) + 1));
    D_DEBUG(ud->pamh,
            "[DEBUG]call_encryptKey_cb get pubkey alg type: %d, alg flag size: %ld(byte),key: %s",
            key->algType,
            len,
            key->pubkey);
    gen_rsa_pubkey(ud->pamh, &(key->rsa), key->pubkey);

    char *rsa_cipher_text = NULL;
    int rsa_cipher_len = 0;
    ret = encrypt_symmtric_key(ud, &rsa_cipher_text, &rsa_cipher_len);

    if (ret < 0) {
        return -1;
    }

    ret = dbus_method_set_symmetric_key(ud, ud->path, rsa_cipher_text, rsa_cipher_len);

    if (rsa_cipher_text) free(rsa_cipher_text);

    if (ret < 0) {
        return -1;
    }

    return 0;
}

int dbus_method_encryptKey(pam_handle_t *pamh,
                           sd_bus *bus,
                           const char *path,
                           int algType,
                           size_t flagSize,
                           unsigned char *flags,
                           struct UserData *ud) {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *m = NULL;
    sd_bus_message *reply = NULL;
    sd_bus_slot *slot = NULL;
    Pubkey *key = ud->key;
    int ret = 0;

    if (!key) return -1;
    ret = sd_bus_message_new_method_call(bus,
                                         &m,
                                         DBUS_SERVICE,
                                         path,
                                         DBUS_AUTHCTRL_INTERFACE,
                                         "EncryptKey");
    if (ret) {
        pam_syslog(pamh,
                   LOG_ERR,
                   "Failed to create bus_message obj: %s, %s",
                   err.name,
                   err.message);
        goto finished;
    }

    sd_bus_message_append(m, "i", algType);
    sd_bus_message_append_array(m, 'y', (void *)flags, flagSize);
    ret = sd_bus_call_async(bus, &slot, m, &call_encryptKey_cb, (void *)ud, -1);
    if (ret < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to call 'EncryptKey': %s, %s", err.name, err.message);
        goto finished;
    }

finished:
    sd_bus_error_free(&err);
    sd_bus_message_unref(reply);

    return ret < 0 ? 1 : 0;
}

#define ACCOUNT_MANAGER_DBUS_SERVICE "com.deepin.daemon.Accounts"
#define ACCOUNT_MANAGER_DBUS_PATH "/com/deepin/daemon/Accounts"
#define ACCOUNT_MANAGER_DBUS_INTERFACE "com.deepin.daemon.Accounts"
#define ACCOUNT_USER_DBUS_INTERFACE "com.deepin.daemon.Accounts.User"

int dbus_get_user_passwd_expired_info(struct UserData *ud,
                                      const char *username,
                                      int *expired_status,
                                      int64_t *left_days) {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    sd_bus_error user_err = SD_BUS_ERROR_NULL;
    sd_bus_message *user_reply = NULL;

    char *userpath_tmp = NULL;
    char userpath[MAX_BUF_SIZE];
    int expired_status_tmp = 0;
    int64_t left_days_tmp = 0;
    int ret = 0;

    memset(userpath, 0, MAX_BUF_SIZE);

    do {
        D_DEBUG(ud->pamh, "[DEBUG] start FindUserByName");
        ret = sd_bus_call_method(ud->bus,
                                 ACCOUNT_MANAGER_DBUS_SERVICE,
                                 ACCOUNT_MANAGER_DBUS_PATH,
                                 ACCOUNT_MANAGER_DBUS_INTERFACE,
                                 "FindUserByName",
                                 &err,
                                 &reply,
                                 "s",
                                 username);
        if (ret < 0) {
            pam_syslog(ud->pamh,
                       LOG_ERR,
                       "Failed to call 'FindUserByName': %s, %s",
                       err.name,
                       err.message);
            break;
        }
        ret = sd_bus_message_read(reply, "s", &userpath_tmp);
        if (ret < 0) {
            D_DEBUG(ud->pamh, "Failed to read 'FindUserByName' value: %s", strerror(errno));
            break;
        }

        strcpy(userpath, userpath_tmp);

        D_DEBUG(ud->pamh, "[DEBUG] start PasswordExpiredInfo for %s", userpath);
        ret = sd_bus_call_method(ud->bus,
                                 ACCOUNT_MANAGER_DBUS_SERVICE,
                                 userpath,
                                 ACCOUNT_USER_DBUS_INTERFACE,
                                 "PasswordExpiredInfo",
                                 &user_err,
                                 &user_reply,
                                 "");
        if (ret < 0) {
            pam_syslog(ud->pamh,
                       LOG_ERR,
                       "Failed to call 'PasswordExpiredInfo': %s, %s",
                       user_err.name,
                       user_err.message);
            break;
        }
        ret = sd_bus_message_read(user_reply, "i", &expired_status_tmp);
        if (ret < 0) {
            D_DEBUG(ud->pamh,
                    "Failed to read 'PasswordExpiredInfo' value 'expiredStatus': %s",
                    strerror(-ret));
            break;
        }
        *expired_status = expired_status_tmp;

        ret = sd_bus_message_read(user_reply, "x", &left_days_tmp);
        if (ret < 0) {
            D_DEBUG(ud->pamh,
                    "Failed to read 'PasswordExpiredInfo' value 'leftDays': %s",
                    strerror(-ret));
            break;
        }
        *left_days = left_days_tmp;
    } while (0);

    sd_bus_error_free(&err);
    if (reply) sd_bus_message_unref(reply);

    if (strlen(userpath)) sd_bus_error_free(&user_err);
    if (user_reply) sd_bus_message_unref(user_reply);

    return ret;
}

int dbus_get_prop_int(struct UserData *ud,
                      const char *service,
                      const char *path,
                      const char *interface,
                      const char *prop_name,
                      int *prop_val) {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    int tmp_val = 0;
    int ret = 0;
    do {
        ret = sd_bus_get_property(ud->bus, service, path, interface, prop_name, &err, &reply, "i");

        if (ret < 0) {
            pam_syslog(ud->pamh,
                       LOG_ERR,
                       "Failed to get '%s': %s, %s",
                       prop_name,
                       err.name,
                       err.message);
            break;
        }
        ret = sd_bus_message_read(reply, "i", &tmp_val);
        if (ret < 0) {
            D_DEBUG(ud->pamh, "Failed to read '%s' value: %s", prop_name, strerror(errno));
            break;
        }
        *prop_val = tmp_val;
    } while (0);
    sd_bus_error_free(&err);
    sd_bus_message_unref(reply);

    return ret;
}

int dbus_method_set_symmetric_key(struct UserData *ud,
                                  const char *path,
                                  char *symmetric_key,
                                  int cipher_len) {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    sd_bus_message *m = NULL;

    int ret = 0;
    do {
        D_DEBUG(ud->pamh,
                "[DEBUG] start SetSymmetricKey for %s, cipher size: %d",
                path,
                cipher_len);

        ret = sd_bus_message_new_method_call(ud->bus,
                                             &m,
                                             DBUS_SERVICE,
                                             path,
                                             DBUS_AUTHCTRL_INTERFACE,
                                             "SetSymmetricKey");
        if (ret) {
            pam_syslog(ud->pamh, LOG_ERR, "Failed to create bus_message obj");
            ret = -1;
            goto finished;
        }

        sd_bus_message_append_array(m, 'y', (void *)symmetric_key, cipher_len);

        ret = sd_bus_call(ud->bus, m, 10000000, &err, &reply);

        if (ret < 0) {
            pam_syslog(ud->pamh,
                       LOG_ERR,
                       "Failed to call 'SetSymmetricKey': %s, %s",
                       err.name,
                       err.message);
            break;
        }
    } while (0);

finished:
    sd_bus_error_free(&err);
    sd_bus_message_unref(reply);
    sd_bus_message_unref(m);
    return ret < 0 ? 1 : 0;
}
