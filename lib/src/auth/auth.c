#include "com.deepin.daemon.Authenticate.h"
#include "com.deepin.daemon.Authenticate.Session.h"
#include <stdio.h>
#include <json-c/json.h>
#include "auth-priv.h"

#define DA_DBUS_SERVER "com.deepin.daemon.Authenticate"
#define DA_DBUS_MANAGER_PATH "/com/deepin/daemon/Authenticate"

#define DA_DBUS_SESSION_INTERFACE "com.deepin.daemon.Authenticate.Session"

int da_set_log_callback(da_proxy *proxy, log_cb cb) {
    if (proxy == NULL || cb == NULL) {
        return -1;
    }
    proxy->log_callback = cb;
    return 0;
}
static int limit_json_deal(gchar *in, da_limit_info **limits, int *limit_len) {
    if (in == NULL || limits == NULL) {
        return -1;
    }
    json_object *pobj = NULL;
    pobj = json_tokener_parse(in);

    int ele_num = json_object_array_length(pobj);
    *limit_len = ele_num;

    *limits = (da_limit_info *)malloc(sizeof(da_limit_info) * ele_num);

    int error_ret = 0;
    for (int i = 0; i < ele_num; i++) {
        json_object *ele_json = json_object_array_get_idx(pobj, i);
        if (ele_json) {
            json_object *json_type = NULL;
            json_object *json_flag = NULL;
            json_object *json_unlock_secs = NULL;
            json_object *json_max_tries = NULL;
            json_object *json_num_failures = NULL;
            json_object *json_locked = NULL;
            json_object *json_unlockT_time = NULL;
            json_bool ret = json_object_object_get_ex(ele_json, "type", &json_type);
            if (!ret) {
                error_ret = -1;
                break;
            }
            ret = json_object_object_get_ex(ele_json, "flag", &json_flag);
            if (!ret) {
                error_ret = -1;
                break;
            }
            ret = json_object_object_get_ex(ele_json, "unlockSecs", &json_unlock_secs);
            if (!ret) {
                error_ret = -1;
                break;
            }
            ret = json_object_object_get_ex(ele_json, "maxTries", &json_max_tries);
            if (!ret) {
                error_ret = -1;
                break;
            }
            ret = json_object_object_get_ex(ele_json, "numFailures", &json_num_failures);
            if (!ret) {
                error_ret = -1;
                break;
            }
            ret = json_object_object_get_ex(ele_json, "locked", &json_locked);
            if (!ret) {
                error_ret = -1;
                break;
            }
            ret = json_object_object_get_ex(ele_json, "unlockTime", &json_unlockT_time);
            if (!ret) {
                error_ret = -1;
                break;
            }
            g_strlcpy(((*limits) + i)->type, json_object_get_string(json_type), 64);
            ((*limits) + i)->flag = json_object_get_int(json_flag);
            ((*limits) + i)->unlock_secs = json_object_get_int(json_unlock_secs);
            ((*limits) + i)->max_tries = json_object_get_int(json_max_tries);
            ((*limits) + i)->fail_num = json_object_get_int(json_num_failures);
            ((*limits) + i)->locked = json_object_get_boolean(json_locked);
            g_strlcpy(((*limits) + i)->unlock_time, json_object_get_string(json_unlockT_time), 64);
        }
    }
    json_object_put(pobj);

    return error_ret;
}

gboolean signal_limit_updated_handler(ComDeepinDaemonAuthenticate *object,
                                      gchar *value,
                                      gpointer userdata) {
    g_return_val_if_fail(IS_COM_DEEPIN_DAEMON_AUTHENTICATE(object), FALSE);

    da_proxy *proxy = (da_proxy *)userdata;

    if (g_strcmp0(value, proxy->username)) {
        return FALSE;
    }

    LOG_CB(proxy, "signal_limit_updated_handler invoked! %s.\n", value);

    if (proxy->sig_limit_update_cb) {
        da_limit_info *dli = NULL;
        int dli_num = 0;

        GError *callError = NULL;
        gchar *out_limits = NULL;
        com_deepin_daemon_authenticate_call_get_limits_sync(
                (ComDeepinDaemonAuthenticate *)(proxy->authenticate_proxy),
                value,
                &out_limits,
                NULL,
                &callError);
        if (callError != NULL) {
            g_error_free(callError);
            return -1;
        }
        if (out_limits == NULL) {
            return -1;
        }

        limit_json_deal(out_limits, &dli, &dli_num);
        proxy->sig_limit_update_cb(proxy->limit_cb_userdata, dli, dli_num);

        if (dli) {
            free(dli);
        }
    }

    return TRUE;
}

bool is_valid_auth_flag(int auth_flag) {
    if (auth_flag == AUTH_FLAG_PASSWORD || auth_flag == AUTH_FLAG_FINGERPRINT ||
        auth_flag == AUTH_FLAG_AD || auth_flag == AUTH_FLAG_FACE ||
        auth_flag == AUTH_FLAG_FINGERVEIN || auth_flag == AUTH_FLAG_IRIS ||
        auth_flag == AUTH_FLAG_UKEY) {
        return true;
    }
    return false;
}

da_limit_info *da_get_auth_limit_info(da_limit_info *dli, int dli_num, DA_AUTH_FLAG auth_flag) {
    if (!dli || !is_valid_auth_flag(auth_flag) || auth_flag == AUTH_FLAG_ALL) {
        return NULL;
    }

    for (int i = 0; i < dli_num; i++) {
        if (&dli[i]) {
            if (dli[i].flag == auth_flag) {
                return &dli[i];
            }
        }
    }

    return NULL;
}

// Released by caller
// if err is NULL, ignore errors
static void error_dup(da_error **err, GError *callError) {
    if (err != NULL && callError != NULL) {
        *err = (da_error *)g_malloc(sizeof(da_error));
        (*err)->msg = g_strdup(callError->message);
        (*err)->code = callError->code;
    }
}

// Released by caller
// if err is NULL, ignore errors
static void error_new(da_error **err, char *msg) {
    if (err != NULL) {
        *err = (da_error *)g_malloc(sizeof(da_error));
        (*err)->msg = g_strdup(msg);
        (*err)->code = -1;
    }
}

static gboolean has_valid_authenticate_proxy(da_proxy *proxy) {
    g_return_val_if_fail((proxy != NULL), FALSE);
    g_return_val_if_fail(IS_COM_DEEPIN_DAEMON_AUTHENTICATE(proxy->authenticate_proxy), FALSE);
    return TRUE;
}
static gboolean has_valid_session_proxy(da_proxy *proxy) {
    g_return_val_if_fail((proxy != NULL), FALSE);
    g_return_val_if_fail(IS_COM_DEEPIN_DAEMON_AUTHENTICATE_SESSION(proxy->session_proxy), FALSE);
    return TRUE;
}

// da_dbus_proxy_new: 创建manager dbus接口proxy
da_proxy *da_dbus_proxy_new() {
    da_proxy *proxy = (da_proxy *)g_malloc(sizeof(da_proxy));
    proxy->limit_cb_userdata = NULL;
    proxy->log_callback = NULL;
    proxy->sig_status_cb = NULL;
    memset(proxy, 0, sizeof(da_proxy));

    GError *connerror = NULL;
    proxy->con = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &connerror);
    if (connerror != NULL) {
        g_error_free(connerror);
        return NULL;
    }
    GError *callError = NULL;
    proxy->authenticate_proxy =
            (GDBusProxy *)com_deepin_daemon_authenticate_proxy_new_sync(proxy->con,
                                                                        G_DBUS_PROXY_FLAGS_NONE,
                                                                        DA_DBUS_SERVER,
                                                                        DA_DBUS_MANAGER_PATH,
                                                                        NULL,
                                                                        &callError);
    if (callError != NULL) {
        g_error_free(callError);
        g_free(proxy);
        return NULL;
    }
    if (proxy->authenticate_proxy == NULL) {
        g_free(proxy);
        return NULL;
    }

    g_signal_connect((ComDeepinDaemonAuthenticate *)(proxy->authenticate_proxy),
                     "limit-updated",
                     G_CALLBACK(signal_limit_updated_handler),
                     proxy);
    return proxy;
}

gboolean signal_status_handler(ComDeepinDaemonAuthenticateSession *object,
                               gint flag,
                               gint status,
                               gchar *msg,
                               gpointer userdata) {
    g_return_val_if_fail(IS_COM_DEEPIN_DAEMON_AUTHENTICATE_SESSION(object), FALSE);

    da_proxy *proxy = (da_proxy *)userdata;

    LOG_CB(proxy, "signal_status_handler invoked!\n");

    if (proxy->sig_status_cb) {
        proxy->sig_status_cb(proxy->signal_cb_userdata, flag, status, msg);
    }

    return TRUE;
}

// da_create_authenticate： 创建session dbus接口proxy
int da_create_authenticate(da_proxy *proxy,
                           const char *username,
                           int flags,
                           int app_type,
                           da_error **err) {
    g_return_val_if_fail(has_valid_authenticate_proxy(proxy), -1);

    GError *callError = NULL;
    gchar *out_path = NULL;
    com_deepin_daemon_authenticate_call_authenticate_sync(
            (ComDeepinDaemonAuthenticate *)(proxy->authenticate_proxy),
            username,
            flags,
            app_type,
            &out_path,
            NULL,
            &callError);
    if (callError != NULL) {
        error_dup(err, callError);
        g_error_free(callError);
        return -1;
    }
    if (out_path == NULL) {
        error_new(err, "call dbus-authenticate failed.");
        return -1;
    }

    proxy->session_proxy = (GDBusProxy *)com_deepin_daemon_authenticate_session_proxy_new_sync(
            proxy->con,
            G_DBUS_PROXY_FLAGS_NONE,
            DA_DBUS_SERVER,
            out_path,
            NULL,
            &callError);
    if (callError != NULL) {
        error_dup(err, callError);
        g_error_free(callError);
        g_free(out_path);
        return -1;
    }
    if (proxy->session_proxy == NULL) {
        error_new(err, "create session failed.");
        g_free(out_path);
        return -1;
    }
    proxy->session_path = out_path;
    proxy->username = g_strdup(username);

    GVariant *args = g_variant_new_array(G_VARIANT_TYPE_INT32, NULL, 0);
    com_deepin_daemon_authenticate_session_call_encrypt_key_sync(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy),
            0,
            args,
            &proxy->enc_type,
            &proxy->enc_method,
            &proxy->pubkey,
            NULL,
            &callError);
    // g_variant_unref(args);

    if (callError != NULL) {
        error_dup(err, callError);
        g_error_free(callError);
        g_free(out_path);
        return -1;
    }

    proxy->key = create_pub_key();

    int ret = gen_rsa_pubkey(proxy->key, proxy->pubkey);
    if (ret) {
        error_new(err, "gen rsa error");
        g_free(out_path);
        return -1;
    }

    create_symmetric_key(&proxy->symmetricKey);

    gchar *encrypt_symmetricKey = NULL;
    int len = rsa_encrypt_data(proxy->key, proxy->symmetricKey, (char **)&encrypt_symmetricKey);

    GBytes *bytes = g_bytes_new(encrypt_symmetricKey, len);

    GVariant *enc_symmetricKey_variant =
            g_variant_new_from_bytes(G_VARIANT_TYPE_BYTESTRING, bytes, TRUE);

    com_deepin_daemon_authenticate_session_call_set_symmetric_key_sync(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy),
            enc_symmetricKey_variant,
            NULL,
            &callError);

    g_free(encrypt_symmetricKey);
    g_bytes_unref(bytes);
    // g_variant_unref(enc_symmetricKey_variant);

    if (callError != NULL) {
        error_dup(err, callError);
        g_error_free(callError);
        g_free(out_path);
        return -1;
    }

    g_signal_connect((ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy),
                     "status",
                     G_CALLBACK(signal_status_handler),
                     proxy);

    return 0;
}

int da_quit_authenticate(da_proxy *proxy, da_error **err) {
    g_return_val_if_fail(has_valid_session_proxy(proxy), -1);

    GError *callError = NULL;
    com_deepin_daemon_authenticate_session_call_end_sync(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy),
            -1,
            NULL,
            NULL,
            &callError);
    if (callError != NULL) {
        error_dup(err, callError);
        g_error_free(callError);
        return -1;
    }
    if (proxy->session_proxy != NULL) {
        g_object_unref(proxy->session_proxy);
    }
    if (proxy->session_path != NULL) {
        g_free(proxy->session_path);
    }
    return 0;
}

static int da_dbus_prop_get_string(GDBusProxy *dbus_proxy,
                                   gchar *interface,
                                   gchar *name,
                                   gchar **value) {
    if (dbus_proxy == NULL || interface == NULL || name == NULL || value == NULL) {
        return -1;
    }
    GError *callError = NULL;
    GVariant *ret1 = g_dbus_proxy_call_sync(dbus_proxy,
                                            "org.freedesktop.DBus.Properties.Get",
                                            g_variant_new("(ss)", interface, name),
                                            G_DBUS_CALL_FLAGS_NONE,
                                            -1,
                                            NULL,
                                            &callError);
    if (callError != NULL) {
        ;
        g_error_free(callError);
        return -1;
    }
    GVariant *ret2 = NULL;
    g_variant_get(ret1, "(v)", &ret2);
    g_variant_get(ret2, "s", value);
    g_variant_unref(ret1);
    g_variant_unref(ret2);
    return 0;
}

static int da_dbus_prop_get_gvariant(GDBusProxy *dbus_proxy,
                                     gchar *interface,
                                     gchar *name,
                                     GVariant **value) {
    if (dbus_proxy == NULL || interface == NULL || name == NULL || value == NULL) {
        return -1;
    }
    GError *callError = NULL;
    GVariant *ret1 = g_dbus_proxy_call_sync(dbus_proxy,
                                            "org.freedesktop.DBus.Properties.Get",
                                            g_variant_new("(ss)", interface, name),
                                            G_DBUS_CALL_FLAGS_NONE,
                                            -1,
                                            NULL,
                                            &callError);
    if (callError != NULL) {
        ;
        g_error_free(callError);
        return -1;
    }
    g_variant_get(ret1, "(v)", value);
    g_variant_unref(ret1);
    return 0;
}

static int da_dbus_prop_get_int(GDBusProxy *dbus_proxy,
                                gchar *interface,
                                gchar *name,
                                gint *value) {
    if (dbus_proxy == NULL || interface == NULL || name == NULL || value == NULL) {
        return -1;
    }
    GError *callError = NULL;
    GVariant *ret1 = g_dbus_proxy_call_sync(dbus_proxy,
                                            "org.freedesktop.DBus.Properties.Get",
                                            g_variant_new("(ss)", interface, name),
                                            G_DBUS_CALL_FLAGS_NONE,
                                            -1,
                                            NULL,
                                            &callError);
    if (callError != NULL) {
        g_error_free(callError);
        return -1;
    }
    GVariant *ret2 = NULL;
    g_variant_get(ret1, "(v)", &ret2);
    g_variant_get(ret2, "i", value);
    g_variant_unref(ret1);
    g_variant_unref(ret2);
    return 0;
}

static int da_dbus_prop_get_bool(GDBusProxy *dbus_proxy,
                                 gchar *interface,
                                 gchar *name,
                                 gboolean *value) {
    if (dbus_proxy == NULL || interface == NULL || name == NULL || value == NULL) {
        return -1;
    }
    GError *callError = NULL;
    GVariant *ret1 = g_dbus_proxy_call_sync(dbus_proxy,
                                            "org.freedesktop.DBus.Properties.Get",
                                            g_variant_new("(ss)", interface, name),
                                            G_DBUS_CALL_FLAGS_NONE,
                                            -1,
                                            NULL,
                                            &callError);
    if (callError != NULL) {
        g_error_free(callError);
        return -1;
    }
    GVariant *ret2 = NULL;
    g_variant_get(ret1, "(v)", &ret2);
    g_variant_get(ret2, "b", value);
    g_variant_unref(ret1);
    g_variant_unref(ret2);
    return 0;
}

int da_get_limits(da_proxy *proxy,
                  const char *username,
                  da_limit_info **limits,
                  int *limit_len,
                  da_error **err) {
    g_return_val_if_fail(has_valid_authenticate_proxy(proxy), -1);

    GError *callError = NULL;
    gchar *out_limits = NULL;
    com_deepin_daemon_authenticate_call_get_limits_sync(
            (ComDeepinDaemonAuthenticate *)(proxy->authenticate_proxy),
            username,
            &out_limits,
            NULL,
            &callError);
    if (callError != NULL) {
        error_dup(err, callError);
        g_error_free(callError);
        return -1;
    }
    if (out_limits == NULL) {
        error_new(err, "call GetLimit failed.");
        return -1;
    }

    gint ret = limit_json_deal(out_limits, limits, limit_len);
    g_free(out_limits);
    return ret;
}

int da_pre_one_key_login(da_proxy *proxy, int flag, char *result, int result_len, da_error **err) {
    g_return_val_if_fail(has_valid_authenticate_proxy(proxy), -1);
    if (result == NULL || result_len <= 0) {
        error_new(err, "parameter error.");
        return -1;
    }
    GError *callError = NULL;
    gchar *out_result;
    com_deepin_daemon_authenticate_call_pre_one_key_login_sync(
            (ComDeepinDaemonAuthenticate *)(proxy->authenticate_proxy),
            flag,
            &out_result,
            NULL,
            &callError);
    if (callError != NULL) {
        error_dup(err, callError);
        g_error_free(callError);
        return -1;
    }
    if (out_result == NULL) {
        error_new(err, "call pre_one_key_login failed.");
        return -1;
    }
    g_strlcpy(result, out_result, result_len);
    g_free(out_result);
    return 0;
}

static int da_auth_dbus_prop_get_string(GDBusProxy *dbus_proxy, gchar *name, gchar **value) {
    return da_dbus_prop_get_string(dbus_proxy, "com.deepin.daemon.Authenticate", name, value);
}
static int da_auth_dbus_prop_get_int(GDBusProxy *dbus_proxy, gchar *name, gint *value) {
    return da_dbus_prop_get_int(dbus_proxy, "com.deepin.daemon.Authenticate", name, value);
}

int da_prop_get_support_encrypts(da_proxy *proxy, char *result, int result_len) {
    g_return_val_if_fail(has_valid_authenticate_proxy(proxy), -1);
    if (result == NULL || result_len <= 0) {
        return -1;
    }

#ifdef DBUS_PROPERTY_CACHE
    const gchar *value = com_deepin_daemon_authenticate_get_support_encrypts(
            (ComDeepinDaemonAuthenticate *)(proxy->authenticate_proxy));
    g_strlcpy(result, value, result_len);
#else
    gchar *value = NULL;
    if (da_auth_dbus_prop_get_string(proxy->authenticate_proxy, "SupportEncrypts", &value)) {
        return -1;
    }
    g_strlcpy(result, value, result_len);
    g_free(value);
#endif
    return 0;
}

int da_prop_get_framework_state(da_proxy *proxy, int *result) {
    g_return_val_if_fail(has_valid_authenticate_proxy(proxy), -1);
    if (result == NULL) {
        return -1;
    }
    gint value = 0;
#ifdef DBUS_PROPERTY_CACHE
    value = com_deepin_daemon_authenticate_get_framework_state(
            (ComDeepinDaemonAuthenticate *)(proxy->authenticate_proxy));
#else
    if (da_auth_dbus_prop_get_int(proxy->authenticate_proxy, "FrameworkState", &value)) {
        return -1;
    }
#endif
    *result = value;
    return 0;
}

int da_prop_get_supported_flags(da_proxy *proxy, int *result) {
    g_return_val_if_fail(has_valid_authenticate_proxy(proxy), -1);
    if (result == NULL) {
        return -1;
    }
    gint value = 0;
#ifdef DBUS_PROPERTY_CACHE
    gint value = com_deepin_daemon_authenticate_get_supported_flags(
            (ComDeepinDaemonAuthenticate *)(proxy->authenticate_proxy));
#else
    if (da_auth_dbus_prop_get_int(proxy->authenticate_proxy, "SupportedFlags", &value)) {
        return -1;
    }
#endif
    *result = value;
    return 0;
}

int da_signal_connect_limit_updated(da_proxy *proxy, signal_limit_updated_cb cb, void *userdata) {
    if (proxy == NULL || cb == NULL) {
        return -1;
    }
    proxy->sig_limit_update_cb = cb;
    proxy->limit_cb_userdata = userdata;
    return 0;
}

int da_session_set_token(da_proxy *proxy,
                         const int auth_type,
                         const char *password,
                         da_error **err) {
    g_return_val_if_fail(has_valid_session_proxy(proxy), -1);
    if (password == NULL) {
        error_new(err, "parameter error.");
        return -1;
    }
    GError *callError = NULL;

    gchar *encrypt_password;
    int encrypt_password_len;

    aes_cbc_encrypt(password,
                    strlen(password),
                    proxy->symmetricKey,
                    strlen(proxy->symmetricKey),
                    &encrypt_password,
                    &encrypt_password_len);
    GBytes *bytes = g_bytes_new(encrypt_password, encrypt_password_len);

    GVariant *enc_token_variant = g_variant_new_from_bytes(G_VARIANT_TYPE_BYTESTRING, bytes, TRUE);

    com_deepin_daemon_authenticate_session_call_set_token_sync(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy),
            auth_type,
            enc_token_variant,
            NULL,
            &callError);
    free(encrypt_password);

    if (callError != NULL) {
        error_dup(err, callError);
        g_error_free(callError);
        return -1;
    }
    return 0;
}

int da_session_end(da_proxy *proxy, int flag, int *out_failNum, da_error **err) {
    g_return_val_if_fail(has_valid_session_proxy(proxy), -1);
    if (out_failNum == NULL) {
        error_new(err, "parameter error.");
        return -1;
    }
    GError *callError = NULL;
    com_deepin_daemon_authenticate_session_call_end_sync(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy),
            flag,
            out_failNum,
            NULL,
            &callError);
    if (callError != NULL) {
        error_dup(err, callError);
        g_error_free(callError);
        return -1;
    }
    return 0;
}

int da_session_get_result(da_proxy *proxy, int *result, da_error **err) {
    g_return_val_if_fail(has_valid_session_proxy(proxy), -1);
    if (result == NULL) {
        error_new(err, "parameter error.");
        return -1;
    }
    GError *callError = NULL;
    com_deepin_daemon_authenticate_session_call_get_result_sync(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy),
            result,
            NULL,
            &callError);
    if (callError != NULL) {
        error_dup(err, callError);
        g_error_free(callError);
        return -1;
    }
    return 0;
}

int da_session_privileges_disable(da_proxy *proxy, da_error **err) {
    g_return_val_if_fail(has_valid_session_proxy(proxy), -1);

    GError *callError = NULL;
    com_deepin_daemon_authenticate_session_call_privileges_disable_sync(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy),
            NULL,
            &callError);
    if (callError != NULL) {
        error_dup(err, callError);
        g_error_free(callError);
        return -1;
    }
    return 0;
}

int da_session_privileges_enable(da_proxy *proxy,
                                 const char *master_path,
                                 bool *enabled,
                                 da_error **err) {
    g_return_val_if_fail(has_valid_session_proxy(proxy), -1);
    if (enabled == NULL || master_path == NULL) {
        error_new(err, "parameter error.");
        return -1;
    }
    GError *callError = NULL;
    com_deepin_daemon_authenticate_session_call_privileges_enable_sync(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy),
            master_path,
            (gboolean *)enabled,
            NULL,
            &callError);
    if (callError != NULL) {
        error_dup(err, callError);
        g_error_free(callError);
        return -1;
    }
    return 0;
}

int da_session_set_quit_flag(da_proxy *proxy, int method, da_error **err) {
    g_return_val_if_fail(has_valid_session_proxy(proxy), -1);

    GError *callError = NULL;
    com_deepin_daemon_authenticate_session_call_set_quit_flag_sync(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy),
            method,
            NULL,
            &callError);
    if (callError != NULL) {
        error_dup(err, callError);
        g_error_free(callError);
        return -1;
    }
    return 0;
}

int da_session_start(da_proxy *proxy, int flag, int timeout, int *failNum, da_error **err) {
    g_return_val_if_fail(has_valid_session_proxy(proxy), -1);
    if (failNum == NULL) {
        error_new(err, "parameter error.");
        return -1;
    }
    GError *callError = NULL;
    com_deepin_daemon_authenticate_session_call_start_sync(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy),
            flag,
            timeout,
            failNum,
            NULL,
            &callError);
    if (callError != NULL) {
        error_dup(err, callError);
        g_error_free(callError);
        return -1;
    }
    return 0;
}

static int da_session_dbus_prop_get_string(GDBusProxy *dbus_proxy, gchar *name, gchar **value) {
    return da_dbus_prop_get_string(dbus_proxy, "com.deepin.daemon.Authenticate.Session", name, value);
}
static int da_session_dbus_prop_get_int(GDBusProxy *dbus_proxy, gchar *name, gint *value) {
    return da_dbus_prop_get_int(dbus_proxy, "com.deepin.daemon.Authenticate.Session", name, value);
}
static int da_session_dbus_prop_get_bool(GDBusProxy *dbus_proxy, gchar *name, gboolean *value) {
    return da_dbus_prop_get_bool(dbus_proxy, "com.deepin.daemon.Authenticate.Session", name, value);
}
static int da_session_dbus_prop_get_gvariant(GDBusProxy *dbus_proxy,
                                             gchar *name,
                                             GVariant **value) {
    return da_dbus_prop_get_gvariant(dbus_proxy, "com.deepin.daemon.Authenticate.Session", name, value);
}

int da_prop_get_is_MFA(da_proxy *proxy, bool *result) {
    g_return_val_if_fail(has_valid_session_proxy(proxy), -1);
    if (result == NULL) {
        return -1;
    }
    gboolean value = FALSE;
#ifdef DBUS_PROPERTY_CACHE
    value = com_deepin_daemon_authenticate_session_get_is_mfa(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy));
#else
    if (da_session_dbus_prop_get_bool(proxy->session_proxy, "IsMFA", &value)) {
        return -1;
    }
#endif
    *result = value;
    return 0;
}
int da_prop_get_prompt(da_proxy *proxy, char *result, int result_len) {
    g_return_val_if_fail(has_valid_session_proxy(proxy), -1);
    if (result == NULL || result_len <= 0) {
        return -1;
    }
#ifdef DBUS_PROPERTY_CACHE
    const gchar *ret = com_deepin_daemon_authenticate_session_get_prompt(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy));
    g_strlcpy(result, ret, result_len);
#else
    gchar *value = NULL;
    if (da_session_dbus_prop_get_string(proxy->session_proxy, "Prompt", &value)) {
        return -1;
    }
    g_strlcpy(result, value, result_len);
    g_free(value);
#endif
    return 0;
}
int da_prop_get_factors_info(da_proxy *proxy, da_factor_info **result, int *factor_info_len) {
    g_return_val_if_fail(has_valid_session_proxy(proxy), -1);
    if (result == NULL) {
        return -1;
    }
    GVariant *value = NULL;
#ifdef DBUS_PROPERTY_CACHE
    value = com_deepin_daemon_authenticate_session_dup_factors_info(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy));
#else
    if (da_session_dbus_prop_get_gvariant(proxy->session_proxy, "FactorsInfo", &value)) {
        return -1;
    }
#endif
    GVariantIter *iter = NULL;
    g_variant_get(value, "a(iiib)", &iter);
    g_variant_unref(value);
    if (iter == NULL) {
        return -1;
    }
    gsize num = g_variant_iter_n_children(iter);

    if (num <= 0) {
        return -1;
    }

    gint curIndex = 0;
    *result = (da_factor_info *)malloc(sizeof(da_factor_info) * num);
    *factor_info_len = num;

    while (g_variant_iter_next(iter,
                               "(iiib)",
                               &((*result)[curIndex].auth_type),
                               &((*result)[curIndex].priority),
                               &((*result)[curIndex].input_type),
                               &((*result)[curIndex].required))) {
        curIndex++;
    }
    g_variant_iter_free(iter);
    return 0;
}

int da_prop_get_username(da_proxy *proxy, char *result, int result_len) {
    g_return_val_if_fail(has_valid_session_proxy(proxy), -1);
    if (result == NULL || result_len <= 0) {
        return -1;
    }
#ifdef DBUS_PROPERTY_CACHE
    const gchar *ret = com_deepin_daemon_authenticate_session_get_username(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy));
    g_strlcpy(result, ret, result_len);
#else
    gchar *value = NULL;
    if (da_session_dbus_prop_get_string(proxy->session_proxy, "Username", &value)) {
        return -1;
    }
    g_strlcpy(result, value, result_len);
    g_free(value);
#endif
    return 0;
}
int da_prop_get_PIN_len(da_proxy *proxy, int *result) {
    g_return_val_if_fail(has_valid_session_proxy(proxy), -1);
    if (result == NULL) {
        return -1;
    }
    gint value = 0;
#ifdef DBUS_PROPERTY_CACHE
    value = com_deepin_daemon_authenticate_session_get_pinlen(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy));
#else
    if (da_session_dbus_prop_get_int(proxy->session_proxy, "PINLen", &value)) {
        return -1;
    }
#endif
    *result = value;
    return 0;
}
int da_prop_get_prg_path(da_proxy *proxy, char *result, int result_len) {
    g_return_val_if_fail(has_valid_session_proxy(proxy), -1);
    if (result == NULL || result_len <= 0) {
        return -1;
    }
#ifdef DBUS_PROPERTY_CACHE
    const gchar *ret = com_deepin_daemon_authenticate_session_get_prg_path(
            (ComDeepinDaemonAuthenticateSession *)(proxy->session_proxy));
    g_strlcpy(result, ret, result_len);
#else
    gchar *value = NULL;
    if (da_session_dbus_prop_get_string(proxy->session_proxy, "PrgPath", &value)) {
        return -1;
    }
    g_strlcpy(result, value, result_len);
    g_free(value);
#endif
    return 0;
}

int da_session_signal_connect_status(da_proxy *proxy, signal_status_cb cb, void *userdata) {
    if (cb == NULL || proxy == NULL) {
        return -1;
    }
    proxy->sig_status_cb = cb;
    proxy->signal_cb_userdata = userdata;
    return 0;
}

void da_error_free(da_error *err) {
    if (err) {
        if (err->msg) {
            g_free(err->msg);
        }
        free(err);
    }
}

void da_dbus_proxy_free(da_proxy *proxy) {
    if (!proxy) return;

    if (proxy->username) {
        g_free(proxy->username);
    }

    if (proxy->authenticate_proxy) g_object_unref(proxy->authenticate_proxy);

    if (proxy->session_proxy) g_object_unref(proxy->session_proxy);

    if (proxy->session_path) g_free(proxy->session_path);

    if (proxy->pubkey) {
        g_free(proxy->pubkey);
    }

    if (proxy->enc_method) {
        g_variant_unref(proxy->enc_method);
    }

    if (proxy->symmetricKey) {
        g_free(proxy->symmetricKey);
    }

    pub_key_free(proxy->key);

    free(proxy);

    proxy = NULL;
}