#pragma once

#include <gio/gio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

G_BEGIN_DECLS

typedef enum {
    STATUS_CODE_SUCCESS = 0,
    STATUS_CODE_FAILURE,
    STATUS_CODE_CANCEL,
    STATUS_CODE_TIMEOUT,
    STATUS_CODE_ERROR,
    STATUS_CODE_VERIFY,
    STATUS_CODE_EXCEPTION,
    STATUS_CODE_PROMPT,
    STATUS_CODE_STARTED,
    STATUS_CODE_ENDED,
    STATUS_CODE_LOCKED,
    STATUS_CODE_RECOVER,
    STATUS_CODE_UNLOCKED,
    STATUS_CODE_UNKNOWN
} DA_STATUS_CODE;

typedef enum {
    AUTH_FLAG_PASSWORD = 0x1 << 0,
    AUTH_FLAG_FINGERPRINT = 0x1 << 1,
    AUTH_FLAG_FACE = 0x1 << 2,
    AUTH_FLAG_AD = 0x1 << 3,
    AUTH_FLAG_UKEY = 0x1 << 4,
    AUTH_FLAG_FINGERVEIN = 0x1 << 5,
    AUTH_FLAG_IRIS = 0x1 << 6,
    AUTH_FLAG_ALL = -1,
} DA_AUTH_FLAG;

typedef void (*log_cb)(const char *fmt, ...);

typedef struct _da_limit_info {
    char type[64];
    bool locked;
    int max_tries;
    int fail_num;
    char unlock_time[64];
    int flag;
    int unlock_secs;
} da_limit_info;

typedef struct _da_factor_info {
    int auth_type;
    int priority;
    int input_type;
    bool required;
} da_factor_info;

typedef bool (*signal_limit_updated_cb)(void *userdata, da_limit_info *dli, int dli_num);
typedef bool (*signal_status_cb)(void *userdata,
                                 DA_AUTH_FLAG flag,
                                 DA_STATUS_CODE status,
                                 char *msg);

typedef struct _auth_proxy da_proxy;

// if it is used, it needs to be freed
typedef struct _da_error {
    int code;
    char *msg;
} da_error;

void da_error_free(da_error *err);

// init, create com.deepin.daemon.Authenticate proxy
int da_set_log_callback(da_proxy *proxy, log_cb cb);

da_proxy *da_dbus_proxy_new();

void da_dbus_proxy_free(da_proxy *proxy);

// create session, create com.deepin.daemon.Authenticate.session proxy
int da_create_authenticate(da_proxy *proxy,
                           const char *username,
                           int flags,
                           int app_type,
                           da_error **err);

int da_quit_authenticate(da_proxy *proxy, da_error **err); // session method

// com.deepin.daemon.Authenticate method
int da_get_limits(da_proxy *proxy,
                  const char *username,
                  da_limit_info **limits,
                  int *limit_len,
                  da_error **err);

int da_pre_one_key_login(da_proxy *proxy, int flag, char *result, int result_len, da_error **err);

// com.deepin.daemon.Authenticate property
int da_prop_get_framework_state(da_proxy *proxy, int *result);

int da_prop_get_supported_flags(da_proxy *proxy, int *result);

// com.deepin.daemon.Authenticate signal
int da_signal_connect_limit_updated(da_proxy *proxy, signal_limit_updated_cb cb, void *userdata);

// after da_create_authenticate, com.deepin.daemon.Authenticate.Session method
int da_session_set_token(da_proxy *proxy,
                         const int auth_type,
                         const char *password,
                         da_error **err);

int da_session_end(da_proxy *proxy, int flag, int *out_failNum, da_error **err);

int da_session_start(da_proxy *proxy, int flag, int timeout, int *failNum, da_error **err);

// com.deepin.daemon.Authenticate property
int da_prop_get_is_MFA(da_proxy *proxy, bool *result);

int da_prop_get_prompt(da_proxy *proxy, char *result, int result_len);

int da_prop_get_factors_info(da_proxy *proxy, da_factor_info **result, int *factor_info_len);

// com.deepin.daemon.Authenticate signal
int da_session_signal_connect_status(da_proxy *proxy, signal_status_cb cb, void *userdata);

bool is_valid_auth_flag(int auth_flag);

da_limit_info *da_get_auth_limit_info(da_limit_info *dli, int dli_num, DA_AUTH_FLAG auth_flag);

G_END_DECLS

#ifdef __cplusplus
}
#endif
