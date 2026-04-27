#ifndef _DBUS_H_
#define _DBUS_H_

#include "common.h"

#define DBUS_SERVICE "com.deepin.daemon.Authenticate"
#define DBUS_PATH "/com/deepin/daemon/Authenticate"
#define DBUS_INTERFACE "com.deepin.daemon.Authenticate"
#define DBUS_AUTHCTRL_INTERFACE "com.deepin.daemon.Authenticate.Session"
#define FINGER_DBUS_PATH "/com/deepin/daemon/Authenticate/Fingerprint"
#define FINGER_DBUS_INTERFACE "com.deepin.daemon.Authenticate.Fingerprint"

#define AUTH_SIGNAL_STATUS "Status"
#define FINGER_SIGNAL_VERIFYSTATUS "VerifyStatus"

int dbus_method_authenticate(struct UserData *ud,
                             const char *username,
                             int flags,
                             int app_type,
                             char *path);
int dbus_method_get_limits(struct UserData *ud, const char *username, char *limits);
int dbus_method_end(struct UserData *ud, const char *path, int flag);
int dbus_method_setToken(struct UserData *ud,
                         const char *path,
                         const int auth_type,
                         const char *password);
int dbus_method_start(struct UserData *ud, const char *path, int flags, int timeout);
int dbus_method_preOneKeyLogin(struct UserData *ud, const char *username, char *id);
int dbus_method_getResult(struct UserData *ud, const char *path, int *res);
int dbus_method_encryptKey(pam_handle_t *pamh,
                           sd_bus *bus,
                           const char *path,
                           int algType,
                           size_t flagSize,
                           unsigned char *flags,
                           struct UserData *ud);

int listen_dbus_signal(struct UserData *userData, sd_bus_message_handler_t cb);

int dbus_get_prop_int(struct UserData *ud,
                      const char *service,
                      const char *path,
                      const char *interface,
                      const char *prop_name,
                      int *prop_val);

int dbus_get_user_passwd_expired_info(struct UserData *ud,
                                      const char *username,
                                      int *expired_status,
                                      int64_t *left_days);

int dbus_method_set_symmetric_key(struct UserData *ud,
                                  const char *path,
                                  char *symmetric_key,
                                  int cipher_len);

#endif
