#ifndef _COMMON_H_
#define _COMMON_H_

#include "debug.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <locale.h>
#include <pthread.h>
#include <pwd.h>
#include <security/_pam_types.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <systemd/sd-bus.h>
#include <termios.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#define PKCS1_HEADER "-----BEGIN RSA PUBLIC KEY-----"
#define PKCS8_HEADER "-----BEGIN PUBLIC KEY-----"

#define MAX_BUF_SIZE 256
#define LIMITS_BUF_SIZE 1024

#define UNUSED_VALUE(a) ((void)(a))

#define AUTH_FLAG_MIN (AT_Password)
#define AUTH_FLAG_MAX                                                          \
    (AT_Password | AT_Fingerprint | AT_Face | AT_ActiveDirectory)
#define AUTH_FLAG_USING (AT_Password | AT_Fingerprint)

#define APP_TYPE_LOGIN ("login")
#define APP_TYPE_LOCK ("lock")
#define APP_TYPE_AUTHORIZATION ("authorization")
#define APP_TYPE_OTHER ("other")

#define APP_VAL_LOGIN (1)
#define APP_VAL_LOCK (2)
#define APP_VAL_AUTHORIZATION (3)
#define APP_VAL_OTHER (4)
#define APP_VAL_UNKNOWN (-1)

#define GET_RESULT_SUCCESS (0)
#define GET_RESULT_FAIL (1)
#define GET_RESULT_UNAVAILABLE (2)

#define EXPIRED_STATUS_NORMAL (0)
#define EXPIRED_STATUS_EXPIRED_SOON (1)
#define EXPIRED_STATUS_EXPIRED_ALREADY (2)

#define APP_TYPE_LIST_FILE_PATH                                                \
    ("/usr/share/deepin-authentication/app-type-list")
#define D_DEBUG(pamh, text, ...)                                               \
    if (get_debug_flag()) {                                                    \
        pam_syslog(pamh, LOG_DEBUG, text, ##__VA_ARGS__);                      \
    }

enum AuthenticateType {
    AT_Password = 0x0001,         // 密码
    AT_Fingerprint = 0x0002,      // 指纹
    AT_Face = 0x0004,             // 人脸
    AT_ActiveDirectory = 0x00008, // 活动目录
    AT_Ukey = 0x00010,            // Ukey
    AT_FingerVein=0x00020,        //指静脉
    AT_Iris = 0x00040,            // Iris
};

#define SUPPORT_AT_TYPE (7)

enum AuthStutaCode {
    ASC_Success = 0, // 认证成功
    ASC_Failure,     // 认证失败
    ASC_Cancel,      // 认证取消
    ASC_Timeout,     // 认证超时
    ASC_Error,       // 认证错误
    ASC_Verify,
    ASC_Expect,
    ASC_Prompt,
    ASC_Started,
    ASC_Ended
};

enum VarifyCode {
    VC_Match = 0,  // 认证成功
    VC_NoMatch,    // 认证失败
    VC_Error,      // 认证取消
    VC_Retry,      // 重试
    VC_Disconnect, // 失去连接
};

enum InputType {
    IT_Keyboard = 1,   //键盘输入
    IT_Fingerprint = 2 //指纹设备
};
enum AlgType { AT_RSA };

struct AuthFactor {
    int authType;
    int priority;
    int inputType;
    int required;
};

struct AuthSession {
    int flags;
    int isMFA;
    char msg[MAX_BUF_SIZE];
    int factorSize;
    int *factorOrder;
    struct AuthFactor *factors;
};

struct Limit {
    int maxTries;
    int numFailures;
    bool locked;
    char unlockTime[MAX_BUF_SIZE];
};

struct _tagPubkey {
    int algType;
    int *flags;
    char *pubkey;
    RSA *rsa;
};
typedef struct _tagPubkey Pubkey;

struct UserData {
    pam_handle_t *pamh;
    sd_bus *bus;
    struct termios *term;
    char path[MAX_BUF_SIZE];
    char username[MAX_BUF_SIZE];
    char prompt[MAX_BUF_SIZE];
    char *auth_tok;
    pthread_t pid; //当前开启的token获取线程pid
    int cur_type; //当前开启的类型,如果是多因子,则为对应的认证类型,如果为单因子模糊认证,则为-1(所有需要token的认证方式共用)
    bool need_cancel;
    struct Limit limits[SUPPORT_AT_TYPE];
    int failed_indexs[SUPPORT_AT_TYPE];
    int failed_num;
    struct AuthSession *auth_ctrl;
    int res;
    bool debug;
    int waiting_result;
    int get_result_val;
    Pubkey *key;
    char *symmetric_key;
};

typedef struct pam_response *(*pam_conv_send_msg)(struct UserData *ud,
                                                  const char *msg, int style);

void *dalloc(size_t size);
void cleanup_data(pam_handle_t *pamh, void *data, int pam_end_status);
struct passwd *get_pwd(pam_handle_t *pamh);
#endif
