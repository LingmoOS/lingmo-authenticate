#include "common.h"
#include "dbus.h"
#include "limit.h"
#include "type.h"
#include "sfa.h"
#include "mfa.h"
#include "utils.h"
#include <unistd.h>

#define PAM_ALLOW_LIST "/usr/share/deepin-authentication/allowlist"

static char *const TIMEOUT_FLAG = "timeout";
static char *const USER_LOCALE_FLAG = "user_locale";
static char *const DEBUG_FLAG = "debug";

static void clean_auth_data(struct UserData *ud) {
    if (ud->bus) {
        if (strlen(ud->path)) {
            D_DEBUG(ud->pamh, "close authenticate bus!");
            dbus_method_end(ud, ud->path, -1);
        }
        sd_bus_flush_close_unref(ud->bus);
        ud->bus = NULL;
    }

    if (ud->pid) {
        D_DEBUG(ud->pamh, "kill child thread:%ld!", ud->pid);
        int ret = pthread_cancel(ud->pid);
        if (ESRCH != ret) {
            if (ret) {
                pam_syslog(ud->pamh, LOG_ERR, "kill child thread error with: %s", strerror(ret));
            } else {
                ret = pthread_join(ud->pid, NULL);
                if (ret && ESRCH != ret) {
                    pam_syslog(ud->pamh,
                               LOG_ERR,
                               "join child thread error with: %s",
                               strerror(ret));
                }
            }
        } // else 线程不存在，说明已经退出了
        ud->pid = 0;
    }

    if (ud->auth_ctrl) {
        if (ud->auth_ctrl->factorOrder) {
            free(ud->auth_ctrl->factorOrder);
            ud->auth_ctrl->factorOrder = NULL;
        }
        if (ud->auth_ctrl->factors) {
            free(ud->auth_ctrl->factors);
            ud->auth_ctrl->factors = NULL;
        }
        free(ud->auth_ctrl);
        ud->auth_ctrl = NULL;
    }

    if (ud->term != NULL) {
        tcsetattr(STDIN_FILENO, TCSADRAIN, ud->term);
        free(ud->term);
        ud->term = NULL;
    }

    if (ud->symmetric_key) {
        free(ud->symmetric_key);
        ud->symmetric_key = NULL;
    }
}

static void pam_clean_func(pam_handle_t *pamh, void *userData, int error_status) {
    struct UserData *ud = userData;
    D_DEBUG(pamh, "cleanup userdata");
    if (error_status & PAM_DATA_REPLACE) {
        D_DEBUG(pamh, "cleanup userdata due to replacing");
    }

    clean_auth_data(ud);

    if (ud->auth_tok != NULL) {
        free(ud->auth_tok);
        ud->auth_tok = NULL;
    }

    D_DEBUG(pamh, "free data!");
    free(ud);
}

static void thread_cleanup(void *user_data) {
    struct UserData *ud = user_data;
    pam_clean_func(ud->pamh, ud, 0);
}

static struct pam_response *send_msg(struct UserData *ud, const char *msg, int style) {
    pam_syslog(ud->pamh, LOG_INFO, "%s", msg);
    const struct pam_message pmsg = {
            .msg = msg,
            .msg_style = style,
    };
    const struct pam_message *pmsg_ptr = &pmsg;
    const struct pam_conv *pconv = NULL;
    struct pam_response *presp = NULL;
    do {
        int ret = 0;
        ret = pam_get_item(ud->pamh, PAM_CONV, (const void **)&pconv);
        if (ret != PAM_SUCCESS) {
            pam_syslog(ud->pamh, LOG_ERR, "pam module get conv item error: %s!", strerror(-ret));
            break;
        }
        if (!pconv || !pconv->conv) {
            pam_syslog(ud->pamh, LOG_ERR, "pam module pconv or pconv->conv is nullptr, error!");
            break;
        }
        ret = pconv->conv(1, &pmsg_ptr, &presp, pconv->appdata_ptr);
        if (ret != PAM_SUCCESS) {
            pam_syslog(ud->pamh,
                       LOG_ERR,
                       "in style %d Cannot get pam module conv : %s!",
                       style,
                       strerror(-ret));
            if (style == PAM_PROMPT_ECHO_OFF || style == PAM_PROMPT_ECHO_ON) {
                ud->res = ud->res == -1 ? PAM_ABORT : ud->res;
            }
            break;
        }
    } while (0);
    return presp;
}

int split_data(char *resp, char **path, char **tok) {
    int ret = 0;

    char *p = strchr(resp, ';');
    do {
        if (p == NULL) {
            ret = -1;
            break;
        } else {
            *path = (char *)malloc(p - resp + 1);
            strncpy(*path, resp, p - resp);
            (*path)[p - resp] = '\0';
            if (strlen(p) > 1) {
                *tok = (char *)malloc(strlen(p));
                strcpy(*tok, p + 1);
                (*tok)[strlen(*tok)] = '\0';
            }
        }
    } while (0);
    return ret;
}

static void *run_request_pw(void *user_data) {
    struct pam_response *rep = NULL;
    struct UserData *ud = user_data;

    D_DEBUG(ud->pamh, "[DEBUG] pam-module start get pass word thread: %ld", pthread_self());

    rep = send_msg(ud, ud->prompt, PAM_PROMPT_ECHO_OFF);
    if (rep) {
        int res = -1;
        char *path = NULL;
        char *tok = NULL;
        if (split_data(rep->resp, &path, &tok) == 0) {
            bool success = false;
            D_DEBUG(ud->pamh, "get path: %s, tok: %s", path, tok);

            dbus_method_getResult(ud, path, &res);

            while (ud->waiting_result) {
                usleep(100);
            }
            if (ud->get_result_val == GET_RESULT_SUCCESS) {
                if (tok) {
                    ud->auth_tok = (char *)malloc(strlen(tok) + 1);
                    strcpy(ud->auth_tok, tok);
                    D_DEBUG(ud->pamh, "set token");
                    pam_set_item(ud->pamh, PAM_AUTHTOK, ud->auth_tok);
                }

                ud->res = PAM_SUCCESS;
                success = true;
            }

            if (path != NULL) {
                free(path);
            }
            if (tok != NULL) {
                free(tok);
            }
            if (success) {
                free(rep);
                return NULL;
            }
        }

        if (!dbus_method_setToken(ud, ud->path, ud->cur_type, rep->resp)) {
            ud->res = PAM_ABORT;
        }

        ud->auth_tok = rep->resp;
        rep->resp = NULL;
        free(rep);
        rep = NULL;
    }

    return NULL;
}

static int bus_signal_cb(sd_bus_message *m, void *user_data, sd_bus_error *ret_error) {
    UNUSED_VALUE(ret_error);
    char *signalmsg = NULL;
    int authType = -1;
    int code = -1;
    struct UserData *ud = user_data;
    char path[MAX_BUF_SIZE] = {0};

    do {
        int ret = 0;
        strcpy(path, sd_bus_message_get_path(m));
        D_DEBUG(ud->pamh, "[DEBUG] signal_cb func be called, auth path: %s", path);
        ret = sd_bus_message_read(m, "iis", &authType, &code, &signalmsg);
        if (ret < 0) {
            D_DEBUG(ud->pamh, "[DEBUG] signal callback error :%s", strerror(errno));
            break;
        }

        D_DEBUG(ud->pamh,
                "[DEBUG] get signal data, auth path:%s, authType: %d, status code: "
                "%d, signal msg: "
                "%s",
                path,
                authType,
                code,
                signalmsg);

        if (ud->auth_ctrl->isMFA) {
            ud->res = mfa_signal_deal(ud, code, authType, signalmsg, send_msg, run_request_pw);
        } else {
            ud->res = sfa_signal_deal(ud, code, authType, signalmsg, send_msg, run_request_pw);
        }
        if (ud->res == PAM_SUCCESS && ud->auth_tok != NULL) {
            pam_set_item(ud->pamh, PAM_AUTHTOK, ud->auth_tok);
        }
    } while (0);

    return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    UNUSED_VALUE(flags);
    const char *username = NULL;
    sd_bus *bus = NULL;
    int ret = 0;
    int authflag = AUTH_FLAG_USING;
    int timeout = 60000;
    char buff[MAX_BUF_SIZE] = {0};
    char user_locale[MAX_BUF_SIZE] = {0};
    int app_type = 0;
    char app_path[MAX_BUF_SIZE];

    for (int idx = 0; idx < argc; ++idx) {
        const char *splitch = strchr(argv[idx], '=');

        strncpy(buff, argv[idx], MAX_BUF_SIZE - 1);
        if (splitch != NULL) {
            buff[((size_t)(splitch - argv[idx])) / sizeof(char)] = '\0';

            if (!strcmp(buff, TIMEOUT_FLAG)) {
                timeout = atoi(splitch + 1);
                continue;
            }

            if (!strcmp(buff, USER_LOCALE_FLAG)) {
                strncpy(user_locale, splitch + 1, MAX_BUF_SIZE - 1);
                continue;
            }
        }

        if (!strcmp(buff, DEBUG_FLAG)) {
            set_debug_flag(true);
        }
    }

    struct UserData *ud = (struct UserData *)malloc(sizeof(struct UserData));
    memset(ud, 0, sizeof(struct UserData));
    ud->pamh = pamh;
    ud->bus = NULL;
    ud->term = NULL;
    ud->pid = 0;
    ud->need_cancel = false;
    ud->auth_tok = NULL;
    ud->res = -1;
    ud->debug = get_debug_flag();
    ud->waiting_result = 0;

    memset(ud->limits, 0, sizeof(struct Limit) * SUPPORT_AT_TYPE);
    pam_set_data(pamh, "deepin-authenticate-user-data", ud, pam_clean_func);
    pthread_cleanup_push(thread_cleanup, ud);
    D_DEBUG(pamh, "new auth");
    ssize_t nbytes = readlink("/proc/self/exe", buff, MAX_BUF_SIZE);
    if (nbytes == -1) {
        pam_syslog(pamh, LOG_ERR, "failed to readlink of /proc/self/exe");
        return PAM_IGNORE;
    }
    D_DEBUG(pamh, "exe path: %s", buff);
    strcpy(app_path, buff);

    FILE *fp = fopen(PAM_ALLOW_LIST, "r");
    if (fp == NULL) {
        pam_syslog(pamh, LOG_ERR, "failed to open allowlist");
        return PAM_IGNORE;
    }
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    bool found = false;
    while ((read = getline(&line, &len, fp)) != -1) {
        if (line[read - 1] == '\n') {
            line[read - 1] = '\0';
        }
        if (strcmp(line, buff) == 0) {
            found = true;
            break;
        }
    }
    fclose(fp);
    if (line) {
        free(line);
        line = NULL;
    }
    if (!found) {
        D_DEBUG(pamh, "this program is not in allow list");
        return PAM_IGNORE;
    }

    if (isatty(fileno(stdin))) {
        D_DEBUG(ud->pamh, "%s is a tty, ttyname -> %s", buff, ttyname(fileno(stdin)));
        ud->term = malloc(sizeof(struct termios));
        ret = tcgetattr(STDIN_FILENO, ud->term);
        if (ret == -1) {
            pam_syslog(pamh, LOG_NOTICE, "cannot get original tty attributes: %s", strerror(errno));
            free(ud->term);
            ud->term = NULL;
        }
    }

    pam_get_user(pamh, &username, "Username: ");
    D_DEBUG(pamh, "[DEBUG] start auth with username:---%s---", username);
    sprintf(ud->username, "%s", username);
    if (user_locale[0] != '\0') {
        load_user_locale(pamh, ud, username, user_locale);
    }
    setlocale(LC_ALL, "");
    textdomain("deepin-authentication");

    char *app_type_string = load_app_type(ud, app_path);
    app_type = get_app_type(app_type_string);
    if (app_type_string) {
        free(app_type_string);
    }

    do {
        ret = sd_bus_open_system(&bus);
        if (ret < 0) {
            pam_syslog(pamh, LOG_ERR, "Failed to connect to system bus: %s", strerror(-ret));
            break;
        }

        ud->bus = bus;

        // 尝试一键登录，不处理失败，失败后走正常的验证逻辑
        dbus_method_preOneKeyLogin(ud, username, buff);

        // 一键登录没有返回信息，说明失败或该账户没有指纹，使用正常的验证逻辑
        if (strlen(buff) == 0) {
            int supprted_flags = authflag;
            int expired_status = 0;
            int64_t left_days = 0;
            if (app_type == APP_VAL_LOGIN &&
                dbus_get_user_passwd_expired_info(ud, username, &expired_status, &left_days) >= 0) {
                D_DEBUG(ud->pamh,
                        "expirted status: %d, left days: %d",
                        expired_status,
                        (int)left_days);

                if (expired_status == EXPIRED_STATUS_EXPIRED_SOON) {
                    sprintf(buff,
                            gettext("Your password will expire in %d days, please change it "
                                    "timely"),
                            (int)left_days);
                    send_msg(ud, buff, PAM_TEXT_INFO);
                }
            }

            dbus_get_prop_int(ud,
                              DBUS_SERVICE,
                              DBUS_PATH,
                              DBUS_INTERFACE,
                              "SupportedFlags",
                              &supprted_flags);

            if (dbus_method_authenticate(ud, username, supprted_flags, app_type, buff)) {
                ud->res = PAM_ABORT;
                break;
            }
        }

        //获取authenticate controller path
        strcpy(ud->path, buff);
        D_DEBUG(pamh, "get dbus path: %s", buff);

        //获取认证因子相关属性
        ud->auth_ctrl = (struct AuthSession *)malloc(sizeof(struct AuthSession));
        ud->auth_ctrl->factors = NULL;
        if (get_authctl_property(ud, ud->path, ud->auth_ctrl) != 0) {
            return PAM_ABORT;
        }
        ud->need_cancel = true;

        D_DEBUG(ud->pamh,
                "[DEBUG] start authenticate path: %s, username: %s!",
                ud->path,
                ud->username);

        get_limits_info(ud);

        int limit_ret = PAM_SUCCESS;
        // 如果不是多因子认证,则直接判断密码是否锁定
        int typeIndex = type_to_index(AT_Password);
        if (typeIndex >= SUPPORT_AT_TYPE) {
            pam_syslog(pamh, LOG_ERR, "index(%d) error of limit type", typeIndex);
            ud->res = PAM_ABORT;
            break;
        }
        limit_ret = get_limit_prompt(buff, &(ud->limits[typeIndex]));

        if (limit_ret != PAM_SUCCESS) {
            send_msg(ud, buff, PAM_ERROR_MSG);
            ud->res = limit_ret;
            break;
        }

        int needToken = 0;
        for (int idx = 0; idx < ud->auth_ctrl->factorSize; ++idx) {
            if (ud->auth_ctrl->factors[idx].inputType == IT_Keyboard) {
                needToken = 1;
                break;
            }
        }

        unsigned char flags = 0;
        ud->key = (Pubkey *)malloc(sizeof(Pubkey));
        memset(ud->key, 0, sizeof(Pubkey));
        if (needToken) {
            D_DEBUG(pamh, "[DEBUG] start get encrypt pubkey");
            dbus_method_encryptKey(pamh, bus, ud->path, AT_RSA, 1, &flags, ud);
        }

        //监听认证信号
        ret = listen_dbus_signal(ud, bus_signal_cb);

        if (ret < 0) {
            pam_syslog(pamh, LOG_ERR, "add match error!");
            ud->res = PAM_ABORT;
            break;
        }

        if (ud->auth_ctrl->isMFA) {
            //如果开启了多因子, 则根据多因子优先级开启第一个认证方式
            //当第一个认证方式完成, 再开启下一个认证方式直到全部完成
            // TODO: 如果多因子可并发开启, 需要修改逻辑
            D_DEBUG(ud->pamh, "start first auth factor");
            ret = mfa_start_verify(ud, 0, timeout);
        } else {
            //如果不是多因子,则认证类型为所有
            ret = sfa_start_verify(ud, -1, timeout);
        }

        if (ret != PAM_SUCCESS) {
            D_DEBUG(ud->pamh, "[DEBUG] start authenticate error!");
            ud->res = PAM_ABORT;
            break;
        }

        D_DEBUG(ud->pamh, "start dbus loop, g_res: %d", ud->res);
        while (ud->res == -1) {
            sd_bus_message *m = NULL;
            ret = sd_bus_process(bus, &m);
            if (ret < 0) {
                // TODO: dbus调用错误会导致认证直接失败
                pam_syslog(pamh, LOG_ERR, "sd_bus_process failed: %s", strerror(ret));
                ud->res = PAM_ABORT;
                break;
            }

            if (ret > 0) {
                continue;
            }

            ret = sd_bus_wait(bus, (uint64_t)100000);
            if (ret < 0) {
                pam_syslog(pamh, LOG_ERR, "sd_bus_wait failed: %s", strerror(ret));
                ud->res = PAM_ABORT;
                break;
            }
        }
    } while (0);

    // 设置认证结果
    pam_set_data(ud->pamh, "deepin_authenticate_result", strdup(ud->res == PAM_SUCCESS ? "true":"false"), cleanup_data);

    pthread_cleanup_pop(0);

    clean_auth_data(ud);

    D_DEBUG(ud->pamh, "auth result: %d", ud->res);
    return ud->res;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    UNUSED_VALUE(pamh);
    UNUSED_VALUE(flags);
    UNUSED_VALUE(argc);
    UNUSED_VALUE(argv);
    return PAM_SUCCESS;
}
