#include "sfa.h"
#include "dbus.h"
#include "limit.h"
#include "type.h"
#include "utils.h"

int sfa_start_verify(struct UserData *userData, int index, int timeout) {
    UNUSED_VALUE(index);
    userData->cur_type = -1;
    if (dbus_method_start(userData, userData->path, userData->cur_type, timeout)) {
        return PAM_ABORT;
    }
    return PAM_SUCCESS;
}

int sfa_signal_deal(struct UserData *ud,
                    int signalCode,
                    int authType,
                    char *signalMsg,
                    pam_conv_send_msg send_msg_cb,
                    void *(*request_pw_cb)(void *)) {
    char msg[MAX_BUF_SIZE];
    int ret = -1;
    D_DEBUG(ud->pamh,
            "in sfa_signal_deal, signalCode is %d, authType is %d, signalMsg is %s",
            signalCode,
            authType,
            signalMsg);
    do {
        switch (signalCode) {
        case ASC_Success:
            if (authType == -1) {
                ret = PAM_SUCCESS;
                ud->need_cancel = false;
                sprintf(msg, gettext("Verification successful"));
                send_msg_cb(ud, msg, PAM_TEXT_INFO);
            }
            break;
        case ASC_Failure: {
            if (authType != -1) {
                D_DEBUG(ud->pamh, "failedIndexs: %d", ud->failed_num);
                ud->failed_indexs[ud->failed_num] = authType;
                ud->failed_num++;
            } else {
                ret = PAM_AUTH_ERR;
                ud->need_cancel = false;

                get_limits_info(ud);

                int failType = AT_Password;
                if (ud->failed_num > 0) {
                    failType = ud->failed_indexs[0];
                }

                // 如果有多种错误类型，且包含密码，则将错误类型展示为密码
                for (int i = 0; i < (ud->failed_num); i++) {
                    if (ud->failed_indexs[i] == AT_Password) {
                        failType = AT_Password;
                        break;
                    }
                }
                int typeIndex = type_to_index(failType);
                if (typeIndex >= SUPPORT_AT_TYPE) {
                    pam_syslog(ud->pamh, LOG_ERR, "index(%d) error of limit type", typeIndex);
                    break;
                }
                struct Limit *limit = &(ud->limits[typeIndex]);
                if (limit->locked) {
                    if (failType != AT_Password) {
                        int offset = 0;
                        // 如果不是输入类型的，并且是终端环境下，则需要加换行
                        if (!is_input_type(failType) && ud->term) {
                            offset = strlen("\n");
                            memcpy(msg, "\n", offset);
                        }
                        snprintf(msg + offset,
                                 MAX_BUF_SIZE,
                                 gettext("%s locked, use password please"),
                                 type_to_tr(failType));
                    } else {
                        char limit_buff[MAX_BUF_SIZE];
                        get_limit_prompt(limit_buff, limit);
                        snprintf(msg, MAX_BUF_SIZE, gettext("Password locked, %s"), limit_buff);
                    }
                } else {
                    int times = limit->maxTries - limit->numFailures;
                    if (times > 1) {
                        if (failType == AT_Password) {
                            snprintf(msg,
                                     MAX_BUF_SIZE,
                                     gettext("Password verification failed, %d chances left"),
                                     times);
                        } else {
                            int offset = 0;
                            if (!is_input_type(failType) && ud->term) {
                                offset = strlen("\n");
                                memcpy(msg, "\n", offset);
                            }
                            snprintf(msg + offset,
                                     MAX_BUF_SIZE,
                                     gettext("%s verification failed, %d chances left"),
                                     type_to_tr(failType),
                                     times);
                        }
                    } else {
                        if (failType == AT_Password) {
                            snprintf(msg,
                                     MAX_BUF_SIZE,
                                     gettext("Password verification failed, only one chance left"));
                        } else {
                            int offset = 0;
                            if (!is_input_type(failType) && ud->term) {
                                offset = strlen("\n");
                                memcpy(msg, "\n", offset);
                            }
                            snprintf(msg + offset,
                                     MAX_BUF_SIZE,
                                     gettext("%s verification failed, only one chance left"),
                                     type_to_tr(failType));
                        }
                    }
                }
                send_msg_cb(ud, msg, PAM_ERROR_MSG);
            }
            break;
        }
        case ASC_Cancel:
        case ASC_Timeout:
        case ASC_Error:
            ud->need_cancel = false;
            D_DEBUG(ud->pamh, "[DEBUG] set result code: %d", signalCode);
            break;
        case ASC_Verify:
            D_DEBUG(ud->pamh, "start resolve verify msg: %s", signalMsg);
            memset(msg, 0, MAX_BUF_SIZE);
            int r = resolve_verify_msg(ud, signalMsg, msg);
            if (r != 0) {
                send_msg_cb(ud, msg, r);
            }
            break;
        case ASC_Expect:
            break;
        case ASC_Prompt:
            if (authType == -1) {
                //在单因并行的情况下,curType = -1, 所有的提示都不会被显示
                int err = 0;

                D_DEBUG(ud->pamh, "[DEBUG] start password authenticate for Forcty: %d!", authType);
                if (ud->pid) {
                    int r = pthread_kill(ud->pid, 0);
                    //在存在活跃的token获取线程时,不应该收到prompt信号
                    // TODO:或者不应该处理
                    if (r != ESRCH) {
                        pam_syslog(ud->pamh, LOG_ERR, "more then one token thread!");
                        ret = PAM_ABORT;
                        break;
                    }
                }
                // 是终端，加：
                if (ud->term) {
                    sprintf(ud->prompt, "%s:", signalMsg);
                } else {
                    sprintf(ud->prompt, "%s", signalMsg);
                }

                err = pthread_create(&ud->pid, NULL, request_pw_cb, (void *)ud);
                if (err != 0) {
                    pam_syslog(ud->pamh, LOG_ERR, "create password thread error: %d", err);
                    ret = PAM_ABORT;
                    break;
                }
                D_DEBUG(ud->pamh, "create password thread id: %ld", ud->pid);
            }
            break;
        case ASC_Started:
            break;
        case ASC_Ended:
            break;
        }
    } while (0);
    return ret;
}
