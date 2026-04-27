#include "mfa.h"
#include "dbus.h"
#include "type.h"
#include "utils.h"

int mfa_start_verify(struct UserData *userData, int index, int timeout) {
    if (userData->auth_ctrl->factorSize > 0 && index < userData->auth_ctrl->factorSize) {
        int idx = userData->auth_ctrl->factorOrder[index];
        // if (!userData->authCtrl->factors[idx])
        //    return;
        userData->cur_type = userData->auth_ctrl->factors[idx].authType;
        if (dbus_method_start(userData, userData->path, userData->cur_type, timeout)) {
            return PAM_ABORT;
        }
    } else {
        return PAM_ABORT;
    }
    return PAM_SUCCESS;
}

int mfa_signal_deal(struct UserData *userData,
                    int signalCode,
                    int authType,
                    char *signalMsg,
                    pam_conv_send_msg send_msg_cb,
                    void *(*request_pw_cb)(void *)) {
    struct UserData *ud = userData;
    char msg[MAX_BUF_SIZE];
    int ret = -1;

    D_DEBUG(ud->pamh,
            "in mfa_signal_deal, signalCode is %d, authType is %d, signalMsg is %s",
            signalCode,
            authType,
            signalMsg);
    do {
        switch (signalCode) {
        case ASC_Success:
            if (authType != -1) {
                sprintf(msg, gettext("Verification successful"));
                send_msg_cb(ud, msg, PAM_TEXT_INFO);

                if (authType == ud->cur_type) {
                    D_DEBUG(ud->pamh, "authType is same: %d, try next auth", authType);
                    int idx = 0;
                    //找到当前认证方式, 在认证优先级排序表中的下标
                    for (; idx < ud->auth_ctrl->factorSize; ++idx) {
                        if (ud->auth_ctrl->factors[ud->auth_ctrl->factorOrder[idx]].authType ==
                            ud->cur_type) {
                            break;
                        }
                    }
                    //找不到的情况不应该出现
                    if (idx == ud->auth_ctrl->factorSize) {
                        pam_syslog(ud->pamh, LOG_ERR, "can not find current auth type");
                        ret = PAM_ABORT;
                        return ret;
                    }
                    //所有方式已经认证完成
                    if (idx == ud->auth_ctrl->factorSize - 1) {
                        return ret;
                    }
                    // 结束当前次认证
                    dbus_method_end(userData, userData->path, authType);
                    //下一个认证方式为认证优先级表中的下一个
                    idx += 1;
                    //开启下一个认证方式
                    int r = mfa_start_verify(userData, idx, -1);
                    if (r != PAM_SUCCESS) {
                        ret = r;
                    }
                } else {
                    //如果与当前认证不相同,不处理
                    D_DEBUG(ud->pamh, "authType not equal: %d", ud->cur_type);
                }
                break;
            }
            ret = PAM_SUCCESS;
            ud->need_cancel = false;
            break;
        case ASC_Failure: {
            if (authType != -1) {
                ret = PAM_AUTH_ERR;
                ud->need_cancel = false;
                if (authType == AT_Password) {
                    snprintf(msg, MAX_BUF_SIZE, gettext("Password verification failed"));
                } else {
                    int offset = 0;
                    if (!is_input_type(authType) && ud->term) {
                        offset = strlen("\n");
                        memcpy(msg, "\n", offset);
                    }
                    snprintf(msg + offset,
                             MAX_BUF_SIZE,
                             gettext("%s verification failed"),
                             type_to_tr(authType));
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
            // 多因情况下，各种认证方式都是顺序控制开启的
            if (authType == ud->cur_type && authType != -1) {
                int err = 0;

                D_DEBUG(ud->pamh, "[DEBUG] start password authenticate for Forcty: %d!", authType);
                if (ud->pid) {
                    int r = pthread_kill(ud->pid, 0);
                    //在存在活跃的token获取线程时,不应该收到prompt信号
                    // TODO:或者不应该处理
                    if (r != ESRCH) {
                        pam_syslog(ud->pamh, LOG_ERR, "more then one token threed!");
                        ret = PAM_ABORT;
                        break;
                    }
                }
                if (ud->term) {
                    if (is_input_type(authType)) {
                        int length = strlen(signalMsg);
                        D_DEBUG(ud->pamh,
                                "%s, -1 is %d, -2 is %d",
                                signalMsg,
                                signalMsg[length - 1],
                                signalMsg[length - 2]);
                        if ((signalMsg[length - 2] == ':' && signalMsg[length - 1] == ' ') ||
                            (signalMsg[length - 1] == ':') || (signalMsg[length - 1] == -102)) {
                            sprintf(ud->prompt, "%s", signalMsg);
                        } else {
                            sprintf(ud->prompt, "%s:", signalMsg);
                        }
                    } else {
                        sprintf(ud->prompt, "%s", signalMsg);
                    }
                } else {
                    sprintf(ud->prompt, "%s", signalMsg);
                }

                err = pthread_create(&ud->pid, NULL, request_pw_cb, ud);
                if (err != 0) {
                    pam_syslog(ud->pamh, LOG_ERR, "create password thread error: %d", err);
                    ret = PAM_ABORT;
                    break;
                }
                D_DEBUG(ud->pamh, "create password thread id: %ld", ud->pid);
            }
            if (authType == -1) {
                send_msg_cb(ud, signalMsg, PAM_TEXT_INFO);
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