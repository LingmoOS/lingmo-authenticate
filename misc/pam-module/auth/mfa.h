#ifndef _MFA_H_
#define _MFA_H_

#include "common.h"

int mfa_start_verify(struct UserData *userData, int index, int timeout);

int mfa_signal_deal(struct UserData *userData,
                    int signalCode,
                    int authType,
                    char *signalMsg,
                    pam_conv_send_msg send_msg_cb,
                    void *(*request_pw_cb)(void *));

#endif