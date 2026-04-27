#ifndef _SFA_H_
#define _SFA_H_

#include "common.h"

int sfa_start_verify(struct UserData *userData, int index, int timeout);

int sfa_signal_deal(struct UserData *userData,
                    int signalCode,
                    int authType,
                    char *signalMsg,
                    pam_conv_send_msg send_msg_cb,
                    void *(*request_pw_cb)(void *));

#endif