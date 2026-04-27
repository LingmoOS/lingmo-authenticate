
#include "common.h"

int type_to_index(int authType) {
    int index = 0;
    while (!(authType & (0x1 << index))) {
        index++;
    }
    return index;
}

char *type_to_tr(int authType) {
    switch (authType) {
    // Password 有多种含义，单独的 "Password" 可表示为 "请输入密码"，此处含义为 "密码"，故屏蔽
    // case AT_Password:
    //     return gettext("Password");
    case AT_Fingerprint:
        return gettext("Fingerprint");
    case AT_Face:
        return gettext("Face recognition");
    case AT_ActiveDirectory:
        return gettext("ActiveDirectory");
    case AT_Ukey:
        return gettext("PIN");
    case AT_Iris:
        return gettext("Iris");
    }
    return gettext("Unknown");
}

bool is_input_type(int authType) {
    if (authType == AT_Password || authType == AT_Ukey || authType == AT_ActiveDirectory) {
        return true;
    }
    return false;
}

int get_app_type(char *app_type) {
    if (!app_type) {
        return APP_VAL_OTHER;
    }

    if (!strcmp(app_type, APP_TYPE_LOGIN)) {
        return APP_VAL_LOGIN;
    } else if (!strcmp(app_type, APP_TYPE_LOCK)) {
        return APP_VAL_LOCK;
    } else if (!strcmp(app_type, APP_TYPE_AUTHORIZATION)) {
        return APP_VAL_AUTHORIZATION;
    }

    return APP_VAL_OTHER;
}