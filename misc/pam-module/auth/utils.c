#include "utils.h"
#include "dbus.h"
#include "type.h"
#include <json-c/json.h>
#include <limits.h>
#include <openssl/aes.h>

int resolve_verify_msg(const struct UserData *ud, const char *verify_msg, char *res_msg) {
    int subcode = -1;
    int flag = -1;
    int code = -1;
    int ret = 0;
    char subdata[MAX_BUF_SIZE] = {0};
    struct json_tokener *json_tor = json_tokener_new();

    D_DEBUG(ud->pamh, "verify msg :%s", verify_msg);
    do {
        struct json_object *parsed_json = NULL;
        struct json_object *json_flag = NULL;
        struct json_object *json_code = NULL;
        struct json_object *json_msg = NULL;
        enum json_tokener_error jerr;

        parsed_json = json_tokener_parse_ex(json_tor, verify_msg, (int)strlen(verify_msg));
        if ((jerr = json_tokener_get_error(json_tor)) != json_tokener_success) {
            pam_syslog(ud->pamh,
                       LOG_ERR,
                       "verify_msg json_tokener_parse error :%s",
                       json_tokener_error_desc(jerr));
            break;
        }

        json_object_object_get_ex(parsed_json, "flag", &json_flag);
        json_object_object_get_ex(parsed_json, "code", &json_code);
        json_object_object_get_ex(parsed_json, "msg", &json_msg);

        flag = json_object_get_int(json_flag);
        code = json_object_get_int(json_code);
        sprintf(subdata, "%s", json_object_get_string(json_msg));

        switch (flag) {
        case AT_Fingerprint: {
            switch (code) {
            case 0: // Match 匹配, 之后结束认证。
                break;
            case 1: // NoMatch 不匹配，之后结束认证。
                break;
            case 2: // Error 失败，之后结束认证。
                switch (subcode) {
                case 1:
                    sprintf(res_msg, gettext("Verification error"));
                    ret = PAM_ERROR_MSG;
                    break;
                case 2:
                    sprintf(res_msg,
                            gettext("Fingerprint verification unavailable, "
                                    "please input password"));
                    ret = PAM_ERROR_MSG;
                    break;
                }
                break;
            case 3: // Retry 重试，之后继续认证。
            {
                struct json_object *json_subcode = NULL;

                json_subcode = json_tokener_parse_ex(json_tor, subdata, (int)strlen(subdata));
                if ((jerr = json_tokener_get_error(json_tor)) != json_tokener_success) {
                    pam_syslog(ud->pamh,
                               LOG_ERR,
                               "subdata json_tokener_parse error :%s",
                               json_tokener_error_desc(jerr));
                    break;
                }

                json_object_object_get_ex(json_subcode, "subcode", &json_subcode);
                subcode = json_object_get_int(json_subcode);

                switch (subcode) {
                case 1: // swipe-too-short 滑动太短
                    sprintf(res_msg, gettext("Clean your finger and try again"));
                    ret = PAM_ERROR_MSG;
                    break;
                case 2: // finger-not-centered 手指不在中间
                    sprintf(res_msg, gettext("Finger not centered"));
                    ret = PAM_ERROR_MSG;
                    break;
                case 3: // remove-and-retry 拿开手指再重新扫描
                    sprintf(res_msg, gettext("Clean your finger and try again"));
                    ret = PAM_ERROR_MSG;
                    break;
                case 4: // quality-bad 图像质量差
                    sprintf(res_msg,
                            gettext("Unclear fingerprint, please clean your "
                                    "finger and try again"));
                    ret = PAM_ERROR_MSG;
                    break;
                case 5: // moved-too-fast 接触时间短
                    sprintf(res_msg,
                            gettext("Finger moved too fast, please do not lift until prompted"));
                    ret = PAM_ERROR_MSG;
                    break;
                default:
                    pam_syslog(ud->pamh, LOG_ERR, "get error msg: %d", subcode);
                    break;
                }
            } break;
            case 4: // Disconnected 与设备失联，之后不要对设备进行任何操作。
                break;
            case 5: // TakenByOthers
                sprintf(res_msg, gettext("Password"));
                ret = PAM_TEXT_INFO;
                break;
            }
        } break;
        }
    } while (0);
    json_tokener_free(json_tor);
    return ret;
}

// 解析 authenticate controller 中的多因子属性
int resolve_authctrl_factors(struct UserData *ud,
                             sd_bus_message *data,
                             struct AuthSession *auth_res) {
    int r = 0;
    r = sd_bus_message_enter_container(data, 'a', "(iiib)");
    if (r < 0) {
        pam_syslog(ud->pamh, LOG_DEBUG, "sd_bus_message_enter_container open error");
        return -1;
    }
    struct AuthFactor *tmp_factors = NULL;
    int length = 0;
    for (;;) {
        tmp_factors = (struct AuthFactor *)malloc(sizeof(struct AuthFactor) * (length + 1));
        if (length != 0) {
            memcpy(tmp_factors, auth_res->factors, sizeof(struct AuthFactor) * length);
        }
        r = sd_bus_message_read(data,
                                "(iiib)",
                                &(tmp_factors[length].authType),
                                &(tmp_factors[length].priority),
                                &(tmp_factors[length].inputType),
                                &(tmp_factors[length].required));
        // 对于n个数据，会遍历n+1次
        if (r <= 0) {
            free(tmp_factors);
            break;
        }
        if (auth_res->factors != NULL) {
            free(auth_res->factors);
        }
        auth_res->factors = tmp_factors;
        length++;
    }
    sd_bus_message_exit_container(data);
    auth_res->factorSize = length;
    auth_res->factorOrder = (int *)malloc(sizeof(int) * length);
    int *order = (int *)malloc(sizeof(int) * length);
    memset(order, 0, sizeof(int) * length);
    for (int i = 0; i < length; i++) {
        order[i] = auth_res->factors[i].priority;
        auth_res->factorOrder[i] = i;
    }
    for (int i = 0; i < length - 1; ++i) {
        int j = 0;
        int max_idx = i;
        D_DEBUG(ud->pamh,
                "resolv auth factory of idx: %d, AuthType: %d, Priority: %d, "
                "InputType: %d, "
                "Required: %d",
                i,
                auth_res->factors[i].authType,
                auth_res->factors[i].priority,
                auth_res->factors[i].inputType,
                auth_res->factors[i].required);

        for (j = i + 1; j < length; ++j) {
            if (order[max_idx] < order[j]) {
                max_idx = j;
            }
        }

        int tmp = auth_res->factorOrder[i];
        auth_res->factorOrder[i] = auth_res->factorOrder[max_idx];
        auth_res->factorOrder[max_idx] = tmp;

        tmp = order[i];
        order[i] = order[max_idx];
        order[max_idx] = tmp;
    }

    free(order);
    return 0;
}

void load_user_locale(pam_handle_t *pamh,
                      struct UserData *ud,
                      const char *username,
                      const char *locale_path) {
    UNUSED_VALUE(ud);
    struct passwd *p;
    if ((p = getpwnam(username)) == NULL) {
        pam_syslog(pamh, LOG_WARNING, "run getpwnam failed: %s", strerror(errno));
        return;
    }
    size_t path_len = strlen(p->pw_dir) + strlen(locale_path) + 2; // 2: '/' + '\0'
    if (path_len > PATH_MAX) {
        pam_syslog(pamh, LOG_WARNING, "user locale path exceeds PATH_MAX");
        return;
    }
    char *buff = malloc(path_len);
    strcpy(buff, p->pw_dir);
    strcat(buff, "/");
    strcat(buff, locale_path);
    struct stat locale_file_stat;
    stat(buff, &locale_file_stat);
    if (!S_ISREG(locale_file_stat.st_mode)) {
        D_DEBUG(pamh, "locale path is not file: %s: %s", buff, strerror(errno));
        free(buff);
        return;
    }
    FILE *f;
    if ((f = fopen(buff, "r")) == NULL) {
        D_DEBUG(pamh, "unable to open env file: %s: %s", buff, strerror(errno));
        free(buff);
        return;
    }
    char *pos = NULL;
    pam_syslog(pamh, LOG_INFO, "loading user locale");
    while (fgets(buff, MAX_BUF_SIZE, f) != NULL) {
        if ((pos = strchr(buff, '\n')) != NULL) {
            *pos = '\0';
        }
        pos = strchr(buff, '=');
        if (pos == NULL || buff == pos) {
            continue;
        }
        *pos = '\0';
        char *value = pos + 1;
        D_DEBUG(pamh, "setenv(%s, %s)", buff, value);
        setenv(buff, value, true);
    }
    fclose(f);
    free(buff);
    return;
}

void get_limits_info(struct UserData *ud) {
    char buff[LIMITS_BUF_SIZE] = {0};
    struct json_tokener *json_tor = json_tokener_new();

    do {
        struct json_object *parsed_json = NULL;
        struct json_object *json_flag = NULL;
        struct json_object *json_maxTries = NULL;
        struct json_object *json_numFailures = NULL;
        struct json_object *json_locked = NULL;
        struct json_object *json_unlockTime = NULL;
        enum json_tokener_error jerr;
        int flag = 0;
        if (dbus_method_get_limits(ud, ud->username, buff)) {
            pam_syslog(ud->pamh, LOG_ERR, "get limits failed");
            break;
        }

        parsed_json = json_tokener_parse_ex(json_tor, buff, (int)strlen(buff));
        if ((jerr = json_tokener_get_error(json_tor)) != json_tokener_success) {
            pam_syslog(ud->pamh,
                       LOG_ERR,
                       "verify_msg json_tokener_parse error :%s",
                       json_tokener_error_desc(jerr));
            break;
        }

        int len = json_object_array_length(parsed_json);
        for (int i = 0; i < len; i++) {
            struct json_object *jobj = json_object_array_get_idx(parsed_json, i);

            json_object_object_get_ex(jobj, "flag", &json_flag);
            json_object_object_get_ex(jobj, "maxTries", &json_maxTries);
            json_object_object_get_ex(jobj, "numFailures", &json_numFailures);
            json_object_object_get_ex(jobj, "locked", &json_locked);
            json_object_object_get_ex(jobj, "unlockTime", &json_unlockTime);

            flag = json_object_get_int(json_flag);
            struct Limit *limit = NULL;
            int typeIndex = type_to_index(flag);
            if (typeIndex >= SUPPORT_AT_TYPE) {
                pam_syslog(ud->pamh, LOG_WARNING, "index(%d) error of limit type", typeIndex);
                continue;
            }
            limit = &(ud->limits[typeIndex]);

            if (limit) {
                limit->maxTries = json_object_get_int(json_maxTries);
                limit->numFailures = json_object_get_int(json_numFailures);
                limit->locked = json_object_get_boolean(json_locked);
                strcpy(limit->unlockTime, json_object_get_string(json_unlockTime));
            }
        }
    } while (0);

    json_tokener_free(json_tor);
}

int get_authctl_property(struct UserData *ud, char *path, struct AuthSession *res) {
    sd_bus_error bus_err = SD_BUS_ERROR_NULL;
    int ret = 0;
    sd_bus_message *bus_message = NULL;
    char *prompt = NULL;
    char *userName = NULL;

#define PRINT_DBUS_ERROR(NAME)                                                                     \
    if (ret < 0) {                                                                                 \
        pam_syslog(ud->pamh,                                                                       \
                   LOG_ERR,                                                                        \
                   "get property '%s' error: %s, %s",                                              \
                   (NAME),                                                                         \
                   bus_err.name,                                                                   \
                   bus_err.message);                                                               \
        ret = PAM_ABORT;                                                                           \
        return ret;                                                                                \
    }

#define GET_AUTHCTL_PROPERTY_BASE(NAME, SIG, DATA)                                                 \
    ret = sd_bus_get_property_trivial(ud->bus,                                                     \
                                      DBUS_SERVICE,                                                \
                                      path,                                                        \
                                      DBUS_AUTHCTRL_INTERFACE,                                     \
                                      NAME,                                                        \
                                      &bus_err,                                                    \
                                      (SIG),                                                       \
                                      &(DATA));                                                    \
    PRINT_DBUS_ERROR(NAME)

#define GET_AUTHCTL_PROPERTY_STRING(NAME, DATA)                                                    \
    ret = sd_bus_get_property_string(ud->bus,                                                      \
                                     DBUS_SERVICE,                                                 \
                                     path,                                                         \
                                     DBUS_AUTHCTRL_INTERFACE,                                      \
                                     NAME,                                                         \
                                     &bus_err,                                                     \
                                     &(DATA));                                                     \
    PRINT_DBUS_ERROR(NAME)

#define GET_AUTHCTL_PROPERTY(NAME, TYPE, DATA)                                                     \
    ret = sd_bus_get_property(ud->bus,                                                             \
                              DBUS_SERVICE,                                                        \
                              path,                                                                \
                              DBUS_AUTHCTRL_INTERFACE,                                             \
                              NAME,                                                                \
                              &bus_err,                                                            \
                              &(DATA),                                                             \
                              TYPE);                                                               \
    PRINT_DBUS_ERROR(NAME)

    GET_AUTHCTL_PROPERTY_BASE("IsMFA", 'b', res->isMFA);
    GET_AUTHCTL_PROPERTY("FactorsInfo", "a(iiib)", bus_message);
    GET_AUTHCTL_PROPERTY_STRING("Prompt", prompt);
    GET_AUTHCTL_PROPERTY_STRING("Username", userName);

#undef GET_AUTHCTL_PROERTY_STRING
#undef GET_AUTHCTL_PROERTY_BASE
#undef PRINT_DBUS_ERROR

    pam_syslog(ud->pamh, LOG_DEBUG, "IsMFA: '%d', Username: '%s'", res->isMFA, userName);

    return resolve_authctrl_factors(ud, bus_message, res);
}

int gen_rsa_pubkey(pam_handle_t *pamh, RSA **rsa, char *key) {
    BIO *bio;
    int ret = 0;

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        pam_syslog(pamh, LOG_ERR, "create bio error\n");
        ret = -1;
        goto finished;
    }

    BIO_puts(bio, key);
    D_DEBUG(pamh, "bio puts finished\n");
    if (0 == strncmp(key, PKCS8_HEADER, strlen(PKCS8_HEADER))) {
        PEM_read_bio_RSA_PUBKEY(bio, rsa, NULL, NULL);
    } else if (0 == strncmp(key, PKCS1_HEADER, strlen(PKCS1_HEADER))) {
        PEM_read_bio_RSAPublicKey(bio, rsa, NULL, NULL);
    }
    D_DEBUG(pamh, "gen pubkey finished\n");

finished:
    if (bio) BIO_free(bio);
    return ret;
}

char *read_file_data(char *filename) {
    char *data = NULL;
    FILE *pf = fopen(filename, "r");
    if (!pf) {
        return NULL;
    }
    fseek(pf, 0, SEEK_END);
    long size = ftell(pf);
    data = (char *)malloc(size + 1);
    rewind(pf);
    fread(data, sizeof(char), size, pf);
    data[size] = '\0';
    fclose(pf);
    return data;
}

char *load_app_type(struct UserData *ud, char *app_path) {

    char *app_type = NULL;

    struct json_tokener *json_obj = NULL;
    struct json_object *parsed_json = NULL;
    struct json_object *json_app_list = NULL;
    struct json_object *json_app = NULL;
    struct json_object *json_type = NULL;
    struct json_object *target = NULL;
    char *data = NULL;
    do {
        data = read_file_data(APP_TYPE_LIST_FILE_PATH);
        if (!data) {
            pam_syslog(ud->pamh, LOG_ERR, "load json file %s error", APP_TYPE_LIST_FILE_PATH);
            break;
        }

        json_obj = json_tokener_new();
        parsed_json = json_tokener_parse_ex(json_obj, data, strlen(data));
        if (!parsed_json) {
            pam_syslog(ud->pamh, LOG_ERR, "parse json file %s error", APP_TYPE_LIST_FILE_PATH);
            break;
        }

        if (!json_object_object_get_ex(parsed_json, "app-type", &json_app_list)) {
            pam_syslog(ud->pamh, LOG_ERR, "parse json file %s error", APP_TYPE_LIST_FILE_PATH);
            break;
        }

        int array_length = json_object_array_length(json_app_list);

        json_bool ret = 0;
        const char *json_app_path;
        for (int i = 0; i < array_length; i++) {
            target = json_object_array_get_idx(json_app_list, i);
            ret = json_object_object_get_ex(target, "app", &json_app);
            ret &= json_object_object_get_ex(target, "type", &json_type);
            if (ret) {
                json_app_path = json_object_get_string(json_app);
                if (!strcmp(json_app_path, app_path)) {
                    app_type = (char *)malloc(json_object_get_string_len(json_type) + 1);
                    strcpy(app_type, json_object_get_string(json_type));
                    app_type[json_object_get_string_len(json_type)] = '\0';
                    break;
                }
            }
            json_object_free_userdata(target, NULL);
            target = NULL;
        }
    } while (0);

    if (data) {
        free(data);
    }
    if (json_obj) {
        json_tokener_free(json_obj);
    }

    return app_type;
}

char *gen_symmetric_key() {
    char *key = (char *)malloc(20);
    srand(time(NULL));
    int rand_num = (10000000 + rand() % 10000000) % 100000000;
    sprintf(key, "%d%d", rand_num, rand_num);

    return key;
}

int rsa_encrypt_data(struct UserData *ud, char *origin_data, char **cipher_text) {
    if (!ud->key || !ud->key->rsa) {
        D_DEBUG(ud->pamh, "[DEBUG] pubkey is null ptr, abort");
        return -1;
    }

    int clipSize = RSA_size(ud->key->rsa);
    *cipher_text = (char *)malloc(clipSize);

    D_DEBUG(ud->pamh, "clipher size is %d", clipSize);
    int ret = RSA_public_encrypt(strlen(origin_data),
                                 (const unsigned char *)origin_data,
                                 (unsigned char *)*cipher_text,
                                 ud->key->rsa,
                                 RSA_PKCS1_PADDING);
    return ret;
}

int encrypt_symmtric_key(struct UserData *ud, char **cipher_text, int *cipher_len) {
    int ret = 0;
    ud->symmetric_key = gen_symmetric_key(ud);
    D_DEBUG(ud->pamh, "symmetrict key: %s", ud->symmetric_key);
    ret = rsa_encrypt_data(ud, ud->symmetric_key, cipher_text);
    *cipher_len = ret;
    return ret;
}

int aes_cbc_encrypt(const char *src,
                    int srcLen,
                    char *key,
                    int keyLen,
                    char **cipher_text,
                    int *outLen) {
    int blockCount = 0;
    int quotient = srcLen / AES_BLOCK_SIZE;
    int mod = srcLen % AES_BLOCK_SIZE;
    blockCount = quotient + 1;

    int padding = AES_BLOCK_SIZE - mod;
    char *in = (char *)malloc(AES_BLOCK_SIZE * blockCount);
    memset(in, padding, AES_BLOCK_SIZE * blockCount);
    memcpy(in, src, srcLen);

    // out
    char *out = (char *)malloc(AES_BLOCK_SIZE * blockCount);
    memset(out, 0x00, AES_BLOCK_SIZE * blockCount);
    *outLen = AES_BLOCK_SIZE * blockCount;

    //初始向量为全0
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

    //开始加密
    AES_KEY aes;
    if (AES_set_encrypt_key((unsigned char *)key, keyLen * 8, &aes) < 0) {
        return -1;
    }
    AES_cbc_encrypt((unsigned char *)in,
                    (unsigned char *)out,
                    AES_BLOCK_SIZE * blockCount,
                    &aes,
                    iv,
                    AES_ENCRYPT);
    free(in);
    *cipher_text = out;

    return 0;
}