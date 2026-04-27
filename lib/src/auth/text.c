#include "auth-priv.h"
#include <libintl.h>
#include <pwd.h>
#include <limits.h>
#include <sys/stat.h>
#include <stdio.h>
#include "text.h"
#include <unistd.h>
#include <time.h>
#include <locale.h>
#include <time.h>

#define DOMAIN "deepin-authentication"

static char *type_to_tr(DA_AUTH_FLAG auth_flag) {
    char* text_str;
    switch (auth_flag) {
    // Password 有多种含义，单独的 "Password" 可表示为 "请输入密码"，此处含义为 "密码"，故屏蔽
    // case AT_Password:
    //     return gettext("Password");
    case AUTH_FLAG_FINGERPRINT:
        text_str = gettext("Fingerprint");
        break;
    case AUTH_FLAG_FACE:
        text_str = gettext("Face recognition");
        break;
    case AUTH_FLAG_AD:
        text_str = gettext("ActiveDirectory");
        break;
    case AUTH_FLAG_UKEY:
        text_str = gettext("PIN");
        break;
    default:
        text_str = gettext("Unknown");
        break;
    }
    return text_str;
}

static bool is_input_type(DA_AUTH_FLAG authType) {
    if (authType == AUTH_FLAG_PASSWORD || authType == AUTH_FLAG_UKEY || authType == AUTH_FLAG_AD) {
        return true;
    }
    return false;
}

static bool is_tty() {
    return isatty(fileno(stdin));
}

static da_limit_info *get_limit_info_priv(da_proxy *proxy,
                                          const char *username,
                                          DA_AUTH_FLAG auth_flag) {
    da_limit_info *dli = NULL;
    int dli_num = 0;
    da_error *error = NULL;
    da_get_limits(proxy, username, &dli, &dli_num, &error);
    if (error) {
        da_error_free(error);
        return NULL;
    }
    da_limit_info *spec_limit = da_get_auth_limit_info(dli, dli_num, auth_flag);
    if (!spec_limit) {
        if (dli) {
            free(dli);
        }
        return NULL;
    }
    da_limit_info *out_limit = malloc(sizeof(da_limit_info));
    memcpy(out_limit, spec_limit, sizeof(da_limit_info));

    if (dli) {
        free(dli);
    }

    return out_limit;
}

static int resolve_limit_time(da_limit_info *limit) {
    struct tm get_time = {
            .tm_isdst = 0,
    };
    strptime(limit->unlock_time, "%FT%TZ", &get_time);
    time_t now = time(NULL);

    time_t get_time_timestamp = mktime(&get_time);

    double diff_of_time = difftime(get_time_timestamp, now);

    int minutes = 0;
    if (diff_of_time >= 0) {
        long long wait = diff_of_time;
        minutes = (wait + 59) / 60;
    }
    return minutes;
}

static int get_limit_prompt(char *buff, da_limit_info *limit) {
    if (limit->locked) {
        int minutes = resolve_limit_time(limit);
        if (minutes > 1) {
            sprintf(buff, gettext("Please try again %d minutes later"), minutes);
        } else {
            sprintf(buff, gettext("Please try again %d minute later"), minutes);
        }
        return 1;
    }
    return 0;
}

void da_load_user_locale(const char *username) {
    const char *locale_path = ".config/locale.conf";
    struct passwd *p;
    if ((p = getpwnam(username)) == NULL) {
        return;
    }
    size_t path_len = strlen(p->pw_dir) + strlen(locale_path) + 2; // 2: '/' + '\0'
    if (path_len > PATH_MAX) {
        return;
    }
    char *buff = malloc(MAX_BUFF_SIZE);
    strcpy(buff, p->pw_dir);
    strcat(buff, "/");
    strcat(buff, locale_path);
    struct stat locale_file_stat;
    stat(buff, &locale_file_stat);
    if (!S_ISREG(locale_file_stat.st_mode)) {
        free(buff);
        return;
    }
    FILE *f;
    if ((f = fopen(buff, "r")) == NULL) {
        free(buff);
        return;
    }
    char *pos = NULL;

    while (fgets(buff, MAX_BUFF_SIZE, f) != NULL) {
        if ((pos = strchr(buff, '\n')) != NULL) {
            *pos = '\0';
        }
        pos = strchr(buff, '=');
        if (pos == NULL || buff == pos) {
            continue;
        }
        *pos = '\0';
        char *value = pos + 1;
        setenv(buff, value, true);
    }
    fclose(f);
    free(buff);
    return;
}

const char *da_success_prompt() {
    setlocale(LC_ALL, "");
    textdomain(DOMAIN);

    return g_dgettext(DOMAIN, "Verification successful");
}

int da_get_lock_info(da_proxy *proxy,
                     const char *username,
                     DA_AUTH_FLAG auth_type,
                     bool *is_lock,
                     char **prompt) {
    setlocale(LC_ALL, "");
    textdomain(DOMAIN);

    da_limit_info *spec_limit = get_limit_info_priv(proxy, username, auth_type);
    if (!spec_limit) {
        return -1;
    }

    char *buff = malloc(MAX_BUFF_SIZE);
    if (get_limit_prompt(buff, spec_limit)) {
        if (is_lock) {
            *is_lock = true;
        }
        *prompt = buff;
        free(spec_limit);
        return 0;
    }
    free(buff);
    free(spec_limit);
    return -1;
}

int da_get_fail_prompt(da_proxy *proxy,
                       DA_AUTH_FLAG auth_flag,
                       bool with_retry_info,
                       char **prompt) {

    setlocale(LC_ALL, "");
    textdomain(DOMAIN);

    if (!proxy) {
        return -1;
    }

    if (!is_valid_auth_flag(auth_flag)) {
        return -1;
    }

    bool append_escape = is_tty() && is_input_type(auth_flag);
    char *out_prompt = malloc(MAX_BUFF_SIZE);

    int offset = 0;
    if (append_escape) {
        offset = strlen("\n");
        memcpy(out_prompt, "\n", offset);
    }
    if (!with_retry_info) {
        if (auth_flag == AUTH_FLAG_PASSWORD) {
            snprintf(out_prompt + offset,
                     MAX_BUFF_SIZE,
                     g_dgettext(DOMAIN, "Password verification failed"));
        } else {
            snprintf(out_prompt + offset,
                     MAX_BUFF_SIZE,
                     g_dgettext(DOMAIN, "%s verification failed"),
                     type_to_tr(auth_flag));
        }
    } else {
        da_limit_info *spec_limit = get_limit_info_priv(proxy, proxy->username, auth_flag);
        if (!spec_limit) {
            free(out_prompt);
            return -1;
        }

        bool locked = spec_limit->locked;
        bool never_locked = spec_limit->max_tries == 0;
        int retry_cnt = spec_limit->max_tries - spec_limit->fail_num;
        free(spec_limit);
        if (never_locked) {
            if (auth_flag == AUTH_FLAG_PASSWORD) {
                snprintf(out_prompt + offset,
                         MAX_BUFF_SIZE,
                         g_dgettext(DOMAIN, "Password verification failed"));
            } else {
                snprintf(out_prompt + offset,
                         MAX_BUFF_SIZE,
                         g_dgettext(DOMAIN, "%s verification failed"),
                         type_to_tr(auth_flag));
            }

        } else if (locked) {
            if (auth_flag == AUTH_FLAG_PASSWORD) {
                char *limit_buff;
                if (da_get_lock_info(proxy, proxy->username, auth_flag, NULL, &limit_buff)) {
                    free(out_prompt);
                    return -1;
                }

                snprintf(out_prompt + offset,
                         MAX_BUFF_SIZE,
                         g_dgettext(DOMAIN, "Password locked, %s"),
                         limit_buff);
                free((void *)limit_buff);
            } else {
                snprintf(out_prompt + offset,
                         MAX_BUFF_SIZE,
                         g_dgettext(DOMAIN, "%s locked, use password please"),
                         type_to_tr(auth_flag));
            }
        } else if (retry_cnt > 1) {
            if (auth_flag == AUTH_FLAG_PASSWORD) {
                snprintf(out_prompt + offset,
                         MAX_BUFF_SIZE,
                         g_dgettext(DOMAIN, "Password verification failed, %d chances left"),
                         retry_cnt);
            } else {
                snprintf(out_prompt + offset,
                         MAX_BUFF_SIZE,
                         g_dgettext(DOMAIN, "%s verification failed, %d chances left"),
                         type_to_tr(auth_flag),
                         retry_cnt);
            }
        } else {
            if (auth_flag == AUTH_FLAG_PASSWORD) {
                snprintf(out_prompt + offset,
                         MAX_BUFF_SIZE,
                         g_dgettext(DOMAIN, "Password verification failed, only one chance left"));
            } else {
                snprintf(out_prompt + offset,
                         MAX_BUFF_SIZE,
                         g_dgettext(DOMAIN, "%s verification failed, only one chance left"),
                         type_to_tr(auth_flag));
            }
        }
    }

    *prompt = out_prompt;
    return 0;
}

static char *str_trim(const char *str, char c) {
    if (!str) {
        return NULL;
    }
    char *s = malloc(strlen(str) + 1);
    memset(s, 0, strlen(str) + 1);

    int str_i = 0;
    int s_i = 0;
    while (str[str_i] != '\0') {
        if (str[str_i] != c) {
            s[s_i++] = str[str_i];
        }
        str_i++;
    }
    return s;
}

int da_get_user_lang(const char *username, char **lang) {
    if (!username) {
        return -1;
    }

    struct passwd *pw = getpwnam(username);
    if (!pw) {
        return -1;
    }

    char buff[MAX_BUFF_SIZE];
    snprintf(buff, MAX_BUFF_SIZE, "%s/.config/locale.conf", pw->pw_dir);
    FILE *f = fopen(buff, "r");
    if (!f) {
        return -1;
    }

    char *pos = NULL;
    while (fgets(buff, MAX_BUFF_SIZE, f) != NULL) {
        if ((pos = strchr(buff, '\n')) != NULL) {
            *pos = '\0';
        }

        // buff 不可能为 NULL
        char *trim_space = str_trim(buff, ' ');
        if (!trim_space) {
            continue;
        }

        strcpy(buff, trim_space);
        free(trim_space);

        pos = strchr(buff, '=');
        if (pos == NULL || buff == pos) {
            continue;
        }
        *pos = '\0';
        char *value = pos + 1;
        if (strcmp(buff, "LANG") == 0) {
            *lang = malloc(strlen(value) + 1);
            strcpy(*lang, value);
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    return -2;
}
