#include "common.h"
#include <time.h>

static int resolve_limit_time(struct Limit *limit) {
    struct tm get_time = {
            .tm_isdst = 0,
    };
    strptime(limit->unlockTime, "%FT%TZ", &get_time);
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

int get_limit_prompt(char *buff, struct Limit *limit) {
    if (limit->locked) {
        int minutes = resolve_limit_time(limit);
        if (minutes > 1) {
            snprintf(buff, MAX_BUF_SIZE, gettext("Please try again %d minutes later"), minutes);
        } else {
            snprintf(buff, MAX_BUF_SIZE, gettext("Please try again %d minute later"), minutes);
        }
        return PAM_MAXTRIES;
    }
    return PAM_SUCCESS;
}
