#include "debug.h"

static bool debug = false;

void set_debug_flag(bool enable) { debug = enable; }

bool get_debug_flag() { return debug ? true : false; }