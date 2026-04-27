#ifndef _TYPE_H_
#define _TYPE_H_

int type_to_index(int authType);

char *type_to_tr(int authType);

bool is_input_type(int authType);

int get_app_type(char *app_type);

#endif