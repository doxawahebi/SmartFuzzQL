#include <stdio.h>
#include <string.h>

#include "vuln.h"

void process_user_name(const char *name) {
    char display_name[16];

    strcpy(display_name, name);
    printf("hello, %s\n", display_name);
}
