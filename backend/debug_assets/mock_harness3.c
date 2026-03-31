
#define main disabled_main
#include "vuln.c"
#undef main

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char buf[1024];
    /* Using AFL++ deferred instrumentation requires __AFL_INIT() but fast instrumentation works without it out of the box */
    ssize_t len = read(0, buf, sizeof(buf)-1);
    if (len > 0) {
        buf[len] = '\0';
        vulnerable_function(buf);
    }
    return 0;
}
