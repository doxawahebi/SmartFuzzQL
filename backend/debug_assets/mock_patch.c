#include <string.h>

void vulnerable_func(char* input) {
    char buf[10];
    // Safe strncpy to prevent buffer overflow
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
}
