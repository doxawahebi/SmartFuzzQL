#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[16];
    // Vulnerability: strcpy does not check bounds of input
    strcpy(buffer, input);
    printf("Buffer contains: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    } else {
        printf("Usage: %s <input>\n", argv[0]);
    }
    return 0;
}
