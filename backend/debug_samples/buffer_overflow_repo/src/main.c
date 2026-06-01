#include <stdio.h>

#include "vuln.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <name>\n", argv[0]);
        return 1;
    }

    process_user_name(argv[1]);
    return 0;
}
