#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

extern void vulnerable_func(char* input);

// Provide a definition of the vulnerable function so the harness links successfully
void vulnerable_func(char* input) {
    char buf[10];
    // Intentionally overflow buf if input is larger than 10 bytes
    strcpy(buf, input);
}

// AFL++ fuzzer harness entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a null-terminated string from the fuzzing input
    char* input = (char*)malloc(Size + 1);
    if (!input) return 0;

    memcpy(input, Data, Size);
    input[Size] = '\0';

    // Call the vulnerable function
    vulnerable_func(input);

    free(input);
    return 0;
}
