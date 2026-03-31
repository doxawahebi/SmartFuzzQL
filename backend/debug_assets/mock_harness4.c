#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// --- Target Function (vulnerable_function) ---
void vulnerable_function(char *input) {
    char buffer[16];
    
    // Vulnerability: strcpy does not check bounds, leading to a Buffer Overflow.
    strcpy(buffer, input);
    
    // printf("Buffer contains: %s\n", buffer);
}

// --- AFL++ Harness Main ---

// Use the official AFL++ initialization macro globally.
// This replaces the manual 'extern' declarations and automatically 
// sets up __afl_fuzz_ptr, __afl_fuzz_len, and __afl_fuzz_alt_ptr.
__AFL_FUZZ_INIT();

int main() {
    // Persistent Mode Loop
    while (__AFL_LOOP(10000)) {
        
        size_t input_len = __AFL_FUZZ_TESTCASE_LEN;
        unsigned char *input_buf = __AFL_FUZZ_TESTCASE_BUF;

        // Input Preparation
        char *fuzzer_input_str = (char *)malloc(input_len + 1);
        if (fuzzer_input_str == NULL) {
            continue; 
        }

        // Copy Data and Apply Null Terminator
        memcpy(fuzzer_input_str, input_buf, input_len);
        fuzzer_input_str[input_len] = '\0'; 

        // Call the vulnerable target function
        vulnerable_function(fuzzer_input_str);

        // Cleanup
        free(fuzzer_input_str);
    }

    return 0;
}