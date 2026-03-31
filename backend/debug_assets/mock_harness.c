#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ------------------------------------------------------------------
// 1. 타겟 함수: 퍼저가 즉시 크래시를 찾을 수 있는 취약한 코드
// ------------------------------------------------------------------
void vulnerable_function(char *input) {
    if (input == NULL || strlen(input) < 4) {
        return; // 너무 짧은 입력은 무시
    }

    // 취약점 A: "FUZZ" 문자열 입력 시 강제 종료 (SIGABRT 발생)
    if (input[0] == 'F' && input[1] == 'U' && input[2] == 'Z' && input[3] == 'Z') {
        abort(); 
    }

    // 취약점 B: 스택 기반 버퍼 오버플로우 (SIGSEGV 발생)
    char small_buffer[8];
    strcpy(small_buffer, input); // 8바이트 이상의 입력이 들어오면 크래시
}

// ------------------------------------------------------------------
// 2. AFL++ 하네스 (main 함수)
// ------------------------------------------------------------------

// AFL++ Shared Memory Fuzzing 초기화 매크로
__AFL_FUZZ_INIT();

int main() {
    // Persistent Mode 루프 (프로세스 재생성 오버헤드 제거)
    while (__AFL_LOOP(10000)) {
        
        size_t input_len = __AFL_FUZZ_TESTCASE_LEN;
        unsigned char *input_buf = __AFL_FUZZ_TESTCASE_BUF;

        // 입력 준비를 위한 메모리 할당 (널 종료 문자 공간 포함)
        char *fuzzer_input_str = (char *)malloc(input_len + 1);
        if (fuzzer_input_str == NULL) {
            continue; 
        }

        // 퍼저의 입력을 복사하고 널 종료 문자로 닫아줌
        memcpy(fuzzer_input_str, input_buf, input_len);
        fuzzer_input_str[input_len] = '\0'; 

        // 취약한 타겟 함수 실행
        vulnerable_function(fuzzer_input_str);

        // 메모리 해제
        free(fuzzer_input_str);
    }

    return 0;
}