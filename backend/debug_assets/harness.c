#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <setjmp.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "netdissect-stdinc.h"
#include "netdissect.h"

#ifndef __AFL_LOOP
#define __AFL_LOOP(x) (0)
#endif

static jmp_buf fuzz_env;

// Dummy implementations for netdissect options
static void fuzz_default_print(netdissect_options *ndo, const u_char *bp, u_int length) { }
static int fuzz_printf(netdissect_options *ndo, const char *fmt, ...) { return 0; }
static void fuzz_error(netdissect_options *ndo, const char *fmt, ...) { longjmp(fuzz_env, 1); }
static void fuzz_warning(netdissect_options *ndo, const char *fmt, ...) { }

int main(int argc, char **argv) {
    netdissect_options *ndo = malloc(sizeof(netdissect_options));
    
    // 입력을 임시로 받을 정적 버퍼 (루프 밖으로 빼서 재사용)
    unsigned char temp_buf[65535]; 
    
    while (__AFL_LOOP(10000)) {
        memset(ndo, 0, sizeof(netdissect_options));
        ndo->ndo_default_print = fuzz_default_print;
        ndo->ndo_printf = fuzz_printf;
        ndo->ndo_error = fuzz_error;
        ndo->ndo_warning = fuzz_warning;
        ndo->ndo_snaplen = 65535;

        // ★ 핵심: 취약점 경로(Deep State)로 진입하기 위한 Verbose 옵션 강제 활성화 ★
        ndo->ndo_vflag = 3;

        // memset은 불필요하므로 삭제하여 속도 최적화!
        // memset(temp_buf, 0, ...)
        
        ssize_t len = read(0, temp_buf, sizeof(temp_buf));
        if (len > 0) {
            // [핵심] ASan Redzone을 타이트하게 붙이기 위한 동적 할당
            unsigned char *target_buf = malloc(len);
            memcpy(target_buf, temp_buf, len);
            
            ndo->ndo_packetp = target_buf;
            ndo->ndo_snapend = target_buf + len;
            
            if (setjmp(fuzz_env) == 0) {
                bootp_print(ndo, target_buf, len);
            }
            
            // 검사가 끝난 후 반드시 메모리 해제
            free(target_buf); 
        }
    }
    
    free(ndo);
    return 0;
}
