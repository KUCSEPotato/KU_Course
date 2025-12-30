// gcc -o vulnerable4_patched vulnerable4_patched.c

// [Patched secure code]
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
    
// patched secure logging function
void log_user_input(const char *input){
    FILE *f = fopen("log.txt","at");
    if(f){
        // patch 1: treat input as data, not format string
        fprintf(f, "%s", input);  // safe usage
        fprintf(f,"\n");
        fclose(f);
    }
    openlog("log", LOG_PID | LOG_CONS, LOG_USER);
    // patch 2: syslog also modified similarly
    syslog(LOG_INFO, "%s", input);  // safe usage
    closelog();
}

int main(int argc, char *argv[]) {
    if (argc != 2){
        fprintf(stderr, "Usage: %s <message>\n", argv[0]);
        return 1;
    }
    const char *msg = argv[1];
    log_user_input(msg);
    
    return 0;
}

/*
// [Original vulnerable code]
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>

void log_user_input(const char *input){
    FILE *f = fopen("log.txt","at");
    if(f){
        fprintf(f, input);  // 취약점: 포맷 스트링 공격 가능
        fprintf(f,"\n");
        fclose(f);
    }
    openlog("log", LOG_PID | LOG_CONS, LOG_USER);
    syslog(LOG_INFO, input);  // 취약점: 포맷 스트링 공격 가능
    closelog();
}

int main(int argc, char *argv[]) {
    if (argc != 2){
        fprintf(stderr, "Usage: %s <message>\n", argv[0]);
        return 1;
    }
    const char *msg = argv[1];
    log_user_input(msg);
    
    return 0;
}
*/