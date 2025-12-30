// gcc -fno-stack-protector -z execstack -no-pie -o vulnerable1 vulnerable1.c
// [patched code]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void func(){
    char secret[8] = "SECRET";  // fix typo
    char buffer[8];
    
    printf("Secret message: %s\n", secret);
    
    printf("Input: ");
    
    // use fgets instead of gets to prevent buffer overflow
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        fprintf(stderr, "Input error\n");
        exit(1);
    }
    
    // delete newline character if present
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len-1] == '\n') {
        buffer[len-1] = '\0';
    }
    
    if (strcmp(secret, "COSE354") == 0){
        printf("Please patch this code!\n");
    } else {
        printf("Try again!\n");
        exit(1);
    }
}

int main(){
    func();
    return 0;
}

// [Original vulnerable code]
/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void func(){
    char seceret[8] = "SECERET";
    char buffer[8];
    
    printf("Seceret message : %s\n",seceret);
    
    printf("Input : ");
    gets(buffer);

    if (strcmp(seceret, "COSE354") == 0){
        printf("Please patch this code!");
    } else {
        printf("Try again!");
        exit(1);
    }
}

int main(){
    func();
    return 0;
}
*/