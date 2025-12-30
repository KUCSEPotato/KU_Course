// gcc -fno-stack-protector -z execstack -no-pie -o vulnerable2 vulnerable2.c
// [Patched secure code]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void func1_patched(){
    char buffer[8];
    int i = 0;
    char c;
    
    printf("Enter Input : ");
    
    // patch1: added bounds checking
    while((c = getchar()) != '\n' && c != EOF) {
        if (i < sizeof(buffer) - 1) {  // make space for null terminator
            buffer[i++] = c;
        } else {
            // If buffer is full, ignore the rest of the input
            while((c = getchar()) != '\n' && c != EOF);
            break;
        }
    }
    buffer[i] = '\0';
    
    printf("Input : %s\n", buffer);
}

void func2_patched(){
    char buffer[64];  // patch 2: allocate sufficient buffer size
    char input[10];
    
    printf("Enter Input : ");
    fgets(input, sizeof(input), stdin);

    // delete newline character if present
    size_t len = strlen(input);
    if (len > 0 && input[len-1] == '\n') {
        input[len-1] = '\0';
    }
    
    // patch 3: use snprintf to limit buffer size
    snprintf(buffer, sizeof(buffer), "User input: %s", input);
    
    printf("Input : %s\n", buffer);

    // patch 6: clear input buffer
    while (getchar() != '\n');
}

void func3_patched(){
    char buffer[8];
    char input[10];
    
    printf("Enter Input : ");

    // patch 4: add length limit to scanf
    scanf("%9s", input);  // max 9 chars + null terminator
    
    // patch 5: use strncpy and null terminator
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // null terminator

    printf("Copied : %s\n", buffer);
}

int main(){
    func1_patched();
    func2_patched();
    func3_patched();
    return 0;
}

/*
// [Original vulnerable code]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void func1(){
    char buffer[8];
    int i = 0;
    char c;
    
    printf("Enter Input : ");
    
    while((c = getchar()) != '\n' && c != EOF) {
        buffer[i++] = c; // No bounds checking; warning; buffer overflow possible
    }
    buffer[i] = '\0';
    
    printf("Input : %s\n", buffer);
}

void func2(){
    char buffer[8];
    char input[10];
    
    printf("Enter Input : ");
    fgets(input, sizeof(input), stdin);
    
    sprintf(buffer, "User input: %s", input); // No bounds checking; warning; buffer overflow possible
    
    printf("Input : %s\n", buffer);
}
void func3(){
    char buffer[8];
    char input[10];
    
    printf("Enter Input : ");
    scanf("%s",input);
    
    strcpy(buffer, input); // No bounds checking; warning; buffer overflow possible
    
    printf("Copied : %s\n", buffer);
}

int main(){
    func1();
    // func2();
    func3();
    return 0;
}
*/