// gcc -o vulnerable3_patched vulnerable3_patched.c
// [Patched secure code]
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>

typedef struct {
    uint32_t id;
    uint32_t balance;
} Account;

static void show(const Account *a){
     printf("[Account %" PRIu32 "] balance=%" PRIu32 " cents\n", a->id, a->balance);
}

// patch1: deposit() - added overflow check
int deposit(Account *a, uint32_t amount){
    // check for negative when cast to signed
    if((int32_t)amount < 0) {
        fprintf(stderr, "Error: Invalid amount (negative when cast to signed)\n");
        return -1;
    }
    
    // check for overflow before performing addition
    // safe check a->balance + amount > UINT32_MAX
    // transform equation: amount > UINT32_MAX - a->balance
    if (amount > UINT32_MAX - a->balance) {
        fprintf(stderr, "Error: Deposit would cause overflow (balance=%" PRIu32 ", amount=%" PRIu32 ")\n", 
                a->balance, amount);
        return -2;
    }
    
    a->balance += amount;
    return 0;
}

// patch2: withdraw() - correct underflow check
int withdraw(Account *a, int32_t amount){
    // validate positive amount
    if (amount <= 0) {
        fprintf(stderr, "Error: Withdrawal amount must be positive\n");
        return -1;
    }
    
    // correct check for not enough balance
    // uint32_t cannot be negative, so check before subtraction
    if (a->balance < (uint32_t)amount) {
        fprintf(stderr, "Error: Insufficient balance (have=%" PRIu32 ", need=%" PRId32 ")\n", 
                a->balance, amount);
        return -2;
    }
    
    // safe to subtract
    a->balance -= (uint32_t)amount;
    return 0; 
}

// patch 3: adjust() - signed/unsigned safety handling
int adjust(Account *a, int32_t delta){
    // when delta is negative
    if (delta < 0) {
        // safe calculation for absolute value
        // using int64_t to handle INT32_MIN case
        uint32_t abs_delta = (uint32_t)(-(int64_t)delta);
        
        // check for underflow
        if (a->balance < abs_delta) {
            fprintf(stderr, "Error: Adjustment would cause underflow (balance=%" PRIu32 ", delta=%" PRId32 ")\n",
                    a->balance, delta);
            return -1;
        }
        
        a->balance -= abs_delta;
    }
    // when delta is positive (increase)
    else if (delta > 0) {
        uint32_t pos_delta = (uint32_t)delta;
        
        // check for overflow
        if (pos_delta > UINT32_MAX - a->balance) {
            fprintf(stderr, "Error: Adjustment would cause overflow (balance=%" PRIu32 ", delta=%" PRId32 ")\n",
                    a->balance, delta);
            return -2;
        }
        
        a->balance += pos_delta;
    }
    // when delta == 0, no operation is performed
    
    return 0;
}

int main(){
    Account a = { .id =1, .balance = 1000 };
    
    printf("=== Test 1: Deposit Overflow Prevention ===\n");
    a.balance = 4294967290;
    show(&a);
    printf("Attempting to deposit 10 cents...\n");
    if(deposit(&a, 10)==0){
        printf("Success!\n");
        show(&a);
    } else {
        printf("Failed! Overflow prevented.\n");
    }
    printf("\n");
    
    printf("=== Test 2: Withdraw Underflow Prevention ===\n");
    a.balance = 100;
    show(&a);
    printf("Attempting to withdraw 500 cents...\n");
    if(withdraw(&a, 500) == 0){
        printf("Success!\n");
        show(&a);
    } else {
        printf("Failed! Insufficient balance.\n");
    }
    printf("\n");

    printf("=== Test 3: Adjust Underflow Prevention ===\n");
    a.balance = 1000;
    show(&a);
    printf("Attempting to adjust by -2000 cents...\n");
    if(adjust(&a, -2000) == 0){
        printf("Success!\n");
        show(&a);
    } else {
        printf("Failed! Underflow prevented.\n");
    }
    printf("\n");
    
    printf("=== Test 4: Normal Operations ===\n");
    a.balance = 10000;
    show(&a);
    printf("Deposit 500 cents...\n");
    deposit(&a, 500);
    show(&a);
    printf("Withdraw 200 cents...\n");
    withdraw(&a, 200);
    show(&a);
    printf("Adjust by -100 cents...\n");
    adjust(&a, -100);
    show(&a);
    
    return 0;
}

/*
// [Original vulnerable code]
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

typedef struct {
    uint32_t id;
    uint32_t balance;
} Account;

static void show(const Account *a){
     printf("[Account %" PRIu32 "] balance=%" PRIu32 " cents\n", a->id, a->balance);
}

int deposit(Account *a, uint32_t amount){
    if((int32_t)amount < 0) return -1;     
      a->balance += amount;
      return 0;
}

int withdraw(Account *a, int32_t amount){
    if (amount <= 0) return -1;
    uint32_t new_balance = a->balance - amount;
    if (new_balance < 0) return -2;
    a->balance = new_balance;
    return 0; 
}

int adjust(Account *a, int32_t delta){
    uint32_t new_balance = a->balance + delta;
    a->balance = new_balance;
    return 0;
}

int main(){
    Account a = { .id =1, .balance = 1000 };
    
    a.balance = 4294967290;
    show(&a);
    if(deposit(&a, 10)==0){
        printf("Success!\n");
        show(&a);
    }
    printf("\n");
    a.balance = 100;
    show(&a);
    if(withdraw(&a, 500) == 0){
        printf("Success!\n");
        show(&a);
    }
    printf("\n");

    a.balance = 1000;
    show(&a);
    if(adjust(&a, -2000) == 0){
        printf("Success!\n");
        show(&a);
    }
    
    return 0;
}
*/