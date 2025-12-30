//  GNU nano 2.9.3                          user_ku_cpu.c                                     

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define KU_CPU 339 // define syscall number
#define FCFS     0
#define SRTF     1
#define RR       2
#define PRIORITY 3

/*
argu1 -> jobTime
argu2 -> delayTime
argu3 -> process name
argu4 -> policy
argu5 -> priority
*/

int main(int argc, char **argv){
    int jobTime;
    int delayTime;
    char name[8];
    int wait = 0;
    /* add for Priority with Preemption 
       it may be argv[5] */
    int priority;
    
    /* add for response time, initialized -1 */
    int response_time = -1;
    /* add for calculate how many times request and when granted
       These two variables must need to calculate response time */
  //  int first_granted = 0;
    int tick = 0; // 전체 요청 시간
    int count = 0; // # of rejection using cpu

    /* add to paremeterizing what is the policy used for scheduling 
       it may be argv[4]*/
    int policy = atoi(argv[4]);

    if (argc < 5){
        printf("\nInsufficient Arguments..\n");
        return 1;
    }

    jobTime = atoi(argv[1]);
    delayTime = atoi(argv[2]);
    strcpy(name, argv[3]);
    int remain = jobTime * 10;

    if (argc >= 5) {
        priority = atoi(argv[5]);
    }
    else {
        priority = 0; // when policy is not priority, use 0 for syscall
    }

    // wait for 'delayTime' seconds before execution
    sleep(delayTime);
    printf("\nProcess %s : I will use CPU by %ds.\n", name, jobTime);

    // continue requesting the system call as long as the jobTime remains
    while (remain > 0) {
        int my_job_time = remain;

        if (syscall(KU_CPU, my_job_time, policy, priority, name)) {
            count++;
        } else {
            if (response_time == -1) {
                response_time = tick;
            }
            wait++; // 실제로 CPU를 사용한 tick
            remain--;  // 수락되었을 때만 줄임
        }
        tick++;  // 전체 흐른 시간 (0.1초 단위)
        usleep(100000);  // 0.1초
    }
    syscall(KU_CPU, 0, policy, 0, name);

    int total_wait_time = tick - wait;

    printf("\nProcess %s : Finish! MY Response time is %ds and My total wait time is %ds.\n", name, response_time / 10, (total_wait_time+5)/10);
    return 0;
}


