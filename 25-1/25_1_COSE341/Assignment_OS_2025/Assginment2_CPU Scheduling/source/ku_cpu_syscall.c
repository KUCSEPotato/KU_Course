#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/linkage.h>
#include <linux/slab.h>

#define MAX_QUEUE_SIZE 128 // define max queue size for waiting queue
#define IDLE -1
#define TIME_SLICE 10 // 1 tick = 0.1 sec, 1초씩 사용하도록 함.
#define MAX_PID 32768 // only for RR

/* declare job_t structure to manage process information for scheduling  */
typedef struct job {
    pid_t pid;
    int job_time;
    char process_name[8];
    int priority;
    int remaining_time; // for RR and SRTF
} job_t;

// scheduler interface
static int handle_fcfs(job_t newJob);
static int handle_srtf(job_t newJob);
static int handle_rr(job_t newJob);
static int handle_priority(job_t newJob);

static job_t current_job; // Full information on currently running jobs
static pid_t now = IDLE; // declare to store process using cpu, Still used but as a secondary

/* circular queue declare */
static job_t waiting_queue[MAX_QUEUE_SIZE];
static int front = 0;
static int rear = 0;
static int size = 0;

/* check duplicated process in waiting queue */
static int ku_is_new_id(pid_t pid) {
    int i;
    if (now == pid) return 0; // already running process
    
    for (i = front; i < rear; i++) {
        if (waiting_queue[i % MAX_QUEUE_SIZE].pid == pid) {
            return 0;
        }
    }
    return 1;
}

/* check cpu is idle or not */
static int ku_is_empty(void) {
    return (size == 0) ? 1 : 0;
}

/* enqueue */
int ku_push(job_t job, int policy) {
    int i;
    int insert_idx;

    if (size >= MAX_QUEUE_SIZE) {
        printk(KERN_WARNING "[Error][ku_push] Queue is full!\n");
        return -1;
    }

    if (policy == 1) { // SRTF
        insert_idx = rear;

        // sorted by remaining time
        for (i = rear - 1; i >= front; i--) {
            int cur = i % MAX_QUEUE_SIZE;
            int next = (i + 1) % MAX_QUEUE_SIZE;

            if (waiting_queue[cur].remaining_time > job.remaining_time) {
                waiting_queue[next] = waiting_queue[cur]; // Push back one space
            } else {
                break;
            }
        }
        insert_idx = (i + 1) % MAX_QUEUE_SIZE;
        waiting_queue[insert_idx] = job;
    }
    else if (policy == 3) { // Priority Scheduling
        insert_idx = rear;

        for (i = rear - 1; i >= front; i--) {
            int cur = i % MAX_QUEUE_SIZE;
            int next = (i + 1) % MAX_QUEUE_SIZE;

            if (waiting_queue[cur].priority > job.priority) {
                waiting_queue[next] = waiting_queue[cur];
            } else {
                break;
            }
        }
        insert_idx = (i + 1) % MAX_QUEUE_SIZE;
        waiting_queue[insert_idx] = job;
    }
    else { // FCFS, RR: simply insert
        waiting_queue[rear % MAX_QUEUE_SIZE] = job;
    }

    rear++;
    size++;

    return 0;
}

/* dequeue */
job_t ku_pop(void) {
    if (ku_is_empty()) {
        printk(KERN_WARNING "[jeongmin_dequeue] Queue is empty!\n");
        job_t null_job = {IDLE, 0, "", 0, 0};
        return null_job;
    }
    
    job_t ret = waiting_queue[front % MAX_QUEUE_SIZE];
    memset(&waiting_queue[front % MAX_QUEUE_SIZE], 0, sizeof(job_t));
    front++;
    size--;

    return ret;
}

static int handle_fcfs(job_t newJob) {
        // register the process if virtual CPU is idle
    if (now == IDLE)
        now = newJob.pid;

    // If the process that sent the request is currently using virtual CPU
    if (now == newJob.pid) {
        // If the job has finished
        if (newJob.job_time == 0) {
            printk(KERN_INFO "[FCFS] Process Finished: %s (pid: %d)\n", newJob.process_name, newJob.pid);

            // if queue is empty, virtual CPU becomes idle
            if (ku_is_empty()) {
                now = IDLE;
                return 0;
                }
            // if not, get next process from queue
            else {
                current_job = ku_pop();
                now = current_job.pid;
            }
            return 0;
        } else {
            current_job.remaining_time = newJob.remaining_time;
            printk(KERN_INFO "[FCFS] Working: %s (pid: %d)\n", newJob.process_name, newJob.pid);
        }

        // request accepted
        return 0;
    } else {
        // if the request is not from currently handling process
        if (ku_is_new_id(newJob.pid))
            ku_push(newJob, 0);

        printk(KERN_INFO "[FCFS] Working Denied: %s (pid: %d)\n", newJob.process_name, newJob.pid);
        // request rejected
        return 1;
    }
}

static int handle_srtf(job_t newJob) {
    if (now == IDLE) {
        now = newJob.pid;
        current_job = newJob;
        printk(KERN_INFO "[SRTF] Working: %s (pid: %d)\n", newJob.process_name, newJob.pid);
        return 0;
    }

    if (now == newJob.pid) {
        if (newJob.job_time == 0) {
            printk(KERN_INFO "[SRTF] Process Finished: %s (pid: %d)\n", newJob.process_name, newJob.pid);

            if (ku_is_empty()) {
                now = IDLE;
            } else {
                current_job = ku_pop();
                now = current_job.pid;
                printk(KERN_INFO "[SRTF] Working: %s (pid: %d)\n", current_job.process_name, current_job.pid);
            }
        } else {
            current_job.remaining_time = newJob.remaining_time;
            printk(KERN_INFO "[SRTF] Working: %s (pid: %d)\n", newJob.process_name, newJob.pid);
        }
        return 0;
    }
    // Preemption condition: 
    // If the remaining_time of the new job is shorter than that of the currently running job.
    if (newJob.remaining_time < current_job.remaining_time) {
        ku_push(current_job, 1);  // Return an existing job to the queue
        current_job = newJob;
        now = newJob.pid;
        printk(KERN_INFO "[SRTF] Preempted! New Working: %s (pid: %d)\n", newJob.process_name, newJob.pid);
        return 0;
    }

    if (ku_is_new_id(newJob.pid)) {
        ku_push(newJob, 1);  // policy 1 = SRTF
    }

    printk(KERN_INFO "[SRTF] Working Denied: %s (pid: %d)\n", newJob.process_name, newJob.pid);
    return 1;
}

static int time_slice_counter; // time 퀀텀 사용 횟수
static int finished[MAX_PID];
static int can_enqueue[MAX_PID]; // 0이면 대기큐에 enq 불가, 1일때 가능

static int handle_rr(job_t newJob) {    
    // 대기큐에 없던 새로운 프로세스 인 경우
    if (ku_is_new_id(newJob.pid)) {
        if (finished[newJob.pid] != 1) {
            ku_push(newJob,2);
            can_enqueue[newJob.pid] = 0; 
            return 1;
        }
    } 

    // 현재 cpu가 놀고 있는 경우
    if (now == IDLE) {

        if (ku_is_empty()) { 
            return 0;
            }
        
        time_slice_counter = 0;
        current_job = ku_pop();
        can_enqueue[current_job.pid] = 1;
        now = current_job.pid;
        current_job.remaining_time--;
        time_slice_counter++;

        printk(KERN_INFO "[RR] Working: %s (pid: %d)\n", current_job.process_name, current_job.pid);
        return 0;
    }
    // 현재 실행 중인 프로세스가 다시 syscall을 요청한 경우
    else if (now == newJob.pid) {
        current_job.remaining_time--;
        time_slice_counter++; // 타임 퀀텀 1회 사용
        
        // 남은 작업 시간이 0일 경우
        if (current_job.remaining_time <= 0) {
            printk(KERN_INFO "[RR] Finish: %s (pid: %d)\n", current_job.process_name, current_job.pid);
            
            finished[current_job.pid] = 1;
            can_enqueue[current_job.pid] = 0;
            
            now = IDLE;
            time_slice_counter = 0;
            
            return 0;
        }
        // 타임 퀀텀을 모두 사용한 경우
        if (time_slice_counter >= TIME_SLICE) {
            printk(KERN_INFO "[RR] Turn Over!: %s (pid: %d)\n", current_job.process_name, current_job.pid);
            
            ku_push(current_job, 2);
            can_enqueue[current_job.pid] = 0;

            now = IDLE;
            time_slice_counter = 0;
            
            return 0;
        }
        return 0;
    }
    // cpu가 다른 프로세스를 처리중인 경우
    else {
        printk(KERN_INFO "[RR] Working Denied: %s (pid: %d)\n", newJob.process_name, newJob.pid);
        if (can_enqueue[newJob.pid] == 1) ku_push(newJob,2);
        return 1;
    }

    return 1;
}

static int handle_priority(job_t newJob) {
    // If the CPU is idle, assign the current job
    if (now == IDLE) {
        now = newJob.pid;
        current_job = newJob;
        printk(KERN_INFO "[PRIORITY] Working: %s (pid: %d)\n", newJob.process_name, newJob.pid);
        return 0;
    }

    // If the requesting job is the one currently using the CPU
    if (now == newJob.pid) {
        if (newJob.job_time == 0) {
            printk(KERN_INFO "[PRIORITY] Process Finished: %s (pid: %d)\n", newJob.process_name, newJob.pid);

            if (ku_is_empty()) {
                now = IDLE;
            } else {
                current_job = ku_pop();
                now = current_job.pid;
                printk(KERN_INFO "[PRIORITY] Switch to: %s (pid: %d)\n", current_job.process_name, current_job.pid);
            }
        } else {
            current_job.remaining_time = newJob.remaining_time;
            printk(KERN_INFO "[PRIORITY] Working: %s (pid: %d)\n", newJob.process_name, newJob.pid);
        }
        return 0;
    }

    // If the new job has higher priority than the currently running one → preemption
    if (newJob.priority < current_job.priority) {
        ku_push(current_job, 3);  // Re-enqueue the current job
        current_job = newJob;
        now = newJob.pid;
        printk(KERN_INFO "[PRIORITY] Preempted! New Working: %s (pid: %d)\n", newJob.process_name, newJob.pid);
        return 0;
    }

    // Otherwise, insert into the waiting queue
    if (ku_is_new_id(newJob.pid)) {
        ku_push(newJob, 3);
    }

    printk(KERN_INFO "[PRIORITY] Working Denied: %s (pid: %d)\n", newJob.process_name, newJob.pid);
    return 1;
}


SYSCALL_DEFINE1(jeongmin_pid_print, char*, name) {
    pid_t pid = current->pid;

    printk("Process name: %s pid: %d\n", name, pid);

    return 0;
}

/* skeleton code */
SYSCALL_DEFINE4 (jeongmin_ku_cpu, int, jobTime, int, policy, int, priority, char *, name) {
    job_t newJob = {current->pid, jobTime, "", priority, jobTime};
    // store pid of current process as pid_t type
    // add name and priority for parameter since structure of job_t
    if (copy_from_user(newJob.process_name, name, sizeof(newJob.process_name))) {
        printk(KERN_ERR "[KU_CPU] copy_from_user failed\n");
        return -EFAULT;
    }
    printk(KERN_INFO "[KU_CPU] Got name: %s, jobTime: %d, policy: %d, priority: %d\n",
    newJob.process_name, jobTime, policy, priority);


        switch (policy) {
        case 0: return handle_fcfs(newJob);
        case 1: return handle_srtf(newJob);
        case 2: return handle_rr(newJob);
        case 3: return handle_priority(newJob);
        default:
            printk(KERN_WARNING "Unknown policy %d\n", policy);
            return -EINVAL;
    }
}
