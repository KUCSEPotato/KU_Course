#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/linkage.h>

#define MAX_QUEUE_SIZE 128

static int queue[MAX_QUEUE_SIZE];
static int front = 0;
static int rear = 0;
static int size = 0;

static int check_duplicate(int val) {
    int i;
    for (i = front; i < rear; i++) {
	if (queue[i % MAX_QUEUE_SIZE] == val) {
	    return 1;
	}
    }
    return 0;
}

// Enqueue system call
SYSCALL_DEFINE1(jeongmin_enqueue, int, a) {
    int i;
    printk(KERN_INFO "[System call] jeongmin_enqueue(); -----\n");
    printk(KERN_INFO "[jeongmin_enqueue] called with value = %d\n", a);

    if (size > MAX_QUEUE_SIZE) {
	printk(KERN_WARNING "[Error][jeongmin_enqueue] Queue is full!\n");
	return -1;
    }

    if (check_duplicate(a)) {
	printk(KERN_WARNING "[Error][jeongmin_enqueue] Already existing value: %d\n", a);
	return -2;
    }

    queue[rear % MAX_QUEUE_SIZE] = a;
    rear++;
    size++;

    printk(KERN_INFO "[jeongmin_enqueue] Enqueued: %d\n", a);

    printk(KERN_INFO "Queue Front---------------------\n");

    for (i = front; i < rear; i++) {
	printk(KERN_INFO "%d\n", queue[i % MAX_QUEUE_SIZE]);
    }

    printk(KERN_INFO "Queue Rear----------------------\n");

    return 0;
}

// Dequeue system call
SYSCALL_DEFINE0(jeongmin_dequeue) {
    int i;
    int result;
    printk(KERN_INFO "[System call] jeongmin_dequeue(); -----\n");

    if (size == 0) {
	printk(KERN_WARNING "[jeongmin_dequeue] Queue is empty!\n");
	return -1;
    }

    result = queue[front % MAX_QUEUE_SIZE];
    front++;
    size--;

    printk(KERN_INFO "[jeongmin_dequeue] Dequeued: %d\n", result);

    printk(KERN_INFO "Queue Front---------------------\n");

    for (i = front; i < rear; i++) {
        printk(KERN_INFO "%d\n", queue[i % MAX_QUEUE_SIZE]);
    }

    printk(KERN_INFO "Queue Rear----------------------\n");

    return result;
}
