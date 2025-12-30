#include <stdio.h>
#include <unistd.h>

#define jeongmin_enqueue 335
#define jeongmin_dequeue 336

int main() {
    int ret;

    syscall(jeongmin_enqueue, 1);
    printf("Enqueue : 1\n");

    syscall(jeongmin_enqueue, 2);
    printf("Enqueue : 2\n");

    syscall(jeongmin_enqueue, 3);
    printf("Enqueue : 3\n");

    syscall(jeongmin_enqueue, 3);
    printf("Enqueue : 3\n");

    ret = syscall(jeongmin_dequeue);
    printf("Dequeue : %d\n", ret);

    ret = syscall(jeongmin_dequeue);
    printf("Dequeue : %d\n", ret);

    ret = syscall(jeongmin_dequeue);
    printf("Dequeue : %d\n", ret);

    return 0;
}
