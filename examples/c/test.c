#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>

int main() {
    char* x = "/tmp/ready_to_checkpoint";
    char* y = (char*)malloc(sizeof(int)*100);
    for (int i='a'; i<'z'; i++) {
        y[i-'a'] = i;
    }
    printf("pid: %d\n", getpid());
    char* x1 = (char*)malloc(sizeof(char)*100);
    printf("BEF CKPT:\t%s, %lx\n", y, y);
    // save the context
    FILE *fptr = fopen("/tmp/ready_to_checkpoint", "w");
    fclose(fptr);
    while(access("/tmp/checkpoint_complete", F_OK)) {
        sleep(1);
    }
    for (int i='a'; i<'z'; i++) {
        y[i-'a'] = 'a' + ('z' - i);
    }
    printf("AFT CKPT:\t%s, %lx\n", y, y);
    // sleep(10);
    printf("Now ready to restore\n");
    FILE *fptr_1 = fopen("/tmp/ready_to_restore", "w");
    fclose(fptr_1);
    while(access("/tmp/restore_complete", F_OK)) {
        sleep(1);
    }

    printf("AFT REST:\t%s, %lx\n", y, y);

    // recover the contex

}