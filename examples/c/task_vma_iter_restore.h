struct task_vma_info {
    pid_t pid;
    pid_t tid;
    int curr_pid;
    unsigned long vma_start;
    unsigned long vma_end;
};

struct task_vma_areas_info {
    pid_t pid;
    int vma_count;
    unsigned long vma_start[10000];
    unsigned long vma_end[10000];
    long size[10000];
};

struct data_t {
   int pid;
   char path[25];
};

struct check_payload {
    unsigned long vma_start;
    unsigned long curr_add;
    unsigned long vma_end;
    int pid;
    char data[256];
    void* ctx;
};

