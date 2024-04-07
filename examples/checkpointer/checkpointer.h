/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Meta */

#define TASK_COMM_LEN 16
#define MAX_STACK_LEN 127

#define WAITING_STATE 0
#define SAVING_STATE 1
#define CHECKPOINTING_STATE 5
#define SAVED_STATE 2
#define RESTORING_STATE 3
#define RESTORED_STATE 4
#define LOOPING_STATE 6
#define LOADING_FOR_RESTORING 7

struct request_info {
	int pid;
	int request_state;
};

struct vma_info {
	pid_t pid;
	unsigned long vma_start;
	unsigned long vma_end;
};

struct enter_openat {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	long syscall_nr;
	long dfd;
	char *filename;
	int flags;
	unsigned short mode;
};
struct enter_access {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	long syscall_nr;
	char *filename;
	unsigned short mode;
};

struct checkpoint_payload {
    unsigned long vma_start;
    unsigned long vma_end;
    unsigned long curr_add;
    char data[256];
    void* ctx;
};

struct checkpoint_data {
	int vma_count;
	unsigned long vma_start[10000];
	unsigned long vma_end[10000];
	int chunk_count[10000];
};