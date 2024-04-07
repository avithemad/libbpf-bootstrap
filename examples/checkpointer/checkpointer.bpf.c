// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 Meta */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "checkpointer.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct request_info);
} request_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1 << 26);
} checkpoint_buffer SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct checkpoint_data);
} checkpoint_data_handle SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 10000);
	__type(key, int);
	__type(value, struct checkpoint_payload);
} write_payloads SEC(".maps");

static __u32 zero = 0;
static __u32 one = 1;

SEC("iter/task_vma")
int get_task_vmas(struct bpf_iter__task_vma *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct vm_area_struct *vma = ctx->vma;
	struct vma_info t;

	/* Check if the process is same as the one user is working on */
	struct request_info *req_state;
	req_state = bpf_map_lookup_elem(&request_state, &zero);
	if (req_state == NULL)
		return 0;
	if (!vma)
		return 0;
	if (req_state->pid != vma->vm_mm->owner->tgid)
		return 0;

	/* Check if the vma region is anononymous */
	unsigned long stack_start = vma->vm_mm->start_stack & 0xFFFFFFFFFFFFF000;
	unsigned long stack_end = vma->vm_mm->start_stack + (vma->vm_mm->stack_vm << 12);
	if (vma->vm_ops != NULL) {
		return 0;
	} 
	/* Ignore stack region */
	if (vma->vm_start >= stack_start && vma->vm_start <= stack_end)
		return 0;
	if (vma->vm_end >= stack_start && vma->vm_end <= stack_end)
		return 0;

	t.pid = vma->vm_mm->owner->tgid;
	t.vma_start = vma->vm_start;
	t.vma_end = vma->vm_end;

	bpf_seq_write(seq, &t, sizeof(struct vma_info));
	return 0;
}

int len(char *c)
{
	int i = 0;
	if (c == NULL)
		return 0;
	while (c[i++] != '\0')
		;
	return i;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_openat(struct enter_openat *ctx)
{
	/* Check if our user process is in waiting state first */
	/* return if its not waiting, since its busy restoring or checkpointing*/
	struct request_info *req_state;
	req_state = bpf_map_lookup_elem(&request_state, &zero);
	if (req_state == NULL)
		return 0;
	if (req_state->request_state != WAITING_STATE)
		return 0;

	/* Now check if we need to checkpoint or restore */
	int pid = bpf_get_current_pid_tgid() >> 32;
	char *checkpoint_file = "/tmp/ready_to_checkpoint";
	char *restore_file = "/tmp/ready_to_restore";

	char filename[40];
	bpf_probe_read_user(&filename, sizeof(filename), ctx->filename);

	bool isCheckpoint = true;
	for (int i = 0; i < len(checkpoint_file) % 40; i++) {
		if (filename[i] != checkpoint_file[i]) {
			isCheckpoint = false;
			break;
		}
	}
	if (isCheckpoint) {
		req_state->pid = pid;
		req_state->request_state = SAVING_STATE;
		bpf_map_update_elem(&request_state, &zero, req_state, 0);
		return 0;
	}
	bool isRestore = true;
	for (int i = 0; i < len(restore_file) % 40; i++) {
		if (filename[i] != restore_file[i]) {
			isRestore = false;
			break;
		}
	}
	if (isRestore) {
		req_state->pid = pid;
		req_state->request_state = RESTORING_STATE;
		bpf_map_update_elem(&request_state, &zero, req_state, 0);
		return 0;
	}
	return 0;
}

static long publish_user_data(__u32 index, struct checkpoint_payload *payload)
{
	unsigned long ptr = payload->vma_start + index * 256;
	/* Check if you are at the last VMA indeed */
	struct checkpoint_data *data_handle;
	data_handle = bpf_map_lookup_elem(&checkpoint_data_handle, &zero);
	if (data_handle != NULL) {
		int last_ind = data_handle->vma_count - 1;
		if (last_ind >= 0 && last_ind < 10000) {
			unsigned long last_vma = data_handle->vma_end[last_ind];

			if (ptr > last_vma) {
				struct request_info *req_state;
				req_state = bpf_map_lookup_elem(&request_state, &zero);
				// bpf_printk(
				// 	"path for final address check ptr - %lx, last_vma - %lx\n",
				// 	ptr, last_vma);
				if (req_state != NULL) {
					req_state->request_state = SAVED_STATE;
					bpf_map_update_elem(&request_state, &zero, req_state, 0);
				}
				return 1;
			}
		}
	}

	if (ptr > payload->vma_end) {
		// bpf_printk("path for inter final address check ptr - %lx, last_vma - %lx\n", ptr,
		// 	   payload->vma_end);

		return 1; // exit the loop
	}
	payload->curr_add = ptr;
	bpf_probe_read_user(payload->data, sizeof(payload->data), (void *)ptr);
	// this is to debug the checkpoint
	// bpf_printk("%d, %lx: %s\n", index, payload->curr_add, payload->data);
	bpf_perf_event_output(payload->ctx, &checkpoint_buffer, BPF_F_CURRENT_CPU, payload,
			      sizeof(*payload));
	return 0;
}

static long restore_chunk(__u32 index, struct checkpoint_payload *payload)
{
	int i = index;
	payload = bpf_map_lookup_elem(&write_payloads, &i);
	if (payload == NULL) {
		struct request_info *req_state;
		req_state = bpf_map_lookup_elem(&request_state, &zero);
		if (req_state != NULL) {
			req_state->request_state = RESTORED_STATE;
			bpf_map_update_elem(&request_state, &zero, req_state, 0);
		}
		return 1;
	}
	if (payload->curr_add == 0) {
		struct request_info *req_state;
		req_state = bpf_map_lookup_elem(&request_state, &zero);
		if (req_state != NULL) {
			req_state->request_state = RESTORED_STATE;
			bpf_map_update_elem(&request_state, &zero, req_state, 0);
		}
		return 1;
	}
	int res = bpf_probe_write_user((void *)payload->curr_add, payload->data,
				       sizeof(payload->data));
	// bpf_printk("%d %lx: %d", i, payload->curr_add, res);
	// if (payload->curr_add == 0) return 1;
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_access")
int tp_sys_access(struct enter_access *ctx)
{
	/* First check if we are in checkpointing or restoring mode */
	char chunk[256];
	struct request_info *req_state;
	req_state = bpf_map_lookup_elem(&request_state, &zero);
	if (req_state == NULL)
		return 0;
	if (req_state->request_state == LOOPING_STATE || req_state->request_state == WAITING_STATE)
		return 0;
	if (req_state->request_state == RESTORED_STATE || req_state->request_state == SAVED_STATE)
		return 0;
	int pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != req_state->pid)
		return 0;
	/* If in saving state, then do the save */
	if (req_state->request_state == CHECKPOINTING_STATE) {
		req_state->request_state = LOOPING_STATE;
		bpf_map_update_elem(&request_state, &zero, req_state, 0);
		struct checkpoint_data *data_handle;
		data_handle = bpf_map_lookup_elem(&checkpoint_data_handle, &zero);
		if (data_handle == NULL)
			return 0;
		for (int i = 0; i < 1000; i++) {
			if (i >= data_handle->vma_count)
				break;

			struct checkpoint_payload p = {};
			p.vma_start = data_handle->vma_start[i];
			p.vma_end = data_handle->vma_end[i];
			p.ctx = ctx;
			bpf_loop(1 << 23, publish_user_data, &p, 0);
		}
		// req_state->request_state = SAVED_STATE;
		// bpf_map_update_elem(&request_state, &zero, req_state, 0);
	} else if (req_state->request_state == LOADING_FOR_RESTORING) {
		req_state->request_state = LOOPING_STATE;
		bpf_map_update_elem(&request_state, &zero, req_state, 0);
		struct checkpoint_payload *p = bpf_map_lookup_elem(&write_payloads, &zero);
		if (p == NULL) {
			// bpf_printk("write payloads is null");
			return 0;
		}
		struct checkpoint_payload p1 = {};
		bpf_loop(10000, restore_chunk, &p1, 0);
	}

	/* If in restoring state, then do the restore */
	return 0;
}
