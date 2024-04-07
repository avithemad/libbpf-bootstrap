#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "task_vma_iter.h"
// #include <linux/mm_types.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct enter_openat {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	long syscall_nr;
	long dfd;
	char *filename;
	int flags;
	umode_t mode;
};
struct enter_access {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	long syscall_nr;
	char *filename;
	umode_t mode;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct task_vma_info);
} task_vma_info_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ready_to_checkpoint SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} fname_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1 << 26);
} cp_payload_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct task_vma_areas_info);
} vma_regions SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} cdata_buf SEC(".maps");

static __u32 zero = 0;

SEC("iter/task_vma")
int get_task_vmas(struct bpf_iter__task_vma *ctx)
{
	// ignore non anonymous memory

	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct vm_area_struct *vma = ctx->vma;
	struct task_vma_info *t;

	if (!vma)
		return 0;
	if (vma->vm_ops)
		return 0;

	unsigned long stack_start = vma->vm_mm->start_stack & 0xFFFFFFFFFFFFF000;
	unsigned long stack_end = vma->vm_mm->start_stack + (vma->vm_mm->stack_vm<<12);
	if (vma->vm_start >= stack_start && vma->vm_start <= stack_end) return 0;
	if (vma->vm_end >= stack_start && vma->vm_end <= stack_end) return 0;
	t = bpf_map_lookup_elem(&task_vma_info_buf, &zero);
	int pid = bpf_get_current_pid_tgid() >> 32;
	if (!t)
		return 0;
	t->pid = vma->vm_mm->owner->tgid;
	t->tid = vma->vm_mm->owner->pid;
	t->vma_start = vma->vm_start;
	t->vma_end = vma->vm_end;
	t->curr_pid = pid;

	bpf_printk("%d, %lx - %lx", t->pid, t->vma_start, t->vma_end);
	// bpf_printk("stack_start:%lx, stack_end:%lx, end code: %lx, end data: %lx", vma->vm_mm->start_stack, 
	// 		vma->vm_mm->start_stack + (vma->vm_mm->stack_vm<<12), vma->vm_mm->end_code,
	// 		vma->vm_mm->end_data);
	bpf_seq_write(seq, t, sizeof(struct task_vma_info));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_openat(struct enter_openat *ctx)
{
	struct data_t data = {};

	int pid = bpf_get_current_pid_tgid() >> 32;
	data.pid = pid;
	bpf_probe_read_user(&data.path, sizeof(data.path), ctx->filename);

	char *fn = "/tmp/ready_to_checkpoint";
	bool ischeck = true;
	for (int i = 0; i < 25; i++) {
		if (fn[i] != data.path[i])
			return 0;
	}
	bpf_perf_event_output(ctx, &fname_buf, BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
}

static long gather_vms(__u32 index, struct check_payload *payload)
{
	unsigned long ptr = payload->vma_start + index * 256;
	if (ptr > payload->vma_end)
		return 1; // exit the loop
	unsigned long temp = payload->vma_start;
	payload->curr_add = ptr;
	bpf_probe_read_user(payload->data, sizeof(payload->data), (void *)ptr);
	// this is to debug the checkpoint
	bpf_printk("%d, %lx: %s\n", index, payload->curr_add, payload->data);
	bpf_perf_event_output(payload->ctx, &cp_payload_buf, BPF_F_CURRENT_CPU, payload,
			      sizeof(*payload));
	return 0;
}

#define MAXVMAS	     500
#define MAX_VMA_SIZE 1 << 23

SEC("tracepoint/syscalls/sys_enter_access")
int tp_sys_access(struct enter_access *ctx)
{
	int *rdy = bpf_map_lookup_elem(&ready_to_checkpoint, &zero);
	if (rdy == NULL)
		return 0;
	if (*rdy == 0) return 0; 
		struct task_vma_areas_info *t;
		int pid = bpf_get_current_pid_tgid() >> 32;
		t = bpf_map_lookup_elem(&vma_regions, &zero);
		if (t != NULL) {
			if (t->pid != pid)
				return 0;
			for (int i = 0; i < MAXVMAS; i++) {
				if (i > t->vma_count)
					break;

				struct check_payload p = {};
				p.vma_start = t->vma_start[i];
				p.vma_end = t->vma_end[i];
				p.ctx = ctx;
			bpf_printk("CHECKPOINTER: sys_enter_access: vma_regions.size:-> %d: %lx\n",
				   t->vma_count, t->vma_start[i]);
				bpf_loop(MAX_VMA_SIZE, gather_vms, &p, 0);
			}
		}
		int tr = 0;
		bpf_map_update_elem(&ready_to_checkpoint, &zero, &tr, 0);
	
	return 0;
}