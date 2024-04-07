#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "task_vma_iter_restore.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define MAX_VMA_SIZE 1 << 20

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
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_VMA_SIZE);
	__type(key, int);
	__type(value, struct check_payload);
} payloads SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ready_to_restore SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} fname_buf SEC(".maps");

static __u32 zero = 0;

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_openat(struct enter_openat *ctx)
{
	struct data_t data = {};

	int pid = bpf_get_current_pid_tgid() >> 32;
	data.pid = pid;
	bpf_probe_read_user(&data.path, sizeof(data.path), ctx->filename);

	char *fn = "/tmp/ready_to_restore";
	bool ischeck = true;
	for (int i = 0; i < 22; i++) {
		if (fn[i] != data.path[i])
			return 0;
	}
	bpf_printk("%s", data.path);
	bpf_perf_event_output(ctx, &fname_buf, BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
}

static long restore_chunk(__u32 index, struct check_payload *payload) {
	int i = index;
	payload = bpf_map_lookup_elem(&payloads, &i);
	if (payload == NULL) return 1;
	if (payload->curr_add == 0) return 1;
	int res = bpf_probe_write_user((void*)payload->curr_add, payload->data, sizeof(payload->data));
	bpf_printk("%d %lx: %d",i, payload->curr_add, res);
	// if (payload->curr_add == 0) return 1;
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_access")
int tp_sys_access(struct enter_access *ctx)
{
	int *rdy = bpf_map_lookup_elem(&ready_to_restore, &zero);
	if (rdy == NULL)
		return 0;
	if (*rdy == 0) return 0;
	// check if pid matches only then proceed
	struct check_payload *p;
	int zero = 0;
	p = bpf_map_lookup_elem(&payloads, &zero);
	if (p == NULL) return 0;
	int pi = (bpf_get_current_pid_tgid() >> 32);
	if (p->pid != pi) return 0;
	bpf_printk("Now ready to restore, %d, %d", p->pid, (bpf_get_current_pid_tgid() >> 32));
	struct check_payload p1 = {};
	bpf_loop(MAX_VMA_SIZE, restore_chunk, &p1, 0);
	bpf_map_update_elem(&ready_to_restore, &zero, &zero, 0);
	return 0;
}