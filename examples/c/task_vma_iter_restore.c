#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include "task_vma_iter_restore.h"
#include "task_vma_iter_restore.skel.h"

#define MAX_VMAS  1000
#define MAX_PROCS 100

static struct env {
	bool verbose;
} env;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}
static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

struct vma_regions {
	int taskid;
	unsigned long start[MAX_VMAS];
	unsigned long end[MAX_VMAS];
};

struct data_t target_process;

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct data_t *m = data;

	for (int i = 0; i < 25; i++) {
		target_process.path[i] = m->path[i];
	}
	target_process.pid = m->pid;
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

struct check_payload final_data[10000];
int final_data_ind = 0;

bool allzero(char *arr)
{
	for (int i = 0; i < 256; i++) {
		if (arr[i] != 0)
			return false;
	}
	return true;
}
void handle_cdata(void *ctx, int cpu, void *data, unsigned int data_size)
{
	struct check_payload *p = data;
	final_data[final_data_ind++] = *p;
}

int vmareas_size = 0;

int wait_for_restore_file(struct task_vma_iter_restore_bpf *skel)
{
	struct perf_buffer *pb = NULL;
	int err;
	pb = perf_buffer__new(bpf_map__fd(skel->maps.fname_buf), 8, handle_event, lost_event, NULL,
			      NULL);

	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		task_vma_iter_restore_bpf__destroy(skel);
		return 1;
	}
	char *checkpoint_file = "/tmp/ready_to_restore";
	printf("Waiting for a restore file\n");
	while (true) {
		perf_buffer__poll(pb, 0);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		if (strcmp(checkpoint_file, target_process.path) == 0) {
			// reset the filename
			target_process.path[0] = '\0';
			break;
		}
		if (exiting)
			break;
	}
	printf("Found restore file\n");
	perf_buffer__free(pb);
	return 0;
}
static int event_handler(void *_ctx, void *data, size_t size)
{
	char *dat = data;
	printf("data: %s\n", dat);
}

static void read_checkpoint_data()
{
	FILE *fptr = fopen("checkpointed_256.dat", "r");
	unsigned long add;
	char bytestream[512];
	char actual[256];
	int k = 0;
	while (fscanf(fptr, "%lx: %s", &add, bytestream) != EOF) {
		for (int i = 0, j = 0; i < 256; i++, j += 2) {
			sscanf(&bytestream[j], "%2hhx", &actual[i]);
		}
		if (allzero(actual)) {
			continue;
		}
		for (int i = 0; i < 256; i++) {
			final_data[k].data[i] = actual[i];
		}
		final_data[k].pid = target_process.pid;
		final_data[k++].curr_add = add;
	}
	fclose(fptr);
	final_data_ind = k;
}
int main(int argc, char **argv)
{
	struct task_vma_iter_restore_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = task_vma_iter_restore_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		goto cleanup;
	}
	err = task_vma_iter_restore_bpf__attach(skel);
	/* Attach tracepoints */
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	/* Open, load, and verify BPF application */
	while (true) {
		int zero = 0, one = 1;
		wait_for_restore_file(skel);
		printf("Loading the checkpoint data\n");
		read_checkpoint_data();
		for (int i = 0; i < final_data_ind; i++) {
			bpf_map__update_elem(skel->maps.payloads, &i, sizeof(i), &final_data[i],
					     sizeof(final_data[i]), 0);
		}
		bpf_map__update_elem(skel->maps.ready_to_restore, &zero, sizeof(zero), &one,
				     sizeof(one), 0);
		printf("pid: %d, payloadsize: %d\n", final_data[0].pid, final_data_ind);
		while (true & final_data_ind != 0) {
			if (exiting)
				break;
			int val;
			bpf_map__lookup_elem(skel->maps.ready_to_restore, &zero, sizeof(zero), &val,
					     sizeof(val), 0);
			if (val == 1) {
				continue;
			} else if (val == 0) {
				printf("Done writing the data");
				break;
			}
		}
		if (exiting)
			break;
		FILE *checkpoint_complete = fopen("/tmp/restore_complete", "w");
		fclose(checkpoint_complete);
		// sleep(0.1);
		// remove("/tmp/checkpoint_complete");
		bpf_map__update_elem(skel->maps.ready_to_restore, &zero, sizeof(zero), &zero,
				     sizeof(zero), 0);
		// goto cleanup;
	}

cleanup:
	/* Clean up */
	task_vma_iter_restore_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}