#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include "task_vma_iter.h"
#include "task_vma_iter.skel.h"

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
unsigned long final_data_ind = 0;

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
	printf("handle_cdata: %lx, %s\n", p->curr_add, p->data);
	if (!allzero(p->data))
		final_data[final_data_ind++] = *p;
}

int vmareas_size = 0;

void wait_for_data_gathering(struct task_vma_iter_bpf *skel)
{
	struct perf_buffer *pb_c = NULL;
	pb_c = perf_buffer__new(bpf_map__fd(skel->maps.cp_payload_buf), 16, handle_cdata, lost_event,
				NULL, NULL);

	while (true) {
		perf_buffer__poll(pb_c, 100);
		__u32 val;
		int z = 0;
		bpf_map__lookup_elem(skel->maps.ready_to_checkpoint, &z, sizeof(z), &val,
				     sizeof(val), 0);
		if (exiting)
			break;
		if (val == 1)
			continue;
		break;
		// sleep(1);
	}
}

int wait_for_checkpoint_file(struct task_vma_iter_bpf *skel)
{
	struct perf_buffer *pb = NULL;
	int err;
	pb = perf_buffer__new(bpf_map__fd(skel->maps.fname_buf), 8, handle_event, lost_event, NULL,
			      NULL);

	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		task_vma_iter_bpf__destroy(skel);
		return 1;
	}
	char *checkpoint_file = "/tmp/ready_to_checkpoint";
	printf("waiting for a checkpoint file\n");
	while (true) {
		perf_buffer__poll(pb, 100);
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
	printf("found for a checkpoint file\n");
	perf_buffer__free(pb);
	return 0;
}
int gather_vma_regions(struct task_vma_iter_bpf *skel)
{
	int ind = 0;
	int f = 0;
	bpf_map__update_elem(skel->maps.ready_to_checkpoint, &ind, sizeof(ind), &f, sizeof(f), 0);
	// this part is in order to gather the VMA regions in a file.
	struct task_vma_info buf;
	ssize_t ret;
	int err;
	int iter_fd = bpf_iter_create(bpf_link__fd(skel->links.get_task_vmas));
	if (iter_fd < 0) {
		err = -1;
		fprintf(stderr, "Failed to create iter\n");
		return -1;
	}
	// FILE *fptr = fopen("/tmp/vma_regions", "w");
	struct task_vma_areas_info vmareas;
	int i = 0;
	while (true) {
		ret = read(iter_fd, &buf, sizeof(struct task_vma_info));

		if (ret < 0) {
			if (errno == EAGAIN)
				continue;
			err = -errno;
			break;
		}
		if (ret == 0) {
			// Need to break here, but for now just keeping on scanning
			printf("Gathered VMA regions, now saving them to file...\n\n");
			break;
		}
		if (exiting) {
			break;
		}
		if (buf.pid == target_process.pid) {
			// fprintf(fptr, "%d %lx %lx\n", buf.pid, buf.vma_start, buf.vma_end);
			unsigned long start_add = buf.vma_start;
			unsigned long end_add = buf.vma_end;
			vmareas.vma_start[i] = start_add;
			vmareas.vma_end[i] = end_add;
			vmareas.size[i] = buf.vma_end - buf.vma_start;
			i++;
			vmareas_size += ((end_add - start_add) / 256);
			printf("%lx-%lx\n", buf.vma_start, buf.vma_end);
		}
	}
	vmareas.vma_count = i;
	vmareas.pid = target_process.pid;
	bpf_map__update_elem(skel->maps.vma_regions, &ind, sizeof(ind), &vmareas, sizeof(vmareas),
			     0);
	int t = 1;
	bpf_map__update_elem(skel->maps.ready_to_checkpoint, &ind, sizeof(ind), &t, sizeof(t), 0);
	// fclose(fptr);
	close(iter_fd);
	return 0;
}
static int event_handler(void *_ctx, void *data, size_t size)
{
	char *dat = data;
	printf("data: %s\n", dat);
}
int main(int argc, char **argv)
{
	struct task_vma_iter_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = task_vma_iter_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		goto cleanup;
	}
	err = task_vma_iter_bpf__attach(skel);
	/* Attach tracepoints */
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	/* Open, load, and verify BPF application */
	while (true) {
		wait_for_checkpoint_file(skel);
		if (gather_vma_regions(skel) == -1)
			goto cleanup;
		if (exiting)
			goto cleanup;
		wait_for_data_gathering(skel);
		printf("data collected in 256 chunks: %ld\n", final_data_ind);
		// if (final_data_ind != 0) {
		FILE *checkpoint_file = fopen("checkpointed_256.dat", "w");
		for (int i = 0; i < final_data_ind; i++) {
			fprintf(checkpoint_file, "%lx: ", final_data[i].curr_add,
				final_data[i].data);
			for (int j = 0; j < 256; j++)
				fprintf(checkpoint_file, "%02x", final_data[i].data[j] & 0xFF);
			fprintf(checkpoint_file, "\n");
		}
		fclose(checkpoint_file);
		// }
		final_data_ind = 0;
		FILE *checkpoint_complete = fopen("/tmp/checkpoint_complete", "w");
		fclose(checkpoint_complete);
		// sleep(0.1);
		// remove("/tmp/checkpoint_complete");
		int ind = 0;
		int f = 0;
		bpf_map__update_elem(skel->maps.ready_to_checkpoint, &ind, sizeof(ind), &f,
				     sizeof(f), 0);

		// goto cleanup;
	}

cleanup:
	/* Clean up */
	task_vma_iter_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}