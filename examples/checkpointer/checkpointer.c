// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 Meta */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include "checkpointer.h"
#include "checkpointer.skel.h"

int zero = 0, one = 1;

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

struct checkpoint_data checkpoint_data_handle;
void get_vmemory_states(struct checkpointer_bpf *skel, struct request_info *req_state)
{
	int iter_fd;
	struct vma_info buf;
	ssize_t ret;
	int err;
	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.get_task_vmas));
	if (iter_fd < 0) {
		err = -1;
		fprintf(stderr, "Failed to create iter\n");
		close(iter_fd);
	}
	int cd_ind = 0;
	while (true) {
		ret = read(iter_fd, &buf, sizeof(struct vma_info));
		if (ret < 0) {
			if (errno == EAGAIN)
				continue;
			err = -errno;
			break;
		}
		if (ret == 0) {
			break;
		}
		if (exiting) {
			break;
		}
		checkpoint_data_handle.vma_start[cd_ind] = buf.vma_start;
		checkpoint_data_handle.vma_end[cd_ind] = buf.vma_end;
		checkpoint_data_handle.chunk_count[cd_ind++] = (buf.vma_end - buf.vma_start) / 256;
		//printf(("%d\t %lx - %lx\n", buf.pid, buf.vma_start, buf.vma_end);
	}
	checkpoint_data_handle.vma_count = cd_ind;
	bpf_map__update_elem(skel->maps.checkpoint_data_handle, &zero, sizeof(zero),
			     &checkpoint_data_handle, sizeof(checkpoint_data_handle), 0);
	req_state->request_state = CHECKPOINTING_STATE;
	bpf_map__update_elem(skel->maps.request_state, &zero, sizeof(zero), req_state,
			     sizeof(*req_state), 0);
	//printf(("total vmas: %d\n", checkpoint_data_handle.vma_count);
	close(iter_fd);
	return;
}

struct checkpoint_payload checkpoint_data[10000];
int checkpoint_data_size = 0;
int prev_size = 0;
void wait_for_event(struct checkpointer_bpf *skel, struct request_info *req_state)
{
	//printf(("Now waiting for event\n");
	prev_size = checkpoint_data_size;
	checkpoint_data_size = 0;
	while (true) {
		if (exiting) {
			break;
		}
		bpf_map__lookup_elem(skel->maps.request_state, &zero, sizeof(zero), req_state,
				     sizeof(req_state), 0);
		if (req_state->request_state == WAITING_STATE)
			continue;
		break;
	}
}

void reset_to_waiting_state(struct checkpointer_bpf *skel, struct request_info *req_state)
{
	req_state->pid = -1;
	req_state->request_state = WAITING_STATE;
	bpf_map__update_elem(skel->maps.request_state, &zero, sizeof(zero), req_state,
			     sizeof(*req_state), 0);
}
void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	//printf(("lost event\n");
}
void handle_checkpoint_data(void *ctx, int cpu, void *data, unsigned int data_size)
{
	struct checkpoint_payload *p = data;
	checkpoint_data[checkpoint_data_size++] = *p;
	// printf("ca: %lx\n", p->curr_add);
}

bool allzero(char *arr)
{
	for (int i = 0; i < 256; i++) {
		if (arr[i] != 0)
			return false;
	}
	return true;
}

void wait_for_restored_state(struct checkpointer_bpf *skel, struct request_info *req_state)
{
	while (true) {
		if (exiting)
			break;
		bpf_map__lookup_elem(skel->maps.request_state, &zero, sizeof(zero), req_state,
				     sizeof(req_state), 0);
		if (req_state->request_state == RESTORED_STATE)
			break;
	}
	reset_to_waiting_state(skel, req_state);

	//printf(("Restore is complete\n");
	FILE *checkpoint_complete = fopen("/tmp/restore_complete", "w");
	fclose(checkpoint_complete);
}

void wait_for_checkpoint_data(struct checkpointer_bpf *skel, struct request_info *req_state,
			      struct perf_buffer *pb_c)
{
	while (true) {
		if (exiting) {
			break;
		}
		perf_buffer__poll(pb_c, 100);
		bpf_map__lookup_elem(skel->maps.request_state, &zero, sizeof(zero), req_state,
				     sizeof(req_state), 0);
		if (req_state->request_state == SAVED_STATE)
			break;
	}

	//printf(("Collected data, writing %d to file...\n", checkpoint_data_size);
	FILE *checkpoint_file = fopen("checkpointed_256.dat", "w");
	for (int i = 0; i < checkpoint_data_size; i++) {
		if (allzero(checkpoint_data[i].data))
			continue;
		fprintf(checkpoint_file, "%lx: ", checkpoint_data[i].curr_add);
		for (int j = 0; j < 256; j++)
			fprintf(checkpoint_file, "%02x", checkpoint_data[i].data[j] & 0xFF);
		fprintf(checkpoint_file, "\n");
	}
	fclose(checkpoint_file);
	reset_to_waiting_state(skel, req_state);

	//printf(("Now signalling the process for checkpoint to complete\n");
	FILE *checkpoint_complete = fopen("/tmp/checkpoint_complete", "w");
	fclose(checkpoint_complete);
}

int main(int argc, char **argv)
{
	struct checkpointer_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Open, load, and verify BPF application */
	skel = checkpointer_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = checkpointer_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* initialize request state */
	struct request_info req_state;

	reset_to_waiting_state(skel, &req_state);

	/* Initialize the buffer to capture the checkpoint datas*/
	struct perf_buffer *pb_c = NULL;
	pb_c = perf_buffer__new(bpf_map__fd(skel->maps.checkpoint_buffer), 8,
				handle_checkpoint_data, lost_event, NULL, NULL);

	/* This is the point where our actual wait loop starts */
	while (true) {
		/* wait for some process to request for checkpoint or restore */
		wait_for_event(skel, &req_state);
		if (req_state.pid == -1) {
			//printf(("no process found to profile, exiting\n");
			break;
		}
		//printf(("Request initiated for process: %d\n", req_state.pid);
		/* Based on the mode either restore of checkpoint */
		if (req_state.request_state == SAVING_STATE) {
			//printf(("Request for checkpointing received\n");
			/* Gather all the vm areas */
			get_vmemory_states(skel, &req_state);
			wait_for_checkpoint_data(skel, &req_state, pb_c);

		} else if (req_state.request_state == RESTORING_STATE) {
			//printf(("Request for restoring received\n");
			//printf(("\nLoading the checkpoint data\n");
			checkpoint_data_size = prev_size;
			for (int i = 0; i < checkpoint_data_size; i++) {
				bpf_map__update_elem(skel->maps.write_payloads, &i, sizeof(i),
						     &checkpoint_data[i],
						     sizeof(checkpoint_data[i]), 0);
			}
			req_state.request_state = LOADING_FOR_RESTORING;
			bpf_map__update_elem(skel->maps.request_state, &zero, sizeof(zero),
					     &req_state, sizeof(req_state), 0);
			//printf(("Loaded, now waiting for restored state\n");
			wait_for_restored_state(skel, &req_state);
		} else {
			//printf(("Unknown request, exiting\n");
			break;
		}

		// reset_to_waiting_state(skel, &req_state);
	}

cleanup:
	/* Clean up */
	checkpointer_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
