#include <linux/bpf.h>
#include <linux/ptrace.h>
#include "include/bpf_helpers.h"

struct bpf_map_def SEC("maps/open_event") open_event = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 128,
	.pinning = 0,
	.namespace = "",
};

struct data_t {
	__u32 pid;
	char file_name[256];
};

SEC("kprobe/do_sys_open")
int kprobe__do_sys_open(struct pt_regs *ctx) {
		struct data_t data = {};

		data.pid = bpf_get_current_pid_tgid() >> 32;
		__u32 cpu = bpf_get_smp_processor_id();

		bpf_probe_read(&data.file_name, sizeof(data.file_name), PT_REGS_PARM2(ctx));

		bpf_perf_event_output(ctx, &open_event, cpu, &data, sizeof(data));

		return 0;
}

char _license[] SEC("license") = "GPL";
