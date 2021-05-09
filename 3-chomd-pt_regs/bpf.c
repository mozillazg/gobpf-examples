#include <linux/bpf.h>
#include <linux/ptrace.h>
#include "include/bpf_helpers.h"

struct bpf_map_def SEC("maps/fchmodat_event") fchmodat_event = {
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
    __u32 mode;
};

SEC("kprobe/do_fchmodat")
int kprobe__do_fchmodat(struct pt_regs *ctx) {
		struct data_t data = {0};
		data.pid = bpf_get_current_pid_tgid() >> 32;

        char *filename = (char *)PT_REGS_PARM2(ctx);
        unsigned int mode = PT_REGS_PARM3(ctx);

		bpf_probe_read(&data.file_name, sizeof(data.file_name), filename);

        data.mode = (__u32) mode;

		bpf_perf_event_output(ctx, &fchmodat_event, BPF_F_CURRENT_CPU, &data, sizeof(data));

		return 0;
}

char _license[] SEC("license") = "GPL";
