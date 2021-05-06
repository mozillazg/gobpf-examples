#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <bpf_helpers.h>

SEC("kprobe/do_sys_open")
int kprobe__do_sys_open(struct pt_regs *ctx)
{
		char file_name[256];

		bpf_probe_read(file_name, sizeof(file_name), PT_REGS_PARM2(ctx));

		char fmt[] = "open file %s\n";
		bpf_trace_printk(fmt, sizeof(fmt), &file_name);

		return 0;
}

char _license[] SEC("license") = "GPL";
