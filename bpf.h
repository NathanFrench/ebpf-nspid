#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

static int (*bpf_probe_read)(void * dst, int size, void * unsafe_ptr) = (void *)BPF_FUNC_probe_read;
static int (* bpf_trace_printk)(const char * fmt, int fmt_size, ...) = (void *)BPF_FUNC_trace_printk;
static unsigned long long (* bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static u64 (* bpf_get_current_task)(void) = (void *)BPF_FUNC_get_current_task;

#endif
