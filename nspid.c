#include <unistd.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>

#include "bpf.h"

#define _inline inline __attribute__((always_inline))

#define _dprintk(fmt, ...)                                          \
    ({                                                              \
        char ____fmt[] = fmt;                                       \
        bpf_trace_printk(____fmt, sizeof(____fmt), ## __VA_ARGS__); \
    })


#define _(P) ({                                  \
        typeof(P)_val;                           \
        memset(&_val, 0, sizeof(_val));          \
        bpf_probe_read(&_val, sizeof(_val), &P); \
        _val;                                    \
    })


/*
 * static inline struct pid *task_pid(struct task_struct *task)
 * {
 *  return task->pids[PIDTYPE_PID].pid;
 * }
 */
static _inline struct pid *
bpf__task_pid(struct task_struct * task)
{
    return _(task->pids[PIDTYPE_PID].pid);
}

/*
 * static inline struct pid_namespace *ns_of_pid(struct pid *pid)
 * {
 *  struct pid_namespace *ns = NULL;
 *  if (pid)
 *      ns = pid->numbers[pid->level].ns;
 *  return ns;
 * }
 */
static _inline struct pid_namespace *
bpf__ns_of_pid(struct pid * pid)
{
    struct pid_namespace * ns = NULL;

    if (pid != NULL) {
        ns = _(pid->numbers[_(pid->level)].ns);
    }

    return ns;
}

/*
 * struct pid_namespace *task_active_pid_ns(struct task_struct *tsk)
 * {
 *  return ns_of_pid(task_pid(tsk));
 * }
 */
static _inline struct pid_namespace *
bpf__task_active_pid_ns(struct task_struct * task)
{
    return bpf__ns_of_pid(bpf__task_pid(task));
}

/*
 * pid_t pid_nr_ns(struct pid *pid, struct pid_namespace *ns)
 * {
 *  struct upid *upid;
 *  pid_t nr = 0;
 *
 *  if (pid && ns->level <= pid->level) {
 *      upid = &pid->numbers[ns->level];
 *      if (upid->ns == ns)
 *          nr = upid->nr;
 *  }
 *  return nr;
 * }
 */
static _inline pid_t
bpf__pid_nr_ns(struct pid * pid, struct pid_namespace * ns)
{
    unsigned int  ns_level;
    struct upid * upid;
    pid_t         nr = 0;

    ns_level = _(ns->level);

    if (pid && ns_level <= _(pid->level)) {
        upid = &pid->numbers[ns_level];
        if (_(upid->ns) == ns) {
            nr = _(upid->nr);
        }
    }

    return nr;
}

/*
 * pid_t __task_pid_nr_ns(struct task_struct *task, enum pid_type type,
 *          struct pid_namespace *ns)
 * {
 *  pid_t nr = 0;
 *
 *  rcu_read_lock();
 *  if (!ns)
 *      ns = task_active_pid_ns(current);
 *  if (likely(pid_alive(task))) {
 *      if (type != PIDTYPE_PID) {
 *          if (type == __PIDTYPE_TGID)
 *              type = PIDTYPE_PID;
 *
 *          task = task->group_leader;
 *      }
 *      nr = pid_nr_ns(rcu_dereference(task->pids[type].pid), ns);
 *  }
 *  rcu_read_unlock();
 *
 *  return nr;
 */
static _inline pid_t
bpf__task_pid_nr_ns(struct task_struct   * task,
                    enum pid_type          type,
                    struct pid_namespace * ns)
{
    pid_t nr = 0;

    if (!ns) {
        ns = bpf__task_active_pid_ns(task);
    }

    if (type != PIDTYPE_PID) {
        if (type == __PIDTYPE_TGID) {
            type = PIDTYPE_PID;
        }

        task = _(task->group_leader);
    }

    nr = bpf__pid_nr_ns(_(task->pids[type].pid), ns);

    return nr;
}

static _inline pid_t
bpf__task_tgid_vnr(struct task_struct * task)
{
    return bpf__task_pid_nr_ns(task, __PIDTYPE_TGID, NULL);
}

static _inline pid_t
bpf__task_pid_vnr(struct task_struct * task)
{
    return bpf__task_pid_nr_ns(task, PIDTYPE_PID, NULL);
}

SEC("tracepoint/raw_syscalls/sys_enter") int
enter(void * ctx)
{
    struct task_struct * task     = (struct task_struct *)bpf_get_current_task();
    pid_t                ns_pid   = bpf__task_pid_vnr(task);
    __u32                this_pid = bpf_get_current_pid_tgid() >> 32;

    if (this_pid != ns_pid && ns_pid != 1) {
        _dprintk(">> PID=%d NSPID=%d\n", this_pid, ns_pid);
    }

    return 0;
}

__u8 _license[] SEC("license") = "GPL";
__u32 _version  SEC("version") = 0xFFFFFFFE;

