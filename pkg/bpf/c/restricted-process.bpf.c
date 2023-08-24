#include "common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>
// #include <linux/bpf.h>
// #include <linux/sched.h>

struct process_create_event_t {
    __u32 pid;
    __u32 ppid;
    char nodename[NEW_UTS_LEN + 1];
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} process_events SEC(".maps");

static inline void get_process_info(struct process_create_event_t *event){
    struct task_struct *current_task;
    struct uts_namespace *uts_ns;
    struct nsproxy *nsproxy;
    //struct fileopen_safeguard_config *config = (struct fileopen_safeguard_config *)bpf_map_lookup_elem(&process_config_map, &index);

    current_task = (struct task_struct *)bpf_get_current_task();

    event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    
    event->ppid = (u32)(BPF_CORE_READ(current_task, real_parent, tgid));
    BPF_CORE_READ_INTO(&nsproxy, current_task, nsproxy);
    BPF_CORE_READ_INTO(&uts_ns, nsproxy, uts_ns);
    BPF_CORE_READ_INTO(&event->nodename, uts_ns, name.nodename);
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
    bpf_probe_read_kernel_str(&event->parent_comm, sizeof(event->parent_comm), &parent_task->comm);
}
 


SEC("tracepoint/sched/sched_process_fork")
int BPF_PROG(restricted_process_fork) {
    struct process_create_event_t event = {};
    get_process_info(&event);
    bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// SEC("tracepoint/sched/sched_process_exit")
// int BPF_PROG(restricted_process_exit) {

//     struct process_exit_event_t event = {};
    
//     event.pid = bpf_get_current_pid_tgid() >> 32;
//     event.ppid = bpf_get_current_pid_tgid();
//     bpf_get_current_comm(&event.comm, sizeof(event.comm));

//     bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU,
//                           &event, sizeof(event), PROCESS_EXIT_EVENT);

//     return 0;
// }

// SEC("lsm/task_alloc")
// int BPF_PROG(restricted_task_alloc, struct task_struct *task, unsigned long clone_flags) {
    
//     return -EPERM;
// }

char _license[] SEC("license") = "GPL";
