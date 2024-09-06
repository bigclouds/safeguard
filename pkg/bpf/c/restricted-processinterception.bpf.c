#include "vmlinux.h"
#include "vmlinux_macro.h"
#include "syscalls.h"
#include "common_structs.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>



#define NAME_MAX 255
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define EPERM 13
#define PATH_BUFFER 0
#define MAX_BUFFER_SIZE 32768
#define MAX_COMBINED_LENGTH 4096
#define MAX_BUFFERS 1
#define LOOP_NAME 70
enum file_hook_type { dpath = 0, dfileread, dfilewrite };
struct processinterception_event{
//  u64 ts; //事件的时间戳

    u32 pid;
    u32 uid;
    int ret;
    // char nodename[NEW_UTS_LEN + 1];
    char task[TASK_COMM_LEN];
    // char parent_task[TASK_COMM_LEN];
    unsigned char path[NAME_MAX];
   //  unsigned char from_source_path[NAME_MAX];

  //bufs_k data;
};

struct processinterception_safeguard_config {
    u32 mode;
    u32 target;
};

//用于与用户态来回传的events
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} processinterception_events SEC(".maps");

typedef struct buffers {
  char buf[MAX_BUFFER_SIZE];
} bufs_t;

struct file_path {
  unsigned char path[NAME_MAX];
};
typedef struct bufkey {
  unsigned char path[NAME_MAX];
 // char source[MAX_STRING_SIZE];
} bufs_k;
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, bufs_t);
  __uint(max_entries, MAX_BUFFERS);
} bufs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, bufs_k);
  __uint(max_entries, 3);
} bufk SEC(".maps");
//struct source_path {
//    unsigned char from_source_path[NAME_MAX];
//};
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, MAX_BUFFERS);
} bufs_off SEC(".maps");

BPF_HASH(processinterception_safeguard_config_map, u32, struct processinterception_safeguard_config, 256);
//BPF_HASH(allowed_access_path, u32, struct file_path, 256);
BPF_HASH(denied_processinterception, u32, struct file_path, 256);
//BPF_HASH(weakpasswd_from_source_list, u32, struct source_path, 256);


static __always_inline u32 *get_buf_off(int buf_idx) {
  return bpf_map_lookup_elem(&bufs_off, &buf_idx);
}
static __always_inline void set_buf_off(int buf_idx, u32 new_off) {
  bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}
static __always_inline bufs_t *get_buf(int idx) {
  return bpf_map_lookup_elem(&bufs, &idx);
}
static inline struct mount *real_mount(struct vfsmount *mnt) {
  return container_of(mnt, struct mount, mnt);
}

static __always_inline bool prepend_path(struct path *path, bufs_t *string_p) {
  char slash = '/';
  char null = '\0';
  int offset = MAX_COMBINED_LENGTH;

  if (path == NULL || string_p == NULL) {
    return false;
  }

  struct dentry *dentry = path->dentry;
  struct vfsmount *vfsmnt = path->mnt;

  struct mount *mnt = real_mount(vfsmnt);

  struct dentry *parent;
  struct dentry *mnt_root;
  struct mount *m;
  struct qstr d_name;

#pragma unroll
  for (int i = 0; i < 30; i++) {
    parent = BPF_CORE_READ(dentry, d_parent);
    mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

    if (dentry == mnt_root) {
      m = BPF_CORE_READ(mnt, mnt_parent);
      if (mnt != m) {
        dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        mnt = BPF_CORE_READ(mnt, mnt_parent);
        vfsmnt = &mnt->mnt;
        continue;
      }
      break;
    }

    if (dentry == parent) {
      break;
    }

    // get d_name
    d_name = BPF_CORE_READ(dentry, d_name);


    offset -= (d_name.len + 1);
    if (offset < 0)
      break;

    int sz = bpf_probe_read_str(
        &(string_p->buf[(offset) & (MAX_COMBINED_LENGTH - 1)]),
        (d_name.len + 1) & (MAX_COMBINED_LENGTH - 1), d_name.name);
    if (sz > 1) {
      bpf_probe_read(
          &(string_p->buf[(offset + d_name.len) & (MAX_COMBINED_LENGTH - 1)]),
          1, &slash);
    } else {
      offset += (d_name.len + 1);
    }

    dentry = parent;
  }

  if (offset == MAX_COMBINED_LENGTH) {
    return false;
  }

  bpf_probe_read(&(string_p->buf[MAX_COMBINED_LENGTH - 1]), 1, &null);
  offset--;

  bpf_probe_read(&(string_p->buf[offset & (MAX_COMBINED_LENGTH - 1)]), 1,
                 &slash);
  set_buf_off(PATH_BUFFER, offset);
  return true;
}

static inline int check_path_hooks(struct path *f_path,struct processinterception_event *event){
  //struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  // bpf_printk("Access Denied: %s\n", id);
   // event *task_info;
    int ret = 0;
   // u_char *file_path = NULL;
    struct file_path *paths;
    unsigned int key = 0;
    paths = (struct file_path *)bpf_map_lookup_elem(&denied_processinterception, &key);
        if (paths == NULL) {
                return 0;
        }

    bpf_printk("deny paths: %s\n", paths->path);

    u32 zero = 0;
    //字符串指针指向map并初始化
    bufs_k *z = bpf_map_lookup_elem(&bufk, &zero);
    if (z == NULL)
      return 0;

    u32 one = 1;
    bufs_k *store = bpf_map_lookup_elem(&bufk, &one);
    if (store == NULL)
      return 0;

    // Reset value for store
    bpf_map_update_elem(&bufk, &one, z, BPF_ANY);

    u32 two = 2;
    bufs_k *pk = bpf_map_lookup_elem(&bufk, &two);
    if (pk == NULL)
      return 0;



  bufs_t *path_buf = get_buf(PATH_BUFFER);
  if (path_buf == NULL)
    return 0;
///*通过实际挂载点计算真实路径*/
  if (!prepend_path(f_path, path_buf))
    return 0;

  u32 *path_offset = get_buf_off(PATH_BUFFER);
  if (path_offset == NULL)
      return 0;

    //获取到的偏移量存在path_ptr
    void *path_ptr = &path_buf->buf[*path_offset];
    //读取路径转换后的字符串并放在store->path里   store是path
    bpf_probe_read_str(store->path, NAME_MAX, path_ptr);

    bpf_probe_read_str(event->path, sizeof(event->path), store->path);

    unsigned int i = 0;
        unsigned int j = 0;
        bool find = true;
        unsigned int equali = 0;
    #pragma unroll
        for (i = 0; i < LOOP_NAME; i++) {
                if (paths->path[i] == '\0') {
                    break;
                }
                if (paths->path[i]==store->path[j]) {
                        j = j + 1;
                } else {
                        j = 0;
                        find = false;
                }

                if (paths->path[i] == '|') {
                    find = true;
                }
                equali = equali + 1;
                if (paths->path[equali + 1] == '|' && find == true) {
                      ret = -EPERM;
                      break;
                }

        }

      return ret;
 // char tmp = path_buf->buf;
//比较内核中获取的地址是否与传过来的地址一致，一致则禁止执行，不一致放行

  // size_t size = strlen(path_buf->buf, NAME_MAX);
  // if (strcmp(paths->path, path_buf->buf, size) == 0) {
  //   ret = -EPERM;
  // } else {
  //   ret = 0;
  // }
  // return ret;
    
}

static inline void get_event_info(struct processinterception_event *event){
    // struct task_struct *current_task;
    // struct uts_namespace *uts_ns;
    // struct mnt_namespace *mnt_ns;
    // struct nsproxy *nsproxy;

    // current_task = (struct task_struct *)bpf_get_current_task();
    // BPF_CORE_READ_INTO(&nsproxy, current_task, nsproxy);
    // BPF_CORE_READ_INTO(&uts_ns, nsproxy, uts_ns);
    // BPF_CORE_READ_INTO(&event->nodename, uts_ns, name.nodename);

    // BPF_CORE_READ_INTO(&mnt_ns, nsproxy, mnt_ns);
    // BPF_CORE_READ_INTO(&inum, mnt_ns, ns.inum);
    //event->cgroup = bpf_get_current_cgroup_id();

    event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);

    bpf_get_current_comm(&event->task, sizeof(event->task));

    // struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
    // bpf_probe_read_kernel_str(&event->parent_task, sizeof(event->parent_task), &parent_task->comm);

    u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = uid_gid & 0xFFFFFFFF;
}


//挂载在创建目录的函数上
SEC("lsm/path_mkdir")
int BPF_PROG(processinterception_mkdir, struct path *dir, struct dentry *dentry) {
  struct path f_path;
  f_path.dentry = dentry;
  f_path.mnt = BPF_CORE_READ(dir, mnt);

  struct processinterception_event event = {};
  event.ret = check_path_hooks(&f_path, &event);
  get_event_info(&event);
  bpf_perf_event_output((void *)ctx, &processinterception_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return event.ret;
}

//挂载在删除目录的函数上
SEC("lsm/path_rmdir")
int BPF_PROG(processinterception_rmdir, struct path *dir, struct dentry *dentry) {
  struct path f_path;
  f_path.dentry = dentry;
  f_path.mnt = BPF_CORE_READ(dir, mnt);

  struct processinterception_event event = {};
  event.ret = check_path_hooks(&f_path, &event);
  get_event_info(&event);
  bpf_perf_event_output((void *)ctx, &processinterception_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return event.ret;
}

SEC("lsm/path_unlink")
int BPF_PROG(processinterception_unlink, struct path *dir, struct dentry *dentry) {
  struct path f_path;
  f_path.dentry = dentry;
  f_path.mnt = BPF_CORE_READ(dir, mnt);

  struct processinterception_event event = {};
  event.ret = check_path_hooks(&f_path, &event);
  get_event_info(&event);
  bpf_perf_event_output((void *)ctx, &processinterception_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return event.ret;
}

SEC("lsm/path_rename")
int BPF_PROG(processinterception_rename, struct path *old_dir, struct dentry *old_dentry, struct path *new_dir, struct dentry *new_dentry) {
  struct path f_path;
  f_path.dentry = old_dentry;
  f_path.mnt = BPF_CORE_READ(old_dir, mnt);

  struct processinterception_event event = {};
  event.ret = check_path_hooks(&f_path, &event);
  get_event_info(&event);
  bpf_perf_event_output((void *)ctx, &processinterception_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return event.ret;
}

SEC("lsm/path_truncate")
int BPF_PROG(processinterception_truncate, struct path *path) {
  struct processinterception_event event = {};
  event.ret = check_path_hooks(path, &event);
  get_event_info(&event);
  bpf_perf_event_output((void *)ctx, &processinterception_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return event.ret;
}

SEC("lsm/path_chmod")
int BPF_PROG(processinterception_chmod, struct path *path, umode_t mode) {
  struct processinterception_event event = {};
  event.ret = check_path_hooks(path, &event);
  get_event_info(&event);
  bpf_perf_event_output((void *)ctx, &processinterception_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return event.ret;
}

SEC("lsm/path_chroot")
int BPF_PROG(processinterception_chroot, struct path *path) {
  struct processinterception_event event = {};
  event.ret = check_path_hooks(path, &event);
  get_event_info(&event);
  bpf_perf_event_output((void *)ctx, &processinterception_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return event.ret;
}

SEC("lsm/path_mknod")
int BPF_PROG(processinterception_mknod, struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev) {
  struct path f_path;
  f_path.dentry = dentry;
  f_path.mnt = BPF_CORE_READ(dir, mnt);

  struct processinterception_event event = {};
  event.ret = check_path_hooks(&f_path, &event);
  get_event_info(&event);
  bpf_perf_event_output((void *)ctx, &processinterception_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return event.ret;
}

SEC("lsm/path_symlink")
int BPF_PROG(processinterception_symlink, struct path *dir, struct dentry *dentry, char *old_name) {
  struct path f_path;
  f_path.dentry = dentry;
  f_path.mnt = BPF_CORE_READ(dir, mnt);

  struct processinterception_event event = {};
  event.ret = check_path_hooks(&f_path, &event);
  get_event_info(&event);
  bpf_perf_event_output((void *)ctx, &processinterception_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return event.ret;
}

SEC("lsm/path_link")
int BPF_PROG(processinterception_link, struct dentry *old_dentry, struct path *new_dir, struct dentry *new_dentry) {
  struct path f_path;
  f_path.dentry = new_dentry;
  f_path.mnt = BPF_CORE_READ(new_dir, mnt);

  struct processinterception_event event = {};
  event.ret = check_path_hooks(&f_path, &event);
  get_event_info(&event);
  bpf_perf_event_output((void *)ctx, &processinterception_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return event.ret;
}