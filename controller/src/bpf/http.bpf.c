#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "helper.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_HTTP_DATA_LEN 256
#define MAX_HTTP_PATH_LEN 128
#define MAX_BUF_SIZE 256
#define TARGET_NETNS_INUM 4026534739ULL

struct event_t
{
    __u64 inum;               // net namespace inum
    __u32 saddr;              // peer IPv4 in network byte order
    __u16 sport;              // peer port in network byte order
    u8 is_request;
    u8 _pad;                  // pad to align data_len at 16
    u32 data_len;
    char data[MAX_HTTP_DATA_LEN];
};

struct recv_args_t {
    __u64 addr;
    __u32 fd;
    // implicit padding to 16 bytes
};

struct sock_key_t {
    __u64 net_ns;
    __u32 fd;
    // implicit padding to 16 bytes
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} http_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u8));
} accept_pending SEC(".maps");

// Track all accepted sockets in target namespace
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(struct sock_key_t));  // composite key: net_ns + fd
    __uint(value_size, sizeof(__u8));
} active_app_sockets SEC(".maps");


struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(u64));  // pid_tgid
    __uint(value_size, sizeof(struct recv_args_t)); // buffer addr + fd
} recv_args_map SEC(".maps");


// Track PIDs in target namespace
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
} target_namespace_pids SEC(".maps");

static __always_inline int is_http_data(char *data, size_t len)
{
    if (len < 4)
        return 0;

    // Check for HTTP request methods
    if ((len >= 4 && data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') ||
        (len >= 5 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T' && data[4] == ' ') ||
        (len >= 4 && data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') ||
        (len >= 4 && data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D') ||
        (len >= 5 && data[0] == 'P' && data[1] == 'A' && data[2] == 'T' && data[3] == 'C' && data[4] == 'H') ||
        (len >= 7 && data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E' && 
         data[4] == 'T' && data[5] == 'E' && data[6] == ' ') ||
        (len >= 8 && data[0] == 'O' && data[1] == 'P' && data[2] == 'T' && data[3] == 'I' &&
         data[4] == 'O' && data[5] == 'N' && data[6] == 'S' && data[7] == ' '))
    {
        return 1; // HTTP request
    }

    // Check for HTTP response
    if (len >= 8 && data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P' && 
        data[4] == '/' && data[5] == '1' && data[6] == '.')
    {
        return 2; // HTTP response
    }
    return 0;
}

static __always_inline int check_target_namespace()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    __u64 net_ns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    
    // Check if this net namespace exists in the inode_num map
    u32 *exists = bpf_map_lookup_elem(&inode_num, &net_ns);
    return (exists != NULL) ? 1 : 0;
}


// Track accepted connections
SEC("kprobe/__sys_accept4")
int accept4_enter(struct pt_regs *ctx)
{
    if (!check_target_namespace())
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u8 one = 1;
    bpf_map_update_elem(&accept_pending, &pid_tgid, &one, BPF_ANY);
    
    u32 pid = pid_tgid >> 32;
    bpf_map_update_elem(&target_namespace_pids, &pid, &one, BPF_ANY);
    
    bpf_printk("accept4_enter: marked pid=%d\n", pid);
    return 0;
}

SEC("kretprobe/__sys_accept4")
int accept4_exit(struct pt_regs *ctx)
{
    int new_fd = PT_REGS_RC(ctx);
    if (new_fd < 0)
        return 0;

    // verify we previously saw accept_enter for this pid
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (bpf_map_lookup_elem(&accept_pending, &pid_tgid) == 0)
        return 0;

    bpf_map_delete_elem(&accept_pending, &pid_tgid);

    // fetch current task's net namespace inum
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    __u64 net_ns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

    struct sock_key_t key = {};
    key.net_ns = net_ns;
    key.fd = (__u32)new_fd;

    __u8 one = 1;
    bpf_map_update_elem(&active_app_sockets, &key, &one, BPF_ANY);

    bpf_printk("accept4_exit: tracked socket net_ns=%llu fd=%d\n", net_ns, new_fd);
    return 0;
}

// Generic helper to handle recv entry
static __always_inline int handle_recv_entry(struct pt_regs *ctx, int fd, void *buf)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)(pid_tgid >> 32);

    if (!bpf_map_lookup_elem(&target_namespace_pids, &pid))
        return 0;

    // get current task net namespace
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;
    __u64 net_ns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

    struct sock_key_t key = {};
    key.net_ns = net_ns;
    key.fd = (__u32)fd;

    __u8 *exists = bpf_map_lookup_elem(&active_app_sockets, &key);
    
    if (!exists)
        return 0;

    bpf_printk("recv_entry: TRACKED net_ns=%llu fd=%d\n", net_ns, fd);

    // FIX: Store both buffer address AND file descriptor
    struct recv_args_t args = {};
    args.addr = (u64)buf;
    args.fd = (__u32)fd;
    bpf_map_update_elem(&recv_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// Generic helper to handle recv exit
static __always_inline int handle_recv_exit(struct pt_regs *ctx, const char *syscall_name)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct recv_args_t *rv = bpf_map_lookup_elem(&recv_args_map, &pid_tgid);
    if (!rv)
        return 0;

    struct recv_args_t rv_copy = {};
    // copy to stack to avoid later map access
    bpf_probe_read_kernel(&rv_copy, sizeof(rv_copy), rv);
    bpf_map_delete_elem(&recv_args_map, &pid_tgid);

    char *buf = (char *)rv_copy.addr;
    int fd = rv_copy.fd;
    long bytes_read = PT_REGS_RC(ctx);
    if (bytes_read <= 0)
        return 0;

    bpf_printk("recv_exit: pid=%d fd=%d bytes=%ld\n", pid, fd, bytes_read);

    struct event_t evt = {};

    // populate event with current task's net namespace inum
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;
    evt.inum = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

    // locate struct file * for fd: files->fdt->fd[fd]
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        return 0;
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return 0;

    void **fd_array = NULL;
    bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);

    struct file *f = NULL;
    // read pointer at fd_array + fd * sizeof(void*)
    bpf_probe_read_kernel(&f, sizeof(f), (void *)((char *)fd_array + (__u64)fd * sizeof(void *)));
    if (!f)
        return 0;

    struct socket *sock = BPF_CORE_READ(f, private_data);
    if (!sock)
        return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    // read IPv4 peer addr/port from sock common fields (network byte order)
    __u32 peer_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 peer_port = BPF_CORE_READ(sk, __sk_common.skc_dport);

    evt.saddr = peer_ip;
    evt.sport = peer_port;

    size_t data_len = bytes_read < MAX_HTTP_DATA_LEN ? bytes_read : MAX_HTTP_DATA_LEN;
    if (bpf_probe_read_user(evt.data, data_len, buf) != 0) {
        bpf_printk("recv_exit: failed to read user buffer\n");
        return 0;
    }

    int http_type = is_http_data(evt.data, data_len);
    if (http_type == 0)
        return 0;

    evt.data_len = data_len;
    evt.is_request = (http_type == 1) ? 1 : 0;

    bpf_printk("HTTP DETECTED! net_ns=%llu src_ip=%u src_port=%u type=%s len=%d\n",
               evt.inum, evt.saddr, evt.sport, http_type == 1 ? "req" : "resp", data_len);

    bpf_perf_event_output(ctx, &http_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// Hook read (common for simple servers)
SEC("kprobe/ksys_read")
int kprobe_ksys_read_entry(struct pt_regs *ctx)
{
    int fd = (int)PT_REGS_PARM1(ctx);
    char *buf = (char *)PT_REGS_PARM2(ctx);
    return handle_recv_entry(ctx, fd, buf);
}

SEC("kretprobe/ksys_read")
int kretprobe_ksys_read_exit(struct pt_regs *ctx)
{
    return handle_recv_exit(ctx, "read");
}

// Track socket close to cleanup
SEC("kprobe/__x64_sys_close")
int kprobe_ksys_close(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)(pid_tgid >> 32);
    
    if (!bpf_map_lookup_elem(&target_namespace_pids, &pid))
        return 0;

    int fd = PT_REGS_PARM1(ctx);

    // obtain current task net namespace
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;
    __u64 net_ns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

    struct sock_key_t key = {};
    key.net_ns = net_ns;
    key.fd = (__u32)fd;
    
    if (bpf_map_delete_elem(&active_app_sockets, &key) == 0) {
        bpf_printk("close: removed socket net_ns=%llu fd=%d\n", net_ns, fd);
    }
    
    return 0;
}