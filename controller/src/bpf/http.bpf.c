#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "helper.h"

#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif
#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_HTTP_DATA_LEN 128

struct conn_info {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 inum;           // namespace inum
};

struct event_t
{
    __u64 inum;               // net namespace inum
    __u32 saddr;              // peer IPv4 in network byte order
    __u32 daddr;
    __u16 sport;              // peer port in network byte order
    __u16 dport;              // local/host port in network byte order
    u8 is_request;
    u8 _pad;                  // pad to align data_len at 16
    u32 data_len;
    char data[MAX_HTTP_DATA_LEN];
};

struct recv_args_t {
    __u64 addr;
    __u32 fd;
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct recv_args_t);
} recv_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct conn_info);
} active_conns SEC(".maps");

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

static __always_inline __u64 make_pid_fd_key(__u32 pid, int fd) {
    return ((__u64)pid << 32) | (__u32)fd;
}

SEC("kprobe/__sys_accept4")
int accept4_enter(struct pt_regs *ctx)
{
    if (!check_target_namespace())
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u8 one = 1;
    bpf_map_update_elem(&accept_pending, &pid_tgid, &one, BPF_ANY);
    return 0;
}

SEC("kretprobe/__sys_accept4")
int accept4_exit(struct pt_regs *ctx)
{
    int new_fd = PT_REGS_RC(ctx);
    if (new_fd < 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!bpf_map_lookup_elem(&accept_pending, &pid_tgid))
        return 0;
    
    bpf_map_delete_elem(&accept_pending, &pid_tgid);

    __u32 pid = pid_tgid >> 32;
    
    // Get namespace and task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;
    __u64 inum = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

    // Get the socket structure to extract connection details
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        return 0;
    
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return 0;

    void **fd_array = NULL;
    bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);

    struct file *f = NULL;
    bpf_probe_read_kernel(&f, sizeof(f), (void *)((char *)fd_array + (__u64)new_fd * sizeof(void *)));
    if (!f)
        return 0;

    struct socket *sock = BPF_CORE_READ(f, private_data);
    if (!sock)
        return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    // Read connection details from socket
    __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);  // local IP
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);       // remote IP
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);         // local port (host order)
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);       // remote port (network order)

    // Store accepted connection info with full details
    struct conn_info info = {};
    info.inum = inum;
    info.saddr = saddr;
    info.daddr = daddr;
    info.sport = sport;
    info.dport = dport;
    
    __u64 key = make_pid_fd_key(pid, new_fd);
    bpf_map_update_elem(&active_conns, &key, &info, BPF_ANY);
    
    bpf_printk("accept4: fd=%d saddr=%u:%u daddr=%u:%u\n", 
               new_fd, saddr, sport, daddr, dport);
    return 0;
}

SEC("kprobe/__sys_connect")
int BPF_KPROBE(trace_connect, int fd, struct sockaddr *uservaddr, int addrlen)
{
     if (!check_target_namespace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Read sockaddr
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), uservaddr);
    
    // Only track IPv4 connections
    if (sa.sin_family != 2) // AF_INET
        return 0;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    __u64 inum = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

    bpf_printk("__sys_connect called fd=%d\n", inum);
    
    // Store connection info
    struct conn_info info = {};
    info.daddr = sa.sin_addr.s_addr;
    info.dport = sa.sin_port;
    info.inum = inum;
    
    // Note: saddr and sport will be filled when we see actual traffic
    // For now, we only know the destination
    
    __u64 key = make_pid_fd_key(pid, fd);
    bpf_map_update_elem(&active_conns, &key, &info, BPF_ANY);
    
    return 0;
}

static __always_inline int process_http_data(void *ctx, int fd, void *buff, size_t len, __u32 pid, int in_out ) {
    __u64 key = make_pid_fd_key(pid, fd);
    struct conn_info *conn = bpf_map_lookup_elem(&active_conns, &key);
    if (!conn)
        return 0;

    // Read data buffer
    char tmp_data[MAX_HTTP_DATA_LEN];
    __builtin_memset(tmp_data, 0, sizeof(tmp_data));
    size_t read_size = len < MAX_HTTP_DATA_LEN ? len : MAX_HTTP_DATA_LEN;
    
    if (bpf_probe_read_user(tmp_data, read_size, buff) < 0)
        return 0;

    int http_type = is_http_data(tmp_data, read_size);
    if (http_type == 0 || http_type != 1)
        return 0;

    // Prepare event
    struct event_t event = {};
    event.inum = conn->inum;
    event.saddr = conn->saddr;
    event.daddr = conn->daddr;
    event.sport = conn->sport;
    event.dport = conn->dport;
    event.is_request = (in_out == 1) ? 1 : 0;  // in ingress, out egress
    event.data_len = read_size;

    #pragma unroll
    for (int i = 0; i < MAX_HTTP_DATA_LEN; i++) {
        if (i >= read_size)
            break;
        event.data[i] = tmp_data[i];
    }
    
    bpf_printk("net_ns=%llu remote=%u:%u local=%u type=%s len=%d\n",
               event.inum, event.saddr, event.sport, event.dport,
               http_type == 1 ? "req" : "resp", (int)event.data_len);
    
    bpf_perf_event_output(ctx, &http_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("kprobe/__sys_sendto")
int BPF_KPROBE(trace_sendto, int fd, void *buff, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    return process_http_data(ctx, fd, buff, len, pid, 1);
}

SEC("kprobe/__sys_recvfrom")
int BPF_KPROBE(trace_recvfrom_entry, int fd, void *buff, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Store buffer info for kretprobe
    struct recv_args_t args = {};
    args.addr = (u64)buff;
    args.fd = fd;
    bpf_map_update_elem(&recv_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/__sys_recvfrom")
int BPF_KRETPROBE(trace_recvfrom_exit)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    struct recv_args_t *args = bpf_map_lookup_elem(&recv_args_map, &pid_tgid);
    if (!args)
        return 0;
    
    struct recv_args_t args_copy = *args;
    bpf_map_delete_elem(&recv_args_map, &pid_tgid);
    
    long bytes_read = PT_REGS_RC(ctx);
    if (bytes_read <= 0)
        return 0;
    
    return process_http_data(ctx, args_copy.fd, (void *)args_copy.addr, bytes_read, pid, 0);
}

SEC("kprobe/ksys_read")
int kprobe_ksys_read_entry(struct pt_regs *ctx)
{
    int fd = (int)PT_REGS_PARM1(ctx);
    char *buf = (char *)PT_REGS_PARM2(ctx);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Store buffer info for kretprobe
    struct recv_args_t args = {};
    args.addr = (u64)buf;
    args.fd = fd;
    bpf_map_update_elem(&recv_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/ksys_read")
int kretprobe_ksys_read_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    struct recv_args_t *args = bpf_map_lookup_elem(&recv_args_map, &pid_tgid);
    if (!args)
        return 0;
    
    struct recv_args_t args_copy = *args;
    bpf_map_delete_elem(&recv_args_map, &pid_tgid);
    
    long bytes_read = PT_REGS_RC(ctx);
    if (bytes_read <= 0)
        return 0;
    
    return process_http_data(ctx, args_copy.fd, (void *)args_copy.addr, bytes_read, pid, 0);
}

SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx)
{
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    
    // Now 'buf' contains plaintext HTTP data before encryption
    char data[128];
    bpf_probe_read_user(data, sizeof(data), buf);

    bpf_printk("uprobe/SSL_write");
    
    // Check if it's HTTP and extract method/path
    if (is_http_data(data, num)) {
        
    }
    
    return 0;
}

SEC("kprobe/__x64_sys_close")
int kprobe_ksys_close(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)(pid_tgid >> 32);

    int fd = (int)PT_REGS_PARM1(ctx);

    __u64 key = make_pid_fd_key(pid, fd);
    if (bpf_map_delete_elem(&active_conns, &key) == 0) {
        bpf_printk("close: removed connection pid=%u fd=%d\n", pid, fd);
    }

    return 0;
}