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

// Direction + HTTP type packed into one byte to avoid struct padding changes:
//   0 = received request  (INGRESS, has method+path)
//   1 = sent     request  (EGRESS,  has method+path)
//   2 = received response (reply to our EGRESS; has status code)
//   3 = sent     response (reply to INGRESS;    has status code)
#define HTTP_RECV_REQUEST  0
#define HTTP_SEND_REQUEST  1
#define HTTP_RECV_RESPONSE 2
#define HTTP_SEND_RESPONSE 3

struct conn_info {
    __u32 saddr;   // local IP  (host byte order for accept; 0 for connect until sendto)
    __u32 daddr;   // remote IP (network byte order)
    __u16 sport;   // local port  (host byte order, from skc_num)
    __u16 dport;   // remote port (network byte order, from skc_dport / sin_port)
    __u64 inum;    // net namespace inode
};

struct event_t {
    __u64 inum;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    u8    direction;   // HTTP_RECV_REQUEST / HTTP_SEND_REQUEST / etc.
    u8    _pad;
    u32   data_len;
    char  data[MAX_HTTP_DATA_LEN];
};

struct recv_args_t {
    __u64 addr;
    __u32 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} http_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __uint(key_size,    sizeof(u64));
    __uint(value_size,  sizeof(u8));
} accept_pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u64);
    __type(value, struct recv_args_t);
} recv_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u64);
    __type(value, struct conn_info);
} active_conns SEC(".maps");

// Returns: 1 = HTTP request, 2 = HTTP response, 0 = not HTTP
static __always_inline int is_http_data(char *data, size_t len)
{
    if (len < 4)
        return 0;

    if ((len >= 4 && data[0]=='G' && data[1]=='E' && data[2]=='T' && data[3]==' ') ||
        (len >= 5 && data[0]=='P' && data[1]=='O' && data[2]=='S' && data[3]=='T' && data[4]==' ') ||
        (len >= 4 && data[0]=='P' && data[1]=='U' && data[2]=='T' && data[3]==' ') ||
        (len >= 5 && data[0]=='H' && data[1]=='E' && data[2]=='A' && data[3]=='D' && data[4]==' ') ||
        (len >= 6 && data[0]=='P' && data[1]=='A' && data[2]=='T' && data[3]=='C' && data[4]=='H' && data[5]==' ') ||
        (len >= 7 && data[0]=='D' && data[1]=='E' && data[2]=='L' && data[3]=='E' && data[4]=='T' && data[5]=='E' && data[6]==' ') ||
        (len >= 8 && data[0]=='O' && data[1]=='P' && data[2]=='T' && data[3]=='I' && data[4]=='O' && data[5]=='N' && data[6]=='S' && data[7]==' '))
        return 1; // HTTP request

    if (len >= 8 && data[0]=='H' && data[1]=='T' && data[2]=='T' && data[3]=='P' &&
        data[4]=='/' && data[5]=='1' && data[6]=='.')
        return 2; // HTTP response

    return 0;
}

static __always_inline int check_target_namespace(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;
    __u64 net_ns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    __u64 key = net_ns;
    return bpf_map_lookup_elem(&inode_num, &key) ? 1 : 0;
}

// Filter out daemonset / ignored IPs.  Only checks the remote IP (daddr) so
// that EGRESS traffic with saddr==0 (connect path) is not incorrectly dropped.
static __always_inline int should_ignore_remote(__u32 remote_ip)
{
    if (remote_ip == 0)
        return 0;
    // Localhost
    __u32 loopback = 0x0100007F; // 127.0.0.1 in network byte order
    if (remote_ip == loopback)
        return 1;
    return bpf_map_lookup_elem(&ignore_ips, &remote_ip) ? 1 : 0;
}

static __always_inline __u64 make_pid_fd_key(__u32 pid, int fd)
{
    return ((__u64)pid << 32) | (__u32)fd;
}

// ── accept4: track incoming connections ──────────────────────────────────────

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

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;
    __u64 inum = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

    // Read socket to extract connection 4-tuple
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files) return 0;
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) return 0;
    void **fd_array = NULL;
    bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);
    struct file *f = NULL;
    bpf_probe_read_kernel(&f, sizeof(f),
        (void *)((char *)fd_array + (__u64)new_fd * sizeof(void *)));
    if (!f) return 0;
    struct socket *sock = BPF_CORE_READ(f, private_data);
    if (!sock) return 0;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) return 0;

    __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr); // local  IP
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);      // remote IP (client)
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);        // local  port (host byte order)
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);      // remote port (network byte order)

    struct conn_info info = {};
    info.inum  = inum;
    info.saddr = saddr;
    info.daddr = daddr;
    info.sport = sport;
    info.dport = dport;

    __u64 key = make_pid_fd_key(pid, new_fd);
    bpf_map_update_elem(&active_conns, &key, &info, BPF_ANY);
    return 0;
}

// ── connect: track outgoing connections ──────────────────────────────────────

SEC("kprobe/__sys_connect")
int BPF_KPROBE(trace_connect, int fd, struct sockaddr *uservaddr, int addrlen)
{
    if (!check_target_namespace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), uservaddr);
    if (sa.sin_family != 2) // AF_INET only
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    __u64 inum = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

    // saddr/sport are unknown until bind; filled in at sendto time if possible.
    struct conn_info info = {};
    info.daddr = sa.sin_addr.s_addr;  // network byte order
    info.dport = sa.sin_port;         // network byte order
    info.inum  = inum;

    __u64 key = make_pid_fd_key(pid, fd);
    bpf_map_update_elem(&active_conns, &key, &info, BPF_ANY);
    return 0;
}

// ── common data handler ──────────────────────────────────────────────────────

static __always_inline int process_http_data(
    int fd, void *buff, size_t len, __u32 pid, int is_send)
{
    __u64 key = make_pid_fd_key(pid, fd);
    struct conn_info *conn = bpf_map_lookup_elem(&active_conns, &key);
    if (!conn)
        return 0;

    // Filter ignored (daemonset) remote IPs before doing any more work
    if (should_ignore_remote(conn->daddr))
        return 0;

    char tmp[MAX_HTTP_DATA_LEN];
    __builtin_memset(tmp, 0, sizeof(tmp));
    size_t read_size = len < MAX_HTTP_DATA_LEN ? len : MAX_HTTP_DATA_LEN;
    if (bpf_probe_read_user(tmp, read_size, buff) < 0)
        return 0;

    // Accept both requests (1) and responses (2); drop only non-HTTP (0)
    int http_type = is_http_data(tmp, read_size);
    if (http_type == 0)
        return 0;

    // Determine the combined direction+type value
    u8 direction;
    if (is_send)
        direction = (http_type == 1) ? HTTP_SEND_REQUEST : HTTP_SEND_RESPONSE;
    else
        direction = (http_type == 1) ? HTTP_RECV_REQUEST : HTTP_RECV_RESPONSE;

    struct event_t *e = bpf_ringbuf_reserve(&http_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->inum      = conn->inum;
    e->saddr     = conn->saddr;
    e->daddr     = conn->daddr;
    e->sport     = conn->sport;
    e->dport     = conn->dport;
    e->direction = direction;
    e->_pad      = 0;
    e->data_len  = read_size;

    #pragma unroll
    for (int i = 0; i < MAX_HTTP_DATA_LEN; i++) {
        if (i < read_size)
            e->data[i] = tmp[i];
        else
            e->data[i] = 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── sendto ───────────────────────────────────────────────────────────────────

SEC("kprobe/__sys_sendto")
int BPF_KPROBE(trace_sendto, int fd, void *buff, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    return process_http_data(fd, buff, len, pid, 1 /* is_send */);
}

// ── recvfrom ─────────────────────────────────────────────────────────────────

SEC("kprobe/__sys_recvfrom")
int BPF_KPROBE(trace_recvfrom_entry, int fd, void *buff, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct recv_args_t args = { .addr = (u64)buff, .fd = fd };
    bpf_map_update_elem(&recv_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/__sys_recvfrom")
int BPF_KRETPROBE(trace_recvfrom_exit)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct recv_args_t *args = bpf_map_lookup_elem(&recv_args_map, &pid_tgid);
    if (!args) return 0;
    struct recv_args_t a = *args;
    bpf_map_delete_elem(&recv_args_map, &pid_tgid);
    long n = PT_REGS_RC(ctx);
    if (n <= 0) return 0;
    return process_http_data(a.fd, (void *)a.addr, n, pid, 0 /* recv */);
}

// ── read / ksys_read ─────────────────────────────────────────────────────────

SEC("kprobe/ksys_read")
int kprobe_ksys_read_entry(struct pt_regs *ctx)
{
    int   fd  = (int)PT_REGS_PARM1(ctx);
    char *buf = (char *)PT_REGS_PARM2(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct recv_args_t args = { .addr = (u64)buf, .fd = fd };
    bpf_map_update_elem(&recv_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/ksys_read")
int kretprobe_ksys_read_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct recv_args_t *args = bpf_map_lookup_elem(&recv_args_map, &pid_tgid);
    if (!args) return 0;
    struct recv_args_t a = *args;
    bpf_map_delete_elem(&recv_args_map, &pid_tgid);
    long n = PT_REGS_RC(ctx);
    if (n <= 0) return 0;
    return process_http_data(a.fd, (void *)a.addr, n, pid, 0 /* recv */);
}

// ── close: cleanup ───────────────────────────────────────────────────────────

SEC("kprobe/__x64_sys_close")
int kprobe_ksys_close(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)(pid_tgid >> 32);
    int fd = (int)PT_REGS_PARM1(ctx);
    __u64 key = make_pid_fd_key(pid, fd);
    bpf_map_delete_elem(&active_conns, &key);
    return 0;
}
