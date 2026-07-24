# Seeing Inside Your Kubernetes Cluster with eBPF: How kguardian Works                             
                                          
  Modern Kubernetes security has a discovery problem. Before you can write a NetworkPolicy, you    
  need to know what's actually talking to what. Before you can write a seccomp profile, you need to
   know which syscalls a container actually makes. The traditional answer to both questions has    
  been: run your workloads, then guess.                                                            
                                                                                                   
  kguardian takes a different approach. It uses eBPF to watch your cluster from inside the kernel —
   silently, continuously, and with no changes to your application code.

## The Problem with "Write It First" Security

  The standard Kubernetes security workflow looks like this:

  1. Deploy a workload
  2. Manually figure out what network traffic it needs
  3. Write a NetworkPolicy
  4. Hope you didn't miss anything
  5. Deploy a seccomp profile that blocks half the syscalls your app actually needs

  The gap between what you think your application does and what it actually does at runtime is
  where security incidents happen. A pod you thought only spoke to a database is also quietly
  resolving DNS over external servers. A container running a web server is also spawning shell
  processes you didn't expect.

  eBPF closes that gap by letting you observe the ground truth — not what you declared in a
  manifest, but what the kernel is actually executing.

## What eBPF Actually Is

  eBPF (extended Berkeley Packet Filter) is a Linux kernel feature that lets you run sandboxed
  programs inside the kernel without modifying kernel source code or loading kernel modules. Think
  of it as a safe, programmable hook into almost any kernel subsystem.

  The kernel verifies every eBPF program before execution — checking that it terminates, that it
  can't crash the system, that it stays within memory bounds. What you get in return is access to
  kernel-level events with near-zero overhead: function calls, system calls, network packet
  processing, and more — all visible from userspace via ring buffers.

  This is how tools like Cilium, Falco, and Pixie work. kguardian uses the same approach, but
  focuses specifically on generating actionable security artifacts from what it observes.

## How kguardian Uses eBPF

  kguardian runs as a DaemonSet — one pod per node — with a Rust controller that loads three eBPF
  programs into the kernel on startup.

  Program 1: Network Traffic Probe

  SEC("fentry/tcp_set_state")
  int BPF_PROG(trace_tcp_state_change, struct sock *sk, int state)

  SEC("fentry/udp_sendmsg")
  int BPF_PROG(trace_udp_send, struct sock *sk, ...)

  SEC("kprobe/inet_csk_accept")
  int BPF_KPROBE(tcp_accept_entry, struct sock *sk)

  These hooks fire inside the kernel at the exact moment a TCP connection becomes established, a
  UDP message is sent, or a new TCP connection is accepted. For each event, the program reads the
  socket's source IP, destination IP, ports, and — critically — the network namespace inode number
  (net_ns->ns.inum).

  The network namespace inode is the key. Every Kubernetes pod gets its own network namespace, and
  kguardian maintains a map of which inodes belong to which pods. When a socket event fires, the
  program does a single BPF map lookup: is this inode in the watched set? If not, the program
  returns in microseconds. If yes, it pushes the event into a ring buffer for userspace to consume.

  The result: every TCP connection and UDP packet for every pod on the node, captured at the kernel
   level, attributed to the right pod — with no iptables rules, no sidecar proxies, and no
  application changes.

  Program 2: Syscall Probe

  SEC("tracepoint/raw_syscalls/sys_enter")
  int trace_execve(struct trace_event_raw_sys_enter *ctx)

  This program fires on every system call entry. It reads the current task's network namespace
  inode, checks the same watched-pod map, and if this is a pod we care about, records the syscall
  number. An allowlist filter means only security-relevant syscalls (process execution, network
  operations, privilege changes, file operations) are tracked — cutting noise dramatically and
  reducing overhead.

  The syscall data feeds seccomp profile generation. Instead of guessing which syscalls nginx
  needs, kguardian watches nginx run and tells you exactly which syscalls it made.

  Program 3: Network Policy Drop Detector

  SEC("fentry/tcp_retransmit_skb")
  int BPF_PROG(trace_tcp_retransmit, struct sock *sk, ...)

  This one is subtler. When a network policy blocks a TCP connection, the kernel doesn't send a RST
   — it silently drops packets. The connecting pod keeps retransmitting SYNs until it times out.
  kguardian hooks into tcp_retransmit_skb and counts SYN retransmissions per connection: after 4
  attempts with no ESTABLISHED state, it records a policy drop event. This gives you visibility
  into "what traffic is being denied by my NetworkPolicies right now" — something that's otherwise
  nearly impossible to observe.

  
## The Network Namespace Trick

  The most important design decision in kguardian's eBPF layer is how it scopes observation to
  specific pods without needing process IDs or container IDs.

  Linux namespaces are kernel objects, and each namespace has an inode number — a stable, unique
  identifier. Every pod in Kubernetes lives in its own network namespace. kguardian's Rust
  controller watches the Kubernetes API for pod events; when a pod starts, it reads the pod's
  network namespace inode from /proc via the containerd API, then writes that inode into the BPF
  map shared with the running eBPF programs.

  From that point on, any kernel event carrying that inode number is automatically attributed to
  that pod — without any per-packet overhead, without any container runtime hooks, and without
  touching the pod itself. When the pod terminates, the inode is removed from the map and events
  stop being recorded for it.

  This design means the observation overhead scales with the number of tracked pods' actual
  traffic, not with total cluster traffic.

### From Raw Events to Security Artifacts

  Capturing events is only half the problem. kguardian's pipeline turns kernel events into
  something useful.

  The Rust controller receives events from the eBPF ring buffers via tokio async channels, enriches
   them with pod metadata (namespace, name, workload labels), and ships them to a central broker
  service backed by a database. The broker serves a REST API consumed by two surfaces:

  The visual dashboard — a React/TypeScript frontend using ReactFlow and ELK layout to render your
  cluster's actual network topology as an interactive graph. Pods are grouped by workload identity.
   Edges are drawn from real traffic, colored by type (internal blue, external amber, dropped red),
   labeled with the top port and protocol (HTTP, HTTPS, DNS, K8s API). You can see at a glance that
   your frontend pods are talking to backend pods on port 8080, to an external payment API on 443,
  and that a previously-unknown DNS query is going to an external resolver.

  The policy generator — click any workload in the graph, click "Build Policy", and kguardian
  generates a least-privilege NetworkPolicy YAML directly from observed traffic. It resolves IPs to
   pod identities and service names, matches service selectors to back-pod labels, and deduplicates
   flows that hit both a service ClusterIP and its backing pod. The result is a NetworkPolicy that
  actually reflects what your application does — egress to the exact namespaces and pod selectors
  you need, on the exact ports you use, nothing more. The same observed syscall data generates
  seccomp profiles: an allowlist of every syscall your container made, with configurable default
  actions for anything not seen.

  The AI assistant — an optional LLM bridge (supporting Anthropic Claude, OpenAI, Gemini, and
  GitHub Copilot) lets you query your cluster's security posture in plain English via an MCP
  server: "What pods have the most outbound connections?", "Show me any pods making unexpected DNS
  queries", "Are there workloads accessing the Kubernetes API server directly?"

  
## What Makes This Different from Sidecar-Based Approaches

  Service meshes like Istio or Linkerd also give you network visibility, but they work by injecting
   sidecar proxies into every pod. This has costs:

  - Every pod gets an extra container consuming memory and CPU
  - Traffic is proxied through userspace, adding latency
  - You have to opt pods into the mesh, or manage exceptions for pods that can't take a sidecar
  - The mesh itself becomes a target

  kguardian's eBPF approach runs entirely outside your pods. Nothing is injected, nothing is
  proxied, nothing is modified. The kernel observes and reports. Your pod doesn't know it's being
  watched, and neither do any processes inside it trying to hide their behaviour.


## The Practical Workflow

  Deploy kguardian via Helm in about 30 seconds:

  helm install kguardian oci://ghcr.io/kguardian-dev/charts/kguardian \
    --namespace kguardian --create-namespace

  Let your workloads run normally for a few minutes or hours. Then open the dashboard, pick a
  namespace, and see your actual network topology — not what you declared, what actually happened.
  Click a workload, generate a NetworkPolicy, review it, apply it.

  For seccomp profiles, the same data drives the CLI:

  kubectl kguardian gen seccomp my-pod -n production --output-dir ./seccomp
  kubectl kguardian gen networkpolicy --all -n production --output-dir ./policies

  The generated YAML is ready to commit to your GitOps repo.

## Considerations

  eBPF is not magic. It requires a reasonably modern kernel (Linux 6.2+), and certain kernel
  lockdown configurations — particularly Secure Boot with lockdown=integrity as used by Talos Linux
   — restrict the tracing program types kguardian relies on. In those environments, the kernel
  treats BPF tracing programs as potential vectors for reading kernel memory, and blocks them
  regardless of capability.

  The eBPF programs use CO-RE (Compile Once — Run Everywhere) via BTF, meaning the compiled
  programs adapt to the running kernel's data structure layout without needing to be recompiled per
   kernel version. This is what makes it practical to ship as a container image rather than
  requiring node-level compilation.


## Conclusion

  Security policy in Kubernetes has always suffered from the observation gap — the difference
  between what you think your workloads do and what they actually do. eBPF closes that gap by
  moving observation into the kernel itself, where there's no escaping it.

  kguardian builds on that foundation to turn raw kernel events into the three things security
  engineers actually need: a map of what's talking to what, a NetworkPolicy that reflects it, and a
   seccomp profile that constrains it. All without touching your applications, all from a single
  DaemonSet, all driven by what the kernel actually saw.

  The code is at github.com/kguardian-dev/kguardian.
