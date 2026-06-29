package tools

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// toolDef holds a tool definition with its name and description.
// This is the single source of truth for all tool metadata.
type toolDef struct {
	Name        string
	Description string
}

// toolDefs is the canonical list of tool definitions used by both
// GetAllToolDefs (for introspection) and RegisterAllTools (for registration).
var toolDefs = []toolDef{
	{
		Name:        "get_pod_network_traffic",
		Description: "Get network traffic for a specific pod by name. Returns source/destination IPs, ports, protocols, ingress/egress types, and packet decisions. Use when the user asks about a specific pod's connections or traffic. Requires only pod_name (not namespace-scoped — the broker resolves by name cluster-wide).",
	},
	{
		Name:        "get_pod_syscalls",
		Description: "Get system calls made by a specific pod. Returns syscall names, frequencies, and architecture. Use when the user asks about a pod's syscalls, seccomp profile, or suspicious behavior. Requires only pod_name (not namespace-scoped).",
	},
	{
		Name:        "get_pod_details",
		Description: "Look up a pod by its IP address. Returns pod name, namespace, IP, and full Kubernetes pod object. Use when the user has an IP address and wants to identify which pod it belongs to. Requires only ip.",
	},
	{
		Name:        "get_service_details",
		Description: "Look up a Kubernetes service by its cluster IP. Returns service name, namespace, IP, ports, and full service spec. Use when the user has a service IP and wants to identify the service. Requires only ip.",
	},
	{
		Name:        "get_cluster_traffic",
		Description: "Get a summary of network traffic across the cluster. Returns per-pod counts (ingress/egress, allow/drop, unique peers) plus a cluster-wide total_drop_count — not raw records. Dropped flows (decision=DROP) come from the eBPF network-policy-drop probe, so this also answers 'what traffic is being blocked/dropped'. Accepts an optional namespace filter. Use for overall traffic patterns, 'what pods are communicating', or 'where is traffic being dropped'.",
	},
	{
		Name:        "get_cluster_pods",
		Description: "List pods in the cluster with compact metadata (name, namespace, IP, node, status). Heavyweight fields like pod_obj are stripped. Accepts an optional namespace parameter to filter results. Use when the user asks 'what pods are running' or needs a pod inventory.",
	},
	{
		Name:        "get_pod_details_by_name",
		Description: "Look up a pod by its name. Returns identity (name, namespace, IP, node, workload selector labels) with the heavyweight pod_obj stripped. Use when the user names a pod (e.g. from a traffic record) and wants its details — prefer this over get_pod_details, which requires an IP.",
	},
	{
		Name:        "list_services",
		Description: "List Kubernetes services in the cluster with compact metadata (name, namespace, cluster IP, selector, ports). Accepts an optional namespace parameter to filter results. Use when the user asks 'what services exist' or needs a service inventory — get_service_details only resolves a single known IP.",
	},
	{
		Name:        "get_pods_on_node",
		Description: "List the pods recorded on a specific Kubernetes node (compact metadata: name, namespace, IP, node, workload labels; live pods only). Use for blast-radius / 'what runs on node X' / 'which workloads share a node' questions. Requires node.",
	},
	{
		Name:        "get_audit_verdicts",
		Description: "Get network-policy evaluation verdicts — flows the AuditNetworkPolicy/AuditClusterNetworkPolicy engine evaluated as Allow or WouldDeny. Returns source/destination pod+namespace, port, protocol, direction, the human-readable reason, and observed_at, newest first. All filters optional: policy, namespace (a single namespace; omit to span all, which includes cluster-scoped), cluster_scoped (true = ONLY cluster-scoped verdicts), verdict ('Allow'|'WouldDeny'), direction ('Ingress'|'Egress'), limit (default 100, max 500). Use for security questions like 'what traffic would be denied', 'why is this flow blocked', or 'show recent policy violations'.",
	},
	{
		Name:        "generate_network_policy",
		Description: "Generate a least-privilege Kubernetes NetworkPolicy (or CiliumNetworkPolicy) for a pod from its observed traffic. Returns ready-to-apply YAML. Parameters: pod_name (required); policy_type ('kubernetes' for a standard NetworkPolicy — the default — or 'cilium'). Use when the user asks to 'generate/create a network policy', 'lock down this pod', or 'restrict traffic for X'. The policy is deterministically synthesised by the advisor from captured flows, not guessed.",
	},
	{
		Name:        "generate_seccomp_profile",
		Description: "Generate a least-privilege seccomp profile for a pod from its observed syscalls. Returns ready-to-use seccomp JSON (allow-lists the observed syscalls, denies the rest). Parameter: pod_name (required). Use when the user asks to 'generate/create a seccomp profile' or 'restrict syscalls for X'.",
	},
}

// GetAllToolDefs returns the canonical list of tool definitions.
// Useful for introspection and testing.
func GetAllToolDefs() []toolDef {
	result := make([]toolDef, len(toolDefs))
	copy(result, toolDefs)
	return result
}

// RegisterAllTools registers all tools with the MCP server using the
// canonical tool definitions from toolDefs.
func RegisterAllTools(server *mcp.Server, brokerURL string) {
	client := NewBrokerClient(brokerURL)

	// Build a lookup map from the canonical definitions.
	defs := make(map[string]string, len(toolDefs))
	for _, d := range toolDefs {
		defs[d.Name] = d.Description
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_pod_network_traffic",
		Description: defs["get_pod_network_traffic"],
	}, NetworkTrafficHandler{client: client}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_pod_syscalls",
		Description: defs["get_pod_syscalls"],
	}, SyscallsHandler{client: client}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_pod_details",
		Description: defs["get_pod_details"],
	}, PodDetailsHandler{client: client}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_service_details",
		Description: defs["get_service_details"],
	}, ServiceDetailsHandler{client: client}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_cluster_traffic",
		Description: defs["get_cluster_traffic"],
	}, ClusterTrafficHandler{client: client}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_cluster_pods",
		Description: defs["get_cluster_pods"],
	}, ClusterPodsHandler{client: client}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_pod_details_by_name",
		Description: defs["get_pod_details_by_name"],
	}, PodByNameHandler{client: client}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_services",
		Description: defs["list_services"],
	}, ClusterServicesHandler{client: client}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_pods_on_node",
		Description: defs["get_pods_on_node"],
	}, PodsOnNodeHandler{client: client}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_audit_verdicts",
		Description: defs["get_audit_verdicts"],
	}, AuditVerdictsHandler{client: client}.Call)

	// Policy/seccomp generation proxies to the advisor service.
	advisor := NewAdvisorClient("")

	mcp.AddTool(server, &mcp.Tool{
		Name:        "generate_network_policy",
		Description: defs["generate_network_policy"],
	}, GenerateNetworkPolicyHandler{advisor: advisor}.Call)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "generate_seccomp_profile",
		Description: defs["generate_seccomp_profile"],
	}, GenerateSeccompProfileHandler{advisor: advisor}.Call)
}
