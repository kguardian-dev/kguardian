# -*- mode: Python -*-
# kguardian local development environment
# Usage: tilt up

load("ext://helm_resource", "helm_resource", "helm_repo")
load("ext://namespace", "namespace_create")

# ─── User-local settings ────────────────────────────────────────────
settings = read_yaml("tilt-settings.yaml", default={})

enable_controller = settings.get("enable_controller", True)
enable_llm_bridge = settings.get("enable_llm_bridge", True)
enable_mcp_server = settings.get("enable_mcp_server", True)
llm_providers = settings.get("llm_providers", {})

# Local build toggles — when False, use latest published GHCR image instead.
build_broker = settings.get("build_broker", True)
build_llm_bridge = settings.get("build_llm_bridge", False)
build_mcp_server = settings.get("build_mcp_server", False)
build_controller = settings.get("build_controller", False)

# Suppress warnings for GHCR images we're not building locally
skip_images = []
if not build_broker:
    skip_images.append("ghcr.io/kguardian-dev/kguardian/broker")
if not build_llm_bridge:
    skip_images.append("ghcr.io/kguardian-dev/kguardian/llm-bridge")
if not build_mcp_server:
    skip_images.append("ghcr.io/kguardian-dev/kguardian/mcp-server")
if not build_controller:
    skip_images.append("ghcr.io/kguardian-dev/kguardian/controller")
update_settings(suppress_unused_image_warnings=skip_images)

# ─── Namespace ───────────────────────────────────────────────────────
NAMESPACE = "kguardian"
namespace_create(NAMESPACE)

# ─── Helm values overrides ──────────────────────────────────────────
helm_set = [
    "llmBridge.enabled=%s" % ("true" if enable_llm_bridge else "false"),
    "mcpServer.enabled=%s" % ("true" if enable_mcp_server else "false"),
    # Pull policy: IfNotPresent when building locally (Tilt loads the image),
    # Always when using pre-built GHCR images so the cluster fetches latest.
    "broker.image.pullPolicy=%s" % ("IfNotPresent" if build_broker else "Always"),
    "controller.image.pullPolicy=%s" % ("IfNotPresent" if build_controller else "Always"),
    "llmBridge.image.pullPolicy=%s" % ("IfNotPresent" if build_llm_bridge else "Always"),
    "mcpServer.image.pullPolicy=%s" % ("IfNotPresent" if build_mcp_server else "Always"),
]

# Wire up LLM provider secret toggles so Helm renders the env var refs
for provider in ["openai", "anthropic", "gemini", "copilot"]:
    cfg = llm_providers.get(provider, {})
    if cfg.get("enabled", False) and cfg.get("api_key", ""):
        helm_set.append("llmBridge.secrets.%s.enabled=true" % provider)

# ─── Helm release ───────────────────────────────────────────────────
yaml = helm(
    "charts/kguardian",
    name="kguardian",
    namespace=NAMESPACE,
    values=["dev/tilt-values.yaml"],
    set=helm_set,
)

k8s_yaml(yaml)

# ─── LLM provider secrets ──────────────────────────────────────────
# Create K8s Secrets for any enabled providers so the LLM Bridge can
# reference them via secretKeyRef.
PROVIDER_SECRET_NAMES = {
    "openai": "kguardian-openai",
    "anthropic": "kguardian-anthropic",
    "gemini": "kguardian-gemini",
    "copilot": "kguardian-copilot",
}

for provider, secret_name in PROVIDER_SECRET_NAMES.items():
    cfg = llm_providers.get(provider, {})
    if cfg.get("enabled", False) and cfg.get("api_key", ""):
        k8s_yaml(blob("""
apiVersion: v1
kind: Secret
metadata:
  name: {name}
  namespace: {ns}
type: Opaque
stringData:
  api-key: "{key}"
""".format(name=secret_name, ns=NAMESPACE, key=cfg["api_key"])))

# ─── Image builds ───────────────────────────────────────────────────
# Components with build_<name>=false (the default) use the latest
# published image from GHCR. Set build_<name>=true in tilt-settings.yaml
# to build from source with live-reload for active development.

if build_broker:
    docker_build(
        "ghcr.io/kguardian-dev/kguardian/broker",
        context="broker",
        dockerfile="broker/Dockerfile",
        live_update=[
            sync("broker/src", "/app/broker/src"),
        ],
    )

if enable_llm_bridge and build_llm_bridge:
    docker_build(
        "ghcr.io/kguardian-dev/kguardian/llm-bridge",
        context="llm-bridge",
        dockerfile="llm-bridge/Dockerfile",
        live_update=[
            sync("llm-bridge/src", "/app/src"),
        ],
    )

if enable_mcp_server and build_mcp_server:
    docker_build(
        "ghcr.io/kguardian-dev/kguardian/mcp-server",
        context="mcp-server",
        dockerfile="mcp-server/Dockerfile",
        live_update=[
            sync("mcp-server/main.go", "/app/main.go"),
            sync("mcp-server/tools", "/app/tools"),
            sync("mcp-server/logger", "/app/logger"),
        ],
    )

if enable_controller and build_controller:
    arch = str(local("uname -m", quiet=True)).strip()
    if arch == "arm64" or arch == "aarch64":
        cross_target = "aarch64-unknown-linux-gnu"
    else:
        cross_target = "x86_64-unknown-linux-gnu"

    custom_build(
        "ghcr.io/kguardian-dev/kguardian/controller",
        command="set -e && cd controller && cross build --release --target %s && cd .. && rm -rf .tilt/controller-build && mkdir -p .tilt/controller-build && cp controller/target/%s/release/kguardian .tilt/controller-build/kguardian && docker build -f dev/controller.Dockerfile -t $EXPECTED_REF .tilt/controller-build" % (cross_target, cross_target),
        deps=["controller/src", "controller/Cargo.toml", "controller/Cargo.lock"],
        skips_local_docker=False,
    )

# ─── Frontend (local Vite dev server) ───────────────────────────────
# The in-cluster frontend deployment is scaled to 0. We run Vite locally
# for instant HMR, proxying API calls to the port-forwarded broker.
local_resource(
    "frontend",
    serve_cmd="cd frontend && npm install && npm run dev",
    deps=["frontend/src", "frontend/index.html", "frontend/vite.config.ts"],
    links=[link("http://localhost:5173", "Frontend")],
    labels=["frontend"],
)

# ─── Resource grouping & port-forwards ──────────────────────────────

# Cluster-wide resources (RBAC, service accounts, namespace) and the
# frontend in-cluster deployment (scaled to 0 — runs locally instead).
k8s_resource(
    "kguardian-frontend",
    new_name="cluster-infra",
    objects=[
        "kguardian:namespace",
        "broker:serviceaccount",
        "controller:serviceaccount",
        "database:serviceaccount",
        "frontend:serviceaccount",
        "llm-bridge:serviceaccount",
        "mcp-server:serviceaccount",
        "kguardian-viewer:clusterrole",
        "kguardian:clusterrolebinding",
    ],
    labels=["infra"],
)

# Database
k8s_resource(
    "kguardian-db",
    port_forwards=["5432:5432"],
    labels=["database"],
)

# Broker
k8s_resource(
    "kguardian-broker",
    port_forwards=["9090:9090"],
    resource_deps=["kguardian-db"],
    labels=["backend"],
)

# Controller — manual trigger since eBPF requires a Linux node with kernel 6.2+
if enable_controller:
    k8s_resource(
        "kguardian-controller",
        resource_deps=["kguardian-broker"],
        labels=["backend"],
        auto_init=True,
        trigger_mode=TRIGGER_MODE_MANUAL,
    )
    warn("Controller requires a Linux node with kernel 6.2+ and eBPF support. It will not work on macOS Docker Desktop. Set enable_controller: false in tilt-settings.yaml to disable it.")

# LLM Bridge
if enable_llm_bridge:
    k8s_resource(
        "kguardian-llm-bridge",
        port_forwards=["8080:8080"],
        resource_deps=["kguardian-broker"],
        labels=["backend"],
    )

# MCP Server
if enable_mcp_server:
    k8s_resource(
        "kguardian-mcp-server",
        port_forwards=["8081:8081"],
        resource_deps=["kguardian-broker"],
        labels=["backend"],
    )
