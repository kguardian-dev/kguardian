# kguardian Helm Chart

This chart bootstraps the [kguardian]() controlplane onto a [Kubernetes](http://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

![Version: 1.1.0](https://img.shields.io/badge/Version-1.1.0-informational?style=flat-square)

## Overview

This Helm chart deploys:

- A kguardian control plane configured to your specifications
- Additional features and components (optional)

## Prerequisites

- Linux Kernel 6.2+
- Kubernetes 1.19+
- kubectl v1.19+
- Helm 3.0+

## Install the Chart

To install the chart with the release name `my-release`:

Add the chart repo

```bash
helm repo add kguardian https://kguardian-dev.github.io/kguardian
```

You can then run `helm search repo kguardian` to search the charts.

Install chart using Helm v3.0+

```bash
helm install kguardian kguardian/kguardian --namespace kguardian --create-namespace
```

If you want to use the OCI variant of the helm chart, you can use the following command:

```bash
helm template kguardian oci://ghcr.io/kguardian-dev/charts/kguardian --namespace kguardian --create-namespace
```

**Note:** *If you have the [Pod Securty Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/) enabled for your cluster you will need to add the following annotation to the namespace that the chart is deployed*

Example:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/warn: privileged
  name: kguardian
```

## Directory Structure

The following shows the directory structure of the Helm chart.

```bash
charts/kguardian/
├── .helmignore   # Contains patterns to ignore when packaging Helm charts.
├── Chart.yaml    # Information about your chart
├── values.yaml   # The default values for your templates
├── charts/       # Charts that this chart depends on
└── templates/    # The template files
    └── tests/    # The test files
```

## Configuration

The following table lists the configurable parameters of the kguardian chart and their default values.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| broker.affinity | object | `{}` | Affinity rules for broker pod assignment |
| broker.autoscaling.enabled | bool | `false` | Enable horizontal pod autoscaling for broker |
| broker.autoscaling.maxReplicas | int | `100` | Maximum number of broker replicas |
| broker.autoscaling.minReplicas | int | `1` | Minimum number of broker replicas |
| broker.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage for autoscaling |
| broker.container.port | int | `9090` | Broker container port |
| broker.fullnameOverride | string | `""` | Override the full name of the broker resources |
| broker.image.pullPolicy | string | `"Always"` | Broker image pull policy |
| broker.image.repository | string | `"ghcr.io/kguardian-dev/kguardian/broker"` | Broker container image repository |
| broker.image.sha | string | `""` | Overrides the image tag using SHA digest |
| broker.image.tag | string | `"latest"` | Broker version tag. Use component version (e.g., "v1.0.0") or "latest" |
| broker.imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| broker.nameOverride | string | `""` | Override the name of the broker resources |
| broker.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for the kguardian broker pod assignment |
| broker.podAnnotations | object | `{}` | Annotations to add to broker pods |
| broker.podSecurityContext | object | `{"fsGroup":1000,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":1000,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"},"supplementalGroups":[1000]}` | Broker pod security context. Runs as non-root user 1000 |
| broker.priorityClassName | string | `""` | Priority class to be used for the kguardian broker pods |
| broker.replicaCount | int | `1` | Number of broker replicas to deploy |
| broker.resources | object | `{}` | Broker pod resource requests and limits |
| broker.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":1000}` | Broker container security context. Hardened with read-only root filesystem |
| broker.service.name | string | `"broker"` | Broker service name |
| broker.service.port | int | `9090` | Broker service port |
| broker.service.type | string | `"ClusterIP"` | Broker service type |
| broker.serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| broker.serviceAccount.automountServiceAccountToken | bool | `false` | Automount API credentials for a service account |
| broker.serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| broker.serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| broker.tolerations | list | `[]` | Tolerations for the kguardian broker pod assignment |
| controller.affinity | object | `{}` | Affinity rules for controller pod assignment |
| controller.autoscaling.enabled | bool | `false` | Enable horizontal pod autoscaling for controller |
| controller.autoscaling.maxReplicas | int | `100` | Maximum number of controller replicas |
| controller.autoscaling.minReplicas | int | `1` | Minimum number of controller replicas |
| controller.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage for autoscaling |
| controller.excludedNamespaces | list | `["kguardian","kube-system"]` | Namespaces to be excluded from monitoring (comma-separated list) |
| controller.fullnameOverride | string | `""` | Override the full name of the controller resources |
| controller.ignoreDaemonSet | bool | `true` | Ignore traffic from daemonset pods to reduce noise |
| controller.image.pullPolicy | string | `"Always"` | Controller image pull policy |
| controller.image.repository | string | `"ghcr.io/kguardian-dev/kguardian/controller"` | Controller container image repository |
| controller.image.sha | string | `""` | Overrides the image tag using SHA digest |
| controller.image.tag | string | `"latest"` | Controller version tag. Use component version (e.g., "v1.0.0") or "latest" |
| controller.imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| controller.initContainer.image.pullPolicy | string | `"Always"` | Init container image pull policy |
| controller.initContainer.image.repository | string | `"busybox"` | Init container image repository |
| controller.initContainer.image.tag | string | `"latest"` | Init container image tag |
| controller.initContainer.securityContext | object | `{}` | Init container security context |
| controller.nameOverride | string | `""` | Override the name of the controller resources |
| controller.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for the kguardian controller pod assignment |
| controller.podAnnotations | object | `{}` | Annotations to add to controller pods |
| controller.podSecurityContext | object | `{"seccompProfile":{"type":"RuntimeDefault"}}` | Controller pod security context. Runs with seccomp RuntimeDefault profile |
| controller.priorityClassName | string | `""` | Priority class to be used for the kguardian controller pods |
| controller.resources | object | `{}` | Controller pod resource requests and limits |
| controller.securityContext | object | `{"allowPrivilegeEscalation":true,"capabilities":{"add":["CAP_BPF"]},"privileged":true,"readOnlyRootFilesystem":true}` | Controller container security context. Requires privileged mode for eBPF |
| controller.service.port | int | `80` | Controller service port |
| controller.service.type | string | `"ClusterIP"` | Controller service type |
| controller.serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| controller.serviceAccount.automountServiceAccountToken | bool | `false` | Automount API credentials for a service account |
| controller.serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| controller.serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| controller.tolerations | list | `[{"effect":"NoSchedule","key":"node-role.kubernetes.io/control-plane","operator":"Exists"}]` | Tolerations for the kguardian controller pod assignment |
| database.affinity | object | `{}` | Affinity rules for database pod assignment |
| database.autoscaling.enabled | bool | `false` | Enable horizontal pod autoscaling for database |
| database.autoscaling.maxReplicas | int | `100` | Maximum number of database replicas |
| database.autoscaling.minReplicas | int | `1` | Minimum number of database replicas |
| database.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage for autoscaling |
| database.container.port | int | `5432` | PostgreSQL container port |
| database.fullnameOverride | string | `""` | Override the full name of the database resources |
| database.image.pullPolicy | string | `"Always"` | PostgreSQL image pull policy |
| database.image.repository | string | `"postgres"` | PostgreSQL container image repository |
| database.image.sha | string | `""` | Overrides the image tag using SHA digest |
| database.image.tag | string | `"latest"` | PostgreSQL image tag |
| database.imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| database.name | string | `"guardian-db"` | Database name for PostgreSQL |
| database.nameOverride | string | `""` | Override the name of the database resources |
| database.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for the kguardian database pod assignment |
| database.persistence.enabled | bool | `false` | Enable persistent storage for database |
| database.persistence.existingClaim | string | `""` | Use an existing PersistentVolumeClaim instead of creating a new one |
| database.podAnnotations | object | `{}` | Annotations to add to database pods |
| database.podSecurityContext | object | `{"fsGroup":999,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":999,"runAsUser":999,"seccompProfile":{"type":"RuntimeDefault"},"supplementalGroups":[999]}` | Database pod security context. Runs as postgres user (999) |
| database.priorityClassName | string | `""` | Priority class to be used for the kguardian database pods |
| database.resources | object | `{}` | Database pod resource requests and limits |
| database.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":false,"runAsNonRoot":true,"runAsUser":999}` | Database container security context. Non-root with dropped capabilities |
| database.service.name | string | `"guardian-db"` | Database service name |
| database.service.port | int | `5432` | Database service port |
| database.service.type | string | `"ClusterIP"` | Database service type |
| database.serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| database.serviceAccount.automountServiceAccountToken | bool | `false` | Automount API credentials for a service account |
| database.serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| database.serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| database.tolerations | list | `[]` | Tolerations for the kguardian database pod assignment |
| global.annotations | object | `{}` | Annotations to apply to all resources |
| global.labels | object | `{}` | Labels to apply to all resources |
| global.priorityClassName | string | `""` | Priority class to be used for the kguardian pods |
| namespace.annotations | object | `{}` | Annotations to add to the namespace |
| namespace.labels | object | `{}` | Labels to add to the namespace |
| namespace.name | string | `""` | Namespace name. If empty, uses the release namespace |
| ui.affinity | object | `{}` | Affinity rules for UI pod assignment |
| ui.autoscaling.enabled | bool | `false` | Enable horizontal pod autoscaling for UI |
| ui.autoscaling.maxReplicas | int | `100` | Maximum number of UI replicas |
| ui.autoscaling.minReplicas | int | `1` | Minimum number of UI replicas |
| ui.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage for autoscaling |
| ui.container.port | int | `80` | UI container port |
| ui.fullnameOverride | string | `""` | Override the full name of the UI resources |
| ui.image.pullPolicy | string | `"Always"` | UI image pull policy |
| ui.image.repository | string | `"ghcr.io/kguardian-dev/kguardian/frontend"` | UI container image repository |
| ui.image.sha | string | `""` | Overrides the image tag using SHA digest |
| ui.image.tag | string | `"latest"` | UI version tag. Use component version (e.g., "v1.0.0") or "latest" |
| ui.imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| ui.nameOverride | string | `""` | Override the name of the UI resources |
| ui.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for the kguardian UI pod assignment |
| ui.podAnnotations | object | `{}` | Annotations to add to UI pods |
| ui.podSecurityContext | object | `{"fsGroup":101,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":101,"runAsUser":101,"seccompProfile":{"type":"RuntimeDefault"},"supplementalGroups":[101]}` | UI pod security context. Runs as nginx user (101) |
| ui.priorityClassName | string | `""` | Priority class to be used for the kguardian UI pods |
| ui.replicaCount | int | `1` | Number of UI replicas to deploy |
| ui.resources | object | `{}` | UI pod resource requests and limits |
| ui.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":101}` | UI container security context. Hardened with read-only root filesystem |
| ui.service.name | string | `"ui"` | UI service name |
| ui.service.port | int | `80` | UI service port |
| ui.service.type | string | `"ClusterIP"` | UI service type |
| ui.serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| ui.serviceAccount.automountServiceAccountToken | bool | `false` | Automount API credentials for a service account |
| ui.serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| ui.serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| ui.tolerations | list | `[]` | Tolerations for the kguardian UI pod assignment |

## Uninstalling the Chart

To uninstall/delete the my-release deployment:

```bash
helm uninstall my-release
```
