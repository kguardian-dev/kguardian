# Xentra Helm Chart

This chart bootstraps the [Xentra]() controlplane onto a [Kubernetes](http://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

![Version: 0.0.7](https://img.shields.io/badge/Version-0.0.7-informational?style=flat-square)

## Overview

This Helm chart deploys:

- A Xentra control plane configured to your specifications
- Additional features and components (optional)

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+

**Note:** *If you're using cilium ensure the following setting is set otherwise PodIPs are not correctly aggregated when determining traffic origin and desgination: `bpf.masquerade: false`*

## Install the Chart

To install the chart with the release name `my-release`:

Add the chart repo

```bash
helm repo add xentra https://xentra-ai.github.io/charts
```

You can then run `helm search repo xentra` to search the charts.

Install chart using Helm v3.0+

```bash
helm install kube-guardian xentra/kube-guardian --namespace kube-guardian --create-namespace
```

If you want to use the OCI variant of the helm chart, you can use the following command:

```bash
helm template kube-guardian oci://ghcr.io/xentra-ai/charts/kube-guardian --namespace kube-guardian --create-namespace
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
  name: kube-guardian
```

## Directory Structure

The following shows the directory structure of the Helm chart.

```bash
charts/xentra/
├── .helmignore   # Contains patterns to ignore when packaging Helm charts.
├── Chart.yaml    # Information about your chart
├── values.yaml   # The default values for your templates
├── charts/       # Charts that this chart depends on
└── templates/    # The template files
    └── tests/    # The test files
```

## Configuration

The following table lists the configurable parameters of the Xentra chart and their default values.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| broker.affinity | object | `{}` |  |
| broker.autoscaling.enabled | bool | `false` |  |
| broker.autoscaling.maxReplicas | int | `100` |  |
| broker.autoscaling.minReplicas | int | `1` |  |
| broker.autoscaling.targetCPUUtilizationPercentage | int | `80` |  |
| broker.container.port | int | `9090` |  |
| broker.fullnameOverride | string | `""` |  |
| broker.image.pullPolicy | string | `"Always"` |  |
| broker.image.repository | string | `"ghcr.io/xentra-ai/images/guardian-broker"` |  |
| broker.image.sha | string | `""` |  |
| broker.image.tag | string | `"latest"` |  |
| broker.imagePullSecrets | list | `[]` |  |
| broker.nameOverride | string | `""` |  |
| broker.nodeSelector | object | `{"kubernetes.io/arch":"amd64"}` | Node labels for the kube-guardian broker pod assignment |
| broker.podAnnotations | object | `{}` |  |
| broker.podSecurityContext | object | `{}` |  |
| broker.priorityClassName | string | `""` |  |
| broker.replicaCount | int | `1` | Number of broker replicas to deploy |
| broker.resources | object | `{}` |  |
| broker.securityContext | object | `{}` |  |
| broker.service.name | string | `"broker"` |  |
| broker.service.port | int | `9090` |  |
| broker.service.type | string | `"ClusterIP"` |  |
| broker.serviceAccount.annotations | object | `{}` |  |
| broker.serviceAccount.automountServiceAccountToken | bool | `false` |  |
| broker.serviceAccount.create | bool | `true` |  |
| broker.serviceAccount.name | string | `""` |  |
| broker.tolerations | list | `[]` | Tolerations for the kube-guardian broker pod assignment |
| controller.affinity | object | `{}` |  |
| controller.autoscaling.enabled | bool | `false` |  |
| controller.autoscaling.maxReplicas | int | `100` |  |
| controller.autoscaling.minReplicas | int | `1` |  |
| controller.autoscaling.targetCPUUtilizationPercentage | int | `80` |  |
| controller.fullnameOverride | string | `""` |  |
| controller.image.pullPolicy | string | `"Always"` |  |
| controller.image.repository | string | `"ghcr.io/xentra-ai/images/guardian-controller"` |  |
| controller.image.sha | string | `""` | Overrides the image tag. |
| controller.image.tag | string | `"latest"` |  |
| controller.imagePullSecrets | list | `[]` |  |
| controller.nameOverride | string | `""` |  |
| controller.nodeSelector | object | `{"kubernetes.io/arch":"amd64"}` | Node labels for the kube-guardian controller pod assignment |
| controller.podAnnotations | object | `{}` |  |
| controller.podSecurityContext | object | `{}` |  |
| controller.priorityClassName | string | `""` | Priority class to be used for the kube-guardian controller pods |
| controller.resources | object | `{}` |  |
| controller.securityContext | object | `{}` |  |
| controller.service.port | int | `80` |  |
| controller.service.type | string | `"ClusterIP"` |  |
| controller.serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| controller.serviceAccount.automountServiceAccountToken | bool | `false` | Automount API credentials for a service account |
| controller.serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| controller.serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| controller.tolerations | list | `[{"effect":"NoSchedule","key":"node-role.kubernetes.io/control-plane","operator":"Exists"}]` | Tolerations for the kube-guardian controller pod assignment |
| database.affinity | object | `{}` |  |
| database.autoscaling.enabled | bool | `false` |  |
| database.autoscaling.maxReplicas | int | `100` |  |
| database.autoscaling.minReplicas | int | `1` |  |
| database.autoscaling.targetCPUUtilizationPercentage | int | `80` |  |
| database.container.port | int | `5432` |  |
| database.fullnameOverride | string | `""` |  |
| database.image.pullPolicy | string | `"Always"` |  |
| database.image.repository | string | `"postgres"` |  |
| database.image.sha | string | `""` |  |
| database.image.tag | string | `"latest"` |  |
| database.imagePullSecrets | list | `[]` |  |
| database.name | string | `"guardian-db"` |  |
| database.nameOverride | string | `""` |  |
| database.nodeSelector | object | `{}` | Node labels for the kube-guardian database pod assignment |
| database.persistence.enabled | bool | `false` |  |
| database.persistence.existingClaim | string | `""` |  |
| database.podAnnotations | object | `{}` |  |
| database.podSecurityContext | object | `{}` |  |
| database.priorityClassName | string | `""` | Priority class to be used for the kube-guardian database pods |
| database.resources | object | `{}` |  |
| database.securityContext | object | `{}` |  |
| database.service.name | string | `"guardian-db"` |  |
| database.service.port | int | `80` |  |
| database.service.type | string | `"ClusterIP"` |  |
| database.serviceAccount.annotations | object | `{}` |  |
| database.serviceAccount.automountServiceAccountToken | bool | `false` |  |
| database.serviceAccount.create | bool | `true` |  |
| database.serviceAccount.name | string | `""` |  |
| database.tolerations | list | `[]` | Tolerations for the kube-guardian database pod assignment |
| global.annotations | object | `{}` | Annotations to apply to all resources |
| global.labels | object | `{}` | Labels to apply to all resources |
| global.priorityClassName | string | `""` | Priority class to be used for the kube-guardian pods |
| namespace.annotations | object | `{}` | Annotations to add to the namespace |
| namespace.labels | object | `{}` | Labels to add to the namespace |
| namespace.name | string | `""` |  |

## Uninstalling the Chart

To uninstall/delete the my-release deployment:

```bash
helm uninstall my-release
```
