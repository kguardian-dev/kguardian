Sudo Filter Logic
=================

type PodTraffic struct {
	UUID         string
	SrcPodName   string
	SrcIP        string
	SrcNamespace string
	DstPodName   string
	DstIP        string
	DstNamespace string
	TimeStamp    string
}

type PodSpec struct {
	UUID      string
	Name      string
	Namespace string
	Spec      map[string]interface{}
}

For Pod get all the traffic relating to it
Get the PodSpec for the Pod
Iterate all Ingress for each Source Pod
  - Iterate all the ports for the pod where ingress is expected
  - Add the namespace (respect kubernetes.io/metadata.name) and labels (respect app.kubernetes.io/name and/or app.kubernetes.io/instance)
Iterate all Egress for each Source Pod
  - Iterate all the ports for the pod where egress is expected
  - Add the namespace (respect kubernetes.io/metadata.name) and labels (respect app.kubernetes.io/name and/or app.kubernetes.io/instance)


Day 1 Assumptions
- All traffic is TCP
- All traffic is internal in-cluster
- PolicyType Ingress/Egress is always defined for a Pod in each network policy

Day 2?
- Potentially split ingress and egress into separate policies?
- Support CIDR ranges and external to cluster traffic
- All protocol types
