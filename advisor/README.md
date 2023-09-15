Sudo Filter Logic
=================

For Pod get all the traffic relating to it
Get the PodSpec for the Pod
Iterate all Ingress for each Source Pod
  - Iterate all the ports for the pod where ingress is expected
  - Add the namespace (respect kubernetes.io/metadata.name)
  -  Checkdeployment controller -> labels (can't respect app.kubernetes.io/name and/or app.kubernetes.io/instance)
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








NetPol

type PodTraffic struct {
	UUID         string      `yaml:"uuid" json:"uuid"`
	SrcPodName   string      `yaml:"pod_name" json:"pod_name"`
	SrcIP        string      `yaml:"pod_ip" json:"pod_ip"`
	SrcNamespace string      `yaml:"pod_namespace" json:"pod_namespace"`
	SrcPodPort   string      `yaml:"pod_port" json:"pod_port"`
	TrafficType  string      `yaml:"traffic_type" json:"traffic_type"`
	DstIP        string      `yaml:"traffic_in_out_ip" json:"traffic_in_out_ip"`
	DstPort      string      `yaml:"traffic_in_out_port" json:"traffic_in_out_port"`
	Protocol     v1.Protocol `yaml:"ip_protocol" json:"ip_protocol"`
}

type PodDetail struct {
	UUID      string `yaml:"uuid" json:"uuid"`
	PodIP     string `yaml:"pod_ip" json:"pod_ip"`
	Name      string `yaml:"pod_name" json:"pod_name"`
	Namespace string `yaml:"pod_namespace" json:"pod_namespace"`
	Pod       v1.Pod `yaml:"pod_obj" json:"pod_obj"`
}


When [POD] receives INGRESS the network policy for INGRESS should use DstIP to get the PodDetails for that PodIP. The SrcPodPort is the port the INGRESS traffic came through.

When [POD] receives EGRESS the network policy for EGRESS should use DstIP to get the PodDetails for that PodIP. The DstPort is the port the EGRESS traffic left through.
