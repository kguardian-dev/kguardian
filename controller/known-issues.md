|issue|explanation|
|-----|-----------|
|Ingress traffic not recorded for pods with `hostNetwork:true`| We attach the tc ebpf programs to veth interface of pods, since there is no veth pairs created for pods with `hostNetwork:true`, the  ingress traffic can't be recorded|
|Traffic not recorded on cilium's cni with ebpf masquerade set to true| | 
