package main

import (
	"fmt"

	"github.com/arx-inc/advisor/pkg/k8s"
)

const (
	name      = "test-network-policy"
	namespace = "default"
)

func main() {
	fmt.Println("Hello, World!")
	spec := k8s.NetworkPolicySpec{}
	policy := k8s.CreateNetworkPolicy(name, namespace, spec)
	fmt.Println(policy)
}
