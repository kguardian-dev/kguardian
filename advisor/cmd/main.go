package main

import (
	"fmt"
	"log"

	db "github.com/arx-inc/advisor/pkg/database"
	"github.com/arx-inc/advisor/pkg/k8s"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
)

const (
	// TODO: Remove these hardcoded values
	name      = "test-network-policy"
	namespace = "default"

	// TODO: replace these with your actual PostgreSQL connection details
	host     = "localhost"
	port     = 5432
	user     = "youruser"
	password = "yourpassword"
	dbname   = "yourdb"
)

func main() {

	// Decide whether to use real DB or stub
	var podTrafficGetter db.PodTrafficGetter
	useDB := false // change this to false to use the stub

	if useDB {
		var err error
		podTrafficGetter, err = db.NewDBConnection(host, port, user, password, dbname)
		if err != nil {
			log.Fatalf("Error opening database connection: %v\n", err)
			return
		}
		defer podTrafficGetter.(*db.DBConnection).Close()
	} else {
		podTrafficGetter = &db.PodTrafficStub{}
	}

	// example of querying for a specific UUID
	podName := "dummy-src-pod"
	podTraffic, err := podTrafficGetter.GetPodTraffic(podName)
	if err != nil {
		log.Fatalf("Error retrieving pod traffic: %v\n", err)
		return
	}

	if podTraffic != nil {
		fmt.Printf("Pod traffic for pod %s: %+v\n", podName, podTraffic)
	} else {
		fmt.Printf("No pod traffic found for pod %s\n", podName)
	}

	podSpec, err := podTrafficGetter.GetPodSpec(podTraffic.SrcPodName)
	if err != nil {
		log.Fatalf("Error retrieving pod spec: %v\n", err)
		return
	}

	if podSpec != nil {
		fmt.Printf("Pod spec for pod %s: %+v\n", podSpec.Name, podSpec.Spec)
	} else {
		fmt.Printf("No pod spec found for pod %s\n", podSpec)
	}

	// TODO: replace this with your actual network policy spec from the database
	spec := k8s.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"app": "MyApp",
			},
		},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		Ingress: []k8s.NetworkPolicyRule{
			{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Protocol: protoPtr(v1.ProtocolTCP),
						Port:     intStrPtr(8080),
					},
				},
				FromTo: []networkingv1.NetworkPolicyPeer{
					{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"access": "allowed",
							},
						},
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"kubernetes.io/metadata.name:": "some-namespace",
							},
						},
					},
				},
			},
		},
		Egress: []k8s.NetworkPolicyRule{
			{
				// No ports specified, so all ports are allowed
				Ports: []networkingv1.NetworkPolicyPort{},
				FromTo: []networkingv1.NetworkPolicyPeer{
					{
						// No pod selector or namespace selector specified, so all destinations are allowed
					},
				},
			},
		},
	}

	policy := k8s.CreateNetworkPolicy(name, namespace, spec)
	policyYAML, err := yaml.Marshal(policy)
	if err != nil {
		fmt.Printf("Error converting policy to YAML: %v", err)
		return
	}

	fmt.Println(string(policyYAML))
}

func protoPtr(protocol v1.Protocol) *v1.Protocol {
	return &protocol
}

func intStrPtr(port int32) *intstr.IntOrString {
	return &intstr.IntOrString{IntVal: port}
}
