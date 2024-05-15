if the egress is to external -> just ip 
                             -> EXTERNAL
                             -> OR KNOW RANGE can be stored and map to the DNS name

* FIELD -> TRAFFIC_TYPE (EXTERNAL/INTERNAL) 
* IF THE SRC or DST doen't fall in POD_CIDR or SERVER_CIDR -> MAP TO EXTERNAL and parse the packet (HTTP)
* Annotation based : 
    NAMESPACE
    POD template spec
* Store the podspec in db in mapping table pod_id


TESTCASE:

1 SVC -> 3 pods : 1 netpol 






scenario: 

1. Newly deployed controller 
    Add label to Namespace:
       * Check the status o




```
2023-08-08T23:20:22.594574Z  INFO kube_guardian::tc: src 10.244.0.29, dst 10.96.227.215, ifIndex 30, ingressIfIndex 30 syn1 ack 0 traffic_type EGRESS
2023-08-08T23:20:22.594599Z  INFO kube_guardian::tc: src 10.244.0.29, dst 10.244.0.24, ifIndex 25, ingressIfIndex 30 syn1 ack 0 traffic_type INGRESS

```