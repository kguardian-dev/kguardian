#!/bin/bash

veth_interfaces=$(ip -o link show | awk -F ': |@' '{print $2}')

# Loop through each veth interface
for interface in $veth_interfaces; do
  # Process each veth interface here
  tc filter del dev $interface egress prio 1 handle 0x63 bpf
  # Add your desired actions or commands here
done


## TODO Unload ebpf on exit