#!/bin/bash
# Run inside the stress VM (see controller-ebpf-stress.yaml):
#   ebpf-runtime-stress.sh <workspace> <iterations>
# Loops the real-runtime capability test with every CPU busy and prints
# the runtime object's drop counter per iteration, then a summary. Fails
# if any iteration fails.
set -u
ws=$1
n=${2:-50}
[[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le 500 ] || { echo "iterations must be 1-500"; exit 1; }
insmod "$ws/kernels/overlay-6.18.ko" 2>/dev/null || true
grep -q preempt=full /proc/cmdline || { echo "not booted with preempt=full"; exit 1; }
hogs=()
for _ in $(seq "$(nproc)"); do
  (while :; do :; done) &
  hogs+=($!)
done
trap 'kill "${hogs[@]}" 2>/dev/null' EXIT
fail=0
drops=0
for i in $(seq "$n"); do
  out=$(KG_RUNC="$ws/runtimes/runc" KG_CRUN="$ws/runtimes/crun" timeout 600 \
    "$ws/ebpf-load-test" --ignored --exact \
    bpf::tests::capability_setup_of_real_runtimes_is_not_counted --nocapture 2>&1)
  rc=$?
  line=$(grep -a -m1 '^runtime_drops:' <<<"$out")
  d=$(sed -n 's/^runtime_drops: sum \([0-9]*\).*/\1/p' <<<"$line")
  drops=$((drops + ${d:-0}))
  echo "iteration $i: exit=$rc ${line:-runtime_drops: (not printed)}"
  if [ "$rc" -ne 0 ]; then
    fail=$((fail + 1))
    grep -a -E 'panicked|on failure:|assertion|left|right' <<<"$out" | head -20
  fi
done
echo "stress summary: iterations=$n failed=$fail runtime_drops_total=$drops"
[ "$fail" -eq 0 ]
