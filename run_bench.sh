#!/usr/bin/env bash
# Benchmark: run N attack cycles while the detector is running separately.
# Usage: sudo bash run_bench.sh [N]   (default N=30)
set -e
N=${1:-30}
echo "=== Running $N attack cycles ==="
for i in $(seq 1 "$N"); do
    python3 ransomware_sim.py setup  > /dev/null
    python3 ransomware_sim.py attack > /dev/null
    sleep 0.2
    printf "\r  cycle %d/%d" "$i" "$N"
done
echo
echo "=== Latency statistics ==="
python3 stats.py
