#!/usr/bin/env python3
"""Print latency statistics from latency.csv."""
import csv, statistics

rows = list(csv.DictReader(open("latency.csv")))
if not rows:
    raise SystemExit("latency.csv is empty — run detector + attack first")

for col in ("latency_us", "time_to_detect_us"):
    v = [int(r[col]) for r in rows]
    p95 = statistics.quantiles(v, n=100, method="inclusive")[94]
    print(f"{col}:  min={min(v)}  median={statistics.median(v):.0f}"
          f"  p95={p95:.0f}  max={max(v)}  (n={len(v)})")
