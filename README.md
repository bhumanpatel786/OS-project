# eBPF Ransomware Guard

## Overview

This project implements a lightweight, real-time ransomware behavior detection
framework using eBPF on Linux.  An in-kernel eBPF program attaches to file-system
syscall tracepoints (`openat`, `rename`, `renameat`, `renameat2`), filters events
targeting a watched directory (`/tmp/victim/`), and streams them via a perf buffer
to a Python user-space detector.  The detector applies a per-process sliding-window
scoring heuristic — weighting suspicious rename extensions (`.locked`, `.enc`,
`.crypt`) higher than plain writes — and raises an alert when the score exceeds a
threshold within one second.  An optional **blocking mode** (`--block`) pushes the
offending PID into a kernel-side hash map so that the eBPF program kills it on its
very next syscall via `bpf_send_signal(9)`.

## Files

| File               | Lines | Purpose                                       |
|--------------------|-------|-----------------------------------------------|
| `detector.py`      | ~90   | BCC eBPF detector: probes, scoring, alerting  |
| `ransomware_sim.py`| ~35   | Safe simulator: setup / attack / benign modes |
| `stats.py`         | ~12   | Reads `latency.csv`, prints min/med/p95/max   |
| `run_bench.sh`     | ~13   | Runs N attack cycles, then calls `stats.py`   |
| `README.md`        | —     | This file                                     |

## Architecture

```
 ┌───────────────────┐
 │  User Process     │   open("/tmp/victim/f.txt", O_WRONLY)
 │  (ransomware_sim) │   rename("f.txt", "f.txt.locked")
 └────────┬──────────┘
          │ syscall
          ▼
 ┌───────────────────────────────────────────────┐
 │              Kernel  Tracepoints              │
 │  sys_enter_openat  sys_enter_rename(at|at2)   │
 └────────┬──────────────────────────────────────┘
          │
          ▼
 ┌───────────────────────────────────────────────┐
 │              eBPF  Programs                   │
 │  emit():  read path → prefix filter           │
 │           → bpf_ktime_get_ns() → perf_submit  │
 │  ┌─────────────────────────────────┐          │
 │  │ (--block) blocked BPF_HASH map  │          │
 │  │  if pid in map → SIGKILL        │          │
 │  └─────────────────────────────────┘          │
 └────────┬──────────────────────────────────────┘
          │ perf buffer
          ▼
 ┌───────────────────────────────────────────────┐
 │         Python Detector (user space)          │
 │  per-PID sliding 1 s window  →  score ≥ 20?  │
 │  YES → [ALERT] + log latency.csv             │
 │        (--block) → insert pid into blocked    │
 └───────────────────────────────────────────────┘
```

## Setup

```bash
# Tested on Ubuntu 22.04 / 24.04, kernel >= 5.5
sudo apt update
sudo apt install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)

# Clone / copy the five project files into a directory
cd ebpf-ransomware-guard
chmod +x run_bench.sh
```

## 5-Minute Demo

Open **two terminals** in the project directory.

### Step 1 — Start detector (Terminal 1)

```bash
sudo python3 detector.py -v
```

### Step 2 — Benign workload (Terminal 2) → no alert expected

```bash
python3 ransomware_sim.py setup
python3 ransomware_sim.py benign
```

You should see individual `OPEN` events in the detector but **no `[ALERT]`** because
only 10 files are written over 5 seconds (score never reaches 20).

### Step 3 — Attack (Terminal 2) → alert expected!

```bash
python3 ransomware_sim.py setup
python3 ransomware_sim.py attack
```

The detector prints a red **`[ALERT]`** within the first few files,
showing `latency` and `time-to-detect` in microseconds.

### Step 4 — Blocking mode (Terminal 1: restart)

```bash
sudo python3 detector.py --block -v
```

```bash
# Terminal 2
python3 ransomware_sim.py setup
python3 ransomware_sim.py attack     # ← gets killed mid-way!
```

The detector prints `[ALERT]` then `[BLOCK]`.  The simulator process is
killed by `SIGKILL` on its next syscall, leaving some files unencrypted.

### Step 5 — View stats

```bash
python3 stats.py
```

## Evaluation & Latency Measurement

Both timestamps use **`CLOCK_MONOTONIC`**:

| Metric              | Formula                                       |
|---------------------|-----------------------------------------------|
| `latency_us`        | `time.monotonic_ns() − event.ts` (kernel ktime) of the event that crossed the threshold, converted to µs |
| `time_to_detect_us` | `time.monotonic_ns() − first_event_ts` in the sliding window, converted to µs |

These are appended to `latency.csv` for every alert.  Run multiple attack
cycles with `run_bench.sh` to collect enough data points:

```bash
# Start detector in another terminal first!
sudo bash run_bench.sh 30
```

## Results

> Fill this table after running the benchmark on your own machine.

| Metric              | Min (µs) | Median (µs) | P95 (µs) | Max (µs) | n  |
|---------------------|----------|-------------|-----------|----------|----|
| `latency_us`        |          |             |           |          |    |
| `time_to_detect_us` |          |             |           |          |    |

## Why Kernel-Level Blocking Is the "Advanced Milestone"

The mandatory tier (monitoring + detection + alerting) runs entirely in user
space after receiving perf-buffer events — it requires **no special kernel
config** beyond basic eBPF tracepoint support.

Blocking with `bpf_send_signal(9)` is the optional advanced feature because:

1. **It is reactive, not preventive.** The signal is delivered on the *next*
   syscall the flagged process makes.  The syscall that triggered the alert
   has already completed, so the file it touched is still modified.
2. **True denial** — stopping the syscall *before* it executes — requires
   either:
   - **`bpf_override_return`** (needs `CONFIG_BPF_KPROBE_OVERRIDE`):
     ```bash
     grep CONFIG_BPF_KPROBE_OVERRIDE /boot/config-$(uname -r)
     ```
   - **BPF LSM hooks** (needs `CONFIG_BPF_LSM` and `lsm=bpf` boot param):
     ```bash
     grep CONFIG_BPF_LSM /boot/config-$(uname -r)
     cat /sys/kernel/security/lsm
     ```
   Most stock Ubuntu kernels do **not** enable these, so they are out of
   scope for this demo project.

## Limitations

| # | Limitation | Explanation |
|---|-----------|-------------|
| 1 | **Hard-coded folder** | Only `/tmp/victim/` is monitored; real deployments would watch `/home`, `/etc`, etc. |
| 2 | **False positives on bulk copies** | `cp -r` or `tar xf` into the watched folder generates rapid opens and could trigger an alert. |
| 3 | **Python user-space overhead** | The perf-buffer callback runs in CPython, adding ~50–200 µs of latency vs. a pure C or Rust consumer. |
| 4 | **Slow ransomware evades the window** | An attacker encrypting one file every 2 seconds stays under the 1-second sliding window threshold. |
| 5 | **Reactive kill only** | `bpf_send_signal` kills on the *next* syscall; the triggering write already succeeded (see above). |

## Work Split (5 Members)

| Member | Responsibility |
|--------|---------------|
| **A** | eBPF C probes: `emit()` helper, tracepoint functions, blocked map |
| **B** | Python detector: perf-buffer callback, sliding-window scoring, CSV logging |
| **C** | Ransomware simulator (`ransomware_sim.py`): setup, attack, benign modes |
| **D** | Benchmarking: `run_bench.sh`, `stats.py`, collect and graph results |
| **E** | Documentation (`README.md`), architecture diagram, demo presentation |

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: No module named 'bcc'` | `sudo apt install python3-bpfcc` |
| `Failed to attach tracepoint` | Run with `sudo`.  Ensure `linux-headers-$(uname -r)` is installed. |
| `bpf_send_signal: unknown func` | Kernel too old (< 5.3).  Upgrade or run without `--block`. |
| `PermissionError` in simulator | The simulator only writes to `/tmp/victim/` — check directory permissions. |
| `latency.csv is empty` | The detector must be running **before** you start the attack. |
| No `[ALERT]` during attack | Delete `latency.csv` and restart the detector (the PID may already be in `alerted`). |
| Very high latency numbers | Ensure no heavy CPU load; Python GC pauses can add jitter. Try `nice -n -20`. |
| `run_bench.sh` permission denied | `chmod +x run_bench.sh` or run with `bash run_bench.sh`. |
