#!/usr/bin/env python3
"""eBPF-based ransomware behavior detector (BCC).  Run with sudo."""
import argparse, time, os, ctypes as ct
from collections import defaultdict
from bcc import BPF

# ── Kernel eBPF C program ────────────────────────────────────────────
BPF_SRC = r"""
#include <uapi/linux/ptrace.h>

struct event { u64 ts; u32 pid; u32 kind; char comm[16]; char path[256]; };
BPF_PERF_OUTPUT(events);

#ifdef KILL
BPF_HASH(blocked, u32, u8);
#endif

/* Read path, keep only /tmp/victim/*, emit to perf buffer. */
static inline int emit(void *ctx, u32 kind, const char *path) {
    struct event e = {};
    int len = bpf_probe_read_user_str(e.path, sizeof(e.path), path);
    if (len < 13) return 0;
    /* unrolled 12-char prefix check: "/tmp/victim/" */
    if (e.path[0] != '/' || e.path[1] != 't' || e.path[2] != 'm' ||
        e.path[3] != 'p' || e.path[4] != '/' || e.path[5] != 'v' ||
        e.path[6] != 'i' || e.path[7] != 'c' || e.path[8] != 't' ||
        e.path[9] != 'i' || e.path[10] != 'm' || e.path[11] != '/')
        return 0;
    e.pid = bpf_get_current_pid_tgid() >> 32;
#ifdef KILL
    u8 *b = blocked.lookup(&e.pid);
    if (b) bpf_send_signal(9);
#endif
    e.ts   = bpf_ktime_get_ns();
    e.kind = kind;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

/* ---- tracepoint probes (written out explicitly for BCC) ---- */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    if (!(args->flags & 0x243)) return 0;   /* write|create|trunc */
    return emit(args, 0, args->filename);
}
TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
    return emit(args, 1, args->newname);
}
TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
    return emit(args, 1, args->newname);
}
TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    return emit(args, 1, args->newname);
}
"""

# ── ctypes mirror of struct event ────────────────────────────────────
class Event(ct.Structure):
    _fields_ = [("ts", ct.c_uint64), ("pid", ct.c_uint32),
                ("kind", ct.c_uint32), ("comm", ct.c_char * 16),
                ("path", ct.c_char * 256)]

# ── CLI ──────────────────────────────────────────────────────────────
ap = argparse.ArgumentParser(description="eBPF ransomware detector")
ap.add_argument("--block", action="store_true", help="kill flagged PIDs")
ap.add_argument("-v", action="store_true", help="verbose event log")
args = ap.parse_args()

# ── Load BPF (add -DKILL only when --block) ──────────────────────────
b = BPF(text=BPF_SRC, cflags=["-DKILL"] if args.block else [])

windows = defaultdict(list)   # pid -> [(kernel_ts_ns, weight)]
alerted = set()               # pids already alerted
CSV = "latency.csv"

if not os.path.exists(CSV):
    open(CSV, "w").write("pid,latency_us,time_to_detect_us\n")

# ── Perf-buffer callback ─────────────────────────────────────────────
def handle_event(cpu, data, size):
    e    = ct.cast(data, ct.POINTER(Event)).contents
    path = e.path.decode(errors="replace")
    now  = time.monotonic_ns()

    # weight: suspicious rename extension → 5, everything else → 1
    w = 5 if e.kind == 1 and any(path.endswith(x)
            for x in (".locked", ".enc", ".crypt")) else 1

    if args.v:
        tag = "OPEN" if e.kind == 0 else "RENAME"
        print(f"  {tag} pid={e.pid} w={w} {path}")

    # sliding 1-second window
    win = windows[e.pid]
    win.append((e.ts, w))
    cutoff = e.ts - 1_000_000_000
    windows[e.pid] = win = [(t, wt) for t, wt in win if t >= cutoff]

    if e.pid in alerted:
        return
    if sum(wt for _, wt in win) >= 20:
        alerted.add(e.pid)
        lat = (now - e.ts) // 1000          # event-to-alert  (µs)
        ttd = (now - win[0][0]) // 1000     # first-event-to-alert (µs)
        print(f"\033[91m[ALERT] pid={e.pid} mass file modification | "
              f"latency={lat}us time-to-detect={ttd}us\033[0m")
        with open(CSV, "a") as f:
            f.write(f"{e.pid},{lat},{ttd}\n")
        if args.block:
            b["blocked"][ct.c_uint32(e.pid)] = ct.c_uint8(1)
            print(f"\033[93m[BLOCK] pid={e.pid} added to kill list\033[0m")

# ── Main loop ────────────────────────────────────────────────────────
b["events"].open_perf_buffer(handle_event)
mode = " [BLOCK mode]" if args.block else ""
print(f"detector: watching /tmp/victim/ …{mode}  Ctrl-C to stop")
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\ndetector: stopped")
