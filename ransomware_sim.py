#!/usr/bin/env python3
"""Safe ransomware simulator — only touches /tmp/victim/."""
import sys, os, shutil, time

DIR = "/tmp/victim"

def setup():
    if os.path.exists(DIR):
        shutil.rmtree(DIR)
    os.makedirs(DIR)
    for i in range(100):
        with open(f"{DIR}/file_{i:03d}.txt", "w") as f:
            f.write(f"important data {i}\n" * 4)
    print(f"setup: created 100 files in {DIR}")

def attack():
    files = sorted(f for f in os.listdir(DIR) if f.endswith(".txt"))
    for i, name in enumerate(files):
        p = os.path.join(DIR, name)
        data = open(p, "rb").read()
        with open(p, "wb") as f:          # overwrite with random bytes
            f.write(os.urandom(len(data)))
        os.rename(p, p + ".locked")       # rename to .locked
        print(f"  [{i+1}/{len(files)}] {name} -> {name}.locked")
    print("attack: done")

def benign():
    os.makedirs(DIR, exist_ok=True)
    for i in range(10):
        with open(f"{DIR}/benign_{i}.txt", "w") as f:
            f.write("normal log line\n")
        print(f"  benign write {i+1}/10")
        time.sleep(0.5)
    print("benign: done")

if __name__ == "__main__":
    cmds = {"setup": setup, "attack": attack, "benign": benign}
    if len(sys.argv) != 2 or sys.argv[1] not in cmds:
        sys.exit(f"usage: {sys.argv[0]} {{setup|attack|benign}}")
    cmds[sys.argv[1]]()
