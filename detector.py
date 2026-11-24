"""Cryptojacking review console. Run with --gui for the desktop interface."""
import argparse
import csv
import json
import os
import queue
import sqlite3
import threading
import tempfile
import time
from datetime import datetime
from pathlib import Path

from evidence import (ROOT, PORTABLE_NAMES, UNUSUAL, classify, file_hash, idle_seconds, match_peers, pool_addresses, pool_rules,
                      process_details, scan_bytes, windows_query)

THRESHOLD, REQUIRED_SAMPLES = 80.0, 10
DATA = Path(os.environ.get("LOCALAPPDATA", ROOT)) / "CryptojackingDetector"
FIELDS = ["timestamp", "process", "pid", "cpu_percent", "reason"]
SAMPLE = b"College demonstration file. This is plain text.\n"


def spreadsheet(value):
    s = str(value)
    return "'" + s if s.lstrip().startswith(("=", "+", "-", "@")) or s.startswith(("\t", "\r", "\n")) else s


def database():
    DATA.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DATA / "review.sqlite3", timeout=10)
    con.execute("CREATE TABLE IF NOT EXISTS trusted (digest TEXT PRIMARY KEY, path TEXT NOT NULL)")
    return con


def trust(item, enable):
    digest = file_hash(item["path"])
    if item.get("digest") != digest:
        raise ValueError("File changed or hash unavailable. Inspect this process again.")
    with database() as con:
        if enable:
            con.execute("INSERT OR REPLACE INTO trusted VALUES (?, ?)", (digest, item["path"]))
        else:
            con.execute("DELETE FROM trusted WHERE digest=?", (digest,))


class DemoSample:
    """A real, reversible move of an app-created text file in a private demo directory."""
    def __init__(self):
        DATA.mkdir(parents=True, exist_ok=True)
        self.folder = Path(tempfile.mkdtemp(prefix="training-", dir=DATA))
        vault = self.folder / "quarantine"
        vault.mkdir()
        self.original = self.folder / "sample.txt"
        self.isolated = vault / "sample.quarantined"
        self.original.write_bytes(SAMPLE)

    def move(self, restore=False):
        source, destination = (self.isolated, self.original) if restore else (self.original, self.isolated)
        if source.is_symlink() or destination.exists() or not source.is_file():
            raise ValueError("Sample is already in the requested state or has changed.")
        if source.stat().st_size != len(SAMPLE) or source.read_bytes() != SAMPLE:
            raise ValueError("The demo sample has changed.")
        source.rename(destination)
        return destination


def persist(item):
    item["time"] = datetime.now().astimezone().isoformat(timespec="seconds")
    DATA.mkdir(parents=True, exist_ok=True)
    stem = "demo_alerts" if item["mode"] == "Demo" else "alerts"
    # Compatible with version one's CSV columns. JSONL retains the full evidence.
    if item.get("manual"):
        stem = "process_reviews"
    with (DATA / (stem + ".csv")).open("a", encoding="utf-8", newline="") as out:
        writer = csv.writer(out)
        if out.tell() == 0:
            writer.writerow(FIELDS)
        writer.writerow([item["time"], spreadsheet(item["name"]), item["pid"], item["cpu"], item["verdict"]])
    with (DATA / (stem + ".jsonl")).open("a", encoding="utf-8") as out:
        out.write(json.dumps(item, ensure_ascii=True) + "\n")


def log_action(item, outcome):
    DATA.mkdir(parents=True, exist_ok=True)
    record = dict(time=datetime.now().astimezone().isoformat(timespec="seconds"),
                  name=item["name"], pid=item["pid"], path=item["path"],
                  digest=item.get("digest"), mode=item["mode"], outcome=outcome)
    with (DATA / "actions.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")


class Streaks:
    def __init__(self, needed):
        self.needed = needed
        self.counts = {}

    def update(self, readings):
        current = {key: min(self.needed + 1, self.counts.get(key, 0) + 1)
                   for key, load in readings.items() if load >= THRESHOLD}
        self.counts = current
        return {key for key, value in current.items() if value == self.needed}


def demo(emit, stop, delay=0):
    """Use the same streak counter, byte scanner and classifier as live mode."""
    streaks = Streaks(REQUIRED_SAMPLES)
    for name, pid, sequence, has_clues in [
        ("Idle + short spike", 8101, [2, 2, 94, 94, 2], False),
        ("Video export", 8102, [95] * 12, False),
        ("Pool client sample", 8104, [95] * 12, True),
        ("Simulated miner", 8103, [95] * 12, True),
    ]:
        key = (pid, 0)
        for cpu in sequence:
            if stop.is_set():
                return
            row = dict(name=name, pid=pid, born=0, cpu=cpu, gpu=None)
            emit("snapshot", ([row], None, "Simulated readings"))
            if key in streaks.update({key: cpu}):
                binary = b"fixture stratum+tcp://pool.example.invalid" if has_clues else b"video-frame"
                markers, entropy = scan_bytes(binary)
                item = dict(**row, mode="Demo", path=f"DEMO/{name}.txt", load="High CPU for 10 readings",
                            idle=None, endpoints=["192.0.2.10:3333"] if pid == 8103 else [],
                            pool_matches=match_peers([("192.0.2.10", 3333)], {"192.0.2.10": "Simulated pool list"}) if pid == 8103 else [],
                            markers=markers, entropy=entropy, startup=[], signature="Simulated",
                            network="Simulated TCP snapshot", notes=["Generated test evidence"], trusted=False)
                item["verdict"] = classify(item)
                persist(item)
                emit("finding", item)
            stop.wait(delay)
    emit("status", "Demo complete. Select a finding to review its evidence.")


class Live:
    def __init__(self, emit, stop):
        self.emit, self.stop = emit, stop
        self.jobs = queue.Queue(maxsize=32)
        self.pending = set()
        self.lock = threading.Lock()
        self.gpu = None
        self.gpu_mark = None
        self.rules = pool_rules()
        self.pool_status = "Pool check pending"

    def request(self, row, reason="", idle=None, pool_observation=()):
        key = (row["pid"], row["born"])
        with self.lock:
            if key in self.pending:
                return
            try:
                self.jobs.put_nowait((row, reason, idle, pool_observation))
                self.pending.add(key)
                return True
            except queue.Full:
                self.emit("status", "Review queue full. Inspect the process again when pending reviews finish.")

    def investigate(self):
        while not self.stop.is_set():
            try:
                row, reason, idle, observation = self.jobs.get(timeout=.3)
            except queue.Empty:
                continue
            try:
                load = reason if reason.startswith(("CPU ", "GPU ")) else (row.get("load") or reason)
                item = process_details(row["pid"], row["born"], row["cpu"], row["gpu"], load, self.rules, idle)
                if observation:
                    item["pool_matches"] = sorted(set(item["pool_matches"]).union(observation))
                    item["verdict"] = classify(item)
                if item["name"] == "Unavailable":
                    item["name"] = row["name"]
                item["manual"] = not reason
                item["trusted"] = False
                if item["path"]:
                    try:
                        item["digest"] = file_hash(item["path"])
                        with database() as con:
                            item["trusted"] = bool(con.execute("SELECT 1 FROM trusted WHERE digest=?", (item["digest"],)).fetchone())
                    except (OSError, ValueError) as exc:
                        item["notes"].append(f"Hash unavailable: {exc}")
                # Allowlisting mutes load-only alerts. Mining-specific evidence stays visible.
                if not (item["trusted"] and item["verdict"] == UNUSUAL and not item["manual"]):
                    persist(item)
                    self.emit("finding", item)
            except Exception as exc:
                self.emit("status", f"Review failed: {exc}")
            finally:
                with self.lock:
                    self.pending.discard((row["pid"], row["born"]))

    def pool_poll(self):
        """Passive local connection table. Report new pool matches even at low CPU."""
        import psutil
        active = set()
        while not self.stop.is_set():
            cache = windows_query("dns", None) if self.rules[0] else []
            table = pool_addresses(self.rules, cache)
            self.pool_status = f"Pool IPs available: {len(table)}"
            if cache is None:
                self.pool_status += " (DNS unavailable)"
            if table:
                try:
                    started = time.time()
                    peers = {}
                    for c in psutil.net_connections(kind="tcp"):
                        if c.pid and c.status == psutil.CONN_ESTABLISHED and c.raddr and c.raddr.ip in table:
                            peers.setdefault(c.pid, set()).add((c.raddr.ip, c.raddr.port))
                    current = set()
                    for pid, destinations in peers.items():
                        try:
                            p = psutil.Process(pid)
                            born = p.create_time()
                            if born > started:
                                continue
                            key = (pid, born)
                            current.add(key)
                            if key not in active:
                                evidence = match_peers(destinations, table)
                                row = dict(pid=pid, born=born, name=p.name(), cpu=None, gpu=None)
                                if not self.request(row, "Pool-associated TCP connection", idle_seconds(), evidence):
                                    current.discard(key)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    active = current
                except (psutil.AccessDenied, OSError):
                    self.pool_status = "Pool connection table unavailable"
            else:
                active.clear()
            self.stop.wait(12)

    def gpu_poll(self):
        while not self.stop.is_set():
            query_started = time.time()
            result = windows_query("gpu", None, timeout=9)
            with self.lock:
                self.gpu = result
                self.gpu_mark = query_started
            if self.stop.wait(4):
                return

    def run(self):
        import psutil
        threading.Thread(target=self.investigate, daemon=True).start()
        threading.Thread(target=self.pool_poll, daemon=True).start()
        if os.name == "nt":
            threading.Thread(target=self.gpu_poll, daemon=True).start()
        previous, last_mark = {}, None
        cpu_counter, gpu_counter = Streaks(REQUIRED_SAMPLES), Streaks(3)
        while not self.stop.is_set():
            rows, current = {}, {}
            with self.lock:
                gpu, mark = self.gpu, self.gpu_mark
            idle = idle_seconds()
            for pid in psutil.pids():
                if not pid:
                    continue
                try:
                    p = psutil.Process(pid)
                    with p.oneshot():
                        key = (p.pid, p.create_time())
                        times, name = p.cpu_times(), p.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                total, now = times.user + times.system, time.monotonic()
                current[key] = total, now
                if key not in previous:
                    if name.casefold() in PORTABLE_NAMES:
                        self.request(dict(pid=p.pid, born=key[1], name=name, cpu=None, gpu=None),
                                     "Known miner filename triggered inspection", idle)
                    continue
                old, then = previous[key]
                if now <= then or total < old:
                    continue
                pct = round(100 * (total - old) / (now - then), 1)
                gpct = None if gpu is None or key[1] > mark else gpu.get(str(p.pid), 0)
                rows[key] = dict(name=name, pid=p.pid, born=key[1], cpu=pct, gpu=gpct)
            previous = current
            cpu_hits = cpu_counter.update({key: row["cpu"] for key, row in rows.items()})
            gpu_hits = set()
            if mark != last_mark:
                gpu_hits = gpu_counter.update({key: row["gpu"] for key, row in rows.items() if row["gpu"] is not None})
                last_mark = mark
            for key, row in rows.items():
                if cpu_counter.counts.get(key, 0) >= REQUIRED_SAMPLES:
                    row["load"] = "CPU >=80% for 10 consecutive samples"
                elif gpu_counter.counts.get(key, 0) >= 3:
                    row["load"] = "GPU engine >=80% for 3 distinct GPU samples"
            for key in cpu_hits | gpu_hits:
                reasons = []
                if key in cpu_hits:
                    reasons.append("CPU >=80% for 10 consecutive samples")
                if key in gpu_hits:
                    reasons.append("GPU engine >=80% for 3 distinct GPU samples")
                self.request(rows[key], " / ".join(reasons), idle)
            self.emit("snapshot", (sorted(rows.values(), key=lambda row: row["cpu"], reverse=True), idle,
                                   ("GPU available" if gpu is not None else "GPU unavailable") + " · " + self.pool_status))
            self.stop.wait(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true", help="Run the offline simulation")
    parser.add_argument("--gui", action="store_true", help="Open the desktop dashboard")
    args = parser.parse_args()
    if args.gui:
        from dashboard import launch
        launch(args.demo)
        return
    def emit(kind, value):
        if kind == "snapshot":
            rows, _, _ = value
            print("\nPID       CPU %    Process (top five)")
            for row in rows[:5]:
                print(f"{row['pid']:<9} {row['cpu']:>6.1f}    {row['name']!r}")
        elif kind == "finding":
            print(f"ALERT | {value['name']!r} | PID {value['pid']} | {value['verdict']} | {value['load']}", flush=True)
        else:
            print(value, flush=True)
    stop = threading.Event()
    try:
        if args.demo:
            print("Simulated readings. No mining or CPU stress test is running.")
            demo(emit, stop)
        else:
            print("Monitoring local processes. Press Ctrl+C to stop.", flush=True)
            Live(emit, stop).run()
    except ModuleNotFoundError as exc:
        if exc.name != "psutil":
            raise
        print("Install psutil with: py -m pip install psutil")
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    finally:
        stop.set()


if __name__ == "__main__":
    main()
