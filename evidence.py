"""Read evidence from one local process. Host commands use fixed scripts and data arguments."""
import ctypes
import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import subprocess
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
MAX_SAMPLE = 4 * 1024 * 1024
STRATUM = re.compile(rb"stratum(?:\+(?:tcp|ssl|tls))?://", re.I)
MINER_OPTION = re.compile(rb"--(?:donate-level|randomx-mode|cpu-priority)\b", re.I)


def powershell(mode, path="", timeout=15, entry=""):
    if os.name != "nt":
        raise OSError("Windows integration unavailable on this OS")
    system_root = Path(os.environ["SystemRoot"])
    executable = system_root / "System32/WindowsPowerShell/v1.0/powershell.exe"
    env = dict(os.environ, DETECTOR_REVIEW_FILE=str(path), DETECTOR_QUERY=mode, DETECTOR_STARTUP_ENTRY=entry)
    script = (ROOT / "tools/windows.ps1").read_text(encoding="utf-8")
    result = subprocess.run(
        [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive",
         "-Command", script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
        encoding="utf-8", errors="replace", creationflags=subprocess.CREATE_NO_WINDOW, env=env)
    if result.returncode:
        raise OSError(result.stderr.strip().splitlines()[0][:200] if result.stderr.strip() else "Windows query failed")
    return json.loads(result.stdout.lstrip("\ufeff"))


def windows_query(mode, fallback, path="", timeout=15):
    try:
        return powershell(mode, path, timeout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return fallback


def idle_seconds():
    if os.name != "nt":
        return None

    class LastInput(ctypes.Structure):
        _fields_ = [("size", ctypes.c_uint32), ("ticks", ctypes.c_uint32)]
    info = LastInput(ctypes.sizeof(LastInput), 0)
    if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
        return ((ctypes.windll.kernel32.GetTickCount() - info.ticks) & 0xffffffff) / 1000
    return None


def scan_bytes(data):
    # Long ASCII strings can also appear as UTF-16LE in Windows programs.
    searchable = data + b"\n" + data.replace(b"\x00", b"")
    clues = []
    if STRATUM.search(searchable):
        clues.append("Stratum URL marker")
    if MINER_OPTION.search(searchable) and (b"randomx" in searchable.lower() or b"donate-level" in searchable.lower()):
        clues.append("Mining software options")
    entropy = -sum((n / len(data)) * math.log2(n / len(data)) for n in Counter(data).values())
    return clues, round(entropy, 2)


def local_file(path):
    if not path or str(path).startswith(("//", "\\\\")):
        return False
    if os.name == "nt":
        drive = Path(path).anchor
        if not drive or ctypes.windll.kernel32.GetDriveTypeW(str(drive)) != 3:
            return False
    return Path(path).is_absolute() and stat.S_ISREG(os.stat(path).st_mode)


def file_evidence(path):
    try:
        if not local_file(path):
            return [], None, "Local regular file unavailable"
        with open(path, "rb") as stream:
            data = stream.read(MAX_SAMPLE)
        clues, entropy = scan_bytes(data)
        return clues, entropy, f"Read {len(data):,} bytes from start of file"
    except OSError as exc:
        return [], None, f"File unavailable: {exc.strerror}"


def file_hash(path):
    if not local_file(path):
        raise ValueError("Select a readable local executable")
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pool_rules():
    config = json.loads((ROOT / "pools.json").read_text(encoding="utf-8"))
    return {x.lower().rstrip(".") for x in config["domains"]}, {
        str(ipaddress.ip_address(x)) for x in config["addresses"]}


def pool_addresses(rules, cache):
    hosts, addresses = rules
    table = {address: "Configured pool IP" for address in addresses}
    for record in cache or ():
        domain = str(record.get("Entry", "")).lower().rstrip(".")
        if domain in hosts:
            try:
                address = str(ipaddress.ip_address(record["Data"]))
            except (KeyError, ValueError):
                continue
            table.setdefault(address, f"Cached pool DNS: {domain} (shared IP possible)")
    return table


def match_peers(peers, table):
    return sorted({f"{address}:{port} | {table[address]}" for address, port in peers if address in table})


PORTABLE_NAMES = {"xmrig.exe", "t-rex.exe", "lolminer.exe", "teamredminer.exe", "gminer.exe"}

LIKELY = "Mining likely"
POSSIBLE = "Possible mining"
UNUSUAL = "Unusual load"
CLEAR = "No indicators observed"
INCOMPLETE = "Limited visibility"

INTERPRETATION = {
    LIKELY: "This process had a pool-associated connection and corroborating mining evidence. Check whether its activity was authorized.",
    POSSIBLE: "A mining-related clue matched. Inspect the evidence and network context before taking action.",
    UNUSUAL: "CPU or GPU use stayed high. The workload may be a game, a build or a video export.",
    CLEAR: "The available checks found no mining clue or sustained-load event for this review.",
    INCOMPLETE: "A key check was unavailable. Read the coverage notes before drawing a conclusion.",
}


def classify(item):
    peers = any(" | " in match for match in item["pool_matches"])
    runtime = "Stratum URL in launch arguments" in item["markers"]
    sustained = item["load"].startswith(("CPU ", "GPU ", "High CPU"))
    if peers and (runtime or (item["markers"] and sustained)):
        return LIKELY
    if item["pool_matches"] or item["markers"]:
        return POSSIBLE
    if sustained:
        return UNUSUAL
    if item.get("coverage_gap"):
        return INCOMPLETE
    return CLEAR


def process_details(pid, born, cpu, gpu, load, rules, idle):
    import psutil
    item = dict(pid=pid, born=born, name="Unavailable", path="", cpu=cpu, gpu=gpu, idle=idle,
                load=load, owned_by_user=False, coverage_gap=False, endpoints=[], pool_matches=[], markers=[], entropy=None, startup=[],
                signature="Unavailable", network="Unavailable", notes=[], mode="Live")
    try:
        p = psutil.Process(pid)
        if p.create_time() != born:
            raise psutil.NoSuchProcess(pid)
        item["name"] = p.name()
        try:
            item["owned_by_user"] = p.username().casefold() == psutil.Process().username().casefold()
        except psutil.AccessDenied:
            item["notes"].append("Process owner unavailable")
        try:
            item["path"] = p.exe()
        except psutil.AccessDenied:
            item["coverage_gap"] = True
            item["notes"].append("Executable path access denied")
        hosts, addresses = rules
        try:
            # Exclude listener sockets, then retain established TCP peers.
            peers = {(str(ipaddress.ip_address(c.raddr.ip)), c.raddr.port)
                     for c in p.net_connections(kind="tcp") if c.raddr and c.status == psutil.CONN_ESTABLISHED}
            item["endpoints"] = [f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"
                                 for addr, port in sorted(peers)]
            item["network"] = f"{len(peers)} established TCP peer(s)"
            cache = windows_query("dns", None) if hosts and peers else []
            if cache is None:
                item["coverage_gap"] = True
                item["notes"].append("Local DNS cache unavailable")
            item["pool_matches"] = match_peers(peers, pool_addresses(rules, cache))
        except (psutil.AccessDenied, OSError):
            item["coverage_gap"] = True
            item["network"] = "Connection access denied or unavailable"
        try:
            # Store rule labels only. Command lines can contain credentials.
            for arg in p.cmdline():
                value = arg.partition("=")[2] if arg.startswith(("--url=", "--pool=")) else arg
                if STRATUM.match(os.fsencode(value)):
                    item["markers"].append("Stratum URL in launch arguments")
                    try:
                        host = urlsplit(value).hostname
                        if host and host.lower().rstrip(".") in hosts:
                            item["pool_matches"].append(f"Pool in launch arguments: {host}")
                    except ValueError:
                        pass
        except psutil.AccessDenied:
            item["coverage_gap"] = True
            item["notes"].append("Launch arguments access denied")
        clues, item["entropy"], status = file_evidence(item["path"])
        item["markers"].extend(clues)
        item["notes"].append(status)
        if not status.startswith("Read "):
            item["coverage_gap"] = True
        if os.name == "nt" and status.startswith("Read "):
            review = windows_query("review", None, item["path"], 25)
            if review:
                item["startup"] = review["entries"]
                item["signature"] = review["signature"]
                item["notes"].extend(review["gaps"])
            else:
                item["notes"].append("Signature and startup queries unavailable")
        else:
            item["notes"].append("Signature and startup review unavailable")
        if not p.is_running():
            item["coverage_gap"] = True
            item["notes"].append("Process ended during review")
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        item["coverage_gap"] = True
        item["notes"].append(f"Process review incomplete: {type(exc).__name__}")
    item["verdict"] = classify(item)
    return item
