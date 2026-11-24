"""Move a selected standalone miner to a private holding folder on the same volume."""
import ctypes
import hashlib
import json
import os
import stat
import uuid
from pathlib import Path

from detector import DATA
from evidence import LIKELY, PORTABLE_NAMES

VAULT = DATA / "isolated"


def user_location(path):
    roots = [Path.home() / part for part in ("Downloads", "Desktop")]
    return (path.is_absolute() and ".." not in path.parts and path.name.casefold() in PORTABLE_NAMES
            and any(path.is_relative_to(root) for root in roots))


def eligible(item):
    return (item.get("mode") == "Live" and item.get("verdict") == LIKELY
            and item.get("owned_by_user") and bool(item.get("digest")) and user_location(Path(item.get("path") or ".")))


def plain_path(path):
    for part in [*reversed(path.parents), path]:
        info = part.lstat()
        if part.is_symlink() or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("Linked or redirected paths require review in Windows Security.")


def move_checked(source, destination, digest):
    """Hash and rename the same locked Windows file handle. Never replace a destination."""
    from ctypes import wintypes as w
    import msvcrt

    plain_path(source)
    plain_path(destination.parent)
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    create = api.CreateFileW
    create.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
    create.restype = w.HANDLE
    # GENERIC_READ | DELETE, FILE_SHARE_READ, OPEN_EXISTING, OPEN_REPARSE_POINT.
    handle = create(str(source), 0x80010000, 1, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        api.CloseHandle(w.HANDLE(handle))
        raise
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError("Only a single ordinary file can be isolated.")
        if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
            raise ValueError("File contents changed. Collect a new finding.")
        encoded = str(destination).encode("utf-16le")

        class RenameInfo(ctypes.Structure):
            _fields_ = [("replace", w.DWORD), ("root", w.HANDLE),
                        ("length", w.DWORD), ("name", w.WCHAR * (len(encoded) // 2 + 1))]

        rename = RenameInfo()
        rename.length = len(encoded)
        ctypes.memmove(ctypes.addressof(rename) + RenameInfo.name.offset, encoded, len(encoded))
        setinfo = api.SetFileInformationByHandle
        setinfo.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD]
        setinfo.restype = w.BOOL
        if not setinfo(handle, 3, ctypes.byref(rename), ctypes.sizeof(rename)):
            raise ctypes.WinError(ctypes.get_last_error())


def isolate(item):
    if os.name != "nt" or not eligible(item):
        raise ValueError("Select an eligible live portable miner.")
    import psutil
    try:
        p = psutil.Process(item["pid"])
        if p.create_time() == item["born"]:
            raise ValueError("End the selected process before moving its file.")
    except psutil.NoSuchProcess:
        pass
    source = Path(item["path"])
    plain_path(source)
    VAULT.mkdir(parents=True, exist_ok=True)
    plain_path(VAULT)
    case = VAULT / uuid.uuid4().hex
    case.mkdir()
    receipt = case / "record.json"
    receipt.write_text(json.dumps({"source": str(source), "sha256": item["digest"]}), encoding="utf-8")
    try:
        move_checked(source, case / "payload.disabled", item["digest"])
    except BaseException:
        if not (case / "payload.disabled").exists():
            receipt.unlink(missing_ok=True)
            case.rmdir()
        raise
    return case


def held_files():
    if not VAULT.exists():
        return []
    plain_path(VAULT)
    return sorted(p.parent for p in VAULT.glob("*/payload.disabled"))


def record(case):
    if case.parent != VAULT or len(case.name) != 32 or any(c not in "0123456789abcdef" for c in case.name):
        raise ValueError("Invalid isolation record.")
    receipt = case / "record.json"
    plain_path(receipt)
    data = json.loads(receipt.read_text(encoding="utf-8"))
    if not user_location(Path(data["source"])):
        raise ValueError("Original location is outside the portable-file scope.")
    return data


def restore(case):
    data = record(case)
    source = Path(data["source"])
    move_checked(case / "payload.disabled", source, data["sha256"])
    (case / "record.json").unlink()
    case.rmdir()
    return source
