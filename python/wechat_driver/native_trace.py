"""观察型调用栈追踪：附加调试器、单个软件断点、采样返回地址后分离。

不发消息、不加载 DLL、不写目标文件；唯一的目标内存写是临时 INT3 与恢复。
帧是启发式候选：x64 无帧指针，返回地址按调用帧展开恢复，需结合证据判断。
"""
from __future__ import annotations

from bisect import bisect_right
import ctypes as C
from ctypes import wintypes as W
from dataclasses import dataclass
import os
from pathlib import Path
import re
import struct
import sys
import time

from .base import DriverError
from .native_loader import NativeLoadError, _parse_pe, _path_key, inspect_process

EXCEPTION_DEBUG_EVENT = 1
EXIT_PROCESS_DEBUG_EVENT = 5
EXCEPTION_BREAKPOINT = 0x80000003
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
_PROCESS_RIGHTS = 0x100000 | 0x0400 | 0x0010 | 0x0008 | 0x0020 | 0x0002
_THREAD_RIGHTS = 0x0008 | 0x0010 | 0x0040
_CONTEXT_SIZE = 1232
_CONTEXT_FLAGS = 0x0010001F  # AMD64 | CONTROL | INTEGER | SEGMENTS | FLOATING_POINT | DEBUG_REGISTERS
_REGISTER_OFFSETS = {"rax": 0x78, "rcx": 0x80, "rdx": 0x88, "rbx": 0x90, "rsp": 0x98,
                     "rbp": 0xA0, "rsi": 0xA8, "rdi": 0xB0, "r8": 0xB8, "r9": 0xC0,
                     "r10": 0xC8, "r11": 0xD0, "r12": 0xD8, "r13": 0xE0, "r14": 0xE8,
                     "r15": 0xF0, "rip": 0xF8, "dr6": 0x68}
_CONTEXT_DEBUG_ONLY = 0x00100010  # CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS
_THREAD_SNAPSHOT = 0x00000004  # TH32CS_SNAPTHREAD


class TraceError(DriverError):
    """不包含进程内容或路径的追踪失败。"""


@dataclass(frozen=True)
class Frame:
    module: str
    base: int
    address: int
    rva: int
    function_start: int | None = None
    function_end: int | None = None


@dataclass(frozen=True)
class TraceResult:
    status: str  # HIT / TIMEOUT / EXITED
    breakpoint_module: str
    breakpoint_rva: int
    breakpoint_address: int
    registers: dict[str, int]
    frames: tuple[Frame, ...]
    detail: str = ""
    restored: bool | None = None
    disarmed: bool | None = None
    # 命中冻结时寄存器指向的内存快照（寄存器名 → 字节），取证用；默认不采集。
    memory: dict[str, bytes] | None = None


class _DEBUG_EVENT(C.Structure):
    _fields_ = [("code", W.DWORD), ("pid", W.DWORD), ("tid", W.DWORD),
                ("pad", W.DWORD), ("data", C.c_ubyte * 160)]


class _Win:
    def __init__(self) -> None:
        if sys.platform != "win32" or C.sizeof(C.c_void_p) != 8:
            raise TraceError("仅支持 64 位 Windows 与 64 位 Python。")
        self.k = C.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
        P, D, H, B, S = C.c_void_p, W.DWORD, W.HANDLE, W.BOOL, C.c_size_t
        signatures = {
            "OpenProcess": (H, [D, B, D]),
            "CloseHandle": (B, [H]),
            "GetProcessTimes": (B, [H] + [C.POINTER(W.FILETIME)] * 4),
            "QueryFullProcessImageNameW": (B, [H, D, W.LPWSTR, C.POINTER(D)]),
            "ReadProcessMemory": (B, [H, P, P, S, C.POINTER(S)]),
            "WriteProcessMemory": (B, [H, P, P, S, C.POINTER(S)]),
            "VirtualProtectEx": (B, [H, P, S, D, C.POINTER(D)]),
            "FlushInstructionCache": (B, [H, P, S]),
            "OpenThread": (H, [D, B, D]),
            "GetThreadContext": (B, [H, P]),
            "SetThreadContext": (B, [H, P]),
            "DebugActiveProcess": (B, [D]),
            "DebugActiveProcessStop": (B, [D]),
            "DebugSetProcessKillOnExit": (B, [B]),
            "DebugBreakProcess": (B, [H]),
            "CreateToolhelp32Snapshot": (H, [D, D]),
            "Thread32First": (B, [H, C.c_void_p]),
            "Thread32Next": (B, [H, C.c_void_p]),
            "OpenThread": (H, [D, B, D]),
            "SuspendThread": (W.DWORD, [H]),
            "ResumeThread": (W.DWORD, [H]),
            "WaitForDebugEvent": (B, [C.POINTER(_DEBUG_EVENT), D]),
            "ContinueDebugEvent": (B, [D, D, D]),
        }
        try:
            for name, (result, args) in signatures.items():
                function = getattr(self.k, name)
                function.restype, function.argtypes = result, args
        except AttributeError:
            raise TraceError("系统缺少所需调试 API。") from None

    @staticmethod
    def error(operation: str) -> TraceError:
        code = C.get_last_error()
        return TraceError(f"{operation} 失败（WinError {code}）。")


def _u64(buffer, offset: int) -> int:
    return struct.unpack_from("<Q", buffer, offset)[0]


def _read_at(stream, sections, rva: int, size: int) -> bytes:
    for section_rva, virtual, raw_offset, raw_size, _ in sections:
        span = max(virtual, raw_size)
        if section_rva <= rva and rva + size <= section_rva + span:
            if rva + size > section_rva + raw_size:
                raise TraceError("RVA 范围落在节的未初始化区域。")
            stream.seek(raw_offset + rva - section_rva)
            data = stream.read(size)
            if len(data) != size:
                raise TraceError("模块文件读取被截断。")
            return data
    raise TraceError("RVA 不在模块文件任何节内。")


def _sections(headers: bytes) -> tuple[tuple[int, int, int, int, int], ...]:
    """像 EXE 与 DLL 一样解析已加载模块；发送能力仍只在 DLL 中验证。"""
    try:
        pe = struct.unpack_from("<I", headers, 0x3C)[0]
        if headers[:2] != b"MZ" or headers[pe:pe + 4] != b"PE\0\0":
            raise ValueError
        machine, count, _ = struct.unpack_from("<HHI", headers, pe + 4)
        optional_size, flags = struct.unpack_from("<HH", headers, pe + 20)
        optional = pe + 24
        if machine != 0x8664 or not flags & 2 or struct.unpack_from("<H", headers, optional)[0] != 0x20B:
            raise ValueError
        image_size, headers_size = struct.unpack_from("<II", headers, optional + 56)
        end = optional + optional_size + count * 40
        if not 1 <= count <= 96 or end > len(headers) or not end <= headers_size <= image_size:
            raise ValueError
        sections = []
        for offset in range(optional + optional_size, end, 40):
            virtual, address, raw_size, raw_offset = struct.unpack_from("<IIII", headers, offset + 8)
            sections.append((address, virtual, raw_offset, raw_size,
                             struct.unpack_from("<I", headers, offset + 36)[0]))
        return tuple(sections)
    except (struct.error, ValueError, IndexError):
        raise TraceError("模块头部无法解析。") from None


def _directories(headers: bytes) -> tuple[tuple[int, int], ...]:
    pe = struct.unpack_from("<I", headers, 0x3C)[0]
    optional = pe + 24
    count = struct.unpack_from("<I", headers, optional + 108)[0]
    return tuple(struct.unpack_from("<II", headers, optional + 112 + index * 8)
                 for index in range(count))


def _export_rva(stream, headers, sections, name: str) -> int | None:
    directories = _directories(headers)
    if not directories or not directories[0][0] or directories[0][1] < 40:
        return None
    export_rva, export_size = directories[0]
    table = _read_at(stream, sections, export_rva, 40)
    names, functions, name_table, ordinal_table = struct.unpack_from("<IIII", table, 24)
    if names > 1_000_000:
        raise TraceError("导出名数量异常。")
    wanted = name.encode("ascii")
    for index in range(names):
        entry = struct.unpack_from("<I", _read_at(stream, sections, name_table + index * 4, 4))[0]
        actual = _read_at(stream, sections, entry, 512).split(b"\0")[0]
        if actual != wanted:
            continue
        ordinal = struct.unpack_from("<H", _read_at(stream, sections, ordinal_table + index * 2, 2))[0]
        target = struct.unpack_from("<I", _read_at(stream, sections, functions + ordinal * 4, 4))[0]
        if export_rva <= target < export_rva + export_size:
            raise TraceError("转发导出不能作为断点。")
        return target
    return None


def _exception_table(stream, headers, sections) -> tuple[tuple[int, int, int], ...]:
    directories = _directories(headers)
    if len(directories) < 4 or not directories[3][0]:
        return ()
    rva, size = directories[3]
    usable = size - size % 12
    if not 0 < usable <= 64 * 1024 * 1024:
        return ()
    blob = _read_at(stream, sections, rva, usable)
    return tuple(sorted(struct.iter_unpack("<III", blob)))


class _Functions:
    """Per-module .pdata / UNWIND_INFO lookup, opened read-only for one trace."""

    _UNWIND_REGISTERS = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")

    def __init__(self) -> None:
        self._tables: dict[str, tuple[tuple[int, int, int], ...]] = {}
        self._starts: dict[str, list[int]] = {}
        self._sections: dict[str, tuple] = {}
        self._unwind: dict[tuple[str, int], tuple] = {}

    def _file(self, path: Path):
        key = _path_key(path)
        if key not in self._tables:
            try:
                with path.open("rb") as stream:
                    headers = stream.read(1024 * 1024)
                    sections = _sections(headers)
                    self._tables[key] = _exception_table(stream, headers, sections)
                    self._starts[key] = [entry[0] for entry in self._tables[key]]
                    self._sections[key] = sections
            except (OSError, TraceError, struct.error):
                self._tables[key], self._starts[key] = (), []
        return key

    def runtime_function(self, path: Path, rva: int) -> tuple[int, int, int] | None:
        key = self._file(path)
        starts = self._starts.get(key, [])
        index = bisect_right(starts, rva) - 1
        if index >= 0 and starts[index] <= rva < self._tables[key][index][1]:
            return self._tables[key][index]
        return None

    def unwind_info(self, path: Path, unwind_rva: int) -> tuple | None:
        key = self._file(path)
        if (key, unwind_rva) in self._unwind:
            return self._unwind[(key, unwind_rva)]
        info = None
        try:
            with path.open("rb") as stream:
                sections = self._sections.get(key, ())
                header = _read_at(stream, sections, unwind_rva, 4)
                count = header[2]
                frame_register, frame_offset = header[3] & 0xF, header[3] >> 4
                raw = _read_at(stream, sections, unwind_rva + 4, count * 2)
                ops, index = [], 0
                while index < count:
                    offset = raw[index * 2]
                    opinfo = raw[index * 2 + 1]
                    operation, argument = opinfo & 0xF, opinfo >> 4
                    index += 1
                    extra = (1 if argument == 0 else 2) if operation == 1 else \
                        1 if operation in (4, 8) else 2 if operation in (5, 9) else 0
                    values = struct.unpack_from("<" + "H" * extra, raw, index * 2) if extra else ()
                    index += extra
                    ops.append((offset, operation, argument, values))
                chained = None
                if header[0] & 0x20:  # UNW_FLAG_CHAININFO 位于标志字节的高位
                    chain = _read_at(stream, sections, unwind_rva + 4 + count * 2, 12)
                    chained = struct.unpack("<III", chain)
                info = (chained, frame_register, frame_offset, ops)
        except (OSError, TraceError, struct.error):
            info = None
        self._unwind[(key, unwind_rva)] = info
        return info

    def unwind_step(self, api, process, path: Path, unwind_rva: int, rsp: int,
                    registers: dict[str, int]) -> int | None:
        depth = 0
        while True:
            depth += 1
            if depth > 8:
                return None
            info = self.unwind_info(path, unwind_rva)
            if info is None:
                return None
            chained, frame_register, frame_offset, ops = info
            slot = 0
            try:
                for _, operation, argument, values in ops:
                    if operation == 0:  # PUSH_NONVOL
                        registers[self._UNWIND_REGISTERS[argument]] = struct.unpack(
                            "<Q", _read(api, process, rsp, 8))[0]
                        rsp += 8
                    elif operation == 1:  # ALLOC_LARGE
                        if argument == 0:
                            rsp += values[0] * 8
                        else:
                            rsp += values[0] | (values[1] << 16)
                    elif operation == 2:  # ALLOC_SMALL
                        rsp += argument * 8 + 8
                    elif operation == 3:  # SET_FPREG
                        rsp = registers[self._UNWIND_REGISTERS[frame_register]] - frame_offset * 16
                    elif operation == 4:  # SAVE_NONVOL
                        registers[self._UNWIND_REGISTERS[argument]] = struct.unpack(
                            "<Q", _read(api, process, rsp + values[0] * 8, 8))[0]
                    elif operation == 5:  # SAVE_NONVOL_FAR
                        offset = values[0] | (values[1] << 16)
                        registers[self._UNWIND_REGISTERS[argument]] = struct.unpack(
                            "<Q", _read(api, process, rsp + offset, 8))[0]
                    elif operation == 10:  # PUSH_MACHFRAME：中断帧不是普通调用
                        return None
            except (TraceError, NativeLoadError, struct.error, IndexError):
                return None
            if chained is None:
                return rsp
            unwind_rva = chained[2]


class _THREADENTRY32(C.Structure):
    _fields_ = [("dw_size", W.DWORD), ("cnt_usage", W.DWORD), ("thread_id", W.DWORD),
                ("owner_pid", W.DWORD), ("tp_base_pri", C.c_long), ("tp_delta_pri", C.c_long),
                ("flags", W.DWORD)]


def _target_threads(api: _Win, pid: int) -> list[int]:
    snapshot_handle = api.k.CreateToolhelp32Snapshot(_THREAD_SNAPSHOT, pid)
    if snapshot_handle == C.c_void_p(-1).value:
        raise api.error("CreateToolhelp32Snapshot")
    try:
        entry = _THREADENTRY32()
        entry.dw_size = C.sizeof(_THREADENTRY32)
        if not api.k.Thread32First(snapshot_handle, C.byref(entry)):
            raise api.error("Thread32First")
        ids = []
        while True:
            if entry.owner_pid == pid:
                ids.append(entry.thread_id)
            if not api.k.Thread32Next(snapshot_handle, C.byref(entry)):
                break
        return ids
    finally:
        api.k.CloseHandle(snapshot_handle)


def _apply_watch(api: _Win, pid: int, *, enable: bool, dr0: int = 0, dr7: int = 0) -> int:
    """对目标线程安装或清除 DR0 数据观察点；优先挂起后修改，个别线程拒绝挂起则跳过。"""
    updated = 0
    for thread_id in _target_threads(api, pid):
        handle = api.k.OpenThread(_THREAD_RIGHTS | 0x0002, False, thread_id)
        if not handle:
            continue
        suspended = False
        try:
            if api.k.SuspendThread(handle) != 0xFFFFFFFF:
                suspended = True
            buffer = C.create_string_buffer(_CONTEXT_SIZE)
            struct.pack_into("<I", buffer, 0x30, _CONTEXT_DEBUG_ONLY)
            if not api.k.GetThreadContext(handle, buffer):
                continue  # 未挂起的线程无法可靠取得上下文，跳过该线程
            if enable:
                struct.pack_into("<Q", buffer, 0x48, dr0)
                struct.pack_into("<Q", buffer, 0x68, 0)
                struct.pack_into("<Q", buffer, 0x70, dr7)
            else:
                struct.pack_into("<Q", buffer, 0x48, 0)
                struct.pack_into("<Q", buffer, 0x70, 0)
            if api.k.SetThreadContext(handle, buffer):
                updated += 1
        finally:
            if suspended:
                api.k.ResumeThread(handle)
            api.k.CloseHandle(handle)
    return updated


def _watch_is_clear(api: _Win, pid: int) -> bool:
    for thread_id in _target_threads(api, pid):
        handle = api.k.OpenThread(0x0008 | 0x0040, False, thread_id)
        if not handle:
            continue
        try:
            buffer = C.create_string_buffer(_CONTEXT_SIZE)
            struct.pack_into("<I", buffer, 0x30, _CONTEXT_DEBUG_ONLY)
            if not api.k.GetThreadContext(handle, buffer):
                return False
            if struct.unpack_from("<Q", buffer, 0x48)[0] or struct.unpack_from("<Q", buffer, 0x70)[0]:
                return False
        finally:
            api.k.CloseHandle(handle)
    return True


def trace_watch(pid: int, address: int, *, timeout_ms: int = 30000,
                read_only: bool = True, watch_length: int = 1) -> TraceResult:
    """硬件数据观察点：读或写命中时采样调用链，随后清除观察点并分离。"""
    if type(pid) is not int or not 0 < pid < 2**32 or pid == os.getpid():
        raise TraceError("PID 必须是有效且非自身的进程。")
    if type(address) is not int or not 0x10000 <= address < (1 << 48) or address & (watch_length - 1):
        raise TraceError("地址或长度不合法。")
    if watch_length not in (1, 2, 4, 8):
        raise TraceError("长度只允许 1/2/4/8 字节。")
    if type(timeout_ms) is not int or not 1 <= timeout_ms < 0xFFFFFFFF:
        raise TraceError("超时必须是有限的正 DWORD 毫秒数。")
    # DR7 DR0 字段：R/W 在 bit16-17（01 只写、11 读写），LEN 在 bit18-19（00/01/10/3=1/2/4/8），
    # 局部启用在 bit0。x86-64 没有纯读观察点，读观察点用 11 实现。
    length_bits = {1: 0b00, 2: 0b01, 4: 0b10, 8: 0b11}[watch_length]
    dr7 = (0b11 if read_only else 0b01) << 16
    dr7 |= length_bits << 18
    dr7 |= 1  # 本地启用 DR0
    api = _Win()
    snapshot = inspect_process(pid)
    process = _open_verified(api, pid, snapshot)
    if not api.k.DebugActiveProcess(pid):
        api.k.CloseHandle(process)
        raise api.error("DebugActiveProcess")
    if not api.k.DebugSetProcessKillOnExit(False):
        api.k.DebugActiveProcessStop(pid)
        api.k.CloseHandle(process)
        raise api.error("DebugSetProcessKillOnExit")
    attached, armed, status, detail = True, False, "TIMEOUT", ""
    registers: dict[str, int] = {}
    frames: tuple[Frame, ...] = ()
    functions = _Functions()
    disarmed: bool | None = None

    def resume(event, *, handled: bool = False) -> None:
        if event.code == EXCEPTION_DEBUG_EVENT:
            exception = struct.unpack_from("<I", bytes(event.data), 0)[0]
            code = DBG_CONTINUE if handled or exception == EXCEPTION_BREAKPOINT else DBG_EXCEPTION_NOT_HANDLED
        else:
            code = DBG_CONTINUE
        api.k.ContinueDebugEvent(pid, event.tid, code)

    try:
        deadline = time.monotonic() + timeout_ms / 1000
        event = _wait(api, deadline)
        if event is None:
            raise TraceError("附加后未收到调试事件。")
        pending = event
        try:
            if event.code == EXIT_PROCESS_DEBUG_EVENT:
                status, detail = "EXITED", "目标在观察点生效前已退出。"
            else:
                armed = _apply_watch(api, pid, enable=True, dr0=address, dr7=dr7) > 0
                if not armed:
                    detail = "没有任何线程接受观察点。"
        finally:
            resume(pending)
            pending = None
        while status == "TIMEOUT":
            event = _wait(api, deadline)
            if event is None:
                detail = "等待超时；观察点已清除并分离。"
                break
            pending, handled = event, False
            try:
                if event.code == EXIT_PROCESS_DEBUG_EVENT:
                    status, detail, armed = "EXITED", "目标已退出。", False
                elif event.code == EXCEPTION_DEBUG_EVENT:
                    data = bytes(event.data)
                    exception, exception_address = struct.unpack_from("<I", data, 0)[0], \
                        struct.unpack_from("<Q", data, 16)[0]
                    current = _context(api, event.tid)
                    if exception == 0x80000004 and armed and (current.get("dr6", 0) & 0xF):
                        try:
                            rip = current["rip"]
                            owner = next((item for item in snapshot.modules
                                          if item.base <= rip < item.base + item.size), None)
                            if owner is not None:
                                frames = _backtrace(api, process, snapshot, owner, rip - owner.base,
                                                    current["rsp"], current, functions, at_entry=False)
                            current["rip"] = rip
                            registers = current
                        finally:
                            _apply_watch(api, pid, enable=False)
                            armed = False
                            status = "HIT"
                            detail = "已清除观察点并分离；调用链为展开结果。"
                            handled = True
            finally:
                if pending is not None:
                    resume(pending, handled=handled)
                    pending = None
        if status == "HIT":
            _drain_watch(api, pid)
    finally:
        try:
            if armed:
                try:
                    _apply_watch(api, pid, enable=False)
                    armed = False
                    detail += " 已在清理阶段清除观察点。"
                except TraceError as error:
                    detail += f" 观察点清除失败：{error}"
        finally:
            try:
                disarmed = _watch_is_clear(api, pid) if attached else None
            except TraceError:
                disarmed = None
            try:
                if attached:
                    if not api.k.DebugActiveProcessStop(pid):
                        detail += f" 分离失败（WinError {C.get_last_error()}）。"
                    attached = False
            finally:
                api.k.CloseHandle(process)
    if armed:
        raise TraceError("观察点未能清除；目标中可能残留调试寄存器状态。")
    return TraceResult(status, "data-watch", 0, address, registers, frames,
                       detail, None, disarmed)


def _drain_watch(api: _Win, pid: int, grace_seconds: float = 1.5) -> None:
    """命中后持续排空其他线程已产生的单步事件，避免分离时留下停住的线程。"""
    deadline = time.monotonic() + grace_seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        event = _wait(api, time.monotonic() + min(0.1, remaining))
        if event is None:
            continue
        if event.code == EXCEPTION_DEBUG_EVENT:
            exception = struct.unpack_from("<I", bytes(event.data), 0)[0]
            status = DBG_CONTINUE if exception in (EXCEPTION_BREAKPOINT, 0x80000004) \
                else DBG_EXCEPTION_NOT_HANDLED
        else:
            status = DBG_CONTINUE
        api.k.ContinueDebugEvent(pid, event.tid, status)


def _backtrace(api: _Win, process: int, snapshot, module, entry_rva: int, rsp: int,
               registers: dict[str, int], functions: _Functions,
               limit: int = 48, *, at_entry: bool = True) -> tuple[Frame, ...]:
    """真实 x64 展开：at_entry 表示断点位于函数入口（序言尚未执行）。"""
    runtime = functions.runtime_function(module.path, entry_rva)
    first_range = (runtime[0], runtime[1]) if runtime else (None, None)
    frames = [Frame(module.path.name, module.base, module.base + entry_rva, entry_rva,
                    first_range[0], first_range[1])]
    registers = {name: registers.get(name, 0) for name in _Functions._UNWIND_REGISTERS}
    try:
        if at_entry:
            return_address = struct.unpack("<Q", _read(api, process, rsp, 8))[0]
            rsp += 8
        else:
            if runtime is None or runtime[2] == 0:
                return tuple(frames)
            unwound = functions.unwind_step(api, process, module.path, runtime[2], rsp, registers)
            if unwound is None:
                return tuple(frames)
            return_address = struct.unpack("<Q", _read(api, process, unwound, 8))[0]
            rsp = unwound + 8
    except (TraceError, NativeLoadError):
        return tuple(frames)
    while return_address and len(frames) < limit:
        pc = return_address - 1
        owner = next((item for item in snapshot.modules
                      if item.base <= pc < item.base + item.size), None)
        if owner is None:
            break
        runtime = functions.runtime_function(owner.path, pc - owner.base)
        if runtime is None:
            break
        frames.append(Frame(owner.path.name, owner.base, pc, pc - owner.base, runtime[0], runtime[1]))
        if runtime[2] == 0:
            break
        rsp = functions.unwind_step(api, process, owner.path, runtime[2], rsp, registers)
        if rsp is None:
            break
        try:
            return_address = struct.unpack("<Q", _read(api, process, rsp, 8))[0]
        except (TraceError, NativeLoadError):
            break
        rsp += 8
    return tuple(frames)


def _open_verified(api: _Win, pid: int, snapshot) -> int:
    process = api.k.OpenProcess(_PROCESS_RIGHTS, False, pid)
    if not process:
        raise api.error("OpenProcess")
    try:
        times = [W.FILETIME() for _ in range(4)]
        if not api.k.GetProcessTimes(process, *(C.byref(value) for value in times)):
            raise api.error("GetProcessTimes")
        creation = times[0].dwLowDateTime | (times[0].dwHighDateTime << 32)
        path, count = C.create_unicode_buffer(32768), W.DWORD(32768)
        if not api.k.QueryFullProcessImageNameW(process, 0, path, C.byref(count)):
            raise api.error("QueryFullProcessImageNameW")
        if creation != snapshot.creation_time or _path_key(Path(path.value)) != _path_key(snapshot.exe_path):
            raise TraceError("进程身份在打开句柄时已变化。")
        return process
    except BaseException:
        api.k.CloseHandle(process)
        raise


def _read(api: _Win, process: int, address: int, size: int) -> bytes:
    buffer, read = C.create_string_buffer(size), C.c_size_t()
    if not api.k.ReadProcessMemory(process, address, buffer, size, C.byref(read)) or read.value != size:
        raise api.error("ReadProcessMemory")
    return buffer.raw


def _write_byte(api: _Win, process: int, address: int, value: int) -> None:
    old = W.DWORD()
    if not api.k.VirtualProtectEx(process, address, 1, 0x40, C.byref(old)):
        raise api.error("VirtualProtectEx")
    try:
        written = C.c_size_t()
        if not api.k.WriteProcessMemory(process, address, C.create_string_buffer(bytes([value])), 1,
                                         C.byref(written)) or written.value != 1:
            raise api.error("WriteProcessMemory")
    finally:
        restored = W.DWORD()
        api.k.VirtualProtectEx(process, address, 1, old.value, C.byref(restored))
    if not api.k.FlushInstructionCache(process, address, 1):
        raise api.error("FlushInstructionCache")


def _context(api: _Win, thread_id: int, *, set_rip: int | None = None) -> dict[str, int]:
    handle = api.k.OpenThread(_THREAD_RIGHTS, False, thread_id)
    if not handle:
        raise api.error("OpenThread")
    try:
        buffer = C.create_string_buffer(_CONTEXT_SIZE)
        struct.pack_into("<I", buffer, 0x30, _CONTEXT_FLAGS)
        if not api.k.GetThreadContext(handle, buffer):
            raise api.error("GetThreadContext")
        values = {name: _u64(buffer.raw, offset) for name, offset in _REGISTER_OFFSETS.items()}
        if set_rip is not None:
            struct.pack_into("<Q", buffer, _REGISTER_OFFSETS["rip"], set_rip)
            if not api.k.SetThreadContext(handle, buffer):
                raise api.error("SetThreadContext")
        return values
    finally:
        api.k.CloseHandle(handle)


def _wait(api: _Win, deadline: float):
    remaining = int(max(1, (deadline - time.monotonic()) * 1000))
    event = _DEBUG_EVENT()
    if api.k.WaitForDebugEvent(C.byref(event), remaining):
        return event
    if C.get_last_error() == 121:  # ERROR_SEM_TIMEOUT
        return None
    raise api.error("WaitForDebugEvent")


def _export_rvas(stream, headers, sections) -> frozenset[int]:
    directories = _directories(headers)
    if not directories or not directories[0][0] or directories[0][1] < 40:
        return frozenset()
    export_rva, export_size = directories[0]
    table = _read_at(stream, sections, export_rva, 40)
    names, functions, name_table, ordinal_table = struct.unpack_from("<IIII", table, 24)
    if names > 200_000:
        return frozenset()
    result = set()
    for index in range(names):
        ordinal = struct.unpack_from("<H", _read_at(stream, sections, ordinal_table + index * 2, 2))[0]
        target = struct.unpack_from("<I", _read_at(stream, sections, functions + ordinal * 4, 4))[0]
        if not export_rva <= target < export_rva + export_size:
            result.add(target)
    return frozenset(result)


def _require_entry(stream, headers, sections, rva: int,
                   allowed_rvas: frozenset[int] | set[int] = frozenset(),
                   allow_interior: bool = False) -> None:
    """只允许可执行节内的已登记函数入口（或导出表直接指向的入口跳板）。

    allow_interior 放宽为 .pdata 登记函数的内部地址：调用点取证需要在 call
    指令处下断以采样本次调用的实参；可执行节与函数范围的校验保持不变。
    """
    section = next((item for item in sections
                    if item[0] <= rva < item[0] + max(item[1], item[3])), None)
    if section is None or not section[4] & 0x20000000:
        raise TraceError("断点 RVA 不在可执行节内。")
    if rva in allowed_rvas:
        return
    if allow_interior:
        if any(entry[0] <= rva < entry[1] for entry in _exception_table(stream, headers, sections)):
            return
        raise TraceError("断点 RVA 不在任何已登记函数范围内。")
    if not any(entry[0] == rva for entry in _exception_table(stream, headers, sections)):
        raise TraceError("断点 RVA 不是已登记的函数入口。")


def find_bytes(pid: int, needle: bytes, *, limit: int = 32) -> list[int]:
    """只读搜索目标进程中的精确字节序列；只返回匹配地址，不回显周围内容。"""
    if type(pid) is not int or not 0 < pid < 2**32 or pid == os.getpid():
        raise TraceError("PID 必须是有效且非自身的进程。")
    if not isinstance(needle, bytes) or not 4 <= len(needle) <= 4096:
        raise TraceError("搜索串必须是 4 到 4096 字节。")
    if type(limit) is not int or not 1 <= limit <= 256:
        raise TraceError("limit 超出范围。")
    api = _Win()
    snapshot = inspect_process(pid)
    process = _open_verified(api, pid, snapshot)
    readable = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
    class _MEMORY_BASIC_INFORMATION(C.Structure):
        _fields_ = [("base", C.c_void_p), ("allocation_base", C.c_void_p),
                    ("allocation_protect", W.DWORD), ("partition", W.WORD), ("pad", W.WORD),
                    ("region_size", C.c_size_t), ("state", W.DWORD), ("protect", W.DWORD),
                    ("type", W.DWORD)]
    query = _MEMORY_BASIC_INFORMATION
    k = api.k
    try:
        addresses: list[int] = []
        address = 0
        info = query()
        while address < 0x00007FFFFFFFFFFF and len(addresses) < limit:
            if not k.VirtualQueryEx(process, C.c_void_p(address), C.byref(info), C.sizeof(info)):
                break
            start = int(info.base or 0)
            size = int(info.region_size)
            if info.state == 0x1000 and info.protect & 0xFF in readable and not info.protect & 0x100:
                cursor, chunk = start, 0x100000
                while cursor < start + size and len(addresses) < limit:
                    block = min(chunk, start + size - cursor)
                    try:
                        data = _read(api, process, cursor, block)
                    except (TraceError, NativeLoadError):
                        cursor += block
                        continue
                    found = 0
                    while True:
                        found = data.find(needle, found)
                        if found < 0:
                            break
                        addresses.append(cursor + found)
                        found += len(needle)
                        if len(addresses) >= limit:
                            break
                    cursor += block
            nxt = start + size
            if nxt <= address:
                break
            address = nxt
        return addresses
    finally:
        api.k.CloseHandle(process)


def trace_breakpoint(pid: int, module_name: str, export_name: str | None = None, *,
                     rva: int | None = None, timeout_ms: int = 15000,
                     dump_mem: int = 0,
                     patch_at_hit: dict[int, bytes] | None = None,
                     allow_interior: bool = False) -> TraceResult:
    """Attach once, break once on module!export or module+rva, sample registers/stack, detach.

    dump_mem > 0 时，命中冻结的瞬间把 rcx/rdx/r8/r9 各指向的内存读这么多字节存进
    TraceResult.memory（坏指针逐个跳过）。
    patch_at_hit 给出 {绝对地址: 字节}：命中冻结、采样完成后、恢复执行前，把这些
    字节写入目标内存（就地补丁——原始管线随后发出的就是补丁后的内容）；任一写入
    失败立即放弃全部补丁并照常恢复，fail closed。恢复与分离语义不变。
    """
    if type(pid) is not int or not 0 < pid < 2**32 or pid == os.getpid():
        raise TraceError("PID 必须是有效且非自身的进程。")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", module_name) or "\\" in module_name or "/" in module_name:
        raise TraceError("模块名必须是纯 basename。")
    if (export_name is None) == (rva is None):
        raise TraceError("必须且只能指定导出名或 RVA 之一。")
    if export_name is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_@?$#.-]{0,255}", export_name):
        raise TraceError("导出名不合法。")
    if rva is not None and (type(rva) is not int or not 0 < rva < 2**32):
        raise TraceError("RVA 必须是正数。")
    if type(timeout_ms) is not int or not 1 <= timeout_ms < 0xFFFFFFFF:
        raise TraceError("超时必须是有限的正 DWORD 毫秒数。")
    if type(dump_mem) is not int or not 0 <= dump_mem <= 4096:
        raise TraceError("dump_mem 必须在 [0, 4096] 字节内。")
    if patch_at_hit is not None:
        if not isinstance(patch_at_hit, dict) or not patch_at_hit:
            raise TraceError("patch_at_hit 必须是非空 {地址: 字节}。")
        for address, payload in patch_at_hit.items():
            if type(address) is not int or not 0 < address < 2**64:
                raise TraceError("补丁地址必须是 64 位以内的非零整数。")
            if not isinstance(payload, (bytes, bytearray)) or not 0 < len(payload) <= 4096:
                raise TraceError("补丁内容必须是非空字节串（≤4096）。")
    api = _Win()
    snapshot = inspect_process(pid)
    matches = [module for module in snapshot.modules
               if _path_key(module.path).endswith("\\" + module_name.casefold())]
    if len(matches) != 1:
        raise TraceError("目标中没有唯一匹配的模块。")
    module = matches[0]
    with module.path.open("rb") as stream:
        headers = stream.read(1024 * 1024)
        pe = _parse_pe(headers)
        resolved = _export_rva(stream, headers, pe.sections, export_name) if export_name else rva
        if resolved is None:
            raise TraceError("模块导出不存在。")
        if not 0 < resolved < 2**32:
            raise TraceError("断点 RVA 越界。")
        exported = frozenset({resolved}) if export_name else _export_rvas(stream, headers, pe.sections)
        _require_entry(stream, headers, pe.sections, resolved, exported,
                       allow_interior=allow_interior and export_name is None)
        expected = _read_at(stream, pe.sections, resolved, 32)
    process = _open_verified(api, pid, snapshot)
    remote = module.base + resolved
    if _read(api, process, remote, 32) != expected:
        api.k.CloseHandle(process)
        raise TraceError("目标代码字节与模块文件不一致，拒绝下断点。")
    if not api.k.DebugActiveProcess(pid):
        api.k.CloseHandle(process)
        raise api.error("DebugActiveProcess")
    if not api.k.DebugSetProcessKillOnExit(False):
        api.k.DebugActiveProcessStop(pid)
        api.k.CloseHandle(process)
        raise api.error("DebugSetProcessKillOnExit")
    attached, patched, status, detail = True, False, "TIMEOUT", ""
    patch_error = ""
    registers: dict[str, int] = {}
    frames: tuple[Frame, ...] = ()
    result_memory: dict[str, bytes] | None = None
    functions = _Functions()

    def resume(event, *, handled: bool = False) -> None:
        if event.code == EXCEPTION_DEBUG_EVENT:
            exception = struct.unpack_from("<I", bytes(event.data), 0)[0]
            status = DBG_CONTINUE if handled or exception == EXCEPTION_BREAKPOINT else DBG_EXCEPTION_NOT_HANDLED
        else:
            status = DBG_CONTINUE
        api.k.ContinueDebugEvent(pid, event.tid, status)

    def our_breakpoint(event) -> bool:
        if event.code != EXCEPTION_DEBUG_EVENT:
            return False
        data = bytes(event.data)
        return (struct.unpack_from("<I", data, 0)[0] == EXCEPTION_BREAKPOINT
                and struct.unpack_from("<Q", data, 16)[0] == remote)

    def restore_at_stop(event) -> None:
        """调用前进程停在该事件上；恢复字节、修正 Rip 后继续。"""
        nonlocal patched
        if patched:
            _write_byte(api, process, remote, expected[0])
            patched = False
        if our_breakpoint(event):
            _context(api, event.tid, set_rip=remote)
        resume(event)

    def drain(grace_seconds: float = 1.5) -> None:
        """命中后持续排空并发线程已触发的同地址事件，避免分离时留下停住的线程。"""
        deadline = time.monotonic() + grace_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            event = _wait(api, time.monotonic() + min(0.1, remaining))
            if event is None:
                continue
            handled = False
            if our_breakpoint(event):
                current = _context(api, event.tid)
                if current["rip"] == remote + 1:
                    _context(api, event.tid, set_rip=remote)
                handled = True
            resume(event, handled=handled)

    try:
        deadline = time.monotonic() + timeout_ms / 1000
        event = _wait(api, deadline)
        if event is None:
            raise TraceError("附加后未收到调试事件。")
        pending = event
        try:
            if event.code == EXIT_PROCESS_DEBUG_EVENT:
                status, detail = "EXITED", "目标在断点前已退出。"
            else:
                _write_byte(api, process, remote, 0xCC)
                patched = True
        finally:
            resume(pending)
            pending = None
        while status == "TIMEOUT":
            event = _wait(api, deadline)
            if event is None:
                detail = "等待超时；断点已恢复并分离。"
                break
            pending, handled = event, False
            try:
                if event.code == EXIT_PROCESS_DEBUG_EVENT:
                    status, detail, patched = "EXITED", "目标在断点前退出。", False
                elif our_breakpoint(event):
                    current = _context(api, event.tid)
                    if current["rip"] == remote + 1:
                        try:
                            frames = _backtrace(api, process, snapshot, module, resolved,
                                                current["rsp"], current, functions)
                            current["rip"] = remote  # 断点处的语义地址，不是 int3 后的 +1
                            registers = current
                            if dump_mem:
                                memory = {}
                                for reg in ("rcx", "rdx", "r8", "r9"):
                                    address = current.get(reg)
                                    if not address:
                                        continue
                                    try:
                                        memory[reg] = _read(api, process, address, dump_mem)
                                    except Exception:  # noqa: BLE001 - 坏指针只是没得读
                                        pass
                                result_memory = memory
                        finally:
                            # 补丁在恢复执行前落盘：冻结窗口内目标内存稳定，写入即生效。
                            if patch_at_hit:
                                try:
                                    for address, payload in patch_at_hit.items():
                                        for offset, byte in enumerate(payload):
                                            _write_byte(api, process, address + offset, byte)
                                    patch_error = ""
                                except (TraceError, NativeLoadError) as error:
                                    patch_error = f" 就地补丁失败（{error}），本次未修改任何目标内容。"
                                else:
                                    detail += " 就地补丁已写入。"
                            # 即使采样失败也必须恢复字节并校正 Rip，不能把 INT3 留在目标里。
                            _write_byte(api, process, remote, expected[0])
                            patched = False
                            _context(api, event.tid, set_rip=remote)
                            handled = True
                        if patch_at_hit and patch_error:
                            detail += patch_error
                        status = "HIT"
                        detail = "已恢复原始字节并分离；调用链为展开结果。"
            finally:
                if pending is not None:
                    resume(pending, handled=handled)
                    pending = None
        if status == "HIT":
            # 必须先把命中事件继续出去，排空才能收到并发线程的后续事件。
            drain()
    finally:
        try:
            if patched:
                # 进程仍在运行：注入一次调试断点使其停下后再恢复字节；失败则在线运行状态下恢复。
                try:
                    if api.k.DebugBreakProcess(process):
                        stop = _wait(api, time.monotonic() + 5)
                        if stop is not None:
                            restore_at_stop(stop)
                    if patched:
                        _write_byte(api, process, remote, expected[0])
                        patched = False
                        detail += " 已在目标运行状态下恢复原始字节。"
                except (TraceError, NativeLoadError) as error:
                    detail += f" 断点恢复失败：{error}"
        finally:
            try:
                if attached:
                    if not api.k.DebugActiveProcessStop(pid):
                        detail += f" 分离失败（WinError {C.get_last_error()}）。"
                    attached = False
            finally:
                api.k.CloseHandle(process)
    if patched:
        raise TraceError("断点未能恢复；目标中可能残留 INT3，已分离，请勿继续依赖该进程。")
    restored = None
    check = api.k.OpenProcess(0x0010, False, pid)
    if check:
        try:
            restored = _read(api, check, remote, 1) == expected[:1]
        except (TraceError, NativeLoadError):
            restored = None
        finally:
            api.k.CloseHandle(check)
    if restored is False:
        detail += " 断点字节回读不一致，请立即人工核对。"
    return TraceResult(status, module.path.name, resolved, remote, registers, frames, detail, restored,
                       memory=result_memory)
