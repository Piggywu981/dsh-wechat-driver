"""独立的本地 Windows AMD64 DLL 加载原语；不含微信发送/发现/提权。

只读取进程身份、模块 PE 头和系统加载入口的少量字节，不读取业务内存。
DLL 是任意本机代码；摘要仅固定用户选择的文件，不代表代码安全审查。
UNKNOWN 禁止自动重试：远端路径及只读文件锁保留至目标退出（不自动回收）。
此模块导入时不加载 WinDLL、不打开进程、不访问应用配置。
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes as C
from ctypes import wintypes as W
from dataclasses import dataclass, replace
import hashlib
import os
from pathlib import Path
import re
import struct
import sys

from .base import DriverError


class NativeLoadError(DriverError):
    """可读且不包含请求内容/业务数据的原生加载失败。"""


@dataclass(frozen=True)
class ModuleIdentity:
    path: Path
    base: int
    size: int


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    exe_path: Path
    creation_time: int  # 原始 FILETIME，避免浮点时间丢失身份精度。
    machine: int
    modules: tuple[ModuleIdentity, ...]


@dataclass(frozen=True)
class LoadResult:
    status: str  # LOADED / ALREADY_LOADED / UNKNOWN
    process: ProcessIdentity
    module_path: Path | None = None
    module_base: int | None = None
    remote_allocation: int | None = None
    retained_file_handle: int | None = None
    detail: str = "仅确认 DLL 加载，不代表发送能力可用。"


@dataclass(frozen=True)
class _PE:
    timestamp: int
    image_size: int
    headers_size: int
    sections: tuple[tuple[int, int, int, int, int], ...]


@dataclass(frozen=True)
class LockedLibrary:
    handle: int
    path: Path
    sha256: str
    pe: _PE | None = None
    header: bytes = b""


class _MODULEINFO(C.Structure):
    _fields_ = [("base", C.c_void_p), ("size", W.DWORD), ("entry", C.c_void_p)]


class _VS_FIXEDFILEINFO(C.Structure):
    _fields_ = [(name, W.DWORD) for name in (
        "signature", "structure_version", "file_version_ms", "file_version_ls",
        "product_version_ms", "product_version_ls", "flags_mask", "flags", "os",
        "type", "subtype", "date_ms", "date_ls",
    )]


def _check_pid(pid: int) -> None:
    if type(pid) is not int or not 0 < pid < 2**32:
        raise NativeLoadError("PID 必须是非零 DWORD 整数。")
    if pid == os.getpid():
        raise NativeLoadError("拒绝对自身进程执行此操作。")


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def same_process(left: ProcessIdentity, right: ProcessIdentity) -> bool:
    """稳定身份只包含 PID、exe、创建时间与架构；模块快照会随目标日常加载而变动。"""
    return (left.pid == right.pid and left.machine == right.machine
            and left.creation_time == right.creation_time
            and _path_key(left.exe_path) == _path_key(right.exe_path))


def _parse_pe(blob: bytes, *, file_size: int | None = None) -> _PE:
    """仅接受完整 AMD64 PE32+ DLL 头；不把扩展名当作格式证据。"""
    try:
        if blob[:2] != b"MZ":
            raise ValueError
        pe = struct.unpack_from("<I", blob, 0x3C)[0]
        if not 64 <= pe <= 1024 * 1024 - 512 or blob[pe:pe + 4] != b"PE\0\0":
            raise ValueError
        machine, count, timestamp = struct.unpack_from("<HHI", blob, pe + 4)
        optional_size, flags = struct.unpack_from("<HH", blob, pe + 20)
        optional = pe + 24
        if machine != 0x8664 or not (flags & 0x2000 and flags & 2):
            raise ValueError
        if optional_size < 112 or struct.unpack_from("<H", blob, optional)[0] != 0x20B:
            raise ValueError
        image_size, headers_size = struct.unpack_from("<II", blob, optional + 56)
        end = optional + optional_size + count * 40
        if not 1 <= count <= 96 or end > len(blob) or not end <= headers_size <= image_size:
            raise ValueError
        if file_size is not None and headers_size > file_size:
            raise ValueError
        sections = []
        for offset in range(optional + optional_size, end, 40):
            virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", blob, offset + 8)
            characteristics = struct.unpack_from("<I", blob, offset + 36)[0]
            if rva + max(virtual_size, raw_size) > image_size:
                raise ValueError
            if file_size is not None and raw_size and raw_offset + raw_size > file_size:
                raise ValueError
            sections.append((rva, virtual_size, raw_offset, raw_size, characteristics))
        return _PE(timestamp, image_size, headers_size, tuple(sections))
    except (struct.error, ValueError, IndexError):
        raise NativeLoadError("文件不是有效的 AMD64 PE32+ DLL，或 PE 头已截断。") from None


class _WinAPI:
    """所有 Win32 签名集中显式声明；地址/句柄/SIZE_T 不经 DWORD。"""

    def __init__(self) -> None:
        if sys.platform != "win32" or C.sizeof(C.c_void_p) != 8:
            raise NativeLoadError("仅支持 64 位 Windows 与 64 位 Python。")
        # 限制 ctypes 自身 DLL 搜索到系统目录；不改变全局 DLL 搜索策略。
        self.k = C.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
        self.v = C.WinDLL("version.dll", use_last_error=True, winmode=0x800)
        P, D, H, B, S = C.c_void_p, W.DWORD, W.HANDLE, W.BOOL, C.c_size_t
        signatures = {
            "OpenProcess": (H, [D, B, D]),
            "CloseHandle": (B, [H]),
            "GetCurrentProcess": (H, []),
            "GetProcessTimes": (B, [H] + [C.POINTER(W.FILETIME)] * 4),
            "QueryFullProcessImageNameW": (B, [H, D, W.LPWSTR, C.POINTER(D)]),
            "IsWow64Process2": (B, [H, C.POINTER(W.WORD), C.POINTER(W.WORD)]),
            "WaitForSingleObject": (D, [H, D]),
            "K32EnumProcessModulesEx": (B, [H, C.POINTER(H), D, C.POINTER(D), D]),
            "K32GetModuleFileNameExW": (D, [H, H, W.LPWSTR, D]),
            "K32GetModuleInformation": (B, [H, H, C.POINTER(_MODULEINFO), D]),
            "GetModuleHandleW": (H, [W.LPCWSTR]),
            "GetModuleHandleExW": (B, [D, P, C.POINTER(H)]),
            "GetProcAddress": (P, [H, C.c_char_p]),
            "FreeLibrary": (B, [H]),
            "GetSystemDirectoryW": (W.UINT, [W.LPWSTR, W.UINT]),
            "GetDriveTypeW": (W.UINT, [W.LPCWSTR]),
            "CreateFileW": (H, [W.LPCWSTR, D, D, P, D, D, H]),
            "GetFinalPathNameByHandleW": (D, [H, W.LPWSTR, D, D]),
            "GetFileSizeEx": (B, [H, C.POINTER(C.c_longlong)]),
            "ReadFile": (B, [H, P, D, C.POINTER(D), P]),
            "SetFilePointerEx": (B, [H, C.c_longlong, C.POINTER(C.c_longlong), D]),
            "ReadProcessMemory": (B, [H, P, P, S, C.POINTER(S)]),
            "VirtualAllocEx": (P, [H, P, S, D, D]),
            "VirtualFreeEx": (B, [H, P, S, D]),
            "WriteProcessMemory": (B, [H, P, P, S, C.POINTER(S)]),
            "CreateRemoteThread": (H, [H, P, S, P, P, D, C.POINTER(D)]),
            "DuplicateHandle": (B, [H, H, H, C.POINTER(H), D, B, D]),
        }
        try:
            for name, (result, args) in signatures.items():
                function = getattr(self.k, name)
                function.restype, function.argtypes = result, args
            for name, result, args in (
                ("GetFileVersionInfoSizeW", D, [W.LPCWSTR, C.POINTER(D)]),
                ("GetFileVersionInfoW", B, [W.LPCWSTR, D, D, P]),
                ("VerQueryValueW", B, [P, W.LPCWSTR, C.POINTER(P), C.POINTER(W.UINT)]),
            ):
                function = getattr(self.v, name)
                function.restype, function.argtypes = result, args
        except AttributeError:
            raise NativeLoadError("系统缺少所需 Win32 API（包括 IsWow64Process2），拒绝猜测架构。") from None

    @staticmethod
    def error(operation: str) -> NativeLoadError:
        code = C.get_last_error()
        # 不回显系统格式化文本，避免包含调用路径或环境内容。
        reason = {5: "权限不足；不会自动提权", 6: "句柄无效", 87: "参数无效或进程已退出",
                  299: "读取不完整，进程可能正在退出", 32: "文件被写入/删除占用"}.get(code, "系统调用失败")
        return NativeLoadError(f"{operation} 失败（WinError {code}：{reason}）。")

    def close(self, handle: int) -> None:
        if not self.k.CloseHandle(handle):
            raise self.error("CloseHandle")

    def wait(self, handle: int, timeout: int) -> int:
        return self.k.WaitForSingleObject(handle, timeout)

    def alive(self, process: int) -> None:
        state = self.wait(process, 0)
        if state == 0:
            raise NativeLoadError("目标进程已退出。")
        if state != 258:
            raise self.error("WaitForSingleObject(process)")

    def open_process(self, pid: int, *, write: bool = False) -> int:
        rights = 0x100000 | 0x0400 | 0x0010  # SYNCHRONIZE, QUERY_INFORMATION, VM_READ
        if write:
            rights |= 0x0002 | 0x0008 | 0x0020 | 0x0040
        process = self.k.OpenProcess(rights, False, pid)
        if not process:
            raise self.error("OpenProcess")
        return process

    def machine(self, process: int) -> int:
        emulated, native = W.WORD(), W.WORD()
        if not self.k.IsWow64Process2(process, C.byref(emulated), C.byref(native)):
            raise self.error("IsWow64Process2")
        if native.value != 0x8664 or emulated.value != 0:
            raise NativeLoadError("目标/调用进程架构不匹配；仅支持原生 AMD64。")
        return native.value

    def identity(self, process: int, pid: int) -> ProcessIdentity:
        self.alive(process)
        self.machine(self.k.GetCurrentProcess())
        machine = self.machine(process)
        times = [W.FILETIME() for _ in range(4)]
        if not self.k.GetProcessTimes(process, *(C.byref(value) for value in times)):
            raise self.error("GetProcessTimes")
        path, count = C.create_unicode_buffer(32768), W.DWORD(32768)
        if not self.k.QueryFullProcessImageNameW(process, 0, path, C.byref(count)):
            raise self.error("QueryFullProcessImageNameW")
        creation = times[0].dwLowDateTime | (times[0].dwHighDateTime << 32)
        modules = self.modules(process)
        self.alive(process)
        return ProcessIdentity(pid, Path(path.value), creation, machine, modules)

    def module(self, process: int, handle: int) -> ModuleIdentity:
        path = C.create_unicode_buffer(32768)
        length = self.k.K32GetModuleFileNameExW(process, handle, path, len(path))
        if not 0 < length < len(path):
            raise self.error("GetModuleFileNameExW")
        info = _MODULEINFO()
        if not self.k.K32GetModuleInformation(process, handle, C.byref(info), C.sizeof(info)):
            raise self.error("GetModuleInformation")
        if not info.base or not info.size:
            raise NativeLoadError("模块地址或映像大小无效。")
        return ModuleIdentity(Path(path.value), info.base, info.size)

    def modules(self, process: int) -> tuple[ModuleIdentity, ...]:
        # 有界的只读枚举；变化/缓冲区不足直接失败，不做不可靠的截断快照。
        handles = (W.HANDLE * 4096)()
        needed = W.DWORD()
        if not self.k.K32EnumProcessModulesEx(process, handles, C.sizeof(handles), C.byref(needed), 2):
            raise self.error("EnumProcessModulesEx")
        if needed.value > C.sizeof(handles) or needed.value % C.sizeof(W.HANDLE):
            raise NativeLoadError("模块快照超出边界，无法可靠确认身份。")
        return tuple(sorted((self.module(process, handles[i])
                             for i in range(needed.value // C.sizeof(W.HANDLE))), key=lambda m: m.base))

    def local_path(self, path: Path) -> Path:
        path = Path(path)
        if not path.is_absolute() or not re.fullmatch(r"[A-Za-z]:", path.drive) or "\0" in str(path):
            raise NativeLoadError("DLL 必须使用本地磁盘的绝对路径（不接受网络路径）。")
        if self.k.GetDriveTypeW(path.anchor) != 3:
            raise NativeLoadError("DLL 必须位于本地固定磁盘。")
        return path

    @contextmanager
    def lock_library(self, path: Path, expected_sha256: str | None = None):
        path = self.local_path(path)
        if expected_sha256 is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
            raise NativeLoadError("预期 SHA256 必须是 64 位十六进制摘要。")
        # GENERIC_READ + FILE_SHARE_READ：拒绝共享写/删除，持续到调用结束。
        handle = self.k.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x80, None)
        if handle == C.c_void_p(-1).value:
            raise self.error("CreateFileW(DLL)")
        try:
            canonical = C.create_unicode_buffer(32768)
            count = self.k.GetFinalPathNameByHandleW(handle, canonical, len(canonical), 0)
            if not 0 < count < len(canonical):
                raise self.error("GetFinalPathNameByHandleW")
            final = canonical.value
            if final.startswith("\\\\?\\"):
                final = final[4:]
            final_path = self.local_path(Path(final))
            size = C.c_longlong()
            if not self.k.GetFileSizeEx(handle, C.byref(size)):
                raise self.error("GetFileSizeEx")
            digest, prefix, consumed = hashlib.sha256(), bytearray(), 0
            while consumed < size.value:
                chunk = self.read_file(handle, min(1024 * 1024, size.value - consumed))
                if not chunk:
                    raise NativeLoadError("DLL 文件读取被截断。")
                digest.update(chunk)
                if len(prefix) < 1024 * 1024:
                    prefix.extend(chunk[:1024 * 1024 - len(prefix)])
                consumed += len(chunk)
            actual = digest.hexdigest()
            if expected_sha256 is not None and actual != expected_sha256.lower():
                raise NativeLoadError("DLL SHA256 与预期不匹配；未执行远程写入。")
            pe = _parse_pe(bytes(prefix), file_size=size.value)
            yield LockedLibrary(handle, final_path, actual, pe, bytes(prefix))
        finally:
            self.close(handle)

    def read_file(self, handle: int, size: int, offset: int | None = None) -> bytes:
        if offset is not None and not self.k.SetFilePointerEx(handle, offset, None, 0):
            raise self.error("SetFilePointerEx")
        buffer, read = C.create_string_buffer(size), W.DWORD()
        if not self.k.ReadFile(handle, buffer, size, C.byref(read), None):
            raise self.error("ReadFile")
        return buffer.raw[:read.value]

    def read_memory(self, process: int, address: int, size: int) -> bytes:
        buffer, read = C.create_string_buffer(size), C.c_size_t()
        if not self.k.ReadProcessMemory(process, address, buffer, size, C.byref(read)) or read.value != size:
            raise self.error("ReadProcessMemory(module metadata)")
        return buffer.raw

    def verify_loaded(self, process: int, module: ModuleIdentity, library: LockedLibrary) -> None:
        if library.pe is None or module.size != library.pe.image_size:
            raise NativeLoadError("已加载模块大小与 DLL 身份不符。")
        size = min(library.pe.headers_size, 1024 * 1024)
        mapped = _parse_pe(self.read_memory(process, module.base, size))
        if mapped != library.pe:
            raise NativeLoadError("已加载模块 PE 身份与 DLL 文件不符。")

    def remote_load_address(self, process: int) -> int:
        local = self.k.GetCurrentProcess()
        kernel = self.k.GetModuleHandleW("kernel32.dll")
        if not kernel:
            raise self.error("GetModuleHandleW")
        address = self.k.GetProcAddress(kernel, b"LoadLibraryW")
        if not address:
            raise self.error("GetProcAddress(LoadLibraryW)")
        owner = W.HANDLE()
        # FROM_ADDRESS 增加本地拥有模块引用，避免在核对期间被卸载。
        if not self.k.GetModuleHandleExW(4, address, C.byref(owner)):
            raise self.error("GetModuleHandleExW")
        try:
            source = self.module(local, owner.value)
            system = C.create_unicode_buffer(32768)
            count = self.k.GetSystemDirectoryW(system, len(system))
            if not 0 < count < len(system):
                raise self.error("GetSystemDirectoryW")
            if _path_key(source.path.parent) != _path_key(Path(system.value)):
                raise NativeLoadError("LoadLibraryW 拥有模块不在系统目录，拒绝使用未知入口。")
            matches = [m for m in self.modules(process) if _path_key(m.path) == _path_key(source.path)]
            if len(matches) != 1:
                raise NativeLoadError("目标缺少唯一同路径系统模块，无法确认加载入口。")
            target = matches[0]
            with self.lock_library(source.path) as library:
                self.verify_loaded(local, source, library)
                self.verify_loaded(process, target, library)
                rva = address - source.base
                executable = [s for s in library.pe.sections
                              if s[4] & 0x20000000 and s[0] <= rva and rva + 32 <= s[0] + min(s[1], s[3])]
                if len(executable) != 1:
                    raise NativeLoadError("加载入口 RVA 不在已验证的可执行节中。")
                section = executable[0]
                expected = self.read_file(library.handle, 32, section[2] + rva - section[0])
                remote_address = target.base + rva
                if (len(expected) != 32 or self.read_memory(local, address, 32) != expected
                        or self.read_memory(process, remote_address, 32) != expected):
                    raise NativeLoadError("系统加载入口字节与锁定文件不符，拒绝使用不可靠地址。")
                return remote_address
        finally:
            if not self.k.FreeLibrary(owner):
                raise self.error("FreeLibrary(local owner reference)")

    def file_version(self, path: Path) -> str:
        unused = W.DWORD()
        size = self.v.GetFileVersionInfoSizeW(str(path), C.byref(unused))
        if not size or size > 16 * 1024 * 1024:
            raise NativeLoadError("无法获取有界文件版本信息。")
        buffer = C.create_string_buffer(size)
        if not self.v.GetFileVersionInfoW(str(path), 0, size, buffer):
            raise self.error("GetFileVersionInfoW")
        pointer, length = C.c_void_p(), W.UINT()
        if not self.v.VerQueryValueW(buffer, "\\", C.byref(pointer), C.byref(length)):
            raise self.error("VerQueryValueW")
        if length.value < C.sizeof(_VS_FIXEDFILEINFO) or not pointer.value:
            raise NativeLoadError("文件版本信息不完整。")
        info = C.cast(pointer, C.POINTER(_VS_FIXEDFILEINFO)).contents
        if info.signature != 0xFEEF04BD:
            raise NativeLoadError("文件版本信息签名无效。")
        return ".".join(str(n) for n in (info.file_version_ms >> 16, info.file_version_ms & 0xFFFF,
                                       info.file_version_ls >> 16, info.file_version_ls & 0xFFFF))

    def allocate(self, process: int, size: int) -> int:
        address = self.k.VirtualAllocEx(process, None, size, 0x3000, 0x04)
        if not address:
            raise self.error("VirtualAllocEx")
        return address

    def free(self, process: int, address: int) -> None:
        if not self.k.VirtualFreeEx(process, address, 0, 0x8000):
            raise self.error("VirtualFreeEx")

    def write(self, process: int, address: int, data: bytes) -> None:
        written = C.c_size_t()
        buffer = C.create_string_buffer(data)
        if not self.k.WriteProcessMemory(process, address, buffer, len(data), C.byref(written)):
            raise self.error("WriteProcessMemory")
        if written.value != len(data):
            raise NativeLoadError("远端 DLL 路径写入不完整。")

    def duplicate_to_target(self, process: int, file_handle: int) -> int:
        duplicate = W.HANDLE()
        if not self.k.DuplicateHandle(self.k.GetCurrentProcess(), file_handle, process,
                                      C.byref(duplicate), 0, False, 2):
            raise self.error("DuplicateHandle(file lock)")
        return duplicate.value

    def close_remote(self, process: int, remote_handle: int) -> None:
        duplicate = W.HANDLE()
        # DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS；只关闭我们复制的锁。
        if not self.k.DuplicateHandle(process, remote_handle, self.k.GetCurrentProcess(),
                                      C.byref(duplicate), 0, False, 3):
            raise self.error("DuplicateHandle(close file lock)")
        self.close(duplicate.value)

    def create_thread(self, process: int, start: int, parameter: int) -> int:
        thread_id = W.DWORD()
        thread = self.k.CreateRemoteThread(process, None, 0, start, parameter, 0, C.byref(thread_id))
        if not thread:
            raise self.error("CreateRemoteThread")
        return thread


def inspect_process(pid: int) -> ProcessIdentity:
    """显式 PID 的只读身份快照；不枚举全机进程，不读取命令行。"""
    _check_pid(pid)
    api = _WinAPI()
    process = api.open_process(pid)
    try:
        return api.identity(process, pid)
    finally:
        api.close(process)


def _inject(api: _WinAPI, process: int, identity: ProcessIdentity,
            library: LockedLibrary, timeout_ms: int) -> LoadResult:
    start = api.remote_load_address(process)
    payload = (str(library.path) + "\0").encode("utf-16-le")
    allocation = api.allocate(process, len(payload))
    remote_file = thread = None
    completed = False
    result = failure = None
    cleanup_errors = []
    remaining_allocation = allocation
    try:
        api.write(process, allocation, payload)
        # 必须在线程启动前复制：即使调用端在 UNKNOWN 后退出，文件仍拒共享写/删除。
        remote_file = api.duplicate_to_target(process, library.handle)
        thread = api.create_thread(process, start, allocation)
        try:
            state = api.wait(thread, timeout_ms)
        except (NativeLoadError, OSError):
            # 线程已启动后，等待异常也不能证明路径已不再被读取。
            state = 0xFFFFFFFF
        if state != 0:
            result = LoadResult(
                "UNKNOWN", identity, remote_allocation=allocation, retained_file_handle=remote_file,
                detail="等待超时或失败，线程可能仍读取路径；禁止自动重试。远端分配及只读文件锁保留至目标退出；本工具不自动回收。",
            )
        else:
            completed = True
            matches = [m for m in api.modules(process) if _path_key(m.path) == _path_key(library.path)]
            if len(matches) != 1:
                raise NativeLoadError("远端线程已结束，但未确认唯一精确路径模块；不宣称加载成功。")
            module = matches[0]
            api.verify_loaded(process, module, library)
            result = LoadResult("LOADED", identity, library.path, module.base)
    except NativeLoadError as error:
        failure = error
    finally:
        # 顺序：先确认线程结束，才释放路径与远端文件锁；最后关闭本地线程句柄。
        # 尚未创建线程时没有远端读者，可以立即释放；UNKNOWN 刻意不进入此分支。
        if thread is None or completed:
            try:
                api.free(process, allocation)
                remaining_allocation = None
            except NativeLoadError as error:
                cleanup_errors.append(str(error))
            if remote_file is not None:
                try:
                    api.close_remote(process, remote_file)
                    remote_file = None
                except NativeLoadError as error:
                    cleanup_errors.append(str(error))
        if thread is not None:
            try:
                api.close(thread)
            except NativeLoadError as error:
                cleanup_errors.append(str(error))
    if cleanup_errors:
        detail = (str(failure) if failure else result.detail) + " 清理失败：" + "；".join(cleanup_errors)
        detail += " 禁止自动重试；远端资源可能残留至目标退出，本地句柄可能残留至调用端退出。"
        return replace(result or LoadResult("UNKNOWN", identity), status="UNKNOWN",
                       remote_allocation=remaining_allocation, retained_file_handle=remote_file, detail=detail)
    if failure is not None:
        raise failure
    return result


def _check_location(dll_path: Path, allowed_root: Path,
                    forbidden_roots: tuple[Path, ...]) -> Path:
    """库层强制项目内、非安装树、非硬链接；CLI 的早期校验不是唯一闸门。"""
    if not isinstance(dll_path, Path) or not dll_path.is_absolute():
        raise NativeLoadError("DLL 必须是绝对路径。")
    try:
        actual = dll_path.resolve(strict=True)
        root = allowed_root.resolve(strict=True)
        excluded = tuple(item.resolve(strict=True) for item in forbidden_roots)
        if not actual.is_file() or not actual.is_relative_to(root):
            raise NativeLoadError("DLL 必须位于允许的项目目录内。")
        if any(actual.is_relative_to(item) for item in excluded):
            raise NativeLoadError("DLL 不能位于微信安装树内。")
        if actual.stat().st_nlink != 1:
            raise NativeLoadError("DLL 不允许使用硬链接。")
        return actual
    except OSError:
        raise NativeLoadError("DLL 路径不存在或无法安全解析。") from None


def load_library(pid: int, dll_path: Path, expected_sha256: str, timeout_ms: int = 10000,
                 *, expected_identity: ProcessIdentity | None = None,
                 allowed_root: Path, forbidden_roots: tuple[Path, ...]) -> LoadResult:
    """固定进程对象和 DLL 后进行一次加载；已加载精确路径不增加引用。

    caller 必须同时给出允许根目录与禁止安装树；两者都是强制约束，不能省略。
    ``expected_identity`` 用于 CLI 诊断到加载间的身份复核；在唯一 OpenProcess 句柄上
    比较创建时间、exe 与架构，任何变化失败关闭。不会自动重试或杀进程。
    ``timeout_ms`` 仅限制远端线程等待，不包括此前的文件摘要与元数据校验耗时。
    """
    _check_pid(pid)
    if type(timeout_ms) is not int or not 1 <= timeout_ms < 0xFFFFFFFF:
        raise NativeLoadError("timeout_ms 必须是有限的正 DWORD 毫秒数。")
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise NativeLoadError("预期 SHA256 必须是 64 位十六进制摘要。")
    dll_path = _check_location(dll_path, allowed_root, forbidden_roots)
    api = _WinAPI()
    # 在任何目标身份判断前打开并保留句柄，后续操作不再通过 PID 重新打开。
    process = api.open_process(pid, write=True)
    result = None
    try:
        identity = api.identity(process, pid)
        if expected_identity is not None and not same_process(identity, expected_identity):
            raise NativeLoadError("进程身份已变化；拒绝向未获校验的目标加载 DLL。")
        with api.lock_library(dll_path, expected_sha256) as library:
            # CLI 已校验的是这个绝对路径；不能让其在解析重解析点后变成另一位置。
            if _path_key(library.path) != _path_key(dll_path):
                raise NativeLoadError("DLL 规范路径已变化；请使用经校验的实际绝对路径。")
            existing = [m for m in api.modules(process) if _path_key(m.path) == _path_key(library.path)]
            if existing:
                if len(existing) != 1:
                    raise NativeLoadError("目标模块路径不唯一。")
                api.verify_loaded(process, existing[0], library)
                result = LoadResult("ALREADY_LOADED", identity, library.path, existing[0].base)
            else:
                api.alive(process)
                result = _inject(api, process, identity, library, timeout_ms)
    except NativeLoadError as error:
        if result is None:
            raise
        result = replace(result, status="UNKNOWN", detail=result.detail + f" 本地文件锁清理失败：{error} 禁止自动重试。")
    finally:
        try:
            api.close(process)
        except NativeLoadError as error:
            if result is None:
                raise
            result = replace(result, status="UNKNOWN", detail=result.detail + f" 本地进程句柄清理失败：{error} 禁止自动重试。")
    return result
