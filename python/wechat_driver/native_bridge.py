"""weixin4 桥接载荷的本地控制端：读导出令牌、连命名管道、按帧协议对话。

只与 wx4bridge.dll 的 v2 协议对话；不读取宿主业务内存。v2 原语（内存分配/
读写/调用）只操作桥自己分配并在册的内存，INVOKE 目标必须是目标进程内已加载
模块映像中的地址——两侧都做同样校验，任何一侧拒绝都 fail closed。
令牌是本地单机边界：只防同用户下其他进程误连/抢注，不防已能读写目标内存的
攻击者（那已是更高层失守）。所有失败路径 fail closed，错误不回显对端字节。
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import struct
import sys
import time

from .base import DriverError
from .native_loader import (NativeLoadError, _WinAPI, _parse_pe, _path_key, inspect_process,
                            load_library, same_process)
from .native_trace import _export_rva

PROTO_VERSION = 2

CMD_HELLO = 1
CMD_PING = 2
CMD_VERSION = 3
CMD_SHUTDOWN = 4
CMD_ALLOC = 5
CMD_FREE = 6
CMD_WRITE = 7
CMD_READ = 8
CMD_INVOKE = 9

ST_OK = 0
ST_AUTH = 1
ST_PROTO = 2
ST_CMD = 3
ST_BUSY = 4
ST_INVAL = 5
ST_TIMEOUT = 6

STATE_LISTEN = 1

FRAME_LEN = 32   # 命令帧：req_id/cmd/填充8/token/proto/payload_len（+payload）
REPLY_LEN = 28   # 应答帧：req_id/cmd/status/proto/build/state/payload_len（+payload）

PAYLOAD_MAX = 64 * 1024       # 单条命令/应答载荷上限（与桥侧一致，先在客户端 fail fast）
ALLOC_MAX = 1024 * 1024       # 单次分配上限（与桥侧一致）
INVOKE_ARGS_MAX = 4           # x64 寄存器实参数量（栈实参尚不支持，见桥侧注释）
INVOKE_TIMEOUT_MAX_MS = 30000

TOKEN_EXPORT = "g_bridge_token"
STATE_EXPORT = "g_bridge_state"

_STATUS_NAMES = {
    ST_OK: "成功", ST_AUTH: "令牌被拒", ST_PROTO: "协议不符", ST_CMD: "未知命令",
    ST_BUSY: "桥接忙", ST_INVAL: "参数或目标非法", ST_TIMEOUT: "调用等待超时",
}


class NativeBridgeError(DriverError):
    """可读且不含对端内容的桥接失败。"""

    @classmethod
    def from_status(cls, operation: str, status: int) -> "NativeBridgeError":
        reason = _STATUS_NAMES.get(status, f"未知状态 {status}")
        return cls(f"{operation} 被桥接拒绝（{reason}）；fail closed。")


class NativeSendUnavailable(NativeBridgeError):
    """原生发送不可用：期2 取证未完成（发送函数签名未知）时的明确信号。"""


def pipe_name(pid: int) -> str:
    if type(pid) is not int or not 0 < pid < 2**32:
        raise NativeBridgeError("PID 必须是有效的非零 DWORD。")
    return f"\\\\.\\pipe\\deepfeiyu-wx4bridge-{pid}"


def read_bridge_globals(pid: int, module_path: Path, *,
                        expected_identity=None) -> tuple[int, int]:
    """读桥接 DLL 导出的令牌与状态；模块必须在目标中唯一在场。

    ``expected_identity`` 传入 load_library 结果里的身份时做注入前后复核，
    身份变化立即失败，防止把令牌读自已被替换的进程。
    """
    if not isinstance(module_path, Path):
        raise NativeBridgeError("模块路径必须是 Path。")
    snapshot = inspect_process(pid)
    if expected_identity is not None and not same_process(snapshot, expected_identity):
        raise NativeBridgeError("进程身份已变化；拒绝读取桥接全局。")
    matches = [module for module in snapshot.modules
               if _path_key(module.path) == _path_key(module_path)]
    if len(matches) != 1:
        raise NativeBridgeError("目标中没有唯一在场的桥接模块；未读取任何内容。")
    module = matches[0]
    try:
        with module_path.open("rb") as stream:
            headers = stream.read(1024 * 1024)
            pe = _parse_pe(headers)
            rva_token = _export_rva(stream, headers, pe.sections, TOKEN_EXPORT)
            rva_state = _export_rva(stream, headers, pe.sections, STATE_EXPORT)
    except NativeLoadError as error:
        raise NativeBridgeError(f"桥接 DLL 导出表无法解析：{error}") from None
    if rva_token is None or rva_state is None:
        raise NativeBridgeError("桥接 DLL 导出表缺少令牌/状态符号；不是 wx4bridge 产物。")
    api = _WinAPI()
    process = api.open_process(pid)
    try:
        token = struct.unpack("<Q", api.read_memory(process, module.base + rva_token, 8))[0]
        state = struct.unpack("<I", api.read_memory(process, module.base + rva_state, 4))[0]
    finally:
        api.close(process)
    return token, state


class _PipeAPI:
    """命名管道客户端的显式 Win32 签名；句柄/地址不经 DWORD。"""

    def __init__(self) -> None:
        if sys.platform != "win32" or C.sizeof(C.c_void_p) != 8:
            raise NativeBridgeError("仅支持 64 位 Windows 与 64 位 Python。")
        self.k = C.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
        P, D, H, B = C.c_void_p, W.DWORD, W.HANDLE, W.BOOL
        signatures = {
            "CreateFileW": (H, [W.LPCWSTR, D, D, P, D, D, H]),
            "ReadFile": (B, [H, P, D, C.POINTER(D), P]),
            "WriteFile": (B, [H, P, D, C.POINTER(D), P]),
            "PeekNamedPipe": (B, [H, P, D, P, C.POINTER(D), P]),
            "CloseHandle": (B, [H]),
        }
        try:
            for name, (result, args) in signatures.items():
                function = getattr(self.k, name)
                function.restype, function.argtypes = result, args
        except AttributeError:
            raise NativeBridgeError("系统缺少所需 Win32 API。") from None

    @staticmethod
    def error(operation: str) -> NativeBridgeError:
        code = C.get_last_error()
        reason = {2: "管道不存在（桥接未就绪或已停止）", 3: "路径不存在", 5: "拒绝访问",
                  231: "桥接忙（已有客户端在服务中）"}.get(code, "系统调用失败")
        return NativeBridgeError(f"{operation} 失败（WinError 2/231 之外不重试；{reason}）。")
    # ↑ 这条消息不再逐码区分：连接失败统一由 connect() 判断是否可重试。

    def open(self, name: str) -> int:
        # 同步句柄；超时语义由调用方用 PeekNamedPipe 轮询实现，管道本身不设超时。
        handle = self.k.CreateFileW(name, 0xC0000000, 0, None, 3, 0, None)
        if handle == C.c_void_p(-1).value:
            raise self.error("CreateFileW(bridge)")
        return handle

    def close(self, handle: int) -> None:
        if not self.k.CloseHandle(handle):
            raise self.error("CloseHandle(bridge)")

    def write(self, handle: int, data: bytes) -> None:
        offset = 0
        total = len(data)
        while offset < total:
            put = W.DWORD()
            chunk = data[offset:]
            if not self.k.WriteFile(handle, chunk, len(chunk), C.byref(put), None) or not put.value:
                raise self.error("WriteFile(bridge)")
            offset += put.value

    def read_exact(self, handle: int, size: int, deadline: float) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NativeBridgeError("读取桥接应答超时；未回显对端内容。")
            available = W.DWORD()
            if not self.k.PeekNamedPipe(handle, None, 0, None, C.byref(available), None):
                raise self.error("PeekNamedPipe(bridge)")
            if not available.value:
                time.sleep(min(0.005, remaining))
                continue
            want = min(available.value, size - len(chunks))
            chunk = C.create_string_buffer(want)
            got = W.DWORD()
            if not self.k.ReadFile(handle, chunk, want, C.byref(got), None) or not got.value:
                raise self.error("ReadFile(bridge)")
            chunks.extend(chunk.raw[:got.value])
        return bytes(chunks)


class BridgeSession:
    """单个桥接客户端连接；先 hello 后才允许其他命令，每帧携带令牌。"""

    def __init__(self, pid: int) -> None:
        self._name = pipe_name(pid)
        self._api = _PipeAPI()
        self._handle = None
        self._request_id = 0
        self._token = 0

    def connect(self, timeout_s: float = 5.0) -> None:
        if type(timeout_s) not in (int, float) or not 0 < timeout_s <= 60:
            raise NativeBridgeError("连接时限必须是 (0, 60] 秒。")
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                self._handle = self._api.open(self._name)
                return
            except NativeBridgeError as error:
                # 只有「管道未出现」和「服务中忙」值得等到时限；权限类失败立即抛。
                retry = "WinError 2" in str(error) or "WinError 231" in str(error)
                if not retry or time.monotonic() >= deadline:
                    raise NativeBridgeError(
                        "桥接管道在时限内未出现（未加载、已停止、被占用或拒绝访问）；未连接任何目标。") from error
                time.sleep(0.01)

    def _exchange(self, command: int, token: int, payload: bytes = b"") -> dict[str, int]:
        if self._handle is None:
            raise NativeBridgeError("先 connect() 再发命令。")
        if len(payload) > PAYLOAD_MAX:
            raise NativeBridgeError("命令载荷超出协议上限；未发送。")
        self._request_id += 1
        frame = struct.pack("<II8xQII", self._request_id, command, token,
                            PROTO_VERSION, len(payload))
        deadline = time.monotonic() + 5.0
        self._api.write(self._handle, struct.pack("<I", FRAME_LEN) + frame + payload)
        header = self._api.read_exact(self._handle, 4, deadline)
        length = struct.unpack("<I", header)[0]
        if length != REPLY_LEN:
            raise NativeBridgeError("桥接应答长度不是协议值；连接已丢弃。")
        body = self._api.read_exact(self._handle, REPLY_LEN, deadline)
        req_id, echoed, status, proto, build, state, reply_len = struct.unpack("<7I", body)
        if req_id != self._request_id or echoed != command:
            raise NativeBridgeError("桥接应答序号不匹配；连接已丢弃。")
        # v2：应答末位 dword 是载荷长度；声称超上限立即断开，不读对端字节。
        data = b""
        if reply_len:
            if reply_len > PAYLOAD_MAX:
                raise NativeBridgeError("桥接应答载荷超出协议上限；连接已丢弃。")
            data = self._api.read_exact(self._handle, reply_len, deadline)
        return {"req_id": req_id, "cmd": echoed, "status": status,
                "proto": proto, "build": build, "state": state, "payload": data}

    def _request(self, command: int, payload: bytes = b"") -> dict[str, int]:
        if not self._token:
            raise NativeBridgeError("先 hello() 拿到有效令牌再发其他命令。")
        return self._exchange(command, self._token, payload)

    def hello(self, token: int) -> dict[str, int]:
        if type(token) is not int or not 0 < token < 2**64:
            raise NativeBridgeError("令牌必须是 64 位非零整数。")
        if self._handle is None:
            raise NativeBridgeError("先 connect() 再握手。")
        response = self._exchange(CMD_HELLO, token)
        if response["status"] == ST_OK:
            self._token = token  # 之后的每帧由 DLL 逐帧复核，这里只是允许发。
        return response

    def ping(self) -> dict[str, int]:
        return self._request(CMD_PING)

    def version(self) -> dict[str, int]:
        return self._request(CMD_VERSION)

    def shutdown(self) -> dict[str, int]:
        return self._request(CMD_SHUTDOWN)

    # ---- v2 原语 ----------------------------------------------------------

    def alloc(self, size: int) -> int:
        """在目标进程分配一块在册内存，返回地址。失败/拒绝一律抛错。"""
        if type(size) is not int or not 0 < size <= ALLOC_MAX:
            raise NativeBridgeError("分配大小必须在 (0, 1MB] 内。")
        response = self._request(CMD_ALLOC, struct.pack("<I", size))
        if response["status"] != ST_OK:
            raise NativeBridgeError.from_status("alloc", response["status"])
        return struct.unpack("<Q", response["payload"])[0]

    def free(self, address: int) -> None:
        self._assert_address(address)
        response = self._request(CMD_FREE, struct.pack("<Q", address))
        if response["status"] != ST_OK:
            raise NativeBridgeError.from_status("free", response["status"])

    def write(self, address: int, data: bytes) -> None:
        self._assert_address(address)
        if not data or len(data) > PAYLOAD_MAX:
            raise NativeBridgeError("写入内容必须非空且不超过单帧载荷上限。")
        payload = struct.pack("<QI", address, len(data)) + data
        response = self._request(CMD_WRITE, payload)
        if response["status"] != ST_OK:
            raise NativeBridgeError.from_status("write", response["status"])

    def read(self, address: int, length: int) -> bytes:
        self._assert_address(address)
        if type(length) is not int or not 0 < length <= PAYLOAD_MAX:
            raise NativeBridgeError("读取长度必须在 (0, 单帧载荷上限] 内。")
        response = self._request(CMD_READ, struct.pack("<QI4x", address, length))
        if response["status"] != ST_OK:
            raise NativeBridgeError.from_status("read", response["status"])
        return response["payload"]

    def invoke(self, target: int, args: tuple[int, ...] = (), *,
               timeout_ms: int = 10000) -> int:
        """调用目标进程内已加载模块映像中的函数，返回 rax。

        args 按 x64 寄存器顺序对应 rcx/rdx/r8/r9，最多 4 个；缺位以 0 补齐。
        超时抛错但目标线程仍在执行（桥侧挂 pending 等待期回收），这是协议
        如实告知的行为。
        """
        if type(target) is not int or not 0 < target < 2**64:
            raise NativeBridgeError("调用目标必须是 64 位非零地址。")
        args = tuple(args)
        if len(args) > INVOKE_ARGS_MAX:
            raise NativeBridgeError("寄存器实参最多 4 个（rcx/rdx/r8/r9）。")
        for value in args:
            if type(value) is not int or not 0 <= value < 2**64:
                raise NativeBridgeError("实参必须是 64 位以内的非负整数。")
        if type(timeout_ms) is not int or not 0 < timeout_ms <= INVOKE_TIMEOUT_MAX_MS:
            raise NativeBridgeError("调用时限必须在 (0, 30000] 毫秒内。")
        padded = args + (0,) * (INVOKE_ARGS_MAX - len(args))
        # 布局对齐桥侧 on_invoke：target@0 args@8 timeout@40 reserved@44。
        payload = struct.pack("<Q4QII", target, *padded, timeout_ms, 0)
        response = self._request(CMD_INVOKE, payload)
        if response["status"] != ST_OK:
            raise NativeBridgeError.from_status("invoke", response["status"])
        return struct.unpack("<Q", response["payload"])[0]

    @staticmethod
    def _assert_address(address: int) -> None:
        if type(address) is not int or not 0 < address < 2**64:
            raise NativeBridgeError("地址必须是 64 位以内的非零整数。")

    def close(self) -> None:
        if self._handle is not None:
            self._api.close(self._handle)
            self._handle = None


def _wait_module_absent(pid: int, module_path: Path, deadline: float) -> bool:
    while time.monotonic() < deadline:
        try:
            snapshot = inspect_process(pid)
        except NativeLoadError:
            return True  # 目标退出同样意味着模块已不在场
        if not any(_path_key(module.path) == _path_key(module_path) for module in snapshot.modules):
            return True
        time.sleep(0.3)
    return False


def load_and_probe(pid: int, dll_path: Path, expected_sha256: str, *, timeout_ms: int = 10000,
                   expected_identity=None, allowed_root: Path, forbidden_roots: tuple[Path, ...],
                   connect_timeout_s: float = 5.0, shutdown_after: bool = False) -> dict:
    """加载（或确认已加载）桥接 DLL 并做一次完整握手探测；可选拆除。

    这是后续 CLI 与 driver 接线要用的唯一高层入口：调用方只需提供与
    native_loader.load_library 相同的强制约束（允许根目录与禁止安装树）。
    """
    result = load_library(pid, dll_path, expected_sha256, timeout_ms,
                          expected_identity=expected_identity, allowed_root=allowed_root,
                          forbidden_roots=forbidden_roots)
    if result.status == "UNKNOWN":
        return {"status": "UNKNOWN", "detail": result.detail, "pid": pid}
    module_path = result.module_path or dll_path
    deadline = time.monotonic() + 5.0
    while True:
        token, state = read_bridge_globals(pid, module_path, expected_identity=result.process)
        if state == STATE_LISTEN and token:
            break
        if time.monotonic() >= deadline:
            raise NativeBridgeError("桥接未进入监听态（令牌未就绪或服务出错）；fail closed。")
        time.sleep(0.05)
    session = BridgeSession(pid)
    out = {"status": result.status, "pid": pid, "module_base": result.module_base}
    try:
        session.connect(connect_timeout_s)
        handshake = session.hello(token)
        if handshake["status"] != ST_OK:
            raise NativeBridgeError("桥接握手被拒（令牌或协议不符）；fail closed。")
        version = session.version()
        ping = session.ping()
        out.update({"proto": version["proto"], "build": version["build"],
                    "state": ping["state"], "ping_ok": ping["status"] == ST_OK,
                    "unloaded": False})
        if shutdown_after:
            shutdown = session.shutdown()
            if shutdown["status"] != ST_OK:
                raise NativeBridgeError("桥接拒绝拆除命令；fail closed。")
            session.close()
            out["unloaded"] = _wait_module_absent(pid, module_path, time.monotonic() + 10.0)
    finally:
        session.close()
    return out
