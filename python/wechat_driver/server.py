"""驱动服务：把 :class:`WeChatDriver` 暴露成可跨进程调用的 NDJSON 服务。

拆分动机
--------
拆包前「驱动」和「业务编排」长在同一个 FastAPI 进程里，想用微信能力就必须把
AI、数据库、定时任务、心情系统全部拉起来。这个服务把它收敛成一条窄缝：
一个只管「连微信 / 收发消息 / 列会话」的长驻进程，宿主（DSH 插件、脚本、测试）
通过 stdio 说话。

线程模型
--------
- 主线程：读请求行、解码、分发。
- ``slow`` 单线程 executor：承载 start/stop/发送/历史/媒体——这些会阻塞几十秒
  （UIA 扫描控件树、SQLCipher 解密），且驱动内部本来就用全局 UI 锁串行，所以
  单线程既是正确性要求也最省心。
- 快方法（ping/status/capabilities/list_chats）在主线程同步跑，**不排队**：
  否则一次发送就能把宿主的健康检查堵死。
- 所有写 stdout 的地方共用一把锁；日志一律走 stderr，绝不允许污染协议流。
"""
from __future__ import annotations

import logging
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, TextIO

from . import protocol
from .base import DriverError, Message, WeChatDriver
from .factory import available, create
from .protocol import DriverNotReady, MethodNotFound, ProtocolError

log = logging.getLogger("wechat_driver.server")

# 主线程同步执行的方法：必须是毫秒级、不碰 UI、不碰数据库解密。
_FAST_METHODS = frozenset({"ping", "status", "capabilities", "list_chats", "info"})

# 走串行慢队的方法：会阻塞秒~几十秒，或在驱动内部抢全局 UI 锁。
_SLOW_METHODS = frozenset(
    {
        "start",
        "stop",
        "send_text",
        "send_file",
        "send_emoji",
        "fetch_history",
        "image",
    }
)


class DriverServer:
    """一条 stdio 连接上的驱动服务。"""

    def __init__(
        self,
        driver_name: str = "weixin4",
        options: dict[str, Any] | None = None,
        *,
        stdout: TextIO | None = None,
        autostart: bool = True,
    ) -> None:
        self._driver_name = driver_name
        self._options = dict(options or {})
        self._out = stdout or sys.stdout
        self._autostart = autostart
        self._write_lock = threading.Lock()
        self._driver: WeChatDriver | None = None
        self._started = False
        self._last_error = ""
        # 发送/启动/媒体都走这条串行队里；驱动内部的 UI 全局锁要求如此。
        self._slow = ThreadPoolExecutor(max_workers=1, thread_name_prefix="driver-slow")
        self._pending: set[threading.Thread] = set()
        self._closed = threading.Event()

    # ------------------------------------------------------------------ 输出

    def _write(self, payload: dict[str, Any]) -> None:
        """线程安全地写一帧；任何写入异常都不允许拖垮服务。"""
        line = protocol.encode(payload)
        with self._write_lock:
            try:
                self._out.write(line)
                self._out.flush()
            except (BrokenPipeError, ValueError):
                # 宿主已经退出，标记关闭让主循环收敛。
                self._closed.set()

    def _emit(self, name: str, data: Any) -> None:
        self._write(protocol.event(name, data))

    # ------------------------------------------------------------- 驱动生命周期

    def _on_message(self, msg: Message) -> None:
        """驱动线程回调 → 推送 ``message`` 事件。"""
        try:
            self._emit("message", msg.to_dict())
        except Exception as exc:  # pragma: no cover - 推送失败不该影响收消息
            log.warning("推送消息事件失败：%s", exc)

    def _ensure_driver(self) -> WeChatDriver:
        if self._driver is None:
            self._driver = create(self._driver_name, self._on_message, self._options)
        return self._driver

    def start(self) -> dict[str, Any]:
        driver = self._ensure_driver()
        driver.start()
        self._started = True
        self._last_error = ""
        return driver.status()

    def stop(self) -> dict[str, Any]:
        if self._driver is not None:
            try:
                self._driver.stop()
            finally:
                self._started = False
        return {"stopped": True}

    # ------------------------------------------------------------------ 方法表

    def _status(self) -> dict[str, Any]:
        if self._driver is None:
            return {
                "driver": self._driver_name,
                "started": False,
                "connected": False,
                "lastError": self._last_error,
            }
        payload = dict(self._driver.status() or {})
        payload.setdefault("driver", self._driver_name)
        payload["started"] = self._started
        if self._last_error:
            payload["lastError"] = self._last_error
        return payload

    def _require_started(self) -> WeChatDriver:
        if self._driver is None or not self._started:
            raise DriverNotReady("驱动未启动：先调用 start")
        return self._driver

    def _dispatch_fast(self, method: str, params: dict[str, Any]) -> Any:
        if method == "ping":
            return {"pong": True, "protocol": protocol.PROTOCOL_VERSION}
        if method == "info":
            return {"driver": self._driver_name, "available": available()}
        if method == "status":
            return self._status()
        if method == "capabilities":
            return self._require_started().capabilities()
        if method == "list_chats":
            driver = self._require_started()
            keyword = str(params.get("keyword") or "")
            limit = int(params.get("limit") or 100)
            return driver.list_chats(keyword=keyword, limit=limit)
        raise MethodNotFound(f"未知方法：{method}")

    def _dispatch_slow(self, method: str, params: dict[str, Any]) -> Any:
        # 先按方法名分支、再校验驱动状态：否则一个拼错的方法名会被报成
        # 「驱动未启动」，宿主排查方向直接被带偏。
        if method == "start":
            return self.start()
        if method == "stop":
            return self.stop()
        if method not in _SLOW_METHODS:
            raise MethodNotFound(f"未知方法：{method}")

        driver = self._require_started()
        if method == "send_text":
            chat_id = str(params.get("chat_id") or "")
            text = str(params.get("text") or "")
            if not chat_id or not text:
                raise ProtocolError("send_text 需要 chat_id 与 text")
            driver.send_text(chat_id, text)
            return {"sent": True}
        if method == "send_file":
            chat_id = str(params.get("chat_id") or "")
            path = str(params.get("path") or "")
            if not chat_id or not path:
                raise ProtocolError("send_file 需要 chat_id 与 path")
            driver.send_file(chat_id, path)
            return {"sent": True}
        if method == "send_emoji":
            chat_id = str(params.get("chat_id") or "")
            path = str(params.get("path") or "")
            if not chat_id or not path:
                raise ProtocolError("send_emoji 需要 chat_id 与 path")
            driver.send_emoji(chat_id, path)
            return {"sent": True}
        if method == "fetch_history":
            chat_id = str(params.get("chat_id") or "")
            if not chat_id:
                raise ProtocolError("fetch_history 需要 chat_id")
            limit = int(params.get("limit") or 50)
            fetch = getattr(driver, "fetch_history", None)
            if not callable(fetch):
                raise ProtocolError(f"驱动 {self._driver_name} 不支持 fetch_history")
            return [m.to_dict() for m in fetch(chat_id, limit=limit)]
        if method == "image":
            chat_id = str(params.get("chat_id") or "")
            local_id = str(params.get("local_id") or "")
            if not chat_id or not local_id:
                raise ProtocolError("image 需要 chat_id 与 local_id")
            getter = getattr(driver, "get_image", None)
            if not callable(getter):
                raise ProtocolError(f"驱动 {self._driver_name} 不支持 image")
            path = getter(
                chat_id,
                local_id,
                shard=str(params.get("shard") or ""),
                tier=str(params.get("tier") or "best"),
            )
            return {"path": path}
        raise MethodNotFound(f"未知方法：{method}")

    # ------------------------------------------------------------------ 请求处理

    def handle(self, frame: dict[str, Any]) -> None:
        """处理一条已解码的请求帧，并把结果写回。"""
        msg_id = frame.get("id")
        method = frame.get("method")
        if not isinstance(method, str) or not method:
            self._write(protocol.fail(msg_id, "BAD_REQUEST", "缺少 method 字段"))
            return
        params = frame.get("params") or {}
        if not isinstance(params, dict):
            self._write(protocol.fail(msg_id, "BAD_REQUEST", "params 必须是对象"))
            return

        try:
            if method in _FAST_METHODS:
                self._write(protocol.ok(msg_id, self._dispatch_fast(method, params)))
            else:
                self._submit_slow(msg_id, method, params)
        except ProtocolError as exc:
            self._write(protocol.fail(msg_id, exc.code, str(exc)))
        except DriverError as exc:
            self._last_error = str(exc)
            self._write(protocol.fail(msg_id, "DRIVER_ERROR", str(exc)))
        except Exception as exc:  # noqa: BLE001 - 服务端兜底，绝不让异常打断连接
            log.exception("处理 %s 失败", method)
            self._last_error = str(exc)
            self._write(protocol.fail(msg_id, "INTERNAL", f"{type(exc).__name__}: {exc}"))

    def _submit_slow(self, msg_id: Any, method: str, params: dict[str, Any]) -> None:
        """把慢方法投进串行队；结果在 worker 线程里写回。"""

        def run() -> None:
            try:
                result = self._dispatch_slow(method, params)
                self._write(protocol.ok(msg_id, result))
            except ProtocolError as exc:
                self._write(protocol.fail(msg_id, exc.code, str(exc)))
            except DriverError as exc:
                self._last_error = str(exc)
                self._write(protocol.fail(msg_id, "DRIVER_ERROR", str(exc)))
            except Exception as exc:  # noqa: BLE001
                log.exception("执行 %s 失败", method)
                self._last_error = str(exc)
                self._write(protocol.fail(msg_id, "INTERNAL", f"{type(exc).__name__}: {exc}"))

        self._slow.submit(run)

    # ------------------------------------------------------------------ 主循环

    def serve(self, stream: TextIO | None = None) -> int:
        """读请求行直到 EOF / shutdown。返回进程退出码。"""
        src = stream or sys.stdin
        if self._autostart and not self._closed.is_set():
            # 启动放到慢队里跑：首次连接要扫库，不能挡住 ping。
            self._submit_slow(None, "start", {})
        try:
            for line in src:
                if self._closed.is_set():
                    break
                try:
                    frame = protocol.decode(line)
                except ProtocolError as exc:
                    self._write(protocol.fail(None, exc.code, str(exc)))
                    continue
                if not frame:
                    continue
                if frame.get("method") == "shutdown":
                    self._write(protocol.ok(frame.get("id"), {"bye": True}))
                    break
                self.handle(frame)
        except KeyboardInterrupt:  # pragma: no cover - 交互调试
            pass
        finally:
            self.close()
        return 0

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """等串行队里已排队的慢方法全部跑完（测试与「发完再退出」用）。

        返回 True 表示队伍已空；False 表示超时（此时慢方法仍在跑）。
        """
        done = threading.Event()

        def marker() -> None:
            done.set()

        try:
            self._slow.submit(marker)
        except RuntimeError:  # executor 已关闭
            return True
        return done.wait(timeout)

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        try:
            self.stop()
        except Exception as exc:  # pragma: no cover
            log.warning("关闭驱动失败：%s", exc)
        self._slow.shutdown(wait=False, cancel_futures=True)


def _force_utf8_stdio() -> None:
    """把协议流钉成 UTF-8。

    Windows 上 stdout 被重定向成管道时 Python 会退回 locale 编码（cp936），中文一过
    管道就变成乱码字节；宿主（Node）按 UTF-8 解码只会看到 ``���``。协议是跨语言的，
    编码必须是显式的 UTF-8 + ``\n`` 行尾，不能跟着系统区域跑。
    """
    for stream in (sys.stdin, sys.stdout):
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace", newline="\n")
        except (ValueError, OSError):  # pragma: no cover - 已被包装的流
            pass


def build_parser():
    """CLI 参数。放在这里而不是 ``__main__``：``python -m`` 场景下模块名是
    ``__main__``，从它反向导入会触发二次执行。"""
    import argparse

    parser = argparse.ArgumentParser(
        prog="wechat_driver",
        description="独立微信驱动服务（NDJSON over stdio）",
    )
    parser.add_argument(
        "--driver",
        default="weixin4",
        choices=available(),
        help="驱动实现（默认 weixin4）",
    )
    parser.add_argument("--account-dir", default="", help="微信账号目录（weixin4）")
    parser.add_argument("--interval", type=float, default=None, help="轮询间隔秒（weixin4）")
    parser.add_argument(
        "--option",
        action="append",
        metavar="KEY=VALUE",
        help="透传给驱动的构造参数，可重复",
    )
    parser.add_argument(
        "--no-autostart",
        action="store_true",
        help="不在连接时自动 start，等宿主显式调用",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="日志级别（写 stderr）",
    )
    return parser


def main(
    argv: list[str] | None = None,
    stream_factory: Callable[[], TextIO] | None = None,
) -> int:
    """``python -m wechat_driver`` 的入口。"""
    args = build_parser().parse_args(argv)
    _force_utf8_stdio()
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        stream=sys.stderr,  # stdout 是协议流，日志只能去 stderr
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    options: dict[str, Any] = {}
    for item in args.option or []:
        key, _, value = str(item).partition("=")
        if not key:
            continue
        options[key] = value
    if args.account_dir:
        options["account_dir"] = args.account_dir
    if args.interval is not None:
        options["interval"] = float(args.interval)

    server = DriverServer(
        driver_name=args.driver,
        options=options,
        autostart=not args.no_autostart,
    )
    log.info("驱动服务就绪（driver=%s, protocol=%d）", args.driver, protocol.PROTOCOL_VERSION)
    return server.serve(stream_factory() if stream_factory else None)
