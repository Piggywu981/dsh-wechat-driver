"""驱动服务的线协议：NDJSON（每行一个 JSON 对象）。

为什麽是 NDJSON 而不是 stdio 上的 length-prefix 或 WebSocket：
宿主是 Node 侧的 DSH 插件，``readline`` 逐行解析最省事，也方便人肉调试
（``echo '{"id":1,"method":"status"}' | python -m wechat_driver``）。

三种帧：

请求  ``{"id": 1, "method": "send_text", "params": {...}}``
响应  ``{"id": 1, "ok": true, "result": {...}}``
      ``{"id": 1, "ok": false, "error": {"code": "...", "message": "..."}}``
事件  ``{"event": "message", "data": {...}}``   ← 服务端主动推送，无 id
"""
from __future__ import annotations

import json
from typing import Any

# 协议版本：宿主连接后先比对，避免新旧两侧字段错位。
PROTOCOL_VERSION = 1


class ProtocolError(Exception):
    """帧本身不合法（不是 JSON、缺 method、参数类型不对）。"""

    code = "BAD_REQUEST"


class MethodNotFound(ProtocolError):
    code = "METHOD_NOT_FOUND"


class DriverNotReady(ProtocolError):
    """驱动还没 start，或已经 stop。"""

    code = "DRIVER_NOT_READY"


def encode(payload: dict[str, Any]) -> str:
    """把一个帧编码成单行（保证不含裸换行，NDJSON 才成立）。"""
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"


def decode(line: str) -> dict[str, Any]:
    """解析一行请求帧；空行返回 ``{}`` 由调用方跳过。"""
    text = (line or "").strip()
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"不是合法 JSON：{exc}") from exc
    if not isinstance(payload, dict):
        raise ProtocolError("帧必须是 JSON 对象")
    return payload


def ok(msg_id: Any, result: Any) -> dict[str, Any]:
    return {"id": msg_id, "ok": True, "result": result}


def fail(msg_id: Any, code: str, message: str) -> dict[str, Any]:
    return {"id": msg_id, "ok": False, "error": {"code": str(code), "message": str(message)}}


def event(name: str, data: Any) -> dict[str, Any]:
    return {"event": str(name), "data": data}


__all__ = [
    "PROTOCOL_VERSION",
    "ProtocolError",
    "MethodNotFound",
    "DriverNotReady",
    "encode",
    "decode",
    "ok",
    "fail",
    "event",
]
