"""驱动工厂：按名字建出驱动实例，并把配置字典摊平成构造参数。

拆包前这层逻辑散在 ``app/wechat/manager.py`` 里（构造 + 账号配置读取 + 默认值兜底），
独立包只保留「名字 → 类 → 构造参数」这一段纯逻辑，业务默认值由宿主传进来。
"""
from __future__ import annotations

from typing import Any, Callable

from .base import DriverError, Message, WeChatDriver

# 驱动名 → (模块名, 类名)。模块按需导入：wcferry 依赖 wcferry 包、weixin4 只支持
# Windows，顶层全量导入会让「只想用 webhook」的宿主也吃一记 ImportError。
_REGISTRY: dict[str, tuple[str, str]] = {
    "weixin4": ("weixin4_driver", "Weixin4Driver"),
    "wcferry": ("wcferry_driver", "WcferryDriver"),
    "webhook": ("webhook_driver", "WebhookDriver"),
}

# 每个驱动的构造参数白名单：宿主配置里多余字段直接丢弃，避免 TypeError。
_ACCEPTS: dict[str, tuple[str, ...]] = {
    "weixin4": (
        "account_dir",
        "interval",
        "warmup_on_start",
        "native_send",
        "background_send",
    ),
    "wcferry": ("host", "port"),
    "webhook": ("callback_url", "token", "account_id"),
}


def available() -> list[str]:
    """列出已注册的驱动名。"""
    return sorted(_REGISTRY)


def driver_class(name: str) -> type[WeChatDriver]:
    import importlib

    key = (name or "").strip().lower()
    if key not in _REGISTRY:
        raise DriverError(
            f"未知的微信驱动：{name!r}（可用：{', '.join(available())}）"
        )
    module_name, class_name = _REGISTRY[key]
    module = importlib.import_module(f".{module_name}", __package__)
    return getattr(module, class_name)


def create(
    name: str,
    on_message: Callable[[Message], None] | None = None,
    options: dict[str, Any] | None = None,
) -> WeChatDriver:
    """按名字创建驱动；``options`` 里不在白名单的键会被忽略。"""
    cls = driver_class(name)
    allowed = _ACCEPTS.get(name.strip().lower(), ())
    kwargs = {k: v for k, v in (options or {}).items() if k in allowed}
    return cls(on_message=on_message, **kwargs)


__all__ = ["available", "driver_class", "create"]
