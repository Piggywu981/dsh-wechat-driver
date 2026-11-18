"""独立微信驱动包：只负责「连微信 / 收发消息 / 列会话」，不含 AI、数据库与业务编排。

对外两副面孔
------------
作为库：

    from wechat_driver import create, configure
    configure("/path/to/data")          # 媒体落盘目录
    driver = create("weixin4", on_message=print, options={"account_dir": "wxid_xxx"})
    driver.start()
    driver.send_text("文件传输助手", "hello")

作为服务（给 DSH 插件等跨语言宿主）：

    python -m wechat_driver --driver weixin4

    → 读 stdin 的 NDJSON 请求，写 stdout 的 NDJSON 响应/事件，日志走 stderr。

顶层不导入具体驱动实现：``weixin4_driver`` 依赖 Windows ctypes/UIA 与
``wechatauto-replica``，只想用 ``webhook`` 的宿主不该被它连带拖垮。用
:func:`create` 或 :func:`driver_class` 按需加载。
"""
from __future__ import annotations

from .base import DriverError, Message, WeChatDriver
from .config import configure, data_dir, media_dir
from .factory import available, create, driver_class
from .protocol import PROTOCOL_VERSION

__version__ = "0.1.0"

__all__ = [
    "DriverError",
    "Message",
    "WeChatDriver",
    "PROTOCOL_VERSION",
    "__version__",
    "available",
    "configure",
    "create",
    "data_dir",
    "driver_class",
    "media_dir",
]
