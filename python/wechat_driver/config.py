"""独立包的运行配置：默认值 + 注入点。

史山里 ``DATA_DIR`` 由 ``app.config`` 统一决定（项目根/data）。独立包不能反向依赖
史山，所以这里只给一个自带默认值，宿主在启动时用 :func:`configure` 注入真实目录。

支持 provider 回调（而不是只存一个常量），这样史山侧可以注册
``lambda: app.config.DATA_DIR``，测试 monkeypatch ``app.config.DATA_DIR`` 时
本包读到的仍然是最新值，行为与拆分前完全一致。
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

# 数据目录解析优先级：显式 provider > 环境变量 > 家目录默认值。
_ENV_KEY = "DEEPFEIYU_DATA_DIR"

_provider: Callable[[], str | os.PathLike[str]] | None = None
_fallback: Path = Path(os.environ.get(_ENV_KEY) or (Path.home() / ".deepfeiyu"))


def configure(
    data_dir: str | os.PathLike[str] | Callable[[], str | os.PathLike[str]] | None = None,
) -> Path | None:
    """注入数据目录。

    ``data_dir`` 传路径则固定为该目录并返回它；传可调用对象则注册为 provider，
    每次读取时求值（跟随宿主配置变化），**注册当下不求值**——宿主如果把
    ``app.config`` 之类重依赖藏在 provider 里，注册动作不该顺手把它拉起来；
    传 ``None`` 只清除 provider，回到环境变量/默认值。

    返回：路径模式下是生效目录；provider 模式与清除模式下返回 ``None``。
    """
    global _provider, _fallback
    if callable(data_dir):
        _provider = data_dir
        return None
    if data_dir is not None:
        _provider = None
        _fallback = Path(data_dir)
        return _fallback
    _provider = None
    return None


def data_dir() -> Path:
    """当前生效的数据目录（每次调用都重新解析，保证与宿主配置同步）。"""
    if _provider is not None:
        return Path(_provider())
    return _fallback


def media_dir(account: str = "") -> Path:
    """媒体落盘目录：``<DATA_DIR>/media/<账号>``，与史山原有布局一致。"""
    return data_dir() / "media" / (account or "wechat")


__all__ = ["configure", "data_dir", "media_dir"]
