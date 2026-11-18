"""``python -m wechat_driver``：独立微信驱动服务的命令行入口。"""
from __future__ import annotations

import sys

from .server import main

if __name__ == "__main__":
    sys.exit(main())
