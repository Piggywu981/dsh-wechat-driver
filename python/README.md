# wechat_driver

独立的微信驱动包：**只管连微信、收发消息、列会话**。不含 AI、数据库、定时任务。

DSH 插件 `dsh-wechat-driver` 用它做后端；也可以单独当库或服务用。

## 当库用

```python
from wechat_driver import create, configure

configure("/path/to/data")                      # 媒体落盘目录（默认 ~/.deepfeiyu）
driver = create("weixin4", on_message=print, options={"account_dir": "wxid_xxx"})
driver.start()
driver.send_text("文件传输助手", "hello")
driver.stop()
```

## 当服务用

```bash
python -m wechat_driver --driver weixin4 --account-dir wxid_xxx
```

stdin 读 NDJSON 请求，stdout 写 NDJSON 响应与事件，**日志一律走 stderr**。

```bash
$ echo '{"id":1,"method":"status"}' | python -m wechat_driver --driver webhook --no-autostart
{"id":1,"ok":true,"result":{"driver":"webhook","started":false,"connected":false,"lastError":""}}
```

## 协议

请求 `{"id":1,"method":"...","params":{...}}` ·
响应 `{"id":1,"ok":true,"result":{...}}` / `{"id":1,"ok":false,"error":{"code","message"}}` ·
事件 `{"event":"message","data":{...}}`（服务端主动推送，无 `id`）

| 方法 | 分流 | 说明 |
|---|---|---|
| `ping` | 快 | 连通性探针，返回协议版本 |
| `info` | 快 | 驱动名 + 已注册驱动列表 |
| `status` | 快 | 连接状态（不需要驱动已 start） |
| `capabilities` | 快 | 当前驱动支持的能力 |
| `list_chats` | 快 | 列会话（读内存缓存） |
| `start` / `stop` | 慢 | 连接 / 断开微信 |
| `send_text` / `send_file` / `send_emoji` | 慢 | 发送，可能要几十秒 |
| `fetch_history` | 慢 | 拉历史消息 |
| `image` | 慢 | 按 local_id 解密图片 |
| `shutdown` | — | 优雅退出 |

**快慢分流是刻意的**：慢方法（UIA 扫控件树、SQLCipher 解密）进单线程队列串行跑，快方法
在主线程同步执行。否则一次发送就能把宿主的健康检查堵死几十秒。

## 编码

协议流强制 UTF-8（`_force_utf8_stdio`）。Windows 下 stdout 被重定向成管道时 Python 会退回
cp936，中文一过管道就烂，所以不能跟着系统区域跑。

## 依赖

核心零依赖（`base` / `protocol` / `server` / `factory` 只用标准库）。具体驱动走 extras：

```bash
pip install ".[weixin4]"   # Windows + 微信 4.x
pip install ".[webhook]"   # HTTP 网关
pip install ".[all]"
```

装不上某个 extras 不影响其它通道——每个驱动模块都是按需导入的，`weixin4_driver`
顶层的 `ctypes.windll` 不会拖累只想用 `webhook` 的宿主。
