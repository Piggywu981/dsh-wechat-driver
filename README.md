# dsh-wechat-driver

在 DeepSeek Harness 里直连本机微信的 DSH 插件：**列会话、发消息、拉历史消息**。

自带驱动实现在 `python/wechat_driver/`，按需起一个 Python 进程，用 NDJSON over stdio 说话。
不开控制台、不连 HTTP、不拉 AI 与数据库——想「看一眼微信连没连、发条消息」时不用把整台
服务端拉起来。

## 结构

```
dsh-wechat-driver/
├── index.js               Host 半：配置归一化、注册工具、进程生命周期
├── lib/
│   ├── driver.js          NDJSON 客户端：懒启动 / 空闲回收 / 超时 / 错误分类
│   ├── driver-tools.js    Agent 工具 wechat_driver
│   └── approval.js        发送审批闸门（跟随 Harness 权限模式）
├── cordis.patch.yml       装载入口与默认配置
└── python/
    ├── pyproject.toml
    └── wechat_driver/     驱动包：base / protocol / server / factory + 三个具体驱动
```

## 安装

插件按本地目录装，`python/` 目录无需 pip install（插件会用 `PYTHONPATH` 指过去）。
但**驱动依赖要装进你指定的那个解释器**：

```bash
# 微信 4.x（Windows）
pip install "./python[weixin4]"
```

也可以在 `cordis.patch.yml` 里把 `pythonPath` 指向一个已经装好依赖的 venv 解释器。

## 配置

```yaml
- insert:
    - id: wechat-driver
      name: dsh-wechat-driver
      config:
        enabled: true
        driver: weixin4        # weixin4 | wcferry | webhook
        accountDir: wxid_xxx   # 留空自动探测；多开时务必显式填
        interval: 1            # 数据库轮询间隔（秒）
        pythonPath: C:\path\to\.venv\Scripts\python.exe
```

| 字段 | 默认 | 说明 |
|---|---|---|
| `enabled` | `true` | 关掉后工具仍注册，但调用会明确报「已关闭」，不会去起进程 |
| `driver` | `weixin4` | `weixin4` 读微信 4.x 本地库 + UIA 发送；`wcferry` 走微信 3.9 hook；`webhook` 走 HTTP 网关 |
| `accountDir` | 空（自动探测） | 微信账号目录。多开时显式指定，驱动会校验目录存在，不自动改绑 |
| `interval` | `1` | 消息轮询间隔秒 |
| `pythonPath` | `python`（PATH） | 驱动器解释器；建议填绝对路径，避免 PATH 里是另一个没装依赖的 python |
| `autostart` | `true` | 连接后是否立刻连接微信；`false` 则等你显式操作再连 |
| `dataDir` | 空 | 媒体落盘目录；空则用 `~/.deepfeiyu` |
| `options` | `{}` | 透传给驱动的构造参数（如 `{ warmup_on_start: "true" }`） |
| `requestTimeoutMs` | `90000` | 普通请求超时 |
| `sendTimeoutMs` | `180000` | 发送超时（UIA 要扫控件树，会慢） |

## 工具 `wechat_driver`

| `action` | 参数 | 作用 |
|---|---|---|
| `status` | — | 驱动状态（不需要已连接也能查） |
| `chats` | `keyword?` `limit?` | 列会话，默认 100 条上限 200 |
| `history` | `chat_id` `limit?` | 拉历史消息，默认 30 条上限 100 |
| `send` | `chat_id` `text` | 发文本，**先过审批闸门** |

发送闸门跟随 Harness 会话权限：完全批准（never）直接发；逐步审批（ask）走
`ctx.approval.request`，只有 `allowed-once` 才发；无法判定时 fail closed。

## 行为约定

- **懒启动**：第一次调用工具才 spawn 驱动进程。
- **空闲回收**：3 分钟没有请求就优雅 shutdown，不留常驻进程。
- **卸载兜底**：插件卸载时终止自起的进程。
- **中文**：驱动侧强制 UTF-8；插件侧按 UTF-8 解码，不跟系统区域跑。
- **隐私**：会话内容与历史消息会进入工具结果，可能包含用户隐私信息。

## 单独用驱动（不开 DSH）

```bash
cd python
python -m wechat_driver --driver weixin4 --account-dir wxid_xxx
# stdin 读 NDJSON 请求，stdout 写响应与事件，日志走 stderr
```

协议与方法表见 [python/README.md](python/README.md)。

## 许可

PolyForm Noncommercial 1.0.0，见 [LICENSE](LICENSE)。
