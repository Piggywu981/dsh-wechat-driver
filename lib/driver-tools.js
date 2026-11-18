// Agent 工具：直连微信驱动。不经过任何控制台 HTTP。
import { DriverDownError, DriverRpcError } from './driver.js'

const OUTPUT_OBJECT = { type: 'object', additionalProperties: true }

function jsonRender(_args, value) {
  return [{ type: 'text', text: JSON.stringify(value, null, 1) }]
}

function requireText(value, field) {
  const text = typeof value === 'string' ? value.trim() : ''
  if (!text) throw new Error(`${field} 不能为空`)
  return text
}

function clamp(value, min, max, fallback) {
  const num = Number(value)
  if (!Number.isFinite(num)) return fallback
  return Math.min(max, Math.max(min, Math.trunc(num)))
}

export function registerDriverTools({ ctx, config, client, sendGate }) {
  ctx.effect(() => ctx.tools.register({
    name: 'wechat_driver',
    description: '直连本机微信：查连接状态、列会话、发文本、拉历史消息。'
      + '首次调用会按需拉起驱动进程（读微信本地数据库 + UIA 发送），空闲后自动回收。'
      + '返回内容可能包含用户隐私信息。',
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['status', 'chats', 'send', 'history'],
          description: 'status 查状态；chats 列会话；send 发文本；history 拉历史',
        },
        keyword: { type: 'string', description: 'chats 的关键词过滤' },
        limit: { type: 'integer', description: 'chats / history 的条数上限' },
        chat_id: { type: 'string', description: 'send / history 的目标会话 id' },
        text: { type: 'string', description: 'send 的正文' },
      },
      additionalProperties: false,
    },
    output: { schema: OUTPUT_OBJECT, render: jsonRender },
    async execute(args, exec) {
      const input = args || {}
      const action = String(input.action || 'status')
      try {
        if (action === 'chats') {
          return {
            chats: await client.request('list_chats', {
              keyword: input.keyword ? String(input.keyword) : '',
              limit: clamp(input.limit, 1, 200, 100),
            }),
          }
        }
        if (action === 'history') {
          const chatId = requireText(input.chat_id, 'chat_id')
          return {
            messages: await client.request('fetch_history', {
              chat_id: chatId,
              limit: clamp(input.limit, 1, 100, 30),
            }),
          }
        }
        if (action === 'send') {
          const chatId = requireText(input.chat_id, 'chat_id')
          const text = requireText(input.text, 'text')
          // 发送走审批闸门：换条通道不等于绕开审批与禁发名单。
          if (sendGate) {
            await sendGate.assertAllowedSend(
              exec,
              `通过微信驱动发送消息到 ${chatId}`,
              `Send a WeChat message to ${chatId} through the driver`,
            )
          }
          await client.request('send_text', { chat_id: chatId, text }, { timeoutMs: config.sendTimeoutMs })
          return { sent: true, chatId }
        }
        return { driver: await client.status(), spawned: client.alive }
      } catch (err) {
        if (err instanceof DriverDownError || err instanceof DriverRpcError) {
          throw new Error(`${err.message}（驱动=${config.driver}，python=${config.pythonPath}）`)
        }
        throw new Error(String(err?.message || err))
      }
    },
  }), 'dsh-wechat-driver.tools')
}
