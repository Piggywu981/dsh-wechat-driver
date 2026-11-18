// 微信驱动 DSH 插件 Host 半：配置归一化 + 注册工具 + 进程生命周期。
//
// 这个插件只做一件事：把 python/wechat_driver 暴露成 Agent 工具。不开控制台、
// 不连 HTTP、不拉 AI 与数据库——驱动进程按需起、空闲回收。
import { dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createDriverClient } from './lib/driver.js'
import { registerDriverTools } from './lib/driver-tools.js'
import { createSendGate } from './lib/approval.js'

export const inject = ['tools', 'subprocess']

const DRIVERS = new Set(['weixin4', 'wcferry', 'webhook'])

const DEFAULTS = {
  enabled: true,
  driver: 'weixin4',
  accountDir: '',
  interval: 1,
  pythonPath: 'python',
  autostart: true,
  dataDir: '',
  options: {},
  requestTimeoutMs: 90000,
  sendTimeoutMs: 180000,
}

function positiveInt(value, fallback, field) {
  if (value === undefined || value === null || value === '') return fallback
  const num = Number(value)
  if (!Number.isInteger(num) || num <= 0) throw new Error(`dsh-wechat-driver: ${field} 必须是正整数`)
  return num
}

function normalizeConfig(rawConfig, packageRoot) {
  const raw = rawConfig && typeof rawConfig === 'object' ? rawConfig : {}
  const name = String(raw.driver || DEFAULTS.driver)
  const interval = Number(raw.interval)
  return {
    ...DEFAULTS,
    ...raw,
    packageRoot,
    enabled: raw.enabled === undefined ? DEFAULTS.enabled : Boolean(raw.enabled),
    driver: DRIVERS.has(name) ? name : DEFAULTS.driver,
    accountDir: raw.accountDir ? String(raw.accountDir) : '',
    interval: Number.isFinite(interval) && interval > 0 ? interval : DEFAULTS.interval,
    pythonPath: raw.pythonPath ? String(raw.pythonPath) : DEFAULTS.pythonPath,
    autostart: raw.autostart === undefined ? DEFAULTS.autostart : Boolean(raw.autostart),
    dataDir: raw.dataDir ? String(raw.dataDir) : '',
    options: raw.options && typeof raw.options === 'object' ? { ...raw.options } : {},
    requestTimeoutMs: positiveInt(raw.requestTimeoutMs, DEFAULTS.requestTimeoutMs, 'requestTimeoutMs'),
    sendTimeoutMs: positiveInt(raw.sendTimeoutMs, DEFAULTS.sendTimeoutMs, 'sendTimeoutMs'),
  }
}

export function apply(ctx, rawConfig) {
  const packageRoot = dirname(fileURLToPath(import.meta.url))
  const config = normalizeConfig(rawConfig, packageRoot)

  const client = createDriverClient({ ctx, config })
  const sendGate = createSendGate(ctx)

  registerDriverTools({ ctx, config, client, sendGate })
  // 卸载时兜底终止自起的驱动进程，不留孤儿。
  ctx.effect(() => () => client.dispose(), 'dsh-wechat-driver.client')

  ctx.logger.info(
    'dsh-wechat-driver: active (driver=%s, enabled=%s, python=%s)',
    config.driver, config.enabled, config.pythonPath,
  )
}
