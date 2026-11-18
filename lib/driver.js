// 直连微信驱动：把进程内自带的 python/wechat_driver 拉成一条 NDJSON 通道。
//
// 生命周期：懒启动（第一次调用才 spawn）、空闲自动回收（避免长驻）、插件卸载时
// 兜底终止。所有请求带超时；进程死掉时把待决请求全部 reject，不让调用方干等。
import { createInterface } from 'node:readline'
import { access } from 'node:fs/promises'
import { join } from 'node:path'

/** 驱动进程没起来 / 已经退出。 */
export class DriverDownError extends Error {
  constructor(message) {
    super(message)
    this.name = 'DriverDownError'
    this.code = 'DRIVER_DOWN'
  }
}

/** 驱动进程回了 ok:false。 */
export class DriverRpcError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'DriverRpcError'
    this.code = code || 'DRIVER_RPC'
  }
}

/** 单条请求超时（发送走 UIA 可能要几十秒，默认给足）。 */
const DEFAULT_TIMEOUT_MS = 90000
/** 空闲多久回收进程：驱动持有微信 DB 句柄与 UIA 线程，没必要一直挂着。 */
const IDLE_RELEASE_MS = 180000

export function createDriverClient({ ctx, config }) {
  let handle = null
  let reader = null
  let seq = 0
  let disposed = false
  let idleTimer = null
  const pending = new Map()
  const messageListeners = new Set()
  const state = {
    phase: 'idle', // idle | starting | running | error
    pid: null,
    lastError: '',
    sent: 0,
    received: 0,
  }

  function driverArgv() {
    const argv = [config.pythonPath, '-m', 'wechat_driver', '--driver', String(config.driver || 'weixin4')]
    if (config.accountDir) argv.push('--account-dir', String(config.accountDir))
    if (Number.isFinite(config.interval)) argv.push('--interval', String(config.interval))
    // 宿主想先看一眼 status 再连微信时用得上。
    if (config.autostart === false) argv.push('--no-autostart')
    for (const [key, value] of Object.entries(config.options || {})) {
      argv.push('--option', `${key}=${value}`)
    }
    return argv
  }

  function env() {
    // 驱动包就在本插件目录下（python/wechat_driver），没 pip install 也能 import。
    // UTF-8 必须显式给：Windows 下 NDJSON 里的中文否则会按 GBK 编码出管道。
    const root = join(config.packageRoot, 'python')
    const existing = process.env.PYTHONPATH
    const merged = {
      ...process.env,
      PYTHONPATH: existing ? `${root};${existing}` : root,
      PYTHONUTF8: '1',
      PYTHONIOENCODING: 'utf-8',
    }
    if (config.dataDir) merged.DEEPFEIYU_DATA_DIR = String(config.dataDir)
    return merged
  }

  function settleAll(error) {
    for (const [, entry] of pending) {
      clearTimeout(entry.timer)
      entry.reject(error)
    }
    pending.clear()
  }

  function armIdle() {
    if (idleTimer) clearTimeout(idleTimer)
    idleTimer = setTimeout(() => { void release() }, IDLE_RELEASE_MS)
    idleTimer.unref?.()
  }

  function onLine(line) {
    const text = line.trim()
    if (!text) return
    let frame
    try {
      frame = JSON.parse(text)
    } catch {
      // 非协议行（某个库往 stdout 打了日志）不该炸掉整条连接。
      state.lastError = `驱动输出非 JSON：${text.slice(0, 200)}`
      return
    }
    if (frame.event) {
      state.received += 1
      if (frame.event === 'message') {
        for (const listener of messageListeners) {
          try { listener(frame.data) } catch { /* 监听器自己的异常不该拖垮连接 */ }
        }
      }
      armIdle()
      return
    }
    const entry = pending.get(frame.id)
    if (!entry) return
    pending.delete(frame.id)
    clearTimeout(entry.timer)
    state.received += 1
    if (frame.ok) entry.resolve(frame.result)
    else entry.reject(new DriverRpcError(frame.error?.code, frame.error?.message || '驱动返回失败'))
    armIdle()
  }

  async function spawn() {
    if (handle) return handle
    if (config.enabled === false) {
      throw new DriverDownError('微信驱动已关闭：把插件配置的 enabled 打开')
    }
    // pythonPath 留空表示用 PATH 上的 python；给了具体路径就要求它真的存在，
    // 否则用户看到的是 spawn 的系统级 ENOENT，很难归因。
    if (config.pythonPath && config.pythonPath !== 'python' && !(await exists(config.pythonPath))) {
      throw new DriverDownError(`未找到 Python 解释器：${config.pythonPath}`)
    }
    state.phase = 'starting'
    state.lastError = ''
    handle = ctx.subprocess.spawn({
      argv: driverArgv(),
      cwd: config.packageRoot,
      stdio: {
        stdin: 'pipe',
        stdout: 'pipe',
        stderr: { maxBytes: 16384 },
      },
      env: env(),
      graceMs: 5000,
    })
    state.pid = handle.pid ?? null
    reader = createInterface({ input: handle.stdout, crlfDelay: Infinity })
    reader.on('line', onLine)
    handle.done.then((outcome) => {
      const code = outcome?.exitCode
      cleanup(`驱动进程退出（code=${code}）`, code === 0)
    }).catch((err) => {
      cleanup(`驱动进程异常：${err?.message || err}`, false)
    })
    state.phase = 'running'
    armIdle()
    return handle
  }

  function cleanup(reason, benign) {
    if (reader) { try { reader.close() } catch { /* 已关闭 */ } reader = null }
    handle = null
    state.pid = null
    state.phase = benign ? 'idle' : 'error'
    if (!benign) state.lastError = reason
    settleAll(new DriverDownError(reason))
    if (idleTimer) { clearTimeout(idleTimer); idleTimer = null }
  }

  async function request(method, params = {}, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    if (disposed) throw new DriverDownError('插件已卸载')
    await spawn()
    const id = ++seq
    const line = JSON.stringify({ id, method, params }) + '\n'
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id)
        reject(new DriverDownError(`驱动请求超时（${method}，${timeoutMs}ms）`))
      }, Math.max(1000, timeoutMs))
      timer.unref?.()
      pending.set(id, { resolve, reject, timer })
      try {
        handle.stdin.write(line)
        state.sent += 1
      } catch (err) {
        pending.delete(id)
        clearTimeout(timer)
        reject(new DriverDownError(`写入驱动失败：${err?.message || err}`))
      }
    })
  }

  async function release() {
    if (!handle) return
    try { handle.stdin.write(JSON.stringify({ id: ++seq, method: 'shutdown' }) + '\n') } catch { /* 已断 */ }
    try { handle.terminate() } catch { /* 已退出 */ }
    try { await handle.waitForExit() } catch { /* 已退出 */ }
    cleanup('主动回收', true)
  }

  function onMessage(listener) {
    messageListeners.add(listener)
    return () => messageListeners.delete(listener)
  }

  async function status() {
    if (!handle) return { ...state }
    try {
      const payload = await request('status', {}, { timeoutMs: 8000 })
      state.phase = 'running'
      return { ...state, driver: payload }
    } catch (err) {
      state.lastError = String(err?.message || err)
      return { ...state }
    }
  }

  function dispose() {
    disposed = true
    messageListeners.clear()
    if (idleTimer) { clearTimeout(idleTimer); idleTimer = null }
    if (handle) {
      try { handle.terminate() } catch { /* 已退出 */ }
      handle = null
    }
    settleAll(new DriverDownError('插件已卸载'))
    state.phase = 'idle'
    state.pid = null
  }

  return {
    request,
    onMessage,
    status,
    release,
    dispose,
    get alive() { return Boolean(handle) },
    snapshot: () => ({ ...state }),
  }
}

async function exists(path) {
  try { await access(path); return true } catch { return false }
}
