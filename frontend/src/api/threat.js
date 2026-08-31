/**
 * 威胁建模 API 封装
 *
 * 统一封装 AI 威胁建模子应用的所有接口。
 * 后端子应用挂载在 /threat 前缀（见 backend/main.py 的 app.mount），
 * 因此这里 baseURL = '/threat/api'。
 *
 * 涵盖功能：
 *  - 健康检查 / 系统提示词查看
 *  - 模板列表 / 文档上传（PDF/DOCX 内嵌图片抽取）
 *  - 异步分析任务提交 / 进度查询 / 取消
 *  - 历史结果 CRUD / 重命名 / 删除 / 导出
 *  - 单条威胁处置状态更新
 *  - 输入指纹计算（用于结果缓存一致性展示）
 */
import axios from 'axios'

// 可选：从 localStorage 读取 API Token（用于后端开启了 API_TOKEN 鉴权的场景）
const API_TOKEN_KEY = 'aitd.api.token'
const apiToken = localStorage.getItem(API_TOKEN_KEY)

// SDLC 平台登录后的 JWT 存于 localStorage.token；威胁建模子应用复用其身份
// 以实现「按角色查看 / 删除建模结果」的权限控制（见 backend/threat/app/core/auth.py）
const SDLC_TOKEN_KEY = 'token'

export const http = axios.create({
  baseURL: '/threat/api',
  // AI 分析采用异步任务：提交立即返回，轮询用较短的超时
  timeout: 15000,
  headers: apiToken ? { 'X-API-Key': apiToken } : {},
})

// 请求拦截器：每次请求自动附带 SDLC JWT，后端据此识别当前用户与角色
http.interceptors.request.use((config) => {
  const sdlcToken = localStorage.getItem(SDLC_TOKEN_KEY)
  if (sdlcToken) {
    config.headers = config.headers || {}
    config.headers.Authorization = `Bearer ${sdlcToken}`
  }
  return config
})

/** 设置/清除 API Token 请求头（供设置界面调用） */
export function setApiToken(t) {
  if (t) {
    localStorage.setItem(API_TOKEN_KEY, t)
    http.defaults.headers.common['X-API-Key'] = t
  } else {
    localStorage.removeItem(API_TOKEN_KEY)
    delete http.defaults.headers.common['X-API-Key']
  }
}

/** 健康检查 */
export async function checkHealth() {
  const { data } = await http.get('/health')
  return data
}

/**
 * 计算输入指纹：对需求/架构/方法论做 SHA-256 摘要。
 * 相同输入 => 相同指纹；用于展示"本次与上次是否同一份输入"，
 * 便于理解后端响应缓存带来的结果一致性。
 *
 * 注意：图片可能非常大（base64 字符串达数 MB），因此这里只对图片做
 * 轻量签名（长度 + 首尾各一段抽样）参与哈希，而不是整个 base64；
 * 并且使用分块 + 每块让出事件循环，避免长字符串同步哈希导致页面卡死。
 * @param {{requirements?: string, architecture?: string, images?: string[], methodology?: string}} payload
 * @returns {Promise<string>} 64 位十六进制摘要
 */
export async function computeInputFingerprint(payload) {
  // 让出一次事件循环，避免在同步调用栈里开启大字符串处理
  await _yield()

  // 图片只取签名参与哈希，绝不对完整 base64 做 JSON.stringify / encode
  const imageSig = (Array.isArray(payload?.images) ? payload.images : [])
    .map((im) => {
      if (typeof im !== 'string') return ''
      // 取长度 + 头尾各 512 字符，作为图片内容指纹的轻量代表
      const head = im.slice(0, 512)
      const tail = im.length > 1024 ? im.slice(im.length - 512) : ''
      return `${im.length}:${head}:${tail}`
    })

  const text = JSON.stringify({
    t: payload?.title ?? '',
    r: payload?.requirements ?? '',
    a: payload?.architecture ?? '',
    im: imageSig,
    m: payload?.methodology ?? '',
  })

  // 优先使用 Web Crypto 的 SHA-256（分块，避免一次性生成超大 ArrayBuffer）
  try {
    if (crypto?.subtle?.digest) {
      const encoder = new TextEncoder()
      const data = encoder.encode(text)
      // 超大输入拆块逐个哈希，每块后让出事件循环
      if (data.byteLength > 1_000_000) {
        let state = new Uint8Array(32) // 占位，实际用滚动哈希简化
        const chunkSize = 512 * 1024
        let h = null
        for (let i = 0; i < data.byteLength; i += chunkSize) {
          await _yield()
          const part = data.slice(i, i + chunkSize)
          const digest = await crypto.subtle.digest('SHA-256', part)
          state = new Uint8Array(digest)
          h = h ? _xor(h, state) : state
        }
        state = h || state
        return [...state].map((b) => b.toString(16).padStart(2, '0')).join('')
      }
      const buf = await crypto.subtle.digest('SHA-256', data)
      return [...new Uint8Array(buf)]
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
    }
  } catch (e) {
    // 降级：分块 FNV-1a 哈希（仅用于展示，不影响后端缓存正确性）
  }
  // 降级 FNV-1a：分块处理，避免长字符串同步循环卡死
  let h1 = 0x811c9dc5
  const block = 1 << 20
  for (let i = 0; i < text.length; i += block) {
    const end = Math.min(i + block, text.length)
    for (let j = i; j < end; j++) {
      h1 ^= text.charCodeAt(j)
      h1 = Math.imul(h1, 0x01000193)
    }
    await _yield()
  }
  return (h1 >>> 0).toString(16).padStart(8, '0')
}

function _xor(a, b) {
  const out = new Uint8Array(a.length)
  for (let i = 0; i < out.length; i++) out[i] = a[i] ^ b[i]
  return out
}

function _yield() {
  return new Promise((resolve) => {
    if (typeof requestIdleCallback === 'function') {
      requestIdleCallback(resolve)
    } else {
      setTimeout(resolve, 0)
    }
  })
}

/**
 * 获取某方法论下的真实系统提示词（后端 ThreatAnalyzer 动态生成）。
 * 用于"系统提示词"按钮调试/查看。
 * @param {{methodology?: string, industry?: string}} opts
 * @returns {Promise<{methodology: string, system_prompt: string, length: number}>}
 */
export async function getSystemPrompt(opts = {}) {
  const params = {}
  if (opts.methodology) params.methodology = opts.methodology
  if (opts.industry) params.industry = opts.industry
  const { data } = await http.get('/system-prompt', { params })
  return data
}

/**
 * 导出结果为文件，触发浏览器下载（md | json | csv）。
 * @param {string} resultId 结果 ID
 * @param {'json'|'md'|'csv'} format 导出格式
 * @param {string} [filename] 下载文件名（默认按 resultId+format 命名）
 */
export async function downloadResult(resultId, format = 'json', filename) {
  const { data, headers } = await http.get(`/results/${resultId}/export`, {
    params: { format },
    responseType: 'blob',
  })
  // 优先使用后端返回的 Content-Disposition 文件名
  const cd = headers?.['content-disposition'] || ''
  const match = cd.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/)
  const serverFilename = match ? decodeURIComponent(match[1].replace(/['"]/g, '')) : null

  const blob = new Blob([data], { type: _mime(format) })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename || serverFilename || `threat-model_${resultId}.${format === 'md' ? 'md' : format}`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function _mime(format) {
  switch ((format || '').toLowerCase()) {
    case 'json':
      return 'application/json;charset=utf-8'
    case 'csv':
      return 'text/csv;charset=utf-8'
    case 'docx':
      return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    case 'md':
    default:
      return 'text/markdown;charset=utf-8'
  }
}

/**
 * 提交 AI 威胁建模分析任务（异步，立即返回 task_id）
 * @param {{requirements: string, architecture?: string, images?: string[], attachments?: string[], llm?: {base_url?: string, api_key?: string, model?: string}}} payload
 * @returns {Promise<{task_id: string, status: string, steps: string[]}>}
 */
export async function analyze(payload) {
  const { data } = await http.post('/analyze', payload)
  return data
}

/**
 * 查询异步任务进度与结果
 * @param {string} taskId
 * @returns {Promise<{id: string, status: string, progress: number, steps: string[], step_index: number, log: {time: number, message: string}[], result?: object, error?: string, status_code?: number}>}
 */
export async function getTask(taskId) {
  const { data } = await http.get(`/tasks/${taskId}`)
  return data
}

/**
 * 获取历史建模结果列表（支持分页 / 筛选 / 搜索）
 * @param {{page?: number, pageSize?: number, methodology?: string, keyword?: string}} [params]
 * @returns {Promise<{items: {id: string, title: string, methodology: string, created_at: number, stats: object}[], total: number, page: number, page_size: number, pages: number}>}
 */
export async function listResults(params = {}) {
  const { data } = await http.get('/results', { params })
  return data
}

/**
 * 获取单个建模结果完整详情
 * @param {string} resultId
 * @returns {Promise<{id: string, title: string, methodology: string, created_at: number, model: object, summary: string, stats: object}>}
 */
export async function getResultDetail(resultId) {
  const { data } = await http.get(`/results/${resultId}`)
  return data
}

/**
 * 删除一条历史建模结果
 * @param {string} resultId
 */
export async function deleteResult(resultId) {
  const { data } = await http.delete(`/results/${resultId}`)
  return data
}

/**
 * 重命名一条历史建模结果标题
 * @param {string} resultId
 * @param {string} title
 * @returns {Promise<{renamed: boolean, id: string, title: string}>}
 */
export async function renameResult(resultId, title) {
  const { data } = await http.patch(`/results/${resultId}`, { title })
  return data
}

/**
 * 导出建模结果（返回文档字符串；格式 md | json | csv）
 * @param {string} resultId
 * @param {'md'|'json'|'csv'} [format]
 * @returns {Promise<{data: string, headers: object}>}
 */
export async function exportResult(resultId, format = 'md') {
  const { data, headers } = await http.get(`/results/${resultId}/export`, {
    params: { format },
    responseType: 'text',
  })
  return { data, headers }
}

/**
 * 更新指定结果中某条威胁的处置状态（Open → Mitigated 等）或范围外标记
 * @param {string} resultId
 * @param {string} threatId
 * @param {string} [status]
 * @param {{ outOfScope?: boolean }} [opts]
 */
export async function updateThreatStatus(resultId, threatId, status, opts = {}) {
  const payload = {}
  if (status !== undefined && status !== null) payload.status = status
  if (typeof opts.outOfScope === 'boolean') payload.outOfScope = opts.outOfScope
  const { data } = await http.patch(`/results/${resultId}/threats/${threatId}`, payload)
  return data
}

/**
 * 取消一个进行中的分析任务
 * @param {string} taskId
 */
export async function cancelTask(taskId) {
  const { data } = await http.post(`/tasks/${taskId}/cancel`)
  return data
}

/**
 * 获取示例场景模板库
 * @returns {Promise<{items: {id: string, name: string, description: string, methodology: string, requirements: string, architecture: string, tags: string[]}[]}>}
 */
export async function listTemplates() {
  const { data } = await http.get('/templates')
  return data
}

/**
 * 上传文档（支持 .txt/.md/.pdf/.docx）。
 * 后端把原始文档保存为附件，并从 PDF/DOCX 中抽取内嵌图片（架构图/数据流图等）
 * 为 data URI，随建模请求以多模态方式交给 AI 分析。
 * @param {File} file 文件对象
 * @returns {Promise<{attachment_id: string, filename: string, filetype: string, chars: number, image_count: number, extracted: string, images: string[]}>}
 */
export async function uploadDocument(file) {
  const fd = new FormData()
  fd.append('file', file)
  return await http.post('/upload', fd, {
    timeout: 60000, // 大文档解析可能较慢
    headers: { 'Content-Type': 'multipart/form-data' },
  })
}
