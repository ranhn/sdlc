/**
 * 统一的中文映射工具，集中维护威胁建模相关的术语翻译。
 * 这样历史数据（severity/status/type/methodology 等英文键）也能立即展示中文。
 */

// 严重度：保留英文键以便按颜色样式类绑定（sev-Critical 等）
export const SEVERITY_MAP = {
  Critical: '严重',
  High: '高危',
  Medium: '中危',
  Low: '低危',
  Unknown: '未知',
  TBD: '待定',
  'N/A': '不适用',
}

// 状态机：仅展示时翻译
export const STATUS_MAP = {
  Open: '待处理',
  Mitigated: '已缓解',
  NotApplicable: '不适用',
  'Not Applicable': '不适用',
}

// 威胁类型：六种方法论统一中文标签
// 为保证 Threat Dragon 模型兼容英文键（methodology.py / model_builder.py 都依赖它），
// 这里只做"展示侧翻译"，后端存储仍保留英文。
export const THREAT_TYPE_MAP = {
  // STRIDE
  Spoofing: '伪装',
  Tampering: '篡改',
  Repudiation: '抵赖',
  'Information Disclosure': '信息泄露',
  'Denial of Service': '拒绝服务',
  'Elevation of Privilege': '权限提升',
  // CIA
  Confidentiality: '机密性',
  Integrity: '完整性',
  Availability: '可用性',
  // CIADIE 扩展
  Distributed: '分布式',
  Immutable: '不可篡改',
  Ephemeral: '临时性',
  // LINDDUN
  Linkability: '可关联',
  Identifiability: '可识别',
  'Non-Repudiation': '不可抵赖',
  Detectability: '可探测',
  'Disclosure of Information': '信息披露',
  Unawareness: '无感知',
  'Non-Compliance': '不合规',
  // PLOT4ai
  'Technique & Processes': '技术流程',
  Accessibility: '可访问性',
  'Identifiability & Linkability': '可识别与可关联',
  Security: '安全性',
  Safety: '安全（人身）',
  'Ethics & Human Rights': '伦理与人权',
  // EOP
  Authentication: '身份认证',
  Authorization: '授权',
  Cryptography: '密码学',
  'Data Validation & Encoding': '数据校验与编码',
  'Session Management': '会话管理',
}

// 方法论：顶层标签（用于 build 页 "采用 XX 方法论" 等场景）
export const METHODOLOGY_MAP = {
  STRIDE: 'STRIDE（通用威胁分类）',
  'STRIDE-AI': 'STRIDE-AI（大模型/Agent/RAG AI 威胁）',
  CIA: 'CIA（机密性/完整性/可用性）',
  CIADIE: 'CIADIE（CIA + 分布式/不可篡改/临时性）',
  LINDDUN: 'LINDDUN（隐私威胁）',
  PLOT4ai: 'PLOT4ai（AI 系统威胁）',
  EOP: 'EOP（OWASP 顶级 Web 威胁）',
}

export function tSeverity(s) {
  if (!s) return SEVERITY_MAP.Unknown
  return SEVERITY_MAP[s] ?? s
}

export function tStatus(s) {
  if (!s) return STATUS_MAP.Open
  return STATUS_MAP[s] ?? s
}

export function tType(t) {
  if (!t) return '未分类'
  return THREAT_TYPE_MAP[t] ?? t
}

export function tMethodology(m) {
  if (!m) return 'STRIDE'
  return METHODOLOGY_MAP[m] ?? m
}

// 严重度排序键：保持原有 "Critical > High > Medium > Low" 顺序
export const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low']
