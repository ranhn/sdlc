// 统一 axios 封装：自动附带 JWT，401 时跳登录
import axios from 'axios'

const http = axios.create({
  baseURL: '/api',
  timeout: 20000,
})

http.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

http.interceptors.response.use(
  (res) => res,
  (err) => {
    // 401: 清除 token + 跳登录
    if (err.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      if (!location.pathname.includes('/login')) {
        location.href = '/login'
      }
    }
    // 把后端的 detail 冒到 message, 避免 UI 只看到
    // "Request failed with status code 4xx" 不知根因。
    // - 字符串 detail (业务 HTTPException) → 直接拼
    // - 数组 detail (Pydantic 校验错误) → 拼 "loc: msg"
    const status = err.response?.status
    const d = err.response?.data?.detail
    if (status && d !== undefined) {
      if (typeof d === 'string') {
        err.message = `${status} ${d}`
      } else if (Array.isArray(d)) {
        err.message = `${status} ` + d
          .map((e) => {
            const loc = Array.isArray(e?.loc) ? e.loc.join('.') : ''
            return `${loc}: ${e?.msg || ''}`
          })
          .filter(Boolean)
          .join('; ')
      } else {
        err.message = `${status} ${JSON.stringify(d)}`
      }
    }
    return Promise.reject(err)
  },
)

export default http
export { http }

// ---------- 认证 ----------
export const authApi = {
  // 后端使用 OAuth2PasswordRequestForm，需提交 form-urlencoded
  login: async (data) => {
    const body = new URLSearchParams()
    body.append('username', data.username)
    body.append('password', data.password)
    const { data: res } = await http.post('/auth/login', body, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    return res
  },
  changePassword: async (data) => {
    const { data: res } = await http.post('/auth/change-password', data)
    return res
  },
}

// ---------- 人员/部门/角色 ----------
export const adminApi = {
  departments: () => http.get('/departments'),
  roles: () => http.get('/roles'),
  users: (params) => http.get('/users', { params }),
  // 人员下拉专用：只返回 id/用户名/姓名（全量 1600+ 人的 UserOut 约 580KB，
  // 下拉只需要其中三个字段；见后端 /api/users/pick 说明）
  userPicks: (params) => http.get('/users/pick', { params }),
  createUser: (data) => http.post('/users', data),
  // 编辑用户（姓名/邮箱/角色/部门）—— 只传要改的字段，没传的后端保持原样
  updateUser: (id, data) => http.put(`/users/${id}`, data),
  toggleUser: (id) => http.post(`/users/${id}/toggle`),
  deleteUser: (id) => http.delete(`/users/${id}`),
  changePassword: (id, data) => http.post(`/users/${id}/change-password`, data),
  // 一键重置为**初始口令**：后端会同步把「账号 + 初始密码」私信发给本人，
  // 响应里回报是否发出（notified/error/password），前端据此提示管理员。
  resetPassword: (id) => http.post(`/users/${id}/reset-password`),
}

// ---------- 飞书同步 ----------
export const feishuApi = {
  config: () => http.get('/admin/feishu/config'),
  // 同步要遍历 400+ 个部门、拉 1600+ 人，实测约 45s，远超全局 20s 超时 ——
  // 必须单独放宽，否则接口还在跑、前端已经报 "timeout of 20000ms exceeded"，
  // 用户以为同步失败（其实服务端已经同步完了），会重复点击。
  sync: () => http.post('/admin/feishu/sync', null, { timeout: 300000 }),
}

// ---------- 系统资产 ----------
export const systemApi = {
  list: () => http.get('/systems'),
  create: (data) => http.post('/systems', data),
  update: (id, data) => http.put(`/systems/${id}`, data),
  del: (id, force = false) => http.delete(`/systems/${id}`, { params: force ? { force: true } : {} }),
}

// ---------- 漏洞管理 ----------
export const vulnApi = {
  list: (params) => http.get('/vulns', { params }),
  detail: (id) => http.get(`/vulns/${id}`),
  create: (data) => http.post('/vulns', data),
  update: (id, data) => http.patch(`/vulns/${id}`, data),
  assign: (id, data) => http.post(`/vulns/${id}/assign`, data),
  action: (id, action, data) => http.post(`/vulns/${id}/action/${action}`, data || {}),
  reject: (id, data) => http.post(`/vulns/${id}/reject`, data),
  flows: (id) => http.get(`/vulns/${id}/flows`),
  comments: (id) => http.get(`/vulns/${id}/comments`),
  addComment: (id, data) => http.post(`/vulns/${id}/comments`, data),
  remove: (id) => http.delete(`/vulns/${id}`),
  export: (fmt, params) => http.get(`/vulns/export`, { params: { fmt, ...params }, responseType: 'blob' }),
}

// ---------- 工作台 ----------
export const dashboardApi = {
  overview: () => http.get('/dashboard/overview'),
  trend: (params) => http.get('/dashboard/trend', { params }),
  distribution: () => http.get('/dashboard/distribution'),
  top: () => http.get('/dashboard/top'),
}

// ---------- 漏洞扫描 ----------
export const scanApi = {
  components: () => http.get('/scan/components'),
  addComponent: (data) => http.post('/scan/components', data),
  removeComponent: (id) => http.delete(`/scan/components/${id}`),
  cves: (params) => http.get('/scan/cves', { params }),
  addCve: (data) => http.post('/scan/cves', data),
  removeCve: (id) => http.delete(`/scan/cves/${id}`),
  runScan: (systemId) => http.post(`/scan/systems/${systemId}/scan`),
  tasks: () => http.get('/scan/tasks'),
  taskResults: (taskId) => http.get(`/scan/tasks/${taskId}/results`),
}

// ---------- 安全基线 ----------
export const baselineApi = {
  // 基线类型目录（5 个类型的 key/label + 各自条目数）。唯一的类型清单来源：
  // 前端不再自己维护 typeNameMap，避免"后端加了类型、前端看不见"。
  types: () => http.get('/baseline/types'),
  categories: (baselineType) => http.get('/baseline/categories', { params: { baseline_type: baselineType || undefined } }),
  createCategory: (data) => http.post('/baseline/categories', data),
  // 检查项清单：params 可带 { category_id } 或 { baseline_type }（模板库抽屉按类型一次取全）
  items: (params) => http.get('/baseline/items', { params }),
  createItem: (data) => http.post('/baseline/items', data),
  removeItem: (id) => http.delete(`/baseline/items/${id}`),
  // 老口径统计（分母 = 系统数 × 全部条目数）。保留兼容，新页面请用 overview()。
  stats: (baselineType) => http.get('/baseline/stats', { params: { baseline_type: baselineType || undefined } }),
  systemItems: (systemId, baselineType) => http.get(`/baseline/systems/${systemId}/items`, { params: { baseline_type: baselineType || undefined } }),
  updateItem: (systemId, itemId, data) =>
    http.put(`/baseline/systems/${systemId}/items/${itemId}`, data),

  // ---------- 需求（某系统绑定哪几个基线）----------
  // 概览：按 (系统, 条目) 去重、按绑定范围算的合规率/进度（新口径）
  overview: () => http.get('/baseline/requirements/overview'),
  requirements: (params) => http.get('/baseline/requirements', { params }),
  createRequirement: (data) => http.post('/baseline/requirements', data),
  updateRequirement: (id, data) => http.put(`/baseline/requirements/${id}`, data),
  removeRequirement: (id) => http.delete(`/baseline/requirements/${id}`),
  // 需求详情：只返回**绑定范围内**的条目 + 已有结论（可按单个基线过滤）
  requirementItems: (id, baselineType) =>
    http.get(`/baseline/requirements/${id}/items`, { params: { baseline_type: baselineType || undefined } }),
  // 需求范围内的评估（负责人可自评；后端会校验条目确实在绑定范围内）
  updateRequirementItem: (id, itemId, data) =>
    http.put(`/baseline/requirements/${id}/items/${itemId}`, data),
}

// ---------- 安全培训 ----------
export const trainingApi = {
  courses: (params) => http.get('/training/courses', { params }),
  coursesAll: () => http.get('/training/courses/all'),
  createCourse: (data) => http.post('/training/courses', data),
  updateCourse: (id, data) => http.put(`/training/courses/${id}`, data),
  removeCourse: (id) => http.delete(`/training/courses/${id}`),
  // 不要显式设 Content-Type, 让 axios 自动加 boundary
  uploadFile: (formData) => http.post('/training/upload', formData),
  startCourse: (id) => http.post(`/training/courses/${id}/start`),
  completeCourse: (id) => http.post(`/training/courses/${id}/complete`),
  progress: () => http.get('/training/progress'),
  stats: () => http.get('/training/stats'),
  questions: () => http.get('/training/questions'),
  createQuestion: (data) => http.post('/training/questions', data),
  removeQuestion: (id) => http.delete(`/training/questions/${id}`),
  createExam: (params) => http.post('/training/exams', null, { params }),
  examQuestions: (id) => http.get(`/training/exams/${id}/questions`),
  submitExam: (id, answers) => http.post(`/training/exams/${id}/submit`, answers),
  myExams: () => http.get('/training/exams/mine'),
  allExams: () => http.get('/training/exams/all'),
  courseStats: () => http.get('/training/course-stats'),
}

// ---------- 威胁建模 ----------
// 威胁建模子应用挂载在 /threat 前缀下，使用独立 baseURL
const threatHttp = axios.create({
  baseURL: '/threat/api',
  timeout: 15000,
})

export const threatApi = {
  health: () => threatHttp.get('/health'),
  analyze: (data) => threatHttp.post('/analyze', data),
  templates: () => threatHttp.get('/templates'),
  tasks: () => threatHttp.get('/tasks'),
  taskDetail: (id) => threatHttp.get(`/tasks/${id}`),
  results: () => threatHttp.get('/results'),
  resultDetail: (id) => threatHttp.get(`/results/${id}`),
}
