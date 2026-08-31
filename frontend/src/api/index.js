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
    if (err.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      if (!location.pathname.includes('/login')) {
        location.href = '/login'
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
  login: (data) => {
    const body = new URLSearchParams()
    body.append('username', data.username)
    body.append('password', data.password)
    return http.post('/auth/login', body, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
  },
  changePassword: (data) => http.post('/auth/change-password', data),
}

// ---------- 人员/部门/角色 ----------
export const adminApi = {
  departments: () => http.get('/departments'),
  roles: () => http.get('/roles'),
  users: (params) => http.get('/users', { params }),
  createUser: (data) => http.post('/users', data),
  toggleUser: (id) => http.post(`/users/${id}/toggle`),
  deleteUser: (id) => http.delete(`/users/${id}`),
  changePassword: (id, data) => http.post(`/users/${id}/change-password`, data),
}

// ---------- 飞书同步 ----------
export const feishuApi = {
  config: () => http.get('/admin/feishu/config'),
  sync: () => http.post('/admin/feishu/sync'),
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
  categories: (baselineType) => http.get('/baseline/categories', { params: { baseline_type: baselineType || undefined } }),
  createCategory: (data) => http.post('/baseline/categories', data),
  items: (categoryId) => http.get('/baseline/items', { params: { category_id: categoryId || undefined } }),
  createItem: (data) => http.post('/baseline/items', data),
  removeItem: (id) => http.delete(`/baseline/items/${id}`),
  stats: (baselineType) => http.get('/baseline/stats', { params: { baseline_type: baselineType || undefined } }),
  systemItems: (systemId, baselineType) => http.get(`/baseline/systems/${systemId}/items`, { params: { baseline_type: baselineType || undefined } }),
  updateItem: (systemId, itemId, data) =>
    http.put(`/baseline/systems/${systemId}/items/${itemId}`, data),
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
