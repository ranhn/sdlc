import { createRouter, createWebHistory } from 'vue-router'
import { useUserStore } from '../store/user'

const routes = [
  { path: '/login', name: 'login', component: () => import('../views/Login.vue'), meta: { public: true } },
  {
    path: '/',
    component: () => import('../layout/AppLayout.vue'),
    redirect: '/dashboard',
    children: [
      { path: 'dashboard', name: 'dashboard', component: () => import('../views/Dashboard.vue'), meta: { title: '整体概览', icon: 'Odometer' } },
      {
        path: 'vulnerabilities',
        meta: { title: '漏洞管理', icon: 'Warning' },
        children: [
          { path: '', redirect: 'submit' },
          { path: 'submit', name: 'vulnerabilities', component: () => import('../views/Vulnerabilities.vue'), meta: { title: '提交漏洞', admin: true } },
          { path: 'fix', name: 'vuln-fix', component: () => import('../views/VulnFix.vue'), meta: { title: '漏洞修复' } },
        ]
      },
      { path: 'systems', name: 'systems', component: () => import('../views/Systems.vue'), meta: { title: '系统资产', icon: 'Monitor' } },
      {
        path: 'scan',
        meta: { title: '漏洞扫描', icon: 'Aim' },
        children: [
          { path: '', redirect: 'components' },
          { path: 'components', name: 'scan-components', component: () => import('../views/Scan.vue'), meta: { title: '组件清单' } },
          { path: 'cves', name: 'scan-cves', component: () => import('../views/Scan.vue'), meta: { title: 'CVE 情报库' } },
          { path: 'tasks', name: 'scan-tasks', component: () => import('../views/Scan.vue'), meta: { title: '扫描任务' } },
          { path: 'results', name: 'scan-results', component: () => import('../views/Scan.vue'), meta: { title: '扫描结果' } },
        ]
      },
      { path: 'baseline', name: 'baseline', component: () => import('../views/Baseline.vue'), meta: { title: '安全基线', icon: 'Checked' } },
      {
        path: 'training',
        meta: { title: '安全培训', icon: 'Reading' },
        children: [
          { path: '', redirect: 'courses' },
          { path: 'courses', name: 'training-courses', component: () => import('../views/Training.vue'), meta: { title: '课程中心' } },
          { path: 'progress', name: 'training-progress', component: () => import('../views/Training.vue'), meta: { title: '我的进度' } },
          { path: 'exams', name: 'training-exams', component: () => import('../views/Training.vue'), meta: { title: '在线考试' } },
          { path: 'stats', name: 'training-stats', component: () => import('../views/Training.vue'), meta: { title: '培训统计' } },
          { path: 'questions', name: 'training-questions', component: () => import('../views/Training.vue'), meta: { title: '题库管理' } },
        ]
      },
      {
        path: 'security-mgmt',
        meta: { title: '安全管理', icon: 'Lock' },
        children: [
          { path: 'users', name: 'users', component: () => import('../views/Users.vue'), meta: { title: '人员管理' } },
          { path: 'audit', name: 'audit', component: () => import('../views/Audit.vue'), meta: { title: '审计日志' } },
        ]
      },
      {
        path: 'threat-modeling',
        meta: { title: 'AI 威胁建模', icon: 'Aim' },
        children: [
          { path: '', redirect: 'input' },
          { path: 'input', name: 'threat-input', component: () => import('../views/ThreatModeling.vue'), meta: { title: '建模输入' } },
          { path: 'analysis', name: 'threat-analysis', component: () => import('../views/ThreatModeling.vue'), meta: { title: '数据流图与威胁分析' } },
          { path: 'results', name: 'threat-results', component: () => import('../views/ThreatModeling.vue'), meta: { title: '建模结果' } },
        ]
      },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to) => {
  const store = useUserStore()
  if (!to.meta.public && !store.isLogin) {
    return { path: '/login', query: { redirect: to.fullPath } }
  }
  if (to.meta.admin && !['admin', 'secops'].includes(store.role)) {
    return { path: '/vulnerabilities/fix' }
  }
  return true
})

export default router
