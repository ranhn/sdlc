<template>
  <el-container class="app-layout">
    <el-aside :width="isCollapse ? '64px' : '220px'" class="app-aside">
      <div class="logo" @click="$router.push('/dashboard')">
        <div class="logo-mark">V</div>
        <div v-if="!isCollapse" class="logo-text">
          <div class="logo-title">VeSync SDLC</div>
        </div>
      </div>
      <el-menu
        :default-active="$route.path"
        :collapse="isCollapse"
        :collapse-transition="false"
        router
        class="app-menu"
      >
        <template v-for="g in menus" :key="g.heading">
          <div v-if="!isCollapse" class="menu-heading">{{ g.heading }}</div>
          <template v-for="m in g.items" :key="m.path || m.title">
            <el-sub-menu v-if="m.children" :index="m.title">
              <template #title>
                <el-icon class="menu-icon"><component :is="m.icon" /></el-icon>
                <span>{{ m.title }}</span>
              </template>
              <el-menu-item v-for="sub in m.children" :key="sub.path" :index="sub.path">
                <template #title>{{ sub.title }}</template>
              </el-menu-item>
            </el-sub-menu>
            <el-menu-item v-else :index="m.path">
              <el-icon class="menu-icon"><component :is="m.icon" /></el-icon>
              <template #title>{{ m.title }}</template>
            </el-menu-item>
          </template>
        </template>
      </el-menu>
    </el-aside>

    <el-container class="app-main">
      <el-header class="app-header">
        <div class="header-left">
          <el-icon class="collapse-btn" @click="isCollapse = !isCollapse">
            <Expand v-if="isCollapse" /><Fold v-else />
          </el-icon>
          <el-breadcrumb separator="/">
            <el-breadcrumb-item :to="{ path: '/dashboard' }">首页</el-breadcrumb-item>
            <el-breadcrumb-item
              v-for="r in $route.matched.filter(r => r.meta?.title && r.path !== '/')"
              :key="r.path"
              :to="r.path !== $route.path ? { path: r.path } : undefined"
            >
              {{ r.meta.title }}
            </el-breadcrumb-item>
          </el-breadcrumb>
        </div>
        <div class="header-right">
          <el-dropdown @command="handleCommand">
            <span class="user-info">
              <el-avatar :size="30" class="avatar">{{ displayName.charAt(0) }}</el-avatar>
              <span class="username">{{ displayName }}</span>
              <el-icon><ArrowDown /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item disabled>{{ roleLabel }}</el-dropdown-item>
                <el-dropdown-item divided command="logout">退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>

      <el-main class="app-content">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useUserStore } from '../store/user'

const router = useRouter()
const store = useUserStore()
const isCollapse = ref(false)

const roleMap = {
  admin: '安全管理员',
  secops: '安全专家',
  reviewer: '安全审核员',
  developer: '开发人员',
  employee: '普通员工',
  user: '普通员工',
}

const menus = computed(() => {
  const isPrivileged = ['admin', 'secops'].includes(store.role)
  const secExpert = [
    { path: '/dashboard', title: '整体概览', icon: 'Odometer' },
    { path: '/systems', title: '系统资产', icon: 'Monitor' },
    { path: '/baseline', title: '安全基线', icon: 'Checked' },
  ]
  const secGovern = [
    {
      title: '漏洞管理',
      icon: 'Warning',
      children: [
        ...(isPrivileged ? [{ path: '/vulnerabilities/submit', title: '提交漏洞' }] : []),
        { path: '/vulnerabilities/fix', title: '漏洞修复' },
      ]
    },
    {
      title: '安全培训',
      icon: 'Reading',
      children: [
        { path: '/training/courses', title: '课程中心' },
        { path: '/training/progress', title: '我的进度' },
        { path: '/training/exams', title: '在线考试' },
        ...(isPrivileged ? [
          { path: '/training/stats', title: '培训统计' },
          { path: '/training/questions', title: '题库管理' },
        ] : []),
      ]
    },
    {
      title: '威胁建模',
      icon: 'Connection',
      children: [
        { path: '/threat-modeling/input', title: '建模输入' },
        { path: '/threat-modeling/analysis', title: '数据流图与威胁分析' },
        { path: '/threat-modeling/results', title: '建模结果' },
      ]
    },
  ]
  const scanMgmt = [
    {
      title: '漏洞扫描',
      icon: 'Aim',
      children: [
        { path: '/scan/components', title: '组件清单' },
        { path: '/scan/cves', title: 'CVE 情报库' },
        { path: '/scan/tasks', title: '扫描任务' },
        { path: '/scan/results', title: '扫描结果' },
      ]
    },
  ]
  const sysMgmt = []
  if (isPrivileged) {
    sysMgmt.push({
      title: '安全管理',
      icon: 'Lock',
      children: [
        { path: '/security-mgmt/users', title: '人员管理' },
        { path: '/security-mgmt/audit', title: '审计日志' },
      ]
    })
  }
  return [
    { heading: '安全概览', items: secExpert },
    { heading: '安全治理', items: secGovern },
    { heading: '扫描管理', items: scanMgmt },
    { heading: '系统管理', items: sysMgmt },
  ].filter(g => g.items.length > 0)
})

const displayName = computed(() => store.displayName || '用户')
const roleLabel = computed(() => roleMap[store.role] || store.role)

function handleCommand(cmd) {
  if (cmd === 'logout') {
    store.logout()
    ElMessage.success('已退出登录')
    router.push('/login')
  }
}
</script>

<style scoped>
.app-layout { height: 100vh; }
.app-aside { background: #0f172a; transition: width 0.2s; overflow-x: hidden; }
.logo { display: flex; align-items: center; gap: 10px; height: 60px; padding: 0 16px; color: #fff; cursor: pointer; }
.logo-mark { width: 34px; height: 34px; border-radius: 8px; background: linear-gradient(135deg,#3b82f6,#8b5cf6); display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 18px; color: #fff; flex-shrink: 0; }
.logo-text { display: flex; align-items: center; }
.logo-title { font-size: 15px; font-weight: 700; line-height: 1.2; white-space: nowrap; }
.app-menu { border-right: none; background: transparent; }
.app-menu :deep(.el-sub-menu .el-menu .el-menu-item) { padding-left: 48px !important; }
.menu-heading { padding: 16px 20px 6px; font-size: 12px; color: #64748b; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase; }
.menu-icon { margin-right: 10px; font-size: 18px; }
.app-menu :deep(.el-menu-item) { color: #cbd5e1; }
.app-menu :deep(.el-menu-item.is-active) { background: rgba(59,130,246,0.15); color: #fff; }
.app-menu :deep(.el-menu-item:hover) { background: rgba(255,255,255,0.06); color: #fff; }
.app-menu :deep(.el-sub-menu__title) { color: #cbd5e1; }
.app-menu :deep(.el-sub-menu__title:hover) { background: rgba(255,255,255,0.06); color: #fff; }
.app-menu :deep(.el-sub-menu.is-active > .el-sub-menu__title) { color: #fff; }
.app-main { background: #f1f5f9; }
.app-header { background: #fff; border-bottom: 1px solid #e2e8f0; display: flex; align-items: center; justify-content: space-between; height: 52px; padding: 0 20px; }
.header-left { display: flex; align-items: center; gap: 16px; }
.collapse-btn { font-size: 20px; cursor: pointer; color: #475569; }
.header-right .user-info { display: flex; align-items: center; gap: 8px; cursor: pointer; color: #334155; }
.avatar { background: #3b82f6; color: #fff; font-weight: 600; }
.username { font-size: 14px; }
.app-content { padding: 12px; overflow-y: auto; }
</style>
