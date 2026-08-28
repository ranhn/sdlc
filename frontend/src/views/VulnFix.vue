<template>
  <div class="vulnfix">
    <div class="page-header">
      <span class="page-title">漏洞修复</span>
    </div>

    <!-- 筛选 -->
    <el-card shadow="never" class="filter-card">
      <el-form inline>
        <el-form-item label="状态">
          <el-select v-model="filters.status" clearable placeholder="全部状态" style="width: 140px" @change="load">
            <el-option label="待确认" value="pending" />
            <el-option label="已确认" value="confirmed" />
            <el-option label="修复中" value="fixing" />
            <el-option label="待复测" value="retest" />
            <el-option label="已修复" value="fixed" />
            <el-option label="已关闭" value="closed" />
            <el-option label="已忽略" value="ignored" />
          </el-select>
        </el-form-item>
        <el-form-item label="等级">
          <el-select v-model="filters.severity" clearable placeholder="全部等级" style="width: 120px" @change="load">
            <el-option label="严重" value="critical" /><el-option label="高危" value="high" />
            <el-option label="中危" value="medium" /><el-option label="低危" value="low" />
          </el-select>
        </el-form-item>
        <el-form-item label="系统">
          <el-select v-model="filters.system_id" clearable filterable placeholder="全部系统" style="width: 160px" @change="load">
            <el-option v-for="s in systems" :key="s.id" :label="s.name" :value="s.id" />
          </el-select>
        </el-form-item>
      </el-form>
      <div class="tip">仅展示指派给您（修复人）的漏洞</div>
    </el-card>

    <!-- 列表 -->
    <el-table :data="list" v-loading="loading" stripe class="vuln-table" :show-overflow-tooltip="true">
      <el-table-column type="index" :index="(idx) => list.length - idx" width="48" align="center" />
      <el-table-column label="标题" min-width="260" show-overflow-tooltip>
        <template #default="{ row }">
          <el-link type="primary" :underline="false" @click="openDetail(row)">{{ row.title }}</el-link>
        </template>
      </el-table-column>
      <el-table-column prop="system_name" label="所属系统" min-width="100" align="center" />
      <el-table-column label="等级" width="70" align="center">
        <template #default="{ row }">
          <el-tag :type="severityType[row.severity]" effect="dark" size="small">{{ severityName[row.severity] }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="vuln_type" label="类型" min-width="90" align="center" />
      <el-table-column label="状态" width="80" align="center">
        <template #default="{ row }">
          <el-tag :type="statusType[row.status]" size="small">{{ statusNames[row.status] }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="reporter_name" label="提交人" min-width="110" align="center" show-overflow-tooltip>
        <template #default="{ row }">{{ row.reporter_name || '—' }}</template>
      </el-table-column>
      <el-table-column prop="created_at" label="提交时间" width="150" align="center">
        <template #default="{ row }">{{ fmt(row.created_at) }}</template>
      </el-table-column>
      <el-table-column label="操作" width="70" align="center" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" size="small" @click="openDetail(row)">详情</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 详情抽屉 -->
    <el-drawer v-model="detailVisible" size="620px" :title="`漏洞 #${current?.id} · ${current?.title}`">
      <template v-if="current">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="等级">
            <el-tag :type="severityType[current.severity]" effect="dark">{{ severityName[current.severity] }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="statusType[current.status]">{{ statusNames[current.status] }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="所属系统">{{ current.system_name || '—' }}</el-descriptions-item>
          <el-descriptions-item label="类型">{{ current.vuln_type || '—' }}</el-descriptions-item>
          <el-descriptions-item label="提交人">{{ current.reporter_name }}</el-descriptions-item>
          <el-descriptions-item label="负责人">{{ current.assignee_name || '未指派' }}</el-descriptions-item>
          <el-descriptions-item label="CVSS">{{ current.cvss || '—' }}</el-descriptions-item>
          <el-descriptions-item label="提交时间">{{ fmt(current.created_at) }}</el-descriptions-item>
        </el-descriptions>

        <div class="sec-title">漏洞描述</div>
        <el-text>{{ current.description || '无' }}</el-text>

        <div class="sec-title">复现步骤</div>
        <el-text><pre class="pre">{{ current.reproduce_steps || '无' }}</pre></el-text>

        <div class="sec-title">影响范围</div>
        <el-text>{{ current.impact || '无' }}</el-text>

        <div v-if="current.screenshots && current.screenshots.length" class="sec-title">截图证据</div>
        <el-image v-for="(img, i) in current.screenshots" :key="i" :src="img" :preview-src-list="current.screenshots"
          fit="cover" class="shot" />

        <!-- 状态操作 -->
        <div class="sec-title">修复操作</div>
        <div class="actions">
          <el-button v-if="can('start_fix')" type="warning" size="small" @click="doAction('start_fix')">开始修复</el-button>
          <el-button v-if="can('finish_fix')" type="success" size="small" @click="doAction('finish_fix')">修复完成</el-button>
          <el-button v-if="can('pass_retest')" type="success" size="small" @click="doAction('pass_retest')">复测通过</el-button>
          <el-button v-if="can('close')" type="primary" size="small" @click="doAction('close')">关闭</el-button>
        </div>

        <!-- 流程图 -->
        <div class="sec-title">状态流转</div>
        <el-steps :active="flowActive" simple class="flow-steps">
          <el-step title="提交" /><el-step title="确认" /><el-step title="修复" /><el-step title="复测" /><el-step title="关闭" />
        </el-steps>

        <!-- 评论 -->
        <div class="sec-title">评论</div>
        <div v-for="c in comments" :key="c.id" class="comment">
          <b>{{ c.username }}</b> · {{ fmt(c.created_at) }}
          <div>{{ c.content }}</div>
        </div>
        <div class="comment-input">
          <el-input v-model="newComment" placeholder="添加评论" @keyup.enter="addComment" />
          <el-button type="primary" @click="addComment">发送</el-button>
        </div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { vulnApi, systemApi } from '../api'
import { useUserStore } from '../store/user'

const store = useUserStore()
const list = ref([])
const systems = ref([])
const loading = ref(false)
const filters = reactive({ status: '', severity: '', system_id: null })

const statusNames = {
  draft: '草稿', pending: '待确认', confirmed: '已确认', fixing: '修复中', retest: '待复测',
  fixed: '已修复', closed: '已关闭', rejected: '已驳回', ignored: '已忽略',
}
const statusType = { draft: 'info', pending: 'warning', confirmed: 'primary', fixing: 'warning', retest: 'warning', fixed: 'success', closed: 'success', rejected: 'danger', ignored: 'info' }
const severityName = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
const severityType = { critical: 'danger', high: 'warning', medium: '', low: 'info' }
const actionRoles = {
  start_fix: ['admin', 'secops', 'dev'], finish_fix: ['admin', 'secops', 'dev', 'tester'],
  pass_retest: ['admin', 'secops', 'tester'], close: ['admin', 'secops'],
}
// 各动作允许的前置状态（与后端 state_machine.ACTION_RULES 保持一致）
const actionFrom = {
  start_fix: ['confirmed'],
  finish_fix: ['fixing'],
  pass_retest: ['retest'],
  close: ['fixed'],
}
const flowMap = { pending: 1, confirmed: 2, fixing: 3, retest: 4, fixed: 5, closed: 6 }

function can(action) {
  if (!current.value) return false
  if (!actionRoles[action]?.includes(store.role)) return false
  if (actionFrom[action] && !actionFrom[action].includes(current.value.status)) return false
  return true
}

// 详情
const detailVisible = ref(false)
const current = ref(null)
const comments = ref([])
const newComment = ref('')
const flowActive = computed(() => (current.value ? flowMap[current.value.status] || 0 : 0))

async function openDetail(row) {
  const res = await vulnApi.detail(row.id)
  current.value = res.data
  detailVisible.value = true
  loadComments(row.id)
}
async function loadComments(id) {
  const res = await vulnApi.comments(id)
  comments.value = res.data
}
async function addComment() {
  if (!newComment.value.trim()) return
  await vulnApi.addComment(current.value.id, { comment: newComment.value })
  newComment.value = ''
  loadComments(current.value.id)
}
function extractErrorMsg(e, fallback = '操作失败') {
  const data = e?.response?.data
  if (typeof data?.detail === 'string') return data.detail
  if (Array.isArray(data?.detail)) return data.detail.map(d => d.msg || JSON.stringify(d)).join('; ')
  if (typeof data === 'string') return data
  return fallback
}
async function doAction(action) {
  try {
    await vulnApi.action(current.value.id, action, { comment: '' })
    ElMessage.success('操作成功')
    openDetail(current.value)
    load()
  } catch (e) {
    ElMessage.error(extractErrorMsg(e))
  }
}

function fmt(d) { return d ? d.replace('T', ' ').slice(0, 16) : '' }

async function load() {
  loading.value = true
  try {
    const params = { assigned_to_me: true }
    if (filters.status) params.status = filters.status
    if (filters.severity) params.severity = filters.severity
    if (filters.system_id) params.system_id = filters.system_id
    const res = await vulnApi.list(params)
    list.value = res.data
  } finally { loading.value = false }
}

onMounted(async () => {
  load()
  try { systems.value = (await systemApi.list()).data } catch {}
})
</script>

<style scoped>
.vulnfix { height: 100%; display: flex; flex-direction: column; }
.vulnfix .page-header { flex-shrink: 0; }
.filter-card { margin-bottom: 12px; flex-shrink: 0; }
.filter-card :deep(.el-card__body) { padding: 12px; }
.tip { font-size: 12px; color: #94a3b8; }
.vuln-table { background: #fff; border-radius: 10px; }
.vuln-table :deep(.el-table__cell) { padding: 6px 0 !important; }
.vuln-table :deep(.el-table .cell) { padding-left: 8px; padding-right: 8px; word-break: keep-all; white-space: nowrap; }
.sec-title { font-weight: 600; margin: 16px 0 8px; color: #0f172a; }
.pre { white-space: pre-wrap; font-family: inherit; margin: 0; }
.shot { width: 90px; height: 90px; margin: 4px; border-radius: 6px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; }
.comment { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 8px 12px; margin-bottom: 8px; font-size: 13px; }
.comment-input { display: flex; gap: 8px; }
</style>
