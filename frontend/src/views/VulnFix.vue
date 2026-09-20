<template>
  <div class="vulnfix">
    <div class="page-header">
      <span class="page-title">漏洞修复</span>
    </div>

    <!-- 筛选 -->
    <el-card shadow="never" class="filter-card">
      <el-form inline>
        <el-form-item label="状态">
          <el-select v-model="filters.status" clearable placeholder="全部状态" style="width: 140px" @change="load(true)">
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
          <el-select v-model="filters.severity" clearable placeholder="全部等级" style="width: 120px" @change="load(true)">
            <el-option label="严重" value="critical" /><el-option label="高危" value="high" />
            <el-option label="中危" value="medium" /><el-option label="低危" value="low" />
          </el-select>
        </el-form-item>
        <el-form-item label="系统">
          <el-select v-model="filters.system_id" clearable filterable placeholder="全部系统" style="width: 160px" @change="load(true)">
            <el-option v-for="s in systems" :key="s.id" :label="s.name" :value="s.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="来源">
          <el-select v-model="filters.is_external" clearable placeholder="全部来源" style="width: 130px" @change="load(true)">
            <el-option label="内部提交" :value="false" />
            <el-option label="外部报告" :value="true" />
          </el-select>
        </el-form-item>
      </el-form>
      <div class="tip">仅展示指派给您（修复人）的漏洞</div>
    </el-card>

    <!-- 列表（每页 12 条，分页见表格下方 .vuln-pager） -->
    <!-- border：Element Plus 的列宽拖拽必须开 border 才有拖拽手柄（与「提交漏洞」页一致） -->
    <el-table
      :data="pagedList"
      v-loading="loading"
      stripe
      border
      class="vuln-table tight-table"
      :show-overflow-tooltip="true"
      ref="tableRef"
      row-key="id"
    >
      <el-table-column type="index" :index="rowIndex" width="44" align="center" />
      <!-- 标题：与「提交漏洞」页同一口径 —— 权重给到最大（Element 按 min-width 比例
           分配富余宽度），其余列压到"够用就行"，配合 .cell 的窄内边距。 -->
      <el-table-column label="标题" min-width="320" show-overflow-tooltip>
        <template #default="{ row }">
          <el-link type="primary" :underline="false" @click="openDetail(row)">{{ row.title }}</el-link>
        </template>
      </el-table-column>
      <el-table-column prop="system_name" label="所属系统" min-width="92" align="center" />
      <el-table-column label="等级" width="64" align="center">
        <template #default="{ row }">
          <el-tag :type="severityType[row.severity]" effect="dark" size="small">{{ severityName[row.severity] }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="vuln_type" label="类型" min-width="96" align="center" />
      <el-table-column label="来源" width="64" align="center">
        <template #default="{ row }">
          <el-tag v-if="row.is_external" type="danger" size="small">外部</el-tag>
          <el-tag v-else type="info" size="small">内部</el-tag>
        </template>
      </el-table-column>
      <!-- 状态/提交人：2~3 个汉字 + 标签，按"不折行"的最小宽度给 -->
      <el-table-column label="状态" width="76" align="center">
        <template #default="{ row }">
          <el-tag :type="statusType[row.status]" size="small">{{ statusNames[row.status] }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="reporter_name" label="提交人" min-width="92" align="center" show-overflow-tooltip>
        <template #default="{ row }">{{ row.reporter_name || '—' }}</template>
      </el-table-column>
      <el-table-column prop="created_at" label="提交时间" width="138" align="center">
        <template #default="{ row }">{{ fmt(row.created_at) }}</template>
      </el-table-column>
      <el-table-column label="操作" width="68" align="center" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" size="small" @click="openDetail(row)">详情</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 分页：固定每页 12 条（列表全量已拉回，这里是纯前端切片） -->
    <div class="vuln-pager">
      <el-pagination
        v-model:current-page="page"
        :page-size="pageSize"
        :total="list.length"
        :pager-count="7"
        layout="total, prev, pager, next, jumper"
        background
        @current-change="onPageChange"
      />
    </div>

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
          <el-descriptions-item label="来源">
            <el-tag v-if="current.is_external" type="danger" size="small">外部</el-tag>
            <el-tag v-else type="info" size="small">内部</el-tag>
            <span v-if="current.is_external && current.external_source" class="ext-src"> · {{ current.external_source }}</span>
          </el-descriptions-item>
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
import { ref, reactive, computed, onMounted, nextTick } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { vulnApi, systemApi } from '../api'
import { useUserStore } from '../store/user'
import { fmtDateTime } from '../utils/time'

const store = useUserStore()
const route = useRoute()
const list = ref([])
const systems = ref([])
const loading = ref(false)
const filters = reactive({ status: '', severity: '', system_id: null, is_external: '' })

// ---- 分页：每页 12 条 ----
// 列表接口一次返回全量（筛选都作用在全量结果上），所以这里做的是**视图切片**：
// 只决定"这一屏显示哪 12 行"，不参与请求参数，也不改变任何筛选语义。
const page = ref(1)
const pageSize = ref(12)
const tableRef = ref()
const pagedList = computed(() => {
  const start = (page.value - 1) * pageSize.value
  return list.value.slice(start, start + pageSize.value)
})
const pageCount = computed(() => Math.max(1, Math.ceil(list.value.length / pageSize.value)))

/** 序号跨页连续：列表按提交时间倒序（最新在最上），序号 = 全量倒序位次 */
function rowIndex(idx) {
  return list.value.length - ((page.value - 1) * pageSize.value + idx)
}

/** 翻页后把列表顶部滚回视口（表格 auto height、整页滚动，不是内部滚动） */
function onPageChange() {
  nextTick(() => tableRef.value?.$el?.scrollIntoView?.({ block: 'start' }))
}

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

function fmt(d) { return fmtDateTime(d) }

/**
 * 拉取"指派给我"的漏洞列表。
 * @param {boolean} resetPage 过滤条件变化时传 true（回到第 1 页）。
 *   修复操作后不传，停在原页；列表变短时收敛到最后一个有效页，
 *   避免停在一个空白页（看起来像数据丢了）。
 */
async function load(resetPage = false) {
  loading.value = true
  try {
    const params = { assigned_to_me: true }
    if (filters.status) params.status = filters.status
    if (filters.severity) params.severity = filters.severity
    if (filters.system_id) params.system_id = filters.system_id
    if (filters.is_external !== null && filters.is_external !== undefined && filters.is_external !== '') {
      params.is_external = filters.is_external
    }
    const res = await vulnApi.list(params)
    list.value = res.data
    if (resetPage) page.value = 1
    else if (page.value > pageCount.value) page.value = pageCount.value
  } finally { loading.value = false }
}

onMounted(async () => {
  load()
  try { systems.value = (await systemApi.list()).data } catch {}
  // 兼容 CSV 导出/通知里的深链：/vulnerabilities/fix?id=123 直接打开该漏洞详情。
  // 与「提交漏洞」页同一套 ?id= 语义（管理员被守卫留在 /submit，开发落到这里），
  // 这样报告里那条链接对两种角色都"点开就是这条漏洞"。
  const qid = Number(route.query.id)
  if (qid && Number.isFinite(qid)) {
    try {
      await openDetail({ id: qid })
    } catch (e) {
      // 静默失败：可能权限不足（非本人负责的漏洞）或漏洞已删除
    }
  }
})
</script>

<style scoped>
.vulnfix { height: 100%; display: flex; flex-direction: column; }
.vulnfix .page-header { flex-shrink: 0; }
.filter-card { margin-bottom: 12px; flex-shrink: 0; }
.filter-card :deep(.el-card__body) { padding: 12px; }
.tip { font-size: 12px; color: #94a3b8; }
.vuln-table { background: #fff; border-radius: 10px; }
/* 分页条：贴着表格下方、右对齐（Element 默认居中，跟表格右缘对齐更像后台列表） */
.vuln-pager { display: flex; justify-content: flex-end; padding: 10px 4px 2px; flex-shrink: 0; }
/* 列间距/不换行由全局 .tight-table 提供（src/styles/main.css），不再本页各写一份 */
.sec-title { font-weight: 600; margin: 16px 0 8px; color: #0f172a; }
.pre { white-space: pre-wrap; font-family: inherit; margin: 0; }
.shot { width: 90px; height: 90px; margin: 4px; border-radius: 6px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; }
.comment { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 8px 12px; margin-bottom: 8px; font-size: 13px; }
.comment-input { display: flex; gap: 8px; }
</style>
