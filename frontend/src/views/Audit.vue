<template>
  <div class="audit">
    <div class="page-header">
      <span class="page-title">审计日志</span>
      <el-form inline>
        <el-form-item label="操作人">
          <el-input v-model="filters.operator" placeholder="姓名/用户名" clearable style="width: 160px" @keyup.enter="load" />
        </el-form-item>
        <el-form-item label="操作类型">
          <el-input v-model="filters.action" placeholder="如 create_vuln" clearable style="width: 160px" @keyup.enter="load" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="load">查询</el-button>
          <el-button @click="resetFilters">重置</el-button>
        </el-form-item>
      </el-form>
    </div>

    <el-card shadow="never">
      <div class="audit-summary">
        <span class="audit-total">共 {{ total }} 条记录</span>
        <span class="audit-legend">
          操作人列格式：<b>用户名</b> · <span class="audit-name">中文姓名</span>（用户删除后仅显示用户名）
        </span>
      </div>
      <el-table :data="list" v-loading="loading" stripe row-key="id">
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column label="操作人" width="180">
          <template #default="{ row }">
            <div class="audit-operator">
              <span class="audit-username">{{ row.username || '-' }}</span>
              <span v-if="row.full_name" class="audit-fullname">· {{ row.full_name }}</span>
              <span v-else class="audit-fullname audit-fullname-empty">（已删除）</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="action" label="操作" width="170">
          <template #default="{ row }">
            <el-tag size="small" :type="actionTagType(row.action)" effect="light">
              {{ row.action }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="module" label="模块" width="100">
          <template #default="{ row }">
            <el-tag v-if="row.module" size="small" effect="plain">{{ row.module }}</el-tag>
            <span v-else class="audit-faint">-</span>
          </template>
        </el-table-column>
        <el-table-column label="详情" min-width="360" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="audit-detail" v-html="renderDetail(row.detail)"></span>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="时间" width="170">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
      </el-table>
      <el-pagination
        v-model:current-page="filters.page"
        :page-size="filters.page_size"
        :total="total"
        layout="total, prev, pager, next"
        background
        class="pager"
        @current-change="load"
      />
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onBeforeUnmount } from 'vue'
import { useRouter } from 'vue-router'
import { http } from '../api'

const router = useRouter()
const list = ref([])
const total = ref(0)
const loading = ref(false)
const filters = reactive({ operator: '', action: '', page: 1, page_size: 20 })

function fmt(d) { return d ? String(d).replace('T', ' ').slice(0, 19) : '' }

/** 转义后保留换行；防止 detail 里的 < > 被 XSS 误解析。 */
function escapeHtml(s) {
  if (s == null) return ''
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** 把「漏洞 #N」「附件 #N」之类的标识渲染为可点击的链接。
 *  - 漏洞 #N  → 跳转 /vulns -> 详情抽屉
 *  - 仅做普通文本高亮，不引入额外外部链接
 */
function renderDetail(detail) {
  const safe = escapeHtml(detail)
  if (!safe) return '<span class="audit-faint">-</span>'
  return safe
    // 指派/提交/删除/驳回 等含「漏洞 #N」
    .replace(
      /(漏洞\s*#\s*(\d+))/g,
      (_m, full, id) =>
        `<a class="audit-link" href="javascript:void(0)" data-vuln-id="${id}">${full}</a>`,
    )
}

/** 渲染后给整列绑定 click，事件委托到具体的漏洞 id 链接上。 */
function onDetailClick(e) {
  const t = e.target
  if (t && t.classList && t.classList.contains('audit-link') && t.dataset.vulnId) {
    router.push({ path: '/vulns', query: { id: t.dataset.vulnId } })
  }
}

/** 动作类型 → Element-Plus tag 颜色；按业务经验粗分 */
function actionTagType(action) {
  if (!action) return 'info'
  if (action.startsWith('create_') || action.includes('assign')) return 'success'
  if (action.startsWith('delete_')) return 'danger'
  if (action.startsWith('vuln_reject') || action.includes('reject')) return 'warning'
  if (action.startsWith('vuln_')) return 'primary'
  if (action.includes('scan') || action.includes('import')) return 'info'
  return ''
}

async function load() {
  loading.value = true
  try {
    const params = { page: filters.page, page_size: filters.page_size }
    if (filters.operator) params.operator = filters.operator
    if (filters.action) params.action = filters.action
    const res = await http.get('/logs', { params })
    list.value = res.data.items || res.data.logs || []
    total.value = res.data.total || 0
  } finally {
    loading.value = false
  }
}

function resetFilters() {
  filters.operator = ''
  filters.action = ''
  filters.page = 1
  load()
}

onMounted(() => {
  load()
  // 详情列事件委托：捕获审计详情里的「漏洞 #N」链接点击
  document.addEventListener('click', onDetailClick)
})

onBeforeUnmount(() => {
  document.removeEventListener('click', onDetailClick)
})
</script>

<style scoped>
.pager {
  margin-top: 16px;
  justify-content: flex-end;
}
.audit-summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 4px 12px;
  font-size: 12px;
  color: var(--text-faint, #909399);
}
.audit-total {
  font-weight: 600;
  color: var(--text-primary, #303133);
}
.audit-legend .audit-name {
  color: var(--primary, #409eff);
}
.audit-operator {
  display: flex;
  align-items: center;
  gap: 4px;
  font-family: var(--font-mono, monospace);
}
.audit-username {
  font-weight: 600;
  color: var(--text-primary, #303133);
}
.audit-fullname {
  color: var(--text-regular, #606266);
}
.audit-fullname-empty {
  color: var(--text-placeholder, #c0c4cc);
  font-style: italic;
}
.audit-faint {
  color: var(--text-placeholder, #c0c4cc);
}
.audit-detail {
  font-family: var(--font-mono, monospace);
  font-size: 12.5px;
  line-height: 1.55;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.audit-detail :deep(.audit-link) {
  color: var(--primary, #409eff);
  text-decoration: none;
  border-bottom: 1px dashed var(--primary, #409eff);
  padding: 0 1px;
  transition: color 0.15s, background 0.15s;
}
.audit-detail :deep(.audit-link:hover) {
  color: #fff;
  background: var(--primary, #409eff);
  border-bottom-color: transparent;
  border-radius: 2px;
}
</style>
