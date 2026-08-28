<template>
  <div class="results-panel panel">
    <Toast ref="toastRef" />
    <div class="rp-head">
      <div class="rp-head-l">
        <div class="rp-head-icon">
          <svg viewBox="0 0 20 20" width="18" height="18" aria-hidden="true">
            <rect x="3" y="4" width="14" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="1.5" />
            <path d="M3 8h14" fill="none" stroke="currentColor" stroke-width="1.5" />
            <path d="M6 12h2M10 12h4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
          </svg>
        </div>
        <div>
          <div class="rp-title-row">
            <h2 class="rp-title">威胁建模结果</h2>
            <span class="rp-count-pill">{{ total }} 条记录</span>
          </div>
          <span class="rp-sub">历史建模记录，可导出 Markdown / JSON / CSV / Word 报告</span>
        </div>
      </div>
      <div class="rp-toolbar">
        <input
          v-model="keyword"
          class="rp-search"
          type="text"
          placeholder="搜索标题…"
          @keyup.enter="load(1)"
        />
        <select v-model="methodologyFilter" class="rp-filter-select" @change="load(1)">
          <option value="">全部方法论</option>
          <option v-for="m in methodologyOptions" :key="m.value" :value="m.value">
            {{ m.label }}
          </option>
        </select>
        <button class="btn btn-sm" :disabled="loading" @click="load(1)">
          <span class="btn-ico">⟳</span>
          {{ loading ? '加载中…' : '刷新' }}
        </button>
      </div>
    </div>

    <!-- 加载/空态 -->
    <div v-if="loading" class="rp-state">正在加载历史结果…</div>
    <div v-else-if="!items.length" class="rp-empty">
      暂无匹配的建模结果。先在「开始建模」页面完成一次 AI 威胁建模，结果会自动保存在这里。
    </div>

    <!-- 结果列表 -->
    <div v-else class="rp-list">
      <div
        v-for="item in items"
        :key="item.id"
        class="rp-item"
        :class="{ expanded: expandedId === item.id }"
      >
        <div class="rp-item-bar" @click="toggle(item.id)">
          <div class="rp-item-main">
            <span class="rp-item-title">{{ item.title }}</span>
            <div class="rp-item-meta">
              <span class="rp-tag">{{ tMethodology(item.methodology) }}</span>
              <span class="rp-time">{{ fmtTime(item.created_at) }}</span>
              <span class="rp-stat">
                {{ item.stats?.componentCount ?? '-' }} 组件 ·
                {{ item.stats?.flowCount ?? '-' }} 数据流 ·
                {{ item.stats?.threatCount ?? '-' }} 威胁
              </span>
            </div>
          </div>
          <div class="rp-item-actions">
            <div class="rp-export-group" @click.stop>
              <button
                class="rp-icon-btn rp-export"
                title="导出报告"
                @click="doExport(item, 'md')"
              >
                导出 ▾
              </button>
              <div class="rp-export-menu">
                <button @click="doExport(item, 'md')">Markdown 报告</button>
                <button @click="doExport(item, 'json')">Threat Dragon JSON</button>
                <button @click="doExport(item, 'csv')">CSV 威胁清单</button>
                <button @click="doExport(item, 'docx')">Word 报告 (.docx)</button>
              </div>
            </div>
            <button
              class="rp-icon-btn rp-rename"
              title="重命名标题"
              @click.stop="openRename(item)"
            >
              重命名
            </button>
            <button
              class="rp-icon-btn rp-del"
              title="删除此结果"
              @click.stop="doDelete(item)"
            >
              删除
            </button>
            <span class="rp-caret">{{ expandedId === item.id ? '▾' : '▸' }}</span>
          </div>
        </div>

        <!-- 展开详情 -->
        <div v-if="expandedId === item.id" class="rp-detail">
          <div v-if="detailLoading" class="rp-state">正在加载详情…</div>
          <template v-else-if="detail">
            <div class="rp-detail-stats">
              <div class="rp-stat-card">
                <span class="rp-stat-ico comp">◇</span>
                <span class="rp-stat-num">{{ detail.stats?.componentCount ?? '-' }}</span>
                <span class="rp-stat-label">组件</span>
              </div>
              <div class="rp-stat-card">
                <span class="rp-stat-ico flow">⇄</span>
                <span class="rp-stat-num">{{ detail.stats?.flowCount ?? '-' }}</span>
                <span class="rp-stat-label">数据流</span>
              </div>
              <div class="rp-stat-card">
                <span class="rp-stat-ico threat">⚠</span>
                <span class="rp-stat-num">{{ detail.stats?.threatCount ?? '-' }}</span>
                <span class="rp-stat-label">威胁</span>
              </div>
              <div class="rp-stat-card risk">
                <span class="rp-stat-ico risk">!</span>
                <span class="rp-stat-num">{{ riskCount(detail) }}</span>
                <span class="rp-stat-label">高危风险</span>
              </div>
            </div>

            <!-- 按等级统计（点击切换筛选） -->
            <div class="rp-sev-summary">
              <span
                v-for="sev in sevOrdered"
                :key="sev.key"
                class="rp-sev-chip"
                :class="['sev-' + sev.key, { 'rp-chip-active': activeSeverities.has(sev.key) }]"
                :title="activeSeverities.has(sev.key) ? '点击取消筛选' : '点击仅查看此严重度'"
                @click="toggleFilter('severity', sev.key)"
              >
                {{ tSeverity(sev.key) }} × {{ detail.stats?.threatCountBySeverity?.[sev.key] ?? 0 }}
              </span>
              <!-- 类型筛选（多选）：自动从当前模型中提取 -->
              <template v-if="availableTypes.length">
                <span class="rp-filter-sep">·</span>
                <span
                  v-for="t in availableTypes"
                  :key="t"
                  class="rp-type-chip"
                  :class="{ 'rp-chip-active': activeTypes.has(t) }"
                  :title="t"
                  @click="toggleFilter('type', t)"
                >
                  {{ tType(t) }} × {{ typeCount(t) }}
                </span>
              </template>
            </div>

            <div class="rp-detail-title">
              <h4>
                威胁明细
                <span class="rp-filter-count">
                  <template v-if="hasFilter">
                    已筛选 {{ filteredThreatList.length }} / {{ threatList.length }}
                  </template>
                  <template v-else>
                    共 {{ threatList.length }}
                  </template>
                </span>
              </h4>
              <div class="rp-detail-actions">
                <button v-if="hasFilter" class="btn btn-sm rp-clear" @click="clearFilters">
                  清空筛选
                </button>
                <button class="btn btn-sm btn-primary" @click="doExport(item)">
                  ⬇ 导出报告 (Markdown)
                </button>
              </div>
            </div>

            <div v-if="!threatList.length" class="rp-empty">该模型未识别到威胁。</div>
            <div v-else-if="!filteredThreatList.length" class="rp-empty">
              当前筛选条件下没有威胁。
              <button class="btn btn-sm rp-clear" @click="clearFilters">清空筛选</button>
            </div>
            <div v-else class="rp-threat-list">
              <div
                v-for="t in filteredThreatList"
                :key="t.threatId || t.title + t.number"
                class="rp-threat"
              >
                <div class="rp-threat-head">
                  <span class="rp-sev-badge" :class="'sev-' + t.severity">{{ tSeverity(t.severity) }}</span>
                  <span class="rp-threat-title">{{ t.title }}</span>
                  <span class="rp-threat-type" :title="t.type">{{ tType(t.type) }}</span>
                  <span class="rp-threat-comp" :title="t.component">@ {{ t.component }}</span>
                  <select
                    class="rp-status-select"
                    :class="'status-' + (t.status || 'Open')"
                    :value="t.status || 'Open'"
                    :title="'点击修改处置状态'"
                    @change="changeThreatStatus(item, t, $event)"
                    @click.stop
                  >
                    <option value="Open">Open</option>
                    <option value="In Progress">进行中</option>
                    <option value="Mitigated">已缓解</option>
                    <option value="Accepted">已接受</option>
                  </select>
                  <label
                    class="rp-oos-toggle"
                    :class="{ active: !!t.outOfScope }"
                    :title="t.outOfScope ? '已标记为范围外，点击取消' : '标记为不在范围内'"
                    @click.stop
                  >
                    <input
                      type="checkbox"
                      :checked="!!t.outOfScope"
                      @change="$event => toggleOOS(item, t, $event)"
                    />
                    <span>{{ t.outOfScope ? '范围外' : '范围内' }}</span>
                  </label>
                </div>
                <p class="rp-threat-desc">{{ t.description }}</p>
                <p v-if="t.mitigation" class="rp-threat-mit">
                  <strong>缓解：</strong>{{ t.mitigation }}
                </p>
                <div class="rp-threat-meta">
                  <span v-if="t.cwe">CWE：{{ t.cwe }}</span>
                  <span v-if="t.methodology">方法论：{{ tMethodology(t.methodology) }}</span>
                </div>
              </div>
            </div>
          </template>
        </div>
      </div>
    </div>

    <!-- 分页 -->
    <div v-if="pages > 1" class="rp-pagination">
      <button
        class="btn btn-sm"
        :disabled="page <= 1"
        @click="load(page - 1)"
      >‹ 上一页</button>
      <span class="rp-page-info">第 {{ page }} / {{ pages }} 页</span>
      <button
        class="btn btn-sm"
        :disabled="page >= pages"
        @click="load(page + 1)"
      >下一页 ›</button>
    </div>

    <!-- 重命名标题弹窗 -->
    <div v-if="renameVisible" class="rp-modal-mask" @click.self="closeRename">
      <div class="rp-modal">
        <div class="rp-modal-head">
          <h3>重命名结果标题</h3>
          <button class="rp-modal-close" @click="closeRename">×</button>
        </div>
        <div class="rp-modal-body">
          <p class="rp-modal-hint">
            给这条威胁建模记录起个好记的名字，方便后续在「搜索结果」中快速定位。
          </p>
          <input
            v-model="renameTitle"
            class="rp-modal-input"
            type="text"
            maxlength="60"
            placeholder="输入新的标题…"
            @keyup.enter="doRename"
          />
        </div>
        <div class="rp-modal-foot">
          <button class="btn btn-sm" @click="closeRename">取消</button>
          <button
            class="btn btn-sm btn-primary"
            :disabled="renaming || !renameTitle.trim()"
            @click="doRename"
          >{{ renaming ? '保存中…' : '保存' }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import Toast from './Toast.vue'
import {
  listResults,
  getResultDetail,
  deleteResult,
  renameResult,
  exportResult,
  downloadResult,
  updateThreatStatus as apiUpdateThreatStatus,
} from '@/api/threat.js'
import { tSeverity, tStatus, tType, tMethodology } from '../../utils/i18n.js'

const toastRef = ref(null)
const toast = (msg, type = 'info') => toastRef.value?.toast(msg, type)

// 暴露事件：'remodel' = 切回建模页；'open-result' = 用户在结果页点开某条记录，
// 触发 App.vue 同步加载该记录的 model，确保切回建模页能直接看到图（无需刷新）
const emit = defineEmits(['remodel', 'open-result'])
const confirmBox = (opts) => toastRef.value?.confirm(opts)

const items = ref([])
const loading = ref(false)
const expandedId = ref(null)
const detail = ref(null)
const detailLoading = ref(false)

// 列表分页 / 筛选 / 搜索
const page = ref(1)
const pageSize = ref(20)
const pages = ref(0)
const total = ref(0)
const keyword = ref('')
const methodologyFilter = ref('')
const methodologyOptions = [
  { value: 'STRIDE', label: 'STRIDE' },
  { value: 'STRIDE-AI', label: 'STRIDE-AI' },
  { value: 'CIA', label: 'CIA' },
  { value: 'CIADIE', label: 'CIADIE' },
  { value: 'LINDDUN', label: 'LINDDUN' },
  { value: 'PLOT4ai', label: 'PLOT4ai' },
  { value: 'EOP', label: 'EOP' },
]

const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low']
const sevOrdered = computed(() =>
  SEV_ORDER.map((key) => ({ key }))
)

// 详情区筛选状态：空 Set 表示"不筛"
const activeSeverities = ref(new Set())
const activeTypes = ref(new Set())

function toggleFilter(kind, key) {
  const target = kind === 'severity' ? activeSeverities : activeTypes
  if (target.value.has(key)) target.value.delete(key)
  else target.value.add(key)
  // 触发响应式更新（Set 的变更默认不可见）
  target.value = new Set(target.value)
}
function clearFilters() {
  activeSeverities.value = new Set()
  activeTypes.value = new Set()
}

function fmtTime(epoch) {
  if (!epoch) return '-'
  const d = new Date(epoch * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

/** 从模型 detail 中收集所有威胁 */
const threatList = computed(() => {
  if (!detail.value) return []
  const diagrams = detail.value.model?.detail?.diagrams || []
  const out = []
  for (const diagram of diagrams) {
    const cells = diagram.cells || []
    const nameById = {}
    for (const c of cells) nameById[c.id] = c.data?.name || ''
    for (const c of cells) {
      for (const t of c.threats || []) {
        out.push({
          ...t,
          component: nameById[c.id] || '',
        })
      }
    }
  }
  return out
})

// 当前模型的所有威胁类型（去重），用于类型筛选 chip
const availableTypes = computed(() => {
  const set = new Set()
  for (const t of threatList.value) if (t.type) set.add(t.type)
  // 与后端 statistics 顺序保持一致以便可预测
  return Array.from(set)
})

function typeCount(typeKey) {
  return threatList.value.filter((t) => t.type === typeKey).length
}

// 高危风险数量（Critical + High）
function riskCount(d) {
  const bySev = d?.stats?.threatCountBySeverity || {}
  return (bySev.Critical || 0) + (bySev.High || 0)
}

const hasFilter = computed(
  () => activeSeverities.value.size > 0 || activeTypes.value.size > 0
)

// 过滤后的威胁列表（严重度 ∩ 类型 可多选，set 内部是 OR；两种筛选维度之间是 AND）
const filteredThreatList = computed(() => {
  if (!hasFilter.value) return threatList.value
  return threatList.value.filter((t) => {
    const sevOk =
      activeSeverities.value.size === 0 || activeSeverities.value.has(t.severity)
    const typeOk = activeTypes.value.size === 0 || activeTypes.value.has(t.type)
    return sevOk && typeOk
  })
})

async function load(targetPage) {
  if (targetPage) page.value = targetPage
  loading.value = true
  try {
    const data = await listResults({
      page: page.value,
      page_size: pageSize.value,
      methodology: methodologyFilter.value || undefined,
      keyword: keyword.value || undefined,
    })
    items.value = data.items || []
    total.value = data.total || 0
    page.value = data.page || 1
    pages.value = data.pages || 0
    if (!items.value.some((i) => i.id === expandedId.value)) {
      expandedId.value = null
      detail.value = null
    }
  } catch (e) {
    toast('加载历史结果失败：' + (e?.response?.data?.detail || e?.message), 'error')
  } finally {
    loading.value = false
  }
}

async function toggle(id) {
  if (expandedId.value === id) {
    expandedId.value = null
    detail.value = null
    return
  }
  expandedId.value = id
  detail.value = null
  detailLoading.value = true
  try {
    const d = await getResultDetail(id)
    detail.value = d
    // 通知父组件：用户已"打开"这条历史记录 → 切回建模页时应显示这张图
    emit('open-result', d)
  } catch (e) {
    toast('加载详情失败：' + (e?.response?.data?.detail || e?.message), 'error')
    expandedId.value = null
  } finally {
    detailLoading.value = false
  }
}

// 重新拉取详情（用于状态/范围变更后同步统计）
async function loadDetail(item, silent) {
  if (!silent) detailLoading.value = true
  try {
    detail.value = await getResultDetail(item.id)
  } catch (e) {
    if (!silent) toast('加载详情失败：' + (e?.response?.data?.detail || e?.message), 'error')
  } finally {
    if (!silent) detailLoading.value = false
  }
}

const FORMAT_MAP = {
  md: { type: 'text/markdown;charset=utf-8', ext: 'md' },
  json: { type: 'application/json;charset=utf-8', ext: 'json' },
  csv: { type: 'text/csv;charset=utf-8', ext: 'csv' },
  docx: { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', ext: 'docx' },
}
async function doExport(item, format = 'md') {
  try {
    if (format === 'docx') {
      // Word 为二进制，走 blob 下载
      await downloadResult(item.id, format)
      toast(`已导出 ${item.title}（DOCX）`, 'success')
      return
    }
    const { data, headers } = await exportResult(item.id, format)
    const fmt = FORMAT_MAP[format] || FORMAT_MAP.md
    const blob = new Blob([data], { type: fmt.type })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    // 优先使用后端返回的 Content-Disposition 文件名
    const cd = headers?.['content-disposition'] || ''
    const match = cd.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/)
    a.download = match ? decodeURIComponent(match[1].replace(/['"]/g, '')) : `threat-model-${item.id}.${fmt.ext}`
    a.click()
    URL.revokeObjectURL(url)
    toast(`已导出 ${item.title}（${format.toUpperCase()}）`, 'success')
  } catch (e) {
    toast('导出失败：' + (e?.response?.data?.detail || e?.message), 'error')
  }
}

async function doDelete(item) {
  const ok = await confirmBox({
    title: '删除建模结果',
    message: `确定删除「${item.title}」？此操作不可撤销。`,
    okText: '删除',
    danger: true,
    icon: '🗑️',
  })
  if (!ok) return
  try {
    await deleteResult(item.id)
    items.value = items.value.filter((i) => i.id !== item.id)
    total.value = Math.max(0, total.value - 1)
    if (expandedId.value === item.id) {
      expandedId.value = null
      detail.value = null
    }
    toast('已删除', 'success')
  } catch (e) {
    toast('删除失败：' + (e?.response?.data?.detail || e?.message), 'error')
  }
}

// —— 重命名标题 ——
const renameVisible = ref(false)
const renameTitle = ref('')
const renaming = ref(false)
const renameTarget = ref(null)

function openRename(item) {
  renameTarget.value = item
  renameTitle.value = item.title || ''
  renameVisible.value = true
  // 弹窗打开后聚焦输入框
  setTimeout(() => {
    const el = document.querySelector('.rp-modal-input')
    el?.focus()
    el?.select()
  }, 50)
}

function closeRename() {
  if (renaming.value) return
  renameVisible.value = false
  renameTarget.value = null
}

async function doRename() {
  const title = renameTitle.value.trim()
  if (!title || !renameTarget.value) return
  renaming.value = true
  try {
    await renameResult(renameTarget.value.id, title)
    // 更新本地列表与展开的详情
    renameTarget.value.title = title
    if (detail.value?.id === renameTarget.value.id) {
      detail.value.title = title
    }
    toast('标题已更新', 'success')
    renameVisible.value = false
    renameTarget.value = null
  } catch (e) {
    toast('重命名失败：' + (e?.response?.data?.detail || e?.message), 'error')
  } finally {
    renaming.value = false
  }
}

// 在结果页直接修改威胁状态（通过 PATCH API 回写持久化）
async function changeThreatStatus(item, t, e) {
  const newStatus = e?.target?.value
  const tid = t.threatId || t.id
  if (!tid) {
    toast('该威胁无可用标识，无法更新', 'error')
    return
  }
  const prev = t.status || 'Open'
  // 立即在前端显示
  t.status = newStatus
  try {
    await apiUpdateThreatStatus(item.id, tid, newStatus)
    // 重新加载详情以同步统计（如有状态变更影响计数）
    if (detail.value && expandedId.value === item.id) {
      await loadDetail(item, /* silent */ true)
    }
  } catch (err) {
    t.status = prev // 回滚
    toast('更新状态失败：' + (err?.response?.data?.detail || err?.message), 'error')
  }
}

// 切换范围外标记
async function toggleOOS(item, t, e) {
  const newVal = !!e?.target?.checked
  const tid = t.threatId || t.id
  if (!tid) {
    toast('该威胁无可用标识，无法更新', 'error')
    return
  }
  const prev = !!t.outOfScope
  t.outOfScope = newVal
  try {
    await apiUpdateThreatStatus(item.id, tid, t.status || 'Open', { outOfScope: newVal })
    if (detail.value && expandedId.value === item.id) {
      await loadDetail(item, /* silent */ true)
    }
  } catch (err) {
    t.outOfScope = prev
    toast('更新范围标记失败：' + (err?.response?.data?.detail || err?.message), 'error')
  }
}

onMounted(() => load(1))
</script>

<style scoped>
.results-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
  padding: 16px 20px;
  gap: 14px;
  background: var(--bg-panel);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
}
.rp-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
  gap: 16px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
}
.rp-head-l {
  display: flex;
  align-items: center;
  gap: 12px;
}
.rp-head-icon {
  width: 38px;
  height: 38px;
  border-radius: 10px;
  display: grid;
  place-items: center;
  background: var(--primary-gradient);
  color: var(--text-on-primary);
  box-shadow: 0 4px 14px rgba(91, 156, 255, 0.35);
  flex-shrink: 0;
}
.rp-title-row {
  display: flex;
  align-items: center;
  gap: 10px;
}
.rp-title {
  font-size: 16px;
  font-weight: 700;
  color: var(--text);
  letter-spacing: 0.2px;
}
.rp-count-pill {
  font-size: 11px;
  font-weight: 600;
  padding: 2px 10px;
  border-radius: var(--radius-pill);
  background: var(--primary-soft);
  color: var(--primary);
  border: 1px solid var(--primary-border);
  font-family: var(--font-mono);
}
.rp-sub {
  font-size: 11.5px;
  color: var(--text-faint);
  margin-top: 2px;
  display: block;
}
.rp-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
}
.rp-search {
  padding: 6px 10px;
  font-size: 12px;
  background: var(--bg-panel-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text);
  outline: none;
  box-shadow: none;
  min-width: 0;
  -webkit-appearance: none;
  appearance: none;
  width: 170px;
  transition: all 0.2s;
  line-height: 1;
  height: 32px;
  box-sizing: border-box;
}
.rp-search:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px var(--primary-soft);
  width: 200px;
}
.rp-filter-select {
  padding: 6px 10px;
  font-size: 12px;
  background: var(--bg-panel-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text);
  cursor: pointer;
  line-height: 1;
  height: 32px;
  box-sizing: border-box;
}
.rp-filter-select:focus {
  outline: none;
  border-color: var(--primary);
}
.btn-ico {
  display: inline-block;
  font-size: 12px;
}
.rp-pagination {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  padding: 12px 0 0;
  flex-shrink: 0;
  border-top: 1px solid var(--border);
}
.rp-page-info {
  font-size: 12.5px;
  color: var(--text-dim);
  font-family: var(--font-mono);
}
.rp-export-group {
  position: relative;
  display: inline-block;
}
.rp-export-group:hover .rp-export-menu {
  display: flex;
}
.rp-export-menu {
  display: none;
  position: absolute;
  right: 0;
  top: 100%;
  z-index: 20;
  flex-direction: column;
  min-width: 168px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  box-shadow: var(--shadow);
  overflow: hidden;
}
.rp-export-menu button {
  padding: 9px 14px;
  font-size: 12.5px;
  text-align: left;
  color: var(--text);
  background: transparent;
  border: none;
  cursor: pointer;
  transition: background 0.15s;
  display: flex;
  align-items: center;
  gap: 6px;
}
.rp-export-menu button:hover {
  background: var(--primary-soft);
  color: var(--primary);
}
.rp-export-menu button:first-child {
  border-radius: var(--radius-sm) var(--radius-sm) 0 0;
}
.rp-export-menu button:last-child {
  border-radius: 0 0 var(--radius-sm) var(--radius-sm);
}
.rp-list {
  flex: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-right: 2px;
}
.rp-state,
.rp-empty {
  padding: 32px 16px;
  text-align: center;
  font-size: 13px;
  color: var(--text-faint);
  border: 1px dashed var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-panel-2);
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}
.rp-item {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-panel-2);
  overflow: hidden;
  transition: border-color 0.2s, box-shadow 0.2s, transform 0.15s;
}
.rp-item:hover {
  border-color: var(--primary-border);
  box-shadow: var(--shadow-sm);
}
.rp-item.expanded {
  border-color: var(--primary);
  box-shadow: 0 0 0 1px var(--primary), var(--shadow);
}
.rp-item-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 12px 14px;
  cursor: pointer;
  transition: background 0.15s;
}
.rp-item-bar:hover {
  background: var(--bg-active);
}
.rp-item-main {
  flex: 1;
  min-width: 0;
}
.rp-item-title {
  font-size: 13.5px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 8px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text);
}
.rp-item-title::before {
  content: '';
  width: 4px;
  height: 16px;
  border-radius: 2px;
  background: var(--primary-gradient);
  flex-shrink: 0;
}
.rp-item-meta {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 5px;
  font-size: 11.5px;
  color: var(--text-faint);
  padding-left: 12px;
}
.rp-tag {
  padding: 1px 7px;
  border-radius: 10px;
  font-size: 10.5px;
  background: var(--info-soft);
  color: var(--info);
  border: 1px solid var(--info-border);
}
.rp-item-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}
.rp-icon-btn {
  font-size: 11.5px;
  padding: 3px 9px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text);
  cursor: pointer;
}
.rp-icon-btn:hover {
  filter: brightness(1.2);
}
.rp-export {
  color: var(--info);
  border-color: var(--info-border);
}
.rp-del {
  color: var(--danger);
  border-color: var(--danger-border);
}
.rp-rename {
  color: var(--primary);
  border-color: var(--primary-border);
}
.rp-caret {
  color: var(--text-faint);
  font-size: 13px;
}
.rp-detail {
  padding: 14px 16px;
  border-top: 1px solid var(--border);
  background: var(--bg-panel-2);
}
.rp-detail-stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
  margin-bottom: 12px;
}
.rp-stat-card {
  position: relative;
  background: var(--bg-panel-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 12px 8px;
  text-align: center;
  overflow: hidden;
  transition: all 0.2s;
}
.rp-stat-card:hover {
  border-color: var(--primary-border);
  transform: translateY(-2px);
  box-shadow: var(--shadow-sm);
}
.rp-stat-ico {
  position: absolute;
  top: 8px;
  left: 10px;
  width: 20px;
  height: 20px;
  display: grid;
  place-items: center;
  border-radius: 6px;
  font-size: 11px;
  color: var(--primary);
  background: var(--primary-soft);
}
.rp-stat-ico.comp { color: var(--primary); background: var(--primary-soft); }
.rp-stat-ico.flow { color: var(--info); background: var(--info-soft); }
.rp-stat-ico.threat { color: var(--warning); background: var(--warning-soft); }
.rp-stat-ico.risk { color: var(--danger); background: var(--danger-soft); }
.rp-stat-num {
  display: block;
  font-size: 22px;
  font-weight: 700;
  line-height: 1.1;
  font-family: var(--font-mono);
  background: var(--primary-gradient);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}
.rp-stat-card.risk .rp-stat-num {
  background: linear-gradient(135deg, var(--danger), #f87171);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}
.rp-stat-label {
  font-size: 11px;
  color: var(--text-dim);
  font-weight: 500;
}
.rp-sev-summary {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  margin-bottom: 12px;
}
.rp-sev-chip {
  font-size: 11px;
  padding: 3px 9px;
  border-radius: 12px;
  cursor: pointer;
  user-select: none;
  transition: filter 0.15s, transform 0.1s, box-shadow 0.15s;
}
.rp-sev-chip:hover {
  filter: brightness(1.18);
}
.rp-sev-chip:active {
  transform: scale(0.97);
}
.rp-chip-active {
  box-shadow: 0 0 0 2px var(--primary-border) inset;
  filter: brightness(1.05);
}
.rp-sev-chip.sev-Critical {
  background: var(--critical-soft);
  color: var(--critical);
  border: 1px solid var(--critical-border);
}
.rp-sev-chip.sev-High {
  background: var(--high-soft);
  color: var(--high);
  border: 1px solid var(--warning-border);
}
.rp-sev-chip.sev-Medium {
  background: var(--medium-soft);
  color: var(--medium);
  border: 1px solid var(--warning-border);
}
.rp-sev-chip.sev-Low {
  background: var(--success-soft);
  color: var(--success);
  border: 1px solid var(--success-border);
}
.rp-filter-sep {
  color: var(--text-faint);
  font-size: 11px;
  margin: 0 2px;
}
.rp-type-chip {
  font-size: 11px;
  padding: 3px 9px;
  border-radius: 12px;
  cursor: pointer;
  user-select: none;
  background: var(--info-soft);
  color: var(--info);
  border: 1px solid var(--info-border);
  transition: filter 0.15s, transform 0.1s, box-shadow 0.15s;
}
.rp-type-chip:hover {
  filter: brightness(1.18);
}
.rp-type-chip:active {
  transform: scale(0.97);
}
.rp-detail-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin: 4px 0 10px;
  padding-left: 10px;
  position: relative;
}
.rp-detail-title::before {
  content: '';
  position: absolute;
  left: 0;
  top: 2px;
  bottom: 2px;
  width: 3px;
  border-radius: 2px;
  background: var(--primary-gradient);
}
.rp-detail-title h4 {
  font-size: 13px;
  font-weight: 700;
  color: var(--text);
}
.rp-filter-count {
  margin-left: 8px;
  font-size: 11px;
  font-weight: 400;
  color: var(--text-faint);
}
.rp-detail-actions {
  display: flex;
  gap: 6px;
  align-items: center;
}
.rp-clear {
  color: var(--info);
  border-color: var(--info-border);
  background: transparent;
}
.rp-clear:hover {
  background: var(--info-soft);
}
.rp-threat-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  /* 让威胁明细独立滚动，避免长列表被父容器裁掉而无法访问 */
  max-height: 58vh;
  overflow-y: auto;
  padding: 4px;
  margin: -4px;
  scrollbar-width: thin;
}
.rp-threat-list::-webkit-scrollbar {
  width: 8px;
}
.rp-threat-list::-webkit-scrollbar-thumb {
  background: var(--scrollbar-thumb);
  border-radius: 4px;
}
.rp-threat-list::-webkit-scrollbar-thumb:hover {
  background: var(--primary);
}
.rp-threat {
  background: var(--bg-panel-solid);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.rp-threat:hover {
  border-color: var(--primary-border);
  box-shadow: var(--shadow-sm);
}
.rp-threat-head {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.rp-sev-badge {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: var(--radius-pill);
  flex-shrink: 0;
  letter-spacing: 0.2px;
}
.rp-sev-badge.sev-Critical {
  background: var(--critical-soft);
  color: var(--critical);
  border: 1px solid var(--critical-border);
}
.rp-sev-badge.sev-High {
  background: var(--high-soft);
  color: var(--high);
  border: 1px solid var(--high-border);
}
.rp-sev-badge.sev-Medium {
  background: var(--medium-soft);
  color: var(--medium);
  border: 1px solid var(--medium-border);
}
.rp-sev-badge.sev-Low {
  background: var(--success-soft);
  color: var(--success);
  border: 1px solid var(--success-border);
}
.rp-threat-title {
  font-size: 13px;
  font-weight: 600;
  flex: 1;
  min-width: 0;
  color: var(--text);
}
.rp-threat-type {
  font-size: 10.5px;
  color: var(--info);
  padding: 1px 7px;
  border-radius: 9px;
  background: var(--info-soft);
  border: 1px solid var(--info-border);
  font-weight: 600;
}
.rp-status-select {
  font-size: 10.5px;
  font-weight: 600;
  padding: 1px 6px 1px 8px;
  border-radius: 10px;
  flex-shrink: 0;
  cursor: pointer;
  outline: none;
  appearance: none;
  -webkit-appearance: none;
  background-image: linear-gradient(45deg, transparent 50%, currentColor 50%),
                    linear-gradient(135deg, currentColor 50%, transparent 50%);
  background-position: calc(100% - 10px) 50%, calc(100% - 7px) 50%;
  background-size: 3px 3px, 3px 3px;
  background-repeat: no-repeat;
  padding-right: 18px;
}
.rp-status-select.status-Open {
  background-color: var(--primary-soft);
  color: var(--primary);
  border: 1px solid var(--primary-border);
}
.rp-status-select.status-Mitigated {
  background-color: var(--success-soft);
  color: var(--success);
  border: 1px solid var(--success-border);
}
.rp-status-select.status-Accepted {
  background-color: var(--warning-soft);
  color: var(--warning);
  border: 1px solid var(--warning-border);
}
.rp-status-select.status-InProgress,
.rp-status-select.status-In-Progress {
  background-color: var(--info-soft);
  color: var(--info);
  border: 1px solid var(--info-border);
}
.rp-status-select:focus {
  outline: 2px solid var(--primary);
  outline-offset: 1px;
}
.rp-oos-toggle {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  font-size: 10.5px;
  font-weight: 600;
  padding: 1px 8px;
  border-radius: 10px;
  background: var(--bg-panel-2);
  border: 1px solid var(--border-light);
  color: var(--text-dim);
  cursor: pointer;
  user-select: none;
  flex-shrink: 0;
  transition: background 0.15s, border-color 0.15s, color 0.15s;
}
.rp-oos-toggle input {
  position: absolute;
  opacity: 0;
  pointer-events: none;
  width: 0;
  height: 0;
}
.rp-oos-toggle.active {
  background: var(--bg-hover);
  color: var(--text-faint);
  border-color: var(--border-strong);
  border-style: dashed;
}
.rp-oos-toggle:hover {
  border-color: var(--primary-border);
  color: var(--primary);
}
.rp-threat-comp {
  font-size: 10.5px;
  color: var(--text-faint);
  background: var(--bg-hover);
  padding: 1px 7px;
  border-radius: 8px;
  border: 1px solid var(--border);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 180px;
}
.rp-threat-desc {
  font-size: 12px;
  color: var(--text);
  line-height: 1.6;
  margin: 8px 0 0;
  word-break: break-word;
  background: var(--bg-panel-2);
  border-radius: var(--radius-sm);
  padding: 8px 10px;
  border-left: 2px solid var(--border-light);
}
.rp-threat-mit {
  font-size: 12px;
  color: var(--success);
  line-height: 1.55;
  margin: 6px 0 0;
  word-break: break-word;
  background: var(--success-soft);
  border-radius: var(--radius-sm);
  padding: 8px 10px;
  border-left: 2px solid var(--success-border);
}
.rp-threat-mit strong {
  color: var(--success);
  margin-right: 4px;
}
.rp-threat-meta {
  display: flex;
  gap: 14px;
  font-size: 11px;
  color: var(--text-faint);
  margin-top: 7px;
  flex-wrap: wrap;
}

/* —— 重命名弹窗 —— */
.rp-modal-mask {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.45);
  backdrop-filter: blur(3px);
  -webkit-backdrop-filter: blur(3px);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  animation: rp-fade 0.16s ease-out;
}
.rp-modal {
  width: 420px;
  max-width: calc(100vw - 40px);
  background: var(--bg-panel-solid);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-lg);
  overflow: hidden;
  animation: rp-pop 0.18s cubic-bezier(0.2, 0.8, 0.3, 1.2);
}
.rp-modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
}
.rp-modal-head h3 {
  font-size: 14px;
  font-weight: 700;
  margin: 0;
}
.rp-modal-close {
  background: transparent;
  border: none;
  color: var(--text-faint);
  font-size: 18px;
  line-height: 1;
  cursor: pointer;
  padding: 2px 6px;
  border-radius: 6px;
}
.rp-modal-close:hover {
  color: var(--danger);
  background: var(--bg-hover);
}
.rp-modal-body {
  padding: 16px;
}
.rp-modal-hint {
  font-size: 12px;
  color: var(--text-dim);
  line-height: 1.6;
  margin: 0 0 12px;
}
.rp-modal-input {
  width: 100%;
  padding: 9px 12px;
  font-size: 13px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  background: var(--bg-panel-2);
  color: var(--text);
  outline: none;
  transition: border-color 0.16s, box-shadow 0.16s;
}
.rp-modal-input:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px var(--primary-soft);
}
.rp-modal-foot {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  padding: 12px 16px;
  border-top: 1px solid var(--border);
  background: var(--bg-panel-2);
}
@keyframes rp-fade {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
}
@keyframes rp-pop {
  from {
    opacity: 0;
    transform: translateY(8px) scale(0.98);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}
</style>
