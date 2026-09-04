<template>
  <div class="rd-panel">
    <Toast ref="toastRef" />

    <!-- 顶部：返回 + 标题 + meta + 操作 -->
    <div class="rd-head">
      <button class="rd-back" @click="goBack" title="返回结果列表">← 返回</button>
      <div class="rd-head-main">
        <h2 class="rd-title">{{ detail?.title || '加载中…' }}</h2>
        <div class="rd-meta">
          <span class="rd-tag">{{ tMethodology(detail?.methodology) }}</span>
          <span class="rd-time">{{ fmtTime(detail?.created_at) }}</span>
          <span class="rd-stat">建模人：{{ ownerLabel(detail) }}</span>
        </div>
      </div>
      <div class="rd-actions">
        <div class="rd-export-group" @click.stop>
          <button class="rd-icon-btn rd-export" @click="doExport(detail, 'md')">导出 ▾</button>
          <div class="rd-export-menu">
            <button @click="doExport(detail, 'md')">Markdown 报告</button>
            <button @click="doExport(detail, 'json')">Threat Dragon JSON</button>
            <button @click="doExport(detail, 'csv')">CSV 威胁清单</button>
            <button @click="doExport(detail, 'docx')">Word 报告 (.docx)</button>
          </div>
        </div>
        <button
          class="rd-icon-btn rd-rename"
          :disabled="!canModify(detail)"
          @click="openRename(detail)"
        >重命名</button>
        <button
          v-if="canDelete(detail)"
          class="rd-icon-btn rd-del"
          @click="doDelete(detail)"
        >删除</button>
      </div>
    </div>

    <!-- 加载/空/错误态 -->
    <div v-if="loading" class="rd-state">正在加载详情…</div>
    <div v-else-if="!detail" class="rd-state">
      未找到该结果（可能已被删除或 id 无效）
      <button class="btn btn-sm rd-clear" @click="goBack">返回列表</button>
    </div>

    <!-- 详情内容：两列布局（左主+右栏，各自独立上下滚动） -->
    <div v-else class="rd-body">
    <div class="rd-content">
      <!-- 4 个 KPI 卡 -->
      <div class="rd-stats">
        <div class="rd-stat-card">
          <span class="rd-stat-ico comp">◇</span>
          <span class="rd-stat-num">{{ detail.stats?.componentCount ?? '-' }}</span>
          <span class="rd-stat-label">组件</span>
        </div>
        <div class="rd-stat-card">
          <span class="rd-stat-ico flow">⇄</span>
          <span class="rd-stat-num">{{ detail.stats?.flowCount ?? '-' }}</span>
          <span class="rd-stat-label">数据流</span>
        </div>
        <div class="rd-stat-card">
          <span class="rd-stat-ico threat">⚠</span>
          <span class="rd-stat-num">{{ detail.stats?.threatCount ?? '-' }}</span>
          <span class="rd-stat-label">威胁</span>
        </div>
        <div class="rd-stat-card risk">
          <span class="rd-stat-ico risk">!</span>
          <span class="rd-stat-num">{{ riskCount(detail) }}</span>
          <span class="rd-stat-label">高危风险</span>
        </div>
      </div>

      <!-- 严重度 + 类型 chips（点击切换筛选） -->
      <div class="rd-chips">
        <span
          v-for="sev in sevOrdered"
          :key="sev.key"
          class="rd-sev-chip"
          :class="['sev-' + sev.key, { 'chip-active': activeSeverities.has(sev.key) }]"
          :title="activeSeverities.has(sev.key) ? '点击取消筛选' : '点击仅查看此严重度'"
          @click="toggleFilter('severity', sev.key)"
        >
          {{ tSeverity(sev.key) }} × {{ detail.stats?.threatCountBySeverity?.[sev.key] ?? 0 }}
        </span>
        <template v-if="availableTypes.length">
          <span class="rd-sep">·</span>
          <span
            v-for="t in availableTypes"
            :key="t"
            class="rd-type-chip"
            :class="{ 'chip-active': activeTypes.has(t) }"
            :title="t"
            @click="toggleFilter('type', t)"
          >
            {{ tType(t) }} × {{ typeCount(t) }}
          </span>
        </template>
      </div>

      <!-- 威胁明细标题 -->
      <div class="rd-threat-title">
        <h4>
          威胁明细
          <span class="rd-filter-count">
            <template v-if="hasFilter">已筛选 {{ filteredThreatList.length }} / {{ threatList.length }}</template>
            <template v-else>共 {{ threatList.length }}</template>
          </span>
        </h4>
        <div class="rd-threat-actions">
          <button v-if="hasFilter" class="btn btn-sm rd-clear" @click="clearFilters">清空筛选</button>
        </div>
      </div>

      <!-- 威胁列表 -->
      <div v-if="!threatList.length" class="rd-state">该模型未识别到威胁。</div>
      <div v-else-if="!filteredThreatList.length" class="rd-state">
        当前筛选条件下没有威胁。
        <button class="btn btn-sm rd-clear" @click="clearFilters">清空筛选</button>
      </div>
      <div v-else class="rd-threat-list">
        <div
          v-for="t in filteredThreatList"
          :key="t.threatId || t.title + t.number"
          :id="'threat-' + (t.threatId || t.id)"
          class="rd-threat"
        >
          <div class="rd-threat-head">
            <span class="rd-sev-badge" :class="'sev-' + t.severity">{{ tSeverity(t.severity) }}</span>
            <span class="rd-threat-title-text">{{ t.title }}</span>
            <span class="rd-threat-type" :title="t.type">{{ tType(t.type) }}</span>
            <span class="rd-threat-comp" :title="t.component">@ {{ t.component }}</span>
            <select
              class="rd-status-select"
              :class="'status-' + (t.status || 'Open')"
              :value="t.status || 'Open'"
              :title="canModify(detail) ? '点击修改处置状态' : '仅建模人/系统管理员/安全专家可修改'"
              :disabled="!canModify(detail)"
              @change="changeThreatStatus(detail, t, $event)"
              @click.stop
            >
              <option value="Open">Open</option>
              <option value="In Progress">进行中</option>
              <option value="Mitigated">已缓解</option>
              <option value="Accepted">已接受</option>
            </select>
            <label
              class="rd-oos-toggle"
              :class="{ active: !!t.outOfScope }"
              :title="t.outOfScope ? '已标记为范围外，点击取消' : '标记为不在范围内'"
              @click.stop
            >
              <input
                type="checkbox"
                :checked="!!t.outOfScope"
                @change="$event => toggleOOS(detail, t, $event)"
              />
              <span>{{ t.outOfScope ? '范围外' : '范围内' }}</span>
            </label>
          </div>
          <p class="rd-threat-desc">{{ t.description }}</p>
          <p v-if="t.mitigation" class="rd-threat-mit">
            <strong>缓解：</strong>{{ t.mitigation }}
          </p>
          <div class="rd-threat-meta">
            <span v-if="t.cwe">CWE：{{ t.cwe }}</span>
            <span v-if="t.methodology">方法论：{{ tMethodology(t.methodology) }}</span>
          </div>
        </div>
      </div>
    </div>

    <aside class="rd-side">
      <!-- 4 张子卡：元信息 + 严重度分布 + 类型分布 + 高危 Top 5 -->
      <div class="rd-side-card">
        <h5>结果信息</h5>
        <dl class="rd-side-meta">
          <dt>建模人</dt><dd>{{ ownerLabel(detail) }}</dd>
          <dt>创建时间</dt><dd>{{ fmtTime(detail?.created_at) }}</dd>
          <dt>方法论</dt><dd>{{ tMethodology(detail?.methodology) }}</dd>
          <dt>结果 ID</dt><dd class="rd-mono">{{ detail?.id }}</dd>
        </dl>
      </div>

      <div class="rd-side-card">
        <h5>严重度分布</h5>
        <div class="rd-side-bars">
          <div
            v-for="sev in SEV_ORDER"
            :key="sev"
            v-show="(detail.stats?.threatCountBySeverity?.[sev] || 0) > 0"
            class="rd-side-bar-row"
          >
            <span class="rd-side-bar-label">{{ tSeverity(sev) }}</span>
            <div class="rd-side-bar-track">
              <div class="rd-side-bar-fill" :class="'sev-' + sev" :style="{ width: barPct(sev) + '%' }"></div>
            </div>
            <span class="rd-side-bar-num">{{ detail.stats?.threatCountBySeverity?.[sev] || 0 }}</span>
          </div>
        </div>
      </div>

      <div v-if="availableTypes.length" class="rd-side-card">
        <h5>类型分布</h5>
        <div class="rd-side-types">
          <span v-for="t in availableTypes" :key="t" class="rd-side-type-chip">
            {{ tType(t) }} × {{ typeCount(t) }}
          </span>
        </div>
      </div>

      <div v-if="topRisks.length" class="rd-side-card">
        <h5>高危优先 · Top {{ topRisks.length }}</h5>
        <div class="rd-side-risks">
          <div
            v-for="t in topRisks"
            :key="t.threatId || t.id || t.title"
            class="rd-side-risk"
            @click="scrollToThreat(t)"
          >
            <span class="rd-sev-badge" :class="'sev-' + t.severity">{{ tSeverity(t.severity) }}</span>
            <span class="rd-side-risk-title" :title="t.title">{{ t.title }}</span>
          </div>
        </div>
      </div>
    </aside>
    </div>

    <!-- 重命名弹窗 -->
    <div v-if="renameVisible" class="rd-modal-mask" @click.self="closeRename">
      <div class="rd-modal">
        <div class="rd-modal-head">
          <h3>重命名结果标题</h3>
          <button class="rd-modal-close" @click="closeRename">×</button>
        </div>
        <div class="rd-modal-body">
          <p class="rd-modal-hint">
            给这条威胁建模记录起个好记的名字，方便后续在「搜索结果」中快速定位。
          </p>
          <input
            v-model="renameTitle"
            class="rd-modal-input"
            type="text"
            maxlength="60"
            placeholder="输入新的标题…"
            @keyup.enter="doRename"
          />
        </div>
        <div class="rd-modal-foot">
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
import { ref, computed, watch, nextTick } from 'vue'
import Toast from './Toast.vue'
import {
  getResultDetail,
  deleteResult,
  renameResult,
  exportResult,
  downloadResult,
  updateThreatStatus as apiUpdateThreatStatus,
} from '@/api/threat.js'
import { tSeverity, tType, tMethodology } from '../../utils/i18n.js'
import { useUserStore } from '@/store/user'

const props = defineProps({
  resultId: { type: [String, Number], required: true },
})

// 通知父组件：用户已打开这条历史记录；返回事件由父组件决定跳转目标
const emit = defineEmits(['back', 'open-result'])

const toastRef = ref(null)
const toast = (msg, type = 'info') => toastRef.value?.toast(msg, type)
const confirmBox = (opts) => toastRef.value?.confirm(opts)

// 数据
const detail = ref(null)
const loading = ref(false)
const error = ref(null)

// 权限
const userStore = useUserStore()
const currentRole = computed(() => userStore.role || '')
const currentUsername = computed(() => userStore.username || '')
const canViewAll = computed(() => ['admin', 'secops'].includes(currentRole.value))
function isOwner(item) {
  return !!(item && item.owner_username && currentUsername.value &&
    item.owner_username === currentUsername.value)
}
function canModify(item) {
  return canViewAll.value || isOwner(item)
}
function canDelete(item) {
  return canModify(item)
}
function ownerLabel(item) {
  if (!item) return '-'
  const u = item.owner_username || currentUsername.value || ''
  const n = item.owner_display_name || ''
  if (n && n !== u) return `${u} · ${n}`
  return u || n || '匿名'
}

// 严重度顺序
const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low']
const sevOrdered = computed(() => SEV_ORDER.map((key) => ({ key })))

// 筛选状态
const activeSeverities = ref(new Set())
const activeTypes = ref(new Set())
function toggleFilter(kind, key) {
  const target = kind === 'severity' ? activeSeverities : activeTypes
  if (target.value.has(key)) target.value.delete(key)
  else target.value.add(key)
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

// 威胁聚合
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
        out.push({ ...t, component: nameById[c.id] || '' })
      }
    }
  }
  return out
})

const availableTypes = computed(() => {
  const set = new Set()
  for (const t of threatList.value) if (t.type) set.add(t.type)
  return Array.from(set)
})

function typeCount(typeKey) {
  return threatList.value.filter((t) => t.type === typeKey).length
}

function riskCount(d) {
  const bySev = d?.stats?.threatCountBySeverity || {}
  return (bySev.Critical || 0) + (bySev.High || 0)
}

// 严重度柱状图百分比（按该 severity 在总威胁数中的占比）
function barPct(sev) {
  const bySev = detail.value?.stats?.threatCountBySeverity || {}
  const total = SEV_ORDER.reduce((s, k) => s + (bySev[k] || 0), 0)
  if (total === 0) return 0
  return Math.round(((bySev[sev] || 0) / total) * 100)
}

// 高危 Top 5 索引（按 severity 优先级排序，Critical > High）
const topRisks = computed(() => {
  const order = { Critical: 0, High: 1, Medium: 2, Low: 3 }
  return [...threatList.value]
    .filter((t) => t.severity === 'Critical' || t.severity === 'High')
    .sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9))
    .slice(0, 5)
})

// 点击 Top 5 → 滚动到对应威胁（先清掉筛选，保证目标可见，再 smooth scroll + 高亮闪烁）
function scrollToThreat(t) {
  const id = t.threatId || t.id
  if (!id) return
  if (hasFilter.value) clearFilters()
  nextTick(() => {
    const el = document.getElementById('threat-' + id)
    if (!el) return
    el.scrollIntoView({ behavior: 'smooth', block: 'center' })
    el.classList.add('rd-threat-flash')
    setTimeout(() => el.classList.remove('rd-threat-flash'), 1500)
  })
}

const hasFilter = computed(
  () => activeSeverities.value.size > 0 || activeTypes.value.size > 0
)
const filteredThreatList = computed(() => {
  if (!hasFilter.value) return threatList.value
  return threatList.value.filter((t) => {
    const sevOk = activeSeverities.value.size === 0 || activeSeverities.value.has(t.severity)
    const typeOk = activeTypes.value.size === 0 || activeTypes.value.has(t.type)
    return sevOk && typeOk
  })
})

// 加载 + 响应 resultId 变化
async function load() {
  if (!props.resultId) return
  loading.value = true
  error.value = null
  detail.value = null
  try {
    const d = await getResultDetail(props.resultId)
    detail.value = d
    // 通知父组件：用户已"打开"这条历史记录 → 切回建模页时应显示这张图
    emit('open-result', d)
  } catch (e) {
    error.value = e?.response?.data?.detail || e?.message || '加载失败'
    toast('加载详情失败：' + error.value, 'error')
  } finally {
    loading.value = false
  }
}
async function loadDetailSilent() {
  try {
    detail.value = await getResultDetail(props.resultId)
  } catch (e) {
    // 静默：状态修改失败已经在上层 toast 过
  }
}

// 加载 + 响应 resultId 变化
watch(() => props.resultId, (v) => { if (v) load() }, { immediate: true })

// 返回
function goBack() {
  emit('back')
}

// 导出
const FORMAT_MAP = {
  md: { type: 'text/markdown;charset=utf-8', ext: 'md' },
  json: { type: 'application/json;charset=utf-8', ext: 'json' },
  csv: { type: 'text/csv;charset=utf-8', ext: 'csv' },
  docx: { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', ext: 'docx' },
}
async function doExport(item, format = 'md') {
  if (!item) return
  try {
    if (format === 'docx') {
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

// 删除（删除后回列表）
async function doDelete(item) {
  if (!item) return
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
    toast('已删除', 'success')
    goBack()
  } catch (e) {
    toast('删除失败：' + (e?.response?.data?.detail || e?.message), 'error')
  }
}

// 重命名
const renameVisible = ref(false)
const renameTitle = ref('')
const renaming = ref(false)
function openRename(item) {
  if (!item) return
  renameTitle.value = item.title || ''
  renameVisible.value = true
  setTimeout(() => {
    const el = document.querySelector('.rd-modal-input')
    el?.focus()
    el?.select()
  }, 50)
}
function closeRename() {
  if (renaming.value) return
  renameVisible.value = false
}
async function doRename() {
  const title = renameTitle.value.trim()
  if (!title || !detail.value) return
  renaming.value = true
  try {
    await renameResult(detail.value.id, title)
    detail.value.title = title
    toast('标题已更新', 'success')
    renameVisible.value = false
  } catch (e) {
    toast('重命名失败：' + (e?.response?.data?.detail || e?.message), 'error')
  } finally {
    renaming.value = false
  }
}

// 状态修改 + 范围外切换（与 ResultsPanel 行为完全一致）
async function changeThreatStatus(item, t, e) {
  const newStatus = e?.target?.value
  const tid = t.threatId || t.id
  if (!tid) {
    toast('该威胁无可用标识，无法更新', 'error')
    return
  }
  const prev = t.status || 'Open'
  t.status = newStatus
  try {
    await apiUpdateThreatStatus(item.id, tid, newStatus)
    await loadDetailSilent()
  } catch (err) {
    t.status = prev
    toast('更新状态失败：' + (err?.response?.data?.detail || err?.message), 'error')
  }
}
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
    await loadDetailSilent()
  } catch (err) {
    t.outOfScope = prev
    toast('更新范围标记失败：' + (err?.response?.data?.detail || err?.message), 'error')
  }
}
</script>

<style scoped>
.rd-panel {
  /* height: 100% 而非 flex: 1: .threat-results-tab 已加 display: flex column,但 height: 100%
     更稳——不依赖任何父级是 flex 容器,只要 .threat-results-tab 撑满 .threat-tab 的受限高度即可 */
  height: 100%;
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
.rd-head {
  display: flex;
  align-items: center;
  gap: 12px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.rd-back {
  font-size: 12.5px;
  padding: 6px 12px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text);
  border-radius: var(--radius-sm);
  cursor: pointer;
  flex-shrink: 0;
  transition: all 0.15s;
}
.rd-back:hover {
  border-color: var(--primary);
  color: var(--primary);
  background: var(--primary-soft);
}
.rd-head-main {
  flex: 1;
  min-width: 0;
}
.rd-title {
  font-size: 16px;
  font-weight: 700;
  color: var(--text);
  margin: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.rd-meta {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 5px;
  font-size: 11.5px;
  color: var(--text-faint);
  flex-wrap: wrap;
}
.rd-tag {
  padding: 1px 7px;
  border-radius: 10px;
  font-size: 10.5px;
  background: var(--info-soft);
  color: var(--info);
  border: 1px solid var(--info-border);
}
.rd-stat {
  color: var(--text-faint);
  font-family: var(--font-mono);
}
.rd-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}
.rd-icon-btn {
  font-size: 11.5px;
  padding: 3px 9px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text);
  cursor: pointer;
}
.rd-icon-btn:hover { filter: brightness(1.2); }
.rd-icon-btn:disabled { opacity: 0.45; cursor: not-allowed; }
.rd-export { color: var(--info); border-color: var(--info-border); }
.rd-del { color: var(--danger); border-color: var(--danger-border); }
.rd-rename { color: var(--primary); border-color: var(--primary-border); }
.rd-export-group { position: relative; display: inline-block; }
.rd-export-group:hover .rd-export-menu { display: flex; }
.rd-export-menu {
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
.rd-export-menu button {
  padding: 9px 14px;
  font-size: 12.5px;
  text-align: left;
  color: var(--text);
  background: transparent;
  border: none;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 6px;
}
.rd-export-menu button:hover { background: var(--primary-soft); color: var(--primary); }
.rd-export-menu button:first-child { border-radius: var(--radius-sm) var(--radius-sm) 0 0; }
.rd-export-menu button:last-child { border-radius: 0 0 var(--radius-sm) var(--radius-sm); }

.rd-body {
  flex: 1;
  display: grid;
  grid-template-columns: 1fr 320px;
  /* 关键: 显式 grid-template-rows,否则 track 高度=内容高度,grid item 会被撑成几千 px */
  /* → 子项的 overflow-y: auto 永远触发不了,无论怎么加 min-height: 0 都白搭 */
  /* 和 ThreatModeling.vue .analysis-grid 的修法完全一致 */
  grid-template-rows: minmax(0, 1fr);
  gap: 14px;
  min-height: 0;
}
.rd-content {
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding-right: 6px;
  min-height: 0;
}

/* 右侧栏：自己上下滚动 */
.rd-side {
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 0;
  padding-right: 4px;
}
.rd-side-card {
  background: var(--bg-panel-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 12px 14px;
  flex-shrink: 0;
}
.rd-side-card h5 {
  font-size: 12px;
  font-weight: 700;
  color: var(--text);
  margin: 0 0 10px;
  display: flex;
  align-items: center;
  gap: 6px;
}
.rd-side-card h5::before {
  content: '';
  width: 3px;
  height: 12px;
  background: var(--primary-gradient);
  border-radius: 2px;
  flex-shrink: 0;
}
.rd-side-meta {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 6px 10px;
  font-size: 12px;
  margin: 0;
}
.rd-side-meta dt {
  color: var(--text-faint);
  font-weight: 500;
}
.rd-side-meta dd {
  margin: 0;
  color: var(--text);
  word-break: break-all;
}
.rd-mono {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-dim);
}
.rd-side-bars {
  display: flex;
  flex-direction: column;
  gap: 7px;
}
.rd-side-bar-row {
  display: grid;
  grid-template-columns: 56px 1fr 28px;
  align-items: center;
  gap: 8px;
  font-size: 11.5px;
}
.rd-side-bar-label { color: var(--text-dim); font-weight: 600; }
.rd-side-bar-track {
  height: 8px;
  background: var(--bg-hover);
  border-radius: 4px;
  overflow: hidden;
}
.rd-side-bar-fill {
  height: 100%;
  border-radius: 4px;
  transition: width 0.4s;
}
.rd-side-bar-fill.sev-Critical { background: var(--critical); }
.rd-side-bar-fill.sev-High { background: var(--high); }
.rd-side-bar-fill.sev-Medium { background: var(--medium); }
.rd-side-bar-fill.sev-Low { background: var(--success); }
.rd-side-bar-num {
  font-family: var(--font-mono);
  font-weight: 700;
  color: var(--text);
  text-align: right;
}
.rd-side-types {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}
.rd-side-type-chip {
  font-size: 10.5px;
  padding: 2px 8px;
  border-radius: 10px;
  background: var(--info-soft);
  color: var(--info);
  border: 1px solid var(--info-border);
  font-weight: 600;
}
.rd-side-risks {
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.rd-side-risk {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 6px 8px;
  border-radius: 6px;
  background: var(--bg-panel-solid);
  border: 1px solid var(--border);
  cursor: pointer;
  transition: all 0.15s;
}
.rd-side-risk:hover {
  border-color: var(--primary-border);
  background: var(--primary-soft);
  transform: translateX(2px);
}
.rd-side-risk-title {
  font-size: 11.5px;
  color: var(--text);
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Top 5 跳转时高亮动画 */
.rd-threat-flash {
  animation: rd-threat-pulse 1.5s ease-out;
  border-color: var(--primary) !important;
}
@keyframes rd-threat-pulse {
  0% { box-shadow: 0 0 0 0 var(--primary-soft); background: var(--primary-soft); }
  100% { box-shadow: 0 0 0 8px transparent; background: transparent; }
}
.rd-state {
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
  flex-wrap: wrap;
}

.rd-stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
}
.rd-stat-card {
  position: relative;
  background: var(--bg-panel-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 12px 8px;
  text-align: center;
  overflow: hidden;
  transition: all 0.2s;
}
.rd-stat-card:hover {
  border-color: var(--primary-border);
  transform: translateY(-2px);
  box-shadow: var(--shadow-sm);
}
.rd-stat-ico {
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
.rd-stat-ico.comp { color: var(--primary); background: var(--primary-soft); }
.rd-stat-ico.flow { color: var(--info); background: var(--info-soft); }
.rd-stat-ico.threat { color: var(--warning); background: var(--warning-soft); }
.rd-stat-ico.risk { color: var(--danger); background: var(--danger-soft); }
.rd-stat-num {
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
.rd-stat-card.risk .rd-stat-num {
  background: linear-gradient(135deg, var(--danger), #f87171);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}
.rd-stat-label {
  font-size: 11px;
  color: var(--text-dim);
  font-weight: 500;
}

.rd-chips {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}
.rd-sev-chip {
  font-size: 11px;
  padding: 3px 9px;
  border-radius: 12px;
  cursor: pointer;
  user-select: none;
  transition: filter 0.15s, transform 0.1s, box-shadow 0.15s;
}
.rd-sev-chip:hover { filter: brightness(1.18); }
.rd-sev-chip:active { transform: scale(0.97); }
.chip-active { box-shadow: 0 0 0 2px var(--primary-border) inset; filter: brightness(1.05); }
.rd-sev-chip.sev-Critical { background: var(--critical-soft); color: var(--critical); border: 1px solid var(--critical-border); }
.rd-sev-chip.sev-High { background: var(--high-soft); color: var(--high); border: 1px solid var(--warning-border); }
.rd-sev-chip.sev-Medium { background: var(--medium-soft); color: var(--medium); border: 1px solid var(--warning-border); }
.rd-sev-chip.sev-Low { background: var(--success-soft); color: var(--success); border: 1px solid var(--success-border); }
.rd-sep { color: var(--text-faint); font-size: 11px; margin: 0 2px; }
.rd-type-chip {
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
.rd-type-chip:hover { filter: brightness(1.18); }
.rd-type-chip:active { transform: scale(0.97); }

.rd-threat-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin: 4px 0 10px;
  padding-left: 10px;
  position: relative;
}
.rd-threat-title::before {
  content: '';
  position: absolute;
  left: 0;
  top: 2px;
  bottom: 2px;
  width: 3px;
  border-radius: 2px;
  background: var(--primary-gradient);
}
.rd-threat-title h4 { font-size: 13px; font-weight: 700; color: var(--text); margin: 0; }
.rd-filter-count { margin-left: 8px; font-size: 11px; font-weight: 400; color: var(--text-faint); }
.rd-threat-actions { display: flex; gap: 6px; align-items: center; }
.rd-clear { color: var(--info); border-color: var(--info-border); background: transparent; }
.rd-clear:hover { background: var(--info-soft); }

.rd-threat-list { display: flex; flex-direction: column; gap: 8px; }
.rd-threat {
  background: var(--bg-panel-solid);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.rd-threat:hover { border-color: var(--primary-border); box-shadow: var(--shadow-sm); }
.rd-threat-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.rd-sev-badge {
  font-size: 10px; font-weight: 700; padding: 2px 8px;
  border-radius: var(--radius-pill); flex-shrink: 0; letter-spacing: 0.2px;
}
.rd-sev-badge.sev-Critical { background: var(--critical-soft); color: var(--critical); border: 1px solid var(--critical-border); }
.rd-sev-badge.sev-High { background: var(--high-soft); color: var(--high); border: 1px solid var(--high-border); }
.rd-sev-badge.sev-Medium { background: var(--medium-soft); color: var(--medium); border: 1px solid var(--medium-border); }
.rd-sev-badge.sev-Low { background: var(--success-soft); color: var(--success); border: 1px solid var(--success-border); }
.rd-threat-title-text {
  font-size: 13px; font-weight: 600; flex: 1; min-width: 0; color: var(--text);
}
.rd-threat-type {
  font-size: 10.5px; color: var(--info); padding: 1px 7px;
  border-radius: 9px; background: var(--info-soft);
  border: 1px solid var(--info-border); font-weight: 600;
}
.rd-threat-comp {
  font-size: 10.5px; color: var(--text-faint);
  background: var(--bg-hover); padding: 1px 7px; border-radius: 8px;
  border: 1px solid var(--border); white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis; max-width: 180px;
}
.rd-status-select {
  font-size: 10.5px; font-weight: 600; padding: 1px 6px 1px 8px;
  border-radius: 10px; flex-shrink: 0; cursor: pointer; outline: none;
  appearance: none; -webkit-appearance: none;
  background-image: linear-gradient(45deg, transparent 50%, currentColor 50%),
                    linear-gradient(135deg, currentColor 50%, transparent 50%);
  background-position: calc(100% - 10px) 50%, calc(100% - 7px) 50%;
  background-size: 3px 3px, 3px 3px;
  background-repeat: no-repeat;
  padding-right: 18px;
}
.rd-status-select.status-Open { background-color: var(--primary-soft); color: var(--primary); border: 1px solid var(--primary-border); }
.rd-status-select.status-Mitigated { background-color: var(--success-soft); color: var(--success); border: 1px solid var(--success-border); }
.rd-status-select.status-Accepted { background-color: var(--warning-soft); color: var(--warning); border: 1px solid var(--warning-border); }
.rd-status-select.status-InProgress,
.rd-status-select.status-In-Progress { background-color: var(--info-soft); color: var(--info); border: 1px solid var(--info-border); }
.rd-status-select:focus { outline: 2px solid var(--primary); outline-offset: 1px; }
.rd-oos-toggle {
  display: inline-flex; align-items: center; gap: 3px;
  font-size: 10.5px; font-weight: 600; padding: 1px 8px;
  border-radius: 10px; background: var(--bg-panel-2);
  border: 1px solid var(--border-light); color: var(--text-dim);
  cursor: pointer; user-select: none; flex-shrink: 0;
  transition: background 0.15s, border-color 0.15s, color 0.15s;
}
.rd-oos-toggle input { position: absolute; opacity: 0; pointer-events: none; width: 0; height: 0; }
.rd-oos-toggle.active { background: var(--bg-hover); color: var(--text-faint); border-color: var(--border-strong); border-style: dashed; }
.rd-oos-toggle:hover { border-color: var(--primary-border); color: var(--primary); }
.rd-threat-desc {
  font-size: 12px; color: var(--text); line-height: 1.6;
  margin: 8px 0 0; word-break: break-word;
  background: var(--bg-panel-2); border-radius: var(--radius-sm);
  padding: 8px 10px; border-left: 2px solid var(--border-light);
}
.rd-threat-mit {
  font-size: 12px; color: var(--success); line-height: 1.55;
  margin: 6px 0 0; word-break: break-word;
  background: var(--success-soft); border-radius: var(--radius-sm);
  padding: 8px 10px; border-left: 2px solid var(--success-border);
}
.rd-threat-mit strong { color: var(--success); margin-right: 4px; }
.rd-threat-meta { display: flex; gap: 14px; font-size: 11px; color: var(--text-faint); margin-top: 7px; flex-wrap: wrap; }

.rd-modal-mask {
  position: fixed; inset: 0; background: rgba(0,0,0,0.45);
  backdrop-filter: blur(3px); -webkit-backdrop-filter: blur(3px);
  z-index: 1000; display: flex; align-items: center; justify-content: center;
  animation: rd-fade 0.16s ease-out;
}
.rd-modal {
  width: 420px; max-width: calc(100vw - 40px);
  background: var(--bg-panel-solid);
  border: 1px solid var(--border-strong); border-radius: var(--radius-md);
  box-shadow: var(--shadow-lg); overflow: hidden;
  animation: rd-pop 0.18s cubic-bezier(0.2, 0.8, 0.3, 1.2);
}
.rd-modal-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 14px 16px; border-bottom: 1px solid var(--border);
}
.rd-modal-head h3 { font-size: 14px; font-weight: 700; margin: 0; }
.rd-modal-close {
  background: transparent; border: none; color: var(--text-faint);
  font-size: 18px; line-height: 1; cursor: pointer;
  padding: 2px 6px; border-radius: 6px;
}
.rd-modal-close:hover { color: var(--danger); background: var(--bg-hover); }
.rd-modal-body { padding: 16px; }
.rd-modal-hint {
  font-size: 12px; color: var(--text-dim);
  line-height: 1.6; margin: 0 0 12px;
}
.rd-modal-input {
  width: 100%; padding: 9px 12px; font-size: 13px;
  border: 1px solid var(--border-strong); border-radius: var(--radius-sm);
  background: var(--bg-panel-2); color: var(--text); outline: none;
  transition: border-color 0.16s, box-shadow 0.16s;
}
.rd-modal-input:focus {
  border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-soft);
}
.rd-modal-foot {
  display: flex; justify-content: flex-end; gap: 8px;
  padding: 12px 16px; border-top: 1px solid var(--border);
  background: var(--bg-panel-2);
}
@keyframes rd-fade { from { opacity: 0; } to { opacity: 1; } }
@keyframes rd-pop { from { opacity: 0; transform: translateY(8px) scale(0.98); } to { opacity: 1; transform: translateY(0) scale(1); } }
</style>
