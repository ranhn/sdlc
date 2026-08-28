<template>
  <div class="threat-panel">
    <Toast ref="toastRef" />

    <!-- 头部 -->
    <header class="tp-head">
      <div class="head-l">
        <div class="head-icon">
          <svg viewBox="0 0 20 20" width="16" height="16" aria-hidden="true">
            <path d="M10 2l8 3v5c0 4.5-3.5 8-8 8.5C5.5 18 2 14.5 2 10V5l8-3z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
            <path d="M10 7v3.5M10 13.2v.01" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
          </svg>
        </div>
        <div class="head-text">
          <h3>威胁分析</h3>
          <p>{{ stats ? `${stats.threatCount || 0} 项威胁已识别` : '点击图中节点查看威胁' }}</p>
        </div>
      </div>
    </header>

    <!-- KPI 卡片 -->
    <div v-if="stats" class="kpi-grid">
      <div class="kpi-card">
        <span class="kpi-num">{{ stats.componentCount || 0 }}</span>
        <span class="kpi-lbl">组件</span>
      </div>
      <div class="kpi-card">
        <span class="kpi-num">{{ stats.flowCount || 0 }}</span>
        <span class="kpi-lbl">数据流</span>
      </div>
      <div class="kpi-card">
        <span class="kpi-num">{{ stats.threatCount || 0 }}</span>
        <span class="kpi-lbl">威胁</span>
      </div>
      <div class="kpi-card danger">
        <span class="kpi-num">{{ highCount }}</span>
        <span class="kpi-lbl">高危</span>
      </div>
    </div>

    <!-- 严重度/类型分布 -->
    <div v-if="stats" class="distribution">
      <div class="dist-row">
        <span class="dist-label">严重度分布</span>
        <div class="bars">
          <span
            v-for="(count, sev) in severityOrdered"
            :key="sev"
            class="bar"
            :class="'sev-' + sevKey(sev)"
            :style="{ width: pct(sev) + '%' }"
            :title="`${sev}: ${count}`"
          ></span>
        </div>
        <span class="dist-detail">{{ severitySummary }}</span>
      </div>
      <div class="dist-row">
        <span class="dist-label">类型分布</span>
        <div class="type-chips">
          <span v-for="(count, type) in stats.threatCountByType || {}" :key="type" class="chip" :title="type">
            {{ shortType(type) }} <b>{{ count }}</b>
          </span>
        </div>
      </div>
    </div>

    <!-- 列表头 -->
    <div class="list-head">
      <h3 v-if="selectedThreats">{{ selectedThreats.cellName }} 的威胁</h3>
      <h3 v-else>威胁列表</h3>
      <button
        v-if="selectedThreats"
        class="btn btn-sm"
        @click="$emit('clear-selection')"
      >
        全部
      </button>
    </div>

    <!-- 威胁列表 -->
    <div ref="listRef" class="threat-list">
      <template v-if="visibleThreats.length">
        <div
          v-for="t in visibleThreats"
          :key="t.threatId || t.number"
          class="threat-item"
          :class="'sev-' + sevKey(t.severity)"
          @click="toggleExpand(t)"
        >
          <div class="threat-head">
            <span class="sev-badge" :class="'sev-' + sevKey(t.severity)">
              {{ tSeverity(t.severity) }}
            </span>
            <select
              class="status-select-inline"
              :class="'status-' + statusKey(t.status)"
              :value="t.status || 'Open'"
              :title="`点击修改处置状态`"
              @change="changeStatus(t, $event)"
              @click.stop
            >
              <option value="Open">Open</option>
              <option value="In Progress">进行中</option>
              <option value="Mitigated">已缓解</option>
              <option value="Accepted">已接受</option>
            </select>
            <span class="threat-type" :title="t.type">{{ shortType(t.type) }}</span>
            <span class="threat-title" :class="{ 'is-out-of-scope': t.outOfScope }">
              <span class="t-num">#{{ t.number }}</span>
              <span>{{ t.title }}</span>
            </span>
            <label
              class="oos-toggle-inline"
              :class="{ active: !!t.outOfScope }"
              :title="t.outOfScope ? '已标记为范围外，点击取消' : '标记为不在范围内'"
              @click.stop
            >
              <input
                type="checkbox"
                :checked="!!t.outOfScope"
                @change="ev => toggleOutOfScope(t, ev)"
              />
              <span class="oos-toggle-text">{{ t.outOfScope ? '范围外' : '范围内' }}</span>
            </label>
            <span class="expand-arrow" :class="{ open: isExpanded(t) }">▾</span>
          </div>
          <transition name="fade">
            <div v-if="isExpanded(t)" class="threat-detail">
              <div class="detail-block">
                <span class="detail-label">描述</span>
                <p>{{ t.description || '—' }}</p>
              </div>
              <div class="detail-block">
                <span class="detail-label">缓解措施</span>
                <p>{{ t.mitigation || '—' }}</p>
              </div>
              <div class="detail-meta">
                <span>状态：{{ tStatus(t.status) }}</span>
                <span v-if="t.aiExtension">方法论：{{ tMethodology('STRIDE-AI') }}</span>
                <span v-else-if="t.modelType">方法论：{{ tMethodology(t.modelType) }}</span>
                <span v-if="t.score">评分：{{ t.score }}</span>
                <span v-if="t.cwe" class="cwe-badge">{{ t.cwe }}</span>
                <span v-if="t.dread" class="dread-badge" :title="dreadTitle(t.dread)">
                  DREAD {{ dreadTotal(t.dread) }}/50
                </span>
              </div>
              <div v-if="t.dread" class="dread-detail">
                <span class="detail-label">DREAD 风险评分</span>
                <div class="dread-grid">
                  <div v-for="d in dreadItems(t.dread)" :key="d.key" class="dread-item">
                    <span class="dread-name">{{ d.label }}</span>
                    <span class="dread-track">
                      <span class="dread-fill" :class="'dread-lv' + d.lv" :style="{ width: d.pct + '%' }"></span>
                    </span>
                    <span class="dread-val">{{ d.val }}/5</span>
                  </div>
                </div>
              </div>
              <div v-if="t.references && t.references.length" class="detail-block">
                <span class="detail-label">参考资料</span>
                <div class="ref-list">
                  <a
                    v-for="(ref, i) in t.references"
                    :key="i"
                    :href="ref"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="ref-link"
                  >{{ ref }}</a>
                </div>
              </div>
            </div>
          </transition>
        </div>
      </template>

      <div v-else-if="model" class="no-threats">
        <div class="nt-icon">✓</div>
        <p v-if="selectedThreats">「{{ selectedThreats.cellName || '该组件' }}」暂无威胁记录</p>
        <p v-else>该区域暂无威胁记录</p>
      </div>
      <div v-else class="no-threats">
        <div class="nt-icon">📊</div>
        <p>尚无威胁数据</p>
        <span>完成一次 AI 建模后，此处将展示多方法论威胁及缓解措施</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick } from 'vue'
import Toast from './Toast.vue'
import { updateThreatStatus } from '@/api/threat.js'
import { tSeverity, tStatus, tType, tMethodology } from '../../utils/i18n.js'

const toastRef = ref(null)
const toast = (msg, type = 'info') => toastRef.value?.toast(msg, type)

const props = defineProps({
  model: { type: Object, default: null },
  stats: { type: Object, default: null },
  selectedCellId: { type: String, default: null },
  selectedThreats: { type: Object, default: null },
  resultId: { type: String, default: null },
})
const emit = defineEmits(['clear-selection', 'threat-updated'])

const expanded = ref(new Set())
const listRef = ref(null)

watch(
  () => props.selectedCellId,
  () => {
    expanded.value = new Set()
    nextTick(() => {
      if (listRef.value) listRef.value.scrollTop = 0
    })
  }
)

const highCount = computed(() => {
  const bySev = props.stats?.threatCountBySeverity || {}
  return (bySev.High || 0) + (bySev.Critical || 0)
})

const severityOrdered = computed(() => {
  const bySev = props.stats?.threatCountBySeverity || {}
  const order = ['Critical', 'High', 'Medium', 'Low', 'Unknown']
  return Object.fromEntries(
    order.filter((k) => bySev[k] !== undefined).map((k) => [k, bySev[k]])
  )
})

const totalThreats = computed(() => {
  const bySev = props.stats?.threatCountBySeverity || {}
  return Object.values(bySev).reduce((a, b) => a + b, 0) || 1
})

function sevKey(sev) {
  const s = String(sev || '').toLowerCase()
  if (s.includes('crit')) return 'critical'
  if (s.includes('high')) return 'high'
  if (s.includes('med')) return 'medium'
  if (s.includes('low')) return 'low'
  if (s.includes('tbd') || s.includes('unassigned') || s === 'n/a') return 'tbd'
  return 'unknown'
}

function statusKey(status) {
  const s = String(status || '').toLowerCase()
  if (s.includes('mitigat')) return 'mitigated'
  if (s.includes('applicable') || s === 'na' || s === 'not applicable') return 'na'
  return 'open'
}

async function toggleOutOfScope(t, event) {
  const newVal = event.target.checked
  const threatId = t.threatId
  const oldVal = !!t.outOfScope
  if (newVal === oldVal) return
  if (!props.resultId || !threatId) {
    // 本地内存中暂存，本次会话未持久化
    t.outOfScope = newVal
    toast('本次会话未持久化，OOS 仅本地生效', 'warning')
    return
  }
  try {
    await updateThreatStatus(props.resultId, threatId, t.status || 'Open', {
      outOfScope: newVal,
    })
    t.outOfScope = newVal
    toast(`威胁 #${t.number} 已${newVal ? '标记' : '取消'}范围外`, 'success')
  } catch (e) {
    event.target.checked = oldVal
    toast('更新范围外失败：' + (e?.response?.data?.detail || e?.message), 'error')
  }
}

function dreadTotal(dread) {
  if (!dread) return 0
  const keys = ['damage', 'reproducibility', 'exploitability', 'affectedUsers', 'discoverability']
  return keys.reduce((a, k) => a + Number(dread[k] || 0), 0)
}

function dreadTitle(dread) {
  const map = {
    damage: '危害', reproducibility: '可重复性', exploitability: '可利用性',
    affectedUsers: '受影响面', discoverability: '可发现性',
  }
  return Object.entries(map)
    .map(([k, zh]) => `${zh}:${dread[k] || 0}`)
    .join('  ')
}

const DREAD_META = [
  { key: 'damage', label: '危害' },
  { key: 'reproducibility', label: '可重复性' },
  { key: 'exploitability', label: '可利用性' },
  { key: 'affectedUsers', label: '受影响面' },
  { key: 'discoverability', label: '可发现性' },
]

function dreadItems(dread) {
  if (!dread) return []
  return DREAD_META.map(({ key, label }) => {
    const val = Math.min(5, Number(dread[key] || 0))
    const lv = val >= 4 ? 'h' : val >= 2 ? 'm' : 'l'
    return { key, label, val, lv, pct: (val / 5) * 100 }
  })
}

async function changeStatus(t, event) {
  const status = event.target.value
  const oldStatus = t.status || 'Open'
  if (status === oldStatus) return
  if (!props.resultId) {
    toast('该威胁暂未关联可保存的结果（本次会话未保存），状态未持久化', 'warning')
    t.status = status
    return
  }
  const threatId = t.threatId
  if (!threatId) {
    toast('威胁缺少 ID，无法回写', 'warning')
    return
  }
  try {
    await updateThreatStatus(props.resultId, threatId, status, {
      outOfScope: !!t.outOfScope,
    })
    t.status = status
    toast(`威胁 #${t.number} 已标记为「${status}」`, 'success')
    emit('threat-updated', { threatId, status })
  } catch (e) {
    toast('更新状态失败：' + (e?.response?.data?.detail || e?.message), 'error')
    event.target.value = oldStatus
  }
}

function pct(sev) {
  return Math.max(4, Math.round(((severityOrdered.value[sev] || 0) / totalThreats.value) * 100))
}

const severitySummary = computed(() =>
  Object.entries(severityOrdered.value)
    .map(([k, v]) => `${tSeverity(k)}:${v}`)
    .join('  ')
)

function shortType(type) {
  const zh = tType(type)
  return zh.length > 8 ? zh.slice(0, 7) + '…' : zh
}

const visibleThreats = computed(() => {
  if (props.selectedThreats) return props.selectedThreats.threats || []
  if (!props.model) return []
  const diagram = props.model.detail?.diagrams?.[0]
  const all = []
  for (const cell of diagram?.cells || []) {
    for (const t of cell.threats || []) {
      all.push({ ...t, _cellName: cell.data?.name || '' })
    }
  }
  return all.sort((a, b) => (a.severityRank ?? 99) - (b.severityRank ?? 99))
})

function toggleExpand(t) {
  const key = t.threatId || `${t.number}-${t.title}`
  const set = new Set(expanded.value)
  if (set.has(key)) set.delete(key)
  else set.add(key)
  expanded.value = set
}

function isExpanded(t) {
  return expanded.value.has(t.threatId || `${t.number}-${t.title}`)
}
</script>

<style scoped>
.threat-panel {
  width: 100%;
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
  background: var(--bg-panel);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
}

/* —— 头部 —— */
.tp-head {
  display: flex;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  background: linear-gradient(180deg, var(--bg-panel-2), transparent);
}
.head-l {
  display: flex;
  align-items: center;
  gap: 11px;
}
.head-icon {
  width: 30px;
  height: 30px;
  display: grid;
  place-items: center;
  border-radius: 9px;
  background: linear-gradient(135deg, var(--danger-soft), var(--warning-soft));
  color: var(--danger);
  border: 1px solid var(--danger-border);
}
.head-text h3 {
  font-size: 14px;
  font-weight: 700;
  color: var(--text);
  line-height: 1.2;
}
.head-text p {
  font-size: 11px;
  color: var(--text-faint);
  margin-top: 2px;
}

/* —— KPI 卡片 —— */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 6px;
  padding: 12px 14px;
  border-bottom: 1px solid var(--border);
}
.kpi-card {
  background: var(--bg-panel-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 9px 4px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1px;
  transition: all 0.2s;
  position: relative;
  overflow: hidden;
}
.kpi-card::before {
  content: '';
  position: absolute;
  inset: 0;
  background: var(--primary-gradient-soft);
  opacity: 0;
  transition: opacity 0.2s;
}
.kpi-card:hover::before {
  opacity: 1;
}
.kpi-card > * {
  position: relative;
  z-index: 1;
}
.kpi-num {
  font-size: 18px;
  font-weight: 700;
  color: var(--primary);
  font-family: var(--font-mono);
  line-height: 1.1;
}
.kpi-lbl {
  font-size: 10.5px;
  color: var(--text-faint);
}
.kpi-card.danger .kpi-num { color: var(--danger); }
.kpi-card.danger {
  background: var(--danger-soft);
  border-color: var(--danger-border);
}
.kpi-card.danger::before {
  background: var(--danger-soft);
  opacity: 1;
}

/* —— 分布 —— */
.distribution {
  padding: 12px 14px;
  border-bottom: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 9px;
}
.dist-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 11px;
}
.dist-label {
  color: var(--text-faint);
  width: 64px;
  flex-shrink: 0;
  font-weight: 500;
}
.bars {
  flex: 1;
  height: 8px;
  background: var(--bg-panel-2);
  border-radius: 4px;
  overflow: hidden;
  display: flex;
  gap: 2px;
  border: 1px solid var(--border);
}
.bar {
  height: 100%;
  border-radius: 2px;
  transition: width 0.4s cubic-bezier(0.4, 0, 0.2, 1);
  min-width: 2px;
}
.bar.sev-critical { background: linear-gradient(90deg, var(--critical), #b91c1c); }
.bar.sev-high { background: linear-gradient(90deg, var(--danger), #dc2626); }
.bar.sev-medium { background: linear-gradient(90deg, var(--medium), #ea580c); }
.bar.sev-low { background: linear-gradient(90deg, var(--low), #0ea5e9); }
.bar.sev-tbd { background: var(--border-strong); }
.bar.sev-unknown { background: var(--text-faint); }
.dist-detail {
  color: var(--text-faint);
  white-space: nowrap;
  font-family: var(--font-mono);
  font-size: 10.5px;
}
.type-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  flex: 1;
}
.chip {
  font-size: 11px;
  padding: 2px 8px;
  border-radius: var(--radius-pill);
  background: var(--bg-panel-2);
  border: 1px solid var(--border-light);
  color: var(--text-dim);
  transition: all 0.2s;
}
.chip:hover {
  border-color: var(--primary-border);
  color: var(--text);
}
.chip b {
  color: var(--primary);
  font-weight: 700;
  margin-left: 3px;
}

/* —— 列表头 —— */
.list-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 11px 14px 6px;
}
.list-head h3 {
  font-size: 12.5px;
  font-weight: 700;
  color: var(--text);
  letter-spacing: 0.2px;
}

/* —— 威胁列表 —— */
.threat-list {
  flex: 1;
  overflow-y: auto;
  padding: 0 14px 14px;
  display: flex;
  flex-direction: column;
  gap: 7px;
}
.threat-item {
  background: var(--bg-panel-2);
  border: 1px solid var(--border);
  border-left-width: 3px;
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
}
.threat-item:hover {
  background: var(--bg-active);
  border-color: var(--primary-border);
  transform: translateY(-1px);
  box-shadow: var(--shadow-sm);
}
.threat-item.sev-critical { border-left-color: var(--critical); }
.threat-item.sev-high { border-left-color: var(--danger); }
.threat-item.sev-medium { border-left-color: var(--medium); }
.threat-item.sev-low { border-left-color: var(--low); }
.threat-item.sev-tbd { border-left-color: var(--border-strong); }
.threat-item.sev-unknown { border-left-color: var(--text-faint); }
.threat-head {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 8px 10px;
}
.sev-badge {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 7px;
  border-radius: var(--radius-pill);
  flex-shrink: 0;
  letter-spacing: 0.2px;
}
.sev-badge.sev-critical {
  background: var(--critical-soft);
  color: var(--critical);
  border: 1px solid var(--critical-border);
}
.sev-badge.sev-high {
  background: var(--danger-soft);
  color: var(--danger);
  border: 1px solid var(--danger-border);
}
.sev-badge.sev-medium {
  background: var(--medium-soft);
  color: var(--medium);
  border: 1px solid var(--warning-border);
}
.sev-badge.sev-low {
  background: var(--low-soft);
  color: var(--low);
  border: 1px solid var(--low-border);
}
.sev-badge.sev-tbd {
  background: var(--bg-hover);
  color: var(--text-dim);
  border: 1px solid var(--border-light);
}
.status-select-inline {
  font-size: 10.5px;
  font-weight: 600;
  padding: 2px 16px 2px 8px;
  border-radius: var(--radius-pill);
  flex-shrink: 0;
  cursor: pointer;
  outline: none;
  appearance: none;
  -webkit-appearance: none;
  background-image: linear-gradient(45deg, transparent 50%, currentColor 50%),
                    linear-gradient(135deg, currentColor 50%, transparent 50%);
  background-position: calc(100% - 9px) 50%, calc(100% - 6px) 50%;
  background-size: 3px 3px, 3px 3px;
  background-repeat: no-repeat;
}
.status-select-inline.status-open {
  background-color: var(--primary-soft);
  color: var(--primary);
  border: 1px solid var(--primary-border);
}
.status-select-inline.status-mitigated {
  background-color: var(--success-soft);
  color: var(--success);
  border: 1px solid var(--success-border);
}
.status-select-inline.status-na {
  background-color: var(--bg-hover);
  color: var(--text-dim);
  border: 1px solid var(--border-light);
}
.status-select-inline:focus {
  outline: 2px solid var(--primary);
  outline-offset: 1px;
}
.oos-toggle-inline {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  font-size: 10.5px;
  font-weight: 600;
  padding: 2px 9px;
  border-radius: var(--radius-pill);
  background: var(--bg-panel-2);
  border: 1px solid var(--border-light);
  color: var(--text-dim);
  cursor: pointer;
  user-select: none;
  flex-shrink: 0;
  transition: all 0.15s;
}
.oos-toggle-inline input {
  position: absolute;
  opacity: 0;
  pointer-events: none;
  width: 0;
  height: 0;
}
.oos-toggle-inline.active {
  background: var(--bg-hover);
  color: var(--text-faint);
  border-color: var(--border-strong);
  border-style: dashed;
}
.oos-toggle-inline:hover {
  border-color: var(--primary-border);
  color: var(--primary);
}
.threat-type {
  font-size: 10px;
  color: var(--primary);
  background: var(--primary-soft);
  border-radius: 4px;
  padding: 1px 6px;
  flex-shrink: 0;
  font-weight: 700;
  min-width: 18px;
  text-align: center;
  font-family: var(--font-mono);
}
.threat-title {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 12.5px;
  color: var(--text);
  line-height: 1.4;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 500;
}
.threat-title .t-num {
  font-family: var(--font-mono);
  font-size: 10.5px;
  color: var(--text-faint);
  flex-shrink: 0;
}
.threat-title.is-out-of-scope span:nth-child(2) {
  color: var(--text-faint);
  text-decoration: line-through;
}
.expand-arrow {
  font-size: 10px;
  color: var(--text-faint);
  transition: transform 0.2s;
}
.expand-arrow.open {
  transform: rotate(180deg);
  color: var(--primary);
}
.threat-detail {
  padding: 0 10px 10px;
  border-top: 1px dashed var(--border);
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding-top: 10px;
  margin-top: -2px;
}
.detail-block {
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.detail-label {
  font-size: 10.5px;
  color: var(--text-faint);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.detail-block p {
  font-size: 12px;
  color: var(--text-dim);
  line-height: 1.6;
}
.detail-meta {
  display: flex;
  gap: 10px;
  font-size: 11px;
  color: var(--text-faint);
  flex-wrap: wrap;
  padding-top: 4px;
  border-top: 1px dashed var(--border);
}
.cwe-badge {
  font-family: var(--font-mono);
  font-size: 10.5px;
  font-weight: 600;
  color: var(--warning);
  background: var(--warning-soft);
  border: 1px solid var(--warning-border);
  border-radius: 4px;
  padding: 0 6px;
}
.dread-badge {
  font-family: var(--font-mono);
  font-size: 10.5px;
  font-weight: 600;
  color: var(--accent-violet);
  background: rgba(124, 58, 237, 0.10);
  border: 1px solid rgba(124, 58, 237, 0.30);
  border-radius: 4px;
  padding: 0 6px;
}
.dread-detail {
  display: flex;
  flex-direction: column;
  gap: 6px;
  border: 1px solid rgba(124, 58, 237, 0.25);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
  background: rgba(124, 58, 237, 0.04);
}
.dread-grid {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.dread-item {
  display: flex;
  align-items: center;
  gap: 8px;
}
.dread-name {
  font-size: 11px;
  color: var(--text-dim);
  width: 58px;
  flex-shrink: 0;
}
.dread-track {
  flex: 1;
  height: 7px;
  background: var(--bg-hover);
  border-radius: 3px;
  overflow: hidden;
  border: 1px solid var(--border-light);
}
.dread-fill {
  display: block;
  height: 100%;
  border-radius: 3px;
  transition: width 0.3s;
}
.dread-fill.dread-lv-h {
  background: linear-gradient(90deg, var(--danger), #f87171);
}
.dread-fill.dread-lv-m {
  background: linear-gradient(90deg, var(--warning), #fbbf24);
}
.dread-fill.dread-lv-l {
  background: linear-gradient(90deg, var(--success), #34d399);
}
.dread-val {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-dim);
  width: 30px;
  text-align: right;
}
.ref-list {
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.ref-link {
  font-size: 11px;
  color: var(--primary);
  text-decoration: none;
  word-break: break-all;
  line-height: 1.4;
  padding: 2px 6px;
  background: var(--primary-soft);
  border-radius: 4px;
}
.ref-link:hover {
  text-decoration: underline;
  background: var(--primary-soft);
}
.no-threats {
  text-align: center;
  color: var(--text-faint);
  font-size: 12.5px;
  padding: 36px 10px;
  border: 1px dashed var(--border-light);
  border-radius: var(--radius-sm);
  display: flex;
  flex-direction: column;
  gap: 6px;
  align-items: center;
}
.no-threats .nt-icon {
  width: 44px;
  height: 44px;
  border-radius: 50%;
  background: var(--success-soft);
  color: var(--success);
  display: grid;
  place-items: center;
  font-size: 22px;
  font-weight: 700;
  margin-bottom: 4px;
  border: 1px solid var(--success-border);
}
.no-threats span {
  font-size: 11.5px;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.25s;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>