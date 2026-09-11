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
          <!-- 副标题里的 "N 项威胁已识别" 与下方 KPI 的 threatCount 卡片重复，
               移除副标题数字；仅在未加载数据时显示引导文字。 -->
          <p v-if="!stats">点击图中节点查看威胁</p>
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
        v-if="resultId"
        class="btn btn-sm btn-add-threat"
        title="AI 识别可能有遗漏，手工补充一条威胁"
        @click="openAddThreat"
      >
        + 新增威胁
      </button>
      <button
        v-if="selectedThreats"
        class="btn btn-sm"
        @click="$emit('clear-selection')"
      >
        全部
      </button>
    </div>

    <!-- 评审进度：回答「这份模型的评审做完了吗」 -->
    <div v-if="reviewProgress.total" class="review-progress">
      <div class="rp-bar">
        <div class="rp-fill" :style="{ width: (reviewProgress.rate * 100).toFixed(1) + '%' }"></div>
      </div>
      <div class="rp-text">
        评审进度 {{ reviewProgress.reviewed }}/{{ reviewProgress.total }}
        <span v-if="reviewProgress.pending" class="rp-pending">· {{ reviewProgress.pending }} 条待评审</span>
        <span v-else class="rp-done">· 已全部评审</span>
      </div>
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
              <option value="NotApplicable">不适用</option>
            </select>
            <span class="threat-type" :title="t.type">{{ shortType(t.type) }}</span>
            <span class="threat-title" :class="{ 'is-out-of-scope': t.outOfScope }">
              <span class="t-num">#{{ t.number }}</span>
              <span>{{ t.title }}</span>
            </span>
            <!-- 评审结论徽标：待评审 / 已确认 / 已驳回 -->
            <span
              class="review-badge"
              :class="'rv-' + reviewState(t)"
              :title="reviewTitle(t)"
              @click.stop
            >
              {{ reviewLabel(t) }}
            </span>
            <!-- 评审操作：一键确认 / 驳回（AI 误报需要人工推翻） -->
            <span v-if="resultId" class="review-actions" @click.stop>
              <button
                class="rv-btn rv-ok"
                :class="{ active: reviewState(t) === 'Confirmed' }"
                title="确认威胁成立，推进整改"
                :disabled="reviewingId === threatKey(t)"
                @click="submitReview(t, 'Confirmed')"
              >
                ✓
              </button>
              <button
                class="rv-btn rv-no"
                :class="{ active: reviewState(t) === 'Rejected' }"
                title="驳回：误报或经评估不成立"
                :disabled="reviewingId === threatKey(t)"
                @click="submitReview(t, 'Rejected')"
              >
                ✕
              </button>
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
                    <span class="dread-val">{{ d.val }}/10</span>
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
              <!-- 转漏洞工单：把威胁推进到漏洞管理的整改流程 -->
              <div v-if="resultId" class="detail-actions">
                <button
                  class="btn-to-vuln"
                  :disabled="converting.has(t.threatId)"
                  :title="vulnLinkOf(t) ? '已转为漏洞单，点击可再次提交（会自动去重）' : '在漏洞管理中创建一条整改工单'"
                  @click.stop="convertToVuln(t)"
                >
                  <template v-if="converting.has(t.threatId)">提交中…</template>
                  <template v-else-if="vulnLinkOf(t)">已转漏洞单 #{{ vulnLinkOf(t) }}</template>
                  <template v-else>转漏洞工单</template>
                </button>
                <span v-if="vulnLinkOf(t)" class="to-vuln-hint">已推送至漏洞管理</span>
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

    <!-- 手工新增威胁弹窗 -->
    <div v-if="addVisible" class="tp-modal-mask" @click.self="closeAddThreat">
      <div class="tp-modal">
        <div class="tp-modal-head">
          <h3>新增威胁</h3>
          <button class="tp-modal-close" @click="closeAddThreat">×</button>
        </div>
        <div class="tp-modal-body">
          <p class="tp-modal-hint">
            AI 识别可能有遗漏，可在此补充你发现的威胁。新增的威胁会标记为「手工录入」。
          </p>
          <div class="tp-field">
            <label class="tp-field-lbl">挂载元素 <i>*</i></label>
            <select v-model="addForm.elementId" class="tp-input">
              <option value="">请选择组件或数据流…</option>
              <option v-for="e in elementOptions" :key="e.id" :value="e.id">
                {{ e.name }}（{{ e.kind }}）
              </option>
            </select>
          </div>
          <div class="tp-field">
            <label class="tp-field-lbl">威胁标题 <i>*</i></label>
            <input v-model="addForm.title" class="tp-input" type="text" maxlength="300" placeholder="如：订单接口未做水平越权校验" />
          </div>
          <div class="tp-field-row">
            <div class="tp-field">
              <label class="tp-field-lbl">威胁类型</label>
              <input v-model="addForm.type" class="tp-input" type="text" placeholder="如 Spoofing" />
            </div>
            <div class="tp-field">
              <label class="tp-field-lbl">严重度</label>
              <select v-model="addForm.severity" class="tp-input">
                <option value="Critical">严重</option>
                <option value="High">高</option>
                <option value="Medium">中</option>
                <option value="Low">低</option>
              </select>
            </div>
          </div>
          <div class="tp-field">
            <label class="tp-field-lbl">描述</label>
            <textarea v-model="addForm.description" class="tp-textarea" rows="3" placeholder="威胁的触发条件与影响…"></textarea>
          </div>
          <div class="tp-field">
            <label class="tp-field-lbl">缓解措施</label>
            <textarea v-model="addForm.mitigation" class="tp-textarea" rows="3" placeholder="建议的整改方案…"></textarea>
          </div>
        </div>
        <div class="tp-modal-foot">
          <button class="btn btn-sm" @click="closeAddThreat">取消</button>
          <button
            class="btn btn-sm btn-primary"
            :disabled="adding || !addForm.elementId || !addForm.title.trim()"
            @click="submitAddThreat"
          >{{ adding ? '提交中…' : '新增' }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick } from 'vue'
import Toast from './Toast.vue'
import { updateThreatStatus, convertThreatToVuln, addThreat, reviewThreat } from '@/api/threat.js'
import { tSeverity, tStatus, tType, tMethodology } from '../../utils/i18n.js'

const toastRef = ref(null)
const toast = (msg, type = 'info') => toastRef.value?.toast(msg, type)

const props = defineProps({
  model: { type: Object, default: null },
  stats: { type: Object, default: null },
  selectedCellId: { type: String, default: null },
  selectedThreats: { type: Object, default: null },
  resultId: { type: String, default: null },
  // 当前登录用户（用于评审后本地回显评审人，避免整页刷新）
  currentUser: { type: Object, default: null },
})
const emit = defineEmits(['clear-selection', 'threat-updated'])

const expanded = ref(new Set())
const listRef = ref(null)

// 正在提交「转漏洞单」的威胁 ID 集合（按 threatId 逐个禁用按钮）
const converting = ref(new Set())
// 已成功转出的漏洞单：threatId -> vuln_id，用于按钮回显与防重复点击
const vulnLinks = ref({})

function vulnLinkOf(t) {
  return vulnLinks.value[t?.threatId] || null
}

/** 把一条威胁推送到漏洞管理模块，创建整改工单 */
async function convertToVuln(t) {
  const threatId = t?.threatId
  if (!props.resultId || !threatId) {
    toast('缺少结果或威胁标识，无法转单', 'error')
    return
  }
  if (converting.value.has(threatId)) return
  converting.value = new Set(converting.value).add(threatId)
  try {
    const res = await convertThreatToVuln(props.resultId, threatId, { skip_duplicate: true })
    vulnLinks.value = { ...vulnLinks.value, [threatId]: res.vuln_id }
    if (res.created) {
      toast(`已转为漏洞单 #${res.vuln_id}：${res.title}`, 'success')
    } else {
      toast(`该威胁已存在未关闭的漏洞单 #${res.vuln_id}，未重复创建`, 'info')
    }
    emit('threat-updated', { threatId, vulnId: res.vuln_id })
  } catch (e) {
    toast('转漏洞单失败：' + (e?.response?.data?.detail || e?.message), 'error')
  } finally {
    const next = new Set(converting.value)
    next.delete(threatId)
    converting.value = next
  }
}

watch(
  () => props.selectedCellId,
  () => {
    expanded.value = new Set()
    nextTick(() => {
      if (listRef.value) listRef.value.scrollTop = 0
    })
  }
)

// ---- 手工新增威胁 ----
const addVisible = ref(false)
const adding = ref(false)
const addForm = ref({
  elementId: '', title: '', type: '', severity: 'Medium',
  description: '', mitigation: '',
})

/**
 * 可作为威胁挂载点的元素清单。
 * 与后端 ``extract_threats`` 一致：组件与数据流（边）都可以挂威胁。
 * 注意取值用元素「名称」而非 cell.id —— 后端 ``_find_cell_by_element``
 * 先按 id 匹配、再按名称兜底，名称更稳定（cell.id 每次建模都会变）。
 */
const elementOptions = computed(() => {
  const cells = props.model?.detail?.diagrams?.[0]?.cells || []
  const rows = []
  for (const cell of cells) {
    if (cell.shape === 'tm.Text') continue
    const name = (cell.data?.name || '').trim()
    if (!name) continue
    // 跳过后端自动补的空 trust boundary（没有子元素）
    const isBoundary = cell.shape === 'tm.BoundaryBox'
    if (isBoundary && !(cell.children || []).length) continue
    const isEdge = !!(cell.source || cell.target)
    rows.push({ id: name, name, kind: isEdge ? '数据流' : '组件' })
  }
  return rows
})

function openAddThreat() {
  addForm.value = {
    // 若用户在画布上选中了某个组件，默认挂到它下面（selectedThreats 是 prop）
    elementId: props.selectedThreats?.cellName || '',
    title: '', type: '', severity: 'Medium', description: '', mitigation: '',
  }
  addVisible.value = true
}

function closeAddThreat() {
  addVisible.value = false
}

async function submitAddThreat() {
  if (!props.resultId || !addForm.value.elementId || !addForm.value.title.trim()) return
  adding.value = true
  try {
    await addThreat(props.resultId, {
      element_id: addForm.value.elementId,
      title: addForm.value.title.trim(),
      type: addForm.value.type.trim() || undefined,
      severity: addForm.value.severity,
      description: addForm.value.description,
      mitigation: addForm.value.mitigation,
    })
    toast('威胁已新增', 'success')
    closeAddThreat()
    emit('threat-updated', { added: true })
  } catch (e) {
    toast('新增失败：' + (e?.response?.data?.detail || e?.message), 'error')
  } finally {
    adding.value = false
  }
}

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

// ---- 威胁评审（确认 / 驳回）----
// AI 识别的威胁必然含误报，需要人工确认或推翻，否则噪音会淹没真实风险。
// 评审结论（review）与处置状态（status）正交：确认威胁成立 ≠ 已经缓解。
const reviewingId = ref('')

/** 威胁的唯一标识（后端 threatId 优先，兜底用序号+标题） */
function threatKey(t) {
  return t.threatId || `${t.number}-${t.title}`
}

/**
 * 评审进度统计（前端本地算，不额外请求后端）。
 * 与后端 ``review_summary`` 口径一致：未评审的威胁视为 Pending。
 */
const reviewProgress = computed(() => {
  const list = allThreats.value
  let confirmed = 0
  let rejected = 0
  for (const t of list) {
    const s = reviewState(t)
    if (s === 'Confirmed') confirmed += 1
    else if (s === 'Rejected') rejected += 1
  }
  const reviewed = confirmed + rejected
  const total = list.length
  return {
    total,
    confirmed,
    rejected,
    reviewed,
    pending: total - reviewed,
    rate: total ? reviewed / total : 0,
  }
})

/** 当前评审结论，未评审时视为 Pending */
function reviewState(t) {
  const s = t.review?.state
  return s === 'Confirmed' || s === 'Rejected' ? s : 'Pending'
}

function reviewLabel(t) {
  const s = reviewState(t)
  if (s === 'Confirmed') return '已确认'
  if (s === 'Rejected') return '已驳回'
  return '待评审'
}

function reviewTitle(t) {
  const r = t.review
  if (!r?.state) return '待评审：请确认威胁是否成立'
  const who = r.reviewer ? `，评审人 ${r.reviewer}` : ''
  const when = r.reviewed_at ? `，${fmtReviewTime(r.reviewed_at)}` : ''
  const cmt = r.comment ? `\n意见：${r.comment}` : ''
  return `${reviewLabel(t)}${who}${when}${cmt}`
}

function fmtReviewTime(epoch) {
  if (!epoch) return ''
  const d = new Date(epoch * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

/**
 * 提交评审结论。
 *
 * 驳回时会弹出输入框收集原因 —— 驳回理由对后续复盘（"当初为什么判为误报"）
 * 很有价值，留空也允许提交。
 */
async function submitReview(t, state) {
  if (!props.resultId) return
  const key = threatKey(t)
  // 再次点击同一结论视为取消评审（回到待评审）
  const next = reviewState(t) === state ? 'Pending' : state

  let comment = ''
  if (next === 'Rejected') {
    const input = window.prompt('驳回原因（可选，便于后续复盘）：', t.review?.comment || '')
    // 用户点取消 → 放弃本次操作
    if (input === null) return
    comment = input
  }

  reviewingId.value = key
  try {
    await reviewThreat(props.resultId, key, next, comment)
    // 本地同步，避免整页刷新（评审是高频轻量操作）
    applyReviewLocally(t, next, comment)
    const tip = next === 'Pending' ? '已取消评审' : next === 'Confirmed' ? '已确认该威胁' : '已驳回该威胁'
    toast(tip, 'success')
    emit('threat-updated', { reviewed: true, state: next })
  } catch (e) {
    toast('评审失败：' + (e?.response?.data?.detail || e?.message), 'error')
  } finally {
    reviewingId.value = ''
  }
}

/** 把评审结果写回 store 中的模型（保持前端状态与后端一致） */
function applyReviewLocally(t, state, comment) {
  const me = props.currentUser || {}
  const cells = props.model?.detail?.diagrams?.[0]?.cells || []
  for (const cell of cells) {
    for (const threat of cell.threats || []) {
      if (threatKey(threat) !== threatKey(t)) continue
      if (state === 'Pending') {
        threat.review = null
      } else {
        threat.review = {
          state,
          comment: comment || '',
          reviewer: me.username || '',
          reviewed_at: Math.floor(Date.now() / 1000),
        }
        // 与后端一致：驳回的威胁同步收敛状态，不再计入待处理
        if (state === 'Rejected') threat.status = 'NotApplicable'
      }
      return
    }
  }
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

// 后端 DREAD 每维取值 0~10（见 output_schema.py 的 dread 字段定义），单维满分 10，总分 50。
const DREAD_MAX_PER_DIM = 10

function dreadItems(dread) {
  if (!dread) return []
  return DREAD_META.map(({ key, label }) => {
    const val = Math.min(DREAD_MAX_PER_DIM, Math.max(0, Number(dread[key] || 0)))
    // 分级阈值：>=7 高、>=4 中、其余低（对应单维 10 分制）
    const lv = val >= 7 ? 'h' : val >= 4 ? 'm' : 'l'
    return { key, label, val, lv, pct: (val / DREAD_MAX_PER_DIM) * 100 }
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

/**
 * 模型中的全部威胁（不受画布选中过滤影响）。
 * 评审进度必须以「全部威胁」为分母，否则选中单个组件时进度条会失真。
 */
const allThreats = computed(() => {
  const diagram = props.model?.detail?.diagrams?.[0]
  const all = []
  for (const cell of diagram?.cells || []) {
    for (const t of cell.threats || []) {
      all.push({ ...t, _cellName: cell.data?.name || '' })
    }
  }
  return all
})

const visibleThreats = computed(() => {
  if (props.selectedThreats) return props.selectedThreats.threats || []
  if (!props.model) return []
  return [...allThreats.value].sort(
    (a, b) => (a.severityRank ?? 99) - (b.severityRank ?? 99)
  )
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
  /* 外层 .analysis-col 已带边框圆角，这里不再叠加描边/圆角，
     避免出现"卡片套卡片"的双层视觉重复。 */
  background: var(--bg-panel);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
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
  /* 行间留 9px（原来 7）：右栏 380px 里塞 9 个控件本来就挤，
     行间距再小就"贴一起"，跟上面 KPI/分布横排的留白节奏不一致。 */
  gap: 9px;
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
  /* 行内元素间距从 7px → 6px：9 个控件挤一行时再宽就溢出换行，
     但 6 比 7 略紧凑，避免相邻 chip 视觉粘连。 */
  gap: 6px;
  /* 行内上下 8/10 → 9/12：让行高略增、左右扩 2px，
     跟 KPI 卡和评审进度的留白节奏统一。 */
  padding: 9px 12px;
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
.detail-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  padding-top: 8px;
  border-top: 1px dashed var(--border-light);
}
.btn-to-vuln {
  font-size: 11.5px;
  font-weight: 500;
  font-family: inherit;
  color: var(--accent-violet);
  background: rgba(124, 58, 237, 0.08);
  border: 1px solid rgba(124, 58, 237, 0.32);
  border-radius: var(--radius-sm);
  padding: 4px 10px;
  cursor: pointer;
  transition: background 0.15s, border-color 0.15s;
}
.btn-to-vuln:hover:not(:disabled) {
  background: rgba(124, 58, 237, 0.16);
  border-color: rgba(124, 58, 237, 0.55);
}
.btn-to-vuln:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
.to-vuln-hint {
  font-size: 10.5px;
  color: var(--text-faint);
}

/* ---- 评审进度条 ---- */
.review-progress {
  padding: 7px 12px 6px;
  border-bottom: 1px solid var(--border-light);
  flex-shrink: 0;
}
.rp-bar {
  height: 4px;
  border-radius: 2px;
  background: rgba(148, 163, 184, 0.25);
  overflow: hidden;
}
.rp-fill {
  height: 100%;
  border-radius: 2px;
  background: linear-gradient(90deg, #7c3aed, #047857);
  transition: width 0.3s ease;
}
.rp-text {
  margin-top: 4px;
  font-size: 10.5px;
  color: var(--text-faint);
}
.rp-pending { color: var(--warning, #d97706); }
.rp-done { color: #047857; }

/* ---- 威胁评审（确认 / 驳回）---- */
.review-badge {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 3px;
  white-space: nowrap;
  flex-shrink: 0;
  border: 1px solid transparent;
  cursor: help;
}
.rv-Pending {
  color: var(--text-faint);
  background: rgba(148, 163, 184, 0.12);
  border-color: rgba(148, 163, 184, 0.3);
}
.rv-Confirmed {
  color: #047857;
  background: rgba(4, 120, 87, 0.1);
  border-color: rgba(4, 120, 87, 0.3);
}
.rv-Rejected {
  color: #b91c1c;
  background: rgba(185, 28, 28, 0.1);
  border-color: rgba(185, 28, 28, 0.28);
}
.review-actions {
  display: inline-flex;
  gap: 3px;
  flex-shrink: 0;
}
.rv-btn {
  width: 20px;
  height: 20px;
  padding: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  line-height: 1;
  border-radius: 4px;
  border: 1px solid var(--border-light);
  background: var(--bg-panel);
  color: var(--text-faint);
  cursor: pointer;
}
.rv-btn:disabled { opacity: 0.45; cursor: not-allowed; }
.rv-ok:hover:not(:disabled), .rv-ok.active { color: #047857; border-color: #047857; }
.rv-no:hover:not(:disabled), .rv-no.active { color: #b91c1c; border-color: #b91c1c; }

/* ---- 手工新增威胁弹窗 ---- */
.btn-add-threat { color: var(--accent-violet); }
.tp-modal-mask {
  position: fixed; inset: 0; z-index: 1000;
  background: rgba(0, 0, 0, 0.45);
  backdrop-filter: blur(3px); -webkit-backdrop-filter: blur(3px);
  display: flex; align-items: center; justify-content: center;
}
.tp-modal {
  width: 520px; max-width: 92vw; max-height: 86vh;
  display: flex; flex-direction: column;
  background: var(--bg-panel); border-radius: var(--radius);
  border: 1px solid var(--border-light);
  box-shadow: 0 18px 48px rgba(0, 0, 0, 0.28);
  overflow: hidden;
}
.tp-modal-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 16px; border-bottom: 1px solid var(--border-light);
}
.tp-modal-head h3 { margin: 0; font-size: 13.5px; color: var(--text); }
.tp-modal-close {
  border: none; background: none; cursor: pointer;
  font-size: 18px; line-height: 1; color: var(--text-faint); padding: 0 4px;
}
.tp-modal-close:hover { color: var(--danger); }
.tp-modal-body { padding: 14px 16px; overflow-y: auto; }
.tp-modal-hint {
  font-size: 11px; color: var(--text-faint);
  margin: 0 0 12px; line-height: 1.5;
}
.tp-field { display: flex; flex-direction: column; gap: 4px; margin-bottom: 10px; flex: 1; }
.tp-field-row { display: flex; gap: 10px; }
.tp-field-lbl { font-size: 11px; color: var(--text-dim); font-weight: 500; }
.tp-field-lbl i { color: var(--danger); font-style: normal; }
.tp-input, .tp-textarea {
  width: 100%; box-sizing: border-box;
  font-family: inherit; font-size: 12px;
  padding: 6px 9px; border-radius: var(--radius-sm);
  border: 1px solid var(--border-light);
  background: var(--bg); color: var(--text);
}
.tp-textarea { resize: vertical; line-height: 1.5; }
.tp-input:focus, .tp-textarea:focus { outline: none; border-color: var(--primary); }
.tp-modal-foot {
  display: flex; justify-content: flex-end; gap: 8px;
  padding: 10px 16px; border-top: 1px solid var(--border-light);
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