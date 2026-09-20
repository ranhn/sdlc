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
               移除副标题数字；仅在未加载数据时显示引导文字。
               文案改为「等待建模结果」，因为新建模进行中时 stats 也是 null，
               此时画布里没节点可点，"点击图中节点"会误导用户。 -->
          <p v-if="!stats">等待建模结果</p>
        </div>
      </div>
    </header>

    <!-- 画布规模总览：原在 DFD 画布工具条上，按反馈移到「威胁分析」标题下 ——
         这 4 个数字讲的正是本面板要分析的那张图（多大 / 多少流 / 多少威胁 /
         覆盖到什么程度），放在这里比挂在画布工具条上更贴近阅读路径。
         数据源与留在工具条时完全一致（ThreatModeling 的 graphStats：优先取
         lastSummary.stats，缺字段时按模型 cells 兜底）。 -->
    <div v-if="graphStats && model" class="tp-stats" :title="statsTitle">
      <span class="tps-item">
        <i class="tps-dot node" />{{ graphStats.nodes }} 节点
      </span>
      <span class="tps-sep" />
      <span class="tps-item">
        <i class="tps-dot flow" />{{ graphStats.flows }} 数据流
      </span>
      <span class="tps-sep" />
      <span class="tps-item threat" :class="{ zero: !graphStats.threats }">
        <i class="tps-dot threat" />{{ graphStats.threats }} 威胁
      </span>
      <template v-if="graphStats.coverage != null">
        <span class="tps-sep" />
        <span class="tps-item cover">
          <i class="tps-dot cover" />覆盖 {{ graphStats.coverage }}%
        </span>
      </template>
    </div>

    
    


      <!-- 威胁类别（STRIDE 维度）单卡片展示。
           严重度统计已并到下方列表头，概览区只剩这张卡片。
           v-if="stats" 必须保留：stats 为 null 时读 threatCountByType 会抛错。 -->
      <div v-if="stats" class="ov-card ov-card-solo">
        <div class="ov-head">
          <span class="ov-title">威胁类别</span>
          <span class="ov-total">{{ typeCount }} 类</span>
        </div>
        <div class="type-list">
          <span
            v-for="(count, type) in stats.threatCountByType || {}"
            :key="type"
            class="type-row"
            :title="type"
          >
            <span class="type-name">{{ shortType(type) }}</span>
            <span class="type-track"><i :style="{ width: typePct(count) + '%' }" /></span>
            <b class="type-num">{{ count }}</b>
          </span>
        </div>
      </div>

    <!-- 列表头 + 快捷筛选：整块 sticky，威胁很多时向下滚动依然能切换筛选 -->
    <div class="list-head-sticky">
      <div class="list-head">
        <h3 v-if="selectedThreats">{{ selectedThreats.cellName }} 的威胁</h3>
        <h3 v-else>威胁列表</h3>
        <div class="list-head-actions">
          <!-- 取消定位：清空父子组件的 selectedCellId → 画布取消高亮、
               列表恢复全量。定位态下才出现（未定位时无需此按钮）。 -->
          <button
            v-if="selectedThreats"
            class="btn btn-sm btn-clear-locate"
            title="取消画布定位，列表恢复显示全部威胁"
            @click="$emit('clear-selection')"
          >
            取消定位
          </button>
          <button
            v-if="resultId"
            class="btn btn-sm btn-add-threat"
            title="AI 识别可能有遗漏，手工补充一条威胁"
            @click="openAddThreat"
          >
            + 新增威胁
          </button>
        </div>
      </div>

      <!-- 筛选条（单行）：快捷筛选（全部/未缓解/待评审） │ 严重度（4 个等级 pill）。
           顺序上快捷筛选在前、严重度在后；两组正交可叠加。
           已移除原快捷筛选里的"高危"：它与严重度 pill 的"高危"口径不同
           （前者按 critical+high 聚合的 38，后者是 stats 里 High 的 29），
           同屏出现两个高危数字会让用户以为数据错乱。 -->
      <div v-if="stats || allThreats.length" class="filter-bar">
        <!-- 组一：快捷筛选（状态 / 处置维度） -->
        <div v-if="allThreats.length" class="filter-group qf-group">
          <button
            v-for="f in filterTabs"
            :key="f.key"
            class="qf-chip"
            :class="{ active: listFilter === f.key, zero: !f.n }"
            :disabled="!f.n && listFilter !== f.key"
            :title="`${f.full}（${f.n} 条）`"
            @click="setListFilter(f.key)"
          >
            {{ f.label }}
            <b>{{ f.n }}</b>
          </button>
        </div>

        <!-- 分隔竖线：两组同时存在时才显示 -->
        <span v-if="stats && allThreats.length" class="filter-divider" aria-hidden="true" />

        <!-- 组二：严重度（等级维度）。点击切换 / 取消，联动列表实时过滤 -->
        <div v-if="stats" class="filter-group sev-group">
          <button
            v-for="lvl in severityLevels"
            :key="lvl.key"
            class="sev-pill"
            :class="['sev-' + lvl.key, { active: severityFilter === lvl.key, zero: !lvl.count }]"
            :title="severityFilter === lvl.key ? `取消「${lvl.label}」筛选` : `只看「${lvl.label}」`"
            @click="toggleSeverityFilter(lvl.key)"
          >
            <span class="sev-name">{{ lvl.label }}</span>
            <span class="sev-count">{{ lvl.count }}</span>
          </button>
        </div>
      </div>
    </div>

    <!-- "已评估"进度合并到下方威胁列表头的 filter tab 单点显示，
         不在 .priority-strip 重复（reviewProgress.reviewed 14 vs filterTabs 统计 108
         两边数字来源不同，会让用户怀疑数据错乱）。 -->

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
            <!-- 第一行：严重度 + 编号 + 标题 + 展开箭头 -->
            <div class="threat-row threat-row-main">
              <span class="sev-badge" :class="'sev-' + sevKey(t.severity)">
                {{ tSeverity(t.severity) }}
              </span>
              <span class="threat-title" :class="{ 'is-out-of-scope': t.outOfScope }">
                <span class="t-num">#{{ t.number }}</span>
                <span class="threat-title-text">{{ t.title }}</span>
              </span>
              <!-- 定位到画布：点这个按钮立即让父组���设置 selectedCellId → 画布高亮对应 cell。
                   @click.stop 避免触发外层 toggleExpand。
                   选中态（绑定到 props.selectedCellId）由 ThreatModeling.vue 控制。
                   v-if="t._cellId" 排除没有 _cellId 的条目（如手工新增时 elementId 输入的不是真实 cell id）。 -->
              <button
                v-if="t._cellId"
                class="locate-btn"
                :class="{ active: String(t._cellId) === String(selectedCellId) }"
                :title="`在画布上定位到「${t._cellName || '该元素'}」`"
                @click.stop="locateToCell(t)"
              >
                <svg width="11" height="11" viewBox="0 0 16 16" fill="none">
                  <circle cx="8" cy="8" r="3" fill="currentColor" />
                  <circle cx="8" cy="8" r="6.5" stroke="currentColor" stroke-width="1" fill="none" />
                </svg>
                <span>定位</span>
              </button>
              <span class="expand-arrow" :class="{ open: isExpanded(t) }">▾</span>
            </div>
            <!-- 挂载元素 + 威胁类型 chip：与"挂载在哪个组件/数据流"语义同组，
                 紧凑放在标题正下方。原 controls 行元素过多（状态 + 类型 +
                 评审 + OOS = 4 组）拆成两组：元信息行 + 处置行。 -->
            <div v-if="t._cellName || t._cellKind" class="threat-cell-chip">
              <span class="cell-chip-label">挂载在</span>
              <span class="cell-chip-name" :title="t._cellName || '匿名元素'">{{ t._cellName || '匿名元素' }}</span>
              <span v-if="t._cellKind" class="cell-chip-kind" :class="'kind-' + kindKey(t._cellKind)">
                {{ kindLabel(t._cellKind) }}
              </span>
              <span v-if="t.type" class="threat-type" :title="t.type">{{ shortType(t.type) }}</span>
            </div>
            <!-- 第二行：处置控件（状态 / 评审 / 范围外）—— 3 个高优先级控件横排 -->
            <div class="threat-row threat-row-controls">
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
              <!-- 评审操作：分段切换器（segmented control）样式。
                   与左侧"已缓解"等状态 chip 视觉明确区分（chip = 流程态、
                   胶囊 = 事实判断），避免"两个绿色块并排"的视觉重复。 -->
              <span v-if="resultId" class="review-actions" @click.stop>
                <button
                  class="rv-btn rv-ok"
                  :class="{ active: reviewState(t) === 'Confirmed' }"
                  :title="reviewTitle(t) || '确认威胁成立，推进整改'"
                  :disabled="reviewingId === threatKey(t)"
                  @click="submitReview(t, 'Confirmed')"
                >
                  ✓
                </button>
                <button
                  class="rv-btn rv-no"
                  :class="{ active: reviewState(t) === 'Rejected' }"
                  :title="reviewTitle(t) || '驳回：误报或经评估不成立'"
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
            </div>
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
        <!-- 有筛选时给出"被筛掉了"的明确提示 + 一键清除，
             否则用户会误以为真的没有这类威胁。 -->
        <template v-if="listFilter !== 'all'">
          <p>当前筛选下没有匹配的威胁</p>
          <span>
            「{{ filterTabs.find((f) => f.key === listFilter)?.full }}」为 0 条，
            可切换到「全部」查看。
          </span>
          <button class="nt-reset" @click="listFilter = 'all'">显示全部</button>
        </template>
        <template v-else>
          <p v-if="selectedThreats">「{{ selectedThreats.cellName || '该组件' }}」暂无威胁记录</p>
          <p v-else>该区域暂无威胁记录</p>
        </template>
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
  // 画布规模总览（节点 / 数据流 / 威胁 / 覆盖）：原在 DFD 工具条上，
  // 按反馈移到本面板标题下，由 ThreatModeling 计算后传下来（口径不变）
  graphStats: { type: Object, default: null },
  selectedCellId: { type: String, default: null },
  selectedThreats: { type: Object, default: null },
  resultId: { type: String, default: null },
  // 当前登录用户（用于评审后本地回显评审人，避免整页刷新）
  currentUser: { type: Object, default: null },
})
const emit = defineEmits(['clear-selection', 'threat-updated', 'locate-cell'])

/** 规模总览的 tooltip 文案（原来挂在工具条的 .gt-stats 上，随这组数字一起搬来） */
const statsTitle = computed(() => {
  const s = props.graphStats || {}
  return (
    `本图共 ${s.nodes} 个元素、${s.flows} 条数据流，已识别 ${s.threats} 条威胁` +
    (s.coverage != null ? `，威胁覆盖度 ${s.coverage}%` : '')
  )
})

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
    // 跳过后端补的**空**信任边界（没有成员，画布上也不画）。
    // 事实优先读建模期落库的 data.boundaryEmpty / boundaryMembers；老模型没有这两个
    // 字段时才退回 cell.children —— 历史实现只看 children，而后端从不写该字段，
    // 结果**所有**边界（含真有成员的）都被排除出"可挂威胁元素"下拉。
    const isBoundary = cell.shape === 'tm.BoundaryBox'
    if (isBoundary) {
      const empty = cell.data?.boundaryEmpty
        ?? !((cell.data?.boundaryMembers || cell.children || []).length)
      if (empty) continue
    }
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

const severityFilter = ref('')
const severityLevels = computed(() => {
  const bySev = props.stats?.threatCountBySeverity || {}
  const defs = [
    ['Critical', 'critical'],
    ['High', 'high'],
    ['Medium', 'medium'],
    ['Low', 'low'],
  ]
  return defs.map(([name, key]) => ({
    name,
    key,
    label: tSeverity(name),
    count: bySev[name] || 0,
  }))
})
function toggleSeverityFilter(key) {
  severityFilter.value = severityFilter.value === key ? '' : key
}

/**
 * 快捷筛选统一入口。
 * 两组筛选（快捷 × 严重度）正交叠加，但用户心智里点「全部」就是
 * "回到全量列表"——若只重置 listFilter 而留着 severityFilter，
 * 会出现"全部 97 但列表只有 19 条"的错觉（正是用户反馈的 bug）。
 * 因此点「全部」时必须同步清空严重度筛选。
 */
function setListFilter(key) {
  listFilter.value = key
  if (key === 'all') severityFilter.value = ''
}

/* —— 概览卡片用到的派生数据 —— */

// 展示用总数：totalThreats 为了防除零做了 `|| 1`，不能直接显示
const totalThreatsDisplay = computed(() => {
  const bySev = props.stats?.threatCountBySeverity || {}
  return Object.values(bySev).reduce((a, b) => a + b, 0)
})

const typeEntries = computed(() => {
  const byType = props.stats?.threatCountByType || {}
  return Object.entries(byType).filter(([, n]) => Number(n) > 0)
})

const typeCount = computed(() => typeEntries.value.length)

// 类别条以"最大类别"为基准做相对长度，否则占比小的大类看着都像没有
const typeMax = computed(() => {
  const nums = typeEntries.value.map(([, n]) => Number(n) || 0)
  return Math.max(1, ...nums)
})

function typePct(count) {
  return Math.max(6, Math.round(((Number(count) || 0) / typeMax.value) * 100))
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

/**
 * 评审结论的悬浮提示，仅在已评审时返回内容。
 *
 * 未评审返回空串 —— 调用方（✓ / ✕ 按钮）会用各自的兜底文案说明
 * 按钮本身的作用，不能在这里统一返回"待评审：请确认威胁是否成立"，
 * 否则两个按钮的提示会变得一模一样，用户分不清哪个是确认哪个是驳回。
 */
function reviewTitle(t) {
  const r = t.review
  if (!r?.state) return ''
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

  // 乐观更新：先落本地状态让 UI 立即响应，再发请求持久化。
  // 之前是先 await 请求、成功后才赋值 —— 网络往返期间勾选框的
  // 文字/样式都停在旧值（且列表若按 OOS 过滤会不重排），
  // 用户看到的就是"点了没反应，刷新才变"。
  applyOutOfScope(t, newVal)

  if (!props.resultId || !threatId) {
    // 本地内存中暂存，本次会话未持久化
    toast('本次会话未持久化，OOS 仅本地生效', 'warning')
    return
  }

  try {
    await updateThreatStatus(props.resultId, threatId, t.status || 'Open', {
      outOfScope: newVal,
    })
    toast(`威胁 #${t.number} 已${newVal ? '标记' : '取消'}范围外`, 'success')
    // 通知父组件，与 status 变更保持一致的口径
    emit('threat-updated', { threatId, outOfScope: newVal })
  } catch (e) {
    // 失败回滚：不仅改回数据，也要同步回 checkbox DOM 的勾选态
    applyOutOfScope(t, oldVal)
    event.target.checked = oldVal
    toast('更新范围外失败：' + (e?.response?.data?.detail || e?.message), 'error')
  }
}

/**
 * 把范围外标记同时写入列表副本与 model 中的原始威胁对象。
 *
 * visibleThreats 渲染的 t 是 allThreats 里 `{ ...threat }` 出来的浅拷贝，
 * 只改副本的话，props.model 上的真身仍是旧值 —— 任何一次
 * 触发 allThreats 重算的操作（新增威胁、父组件刷新数据）都会把
 * 副本覆盖回去，界面出现"改完又跳回去"的诡异现象。
 * 因此这里按 threatKey 定位真身一并同步，与 applyReviewLocally 同思路。
 */
function applyOutOfScope(t, val) {
  t.outOfScope = val
  const key = threatKey(t)
  const cells = props.model?.detail?.diagrams?.[0]?.cells || []
  for (const cell of cells) {
    for (const threat of cell.threats || []) {
      if (threatKey(threat) !== key) continue
      threat.outOfScope = val
      return
    }
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
    applyStatus(t, status)
    return
  }
  const threatId = t.threatId
  if (!threatId) {
    toast('威胁缺少 ID，无法回写', 'warning')
    return
  }
  // 乐观更新：与 toggleOutOfScope 同口径，先刷 UI 再持久化，
  // 避免网络往返期间下拉框停留在旧值像是"点了没反应"。
  applyStatus(t, status)
  try {
    await updateThreatStatus(props.resultId, threatId, status, {
      outOfScope: !!t.outOfScope,
    })
    toast(`威胁 #${t.number} 已标记为「${status}」`, 'success')
    emit('threat-updated', { threatId, status })
  } catch (e) {
    applyStatus(t, oldStatus)
    event.target.value = oldStatus
    toast('更新状态失败：' + (e?.response?.data?.detail || e?.message), 'error')
  }
}

/** 状态写入列表副本 + model 真身，避免副本被重算覆盖（同 applyOutOfScope） */
function applyStatus(t, status) {
  t.status = status
  const key = threatKey(t)
  const cells = props.model?.detail?.diagrams?.[0]?.cells || []
  for (const cell of cells) {
    for (const threat of cell.threats || []) {
      if (threatKey(threat) !== key) continue
      threat.status = status
      return
    }
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
      // 注入 _cellName + _cellId：
      //  - _cellName：渲染"挂载在 XX"chip，让用户一眼看到威胁对应的组件
      //  - _cellId：点威胁项时 emit 给父组件 → 画布高亮对应 cell
      all.push({
        ...t,
        _cellName: cell.data?.name || '',
        _cellId: cell.id,
        _cellKind: cell.kind || cell.data?.kind || '',
      })
    }
  }
  return all
})

const visibleThreats = computed(() => {
  // 先取基础集合（画布选中时只看该组件），再套用快捷筛选。
  let base
  if (props.selectedThreats) {
    base = props.selectedThreats.threats || []
  } else {
    if (!props.model) return []
    // 主排序：建模顺序（后端 number，全局正序）。
    // 用户看威胁列表时，"#4 / #5 / #6 / #7 / #11" 这种断裂编号
    // 会误以为中间数据丢失；按 number 升序展示让编号连续，匹配
    // "模型按 AI 生成顺序逐条追加"的心智模型。
    // 次排序：同 number 时按严重度（严重→低）把更严重的排前。
    base = [...allThreats.value].sort((a, b) => {
      const an = Number(a.number || 0)
      const bn = Number(b.number || 0)
      if (an !== bn) return an - bn
      return (a.severityRank ?? 99) - (b.severityRank ?? 99)
    })
  }
  return base.filter((t) => {
    // 严重度 chip 过滤：与列表快捷筛选正交，两者可叠加
    if (severityFilter.value && sevKey(t.severity) !== severityFilter.value) return false
    if (listFilter.value === 'open') return t.status !== 'Mitigated'
    if (listFilter.value === 'todo') {
      // 待评审：与 reviewProgress / filterTabs 统一走 reviewState()，
      // 否则 chip 数字（reviewState 口径）和列表实际条数（reviewStatus 口径）会对不上。
      return reviewState(t) === 'Pending'
    }
    return true
  })
})

/**
 * 快捷筛选：全部 / 高危 / 未缓解 / 待评审。
 * 威胁多起来后（十几条以上），用户最常见的心智是"我只想看该马上处理的"，
 * 比逐个点严重度 chip 更快。
 */
const listFilter = ref('all')
const filterTabs = computed(() => {
  const src = props.selectedThreats?.threats || allThreats.value
  const open = src.filter((t) => t.status !== 'Mitigated').length
  // 待评审必须复用 reviewState()：之前读的是 t.reviewStatus，与上方
  // reviewProgress（读 t.review.state）字段不同源，同一个页面出现
  // "94 待评审"（priority-strip）和"108 待评审"（本 chip）两个数字。
  const todo = src.filter((t) => reviewState(t) === 'Pending').length
  return [
    // 不提供"高危"chip：严重度筛选由右侧严重度 pill 负责，
    // 否则同屏出现两个口径不同的"高危"数字（38 vs 29）会让用户以为数据错乱。
    { key: 'all', label: '全部', full: '全部威胁', n: src.length },
    { key: 'open', label: '未缓解', full: '未缓解', n: open },
    { key: 'todo', label: '待评审', full: '待评审', n: todo },
  ]
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

/**
 * 点击"定位"按钮 → 通知父组件 ThreatModeling.vue 把画布选中态切到该 cell。
 * 父组件收到后会把 cellId 写到 selectedCellId，进而触发 DfdGraph 的 watch 高亮 + 居中。
 */
function locateToCell(t) {
  if (!t._cellId) {
    console.warn('[ThreatPanel] locateToCell: 该威胁没有 _cellId，无法定位', t)
    return
  }
  console.log('[ThreatPanel] locate-cell emit', { cellId: t._cellId, cellName: t._cellName })
  emit('locate-cell', { cellId: t._cellId, cellName: t._cellName })
}

/* kind 字符串归一：DFD 节点 kind 通常是 process / store / actor / ai / flow/lane/... */
function kindKey(kind) {
  const k = String(kind || '').toLowerCase()
  if (k.includes('process') || k === '处理') return 'process'
  if (k.includes('store') || k === '数据存储') return 'store'
  if (k.includes('actor') || k.includes('external') || k === '外部实体') return 'actor'
  if (k.includes('ai')) return 'ai'
  if (k.includes('flow') || k.includes('edge')) return 'flow'
  return 'other'
}
function kindLabel(kind) {
  const map = { process: '处理', store: '存储', actor: '实体', ai: 'AI', flow: '流', other: '元素' }
  return map[kindKey(kind)] || '元素'
}
</script>

<style scoped>
.threat-panel {
  width: 100%;
  height: 100%;
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
  flex: none;
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

/* —— 画布规模总览（原在 DFD 工具条上，按反馈移到本面板标题下） ——
   贴在头部下沿：靠底色台阶（bg-panel-2）与头部区分，不再多画一条横线
   （头部已经有 border-bottom），避免"两条同色带 + 两条横线"叠着发碎。 */
.tp-stats {
  display: flex;
  align-items: center;
  /* 面板只有 ~300px 宽：允许折行，宁可换行也不要压成一条挤在一起的浮字 */
  flex-wrap: wrap;
  gap: 4px 9px;
  flex: none;
  padding: 7px 14px 8px;
  background: var(--bg-panel-2);
  font-size: 11px;
  color: var(--text-dim);
  /* 数字等宽：威胁数从 111 → 999 时不会把后面的指标推来推去 */
  font-variant-numeric: tabular-nums;
}
.tps-item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
}
.tps-item.threat {
  color: var(--danger, #b91c1c);
  font-weight: 600;
}
.tps-item.threat.zero {
  color: var(--text-faint, #94a3b8);
  font-weight: 500;
}
.tps-item.cover {
  color: #15803d;
  font-weight: 600;
}
.tps-sep {
  width: 1px;
  height: 11px;
  background: var(--border, #cbd5e1);
  flex-shrink: 0;
}
/* 指标点统一成同尺寸圆点：颜色一一对应节点 / 数据流 / 威胁 / 覆盖 */
.tps-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  display: inline-block;
  flex-shrink: 0;
}
.tps-dot.node { background: #2563eb; }
.tps-dot.flow { background: #0891b2; }
.tps-dot.threat { background: #dc2626; }
.tps-dot.cover { background: #16a34a; }

/* —— 关键提醒条 —— 取代原 KPI 卡片：
   原来 4 格 KPI（组件/数据流/威胁/高危）与工具条重复 3 格，
   这里只保留"高危 + 待评审"2 个右栏独占指标，单行紧凑。
   "已评估 N/M"与列表头筛选 tab 的"已评估"重复且数字来源不同
   （reviewProgress vs filterTabs 统计），会出现"14 vs 108"对不上，
   所以删掉第三项，留给筛选 tab 单一来源显示。 */
.priority-strip {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 11px 14px;
  border-bottom: 1px solid var(--border);
  font-variant-numeric: tabular-nums;
}
.ps-item {
  display: inline-flex;
  align-items: baseline;
  gap: 4px;
  font-size: 11px;
  color: var(--text);
  min-width: 0;
}
.ps-item.muted {
  color: var(--text-faint);
}
.ps-num {
  font-size: 16px;
  font-weight: 700;
  font-family: var(--font-mono);
  color: var(--text);
  line-height: 1.05;
}
.ps-lbl {
  font-size: 10.5px;
  color: var(--text-faint);
}
.ps-item.danger .ps-num {
  color: var(--danger, #dc2626);
}
.ps-item.danger .ps-lbl {
  color: var(--danger, #dc2626);
  font-weight: 600;
}
.ps-item.zero .ps-num,
.ps-item.zero .ps-lbl {
  color: var(--text-faint);
}
.ps-sep {
  width: 1px;
  height: 14px;
  background: var(--border-light, #e2e8f0);
  flex-shrink: 0;
}

.ov-card {
  background: var(--bg-panel-2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 5px 8px 6px;
  min-width: 0;
}
/* 严重度并入列表头后，概览区只剩这一张卡片。需要自己的内外边距，
   取代原来 .overview 父容器的 padding / gap / border-bottom。 */
.ov-card-solo {
  /* 左右 14px：与下方威胁列表的 padding (14px) 对齐，
     让卡片右缘与 .threat-item 右缘精确对齐到同一条竖线 */
  margin: 8px 14px 10px;
}
.ov-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 4px;
}
.ov-title {
  font-size: 10.5px;
  font-weight: 600;
  color: var(--text-dim);
  letter-spacing: 0.02em;
}
.ov-total {
  font-size: 9.5px;
  color: var(--text-faint);
  font-family: var(--font-mono);
}

/* —— 筛选条（单行）：快捷筛选（全部/未缓解/待评审） │ 严重度（4 个等级 pill） —— */
.filter-bar {
  display: flex;
  align-items: center;
  /* 不换行：两组 chip 在同一排，靠左紧凑排，右边留呼吸空间 */
  flex-wrap: nowrap;
  gap: 4px;
  /* 左 12px 与列表头对齐；右 20px：比列表头多留 8px，
     让严重度组右缘与「+新增威胁」按钮错开，不贴边。 */
  /* 左 12px 与列表头对齐；右 24px：最后一个 pill 右缘与「+新增威胁」按钮右缘对齐 */
  padding: 2px 24px 8px 12px;
}
.filter-group {
  display: flex;
  align-items: center;
  gap: 3px;
  min-width: 0;
}
/* 两组都不撑开（flex:0 1 auto）：按内容紧凑排，组内 chip 各按内容宽度。
   这样筛选条不会拉满整行，右边留出呼吸空间，跟「+新增威胁」按钮也错开。 */
.sev-group { flex: 0 1 auto; }
.qf-group { flex: 0 1 auto; }
/* 竖线分隔：独占 1px，不参与伸缩 */
.filter-divider {
  flex: none;
  width: 1px;
  height: 14px;
  background: var(--border);
  margin: 0 2px;
}

/* 严重度 pill：按内容宽度紧凑排布，与同行 .qf-chip 高度对齐。
   不用独立色点（省 ~8px/个），改用左侧 3px 色条标级别 ——
   颜色仍由 .sev-* 的 currentColor 驱动，识别度不降。 */
.sev-pill {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  /* 上下 3px / 左右 5px；左 3px 给色条。
     与 .qf-chip（5px）齐平，整行视觉密度一致；
     左右 5px 而不是 7px：4 个 pill + 3 px 色条 = 节省约 16px，避免溢出。 */
  padding: 3px 3px 3px 3px;
  border-radius: 999px;
  border: 1px solid var(--border);
  border-left: 3px solid currentColor;
  background: var(--bg-panel);
  cursor: pointer;
  font: inherit;
  white-space: nowrap;
  /* 按内容紧凑：pill 宽度贴合文字，不再拉伸 */
  flex: 0 0 auto;
  justify-content: center;
  transition: border-color 0.18s, box-shadow 0.18s;
}
/* hover / active 只改「除左色条外」的三边颜色：
   border-color 简写会把 border-left-color 一起覆盖，导致级别色丢失，
   所以统一用 border-top/right/bottom-color 单独声明。 */
.sev-pill:hover {
  border-top-color: var(--border-strong);
  border-right-color: var(--border-strong);
  border-bottom-color: var(--border-strong);
  box-shadow: var(--shadow-sm);
}
.sev-pill.active {
  border-top-color: currentColor;
  border-right-color: currentColor;
  border-bottom-color: currentColor;
  box-shadow: 0 0 0 1px currentColor inset;
}
/* 计数为 0 时整体降透明度，避免"看起来有威胁"的误读 */
.sev-pill.zero {
  opacity: 0.42;
}
.sev-name {
  font-size: 11.5px;
  color: var(--text-dim);
  white-space: nowrap;
  flex-shrink: 0;
}
.sev-count {
  font-size: 11.5px;
  font-weight: 700;
  color: currentColor;
  font-variant-numeric: tabular-nums;
}
/* 各级别主色：用 currentColor 驱动点 / 数字，改一处即可 */
.sev-critical { color: var(--critical); }
.sev-high { color: var(--high); }
.sev-medium { color: var(--medium); }
.sev-low { color: var(--low); }

/* 威胁类别：每行「名称 / 相对长度条 / 数字」—— 整行高度紧凑 */
.type-list {
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.type-row {
  display: grid;
  grid-template-columns: 52px minmax(0, 1fr) 22px;
  align-items: center;
  gap: 6px;
  font-size: 10px;
}
.type-name {
  color: var(--text-dim);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  line-height: 1.1;
}
.type-track {
  height: 4px;
  border-radius: 2px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  overflow: hidden;
}
.type-track > i {
  display: block;
  height: 100%;
  border-radius: 2px;
  background: linear-gradient(90deg, var(--primary), var(--accent-cyan));
  transition: width 0.4s cubic-bezier(0.4, 0, 0.2, 1);
}
.type-num {
  text-align: right;
  color: var(--primary);
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  font-size: 10px;
}

/* —— 列表头（含快捷筛选） —— */
/* 注意：.threat-list 自身是滚动容器，把 sticky 放在它外面对它无效。
   这里用"顺序固定 + flex 不收缩"实现同样效果：头部/KPI/筛选留在原地，
   只有 .threat-list 内部滚动，视觉上等同吸顶且不依赖 sticky 兼容性。 */
.list-head-sticky {
  flex: none;
  background: var(--bg-panel);
  box-shadow: 0 1px 0 var(--border-light);
}
.list-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  /* 下 padding 收紧：下方紧跟统一筛选条（.filter-bar 上 2px），
     让标题与筛选条视觉上属于同一区块。 */
  padding: 11px 14px 3px;
  gap: 8px;
}

.qf-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-family: inherit;
  font-size: 11.5px;
  font-weight: 500;
  color: var(--text-muted, #64748b);
  background: var(--bg-panel-2, #f8fafc);
  border: 1px solid var(--border-light, #e2e8f0);
  border-radius: 999px;
  /* 3px 内边距：与严重度 pill 等密度，整行视觉节奏一致 */
  padding: 3px 3px;
  cursor: pointer;
  white-space: nowrap;
  /* 按内容紧凑：chip 宽度贴合文字，不再拉伸 */
  flex: 0 0 auto;
  justify-content: center;
  transition: all 0.15s;
}
.qf-chip b {
  font-size: 11.5px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  color: var(--text, #334155);
}
.qf-chip:hover:not(:disabled) {
  border-color: var(--primary, #7c3aed);
  color: var(--primary, #7c3aed);
}
.qf-chip.active {
  background: var(--primary, #7c3aed);
  border-color: var(--primary, #7c3aed);
  color: #fff;
}
.qf-chip.active b {
  color: #fff;
}
.qf-chip.zero {
  opacity: 0.5;
}
.qf-chip:disabled {
  cursor: not-allowed;
}
/* 空态里的一键清除筛选 */
.nt-reset {
  margin-top: 2px;
  font-family: inherit;
  font-size: 11px;
  font-weight: 600;
  color: var(--primary, #7c3aed);
  background: rgba(124, 58, 237, 0.07);
  border: 1px solid rgba(124, 58, 237, 0.25);
  border-radius: 999px;
  padding: 2px 11px;
  cursor: pointer;
}
.nt-reset:hover {
  background: var(--primary, #7c3aed);
  color: #fff;
}
.list-head h3 {
  font-size: 12.5px;
  font-weight: 700;
  color: var(--text);
  letter-spacing: 0.2px;
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.list-head-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}

/* —— 威胁列表 —— */
.threat-list {
  flex: 1 1 0;
  min-height: 0;
  overflow-y: auto;
  padding: 4px 14px 14px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  /* 与上方评审进度之间留一道隐形边距：列表项的 border-radius 更软，
     跟上面 KPI / 分布的视觉块边界形成节奏分割。 */
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
  flex-direction: column;
  /* 主行 + 控件行，两行排列避免 9 个控件挤在 380px 同一行 */
  gap: 6px;
  padding: 8px 12px 9px;
}
/* 主行：严重度徽章 + 编号 + 标题 + 箭头 */
.threat-row {
  display: flex;
  align-items: center;
  gap: 6px;
}
.threat-row-main { gap: 7px; }
.threat-row-main .threat-title { flex: 1; }
.threat-row-controls {
  flex-wrap: wrap;
  /* 控件统一高度 ~22px：状态 chip / 评审按钮 / OOS 胶囊垂直对齐，
     避免原来参差 20-26px 导致的"参差不齐"观感 */
  align-items: center;
  gap: 6px;
  padding-left: 1px;
}
.sev-badge {
  font-size: 11px;
  font-weight: 700;
  padding: 2px 8px;
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
  font-size: 11px;
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
  font-size: 11px;
  font-weight: 600;
  /* 胶囊高度 22px：与其他控件对齐（状态 chip 22、review 按钮 20+1 边距）。
     padding 由 2px 9px 改 2px 7px —— 节省 ~8px 让一行挤下三个控件 */
  padding: 2px 7px;
  border-radius: var(--radius-pill);
  /* 默认"圈内"态：用 dashed 边框 + 白底，与相邻的实色 chip 控件
     （Open / 已缓解 / ✓ ✕）明确区分——这是个开关、不是状态徽章。
     显式写死颜色 #64748b 不依赖未定义的 --text-muted 变量。 */
  background: #fff;
  border: 1px dashed #e2e8f0;
  color: #64748b;
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
  /* 范围外激活态：用 warning 色（橙）语义化"暂搁置、需关注"；
     与"严重" badge 同色系传达"这不是解决、是需要复查" */
  background: var(--warning-soft, rgba(245, 158, 11, 0.12));
  color: var(--warning, #b45309);
  border-color: var(--warning-border, #f59e0b);
  border-style: solid;
}
.oos-toggle-inline:hover {
  border-color: var(--primary-border);
  color: var(--primary);
}
.threat-type {
  font-size: 10.5px;
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
  min-width: 0;
  display: flex;
  /* 编号与标题基线对齐（原 center 在多行标题下会让 #N 浮在中间） */
  align-items: baseline;
  gap: 5px;
  /* 14px / 600：让标题比副文本（11px）显著大，作为信息层级锚点 */
  font-size: 14px;
  color: var(--text);
  line-height: 1.42;
  font-weight: 600;
}
.threat-title .t-num {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-faint);
  flex-shrink: 0;
}
.threat-title-text {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  /* 右栏加宽到 420px 后，标题最多显示 2 行再省略：
     "越权访问用户账户资金并篡改交易记录" 这类长标题一行放不下，
     强行单行会截成 "越权访问用户账户资金…"，丢失关键区分信息。 */
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  word-break: break-word;
}
.threat-title.is-out-of-scope .threat-title-text {
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

/* —— 定位到画布按钮 —— */
.locate-btn {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  padding: 2px 7px 2px 5px;
  font-family: inherit;
  font-size: 10.5px;
  font-weight: 500;
  color: var(--text-muted, #64748b);
  background: var(--bg-panel-2, #fff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.15s;
  flex-shrink: 0;
}
.locate-btn:hover {
  color: var(--primary, #7c3aed);
  border-color: var(--primary, #7c3aed);
  background: rgba(124, 58, 237, 0.04);
}
.locate-btn.active {
  color: #fff;
  background: var(--primary, #7c3aed);
  border-color: var(--primary, #7c3aed);
  box-shadow: 0 0 0 2px rgba(124, 58, 237, 0.18);
}
.locate-btn svg {
  width: 11px;
  height: 11px;
}

/* —— 挂载元素 chip —— 显示"挂载在 XX · 处理" */
.threat-cell-chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 11px;
  color: var(--text-muted, #64748b);
  padding: 2px 7px;
  margin-top: 2px;
  align-self: flex-start;
  max-width: 100%;
  background: var(--bg-panel);
  border: 1px solid var(--border-light, #e2e8f0);
  border-radius: var(--radius-pill, 999px);
}
.cell-chip-label {
  color: var(--text-faint, #94a3b8);
  flex-shrink: 0;
}
.cell-chip-name {
  color: var(--text, #334155);
  font-weight: 500;
  /* 1) flex:1 占据中间剩余空间，把 kind chip 推到底；2) min-width:0
     允许文本在更长场景下溢出 ellipsis（数据里最长 280px，剩下空间也够） */
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.cell-chip-kind {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 3px;
  font-weight: 500;
  letter-spacing: 0.2px;
}
.cell-chip-kind.kind-process { background: rgba(22, 163, 74, 0.12); color: #15803d; }
.cell-chip-kind.kind-store   { background: rgba(217, 119, 6, 0.12); color: #b45309; }
.cell-chip-kind.kind-actor   { background: rgba(37, 99, 235, 0.12); color: #1d4ed8; }
.cell-chip-kind.kind-ai      { background: rgba(124, 58, 237, 0.14); color: #6d28d9; }
.cell-chip-kind.kind-flow    { background: rgba(8, 145, 178, 0.12); color: #0e7490; }
.cell-chip-kind.kind-other   { background: rgba(100, 116, 139, 0.12); color: #475569; }
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

/* ---- 评审进度：合并到 .priority-strip 显示，原 .review-progress 条删除 ---- */

/* ---- 威胁评审（确认 / 驳回）----
   segmented control 形态：外层胶囊包裹 ✓ / ✕，与左侧状态 chip
   形成"细胶囊 ↔ 方按钮"的视觉对比，避免"两个绿色块并排"的重复感。 */
.review-actions {
  display: inline-flex;
  align-items: stretch;
  flex-shrink: 0;
  /* 整体高度 22px，与状态 chip / OOS 胶囊统一 */
  height: 22px;
  background: var(--bg-panel);
  border: 1px solid var(--border-light);
  border-radius: 999px;
  overflow: hidden;
  /* 用 :before 画细分隔线，避免两个按钮之间用 border 时一边消失 */
  position: relative;
}
.review-actions::before {
  content: '';
  position: absolute;
  left: 50%;
  top: 4px;
  bottom: 4px;
  width: 1px;
  background: var(--border-light);
  transform: translateX(-0.5px);
}
.rv-btn {
  width: 22px;
  height: 100%;
  padding: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  line-height: 1;
  border: none;
  background: transparent;
  color: var(--text-faint);
  cursor: pointer;
  transition: background 0.12s, color 0.12s;
}
.rv-btn:hover:not(:disabled) { background: var(--bg-hover); }
.rv-btn:disabled { opacity: 0.45; cursor: not-allowed; }
/* active 态：✓ 用绿底、✕ 用红底，整段胶囊内"半填色"，与左侧状态 chip
   形成"色块 chip ↔ 胶囊内半填色"的差异化视觉 */
.rv-ok.active { background: #047857; color: #fff; }
.rv-no.active { background: #b91c1c; color: #fff; }
.rv-no:hover:not(:disabled), .rv-no.active { color: #b91c1c; border-color: #b91c1c; }

/* ---- 手工新增威胁弹窗 ---- */
.btn-add-threat { color: var(--accent-violet); }
/* 取消定位：定位态的"出口"，主色描边让它比普通次按钮更可发现 */
.btn.btn-clear-locate {
  color: var(--primary, #7c3aed);
  border-color: var(--primary-border, #ddd6fe);
  background: var(--primary-soft, #f5f3ff);
}
.btn.btn-clear-locate:hover {
  background: var(--primary, #7c3aed);
  border-color: var(--primary, #7c3aed);
  color: #fff;
}
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
