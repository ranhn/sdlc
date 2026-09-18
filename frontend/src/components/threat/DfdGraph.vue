<template>
  <div class="graph-wrap">
    <!-- 适配视图按钮已迁到 ThreatModeling.vue 的 .gt-right（与「保存布局 / 折叠右栏」并列），
         自动纠错提示改为画布内的右上浮层（不占独立行高度，画布可多 30+px 垂直空间）。
         原 .graph-head 整块移除。 -->

    <!-- 图例：节点类型项同时是高亮开关（点击切换），
         与只读的线条图例区分 —— 前者是可点按钮，后者是纯展示。
         历史实现是"一个 flex-wrap 容器装全部"，于是节点项和数据流项混排自动
         折行：窗口一窄，数据流这一族就被拆到第三排、和筛选按钮各占一行。
         现在固定成两排成组（.legend-row），第 2 排专放数据流家族 + 数据流筛选。 -->
    <div v-if="model" class="legend">
      <!-- 第 1 排：节点类型 —— 四类都是高亮开关（可点性一致，此前 AI 组件是
           唯一一个只读项，一排里 3 个能点 1 个不能点最容易被当成"乱"）。
           造型统一画在 36px 宽的图框里（preserveAspectRatio=meet 只居中不拉伸），
           于是与第 2 排 36px 的线型图例左右同宽、圆心对齐成同一列。 -->
      <div class="legend-row">
        <button
          type="button"
          class="lg-item lg-toggle"
          :class="{ active: activeHighlight === 'actor' }"
          title="点击高亮所有外部实体"
          @click="toggleHighlight('actor')"
        >
          <svg class="lg-fig" width="36" height="12" viewBox="0 0 24 12" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
            <rect x="0.75" y="0.75" width="22.5" height="10.5" rx="5.25"
                  :fill="specOf('tm.Actor').fill" :stroke="specOf('tm.Actor').stroke" stroke-width="1.5" />
          </svg>
          <span class="lg-label">外部实体</span>
        </button>
        <button
          type="button"
          class="lg-item lg-toggle"
          :class="{ active: activeHighlight === 'process' }"
          title="点击高亮所有处理节点"
          @click="toggleHighlight('process')"
        >
          <svg class="lg-fig" width="36" height="12" viewBox="0 0 24 12" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
            <rect x="0.75" y="0.75" width="22.5" height="10.5" rx="3"
                  :fill="specOf('tm.Process').fill" :stroke="specOf('tm.Process').stroke" stroke-width="1.5" />
          </svg>
          <span class="lg-label">处理</span>
        </button>
        <button
          type="button"
          class="lg-item lg-toggle"
          :class="{ active: activeHighlight === 'store' }"
          title="点击高亮所有数据存储"
          @click="toggleHighlight('store')"
        >
          <!-- 图例里的造型必须与实际节点同形状：圆柱走与节点同一份
               cylinderBodyD（dfd_spec 比例），否则又回到"图例说矩形、
               图上画圆柱"的历史不一致。 -->
          <svg class="lg-fig" width="36" height="12" viewBox="0 0 24 12" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
            <path :d="cylinderBodyD(24, 12)" :fill="specOf('tm.Store').fill"
                  :stroke="specOf('tm.Store').stroke" stroke-width="1.1" />
          </svg>
          <span class="lg-label">数据存储</span>
        </button>
        <button
          type="button"
          class="lg-item lg-toggle"
          :class="{ active: activeHighlight === 'model' }"
          title="点击高亮所有 AI 组件"
          @click="toggleHighlight('model')"
        >
          <svg class="lg-fig" width="36" height="12" viewBox="0 0 24 12" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
            <rect x="0.75" y="0.75" width="22.5" height="10.5" rx="3"
                  :fill="specOf('tm.Model').fill" :stroke="specOf('tm.Model').stroke" stroke-width="1.5" />
          </svg>
          <span class="lg-label">AI 组件</span>
        </button>
      </div>
      <!-- 第 2 排：数据流家族（线型图例）+ 数据流筛选。
           注：原先首项是「数据流」高亮开关（点击把非数据流元素压暗），
           与紧邻的「全部数据流 x/y」筛选 chip 语义相近、易被当成同一功能，
           且四档线型图例本身已说明"什么线是数据流"，故按反馈移除；
           第 1 排的节点高亮开关保留。 -->
      <div class="legend-row">
        <span class="lg-item">
          <svg width="36" height="10" viewBox="0 0 36 10" aria-hidden="true">
            <line x1="0" y1="5" x2="36" y2="5" stroke="#16a34a" stroke-width="2.4" />
          </svg>
          <span class="lg-label">加密流</span>
        </span>
        <span class="lg-item">
          <svg width="36" height="10" viewBox="0 0 36 10" aria-hidden="true">
            <line x1="0" y1="5" x2="36" y2="5" stroke="#ea580c" stroke-width="2.4" />
          </svg>
          <span class="lg-label">公网流</span>
        </span>
        <span class="lg-item">
          <svg width="36" height="10" viewBox="0 0 36 10" aria-hidden="true">
            <line x1="0" y1="5" x2="36" y2="5" stroke="#475569" stroke-width="2" stroke-dasharray="6 4" />
          </svg>
          <span class="lg-label">跨边界</span>
        </span>
        <span class="lg-item">
          <svg width="36" height="10" viewBox="0 0 36 10" aria-hidden="true">
            <line x1="0" y1="5" x2="36" y2="5" stroke="#16a34a" stroke-width="2.4" stroke-dasharray="6 4" />
          </svg>
          <span class="lg-label">跨边界+加密</span>
        </span>
        <span class="lg-item">
          <svg width="36" height="10" viewBox="0 0 36 10" aria-hidden="true">
            <line x1="0" y1="5" x2="36" y2="5" stroke="#ea580c" stroke-width="2.4" stroke-dasharray="6 4" />
          </svg>
          <span class="lg-label">跨边界+公网</span>
        </span>
        <span class="lg-sep"></span>
        <!-- 数据流精简：视图层过滤，不删模型数据。删除数据流会连带影响
             威胁归属与报告口径（STRIDE 按交互路径分析），所以做成可逆的
             显示过滤。三档循环：全部 → 仅跨边界(9/18) → 跨边界∩高危(7/18)。 -->
        <button
          type="button"
          class="lg-item lg-toggle"
          :class="{ active: securityFlowFilter }"
          :title="`当前：${filterLabel}。点击切换到下一档（全部 → 仅跨边界 → 跨边界∩高危）`"
          @click="toggleSecurityFilter"
        >
          <svg width="18" height="10" viewBox="0 0 18 10" aria-hidden="true">
            <line x1="0" y1="5" x2="18" y2="5" stroke="currentColor" stroke-width="2"
                  stroke-dasharray="3 2.4" stroke-linecap="round" />
          </svg>
          {{ filterLabel }}
          <span class="lg-count">{{ flowStats.relevant }}/{{ flowStats.total }}</span>
        </button>
      </div>
    </div>

    <!-- 自动纠错明细（仅在有纠正项时显示） -->
    <div
      v-if="props.dfdAutofix && props.dfdAutofix.length && autofixOpen"
      class="autofix-panel"
    >
      <div class="autofix-title">DFD 自动纠错明细</div>
      <ul class="autofix-list">
        <li v-for="(msg, i) in props.dfdAutofix" :key="i">{{ msg }}</li>
      </ul>
      <p class="autofix-tip">
        AI 自动建模偶尔会误判组件类型或漏标敏感数据流的加密属性，后端已按常见规则自动修复。
      </p>
    </div>

    <!-- 自动纠错明细（仅在有纠正项时显示） -->
    <div
      v-if="props.dfdAutofix && props.dfdAutofix.length && autofixOpen"
      class="autofix-panel"
    >
      <div class="autofix-title">DFD 自动纠错明细</div>
      <ul class="autofix-list">
        <li v-for="(msg, i) in props.dfdAutofix" :key="i">{{ msg }}</li>
      </ul>
      <p class="autofix-tip">
        AI 自动建模偶尔会误判组件类型或漏标敏感数据流的加密属性，后端已按常见规则自动修复。
      </p>
    </div>

    <!-- 主图区 -->
    <div class="graph-body">
      <!-- 自动纠错提示：浮在画布右上角，不占独立行；
           无纠错项时不渲染，避免空白。 -->
      <button
        v-if="props.dfdAutofix && props.dfdAutofix.length"
        class="autofix-fab"
        type="button"
        title="查看自���纠错明细"
        @click="autofixOpen = !autofixOpen"
      >
        <svg viewBox="0 0 20 20" width="13" height="13" aria-hidden="true">
          <path d="M10 2 L18 17 H2 Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
          <path d="M10 8 V12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
          <circle cx="10" cy="14.5" r="0.9" fill="currentColor" />
        </svg>
        <span>已自动纠错 {{ props.dfdAutofix.length }} 项</span>
      </button>
      <div v-if="!model" class="empty-state">
        <div class="empty-illust">
          <svg viewBox="0 0 240 160" width="240" height="160" aria-hidden="true">
            <defs>
              <linearGradient id="ds-empty" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stop-color="var(--primary)" stop-opacity="0.18" />
                <stop offset="100%" stop-color="var(--accent-cyan)" stop-opacity="0.10" />
              </linearGradient>
            </defs>
            <rect x="2" y="2" width="236" height="156" rx="14" fill="url(#ds-empty)" stroke="var(--primary-border)" stroke-width="1.5" stroke-dasharray="8 5" />
            <circle cx="55" cy="58" r="14" fill="var(--bg-panel-solid)" stroke="var(--primary)" stroke-width="2" />
            <rect x="92" y="46" width="50" height="24" rx="3" fill="var(--success-soft)" stroke="var(--success)" stroke-width="1.5" />
            <rect x="160" y="46" width="50" height="24" rx="3" fill="var(--warning-soft)" stroke="var(--warning)" stroke-width="1.5" />
            <rect x="20" y="100" width="50" height="24" rx="3" fill="var(--bg-panel-2)" stroke="var(--text-faint)" stroke-width="1.5" />
            <rect x="92" y="100" width="50" height="24" rx="3" fill="var(--primary-soft)" stroke="var(--primary)" stroke-width="1.5" />
            <rect x="160" y="100" width="50" height="24" rx="3" fill="var(--primary-soft)" stroke="var(--primary)" stroke-width="1.5" />
            <path d="M55 72 L92 60" stroke="var(--text-faint)" stroke-width="1.5" />
            <path d="M142 60 L160 60" stroke="var(--text-faint)" stroke-width="1.5" />
            <path d="M55 72 L45 100" stroke="var(--text-faint)" stroke-width="1.5" />
            <path d="M117 70 L117 100" stroke="var(--text-faint)" stroke-width="1.5" />
            <path d="M192 70 L192 100" stroke="var(--text-faint)" stroke-width="1.5" />
            <text x="120" y="148" text-anchor="middle" fill="var(--text-faint)" font-size="11" font-family="var(--font-mono)">DFD Preview</text>
          </svg>
        </div>
        <h3>等待生成数据流图</h3>
        <ul>
          <li>
            <span class="ul-icon">🧩</span>
            <span>AI 自动识别组件：外部实体、进程、数据存储、信任边界</span>
          </li>
          <li>
            <span class="ul-icon">🔗</span>
            <span>AI 自动生成数据流关系</span>
          </li>
          <li>
            <span class="ul-icon">🛡️</span>
            <span>点击节点可查看该组件上的威胁</span>
          </li>
        </ul>
      </div>
      <div v-else ref="containerRef" class="graph-container"></div>
    </div>

    <!-- 节点悬停浮层 -->
    <div v-show="tooltip.visible" class="node-tooltip" :style="tooltip.style">
      <div class="tt-head">
        <b>{{ tooltip.name }}</b>
        <span class="tt-count" :class="{ warn: (tooltip.threats || []).length > 0 }">
          {{ tooltip.threats?.length || 0 }} 威胁
        </span>
      </div>
      <div v-if="tooltip.threats?.length" class="tt-list">
        <div v-for="(t, i) in tooltip.threats.slice(0, 5)" :key="i" class="tt-item">
          <span class="tt-sev" :class="'sev-' + sevKey(t.severity)">{{ tSeverity(t.severity) }}</span>
          <span class="tt-title">{{ t.title }}</span>
        </div>
        <div v-if="tooltip.threats.length > 5" class="tt-more">… 等 {{ tooltip.threats.length }} 条威胁，点击节点查看全部</div>
      </div>
      <div v-else class="tt-empty">暂无威胁</div>
    </div>

    <!-- 数据流详情浮层：点击边后浮现 -->
    <Transition name="flow-detail">
      <div v-if="flowDetail" class="flow-detail" role="dialog" aria-label="数据流详情">
        <header class="fd-head" :class="flowDetailType">
          <div class="fd-head-icon">{{ flowDetailIcon }}</div>
          <div class="fd-head-text">
            <h4>{{ flowDetail.name }}</h4>
            <p>{{ flowDetail.isBidirectional ? '双向数据流' : '单向数据流' }}</p>
          </div>
          <button class="fd-close" type="button" @click="closeFlowDetail" title="关闭">×</button>
        </header>

        <div class="fd-route">
          <div class="fd-node src">
            <span class="fd-node-tag">源</span>
            <span class="fd-node-name">{{ flowDetail.sourceName }}</span>
          </div>
          <div class="fd-arrow" :class="flowDetailType">
            <svg viewBox="0 0 40 18" width="40" height="18" aria-hidden="true">
              <line x1="2" y1="9" x2="32" y2="9"
                    :stroke="flowDetailStroke" stroke-width="1.6"
                    :stroke-dasharray="flowDetailDasharray" />
              <polygon points="32,5 38,9 32,13" :fill="flowDetailStroke" />
            </svg>
            <span v-if="flowDetail.isBidirectional" class="fd-arrow-label">↔</span>
          </div>
          <div class="fd-node dst">
            <span class="fd-node-tag">目标</span>
            <span class="fd-node-name">{{ flowDetail.targetName }}</span>
          </div>
        </div>

        <div class="fd-badges">
          <span v-if="flowDetail.isEncrypted" class="fd-badge encrypted" title="信道已加密">
            <span class="fd-badge-ic">🔒</span>加密
          </span>
          <span v-if="flowDetail.isPublicNetwork" class="fd-badge public" title="跨越公网">
            <span class="fd-badge-ic">🌐</span>公网
          </span>
          <span v-if="flowDetail.crossesTrustBoundary" class="fd-badge cross" title="跨信任边界">
            <span class="fd-badge-ic">⇋</span>跨边界
          </span>
          <span v-if="flowDetail.outOfScope" class="fd-badge oos" title="超出建模范围">
            <span class="fd-badge-ic">∅</span>超范围
          </span>
          <span v-if="flowDetail.dataClassification" class="fd-badge data">
            <span class="fd-badge-ic">◆</span>{{ flowDetail.dataClassification }}
          </span>
          <span v-if="flowDetail.protocol" class="fd-badge proto">
            <span class="fd-badge-ic">⇄</span>{{ flowDetail.protocol }}
          </span>
        </div>

        <div class="fd-stats">
          <div class="fd-stat" :class="{ warn: flowDetail.openThreats.length }">
            <span class="fd-stat-num">{{ flowDetail.openThreats.length }}</span>
            <span class="fd-stat-lbl">未缓解威胁</span>
          </div>
          <div class="fd-stat">
            <span class="fd-stat-num">{{ flowDetail.mitigated.length }}</span>
            <span class="fd-stat-lbl">已缓解</span>
          </div>
        </div>

        <div v-if="flowDetail.openThreats.length" class="fd-threats">
          <div class="fd-threats-title">未缓解威胁（{{ flowDetail.openThreats.length }}）</div>
          <ul class="fd-threats-list">
            <li v-for="(t, i) in flowDetail.openThreats.slice(0, 6)" :key="i" class="fd-threats-item">
              <span class="tt-sev" :class="'sev-' + sevKey(t.severity)">{{ tSeverity(t.severity) }}</span>
              <span class="fd-threats-name">{{ t.title }}</span>
            </li>
            <li v-if="flowDetail.openThreats.length > 6" class="fd-threats-more">
              … 等 {{ flowDetail.openThreats.length }} 条，请到威胁列表查看全部
            </li>
          </ul>
        </div>
        <div v-else-if="flowDetail.mitigated.length" class="fd-threats ok">
          <div class="fd-threats-title">已全部缓解</div>
          <p class="fd-threats-empty">此数据流上的 {{ flowDetail.mitigated.length }} 条威胁已实施缓解措施。</p>
        </div>
        <div v-else class="fd-threats">
          <div class="fd-threats-title">暂无威胁</div>
          <p class="fd-threats-empty">AI 未在此数据流上识别出 STRIDE 类别威胁。</p>
        </div>

        <footer v-if="flowDetail.notes" class="fd-notes">
          <span class="fd-notes-lbl">备注</span>
          <span class="fd-notes-txt">{{ flowDetail.notes }}</span>
        </footer>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount, watch, nextTick, computed } from 'vue'
import { Graph } from '@antv/x6'
import '@antv/x6/dist/index.css'
import { tSeverity } from '../../utils/i18n.js'

const props = defineProps({
  model: { type: Object, default: null },
  highlightCellId: { type: String, default: null },
  // 外部"定位"按钮每次点击递增；用于同一 cell 重复定位时强制重新居中
  locateNonce: { type: Number, default: 0 },
  // DFD 自动纠错日志（后端在 LLM 输出明显错误时自动修正，并记录到这里）
  dfdAutofix: { type: Array, default: () => [] },
  // 编辑模式：开启后可拖拽节点、改名、删除节点、拉线连接
  editable: { type: Boolean, default: false },
})
const emit = defineEmits(['select-cell', 'node-moved', 'node-renamed', 'node-removed', 'node-added'])

const containerRef = ref(null)
let graph = null
let allCellsRef = []  // 当前 DFD 全量 cells，供 addNode 内做"空 trust boundary 隐藏"判定

// 泳道背景带的**后端下发几何**（原始宽度）。
// 泳道只是"分区底色"：视口比内容宽时把它的矩形左右拉宽铺满画布，
// 但原始宽度必须留存——拉宽只增不减，且泳道标题锚点要按偏移量补偿。
let laneBands = []
// 拉宽动作挂在画布 scale/translate 上（滚轮缩放/拖拽平移都是高频事件），
// 用 rAF 合帧，避免一帧里重复算同一份视口范围。
let laneSyncRaf = 0

// D2/D5: 后端布局期算出的路由/标签提示表 { flowId: {labelT, labelOffset, crossOffset} }。
// 由 render() 从 diagram.layoutHints 提取；addEdge 渲染时需要读它。
// 用普通变量（非 ref）即可——只在 render 期间被消费，不参与响应式渲染。
let currentLayoutHints = null

const tooltip = ref({ visible: false, name: '', threats: [], style: {} })

// 当前选中的数据流详情;null = 未选中
const flowDetail = ref(null)
// 当前选中的边 id;null = 未选中（与 flowDetail 同步）
const selectedEdgeId = ref(null)

const autofixOpen = ref(false)

// 注：原先这里维护过 cellCounts（按形状统计节点数）用于头部 KPI 数字格。
// 该数字格与右侧 ThreatPanel 的 KPI 视觉同形、易被误读为两套统计口径，
// 已改为无计数的筛选 chip，统计逻辑一并移除。

const activeHighlight = ref(null)

function toggleHighlight(type) {
  if (activeHighlight.value === type) {
    clearHighlight()
    return
  }
  activeHighlight.value = type
  applyHighlight(type)
}

// —— 只看跨边界的数据流（视图过滤，不改模型） ——
// 判定：只保留 crossesTrustBoundary 的流。实测依据（健康手环模型 18 条流）���
//   - 18/18 全部挂有威胁 → "挂威胁保留"会让过滤完全失效（上一版踩的坑）；
//   - AI 对 enc/pub 标注偏松（15 条加密、13 条公网）→ 以此为条件也滤不掉几条；
//   - 跨信任边界是 STRIDE 威胁的核心发生地，9/18 保留恰好砍半。
// 删除数据流属于改模型的高风险操作（威胁归属、覆盖度、报告口径都会变），
// 所以这里只做可逆的显示过滤。
function flowSecurityRelevant(cell) {
  if (!cell) return true
  const mode = flowFilterMode.value
  if (!mode) return true
  const cross = (cell.data || {}).crossesTrustBoundary === true
  if (mode === 'cross') return cross
  const high = flowHasHighThreat(cell)
  if (mode === 'crossHigh') return cross && high
  return cross || high
}

const flowFilterMode = ref('')
const securityFlowFilter = computed(() => flowFilterMode.value !== '')

function flowHasHighThreat(cell) {
  return (cell?.threats || []).some(
    (t) => String(t.severity || t.level || '').toLowerCase() === 'high',
  )
}

/** 图例徽标：安全相关流数 / 总流数（开不开都显示，让用户预知过滤效果） */
const flowStats = computed(() => {
  const cells = props.model?.detail?.diagrams?.[0]?.cells || []
  const flows = cells.filter((c) => c.shape === 'tm.Flow')
  return {
    total: flows.length,
    cross: flows.filter((c) => (c.data || {}).crossesTrustBoundary === true).length,
    relevant: flows.filter(flowSecurityRelevant).length,
  }
})

const FILTER_LABEL = { '': '全部数据流', cross: '仅跨边界', crossHigh: '跨边界∩高危' }
const filterLabel = computed(() => FILTER_LABEL[flowFilterMode.value] || '')

function toggleSecurityFilter() {
  const cycle = ['', 'cross', 'crossHigh']
  const i = cycle.indexOf(flowFilterMode.value)
  flowFilterMode.value = cycle[(i + 1) % cycle.length]
  applyFlowFilter()
}

/** 把当前档位的可见性写到所有边上 */
function applyFlowFilter() {
  if (!graph) return
  for (const e of graph.getEdges()) {
    const cell = e.getData()?.tdCell
    if (!cell) continue
    e.setVisible(!securityFlowFilter.value || flowSecurityRelevant(cell))
  }
}

function clearHighlight() {
  activeHighlight.value = null
  if (!graph) return
  graph.getNodes().forEach((n) => {
    n.attr('body/style/opacity', 1)
    n.attr('label/style/opacity', 1)
    n.attr('image/style/opacity', 1)
  })
  graph.getEdges().forEach((e) => {
    e.attr('line/style/opacity', 1)
    e.attr('label/style/opacity', 1)
  })
}

function applyHighlight(type) {
  if (!graph) return
  // X6 节点 shape 统一是 'rect'，原始类型存在 data.tdCell.shape 中
  // （type='flow' 目前无 UI 入口——图例里的「数据流」高亮 chip 已按反馈移除；
  //   分支保留，语义仍是"只亮数据流、把节点压暗"，便于以后重新挂入口。）
  const shapeMap = {
    process: 'tm.Process',
    store: 'tm.Store',
    actor: 'tm.Actor',
    // AI 组件也可高亮：第一排四类节点是全套开关，不能有一个点不动
    model: 'tm.Model',
  }
  const targetShape = shapeMap[type]
  graph.getNodes().forEach((n) => {
    const cellShape = n.data?.tdCell?.shape
    const isMatch = cellShape === targetShape
    const opacity = isMatch ? 1 : 0.15
    n.attr('body/style/opacity', opacity)
    n.attr('label/style/opacity', opacity)
    n.attr('image/style/opacity', opacity)
  })
  graph.getEdges().forEach((e) => {
    const isMatch = type === 'flow'
    const opacity = isMatch ? 1 : 0.15
    e.attr('line/style/opacity', opacity)
    e.attr('label/style/opacity', opacity)
  })
}

function sevKey(sev) {
  const s = String(sev || '').toLowerCase()
  if (s.includes('crit')) return 'critical'
  if (s.includes('high')) return 'high'
  if (s.includes('med')) return 'medium'
  if (s.includes('low')) return 'low'
  return 'unknown'
}

// —— 节点视觉规格 ——
// 唯一事实来源是后端 dfd_spec.NODE_STYLE（figure / radius / 配色 / 图标）。
// 这里保留一份**内置兜底**：首屏或接口不可用时仍能画出正确造型，
// 拿到 /threat/api/dfd/spec 后用 applySpec() 覆盖，保证"改一处、两端同时生效"。
const SPEC = {
  nodes: {
    'tm.Actor': { fill: '#e0f2fe', stroke: '#0284c7', text: '#075985', radius: 26, figure: 'capsule', icon: '' },
    'tm.Process': { fill: '#dcfce7', stroke: '#16a34a', text: '#14532d', radius: 8, figure: 'rounded', icon: '' },
    'tm.Store': { fill: '#fef3c7', stroke: '#d97706', text: '#92400e', radius: 0, figure: 'cylinder', icon: '' },
    'tm.BoundaryBox': { fill: '#f1f5f9', stroke: '#64748b', text: '#475569', radius: 6, figure: 'rounded', icon: '' },
    'tm.Model': { fill: '#ede9fe', stroke: '#7c3aed', text: '#4c1d95', radius: 8, figure: 'rounded', icon: '🧠' },
    'tm.Prompt': { fill: '#fae8ff', stroke: '#c026d3', text: '#86198f', radius: 8, figure: 'rounded', icon: '📝' },
    'tm.VectorStore': { fill: '#f5d0fe', stroke: '#a21caf', text: '#701a75', radius: 0, figure: 'cylinder', icon: '📚' },
    'tm.Tool': { fill: '#e0e7ff', stroke: '#4f46e5', text: '#3730a3', radius: 8, figure: 'rounded', icon: '🔧' },
    'tm.TrainingData': { fill: '#e0f2fe', stroke: '#0891b2', text: '#155e75', radius: 8, figure: 'rounded', icon: '🗂️' },
    'tm.AgentConfig': { fill: '#cffafe', stroke: '#0e7490', text: '#164e63', radius: 8, figure: 'rounded', icon: '⚙️' },
  },
  fallbackShape: 'tm.Process',
  cylinder: { capRatio: 0.20, bottomBulge: 0.20, labelCenterRatio: 0.56 },
  // —— 线型规格：权威值在 dfd_spec（flow_stroke_and_dash）。
  // 这里是与之一致的内置兜底，拿到 /api/dfd/spec 后由 applySpec 覆盖。
  // 历史问题：dash '4 3'/'6 4' 与四档线宽在节点样式之外各写一份，
  // 改动时极易只改一端（"图例说虚线、实际画实线"就源于此）。
  flow: {
    defaultStroke: '#475569',
    encrypted: '#16a34a',
    public: '#ea580c',
    dashOutOfScope: [4, 3],
    dashCrossBoundary: [6, 4],
    widthBoth: 2.0,
    widthSingleMark: 1.8,
    widthCross: 1.6,
    widthPlain: 1.4,
    arrowSize: 7.0,
  },
}

// 泳道 / 文本 / 流默认色（不进 NODE_STYLE，单独一项，语义上不是"节点"）
const STYLE = {
  Lane: { fill: '#f4f7fb', stroke: '#cbd5e1', text: '#64748b' },
  Text: { fill: 'transparent', stroke: 'transparent', text: '#334155' },
  Flow: { stroke: '#475569', text: '#475569' },
}

/** 取某 shape 的视觉规格（未知 shape 退回处理过程，与后端 node_spec 同规则）。 */
function nodeSpec(shape) {
  return SPEC.nodes[shape] || SPEC.nodes[SPEC.fallbackShape] || SPEC.nodes['tm.Process']
}

/**
 * 按语义标记算出 (描边色, dash 数组, 线宽)。
 *
 * 与后端 dfd_spec.flow_stroke_and_dash **逐条同规则**，取值全部来自
 * SPEC.flow（由后端下发）。前端不再自带一套硬编码数值，否则改线型
 * 要改两处、且只读/编辑/报告三处观感漂移。
 *   - 颜色：公网 > 加密 > 默认（跨边界不覆盖颜色，只用虚线表达）
 *   - dash：outOfScope > crossBoundary > 实线
 *   - 线宽：加密&公网 > 单标记 > 跨边界 > 普通
 */
function flowStrokeAndDash(enc, pub, cross, oos) {
  const F = SPEC.flow
  const toArr = (v) => (Array.isArray(v) ? v.join(' ') : v)

  const stroke = pub ? F.public : enc ? F.encrypted : F.defaultStroke
  const dash = oos
    ? toArr(F.dashOutOfScope)
    : cross
    ? toArr(F.dashCrossBoundary)
    : null
  let width = F.widthPlain
  if (enc && pub) width = F.widthBoth
  else if (enc || pub) width = F.widthSingleMark
  else if (cross) width = F.widthCross
  return { stroke, dash, width }
}

/** 消费后端 /api/dfd/spec 下发的权威规格（失败静默，用内置兜底继续）。 */
function applySpec(payload) {
  if (!payload) return
  if (payload.nodes && typeof payload.nodes === 'object') {
    for (const [shape, s] of Object.entries(payload.nodes)) {
      SPEC.nodes[shape] = { ...(SPEC.nodes[shape] || {}), ...s }
    }
  }
  if (payload.fallbackShape) SPEC.fallbackShape = payload.fallbackShape
  if (payload.cylinder) {
    if (typeof payload.cylinder.capRatio === 'number') SPEC.cylinder.capRatio = payload.cylinder.capRatio
    if (typeof payload.cylinder.bottomBulge === 'number') SPEC.cylinder.bottomBulge = payload.cylinder.bottomBulge
    if (typeof payload.cylinder.labelCenterRatio === 'number') {
      SPEC.cylinder.labelCenterRatio = payload.cylinder.labelCenterRatio
    }
  }
  // 线型规格：逐字段覆盖，缺字段保持兜底（后端增删字段不会打崩渲染）
  if (payload.flow && typeof payload.flow === 'object') {
    for (const [k, v] of Object.entries(payload.flow)) {
      if (v !== null && v !== undefined) SPEC.flow[k] = v
    }
  }
}

/**
 * 圆柱轮廓 path——**按实际节点尺寸生成绝对坐标**（本地坐标系 0..w / 0..h），
 * 几何与后端 _cylinder() 完全同源：左右直边 + 底部下凸弧（ry=顶盖半高）
 * + 顶盖上凸弧 + 顶盖弦线（capLine 单独画）。
 *
 * 历史版本用 0..100 归一化 path + X6 refD 拉伸到节点 bbox——X6 的 refD
 * 对含圆弧 path 的形状 bbox 计算不可靠（capLine 的注释里踩过一次零高
 * bbox 的坑），弧线被错误缩放后宽扁的存储节点变成"透镜/贝壳"状。
 * 绝对坐标 + 普通 d 属性彻底绕开 refD，圆柱与后端 PNG 同形。
 */
function cylinderBodyD(w, h) {
  const cap = h * (SPEC.cylinder.capRatio || 0.2)
  const bulge = h * (SPEC.cylinder.bottomBulge || 0.2)
  return `M 0 ${cap} L 0 ${h - bulge} `
    + `A ${w / 2} ${cap} 0 0 0 ${w} ${h - bulge} `
    + `L ${w} ${cap} A ${w / 2} ${cap} 0 0 1 0 ${cap} Z`
}

const AI_ICON = Object.fromEntries(
  Object.entries(SPEC.nodes)
    .filter(([, s]) => s.icon)
    .map(([shape, s]) => [shape.replace('tm.', ''), s.icon])
)
const AI_TYPES = new Set(
  Object.keys(SPEC.nodes).filter((k) => AI_ICON[k.replace('tm.', '')])
)

// —— 图例造型绑定 ——
// 图例必须画"和节点一样的形状"，所以直接读同一份规格，而不是维护第二套色点。
function specOf(shape) {
  return nodeSpec(shape)
}

// —— FlowDetailPanel 的派生属性 ——
const flowDetailType = computed(() => {
  if (!flowDetail.value) return ''
  if (flowDetail.value.isEncrypted) return 'enc'
  if (flowDetail.value.isPublicNetwork) return 'pub'
  return 'normal'
})
const flowDetailIcon = computed(() => {
  if (!flowDetail.value) return '⇄'
  if (flowDetail.value.isEncrypted) return '🔒'
  if (flowDetail.value.isPublicNetwork) return '🌐'
  return '⇄'
})
const flowDetailStroke = computed(() => {
  if (flowDetail.value?.isEncrypted) return '#16a34a'
  if (flowDetail.value?.isPublicNetwork) return '#ea580c'
  return '#475569'
})
const flowDetailDasharray = computed(() => {
  if (flowDetail.value?.outOfScope) return '4 3'
  if (flowDetail.value?.crossesTrustBoundary) return '7 5'
  return null
})
function closeFlowDetail() {
  selectedEdgeId.value = null
  flowDetail.value = null
  if (graph) restoreAllEdgeStyles()
  emit('select-cell', null)
}

let visibilityObserver = null
let resizeObserver = null
// 视觉规格是否已从后端覆盖过。只拉一次——规格是常量表，不需要订阅。
let specLoaded = false

/**
 * 拉取后端 /threat/api/dfd/spec 并覆盖内置兜底规格。
 * 路由前缀不能省：威胁建模子应用挂载在 /threat 下（见 backend/main.py 的 app.mount），
 * 与 api/threat.js 的 baseURL 保持一致。
 * 失败静默处理：内置常量与后端当前值一致，图照常渲染，只失去"改一处两端同步"能力。
 * 拉到规格后需要重渲染一次（节点造型/配色在 addNode 里已被固化进 attrs）。
 */
async function loadSpec() {
  if (specLoaded) return
  specLoaded = true
  try {
    const resp = await fetch('/threat/api/dfd/spec')
    if (!resp.ok) return
    const payload = await resp.json()
    const before = JSON.stringify(SPEC)
    applySpec(payload)
    if (JSON.stringify(SPEC) === before) return   // 无变化，不必重渲染
    if (props.model && graph) render(props.model)
  } catch (e) {
    console.warn('[DfdGraph] 拉取 dfd spec 失败，使用内置规格', e)
  }
}

// 容器原生 keydown 监听：编辑模式下 Delete/Backspace 删除选中节点。
// 之所以不用 graph.bindKey，是因为它属于未安装的 x6-plugin-keyboard。
let keydownHandler = null

// 重试渲染工具：当容器尚未挂载时（如 v-if/v-else 切换、路由恢复）延迟重试
function tryRender(model, attempt = 0) {
  if (!model) return
  if (!containerRef.value) {
    if (attempt < 30) {
      setTimeout(() => tryRender(model, attempt + 1), 80)
    } else {
      // 兜底：刷新后 v-show 父级 layout 回流可能慢，把重试拉到约 2.4s
      console.warn('[DfdGraph] containerRef 始终为空，放弃渲染', { attempt })
    }
    return
  }
  // initGraph 内部会绑定事件/插件能力，失败时必须暴露出来：
  // 早期版本在此链路里调用过未安装插件的 API，异常被吞掉后 render() 永不执行，
  // 表现为"画布空白且无任何报错"，排查成本极高。
  try {
    initGraph()
  } catch (e) {
    console.error('[DfdGraph] initGraph 失败,画布无法初始化', e)
    return
  }
  if (graph) render(model)
  // 渲染完成后适配视图
  setTimeout(() => { if (graph) fitView() }, 50)
}

onMounted(() => {
  // 首次挂载：延迟一帧再渲染，确保 DOM 稳定
  nextTick(() => {
    if (props.model) {
      tryRender(props.model)
    }
  })
  // 并行拉取权威视觉规格（不阻塞首屏：内置兜底规格已能画出正确造型）。
  // 拿到后若与内置值有差异会自行重渲染一次。
  loadSpec()
  // 监听容器可见性（el-tabs 切换时组件从 display:none 恢复需重新 fitView）
  nextTick(() => {
    if (containerRef.value && typeof IntersectionObserver !== 'undefined') {
      visibilityObserver = new IntersectionObserver(
        (entries) => {
          for (const entry of entries) {
            if (entry.isIntersecting && graph) {
              setTimeout(() => fitView(), 100)
            }
          }
        },
        { threshold: 0.1 }
      )
      visibilityObserver.observe(containerRef.value)
    }
  })
  // ResizeObserver 兜底：容器尺寸从 0 变 > 0 时主动 fitView
  // 覆盖刷新场景下 threat-page 多层 flex + v-show 父级回流慢导致 fitView 算错尺寸
  if (containerRef.value && typeof ResizeObserver !== 'undefined') {
    resizeObserver = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect
        if (width > 0 && height > 0 && graph) {
          setTimeout(() => fitView(), 50)
        }
      }
    })
    resizeObserver.observe(containerRef.value)
  }
})

function initGraph() {
  if (graph || !containerRef.value) return
  const c = containerRef.value
  const cw = c.clientWidth
  const ch = c.clientHeight
  console.log('[DfdGraph] initGraph start', { cw, ch, containerClass: c.className })
  // 编辑模式：AI 提取的 DFD 必然有误差，允许用户拖动节点微调布局。
  // 注意：拖拽/连线/删除都需要显式进入编辑模式，避免误操作破坏模型，
  // 也避免"只读时拖了节点没保存"导致页面与后端/导出图不一致。
  graph = new Graph({
    container: c,
    grid: { visible: true, size: 20, type: 'dot' },
    background: { color: 'transparent' },
    // 平移与缩放两种模式都保留：只读浏览同样需要挪动/放大看细节
    panning: { enabled: true },
    mousewheel: { enabled: true, zoomAtMousePosition: true },
    selecting: { enabled: true, rubberband: false, showNodeSelectionBox: true },
    interacting: {
      edgeLabelMovable: false,
      // 节点拖动跟随 editable：只读锁定布局，编辑才允许微调
      nodeMovable: !!props.editable,
      arrowheadMovable: false,
    },
    // 只允许编辑模式下从锚点拉线
    connecting: {
      enabled: false,
      snap: { radius: 24 },
      allowBlank: false,
      allowLoop: false,
      allowMulti: true,
      highlight: true,
      router: 'normal',
      connector: { name: 'rounded', args: { radius: 8 } },
      createEdge() {
        return this.createEdge({
          shape: 'edge',
          attrs: {
            line: {
              stroke: '#94a3b8',
              strokeWidth: 1.6,
              targetMarker: { name: 'block', width: 10, height: 7 },
            },
          },
          zIndex: 50,
        })
      },
    },
  })
  // 关键：X6 创建时不知道容器真实尺寸，需同步 resize 一次
  // 否则首次 zoomToFit 可能基于 0 viewport 算出 scale=0/NaN，图"看不见"
  if (cw > 0 && ch > 0) {
    graph.resize(cw, ch)
    console.log('[DfdGraph] initGraph resized', { cw, ch })
  } else {
    console.warn('[DfdGraph] initGraph 容器 0 尺寸,等 ResizeObserver 兜底', { cw, ch })
  }

  // 缩放/平移后把泳道底色带重新拉到视口两端：泳道不参与适配 bbox，
  // 所以调整视口后必须主动同步一次，否则缩放回来又会露出左右空白。
  graph.on('scale', scheduleLaneSync)
  graph.on('translate', scheduleLaneSync)

  graph.on('node:click', ({ node }) => {
    if (isLaneNode(node)) return
    // X6 v2 的"选中" API 是 graph.select(...)，不是 resetSelection。
    // 原代码用 resetSelection 在 v2 会抛 TypeError(在控制台看到但用户感知不到)
    // —— 这也是点击节点不出现内置选中框的原因。
    graph.select([node.id])
    emit('select-cell', node.id)
  })
  graph.on('edge:click', ({ edge }) => {
    // 走完整的"选中 + 详情浮层"流程
    selectEdge(edge.id)
  })
  graph.on('blank:click', () => {
    // 关闭流详情浮层
    if (selectedEdgeId.value) closeFlowDetail()
    else emit('select-cell', null)
  })
  graph.on('node:mouseenter', ({ node }) => {
    if (isLaneNode(node)) return
    if (containerRef.value) containerRef.value.style.cursor = 'pointer'
    showTooltip(node)
  })
  graph.on('node:mouseleave', () => {
    if (containerRef.value) containerRef.value.style.cursor = ''
    tooltip.value.visible = false
  })

  // 拖动时把后端 route 折点「就地重算端点 + 保持通道不动」，而不是丢弃后
  // 交给 X6 manhattan 重算。
  //
  // 为什么不能降级重算：X6 manhattan 会重新选通道，与后端 plan_edge_routes
  // 的结果（过道位置、并行边错位、避障评分）必然不同。用户拖完常常直接导出，
  // 此时还没保存布局，后端仍是旧坐标 —— 页面与 PNG 于是各画一套。
  //
  // 重算策略（保持 route 拓扑与正交性不变）：
  //   - 端点锚点：按**新节点矩形**重算，口径与后端 _anchor 一致
  //     （沿「相邻折点 → 节点中心」方向取矩形边界交点）；
  //   - 与端点相邻的第一个折点：只跟随「该段所在轴」分量，
  //     使最后一段仍正交，而通道所在的另一轴保持后端原值；
  //   - 其余折点与另一端点：完全不动（通道位置由后端决定，不因拖动漂移）。
  // 这样线会跟着节点走，整体形状与后端同构；保存后后端重算的结果也接近。
  function boundaryPointToward(rect, toward) {
    // rect: {x, y, width, height}；toward: 目标点（通常是折点）
    // 返回「节点中心 → toward」射线与矩形边界的交点（与后端口径一致）
    const cx = rect.x + rect.width / 2
    const cy = rect.y + rect.height / 2
    const dx = toward.x - cx
    const dy = toward.y - cy
    if (Math.abs(dx) < 1e-6 && Math.abs(dy) < 1e-6) {
      return { x: cx, y: rect.y + rect.height }
    }
    const hw = rect.width / 2
    const hh = rect.height / 2
    // 求射线离开矩形的参数 t
    const tx = Math.abs(dx) < 1e-6 ? Infinity : hw / Math.abs(dx)
    const ty = Math.abs(dy) < 1e-6 ? Infinity : hh / Math.abs(dy)
    const t = Math.min(tx, ty)
    return { x: cx + dx * t, y: cy + dy * t }
  }

  // 按节点的新矩形重建 route 的某一端（另一端保持不动）。
  // 返回新的点列，保证：端点贴合新矩形、所有相邻段严格 H/V（无斜线）。
  function rebuildRouteEnd(route, isSrc, rect) {
    const pts = route.map((p) => ({ x: p.x, y: p.y }))
    if (pts.length < 2) return null
    const anchorIdx = isSrc ? 0 : pts.length - 1
    const adjIdx = isSrc ? 1 : pts.length - 2
    if (adjIdx < 0 || adjIdx >= pts.length) return null

    const adj = pts[adjIdx]
    const oldAnchor = pts[anchorIdx]
    const newAnchor = boundaryPointToward(rect, adj)

    // 与端点相邻的那一段原本是水平还是竖直：由「旧锚点 → adj」判定。
    // 这段方向必须保持，否则新锚点接上去就会产生斜线。
    const segH = Math.abs(adj.x - oldAnchor.x) >= Math.abs(adj.y - oldAnchor.y)
    const eps = 1e-6
    let insert = null
    if (segH) {
      // 原为水平段 → 新锚点需与 adj 同 y；不同则插一个过渡点
      if (Math.abs(newAnchor.y - adj.y) > eps) insert = { x: newAnchor.x, y: adj.y }
    } else {
      // 原为竖直段 → 新锚点需与 adj 同 x
      if (Math.abs(newAnchor.x - adj.x) > eps) insert = { x: adj.x, y: newAnchor.y }
    }

    const out = isSrc
      ? [newAnchor, ...(insert ? [insert] : []), ...pts.slice(1)]
      : [...pts.slice(0, -1), ...(insert ? [insert] : []), newAnchor]

    // 去掉相邻重复点（插入点可能与 newAnchor 或 adj 重合）
    const dedup = []
    for (const p of out) {
      const last = dedup[dedup.length - 1]
      if (last && Math.abs(last.x - p.x) < eps && Math.abs(last.y - p.y) < eps) continue
      dedup.push(p)
    }
    return dedup
  }

  // 依据「相对后端基准的节点位移」重建一条边，返回 { pts, shifts }。
  //
  // 基准是后端原始 route（_routeBase，不可变），因此：
  //   - 反复拖动不会累积多余折点；
  //   - 拖动多个节点时各端位移叠加（先拖源、再拖目标，两端都生效）；
  //   - 节点被拖回基准位置时，该端恢复后端原始形状。
  //
  // nodeId 为本次正在拖动的节点（可为 null，表示只按已有位移重建）。
  function rebuildEdgeRoute(edge, nodeId) {
    const ed = edge.getData?.() || {}
    const base = ed._routeBase
    if (!Array.isArray(base) || base.length < 2) return null
    const cell = ed.tdCell || {}
    const srcId = cell.source?.cell
    const tgtId = cell.target?.cell
    const shifts = { ...(ed._nodeShifts || {}) }

    // 更新本次拖动节点的位移标记：与后端基准坐标比对，
    // 差异 ≤0.5px 视为未移动（避免浮点噪音与"拖回原位"误判）。
    if (nodeId) {
      const node = graph.getCellById(nodeId)
      const pos = node?.position?.()
      const basePos = ed._basePositions?.[nodeId]
      const moved = !basePos || !pos
        ? false
        : (Math.abs(basePos.x - pos.x) > 0.5 || Math.abs(basePos.y - pos.y) > 0.5)
      if (moved) shifts[nodeId] = true
      else delete shifts[nodeId]
    }

    const rectOf = (cid) => {
      const n = graph.getCellById(cid)
      const p = n?.position?.()
      const s = n?.size?.()
      return p && s ? { x: p.x, y: p.y, width: s.width, height: s.height } : null
    }

    let pts = base.map((p) => ({ x: p.x, y: p.y }))
    // 两端各自只改相邻折点，顺序无关
    if (srcId && shifts[srcId]) {
      const r = rectOf(srcId)
      if (r) pts = rebuildRouteEnd(pts, true, r) || pts
    }
    if (tgtId && shifts[tgtId]) {
      const r = rectOf(tgtId)
      if (r) pts = rebuildRouteEnd(pts, false, r) || pts
    }
    return { pts, shifts }
  }

  // 让被拖节点的相连边跟随：重建端点锚点、保持通道折点不动。
  // 拖动中（node:moving）与松手后（node:moved）都调用，保证线实时跟随
  // 且形状始终与后端同构。
  function refollowEdges(node) {
    try {
      graph.getConnectedEdges(node).forEach((e) => {
        const ed = e.getData?.() || {}
        if (!ed._backendRoute) return
        const rebuilt = rebuildEdgeRoute(e, node.id)
        if (rebuilt) {
          e.setVertices(rebuilt.pts)
          e.setData({ _nodeShifts: rebuilt.shifts })
        }
        // 标签若来自布局期绝对坐标（labelX/labelY），节点一动该坐标就失效
        // ——必须切回"沿边参数化"定位，否则标签会留在旧位置与线脱节。
        // 用拖动前的 labelT/labelOffset（若布局期给过）作为参数化落点。
        if (ed._absLabel) {
          const hint = currentLayoutHints?.[ed.tdCell?.data?.flowId] || {}
          const hp = labelPos(e.id)
          const dist = typeof hint.labelT === 'number' ? hint.labelT : hp.distance
          const off = typeof hint.labelOffset === 'number' ? hint.labelOffset : hp.offset
          e.setData({ _absLabel: false })
          e.prop('labels/0/position', { distance: dist, offset: off })
          e.prop('labels/0/attrs/label/textAnchor', null)
          e.prop('labels/0/attrs/label/textVerticalAnchor', null)
        }
      })
    } catch { /* 折点重建失败不影响拖拽流程 */ }
  }

  // 拖动过程中实时跟随（否则线要等松手才跳到新位置，观感是"线脱节"）
  graph.on('node:moving', ({ node }) => {
    if (isLaneNode(node)) return
    refollowEdges(node)
  })

  // 拖拽结束：把新坐标回传给父组件，由其负责持久化到后端/本地模型。
  // 只上报真实位移，避免点击时的 0 位移噪音。
  graph.on('node:moved', ({ node }) => {
    const pos = node.position()
    const data = node.getData?.() || {}
    const tdCell = data.tdCell || {}
    const reallyMoved = !(tdCell.position
      && tdCell.position.x === pos.x && tdCell.position.y === pos.y)
    // 拖动节点后端点锚点随节点平移；通道折点保持不动（见函数注释）。
    // 不再降级 manhattan —— 那会让页面与后端 PNG 画成两张不同的图。
    if (reallyMoved) {
      refollowEdges(node)
      // 位移后跨界标记的交点已失效（按旧路由算的）：全部清除，
      // 等下一次整图渲染重建
      graph.getNodes()
        .filter((n) => n.getData?.()?.crossMarker === true)
        .forEach((n) => n.remove())
    }
    if (isLaneNode(node) || !props.editable) return
    if (!reallyMoved) return
    emit('node-moved', { cellId: node.id, x: pos.x, y: pos.y })
  })

  // 双击节点：编辑模式下弹窗重命名
  graph.on('node:dblclick', ({ node }) => {
    if (isLaneNode(node) || !props.editable) return
    const data = node.getData?.() || {}
    const tdCell = data.tdCell || {}
    const current = ((tdCell.data || {}).name) || ''
    const next = window.prompt('修改元素名称：', current)
    if (next == null) return
    const name = next.trim()
    if (!name || name === current) return
    node.attr('label/text', name)
    emit('node-renamed', { cellId: node.id, name })
  })

  // 删除键：编辑模式下移除选中的节点（数据流边不允许单独删除，避免破坏模型一致性）
  // 注意：不使用 graph.bindKey —— 那是 @antv/x6-plugin-keyboard 的 API，
  // 本项目未安装该插件（package.json 仅依赖 @antv/x6 与 x6-plugin-snapline），
  // 直接调用会在 initGraph 抛 TypeError，导致后续 render() 永远不执行、画布空白。
  // 因此改为在容器上监听原生 keydown，行为等价且无额外依赖。
  keydownHandler = (ev) => {
    if (!props.editable) return
    if (ev.key !== 'Delete' && ev.key !== 'Backspace') return
    const target = ev.target
    // 输入态（如双击改名弹窗/输入框）不劫持删除键，避免误删节点或影响输入
    if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable)) return
    const nodes = graph.getSelectedCells().filter((c) => c.isNode() && !isLaneNode(c))
    if (!nodes.length) return
    ev.preventDefault()
    nodes.forEach((n) => {
      emit('node-removed', { cellId: n.id })
      n.remove()
    })
  }
  c.addEventListener('keydown', keydownHandler)
  // 让容器可聚焦，否则 keydown 只在容器内已有焦点元素时才触发
  if (!c.hasAttribute('tabindex')) c.setAttribute('tabindex', '0')
}

// 泳道背景 / 跨界落点标记：不可交互（不触发选中 / 点击 / 悬停浮层 / 删除）
function isLaneNode(node) {
  const d = node?.getData?.() || node?.data || {}
  return d.lane === true || d.crossMarker === true
}

function showTooltip(node) {
  if (isLaneNode(node)) return
  const cell = node?.getData?.()?.tdCell || node?.data?.tdCell || node?.getData?.()
  const threats = (cell?.threats || []).filter((t) => !t.outOfScope)
  const rect = containerRef.value?.getBoundingClientRect?.()
  const bbox = node.getBBox?.() || { x: 0, y: 0, width: 0, height: 0 }
  let left = bbox.x + bbox.width + 14
  let top = bbox.y + bbox.height + 12
  if (rect && graph) {
    try {
      const client = graph.localToClient({ x: bbox.x + bbox.width, y: bbox.y + bbox.height })
      left = client.x - rect.left + 12
      top = client.y - rect.top + 12
    } catch (e) {
      /* fallback to bbox */
    }
    left = Math.min(Math.max(left, 10), rect.width - 290)
    if (top + 150 > rect.height) top = Math.max(10, top - 170)
  }
  tooltip.value = {
    visible: true,
    name: cell?.name || node.label || '组件',
    threats,
    style: { left: `${left}px`, top: `${top}px` },
  }
}

onBeforeUnmount(() => {
  // 先停掉挂起的泳道同步帧：回调里会访问已 dispose 的 graph
  if (laneSyncRaf) {
    cancelAnimationFrame(laneSyncRaf)
    laneSyncRaf = 0
  }
  laneBands = []
  if (graph) {
    graph.dispose()
    graph = null
  }
  if (visibilityObserver) {
    visibilityObserver.disconnect()
    visibilityObserver = null
  }
  if (resizeObserver) {
    resizeObserver.disconnect()
    resizeObserver = null
  }
  if (keydownHandler && containerRef.value) {
    containerRef.value.removeEventListener('keydown', keydownHandler)
    keydownHandler = null
  }
})

watch(
  () => props.model,
  (m) => {
    // model 从无到有时调用重试渲染（内部会等待容器挂载）
    if (m) {
      tryRender(m)
      return
    }
    // model 清空时仅清理图内容
    if (graph) graph.clearCells()
  },
  // flush:'post' 让 callback 在 DOM 更新（v-if/v-else 切换）完成后再执行，
  // 避免刷新场景下 v-else 还没渲染时 containerRef 还是 null
  { immediate: false, flush: 'post' }
)

watch(
  () => props.highlightCellId,
  (id) => {
    focusCell(id)
  }
)

// 同一 cell 重复定位时 highlightCellId 不变，watch 不会触发；
// 父组件用 locateNonce 递增强制驱动一次（解决"点了没反应"）。
watch(
  () => props.locateNonce,
  () => {
    focusCell(props.highlightCellId)
  }
)

/**
 * 高亮指定 cell。默认不动视图（画布保持用户当前的缩放/位置），
 * 仅当该 cell 完全在当前视口外时才把视图平移过去 ——
 * 否则"定位"了却看不到任何高亮，功能等于失效。
 */

/** 把视图平移让 cell 进入视口（优先保持当前缩放） */
function centerOn(cell) {
  try {
    if (typeof graph.centerCell === 'function') {
      graph.centerCell(cell)
      return
    }
    const b = cell.getBBox?.()
    if (b && typeof graph.zoomTo === 'function') {
      graph.zoomTo(b, { padding: 40, minScale: 0.3, maxScale: 1.2 })
    }
  } catch (e) {
    console.warn('[DfdGraph] centerOn 失败:', e?.message || e)
  }
}

function isCellVisible(cell) {
  try {
    // flush:false 让它拿实时几何；边的 bbox 在未完成布局时可能为 0 尺寸，
    // 此时宁可判定为"不可见"把视图带过去，也好过边在视口外却不动画布。
    const b = cell.getBBox?.({ flush: false })
    const a = graph?.getGraphArea?.()
    if (!b || !a) return true
    if (!b.width && !b.height) return false
    const p = 12
    return b.x + b.width > a.x + p && b.x < a.x + a.width - p
      && b.y + b.height > a.y + p && b.y < a.y + a.height - p
  } catch (e) {
    return true
  }
}

function focusCell(id) {
  if (!graph || !id) return
  const cell = graph.getCellById(id)
  if (!cell) {
    console.warn('[DfdGraph] focusCell: 找不到 cell', id)
    return
  }
  // 不调用 graph.resetSelection —— 这版 X6 在某些路径上
  // 抛 TypeError(graph.resetSelection is not a function),整条 watcher 链路都被
  // Vue 吞掉,导致 emphasisCell/centerCell 全部不执行,体感"点了没反应"。
  // emphasisCell 已经提供视觉反馈,不需要内置选中。
  // 「只看跨边界」开启时，被过滤隐藏的数据流也要能被定位到：
  // 威胁列表的"定位"可能指向隐藏的流，此时临时恢复显示该边，
  // 否则高亮/居中都作用在不可见元素上，等于"点了没反应"。
  if (cell.isEdge?.() && !cell.isVisible()) {
    cell.setVisible(true)
  }
  emphasisCell(cell)
  // 仅在"完全看不见"时才平移动视图；可见时保持画布纹丝不动
  if (!isCellVisible(cell)) centerOn(cell)
}

// 当前正在做强调动画的 cell id 与其原始描边，用于动画结束后还原
let emphasisTimer = null
let emphasisOriginal = null
// isCellVisible / centerOn 定义在文件末尾的 helper 区

/**
 * 节点脉冲强调：描边加粗变紫 + 轻微放大，1.2s 后还原。
 * 解决"resetSelection 无视觉反馈"的问题——用户能明确看到定位到了哪个节点。
 */
/**
 * 定位强调的属性名：节点用 body/*，边（数据流）用 line/*。
 * 必须区分——DFD 里大量威胁挂在数据流上（flowCount 40 / componentCount 19），
 * 早先只处理 isNode 会在点击数据流类威胁时静默 return：
 * 无日志、无高亮，用户体感"点了没反应"。
 */
function emphasisAttrsOf(cell) {
  return cell?.isEdge?.()
    ? { stroke: 'line/stroke', width: 'line/strokeWidth' }
    : { stroke: 'body/stroke', width: 'body/strokeWidth' }
}

/** 记录 cell 当前描边，供动画结束后还原 */
function snapshotStroke(cell) {
  const a = emphasisAttrsOf(cell)
  return { id: cell.id, stroke: cell.attr(a.stroke), strokeWidth: cell.attr(a.width) }
}

/** 把描边写回快照值 */
function restoreStroke(cell, snap) {
  const a = emphasisAttrsOf(cell)
  cell.attr(a.stroke, snap.stroke)
  cell.attr(a.width, snap.strokeWidth)
}

function emphasisCell(cell) {
  if (!cell) return
  // 节点与边都要支持；泳道背景是纯排版元素（威胁不会挂在其上），
  // 其余辅助图形（text 等）同样不做强调
  if (isLaneNode(cell)) return
  if (!cell.isNode?.() && !cell.isEdge?.()) return
  try {
    // 连续点击时先还原上一个，避免样式叠加残留
    if (emphasisTimer) {
      clearTimeout(emphasisTimer)
      emphasisTimer = null
    }
    if (emphasisOriginal) {
      const prev = graph?.getCellById?.(emphasisOriginal.id)
      if (prev) restoreStroke(prev, emphasisOriginal)
      emphasisOriginal = null
    }
    emphasisOriginal = snapshotStroke(cell)
    const a = emphasisAttrsOf(cell)
    cell.attr(a.stroke, '#7c3aed')
    cell.attr(a.width, 3)
    emphasisTimer = setTimeout(() => {
      // 还原时需要重新取 cell（避免持有已销毁引用）
      const c = graph?.getCellById?.(emphasisOriginal?.id)
      if (c && emphasisOriginal) restoreStroke(c, emphasisOriginal)
      emphasisOriginal = null
      emphasisTimer = null
    }, 1200)
  } catch (e) {
    console.warn('[DfdGraph] emphasisCell 失败:', e?.message || e)
  }
}

// 编辑模式切换：开启后允许从锚点拉线新建数据流、拖动节点微调布局
watch(
  () => props.editable,
  (on) => {
    if (!graph) return
    graph.options.connecting.enabled = !!on
    // 只读时锁定节点位置，避免"拖了没保存"造成页面与导出图不一致
    if (graph.options.interacting) {
      graph.options.interacting.nodeMovable = !!on
    }
    // 已选中的节点在只读态下不再可拖，清掉选中框避免误导
    if (!on) graph.cleanSelection?.()
  }
)

function render(model) {
  if (!graph) {
    console.warn('[DfdGraph] render: graph is null,跳过')
    return
  }
  graph.clearCells()
  currentLayoutHints = null   // 避免无模型/缺 diagram 时残留上一次的 hints
  // 泳道原始几何随 cells 一起清空：换图后若还留着上一张图的 band，
  // 拉宽逻辑会去 getCellById 一个已不存在的泳道（白跑一轮并且语义错乱）。
  laneBands = []
  if (laneSyncRaf) {
    cancelAnimationFrame(laneSyncRaf)
    laneSyncRaf = 0
  }
  if (!model) return
  const diagram = model.detail?.diagrams?.[0]
  if (!diagram) {
    console.warn('[DfdGraph] render: model.detail.diagrams[0] 缺失', { hasModel: !!model })
    return
  }
  const cells = diagram.cells || []
  // 供 addNode 内"空 trust boundary 判定"使用
  allCellsRef = cells
  // D2/D5：后端布局提示（标签锚点 / 跨泳道过道错位）。老模型没有这个字段，
  // 此时为 null，addEdge 会退回原有的哈希分散策略，行为与修复前一致。
  currentLayoutHints = diagram.layoutHints || null
  console.log('[DfdGraph] render start', {
    cellsCount: cells.length,
    lanesCount: (diagram.lanes || []).length,
    firstCell: cells[0] ? { id: cells[0].id, pos: cells[0].position, size: cells[0].size, shape: cells[0].shape } : null,
  })
  try {
    // 生命周期泳道背景（后端在生命周期泳道布局时输出 diagram.lanes）
    for (const lane of diagram.lanes || []) {
      addLane(lane)
    }
    for (const cell of cells) {
      if (cell.shape === 'tm.Flow' && cell.source?.cell && cell.target?.cell) {
        addEdge(cell)
      } else if (cell.shape === 'tm.Text') {
        addTextNode(cell)
      } else {
        addNode(cell)
      }
    }
    // 全部边就位后跑一次内容级标签避让（需要完整路径几何才能取锚点）
    avoidEdgeLabels()
    // 跨界落点标记：必须在全部边/边界就位后计算交点（依赖路由顶点）
    addCrossMarkers()
    console.log('[DfdGraph] render done, cells in graph:', graph.getCells().length)
  } catch (e) {
    console.error('[DfdGraph] render error:', e, e.stack)
  }
  // 延迟 fitView，确保容器已完成布局（el-tabs 切换时容器可能刚从 display:none 恢复）
  requestAnimationFrame(() => {
    setTimeout(() => fitView(), 100)
  })
}

// 节点类型副标签（与后端 PNG 渲染器 TYPE_LABEL 一致）：
// 名称下方的类型小字是商业级图例语义的一部分，读者不必靠颜色猜形状含义。
// 权威来源是 dfd_spec 的 label_zh，这里只保留最小值兜底（首屏/离线时用）。
const TYPE_LABEL = {
  'tm.Actor': '外部实体',
  'tm.Process': '处理过程',
  'tm.Store': '数据存储',
}

/** 是否是信任边界容器（容器走"圆角矩形 + 虚线 + 左上角名称"，不参与 node figure）。 */
function isBoundaryShape(shape) {
  return shape === 'tm.BoundaryBox'
}

function addNode(cell) {
  const data = cell.data || {}
  const shape = cell.shape || 'tm.Process'
  // AI 子类型从 data.aiElementType 读取（data.type 已是 TD-可识别的形状）
  const aiType = (data.aiElementType || '').replace('tm.', '')
  const aiStyleKey = AI_ICON[aiType] ? aiType : null
  // 造型键与配色键的统一取法：AI 子类型优先，否则按 cell.shape。
  // 两者都查 dfd_spec 派生的 SPEC.nodes，因此"圆柱/胶囊"与配色永远同源。
  const specShape = aiStyleKey ? `tm.${aiStyleKey}` : shape
  const s = nodeSpec(specShape)
  const figure = isBoundaryShape(shape) ? 'rounded' : s.figure
  const isBoundary = isBoundaryShape(shape)
  const pos = cell.position || { x: 0, y: 0 }
  const size = cell.size || { width: 180, height: 60 }
  const name = data.name || '未命名'
  // 只显示"未缓解"威胁——已 Mitigated 的不应误导读者
  const openThreats = (cell.threats || []).filter((t) => t.status !== 'Mitigated')
  const threatCount = openThreats.length
  const icon = aiStyleKey ? (s.icon || AI_ICON[aiStyleKey]) + ' ' : ''
  // 威胁数不再拼进 label（会顶出节点高度、把字号挤小）。
  // 改为节点下方独立的小徽标：名称保持 12px 可读，徽标作次要信息。
  const typeTag = aiStyleKey ? ` [${aiType}]` : ''

  // 空 trust boundary：LLM 偶尔会生成没有 child 的边界容器（噪音），画出来只会让图更乱，直接隐藏。
  // 边界显示矩形（含成员包围盒收缩）统一由 boundaryLayout 计算——
  // 跨界落点标记（addCrossMarkers）必须用同一个矩形，才能贴住可见边框。
  const bl = isBoundary ? boundaryLayout(cell) : null
  const isEmptyBoundary = isBoundary && bl.memberCount === 0

  // 威胁徽标画进节点自身 markup（而不是独立 cell）：
  // 独立 cell 会被框选/fitView/allCellsRef 当成真实元素，还会在拖动时滞留原地，
  // 用 markup 追加一个 <rect>+<text> 最省事——自动跟随节点、不污染数据。
  const showBadge = threatCount > 0 && !isEmptyBoundary
  const badgeText = threatCount > 9 ? '9+' : String(threatCount)

  // 显示矩形：边界按 boundaryLayout 结果，其余用原尺寸
  let drawX = pos.x
  let drawY = pos.y
  let drawW = size.width
  let drawH = size.height
  if (bl) {
    drawX = bl.rect.x0
    drawY = bl.rect.y0
    drawW = bl.rect.x1 - bl.rect.x0
    drawH = bl.rect.y1 - bl.rect.y0
  }

  // 类型副标签行：AI 子类型已有 [type] 标记时不重复加；
  // 名称换行后 ≤2 行才追加，保证"名称 + 类型"不超过 3 行溢出节点。
  // 圆柱的可视文字带只有中间 60%（顶盖/底弧各占 20%），名称最多 1 行。
  const isCylinder = figure === 'cylinder'
  // 字号 13：后端 PNG 用 15px，X6 受 60px 节高约束取折中；
  // 换行宽度按节点实际宽度估算（CJK 字宽≈字号），不再用固定 16 字。
  const nodeFontSize = 13
  const wrapChars = Math.max(5, Math.floor((drawW - 24) / nodeFontSize))
  const wrappedName = wrapLabel(name, isCylinder ? Math.min(12, wrapChars) : wrapChars)
  const nameLines = wrappedName.split('\n').length
  const typeLine = s.labelZh || TYPE_LABEL[shape]
  const fullText = icon + wrappedName + typeTag
    + (!typeTag && typeLine && nameLines <= (isCylinder ? 1 : 2) ? `\n${typeLine}` : '')

  // 造型轮廓 markup：body 的 tagName 由 figure 决定——
  //   cylinder → path（cylinderBodyD 按节点实际宽高生成绝对坐标，几何
  //   与后端 _cylinder 同源；不用 refD——它对含弧 path 的 bbox 计算不可靠，
  //   会把宽扁的存储节点缩成"透镜"状）
  //   capsule  → 胶囊是圆角矩形的一种（rx 由 SPEC.radius 给，clamp 到 h/2）
  //   rounded  → 圆角矩形
  // 圆柱还要补一条顶盖弦线（capLine）：后端 _cylinder 专门画这条
  // "上沿翻边"（spec.CYLINDER_CAP_LINE_Y），缺了它圆柱顶是纯椭圆，观感不同。
  const baseMarkup = [
    { tagName: 'text', selector: 'label' },
    {
      tagName: 'g',
      selector: 'badgeGroup',
      children: [
        { tagName: 'rect', selector: 'badgeBody' },
        { tagName: 'text', selector: 'badgeText' },
      ],
    },
  ]
  const nodeMarkup = isCylinder
    ? [
        { tagName: 'path', selector: 'body' },
        { tagName: 'path', selector: 'capLine' },
        ...baseMarkup,
      ]
    : [
        { tagName: 'rect', selector: 'body' },
        ...baseMarkup,
      ]
  // 胶囊半径不得超过高度一半（与后端 min(radius, h/2) 同规则，防溢出变形）
  const radius = figure === 'capsule'
    ? Math.min(s.radius || 0, drawH / 2)
    : (s.radius || 0)

  const capPx = drawH * (SPEC.cylinder.capRatio || 0.2)
  const bodyAttrs = isCylinder
    ? {
        // 绝对坐标 path（节点本地 0..drawW / 0..drawH）——与 capLine 同一
        // 坐标口径，和后端 _cylinder 逐像素同形
        d: cylinderBodyD(drawW, drawH),
        fill: isEmptyBoundary ? 'transparent' : s.fill,
        stroke: isEmptyBoundary ? 'transparent' : s.stroke,
        strokeWidth: 1.6,
      }
    : {
        fill: isEmptyBoundary ? 'transparent' : s.fill,
        stroke: isEmptyBoundary ? 'transparent' : s.stroke,
        strokeWidth: isBoundary ? 2 : 1.6,
        // 只有 trust boundary 自身画虚线；AI 子类型不应再用虚线表达
        strokeDasharray: isBoundary ? '10 5' : null,
        rx: radius,
        ry: radius,
      }

  graph.addNode({
    id: cell.id,
    x: drawX,
    y: drawY,
    width: drawW,
    height: drawH,
    shape: 'rect',
    // 节点 zIndex 必须高于 lane（-100）和边（50），才能保证节点始终可点、可读、不被遮挡。
    zIndex: cell.zIndex ?? 200,
    visible: !isEmptyBoundary,
    data: { tdCell: cell },
    markup: nodeMarkup,
    attrs: {
      body: bodyAttrs,
      capLine: isCylinder
        ? {
            // 顶盖弦线：绝对坐标 d（node 本地坐标系 0..drawW / 0..drawH）。
            // 不能用 refD：水平线的形状 bbox 高为 0，refD 对零高形状 sy=1，
            // y 会停在 20px 绝对位置而不是按比例缩放。
            d: `M 0 ${capPx} L ${drawW} ${capPx}`,
            stroke: isEmptyBoundary ? 'transparent' : s.stroke,
            strokeWidth: 1.6,
          }
        : null,
      label: isBoundary
        ? {
            // 边界名称贴左上角（与后端 PNG 一致），白描边保证压线可读
            text: name,
            fill: s.text,
            fontSize: nodeFontSize,
            fontWeight: 600,
            textAnchor: 'start',
            refX: 10,
            refY: 8,
            stroke: '#ffffff',
            strokeWidth: 3,
            paintOrder: 'stroke',
            strokeLinejoin: 'round',
          }
        : {
            text: fullText,
            fill: s.text,
            fontSize: nodeFontSize,
            // 有未缓解威胁时加粗，作为"整体扫视"的粗粒度信号；
            // 精确条数由右下角徽标承担，不需再靠字重区分。
            fontWeight: threatCount > 0 ? 700 : 500,
            lineHeight: 17,
            // 圆柱标签下移到"可视文字带"中心（顶盖 20% + 底弧 20% 之间的 60%），
            // 与后端 CYLINDER_LABEL_CENTER_RATIO 同值；矩形/胶囊保持垂直居中。
            ...(isCylinder ? { refY: drawH * SPEC.cylinder.labelCenterRatio } : {}),
          },
      // 徽标整组贴在右下角：refX/refY 相对节点宽高定位，
      // 节点被 resize 时 X6 会自动重算，不需要额外监听。
      badgeGroup: {
        // 用 ref 定位而不是绝对坐标，随节点尺寸自适应
        display: showBadge ? 'block' : 'none',
        refX: drawW - (badgeText.length > 1 ? 30 : 22),
        refY: drawH - 18,
      },
      badgeBody: {
        width: badgeText.length > 1 ? 28 : 20,
        height: 14,
        rx: 7,
        ry: 7,
        fill: '#dc2626',
        stroke: 'none',
      },
      badgeText: {
        text: '⚠' + badgeText,
        fill: '#fff',
        fontSize: 9.5,
        fontWeight: 700,
        refX: badgeText.length > 1 ? 14 : 10,
        refY: 7,
        textAnchor: 'middle',
        textVerticalAnchor: 'middle',
      },
    },
  })
}

function addTextNode(cell) {
  const pos = cell.position || { x: 0, y: 0 }
  graph.addNode({
    id: cell.id,
    x: pos.x,
    y: pos.y,
    width: 200,
    height: 30,
    shape: 'rect',
    attrs: {
      body: { fill: 'transparent', stroke: 'transparent' },
      label: {
        text: cell.data?.name || '',
        fill: STYLE.Text.text,
        fontSize: 13,
        fontStyle: 'italic',
      },
    },
  })
}

// 生命周期泳道背景：半透明底色 + 泳道标签（不可交互）。
// 标签样式对齐后端 PNG：CJK 标签在泳道左缘竖排（每字一行），
// 含拉丁字符的保持横排（竖排英文不可读）。
function addLane(lane) {
  const label = lane.label || ''
  const isCjk = [...label].length > 0 && [...label].every((ch) => ch.charCodeAt(0) > 255)
  const labelRefX = isCjk ? 10 : 16
  // 记录后端下发的原始几何：拉宽泳道时按 band.x 判断"只增不减"，
  // 并按 (band.x - 新左缘) 补偿标题锚点。
  laneBands.push({
    id: `lane-${lane.key || label}`,
    x: lane.x,
    y: lane.y,
    width: lane.width,
    height: lane.height,
    labelRefX,
  })
  graph.addNode({
    id: `lane-${lane.key || label}`,
    x: lane.x,
    y: lane.y,
    width: lane.width,
    height: lane.height,
    shape: 'rect',
    zIndex: -100,
    data: { lane: true, tdCell: null },
    attrs: {
      body: {
        fill: STYLE.Lane.fill,
        stroke: STYLE.Lane.stroke,
        strokeWidth: 1,
        // 直角对齐后端 PNG（泳道是"分区底色"，不是卡片）
        rx: 0,
        ry: 0,
      },
      label: {
        text: isCjk ? [...label].join('\n') : label,
        fill: STYLE.Lane.text,
        fontSize: 13,
        fontWeight: 600,
        lineHeight: 16,
        textAnchor: 'start',
        refX: labelRefX,
        // refY 是文字块**中心**相对矩形顶边的偏移（X6 默认 textVerticalAnchor
        // 为 middle），取 lane.height / 2 即"落在泳道中线上"。
        // 口径与后端 PNG 完全一致：dfd_renderer 里泳道标签是
        //   _vertical_text(draw, label, x0 + S(8), (y0 + y1) / 2, ...)
        // —— 竖排文字以泳道垂直中线为中心。
        // 历史值 18 / 22 是"贴顶"，画布上标题会压在上沿、看着不在泳道里。
        refY: lane.height / 2,
      },
    },
  })
}

// 泳道标题距"泳道可见左边缘"的视觉内缩（屏幕像素）。泳道被拉宽到视口两端时，
// 标题贴在这条内缩线上（行头式），既不飘在泳道中段、也不会随越界左缘跑丢。
const TITLE_INSET_PX = 16

/**
 * 泳道底色带横向铺满视口（"泳道左右两侧不要再留空白"）。
 *
 * 为什么需要：后端下发的泳道矩形只包裹内容（例如 x=40..1106），而画布视口
 * 通常比内容宽得多。适配视图按**内容**宽高比等比缩放（本图纵向泳道多、
 * 由高度决定缩放比）之后，泳道左右两侧会各剩一大块空白——观感就是
 * "泳道只占中间一条窄带，左右两边空空的"。
 *
 * 做法与约束：
 *   · 泳道是分区底色（zIndex -100、不可交互、被 fitView 排除在 bbox 之外），
 *     因此拉宽它**不改变**节点/连线/标签的任何模型坐标，也不影响适配比例；
 *   · 只改左右，不动高度：泳道高度是"行高"语义，改了会让跨道流的过道错位；
 *   · 只增不减：视口比泳道窄（放大看细节）时保持后端原宽，避免泳道反而
 *     比内容还窄；
 *   · 泳道标题贴住**可见左边缘**（行头式）：泳道被拉宽后，标题必须跟着
 *     可见左缘走，否则它会悬在泳道中段、看着"不在泳道里"（见下方注释）。
 */
function syncLaneBandWidth() {
  if (!graph || !laneBands.length) return
  const cw = containerRef.value?.clientWidth || 0
  if (cw <= 0) return
  const s = graph.zoom()
  if (!s || !Number.isFinite(s) || s <= 0) return
  const t = graph.translate() || {}
  const tx = Number(t.tx) || 0
  // 视口在模型坐标系里的横向范围：screen = model * s + tx
  const viewX0 = (0 - tx) / s
  const viewX1 = (cw - tx) / s
  // 视觉 ~24px 的越界余量（换算回模型坐标）：让泳道左右边缘始终落在视口外，
  // 避免浮点取整后在画布左/右露出发丝宽的白缝。
  const pad = 24 / s
  // 泳道标题距"可见左边缘"的视觉内缩（屏幕像素），换算成模型坐标。
  const titleInset = TITLE_INSET_PX / s
  for (const band of laneBands) {
    const cell = graph.getCellById(band.id)
    if (!cell) continue
    const x0 = Math.min(viewX0 - pad, band.x)
    const x1 = Math.max(viewX1 + pad, band.x + band.width)
    const width = x1 - x0
    const pos = cell.position()
    const size = cell.size()
    if (Math.abs(pos.x - x0) >= 0.5 || Math.abs(size.width - width) >= 0.5) {
      cell.position(x0, pos.y)
      cell.size(width, size.height)
    }
    // 标题锚点（行头式）：跟着**可见的左边缘**走，不再留在内容旁边。
    //   · 泳道左缘可见（未拉宽 / 已平移到左缘）→ 保持后端原生的标题位置；
    //   · 泳道被拉宽到视口之外（左缘在画布外）→ 标题贴到画布可见左缘，
    //     否则它会悬在泳道中段，看起来"不在泳道里"（用户反馈原话）。
    const leftVisible = (x0 * s + tx) >= 0
    const titleX = leftVisible ? band.x + band.labelRefX : viewX0 + titleInset
    const wantRef = titleX - x0
    // 首次（band.refX 未记录）必须写入一次；之后只在偏移真的变了才写，
    // 避免每帧缩放/平移都触发一次无意义的 attr 重绘。
    if (band.refX === undefined || Math.abs(band.refX - wantRef) >= 0.5) {
      cell.attr('label/refX', wantRef)
      band.refX = wantRef
    }
  }
}

/** rAF 合帧：滚轮缩放 / 拖拽平移会连续触发，同一帧只算一次即可。 */
function scheduleLaneSync() {
  if (laneSyncRaf) return
  laneSyncRaf = requestAnimationFrame(() => {
    laneSyncRaf = 0
    syncLaneBandWidth()
  })
}

// 流标签沿路径分位放置：以边 id 做确定性 hash，把标签从"统一中点"散开到
// 路径 0.34~0.66 区间，并垂直错开 ±13px，缓解中心节点扇出时标签堆叠
function labelPos(seed) {
  let h = 0
  const s = String(seed || '')
  for (let i = 0; i < s.length; i += 1) h = (h * 31 + s.charCodeAt(i)) >>> 0
  const distance = 0.34 + (h % 33) / 100
  const offset = (h >> 4) % 2 === 0 ? -13 : 13
  return { distance, offset }
}

/**
 * D6: 并行边路由 padding 层级（0~3）。
 * X6 manhattan 路由对每条边独立求解，并列的多条边会算出完全相同的绕行
 * 路径而重合。用边的稳定 id 哈希分到 4 个 padding 档位，让并行边在节点
 * 周界的绕行距离不同，路径自然分层。
 */
function edgePadLevel(seed) {
  let h = 0
  const s = String(seed || '')
  for (let i = 0; i < s.length; i += 1) h = (h * 37 + s.charCodeAt(i)) >>> 0
  return h % 4
}

// 推断 cell 属于哪个 BoundaryBox（基于位置包含关系）
// 返回 boundary id 或 null（不在任何 boundary 内）
function findContainingBoundary(cell, allCells) {
  if (!cell?.position) return null
  const cx = cell.position.x
  const cy = cell.position.y
  const cw = cell.size?.width || 0
  const ch = cell.size?.height || 0
  for (const b of allCells) {
    if (b.shape !== 'tm.BoundaryBox') continue
    const bp = b.position
    const bs = b.size
    if (!bp || !bs) continue
    // cell 完全包含在 boundary 矩形内
    if (cx >= bp.x && cx + cw <= bp.x + bs.width
        && cy >= bp.y && cy + ch <= bp.y + bs.height) {
      return b.id
    }
  }
  return null
}

// —— 边界显示矩形（addNode 与跨界标记共用的唯一实现）——
// 从 addNode 的"成员包围盒收缩"逻辑提取：只缩不涨、防退化（缩后过小
// 则放弃收缩回原矩形）。跨信任边界落点标记必须用这个矩形求交点，
// 才能正好落在用户看到的边框上。
function boundaryLayout(cell) {
  const pos = cell.position || { x: 0, y: 0 }
  const size = cell.size || { width: 180, height: 60 }
  let innerBox = null
  let memberCount = 0
  for (const cid of cell.children || []) {
    const sib = allCellsRef.find((c) => c.id === cid)
    if (!sib || sib.shape === 'tm.BoundaryBox' || sib.shape === 'tm.Text') continue
    memberCount += 1
    const p = sib.position
    if (!p) continue
    const sz = sib.size || { width: 180, height: 60 }
    innerBox = innerBox
      ? { x0: Math.min(innerBox.x0, p.x), y0: Math.min(innerBox.y0, p.y),
          x1: Math.max(innerBox.x1, p.x + sz.width), y1: Math.max(innerBox.y1, p.y + sz.height) }
      : { x0: p.x, y0: p.y, x1: p.x + sz.width, y1: p.y + sz.height }
  }
  const rect = { x0: pos.x, y0: pos.y, x1: pos.x + size.width, y1: pos.y + size.height }
  if (innerBox) {
    // 水平拉宽：泳道只贴内容（PAD_X=30）时，纵向长条 DFD 在宽画布上
    // 两侧全是空白（fitView 按高度缩放，宽度天然富余）。泳道作为背景
    // 应主动向左右伸展填满空间：目标 = 内容 ± STRETCH_X，允许超出模型
    // 存的原始矩形，但不得侵入水平相邻泳道的领地（垂直堆叠的泳道
    // 互不阻挡）。垂直方向维持"只缩不涨"——泳道上下紧挨，竖向膨胀
    // 会互相压盖。
    const STRETCH_X = 240
    const PAD_Y = 26
    let fx0 = Math.min(rect.x0, innerBox.x0 - STRETCH_X)
    let fx1 = Math.max(rect.x1, innerBox.x1 + STRETCH_X)
    for (const b of allCellsRef) {
      if (b.id === cell.id || b.shape !== 'tm.BoundaryBox' || b.visible === false) continue
      const ib = boundaryChildrenBBox(b)
      if (!ib) continue // 空泳道不画也不挡（与渲染规则一致）
      // 只钳制"真邻居"：垂直有重叠、水平不相交的泳道；嵌套/上下堆叠不设限
      const vOverlap = ib.y0 < innerBox.y1 && ib.y1 > innerBox.y0
      const hBefore = ib.x1 <= innerBox.x0
      const hAfter = ib.x0 >= innerBox.x1
      if (!vOverlap || (!hBefore && !hAfter)) continue
      if (hBefore) fx0 = Math.max(fx0, ib.x1 + 40)
      else fx1 = Math.min(fx1, ib.x0 - 40)
    }
    const fy0 = Math.max(rect.y0, innerBox.y0 - PAD_Y)
    const fy1 = Math.min(rect.y1, innerBox.y1 + PAD_Y)
    if (fx1 - fx0 >= 60 && fy1 - fy0 >= 48) {
      rect.x0 = fx0
      rect.y0 = fy0
      rect.x1 = fx1
      rect.y1 = fy1
    }
  }
  return { rect, memberCount }
}

/** 泳道成员包围盒（几何判定：中心点落在边界矩形内的非边非容器节点）。
 * 与后端 _boundary_children_bbox 同口径，供相邻泳道钳制使用；
 * 自己的成员盒仍走 cell.children（权威来源），两者仅在异常模型下有出入。 */
function boundaryChildrenBBox(bCell) {
  const bp = bCell.position
  const bs = bCell.size
  if (!bp || !bs) return null
  let box = null
  for (const c of allCellsRef) {
    if (c.id === bCell.id) continue
    if (c.shape === 'tm.BoundaryBox' || c.shape === 'tm.Text') continue
    if (c.source && c.target) continue
    const p = c.position
    if (!p) continue
    const sz = c.size || { width: 180, height: 60 }
    const cx = p.x + sz.width / 2
    const cy = p.y + sz.height / 2
    if (cx >= bp.x && cx <= bp.x + bs.width && cy >= bp.y && cy <= bp.y + bs.height) {
      box = box
        ? { x0: Math.min(box.x0, p.x), y0: Math.min(box.y0, p.y),
            x1: Math.max(box.x1, p.x + sz.width), y1: Math.max(box.y1, p.y + sz.height) }
        : { x0: p.x, y0: p.y, x1: p.x + sz.width, y1: p.y + sz.height }
    }
  }
  return box
}

// —— 跨信任边界落点标记（与后端 PNG 的 crossMarker 同款红方块）——
// PNG 渲染器在跨界折线穿过边界框的位置画 7px 红方块（spec.crossMarker），
// 让「信任级变化的发生点」在图上可定位；前端此前只有虚线一种表达。
// 只对「消费后端预计算路由」的边绘制：manhattan 回退的路径是 X6 实时
// 算的、getVertices 拿不到稳定折线。节点拖动后交点已失效，由 node:moved
// 整体清除（见 handler），下次整图渲染重建。
function segRectBorderPoints(p, q, rects) {
  const out = []
  const dx = q.x - p.x
  const dy = q.y - p.y
  for (const r of rects) {
    if (dx !== 0) {
      for (const bx of [r.x0, r.x1]) {
        const t = (bx - p.x) / dx
        if (t <= 0 || t >= 1) continue
        const y = p.y + t * dy
        if (y >= r.y0 && y <= r.y1) out.push([bx, y])
      }
    }
    if (dy !== 0) {
      for (const by of [r.y0, r.y1]) {
        const t = (by - p.y) / dy
        if (t <= 0 || t >= 1) continue
        const x = p.x + t * dx
        if (x >= r.x0 && x <= r.x1) out.push([x, by])
      }
    }
  }
  return out
}

function addCrossMarkers() {
  const rects = allCellsRef
    .filter((c) => c.shape === 'tm.BoundaryBox' && c.visible !== false)
    .map((c) => boundaryLayout(c)?.rect)
    .filter(Boolean)
  if (!rects.length) return
  const seen = new Set()   // 角点/多边界重叠处可能算出相同落点，全局去重
  for (const edge of graph.getEdges()) {
    const cell = (edge.getData?.() || {}).tdCell
    if (!cell || cell.data?.crossesTrustBoundary !== true) continue
    const vertices = edge.getVertices?.() || []
    if (vertices.length < 2) continue
    for (let i = 0; i < vertices.length - 1; i += 1) {
      for (const [px, py] of segRectBorderPoints(vertices[i], vertices[i + 1], rects)) {
        const key = `${Math.round(px)}:${Math.round(py)}`
        if (seen.has(key)) continue
        seen.add(key)
        graph.addNode({
          id: `cross-mark-${edge.id}-${key}`,
          x: px - 3.5,
          y: py - 3.5,
          width: 7,
          height: 7,
          shape: 'rect',
          // 与边同层（节点之下、lane 之上），与 PNG 的绘制顺序一致
          zIndex: 60,
          markup: [{ tagName: 'rect', selector: 'body' }],
          attrs: { body: { fill: '#dc2626', stroke: 'none' } },
          // crossMarker: true → isLaneNode 命中，不参与选中/删除/tooltip
          data: { crossMarker: true, tdCell: null },
        })
      }
    }
  }
}

function addEdge(cell) {
  const data = cell.data || {}
  const isBidirectional = !!data.isBidirectional
  const isEncrypted = !!data.isEncrypted
  const isPublicNetwork = !!data.isPublicNetwork
  const isOutOfScope = !!data.outOfScope

  // 跨边界判定: 优先用后端 LLM 标注;字段缺失时基于位置推断（兼容老 result）
  // 推断规则保守: 只在两端都明确属于某个 boundary 且不同时才推断为跨边界
  // (不推断"一端在、一端不在"——大部分 cell 不在任何 boundary 内,会过度标记)
  let crossesBoundary = data.crossesTrustBoundary === true
  if (data.crossesTrustBoundary === undefined && allCellsRef.length) {
    const srcCell = allCellsRef.find(c => c.id === cell.source?.cell)
    const tgtCell = allCellsRef.find(c => c.id === cell.target?.cell)
    const srcB = srcCell ? findContainingBoundary(srcCell, allCellsRef) : null
    const tgtB = tgtCell ? findContainingBoundary(tgtCell, allCellsRef) : null
    // 两端都在 boundary 内且不同 → 跨边界
    if (srcB && tgtB && srcB !== tgtB) crossesBoundary = true
  }

  // —— 视觉语义 ——
  // 描边色 / 虚线 / 线宽全部由 flowStrokeAndDash 按后端规格算出，
  // 与后端 PNG、报告图例同源。此前这三段是前端硬编码（'4 3'/'6 4'、
  // 1.4~2.0、'#ea580c'/'#16a34a'），与 dfd_spec 各持一份，改一端就漂移。
  // 语义：颜色 公网 > 加密 > 默认；虚线 越界 > 跨边界 > 实线；
  //       线宽 加密&公网 > 单标记 > 跨边界 > 普通。
  const flowVis = flowStrokeAndDash(
    isEncrypted, isPublicNetwork, crossesBoundary, isOutOfScope
  )
  const strokeDasharray = flowVis.dash
  const baseStrokeWidth = flowVis.width
  const stroke = flowVis.stroke

  // 标签：加密/公网带语义图标，普通流仅显示名称
  const hint = isEncrypted ? '🔒 ' : isPublicNetwork ? '🌐 ' : ''
  const labelText = (data.name || '').trim() ? hint + wrapLabel(data.name, 22) : hint
  const labelFill = isEncrypted
    ? '#15803d'
    : isPublicNetwork
    ? '#c2410c'
    : STYLE.Flow.text

  // —— 标签位置 & 路由 padding：优先用后端布局提示（D5/D2），否则退回哈希分散 ——
  // 后端在「同一节点对存在多条流」时会给出分散的 labelT/labelOffset，
  // 这是真正能消除标签叠压的机制（哈希是纯随机，撞车概率不低）。
  // 注意：currentLayoutHints 是普通变量（非 ref），老模型/无提示时为 null，
  // 之前误写成 .value 导致 TypeError → render 循环中止 → 所有数据流消失。
  const layoutHints = currentLayoutHints || {}
  const flowHint = (data.flowId && layoutHints[data.flowId]) || null
  const hp = labelPos(cell.id)   // 兜底：保持原有哈希分散行为
  const labelDistance = flowHint && typeof flowHint.labelT === 'number'
    ? flowHint.labelT
    : hp.distance
  const labelOffset = flowHint && typeof flowHint.labelOffset === 'number'
    ? flowHint.labelOffset
    : hp.offset

  // —— 标签最终落点：布局期唯一真源直供（首选路径）——
  // 后端 dfd_spec.place_edge_labels 在布局期已做完内容级避让，落点写进
  // layoutHints[flowId].labelX/labelY（模型坐标，标签**中心**）。
  // 这里直接把它折算成 X6 的绝对坐标点，标签不再走 position{distance,offset}
  // ——因为 X6 的 distance/offset 是"沿边参数化"，与后端按弧长取点的口径
  // 存在细微差异，而绝对坐标能与导出图逐像素对上。
  //
  // 与后�� PNG 完全同源：后端渲染时同样优先消费 labelX/labelY
  // （见 dfd_renderer 的标签绘制分支），因此页面上标签位置 = 导出图标签位置。
  const hasAbsLabel = !!(flowHint
    && typeof flowHint.labelX === 'number' && typeof flowHint.labelY === 'number')

  // D6: 并行边路径分层。
  // X6 的 manhattan 路由本身会绕开节点，但**每条边独立计算**、彼此不知道
  // 对方存在 → 多条边挤同一通道时路径完全重合（截图里"线叠在一起"）。
  // 这里按边的稳定哈希给不同的 padding，使并行边在节点周界的绕行位置上
  // 自然错开，成本极低且不影响单边观感。
  const padLevel = edgePadLevel(cell.id)

  // —— P2-1 统一渲染真相源：优先消费后端布局期算好的正交路由 ——
  // layoutHints[flowId].route 由后端 dfd_layout_metrics.plan_edge_routes 统一
  // 计算（PNG/SVG 导出、质量度量、前端初始渲染三处同源），保证
  // 「度量通过 = 页面上画的就是这条线」。历史上这里曾无视后端结果、
  // 每条边用 X6 manhattan 独立重算，导致后端所有布线修复在页面上全部失效。
  //
  // 几何细节：route 首尾点是后端算好的**节点边界锚点**。把完整 route
  // （含首尾锚点）作为 vertices 传给 X6 时，connectionPoint 沿
  // 「节点中心 → 首个 vertex」方向取边界交点，而锚点本身就在边界上，
  // 交点恰好等于锚点 → 端点与后端路径严格重合，且不产生斜线残段。
  //
  // 无 route（老模型 / 布局期计算失败）时回退 X6 manhattan 实时避让。
  const backendRoute = flowHint
    && Array.isArray(flowHint.route)
    && flowHint.route.length >= 2
    ? flowHint.route.map((p) => ({ x: p[0], y: p[1] }))
    : null

  const edge = graph.addEdge({
    id: cell.id,
    source: { cell: cell.source.cell },
    target: { cell: cell.target.cell },
    // 数据流精简档位开启时隐藏不匹配的流（判定见 flowSecurityRelevant）；
    // 重渲染走同一分支，过滤状态在渲染间保持一致
    visible: !securityFlowFilter.value || flowSecurityRelevant(cell),
    // 边保持在 lane 之上、节点之下，避免遮挡组件标签但不被虚线边界覆盖
    zIndex: cell.zIndex ?? 50,
    data: {
      tdCell: cell,
      _baseStroke: stroke,
      _baseStrokeWidth: baseStrokeWidth,
      _baseStrokeDasharray: strokeDasharray,
      _backendRoute: !!backendRoute,
      // 后端下发的**原始** route（模型坐标），作为拖动重建的不可变基准：
      // 反复拖动时都从它出发，避免累积插入的过渡折点；
      // 保存布局后由后端重算并整体替换（重新渲染时刷新）。
      _routeBase: backendRoute,
      // 两端节点在**后端基准**下的坐标（直接取自后端下发的 cells）：
      // 用于判断某节点是否真的移动过——拖回原位时应视作未移动，
      // 让 route 恢复后端原始形状。
      _basePositions: (() => {
        const out = {}
        for (const cid of [cell.source?.cell, cell.target?.cell]) {
          if (!cid) continue
          const c = allCellsRef.find((x) => x.id === cid)
          if (c?.position) out[cid] = { x: c.position.x, y: c.position.y }
        }
        return out
      })(),
      _nodeShifts: {},
      // 标签是否来自后端绝对坐标（labelX/labelY）：节点一动该坐标失效，
      // 需切回"沿边参数化"定位，否则标签会留在旧位置与线脱节。
      _absLabel: hasAbsLabel,
    },
    // 后端路由：router 'normal' 原样通过 vertices。
    // connector 'rounded' r=8 —— 必须显式指定：X6 边级默认 connector 是
    // 'normal'（尖角），而后端 dfd_renderer._rounded_corners 把每个直角拐点
    // 替换成了 r=8 的贝塞尔圆角。此前前端只有 connecting（手绘连线）配了
    // rounded，已渲染的边没配，于是同一张图在页面上是尖角、在导出 PNG 里
    // 是圆角。这是两侧最后两处几何差异之一。
    router: backendRoute ? 'normal' : 'manhattan',
    connector: { name: 'rounded', args: { radius: 8 } },
    ...(backendRoute
      ? { vertices: backendRoute }
      : { routerArgs: { padding: 32 + padLevel * 14, step: 8, maxDirectionChange: 3 } }),
    labels: labelText
      ? [
          hasAbsLabel
            ? {
                // 首选：布局期算定的绝对落点（模型坐标 → 画布坐标一致，
                // X6 的 vertices/坐标就是模型坐标，无需换算）
                position: { x: flowHint.labelX, y: flowHint.labelY },
                attrs: {
                  label: {
                    text: labelText,
                    fill: labelFill,
                    fontSize: 11,
                    fontWeight: isEncrypted || isPublicNetwork ? 600 : 500,
                    // 标签中心对齐到给定点：X6 的 position.x/y 默认也是中心
                    // 锚点，与后端 labelX/labelY（中心）口径一致。
                    textAnchor: 'middle',
                    textVerticalAnchor: 'middle',
                    // 白描边打底（等效后端 PNG 标签的白色底板）：标签压在
                    // 线上/网格上时仍有干净可读的轮廓，不必引入额外的
                    // rect markup 增加布局复杂度。
                    stroke: '#ffffff',
                    strokeWidth: 3,
                    paintOrder: 'stroke',
                    strokeLinejoin: 'round',
                  },
                },
              }
            : {
                position: { distance: labelDistance, offset: labelOffset },
                attrs: {
                  label: {
                    text: labelText,
                    fill: labelFill,
                    fontSize: 11,
                    fontWeight: isEncrypted || isPublicNetwork ? 600 : 500,
                    stroke: '#ffffff',
                    strokeWidth: 3,
                    paintOrder: 'stroke',
                    strokeLinejoin: 'round',
                  },
                },
              },
        ]
      : [],
    attrs: {
      line: {
        stroke,
        strokeWidth: baseStrokeWidth,
        strokeDasharray,
        // 普通流 0.9：对齐后端 PNG 的实线观感（此前 0.75，缩小后灰线发虚）；
        // hover 时仍统一压到 0.18，对比度不受影响。
        opacity: isEncrypted ? 0.95 : isPublicNetwork ? 0.95 : 0.9,
        targetMarker: {
          name: 'block',
          size: 7,
          ...(isBidirectional ? { direction: 'reverse' } : {}),
        },
        sourceMarker: isBidirectional ? { name: 'block', size: 7 } : null,
      },
    },
  })

  // —— 交互：hover 强调；click 选中并展示数据流详情 ——
  // hover 视觉：所有未选中的边降透明度到 0.18,被 hover 的边保持基准色并加粗
  // click 视觉：被选中的边线宽 2.6 + 红色高亮;其他边全部降透明度到 0.2
  edge.on('mouseenter', () => {
    if (containerRef.value) containerRef.value.style.cursor = 'pointer'
    if (selectedEdgeId.value === cell.id) return // 已是选中态,不再覆盖
    // 降透明度:所有边
    for (const e of graph.getEdges()) {
      e.attr('line/opacity', e === edge ? 0.95 : 0.18)
    }
    // 当前边加粗 + 显示 hover 阴影
    edge.attr('line/strokeWidth', baseStrokeWidth + 0.7)
    edge.attr('line/filter', 'drop-shadow(0 0 4px rgba(2, 132, 199, 0.55))')
  })
  edge.on('mouseleave', () => {
    if (containerRef.value) containerRef.value.style.cursor = ''
    if (selectedEdgeId.value === cell.id) {
      // 切回选中态样式
      applySelectedEdgeStyle(edge, cell)
      return
    }
    // 恢复所有边
    restoreAllEdgeStyles()
  })
  edge.on('click', ({ edge: e }) => {
    e.stopPropagation()
    selectEdge(cell.id)
  })
}

// 当前选中的边 id;null = 未选中（与 flowDetail 同步，定义在 setup 顶部）

// —— P1-1 内容级边标签避让（**仅兜底**，首选是后端布局期直供）——
// 后端已在布局期用 dfd_spec.place_edge_labels 完成内容级避让，落点写在
// layoutHints[flowId].labelX/labelY，前端 addEdge 已把标签钉死在该绝对
// 坐标上（hasAbsLabel 分支）。
//
// 因此本函数**只处理拿不到绝对落点的边**（老模型 / 布局期计算失败）：
// 后端 labelT/labelOffset 只解决「同一节点对多条流」的标签分散，
// 不同节点对的标签仍可能撞在一起，这里做本地兜底。
//
// 关键：对已有绝对落点的边，只把它的 bbox 登记进 placed 参与后续避让，
// **绝不移动它**——一旦移动就与导出图不一致了。
function avoidEdgeLabels() {
  const SEP = 4                                    // bbox 外扩，视觉呼吸感
  const STEPS = [0, 16, -16, 32, -32, 48, -48, 64, -64]
  const placed = []                                // 已放置标签 bbox（含 SEP）

  const nodeBoxes = graph.getNodes()
    .filter((n) => !isLaneNode(n))
    .map((n) => n.getBBox())
    .map((b) => ({ x: b.x, y: b.y, x1: b.x + b.width, y1: b.y + b.height }))

  const rectHit = (a, b) => a.x < b.x1 && a.x1 > b.x && a.y < b.y1 && a.y1 > b.y
  const countHits = (b) => {
    let n = 0
    for (const p of placed) if (rectHit(b, p)) n += 1
    for (const nb of nodeBoxes) if (rectHit(b, nb)) n += 1
    return n
  }

  // 彩色/语义边优先占位（与后端 _edge_rank 的先灰后彩一致）
  const rank = (e) => {
    const d = (e.getData()?.tdCell?.data) || {}
    return (d.isPublicNetwork ? 4 : 0) + (d.isEncrypted ? 2 : 0)
      + (d.crossesTrustBoundary ? 1 : 0)
  }
  const edges = graph.getEdges()
    .filter((e) => e.getLabelAt(0)?.attrs?.label?.text)
    .sort((a, b) => rank(b) - rank(a))

  // 先登记「后端定点标签」的占位，再对未定点的标签做兜底避让。
  // 两趟处理：若混在一趟里，先处理到的定点标签会被后续边当作已占位，
  // 但顺序依赖 rank 排序会打乱「先占位」的确定性，分开更清晰。
  const pinned = []
  const floating = []
  for (const e of edges) {
    if (e.getData()?._absLabel) pinned.push(e)
    else floating.push(e)
  }
  for (const e of pinned) {
    // 用实际渲染 bbox 登记占位（含 SEP 外扩）
    try {
      const b = e.getLabelAt(0)?.getBBox?.() || e.getLabelAt(0)?.bbox
      const r = b && typeof b.x === 'number'
        ? { x: b.x - SEP, y: b.y - SEP, x1: b.x + b.width + SEP, y1: b.y + b.height + SEP }
        : null
      if (r) placed.push(r)
    } catch { /* bbox 未就绪：跳过登记，不影响定点标签自身位置 */ }
  }

  for (const e of floating) {
    const lab = e.getLabelAt(0)
    const text = lab.attrs.label.text
    const dist = typeof lab.position?.distance === 'number' ? lab.position.distance : 0.5
    const baseOff = lab.position?.offset
    const cur = typeof baseOff === 'number'
      ? { x: 0, y: baseOff }
      : { x: baseOff?.x || 0, y: baseOff?.y || 0 }

    // 锚点：沿边路径按 distance 取点（X6 基于含 vertices/router 的最终几何）
    let anchor = null
    try {
      const pt = e.getPointAtRatio(dist)
      if (pt && Number.isFinite(pt.x) && Number.isFinite(pt.y)) anchor = { x: pt.x, y: pt.y }
    } catch { /* 路径尚未就绪时跳过避让，保留原位 */ }
    if (!anchor) continue

    // 文本宽度估算（fontSize 10：CJK ≈10px、ASCII ≈5.5px）+ 内边距
    let w = 8
    for (const ch of text) w += ch.charCodeAt(0) > 255 ? 10 : 5.5
    const h = 14

    let best = null
    let bestHits = Infinity
    for (const dy of STEPS) {
      const off = { x: cur.x, y: cur.y + dy }
      const cx = anchor.x + off.x
      const cy = anchor.y + off.y - h / 2
      const b = { x: cx - w / 2 - SEP, y: cy - SEP, x1: cx + w / 2 + SEP, y1: cy + h + SEP }
      const hits = countHits(b)
      if (hits === 0) { best = { b, off }; break }
      if (hits < bestHits) { bestHits = hits; best = { b, off } }
    }
    if (!best) continue
    e.prop('labels/0/position/offset', best.off)
    placed.push(best.b)
  }
}

// 应用"已选中"样式
function applySelectedEdgeStyle(edge, cell) {
  const openThreats = (cell.threats || []).filter((t) => t.status !== 'Mitigated').length
  // 选中态:所有其他边降透明度 0.2,自己高亮
  for (const e of graph.getEdges()) {
    if (e === edge) {
      e.attr('line/stroke', openThreats > 0 ? '#dc2626' : edge.getData()?._baseStroke || '#0284c7')
      e.attr('line/strokeWidth', 2.8)
      e.attr('line/opacity', 1)
      e.attr('line/filter', 'drop-shadow(0 0 6px rgba(220, 38, 38, 0.6))')
    } else {
      e.attr('line/opacity', 0.18)
      e.attr('line/filter', null)
    }
  }
}

// 恢复所有边到基准态
function restoreAllEdgeStyles() {
  for (const e of graph.getEdges()) {
    const d = e.getData() || {}
    e.attr('line/stroke', d._baseStroke || STYLE.Flow.stroke)
    e.attr('line/strokeWidth', d._baseStrokeWidth || 1.5)
    e.attr('line/strokeDasharray', d._baseStrokeDasharray || null)
    e.attr('line/opacity', 0.9)
    e.attr('line/filter', null)
  }
}

// 选中某条流（由 click 或 App 侧 emit('select-cell', edgeId) 触发）
function selectEdge(edgeId) {
  if (!graph) return
  if (!edgeId) {
    selectedEdgeId.value = null
    flowDetail.value = null
    restoreAllEdgeStyles()
    return
  }
  const edge = graph.getCellById(edgeId)
  if (!edge) return
  const cell = edge.getData()?.tdCell
  if (!cell) return
  selectedEdgeId.value = edgeId
  // X6 v2 用 graph.select 代替 resetSelection
  graph.select([edgeId])
  applySelectedEdgeStyle(edge, cell)
  // 构造详情面板数据
  const openThreats = (cell.threats || []).filter((t) => t.status !== 'Mitigated')
  const mitigated = (cell.threats || []).filter((t) => t.status === 'Mitigated')
  // 找源/目标节点的展示名
  const src = graph.getCellById(cell.source?.cell)
  const dst = graph.getCellById(cell.target?.cell)
  flowDetail.value = {
    id: cell.id,
    name: cell.data?.name || '(未命名流)',
    isBidirectional: !!cell.data?.isBidirectional,
    isEncrypted: !!cell.data?.isEncrypted,
    isPublicNetwork: !!cell.data?.isPublicNetwork,
    outOfScope: !!cell.data?.outOfScope,
    crossesTrustBoundary: cell.data?.crossesTrustBoundary === true,
    protocol: cell.data?.protocol || '',
    dataClassification: cell.data?.dataClassification || '',
    sourceName: src?.getData()?.tdCell?.name || cell.source?.cell || '?',
    targetName: dst?.getData()?.tdCell?.name || cell.target?.cell || '?',
    openThreats,
    mitigated,
    notes: cell.data?.description || '',
  }
  // 通知父组件
  emit('select-cell', edgeId)
}

function wrapLabel(text, maxChars) {
  if (!text) return ''
  if (text.length <= maxChars) return text
  const lines = []
  let cur = ''
  for (const ch of text) {
    if (cur.length >= maxChars) {
      lines.push(cur)
      cur = ''
    }
    cur += ch
  }
  if (cur) lines.push(cur)
  return lines.slice(0, 2).join('\n')
}

function fitView(retry = 10) {
  if (!graph) {
    console.warn('[DfdGraph] fitView: graph is null,跳过')
    return
  }
  // 容器尺寸为 0 时（如 el-tabs 切换前组件处于 display:none），延迟重试
  const rect = containerRef.value?.getBoundingClientRect()
  if (!rect || rect.width === 0 || rect.height === 0) {
    if (retry > 0) {
      setTimeout(() => fitView(retry - 1), 150)
    } else {
      // 兜底：刷新场景下 threat-page 多层 flex + v-show 父级回流可能慢，
      // 拉到 10 次（约 1.5s）覆盖布局稳定窗口
      console.warn('[DfdGraph] fitView 容器 0 尺寸超时放弃', { rect })
    }
    return
  }
  // 容器从 display:none 变为可见后，X6 内部 viewport 尺寸可能仍为 0，
  // 需要先同步画布尺寸再缩放，否则 zoomToFit 计算出的 scale 为 0/NaN 导致图不可见
  try {
    const viewport = graph.getGraphContainer?.()
    const curW = viewport?.clientWidth ?? graph.container?.clientWidth ?? 0
    const curH = viewport?.clientHeight ?? graph.container?.clientHeight ?? 0
    if (curW !== rect.width || curH !== rect.height) {
      graph.resize(rect.width, rect.height)
    }
  } catch (e) {
    // 忽略 resize 异常
  }
  // —— 只适配「真实内容」，排除两类"装饰性大矩形"（最终 scale 会放大到
  //    贴住长边，泳道作为背景自然跟着被拉宽，无需自己计入 bbox） ——
  // 1) 泳道背景(lane)：纵向铺满、宽度常达 1680px，比节点内容大一圈；
  // 2) 跨界落点标记(crossMarker)：7px 小方块，但贴在边界框外沿，
  //    会把 bbox 往边界外多带几十像素（边界本身已计入，无需重复）。
  //
  // 这是「前端图比 PNG 小一大圈」的根因：X6 内置 zoomToFit() 的 contentArea
  // 是 model.getAllCellsBBox()，包含撑满画布的泳道大矩形 → 节点被压成小点。
  // 历史注释一直写着"排除泳道"，但过滤结果从未参与缩放计算（zoomToFit 不
  // 接受 cells 参数），必须手动 union 真实内容 bbox 再适配。
  const contentCells = graph.getCells().filter((c) => {
    if (!c.isNode?.()) return false
    const d = c.getData ? c.getData() : c.data
    if (!d || typeof d !== 'object') return true
    return d.lane !== true && d.crossMarker !== true
  })
  if (contentCells.length === 0) {
    console.warn('[DfdGraph] fitView: 0 真实内容节点,图空')
    return
  }
  console.log('[DfdGraph] fitView start', {
    retry, rect: { w: rect.width, h: rect.height }, contentCount: contentCells.length,
  })
  let bbox = null
  for (const c of contentCells) {
    const b = c.getBBox?.()
    if (!b || b.width === 0 || b.height === 0) continue
    const nx = Math.min(bbox ? bbox.x : Infinity, b.x)
    const ny = Math.min(bbox ? bbox.y : Infinity, b.y)
    const nx1 = Math.max(bbox ? bbox.x + bbox.width : -Infinity, b.x + b.width)
    const ny1 = Math.max(bbox ? bbox.y + bbox.height : -Infinity, b.y + b.height)
    bbox = { x: nx, y: ny, width: nx1 - nx, height: ny1 - ny }
  }
  if (!bbox || bbox.width <= 0 || bbox.height <= 0) {
    console.warn('[DfdGraph] fitView: 无有效节点 bbox,跳过缩放')
    return
  }
  const PAD = 40
  const availW = Math.max(1, rect.width - PAD * 2)
  const availH = Math.max(1, rect.height - PAD * 2)
  // 适配 = **整图完整可见 + 尽量放大填满**：等比塞入后，若两轴都有富余
  // 就放大到贴住长边，泳道随之被拉宽，画布空间用满。
  // 历史坑位：早期给 scale 设 0.75 "可读性下限"，纵向大图装不下被截；
  // 中期又只允许缩不放大（上限 1.2），于是模型坐标仅几百像素宽的泳道图
  // 在 1000+ 宽的画布上"小小地缩在中间、四周全是留白"。现在上限提到 2.0，
  // 让"装得下就拉宽铺满"真正生效。
  const fitScale = Math.min(availW / bbox.width, availH / bbox.height)
  const scale = Math.max(0.2, Math.min(2.0, fitScale))
  try {
    graph.zoomTo(scale, { absolute: true })
    graph.centerPoint(bbox.x + bbox.width / 2, bbox.y + bbox.height / 2)
    console.log('[DfdGraph] fitView done', {
      bbox, fitScale: Number(fitScale.toFixed(3)), scale: Number(scale.toFixed(3)),
    })
  } catch (e) {
    console.error('[DfdGraph] fitView 缩放失败:', e?.message || e)
  }
  // 适配比例由**内容**决定，泳道不参与 bbox：缩放/居中定下来之后，
  // 再把泳道底色带拉到当前视口左右两端，填掉两侧空白。
  // （zoomTo / centerPoint 也会发 scale/translate 事件，这里显式再调一次
  //   是为了不依赖"事件一定被派发"这一实现细节。）
  syncLaneBandWidth()
}

defineExpose({ fitView })
</script>

<style scoped>
.graph-wrap {
  flex: 1;
  min-height: 0;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  background: var(--bg-panel);
  border-radius: var(--radius-sm);
}
/* graph-body 是 graph-wrap 的 flex 子项：必须显式 flex:1 + flex column，
   否则作为 block 元素它"内容撑开"宽高，内部的 .graph-container 即使写了
   width:100% 也跟着固化为初始尺寸，折叠右栏时画布不会跟着扩展。 */
.graph-body {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
}

/* —— 图例 —— */
/* 固定两排成组：第 1 排节点类型 / 第 2 排数据流家族（含"数据流"高亮开关与
   数据流筛选）。整块本身不再折行——折行下放给每个 .legend-row，
   这样窄屏最多是"某一排内部换行"，不会让两族混排、也不会把
   数据流那族挤成"每行一个"的碎块。 */
.legend {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  /* 左右内缩与上方 .graph-toolbar 统一 14px：两块的左缘落在同一条竖线上 */
  padding: 6px 14px 7px;
  font-size: 11px;
  color: var(--c-text-3, #64748b);
  /* 整条头部带只在图例下沿收一条线（工具条自己不再画线），
     让"工具条 + 图例"读成一块，而不是三条同色带叠着两条横线。 */
  border-bottom: 1px solid var(--c-line, #e2e8f0);
  background: var(--c-bg-soft, #f8fafc);
  gap: 4px;
}
/* 单排：两排共用同一个左内缩与间距，于是"造型圆心"落在同一竖线上
   （36px 图框的几何中心 = 14(pad) + 18 = 32px）。 */
.legend-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  /* 16px：与 .lg-toggle 的 -6px 负边距相抵后，可点胶囊之间仍有 4px 视觉间隙 */
  gap: 16px;
  min-width: 0;
}
/* 浮在画布右上角的纠错提示按钮：绝对定位，不占任何行高度；
   无内容时不渲染（模板里 v-if），不需要为空占位。 */
.autofix-fab {
  position: absolute;
  top: 10px;
  right: 16px;
  z-index: 20;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border: 1px solid var(--warning);
  border-radius: 999px;
  background: var(--warning-soft);
  color: var(--warning);
  font-size: 11px;
  font-weight: 500;
  font-family: inherit;
  cursor: pointer;
  white-space: nowrap;
  box-shadow: 0 1px 3px rgba(217, 119, 6, 0.16);
  transition: background 0.15s ease, transform 0.15s;
}
.autofix-fab:hover {
  background: rgba(217, 119, 6, 0.18);
  transform: translateY(-1px);
}
/* 浮层细节面板：从右上角向下展开，避免遮挡画布节点 */
.autofix-panel {
  position: absolute;
  top: 44px;
  right: 16px;
  z-index: 21;
  width: 320px;
  max-height: 260px;
  overflow-y: auto;
  padding: 10px 12px 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg-panel-2);
  box-shadow: var(--shadow-md, 0 4px 12px rgba(15, 23, 42, 0.12));
}
.autofix-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--c-text, #0f172a);
  margin-bottom: 6px;
}
.autofix-list {
  margin: 0;
  padding-left: 18px;
  font-size: 12px;
  color: var(--text);
  line-height: 1.7;
}
.autofix-tip {
  margin: 8px 0 0;
  font-size: 11px;
  color: var(--text-dim);
}
.lg-item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  /* 统一行高：两排 chip 的基线、造型中心因此完全对齐（此前 12px 字号 + 不同
     造型高度，两排是"各自居中"的松排） */
  height: 22px;
  font-size: 11.5px;
  color: var(--text);
}
.lg-item .lg-label {
  font-weight: 600;
}
/* 「只看安全相关」开关的保留/总数徽标 */
.lg-item .lg-count {
  padding: 0 5px;
  border-radius: 8px;
  background: var(--border);
  font-size: 10.5px;
  font-variant-numeric: tabular-nums;
  color: var(--text-dim);
  line-height: 15px;
}
.lg-toggle.active .lg-count {
  background: var(--primary, #2563eb);
  color: #fff;
}
.lg-item .lg-fig {
  display: inline-block;
  flex-shrink: 0;
  overflow: visible;
}
/* active（高亮打开）时白底上要仍可辨：给造型加一圈描边阴影。
   造型本身已有 stroke，这里只补底色衬托，避免圆柱顶盖与白底糊在一起。 */
.lg-toggle.active .lg-fig {
  filter: drop-shadow(0 0 0.5px rgba(255, 255, 255, 0.9));
}
.lg-item .dash {
  width: 22px;
  height: 0;
  border-top: 2px dashed var(--text-dim);
}
/* 可点击的图例项（节点类型高亮开关）：
   默认与只读图例同款式，靠 hover/active 反馈表明可点，不额外加边框以免图例变噪。 */
/* 可点图例项：左右各 6px 内衬 + 等量负外边距 —— 内衬让 hover/active 的
   胶囊底有呼吸感，负 margin 把这份内衬"还"给行布局，于是**文字/造型**仍与
   只读图例项落在同一条竖线上（左右内缩不变）。行间距 16px 与 -6px 相抵后，
   两个胶囊之间仍有 4px 视觉间隙，不会互相压边。 */
.lg-toggle {
  padding: 0 6px;
  margin: 0 -6px;
  border: none;
  border-radius: 999px;
  background: transparent;
  font-family: inherit;
  cursor: pointer;
  transition: background 0.15s, color 0.15s, box-shadow 0.15s;
}
/* 鼠标点击后不要留浏览器默认焦点框（用户点一下图例就出现黑框，观感很脏），
   键盘 Tab 聚焦才给品牌色光圈。 */
.lg-toggle:focus {
  outline: none;
}
.lg-toggle:focus-visible {
  outline: 2px solid var(--primary-border, rgba(37, 99, 235, 0.28));
  outline-offset: 1px;
}
.lg-toggle:hover {
  background: var(--bg-active);
  color: var(--primary);
}
/* 高亮打开：浅色底 + 内描边（原来整块填 --primary 深色，在图例里像贴了块
   黑膏药，和旁边只读图例的轻盈感不搭）。 */
.lg-toggle.active {
  background: var(--primary-soft, rgba(37, 99, 235, 0.08));
  color: var(--primary);
  box-shadow: inset 0 0 0 1px var(--primary-border, rgba(37, 99, 235, 0.28));
}
/* .lg-label 自带深色，active 时要一起变主题色，否则文字仍是深灰 */
.lg-toggle:hover .lg-label,
.lg-toggle.active .lg-label {
  color: inherit;
}
/* active 时色块需在白底上仍可辨：加深描边 */
.lg-toggle.active i.dot {
  box-shadow: 0 0 0 1.5px rgba(255, 255, 255, 0.85);
}

/* —— 主图区 —— */
.graph-body {
  flex: 1;
  min-height: 0;
  position: relative;
  background:
    linear-gradient(45deg, var(--bg-panel-2) 25%, transparent 25%),
    linear-gradient(-45deg, var(--bg-panel-2) 25%, transparent 25%),
    linear-gradient(45deg, transparent 75%, var(--bg-panel-2) 75%),
    linear-gradient(-45deg, transparent 75%, var(--bg-panel-2) 75%);
  background-size: 18px 18px;
  background-position: 0 0, 0 9px, 9px -9px, -9px 0;
}
.graph-container {
  /* X6 内部会通过内联 style 写死宽高（基于初始化时容器尺寸），
     导致折叠右栏时画布不跟着扩展。用 !important 覆盖，强制随父级 stretch。
     ResizeObserver 触发后 X6 会再写内联宽高，但下一次也会被这条规则推回去。 */
  width: 100% !important;
  height: 100% !important;
  /* 宽内容时 fitView 会保留下限缩放（不把图缩成小点），超出部分靠画布
     自身的滚轮/拖拽平移浏览；overflow 保持 hidden 避免出现"图表外还套一层
     原生滚动条"的双重滚动观感。 */
  overflow: hidden;
}

/* —— 空态 —— */
.empty-state {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 14px;
  padding: 40px;
  text-align: center;
  color: var(--text-faint);
  background: var(--bg-panel);
}
.empty-illust {
  margin-bottom: 4px;
  filter: drop-shadow(0 4px 12px rgba(91, 156, 255, 0.10));
}
.empty-state h3 {
  font-size: 18px;
  font-weight: 700;
  color: var(--text);
  letter-spacing: 0.3px;
}
.empty-state p {
  max-width: 460px;
  font-size: 13px;
  line-height: 1.7;
  color: var(--text-dim);
}
.empty-state ul {
  list-style: none;
  font-size: 12.5px;
  color: var(--text-dim);
  display: flex;
  flex-direction: column;
  gap: 7px;
  margin-top: 6px;
  text-align: left;
}
.empty-state ul li {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 6px 12px;
  background: var(--bg-panel-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-pill);
}
.ul-icon {
  font-size: 14px;
}

/* —— 节点浮层 —— */
.node-tooltip {
  position: absolute;
  z-index: 40;
  min-width: 240px;
  max-width: 280px;
  padding: 9px 11px;
  background: var(--bg-elevated);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border: 1px solid var(--border-light);
  border-radius: 10px;
  box-shadow: var(--shadow-lg);
  color: var(--text);
  font-size: 12px;
  pointer-events: none;
}
.tt-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 6px;
}
.tt-head b {
  font-size: 12.5px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.tt-count {
  flex-shrink: 0;
  font-size: 11px;
  color: var(--text-dim);
  background: var(--bg-hover);
  border-radius: 10px;
  padding: 1px 8px;
}
.tt-count.warn {
  color: var(--danger);
  background: var(--danger-soft);
  border: 1px solid var(--danger-border);
}
.tt-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
  max-height: 130px;
  overflow: hidden;
}
.tt-item {
  display: flex;
  align-items: flex-start;
  gap: 6px;
}
.tt-sev {
  flex-shrink: 0;
  font-size: 10.5px;
  font-weight: 600;
  border-radius: 4px;
  padding: 0 5px;
  margin-top: 1px;
}
.tt-sev.sev-critical { background: var(--critical-soft); color: var(--critical); border: 1px solid var(--critical-border); }
.tt-sev.sev-high { background: var(--danger-soft); color: var(--danger); border: 1px solid var(--danger-border); }
.tt-sev.sev-medium { background: var(--medium-soft); color: var(--medium); border: 1px solid var(--warning-border); }
.tt-sev.sev-low { background: var(--success-soft); color: var(--success); border: 1px solid var(--success-border); }
.tt-sev.sev-unknown { background: var(--bg-hover); color: var(--text-dim); border: 1px solid var(--border-light); }
.tt-title {
  line-height: 1.45;
  word-break: break-all;
}
.tt-more {
  color: var(--text-faint);
  font-size: 11px;
  margin-top: 2px;
}
.tt-empty {
  color: var(--text-faint);
  font-size: 11.5px;
  padding: 2px 0;
}

/* —— 图例分隔与提示 —— */
.lg-sep {
  width: 1px;
  height: 13px;
  background: var(--border);
  /* 排间距已由 .legend-row 的 gap 提供，这里只做"语义分隔"的窄留白 */
  margin: 0 2px;
}

/* —— 数据流详情浮层（点击边后浮现） —— */
.flow-detail {
  position: absolute;
  z-index: 50;
  top: 16px;
  right: 16px;
  width: 320px;
  max-height: calc(100% - 32px);
  overflow-y: auto;
  background: var(--bg-elevated);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border: 1px solid var(--border-light);
  border-radius: 12px;
  box-shadow: 0 12px 36px rgba(0, 0, 0, 0.18), 0 2px 6px rgba(0, 0, 0, 0.06);
  color: var(--text);
  font-size: 12.5px;
  display: flex;
  flex-direction: column;
}
.fd-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 14px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-panel-2);
  border-radius: 12px 12px 0 0;
}
.fd-head.enc { background: linear-gradient(180deg, rgba(22, 163, 74, 0.10), var(--bg-panel-2)); }
.fd-head.pub { background: linear-gradient(180deg, rgba(234, 88, 12, 0.10), var(--bg-panel-2)); }
.fd-head-icon {
  flex-shrink: 0;
  width: 32px;
  height: 32px;
  display: grid;
  place-items: center;
  border-radius: 9px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  font-size: 16px;
}
.fd-head.enc .fd-head-icon { background: rgba(22, 163, 74, 0.12); border-color: rgba(22, 163, 74, 0.32); }
.fd-head.pub .fd-head-icon { background: rgba(234, 88, 12, 0.12); border-color: rgba(234, 88, 12, 0.32); }
.fd-head-text { flex: 1; min-width: 0; }
.fd-head-text h4 {
  font-size: 13.5px;
  font-weight: 700;
  color: var(--c-text, #0f172a);
  line-height: 1.2;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.fd-head-text p {
  font-size: 11px;
  color: var(--text-faint);
  margin-top: 2px;
}
.fd-close {
  flex-shrink: 0;
  width: 24px;
  height: 24px;
  border: none;
  background: transparent;
  border-radius: 6px;
  font-size: 18px;
  line-height: 1;
  color: var(--text-dim);
  cursor: pointer;
  display: grid;
  place-items: center;
  transition: background 0.15s ease;
}
.fd-close:hover { background: var(--bg-hover); color: var(--text); }

/* —— 源→目标 路由示意 —— */
.fd-route {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 12px 14px 8px;
}
.fd-node {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 3px;
  padding: 6px 9px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}
.fd-node-tag {
  font-size: 10px;
  font-weight: 600;
  color: var(--text-faint);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.fd-node-name {
  font-size: 12.5px;
  font-weight: 600;
  color: var(--c-text, #0f172a);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.fd-arrow {
  flex-shrink: 0;
  display: flex;
  align-items: center;
  gap: 1px;
  color: var(--text-faint);
}
.fd-arrow-label {
  font-size: 11px;
  color: var(--text-faint);
}

/* —— 标签徽章 —— */
.fd-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  padding: 0 14px 10px;
}
.fd-badge {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  padding: 2px 7px;
  font-size: 10.5px;
  font-weight: 600;
  border-radius: 999px;
  background: var(--bg-hover);
  color: var(--text-dim);
  border: 1px solid var(--border);
}
.fd-badge-ic { font-size: 10px; }
.fd-badge.encrypted { background: rgba(22, 163, 74, 0.10); color: #15803d; border-color: rgba(22, 163, 74, 0.32); }
.fd-badge.public { background: rgba(234, 88, 12, 0.10); color: #c2410c; border-color: rgba(234, 88, 12, 0.32); }
.fd-badge.cross { background: rgba(2, 132, 199, 0.10); color: #075985; border-color: rgba(2, 132, 199, 0.30); }
.fd-badge.oos { background: var(--bg-hover); color: var(--text-faint); }
.fd-badge.data { background: rgba(124, 58, 237, 0.10); color: #6d28d9; border-color: rgba(124, 58, 237, 0.30); }
.fd-badge.proto { background: rgba(2, 132, 199, 0.08); color: #0369a1; border-color: rgba(2, 132, 199, 0.22); }

/* —— 数字统计 —— */
.fd-stats {
  display: flex;
  gap: 8px;
  padding: 0 14px 10px;
}
.fd-stat {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1px;
  padding: 6px 0;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 8px;
}
.fd-stat-num {
  font-size: 16px;
  font-weight: 700;
  color: var(--text);
  line-height: 1.1;
}
.fd-stat-lbl {
  font-size: 10.5px;
  color: var(--text-faint);
}
.fd-stat.warn { background: var(--danger-soft); border-color: var(--danger-border); }
.fd-stat.warn .fd-stat-num { color: var(--danger); }

/* —— 威胁列表 —— */
.fd-threats {
  margin: 0 14px 12px;
  padding: 9px 11px 10px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 8px;
}
.fd-threats.ok { background: var(--success-soft); border-color: var(--success-border); }
.fd-threats-title {
  font-size: 11.5px;
  font-weight: 600;
  color: var(--c-text, #0f172a);
  margin-bottom: 6px;
}
.fd-threats-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.fd-threats-item {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  font-size: 11.5px;
  color: var(--text);
  line-height: 1.5;
}
.fd-threats-name { word-break: break-all; }
.fd-threats-more {
  color: var(--text-faint);
  font-size: 10.5px;
  margin-top: 2px;
}
.fd-threats-empty {
  margin: 0;
  font-size: 11.5px;
  color: var(--text-dim);
  line-height: 1.5;
}

/* —— 备注 —— */
.fd-notes {
  display: flex;
  gap: 8px;
  padding: 9px 14px 12px;
  border-top: 1px solid var(--border);
  font-size: 11.5px;
  color: var(--text-dim);
  line-height: 1.55;
  background: var(--bg-panel-2);
  border-radius: 0 0 12px 12px;
}
.fd-notes-lbl {
  flex-shrink: 0;
  font-weight: 600;
  color: var(--text);
}
.fd-notes-txt { word-break: break-all; }

/* —— 浮层过渡 —— */
.flow-detail-enter-active, .flow-detail-leave-active {
  transition: opacity 0.18s ease, transform 0.22s cubic-bezier(0.2, 0.9, 0.3, 1.1);
}
.flow-detail-enter-from, .flow-detail-leave-to {
  opacity: 0;
  transform: translateX(12px);
}
</style>
