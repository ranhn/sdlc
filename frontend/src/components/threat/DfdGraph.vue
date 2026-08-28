<template>
  <div class="graph-wrap">
    <!-- 顶部工具栏 -->
    <header class="graph-head">
      <button
        v-if="props.dfdAutofix && props.dfdAutofix.length"
        class="autofix-chip"
        type="button"
        title="查看自动纠错明细"
        @click="autofixOpen = !autofixOpen"
      >
        <svg viewBox="0 0 20 20" width="13" height="13" aria-hidden="true">
          <path d="M10 2 L18 17 H2 Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
          <path d="M10 8 V12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
          <circle cx="10" cy="14.5" r="0.9" fill="currentColor" />
        </svg>
        <span>已自动纠错 {{ props.dfdAutofix.length }} 项</span>
      </button>
      <div v-if="model" class="head-r">
        <div
          class="kpi"
          :class="{ active: activeHighlight === 'process' }"
          title="点击高亮所有进程节点"
          @click="toggleHighlight('process')"
        >
          <span class="kpi-num">{{ cellCounts.process }}</span>
          <span class="kpi-lbl">处理</span>
        </div>
        <div
          class="kpi"
          :class="{ active: activeHighlight === 'store' }"
          title="点击高亮所有存储节点"
          @click="toggleHighlight('store')"
        >
          <span class="kpi-num">{{ cellCounts.store }}</span>
          <span class="kpi-lbl">存储</span>
        </div>
        <div
          class="kpi"
          :class="{ active: activeHighlight === 'actor' }"
          title="点击高亮所有实体节点"
          @click="toggleHighlight('actor')"
        >
          <span class="kpi-num">{{ cellCounts.actor }}</span>
          <span class="kpi-lbl">实体</span>
        </div>
        <div
          class="kpi flow"
          :class="{ active: activeHighlight === 'flow' }"
          title="点击高亮所有数据流"
          @click="toggleHighlight('flow')"
        >
          <span class="kpi-num">{{ cellCounts.flow }}</span>
          <span class="kpi-lbl">流</span>
        </div>
        <button class="btn btn-ghost btn-sm" @click="fitView" title="适配视图">
          <svg viewBox="0 0 20 20" width="14" height="14" aria-hidden="true">
            <path d="M3 8V3h5M17 8V3h-5M3 12v5h5M17 12v5h-5" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" />
          </svg>
        </button>
      </div>
    </header>

    <!-- 图例 -->
    <div v-if="model" class="legend">
      <span class="lg-item"><i class="dot actor" /> 外部实体</span>
      <span class="lg-item"><i class="dot process" /> 处理</span>
      <span class="lg-item"><i class="dot store" /> 数据存储</span>
      <span class="lg-item"><i class="dot ai" /> AI 组件</span>
      <span class="lg-sep"></span>
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
      <span class="lg-hint">点击任一数据流查看详情</span>
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
  // DFD 自动纠错日志（后端在 LLM 输出明显错误时自动修正，并记录到这里）
  dfdAutofix: { type: Array, default: () => [] },
})
const emit = defineEmits(['select-cell'])

const containerRef = ref(null)
let graph = null
let allCellsRef = []  // 当前 DFD 全量 cells，供 addNode 内做"空 trust boundary 隐藏"判定

const tooltip = ref({ visible: false, name: '', threats: [], style: {} })

// 当前选中的数据流详情;null = 未选中
const flowDetail = ref(null)
// 当前选中的边 id;null = 未选中（与 flowDetail 同步）
const selectedEdgeId = ref(null)

// 节点数量统计
const autofixOpen = ref(false)

// 节点数量统计
const cellCounts = computed(() => {
  const out = { process: 0, store: 0, actor: 0, flow: 0, boundary: 0 }
  const d = props.model?.detail?.diagrams?.[0]
  if (!d) return out
  for (const c of d.cells || []) {
    if (c.shape === 'tm.Flow') out.flow += 1
    else if (c.shape === 'tm.Actor') out.actor += 1
    else if (c.shape === 'tm.Store') out.store += 1
    else if (c.shape === 'tm.BoundaryBox') out.boundary += 1
    else if (c.shape === 'tm.Process') {
      // data.type 已是 TD-可识别的形状（tm.Process/tm.Store/tm.Actor），
      // AI 子类型从 data.aiElementType 读取 —— 此处仅按形状归档，
      // 视觉样式（图标/边框）由 addNode 用 aiElementType 决定。
      const t = c.data?.type
      if (t === 'tm.Store') out.store += 1
      else if (t === 'tm.Actor') out.actor += 1
      else out.process += 1
    }
  }
  return out
})

const activeHighlight = ref(null)

function toggleHighlight(type) {
  if (activeHighlight.value === type) {
    clearHighlight()
    return
  }
  activeHighlight.value = type
  applyHighlight(type)
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
  const shapeMap = {
    process: 'tm.Process',
    store: 'tm.Store',
    actor: 'tm.Actor',
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

// 节点视觉风格
const STYLE = {
  Actor: { fill: '#e0f2fe', stroke: '#0284c7', text: '#075985' },
  Process: { fill: '#dcfce7', stroke: '#16a34a', text: '#14532d' },
  Store: { fill: '#fef3c7', stroke: '#d97706', text: '#92400e' },
  BoundaryBox: { fill: '#f1f5f9', stroke: '#64748b', text: '#475569' },
  Lane: { fill: '#f4f7fb', stroke: '#cbd5e1', text: '#64748b' },
  Text: { fill: 'transparent', stroke: 'transparent', text: '#334155' },
  Flow: { stroke: '#475569', text: '#475569' },
  Model: { fill: '#ede9fe', stroke: '#7c3aed', text: '#4c1d95' },
  Prompt: { fill: '#fae8ff', stroke: '#c026d3', text: '#86198f' },
  VectorStore: { fill: '#f5d0fe', stroke: '#a21caf', text: '#701a75' },
  Tool: { fill: '#e0e7ff', stroke: '#4f46e5', text: '#3730a3' },
  TrainingData: { fill: '#e0f2fe', stroke: '#0891b2', text: '#155e75' },
  AgentConfig: { fill: '#cffafe', stroke: '#0e7490', text: '#164e63' },
}

const AI_ICON = {
  Model: '🧠',
  Prompt: '📝',
  VectorStore: '📚',
  Tool: '🔧',
  TrainingData: '🗂️',
  AgentConfig: '⚙️',
}
const AI_TYPES = new Set([
  'tm.Model', 'tm.Prompt', 'tm.VectorStore', 'tm.Tool', 'tm.TrainingData', 'tm.AgentConfig',
])

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

// 重试渲染工具：当容器尚未挂载时（如 v-if/v-else 切换、路由恢复）延迟重试
function tryRender(model, attempt = 0) {
  if (!model) return
  if (!containerRef.value) {
    if (attempt < 10) {
      setTimeout(() => tryRender(model, attempt + 1), 80)
    }
    return
  }
  initGraph()
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
})

function initGraph() {
  if (graph || !containerRef.value) return
  graph = new Graph({
    container: containerRef.value,
    grid: { visible: true, size: 20, type: 'dot' },
    background: { color: 'transparent' },
    panning: { enabled: true },
    mousewheel: { enabled: true, zoomAtMousePosition: true },
    selecting: { enabled: true, rubberband: false, showNodeSelectionBox: true },
    interacting: { edgeLabelMovable: false },
  })

  graph.on('node:click', ({ node }) => {
    if (isLaneNode(node)) return
    graph.resetSelection([node.id])
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
}

// 泳道背景节点：不可交互（不触发选中 / 点击 / 悬停浮层）
function isLaneNode(node) {
  const d = node?.getData?.() || node?.data || {}
  return d.lane === true
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
  if (graph) {
    graph.dispose()
    graph = null
  }
  if (visibilityObserver) {
    visibilityObserver.disconnect()
    visibilityObserver = null
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
  { immediate: false }
)

watch(
  () => props.highlightCellId,
  (id) => {
    if (!graph) return
    if (id) graph.resetSelection([id])
  }
)

function render(model) {
  if (!graph) return
  graph.clearCells()
  if (!model) return
  const diagram = model.detail?.diagrams?.[0]
  if (!diagram) return
  const cells = diagram.cells || []
  // 供 addNode 内"空 trust boundary 判定"使用
  allCellsRef = cells
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
  } catch (e) {
    console.error('[DfdGraph] render error:', e)
  }
  // 延迟 fitView，确保容器已完成布局（el-tabs 切换时容器可能刚从 display:none 恢复）
  requestAnimationFrame(() => {
    setTimeout(() => fitView(), 100)
  })
}

function addNode(cell) {
  const data = cell.data || {}
  const shape = cell.shape || 'tm.Process'
  // AI 子类型从 data.aiElementType 读取（data.type 已是 TD-可识别的形状）
  const aiType = (data.aiElementType || '').replace('tm.', '')
  const aiStyleKey = AI_ICON[aiType] ? aiType : null
  const s = (aiStyleKey ? STYLE[aiStyleKey] : null) || STYLE[shape.replace('tm.', '')] || STYLE.Process
  const isBoundary = shape === 'tm.BoundaryBox'
  const pos = cell.position || { x: 0, y: 0 }
  const size = cell.size || { width: 180, height: 60 }
  const name = data.name || '未命名'
  // 只显示"未缓解"威胁——已 Mitigated 的不应误导读者
  const openThreats = (cell.threats || []).filter((t) => t.status !== 'Mitigated')
  const threatCount = openThreats.length
  const icon = aiStyleKey ? AI_ICON[aiStyleKey] + ' ' : ''
  const typeTag = aiStyleKey ? `\n[${aiType}]` : ''
  const threatBadge = threatCount > 0 ? `\n🔴 ${threatCount} 个未缓解威胁` : ''

  // 空 trust boundary：LLM 偶尔会生成没有 child 的边界容器（噪音），画出来只会让图更乱，直接隐藏。
  const innerCount = isBoundary
    ? (cell.children || []).filter((cid) => {
        const sib = allCellsRef.find((c) => c.id === cid)
        return sib && sib.shape !== 'tm.BoundaryBox' && sib.shape !== 'tm.Text'
      }).length
    : 0
  const isEmptyBoundary = isBoundary && innerCount === 0

  graph.addNode({
    id: cell.id,
    x: pos.x,
    y: pos.y,
    width: size.width,
    height: size.height,
    shape: 'rect',
    // 节点 zIndex 必须高于 lane（-100）和边（50），才能保证节点始终可点、可读、不被遮挡。
    zIndex: cell.zIndex ?? 200,
    visible: !isEmptyBoundary,
    data: { tdCell: cell },
    attrs: {
      body: {
        fill: isEmptyBoundary ? 'transparent' : s.fill,
        stroke: isEmptyBoundary ? 'transparent' : s.stroke,
        strokeWidth: isBoundary ? 2 : 1.6,
        // 只有 trust boundary 自身画虚线；AI 子类型不应再用虚线表达
        strokeDasharray: isBoundary ? '10 5' : null,
        rx: shape === 'tm.Actor' ? 26 : isBoundary ? 6 : 8,
        ry: shape === 'tm.Actor' ? 26 : isBoundary ? 6 : 8,
      },
      label: {
        text: icon + wrapLabel(name, 16) + typeTag + threatBadge,
        fill: s.text,
        fontSize: 12,
        fontWeight: threatCount > 0 ? 700 : 400,
        lineHeight: 18,
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

// 生命周期泳道背景：半透明底色 + 左上角泳道标签（不可交互）
function addLane(lane) {
  graph.addNode({
    id: `lane-${lane.key || lane.label}`,
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
        rx: 10,
        ry: 10,
      },
      label: {
        text: lane.label,
        fill: STYLE.Lane.text,
        fontSize: 12,
        fontWeight: 600,
        textAnchor: 'start',
        refX: 16,
        refY: 22,
      },
    },
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

function addEdge(cell) {
  const data = cell.data || {}
  const isBidirectional = !!data.isBidirectional
  const isEncrypted = !!data.isEncrypted
  const isPublicNetwork = !!data.isPublicNetwork
  const isOutOfScope = !!data.outOfScope
  const crossesBoundary = data.crossesTrustBoundary === true

  // —— 视觉语义（与官方 Threat Dragon data-changed.js 一致）——
  // 1. 默认实线 + 灰色
  // 2. outOfScope（超出模型范围）→ 短虚线 '4 3'
  // 3. 跨信任边界（端点不在同一 boundary）→ 中虚线 '7 5'
  // 4. isEncrypted → 绿色描边（加密信道，绿色表示安全），实线
  // 5. isPublicNetwork → 橙色描边（公网风险，醒目），实线
  // 注意：流的"基准颜色"只承载信道语义，不被"是否已识别威胁"持续性改写——
  // 否则只要一条流识别出未缓解威胁，整条连线变红淹没所有语义信息。
  // "有未缓解威胁"信息改由节点上的 ⚠ N 徽章承载，并仅在 hover 时整条变红。
  const strokeDasharray = isOutOfScope ? '4 3' : crossesBoundary ? '7 5' : null

  // 加密流略粗,公网流略粗(高视觉权重),普通流适中
  const baseStrokeWidth = isEncrypted ? 1.9 : isPublicNetwork ? 1.9 : 1.5

  let stroke = STYLE.Flow.stroke
  if (isEncrypted) stroke = '#16a34a'
  else if (isPublicNetwork) stroke = '#ea580c'

  // 标签：加密/公网带语义图标(放在边上 0.5 处),普通流仅显示名称
  const hint = isEncrypted ? '🔒 ' : isPublicNetwork ? '🌐 ' : ''
  const labelText = (data.name || '').trim() ? hint + wrapLabel(data.name, 22) : hint
  const labelFill = isEncrypted
    ? '#15803d'
    : isPublicNetwork
    ? '#c2410c'
    : STYLE.Flow.text

  const edge = graph.addEdge({
    id: cell.id,
    source: { cell: cell.source.cell },
    target: { cell: cell.target.cell },
    // 边保持在 lane 之上、节点之下，避免遮挡组件标签但不被虚线边界覆盖
    zIndex: cell.zIndex ?? 50,
    data: {
      tdCell: cell,
      _baseStroke: stroke,
      _baseStrokeWidth: baseStrokeWidth,
      _baseStrokeDasharray: strokeDasharray,
    },
    // 路由策略：统一用曼哈顿正交路由（忽略后端人为制造的"交叉穿越"vertices），
    // X6 自动计算最少折点的正交路径，配合大 padding 在节点周界避让，链路清晰不交叉。
    // 若个别流需要绕行避让节点，可通过 connector 起点方向控制；默认最短正交路径。
    router: 'manhattan',
    routerArgs: { padding: 32, step: 8, maxDirectionChange: 3 },
    labels: labelText
      ? [
          {
            position: { distance: 0.5, offset: 0 },
            attrs: {
              label: {
                text: labelText,
                fill: labelFill,
                fontSize: 10,
                fontWeight: isEncrypted || isPublicNetwork ? 600 : 500,
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
        opacity: isEncrypted ? 0.95 : isPublicNetwork ? 0.95 : 0.75,
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
    e.attr('line/opacity', 0.75)
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
  graph.resetSelection([edgeId])
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

function fitView(retry = 3) {
  if (!graph) return
  // 容器尺寸为 0 时（如 el-tabs 切换前组件处于 display:none），延迟重试
  const rect = containerRef.value?.getBoundingClientRect()
  if (!rect || rect.width === 0 || rect.height === 0) {
    if (retry > 0) {
      setTimeout(() => fitView(retry - 1), 150)
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
  // 排除泳道(lane)背景节点：它们是占满画布的大矩形，若计入 bbox 会把图压到画布一角
  const cells = graph.getCells().filter((c) => {
    const d = c.getData ? c.getData() : c.data
    return !(d && d.lane === true)
  })
  if (cells.length === 0) return
  // 优先用 X6 v2 内置 zoomToFit（内部用 graph 自己的 view area + cell bbox，
  // 不依赖外部 viewport，避免容器布局未完成时算错尺寸导致首次 fit 把图压成一小块）
  if (typeof graph.zoomToFit === 'function') {
    try {
      graph.zoomToFit({
        padding: 40,
        minScale: 0.3,
        maxScale: 1.2,
      })
      return
    } catch (e) {
      // 某些 X6 版本对空 cell 列表或边界异常会抛错,回退到 zoomTo
    }
  }
  // 回退：手动算 bbox + zoomTo
  const bbox = graph.getContentBBox(cells)
  if (!bbox) return
  graph.zoomTo(bbox, { padding: 40, minScale: 0.3, maxScale: 1.2 })
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

/* —— 头部 —— */
.graph-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
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
  background: var(--primary-gradient-soft);
  color: var(--primary);
  border: 1px solid var(--primary-border);
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

.head-r {
  display: flex;
  align-items: center;
  gap: 4px;
}
.kpi {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 4px 10px;
  border-radius: 6px;
  background: var(--bg-panel-2);
  border: 1px solid var(--border);
  min-width: 44px;
  transition: all 0.2s;
}
.kpi:hover {
  border-color: var(--primary-border);
  background: var(--primary-soft);
}
.kpi-num {
  font-size: 14px;
  font-weight: 700;
  color: var(--text);
  line-height: 1.2;
  font-family: var(--font-mono);
}
.kpi-lbl {
  font-size: 9.5px;
  color: var(--text-faint);
  font-weight: 500;
}
.kpi.flow .kpi-num { color: var(--primary); }
.kpi.active {
  border-color: var(--primary);
  background: var(--primary-soft);
  box-shadow: 0 0 0 2px var(--primary-soft);
  cursor: pointer;
}
.kpi { cursor: pointer; }

/* —— 图例 —— */
.legend {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 16px;
  font-size: 11px;
  color: var(--text-dim);
  border-bottom: 1px solid var(--border);
  background: var(--bg-panel-2);
  flex-wrap: wrap;
}
.autofix-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin-left: auto;
  margin-right: 16px;
  padding: 4px 10px;
  border: 1px solid var(--warning);
  border-radius: 999px;
  background: var(--warning-soft);
  color: var(--warning);
  font-size: 11px;
  font-weight: 500;
  cursor: pointer;
  white-space: nowrap;
  transition: background 0.15s ease;
}
.autofix-chip:hover {
  background: rgba(217, 119, 6, 0.18);
}
.autofix-panel {
  margin: 0 16px 8px;
  padding: 10px 12px 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg-panel-2);
}
.autofix-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-strong);
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
  font-size: 12px;
  color: var(--text);
}
.lg-item .lg-label {
  font-weight: 600;
}
.lg-item i.dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
}
.lg-item i.dot.actor { background: #0284c7; }
.lg-item i.dot.process { background: #16a34a; border-radius: 0; }
.lg-item i.dot.store { background: #d97706; border-radius: 0; }
.lg-item i.dot.ai { background: #7c3aed; border-radius: 0; }
.lg-item .dash {
  width: 22px;
  height: 0;
  border-top: 2px dashed var(--text-dim);
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
  width: 100%;
  height: 100%;
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
  height: 14px;
  background: var(--border);
  margin: 0 4px;
}
.lg-hint {
  margin-left: auto;
  font-size: 10.5px;
  color: var(--text-faint);
  font-style: italic;
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
  color: var(--text-strong);
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
  color: var(--text-strong);
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
  color: var(--text-strong);
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
