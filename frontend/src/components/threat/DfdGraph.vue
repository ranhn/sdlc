<template>
  <div class="graph-wrap">
    <!-- 适配视图按钮已迁到 ThreatModeling.vue 的 .gt-right（与「保存布局 / 折叠右栏」并列），
         自动纠错提示改为画布内的右上浮层（不占独立行高度，画布可多 30+px 垂直空间）。
         原 .graph-head 整块移除。 -->

    <!-- 图例：节点类型项同时是高亮开关（点击切换），
         与只读的线条图例区分 —— 前者是可点按钮，后者是纯展示。
         这样原来独立的 .filter-chip 行与之合并，消除重复。 -->
    <div v-if="model" class="legend">
      <button
        type="button"
        class="lg-item lg-toggle"
        :class="{ active: activeHighlight === 'actor' }"
        title="点击高亮所有外部实体"
        @click="toggleHighlight('actor')"
      >
        <i class="dot actor" /> 外部实体
      </button>
      <button
        type="button"
        class="lg-item lg-toggle"
        :class="{ active: activeHighlight === 'process' }"
        title="点击高亮所有处理节点"
        @click="toggleHighlight('process')"
      >
        <i class="dot process" /> 处理
      </button>
      <button
        type="button"
        class="lg-item lg-toggle"
        :class="{ active: activeHighlight === 'store' }"
        title="点击高亮所有数据存储"
        @click="toggleHighlight('store')"
      >
        <i class="dot store" /> 数据存储
      </button>
      <span class="lg-item"><i class="dot ai" /> AI 组件</span>
      <button
        type="button"
        class="lg-item lg-toggle"
        :class="{ active: activeHighlight === 'flow' }"
        title="点击高亮所有数据流"
        @click="toggleHighlight('flow')"
      >
        <svg width="18" height="10" viewBox="0 0 18 10" aria-hidden="true">
          <line x1="0" y1="5" x2="18" y2="5" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
        </svg>
        数据流
      </button>
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
let resizeObserver = null
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
  // 注意：默认只开启「拖拽」，连线/删除需要用户显式进入编辑模式（editMode），
  // 避免误操作破坏 AI 生成的模型。
  graph = new Graph({
    container: c,
    grid: { visible: true, size: 20, type: 'dot' },
    background: { color: 'transparent' },
    panning: { enabled: true },
    mousewheel: { enabled: true, zoomAtMousePosition: true },
    selecting: { enabled: true, rubberband: false, showNodeSelectionBox: true },
    interacting: {
      edgeLabelMovable: false,
      // 节点可拖动（布局微调）；连线由 editMode 控制
      nodeMovable: true,
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

  // 拖拽结束：把新坐标回传给父组件，由其负责持久化到后端/本地模型。
  // 只上报真实位移，避免点击时的 0 位移噪音。
  graph.on('node:moved', ({ node }) => {
    if (isLaneNode(node) || !props.editable) return
    const pos = node.position()
    const data = node.getData?.() || {}
    const tdCell = data.tdCell || {}
    if (tdCell.position && tdCell.position.x === pos.x && tdCell.position.y === pos.y) return
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

// 编辑模式切换：开启后允许从锚点拉线新建数据流
watch(
  () => props.editable,
  (on) => {
    if (!graph) return
    graph.options.connecting.enabled = !!on
  }
)

function render(model) {
  if (!graph) {
    console.warn('[DfdGraph] render: graph is null,跳过')
    return
  }
  graph.clearCells()
  if (!model) return
  const diagram = model.detail?.diagrams?.[0]
  if (!diagram) {
    console.warn('[DfdGraph] render: model.detail.diagrams[0] 缺失', { hasModel: !!model })
    return
  }
  const cells = diagram.cells || []
  // 供 addNode 内"空 trust boundary 判定"使用
  allCellsRef = cells
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
    console.log('[DfdGraph] render done, cells in graph:', graph.getCells().length)
  } catch (e) {
    console.error('[DfdGraph] render error:', e, e.stack)
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
  // 威胁数不再拼进 label（会顶出节点高度、把字号挤小）。
  // 改为节点下方独立的小徽标：名称保持 12px 可读，徽标作次要信息。
  const typeTag = aiStyleKey ? ` [${aiType}]` : ''

  // 空 trust boundary：LLM 偶尔会生成没有 child 的边界容器（噪音），画出来只会让图更乱，直接隐藏。
  const innerCount = isBoundary
    ? (cell.children || []).filter((cid) => {
        const sib = allCellsRef.find((c) => c.id === cid)
        return sib && sib.shape !== 'tm.BoundaryBox' && sib.shape !== 'tm.Text'
      }).length
    : 0
  const isEmptyBoundary = isBoundary && innerCount === 0

  // 威胁徽标画进节点自身 markup（而不是独立 cell）：
  // 独立 cell 会被框选/fitView/allCellsRef 当成真实元素，还会在拖动时滞留原地，
  // 用 markup 追加一个 <rect>+<text> 最省事——自动跟随节点、不污染数据。
  const showBadge = threatCount > 0 && !isEmptyBoundary
  const badgeText = threatCount > 9 ? '9+' : String(threatCount)

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
    // 追加 badge 节点：position 用 relative，坐标以节点左上角为原点。
    markup: [
      { tagName: 'rect', selector: 'body' },
      { tagName: 'text', selector: 'label' },
      {
        tagName: 'g',
        selector: 'badgeGroup',
        children: [
          { tagName: 'rect', selector: 'badgeBody' },
          { tagName: 'text', selector: 'badgeText' },
        ],
      },
    ],
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
        text: icon + wrapLabel(name, 16) + typeTag,
        fill: s.text,
        fontSize: 12,
        // 有未缓解威胁时加粗，作为"整体扫视"的粗粒度信号；
        // 精确条数由右下角徽标承担，不需再靠字重区分。
        fontWeight: threatCount > 0 ? 700 : 500,
        lineHeight: 17,
      },
      // 徽标整组贴在右下角：refX/refY 相对节点宽高定位，
      // 节点被 resize 时 X6 会自动重算，不需要额外监听。
      badgeGroup: {
        // 用 ref 定位而不是绝对坐标，随节点尺寸自适应
        display: showBadge ? 'block' : 'none',
        refX: size.width - (badgeText.length > 1 ? 30 : 22),
        refY: size.height - 18,
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
  // 1. 默认实线 + 灰色
  // 2. outOfScope（超出模型范围）→ 短虚线 '4 3'
  // 3. 跨信任边界 → 中虚线 '6 4' + 强制灰色（与图例一致，覆盖加密/公网颜色）
  // 4. isEncrypted → 绿色描边（不跨边界时）
  // 5. isPublicNetwork → 橙色描边（不跨边界时）
  // 跨边界的"灰色"优先级最高：跨边界本身就是最重要的视觉信号，
  // 加密/公网信息通过详情面板/标签查看，避免颜色叠加导致跨边界无法识别。
  const strokeDasharray = isOutOfScope ? '4 3' : crossesBoundary ? '6 4' : null

  // 视觉权重: 加密+公网双标记最粗(2.0) > 加密或公网(1.8) > 跨边界(1.6) > 普通(1.4)
  let baseStrokeWidth = 1.4
  if (isEncrypted || isPublicNetwork) baseStrokeWidth = 1.8
  if (isEncrypted && isPublicNetwork) baseStrokeWidth = 2.0
  if (crossesBoundary && !isEncrypted && !isPublicNetwork) baseStrokeWidth = 1.6

  // 颜色优先级: 公网(橙) > 加密(绿) > 默认(灰)
  // 跨边界通过虚线样式（strokeDasharray）表达，不覆盖颜色——保持叠加语义。
  // 跨边界+加密 = 绿虚线;跨边界+公网 = 橙虚线;跨边界+普通 = 灰虚线
  let stroke = STYLE.Flow.stroke
  if (isPublicNetwork) stroke = '#ea580c'
  else if (isEncrypted) stroke = '#16a34a'

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
  // 排除泳道(lane)背景节点：它们是占满画布的大矩形，若计入 bbox 会把图压到画布一角
  const cells = graph.getCells().filter((c) => {
    const d = c.getData ? c.getData() : c.data
    return !(d && d.lane === true)
  })
  if (cells.length === 0) {
    console.warn('[DfdGraph] fitView: 0 非 lane cells,图空')
    return
  }
  console.log('[DfdGraph] fitView start', { retry, rect: { w: rect.width, h: rect.height }, cellsCount: cells.length })
  // 优先用 X6 v2 内置 zoomToFit（内部用 graph 自己的 view area + cell bbox，
  // 不依赖外部 viewport，避免容器布局未完成时算错尺寸导致首次 fit 把图压成一小块）
  if (typeof graph.zoomToFit === 'function') {
    try {
      graph.zoomToFit({
        padding: 40,
        minScale: 0.3,
        maxScale: 1.2,
      })
      try {
        const t = graph.translate()
        const s = graph.zoom()
        console.log('[DfdGraph] fitView done', { zoom: s, translate: { tx: t.tx, ty: t.ty } })
      } catch (_) { /* 读取 transform 失败不影响图 */ }
      return
    } catch (e) {
      // 某些 X6 版本对空 cell 列表或边界异常会抛错,回退到 zoomTo
      console.error('[DfdGraph] zoomToFit failed, fallback', e)
    }
  }
  // 回退：手动算 bbox + zoomTo
  const bbox = graph.getContentBBox(cells)
  if (!bbox) {
    console.warn('[DfdGraph] fitView fallback: getContentBBox 失败')
    return
  }
  graph.zoomTo(bbox, { padding: 40, minScale: 0.3, maxScale: 1.2 })
  console.log('[DfdGraph] fitView (fallback) done', { bbox })
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
.legend {
  display: flex;
  align-items: center;
  /* 两排"圆点圆心"对齐到同一垂直线 (x ≈ 27px)：
     - 第 1 排 .gt-title-dot  圆心 = 14(.graph-toolbar) + 8(.gt-title) + 3(半径) = 25
     - 第 2 排 .lg-item .dot  圆心 = pad-left(.legend) + 5 = 27 → pad-left = 22
     （原第 2 排 .filter-chip 已并入本图例，该行不再存在。） */
  padding: 7px 16px 7px 22px;
  font-size: 11px;
  color: var(--c-text-3, #64748b);
  border-bottom: 1px solid var(--c-line, #e2e8f0);
  background: var(--c-bg-soft, #f8fafc);
  flex-wrap: wrap;
  gap: 10px;
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
/* 可点击的图例项（节点类型高亮开关）：
   默认与只读图例同款式，靠 hover/active 反馈表明可点，不额外加边框以免图例变噪。 */
.lg-toggle {
  padding: 2px 6px;
  margin: -2px -6px;
  border: none;
  border-radius: 4px;
  background: transparent;
  font-family: inherit;
  cursor: pointer;
  transition: background 0.15s, color 0.15s;
}
.lg-toggle:hover {
  background: var(--bg-active);
  color: var(--primary);
}
.lg-toggle.active {
  background: var(--primary);
  color: #fff;
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
