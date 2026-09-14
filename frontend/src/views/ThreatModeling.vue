<template>
  <div ref="pageRef" class="threat-page">
    <!-- 顶部工具条 -->
    <div class="threat-toolbar">
      <div class="toolbar-left">
        <span class="page-title">{{ pageTitle }}</span>
      </div>
      <div class="toolbar-right">
        <span
          class="status-badge"
          :class="backendStatus"
          @click="onBackendBadgeClick"
          :title="backendBadge.title"
        >
          <span class="dot" /> {{ backendBadge.text }}
        </span>
        <span
          class="status-badge"
          :class="llmStatus"
          title="点击配置 LLM"
          style="cursor: pointer"
          @click="settingsVisible = true"
        >
          <span class="dot" /> LLM：{{ llmBadge.text }}
        </span>
        <el-button size="small" @click="showPrompt">
          <el-icon><Document /></el-icon>
          系统提示词
        </el-button>
        <el-button size="small" :disabled="!lastResultId" @click="exportJson">
          <el-icon><Download /></el-icon>
          导出 JSON
        </el-button>

      </div>
    </div>

    <!-- Tab 1: 建模输入 -->
    <div v-show="activeTab === 'input'" class="threat-tab threat-input-tab">
      <InputPanel :analyzing="analyzing" @analyze="onAnalyzeRequest" @error="onErrorToast" />
    </div>

    <!-- Tab 2: 数据流图与威胁分析 -->
    <div v-show="activeTab === 'analysis'" class="threat-tab threat-analysis-tab">
      <div class="analysis-grid" :class="{ 'side-collapsed': sideCollapsed }">
        <div class="analysis-col analysis-col-main">
          <!-- 分析进度 -->
          <div v-if="analyzing" class="mid-progress">
            <header class="progress-head">
              <div class="head-l">
                <span class="head-pulse" aria-hidden="true" />
                <span class="progress-title">AI 威胁建模分析中…</span>
                <span class="progress-stage">{{ analyzeStage || '处理中…' }}</span>
              </div>
              <el-button class="cancel-btn" size="small" type="danger" @click="onCancelAnalyze">
                <el-icon class="cancel-ico"><Close /></el-icon>
                <span>取消建模</span>
              </el-button>
            </header>
            <div class="progress-bar-wrap">
              <el-progress
                :percentage="analyzeProgress"
                :stroke-width="6"
                :color="'var(--primary)'"
                :show-text="false"
              />
              <span class="progress-bar-num">{{ analyzeProgress }}%</span>
            </div>
            <div class="progress-log">
              <div
                v-for="(log, i) in analyzeLogs"
                :key="i"
                class="log-row"
                :class="['log-' + classifyLog(log.msg), { 'log-latest': i === analyzeLogs.length - 1 && analyzing }]"
              >
                <span class="log-dot" aria-hidden="true">{{ logIcon(log.msg) }}</span>
                <span class="log-time">{{ log.time }}</span>
                <span class="log-text">{{ log.msg }}</span>
              </div>
              <span v-if="!analyzeLogs.length" class="log-empty">准备建模…</span>
            </div>
          </div>

          <!-- DFD 图区域 -->
          <div v-else class="mid-graph">
            <div
              v-if="model && lastSummary?.cache_meta"
              class="cache-meta-banner"
              :class="lastSummary.cache_meta.hit ? 'hit' : 'fresh'"
            >
              <span class="cmb-dot" />
              <span class="cmb-text">
                {{
                  lastSummary.cache_meta.hit
                    ? '本次结果命中响应缓存：与历史某次分析完全一致（确定性复现，已锁定）'
                    : '本次为全新分析：输入（文档/图片/方法论）与此前不同，结果由 AI 重新生成'
                }}
              </span>
            </div>

            <!-- 画布工具条：AI 提取的 DFD 必然有误差，允许用户微调布局与元素名 -->
            <!-- 重做：左标题"DFD 画布" · 中模式切换 · 右编辑/保存组，
                 避免"只有一个复选框漂浮"的视觉断裂（只读模式时其他条件不满足，
                 原工具条会塌成单 label）。 -->
            <div v-if="activeTab === 'analysis' && model" class="graph-toolbar">
              <div class="gt-left">
                <span class="gt-title">
                  <span class="gt-title-dot" />
                  DFD 画布
                </span>
                <!-- 画布规模总览：让用户一眼知道图有多大、威胁覆盖到什么程度，
                     不必先去右侧列表数一遍。数字全部来自 lastSummary.stats。 -->
                <span class="gt-stats" :title="graphStatTitle">
                  <span class="gts-item">
                    <i class="gts-ico node" />{{ graphStats.nodes }} 节点
                  </span>
                  <span class="gts-sep" />
                  <span class="gts-item">
                    <i class="gts-ico flow" />{{ graphStats.flows }} 数据流
                  </span>
                  <span class="gts-sep" />
                  <span class="gts-item threat" :class="{ zero: !graphStats.threats }">
                    <i class="gts-ico threat" />{{ graphStats.threats }} 威胁
                  </span>
                  <span v-if="graphStats.coverage != null" class="gts-sep" />
                  <span v-if="graphStats.coverage != null" class="gts-item cover">
                    <i class="gts-ico cover" />覆盖 {{ graphStats.coverage }}%
                  </span>
                </span>
                <label class="gt-toggle" :title="canvasEditable ? '退出编辑，恢复只读浏览' : '进入编辑：可拖拽节点、双击改名、Delete 删除'">
                  <input v-model="canvasEditable" type="checkbox" />
                  <span class="gt-toggle-text">
                    {{ canvasEditable ? '编辑模式' : '只读模式' }}
                  </span>
                </label>
                <span v-if="canvasEditable" class="gt-hint">
                  拖拽 · 双击改名 · Delete 删除
                </span>
              </div>
              <div class="gt-right">
                <span v-if="layoutSaving" class="gt-saving">保存中…</span>
                <button class="gt-btn" :disabled="!canvasEditable || !layoutDirty" @click="saveLayout">保存布局</button>
                <!-- 适配视图：从 DfdGraph 暴露的 fitView 触发；
                按钮迁到这里是为了不单独占一行（避免与下方工具栏连层），给画布腾出 32px 高度 -->
                <button
                  class="gt-icon-btn"
                  title="适配视图：缩放到当前可见的所有节点"
                  @click="dfdGraphRef?.fitView?.()"
                >
                  <svg width="13" height="13" viewBox="0 0 20 20" fill="none" aria-hidden="true">
                    <path d="M3 8V3h5M17 8V3h-5M3 12v5h5M17 12v5h-5" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" />
                  </svg>
                </button>
                <!-- 折叠右栏：给画布腾出 360px 宽度，专注看大图 -->
                <button
                  class="gt-icon-btn"
                  :title="sideCollapsed ? '展开威胁分析栏' : '折叠威胁分析栏，画布独占整宽'"
                  @click="sideCollapsed = !sideCollapsed"
                >
                  <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                    <rect x="1.5" y="2.5" width="13" height="11" rx="1.6" stroke="currentColor" stroke-width="1.3" />
                    <path d="M10 2.5v11" stroke="currentColor" stroke-width="1.3" />
                    <path
                      v-if="sideCollapsed"
                      d="M7 6l-2 2 2 2"
                      stroke="currentColor"
                      stroke-width="1.3"
                      stroke-linecap="round"
                      stroke-linejoin="round"
                    />
                    <path
                      v-else
                      d="M4.6 6L6.6 8l-2 2"
                      stroke="currentColor"
                      stroke-width="1.3"
                      stroke-linecap="round"
                      stroke-linejoin="round"
                    />
                  </svg>
                </button>
              </div>
            </div>

            <DfdGraph
              v-if="activeTab === 'analysis'"
              ref="dfdGraphRef"
              :key="resultKey"
              :model="model"
              :dfd-autofix="lastDfdAutofix"
              :editable="canvasEditable"
              :highlight-cell-id="selectedCellId"
              :locate-nonce="locateNonce"
              @select-cell="onSelectCell"
              @node-moved="onNodeMoved"
              @node-renamed="onNodeRenamed"
              @node-removed="onNodeRemoved"
            />
            <div v-else class="mid-empty">
              <el-icon :size="48" color="#cbd5e1"><DataAnalysis /></el-icon>
              <p>配置输入后点击「开始建模」，将在此绘制 DFD 数据流图</p>
            </div>
          </div>
        </div>

        <div class="analysis-col analysis-col-side">
          <ThreatPanel
            :model="model"
            :result-id="lastResultId"
            :stats="lastSummary?.stats"
            :selected-threats="selectedThreatsPayload"
            :selected-cell-id="selectedCellId"
            :current-user="currentUser"
            @clear-selection="selectedCellId = null"
            @threat-updated="onThreatUpdated"
            @locate-cell="onLocateCell"
          />
        </div>
      </div>

      <!-- 右栏折叠后的"召回把手"：固定在画布区右边缘，点击展开回来。
           没有它的话折叠后无处可点（工具条上的按钮在视口很宽时容易被忽略）。 -->
      <button
        v-if="sideCollapsed && model"
        class="side-reopen"
        title="展开威胁分析栏"
        @click="sideCollapsed = false"
      >
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
          <path d="M6 6L4 8l2 2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
          <path d="M1.5 2.5h13v11h-13z" stroke="currentColor" stroke-width="1.3" fill="none" rx="1.6" />
        </svg>
        <span>威胁分析</span>
      </button>
    </div>

    <!-- Tab 3: 建模结果 -->
    <div v-show="activeTab === 'results'" class="threat-tab threat-results-tab">
      <ResultDetail
        v-if="route.params.id"
        :result-id="route.params.id"
        @back="onBackFromDetail"
        @open-result="onOpenHistoryResult"
      />
      <ResultsPanel
        v-else
        :result="lastSummary"
        :model="model"
        @remodel="onRemodel"
        @open-result="onOpenHistoryResult"
      />
    </div>

    <!-- 系统提示词弹窗 -->
    <el-dialog v-model="promptVisible" title="系统提示词" width="720px" top="6vh">
      <div class="prompt-body">
        <el-select v-model="promptMethodology" placeholder="选择方法论" style="width: 200px" @change="showPrompt">
          <el-option v-for="m in methodologies" :key="m" :label="m" :value="m" />
        </el-select>
        <el-button size="small" :loading="promptLoading" @click="showPrompt">刷新</el-button>
        <el-button size="small" :disabled="!promptContent" @click="copyPrompt">复制</el-button>
      </div>
      <pre class="prompt-content">{{ promptContent || '加载中…' }}</pre>
      <template #footer>
        <el-button @click="promptVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <!-- LLM 配置弹窗 -->
    <el-dialog v-model="settingsVisible" title="LLM 服务配置（公司统一配置）" width="540px" top="10vh">
      <el-alert
        v-if="!isAdmin"
        type="info"
        :closable="false"
        show-icon
        style="margin-bottom: 14px"
        title="您不是管理员，只能查看公司统一 LLM 配置；如需修改请联系管理员。"
      />
      <el-form :model="llmForm" label-width="100px">
        <el-form-item label="API 地址">
          <el-input
            v-model="llmForm.base_url"
            :disabled="!isAdmin"
            placeholder="https://api.openai.com/v1"
          />
        </el-form-item>
        <el-form-item :label="isAdmin ? 'API Key' : 'API Key 状态'">
          <el-input
            v-if="isAdmin"
            v-model="llmForm.api_key"
            type="password"
            show-password
            :placeholder="llmKeyChanged ? '输入新 Key 覆盖' : '留空 = 保留当前 Key'"
            @input="llmKeyChanged = true"
          />
          <el-input
            v-else
            :model-value="llmKeyMasked || '（未配置）'"
            disabled
          />
        </el-form-item>
        <el-form-item label="模型">
          <el-input
            v-model="llmForm.model"
            :disabled="!isAdmin"
            placeholder="deepseek-v3-flash"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="settingsVisible = false">取消</el-button>
        <el-button v-if="isAdmin" plain @click="clearLlmSettings">清空配置</el-button>
        <el-button v-if="isAdmin" type="primary" :loading="settingsSaving" @click="saveLlmSettings">
          保存配置（公司全员生效）
        </el-button>
      </template>
    </el-dialog>

    <!-- Toast 消息组件（子组件依赖 window.$toast） -->
    <Toast />
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Document, Download, DataAnalysis, Close } from '@element-plus/icons-vue'

import InputPanel from '../components/threat/InputPanel.vue'
import DfdGraph from '../components/threat/DfdGraph.vue'
import ThreatPanel from '../components/threat/ThreatPanel.vue'
import ResultsPanel from '../components/threat/ResultsPanel.vue'
import ResultDetail from '../components/threat/ResultDetail.vue'
import Toast from '../components/threat/Toast.vue'
import {
  http,
  checkHealth,
  getResultDetail,
  listResults,
  getSystemPrompt,
  downloadResult,
  analyze,
  getTask,
  cancelTask,
  getLlmConfig,
  saveLlmConfig as saveLlmConfigApi,
  clearLlmConfig as clearLlmConfigApi,
  updateLayout,
  renameElement,
} from '@/api/threat.js'
import { useThreatAnalysisStore } from '@/store/threat-analysis.js'
import { useUserStore } from '@/store/user.js'
import '@/styles/threat.css'

const pageRef = ref(null)
const store = useThreatAnalysisStore()
const route = useRoute()
const router = useRouter()

// ---- 导航与状态（组件级，路由切换可丢失）----
const activeTab = computed(() => {
  const p = route.path
  if (p.includes('/analysis')) return 'analysis'
  if (p.includes('/results')) return 'results'
  return 'input'
})

const pageTitle = computed(() => {
  const titles = { input: '建模输入', analysis: '数据流图与威胁分析', results: '建模结果' }
  return titles[activeTab.value] || '建模输入'
})

const llmStatus = ref('unknown')
const backendStatus = ref('checking')
const llmForm = ref({ base_url: '', api_key: '', model: '' })
// 当前登录用户角色（决定是否显示 LLM 编辑入口）
const currentRole = ref('')
const isAdmin = computed(() => {
  const r = (currentRole.value || '').toLowerCase()
  return r === 'admin' || r === 'secops'
})
// 保存 LLM 配置时是否在改 key（admin 改 model 时不丢 key 用）
const llmKeyChanged = ref(false)

const llmBadge = computed(() => {
  if (llmStatus.value === 'ready') return { text: '模型已配置', cls: 'ready' }
  if (llmStatus.value === 'missing') return { text: '未配置 LLM', cls: 'missing' }
  return { text: '检查中…', cls: 'unknown' }
})
const backendBadge = computed(() => {
  if (backendStatus.value === 'online') return { text: '后端在线', cls: 'online' }
  if (backendStatus.value === 'offline') {
    return { text: '后端离线（点击重试）', cls: 'offline', title: '无法连接威胁建模后端，请确认服务已启动' }
  }
  return { text: '连接中…', cls: 'unknown' }
})

// ---- 从 store 读取分析状态（路由切换不丢失）----
const analyzing = computed(() => store.analyzing)
const currentTaskId = computed(() => store.currentTaskId)
const analyzeProgress = computed(() => store.analyzeProgress)
const analyzeStage = computed(() => store.analyzeStage)
const analyzeSteps = computed(() => store.analyzeSteps)
const analyzeLogs = computed(() => store.analyzeLogs)
const model = computed(() => store.model)
const lastResultId = computed(() => store.lastResultId)
const lastSummary = computed(() => store.lastSummary)
const lastDfdAutofix = computed(() => store.lastDfdAutofix)
const resultKey = computed(() => store.resultKey)

// ---- 画布规模总览（工具条上的"X 节点 / Y 数据流 / Z 威胁 / 覆盖 n%"） ----
// 全部取自 lastSummary.stats（后端已算好），画布节点数兜底用 model.cells 里
// 排除 lane / text / boundary 后的真实元素数，避免后端字段缺失时显示 0。
const sideCollapsed = ref(false)
// 折叠右栏后画布列宽从 ~574px 突然扩到 ~1010px，X6 viewport 还是旧宽度，
// ResizeObserver 在 grid-template-columns 过渡动画期间不一定及时触发 fitView，
// 结果画布节点挤在左半边。手动 watch + rAF 等动画结束再 fitView 兜底。
const dfdGraphRef = ref(null)
watch(sideCollapsed, async () => {
  await nextTick()
  // 给 grid-template-columns 的 0.22s 过渡 + X6 自身 reflow 留时间
  setTimeout(() => {
    try { dfdGraphRef.value?.fitView?.() } catch (_) {}
  }, 260)
})
const graphStats = computed(() => {
  // 字段名对齐后端 stats：componentCount / flowCount / threatCount（与右栏 KPI 同源）。
  const s = lastSummary.value?.stats || {}
  const cells = model.value?.detail?.diagrams?.[0]?.cells || []

  // 仅把"真节点"算进覆盖度：
  //  - 排除 tm.Flow（数据流边）：边虽然能挂威胁，但它不是"组件"，不应进覆盖度分母
  //  - 排除 tm.Text / tm.BoundaryBox / lane：这些是装饰元素
  // 之前漏掉 tm.Flow，导致"分子 = 有威胁的节点 ∪ 有威胁的边"，分母 = 节点 ∪ 边，
  // 出现分子 > 分母 → 覆盖度 > 100%（之前显示 110% 就是这个原因）。
  const isRealNode = (c) =>
    c.shape !== 'tm.Text' &&
    c.shape !== 'tm.BoundaryBox' &&
    c.shape !== 'tm.Flow' &&
    !c.isLane
  const realNodes = cells.filter(isRealNode).length
  const threats =
    s.threatCount ?? cells.reduce((n, c) => n + (c.threats?.length || 0), 0)
  // 覆盖度本地算：只在 stats 没给时启用兜底。后端没提供 coverageRate 字段（已查 openapi.json），
  // 走本地口径——只算"真节点"，不再混入 flow 边。
  const withThreats = cells.filter(
    (c) => isRealNode(c) && (c.threats?.length || 0) > 0,
  ).length
  const coverage = realNodes
    ? Math.round((withThreats / realNodes) * 100)
    : null
  return {
    nodes: s.componentCount ?? realNodes,
    flows: s.flowCount ?? 0,
    threats,
    coverage,
  }
})
const graphStatTitle = computed(
  () =>
    `本图共 ${graphStats.value.nodes} 个元素、${graphStats.value.flows} 条数据流，` +
    `已识别 ${graphStats.value.threats} 条威胁` +
    (graphStats.value.coverage != null ? `，威胁覆盖度 ${graphStats.value.coverage}%` : ''),
)

// ---- 当前登录用户（威胁评审需要记录评审人）----
const userStore = useUserStore()
const currentUser = computed(() => ({
  username: userStore.username,
  role: userStore.role,
}))

// ---- 画布选中 → 右侧威胁列表联动 ----
// 点击 DFD 节点后，右侧只显示该组件的威胁；点空白处恢复全量列表。
const selectedCellId = ref(null)

/** 把选中元素的信息 + 其威胁装成 ThreatPanel 期望的结构 */
const selectedThreatsPayload = computed(() => {
  const id = selectedCellId.value
  if (!id) return null
  const cells = store.model?.detail?.diagrams?.[0]?.cells || []
  const cell = cells.find((c) => String(c.id) === String(id))
  if (!cell) return null
  return {
    cellId: cell.id,
    cellName: cell.data?.name || '未命名元素',
    // 注入 _cellId / _cellName / _cellKind��ThreatPanel 的"定位"按钮与
    // "挂载在 XX" chip 依赖这三个字段；否则走 selectedThreats 分支时
    // 会因 v-if="t._cellId" 不成立而整块不渲染。
    threats: (cell.threats || []).map((t) => ({
      ...t,
      _cellName: cell.data?.name || '',
      _cellId: cell.id,
      _cellKind: cell.kind || cell.data?.kind || '',
    })),
  }
})

// ---- DFD 画布编辑 ----
// AI 提取的 DFD 必然有误差（组件名不准、布局拥挤），这里允许用户：
//   1) 拖拽节点微调布局（本地即时生效，点「保存布局」才落库）
//   2) 双击节点改名（立即落库）
//   3) 选中节点按 Delete 删除（仅从画布移除，不改后端模型，避免破坏数据）
// 默认只读，避免误操作破坏 AI 生成的模型。
const canvasEditable = ref(false)
const layoutSaving = ref(false)
const layoutDirty = ref(false)
// cellId -> {x, y}，累积待保存的坐标
const pendingPositions = ref({})

function onSelectCell(cellId) {
  selectedCellId.value = cellId || null
}

/**
 * 威胁列表里点"定位"按钮 → 把 selectedCellId 切到对应 cell，
 * 触发 DfdGraph 的 watch highlightCellId 把该节点高亮 + 滚动到可视区。
 * 同时也设置 selectedThreatsPayload，让列表聚焦到该组件的威胁子集。
 *
 * 注意：若画布已经选中同一个 cell，直接赋值是同值，Vue 不会触发 DfdGraph 的
 * watch，用户看到"点了没反应"。所以用 locateNonce 计数器强制驱动一次定位。
 */
const locateNonce = ref(0)
function onLocateCell({ cellId }) {
  if (!cellId) return
  const same = String(selectedCellId.value || '') === String(cellId)
  selectedCellId.value = cellId
  // 同值也强制 +1，DfdGraph 监听非零变化后重新 zoomTo 居中
  locateNonce.value += 1
  if (same) {
    // 同值时 selectedCellId 不变，靠 nonce 触发；非 same 时 watch 已触发一次，
    // 这里不再重复，避免连续两次 zoomTo 造成抖动。
  }
}

/** 威胁发生变更（新增/编辑/删除）后，从后端重新拉取模型以保持数据一致 */
async function onThreatUpdated() {
  const rid = lastResultId.value
  if (!rid) return
  try {
    const detail = await getResultDetail(rid)
    store.setResult(detail)
  } catch (e) {
    console.warn('[onThreatUpdated]', e)
  }
}

function onNodeMoved({ cellId, x, y }) {
  pendingPositions.value = { ...pendingPositions.value, [cellId]: { x, y } }
  layoutDirty.value = true
}

async function saveLayout() {
  const rid = lastResultId.value
  if (!rid || !Object.keys(pendingPositions.value).length) return
  layoutSaving.value = true
  try {
    await updateLayout(rid, pendingPositions.value)
    pendingPositions.value = {}
    layoutDirty.value = false
    ElMessage.success('布局已保存')
  } catch (e) {
    ElMessage.error('保存布局失败：' + (e?.response?.data?.detail || e?.message))
  } finally {
    layoutSaving.value = false
  }
}

async function onNodeRenamed({ cellId, name }) {
  const rid = lastResultId.value
  if (!rid) return
  try {
    await renameElement(rid, cellId, name)
    // 同步内存中的模型，避免切 tab 回来又变回旧名字
    syncElementName(cellId, name)
    ElMessage.success('已重命名')
  } catch (e) {
    ElMessage.error('重命名失败：' + (e?.response?.data?.detail || e?.message))
  }
}

/** 把新的元素名写回 store 中的模型（保持前端状态与后端一致） */
function syncElementName(cellId, name) {
  const m = store.model
  const cells = m?.detail?.diagrams?.[0]?.cells
  if (!Array.isArray(cells)) return
  const cell = cells.find((c) => String(c.id) === String(cellId))
  if (cell) {
    if (!cell.data) cell.data = {}
    cell.data.name = name
  }
}

function onNodeRemoved({ cellId }) {
  // 只从画布移除，不落库：删除元素会连带影响威胁归属与数据流，
  // 属于高风险操作，需要用户重新建模才能生成一致的模型。
  ElMessage.warning('节点已从画布移除（未同步到后端，刷新后恢复）')
  // 取消该节点待保存的坐标，避免保存已不存在的元素
  const next = { ...pendingPositions.value }
  delete next[cellId]
  pendingPositions.value = next
  if (!Object.keys(next).length) layoutDirty.value = false
}

// ---- 弹窗 ----
const promptVisible = ref(false)
const promptContent = ref('')
const promptLoading = ref(false)
const promptMethodology = ref('STRIDE')
const methodologies = ['STRIDE', 'STRIDE-AI', 'CIA', 'CIADIE', 'LINDDUN', 'PLOT4ai', 'EOP', 'MAESTRO']

const settingsVisible = ref(false)
const settingsSaving = ref(false)

let heartbeatTimer = null

// ---- 日志滚动到底部 ----
watch(analyzeLogs, () => {
  nextTick(() => {
    const el = document.querySelector('.progress-log')
    if (el) el.scrollTop = el.scrollHeight
  })
}, { deep: true })

// ---- 健康检查 ----
async function checkLLM() {
  try {
    const raw = localStorage.getItem('ai-td-llm')
    if (raw) {
      const cfg = JSON.parse(raw)
      if (cfg.base_url || cfg.api_key || cfg.model) {
        llmStatus.value = 'ready'
        return
      }
    }
  } catch (e) { /* ignore */ }

  try {
    const r = await checkHealth()
    llmStatus.value = r?.llm_configured ? 'ready' : 'missing'
  } catch (e) {
    llmStatus.value = 'unknown'
  }
}
async function checkBackend() {
  try {
    await http.get('/health', { timeout: 3000 })
    backendStatus.value = 'online'
  } catch (e) {
    backendStatus.value = 'offline'
  }
}
function onBackendBadgeClick() {
  if (backendStatus.value === 'online') {
    window.$toast?.('后端服务正常', 'success')
  } else {
    window.$toast?.('后端服务不可用，正在重新检测…', 'warning')
    checkBackend()
  }
}

// ---- LLM 配置（公司统一，由管理员在 UI 配置；所有用户共享） ----
function _readUserRole() {
  // 从 SDLC 平台登录信息读取角色（存于 localStorage.user JSON.role 字段）
  try {
    const raw = localStorage.getItem('user')
    if (!raw) return ''
    const u = JSON.parse(raw)
    return (u?.role || u?.user?.role || '').toLowerCase()
  } catch (e) {
    return ''
  }
}
const llmKeyMasked = ref('')  // 非管理员看到的脱敏 key（仅展示）

async function loadLlmConfig() {
  // 从后端读取公司统一 LLM 配置。
  // 关键：完整 api_key **不**从后端返回（安全设计）。
  // 非管理员：admin 配的 base_url / model 仍可看（只读），api_key 字段用脱敏值展示
  // 管理员：可编辑
  try {
    const cfg = await getLlmConfig()
    currentRole.value = cfg?.is_admin ? 'admin' : 'user'
    if (cfg) {
      llmForm.value = {
        base_url: cfg.base_url || '',
        api_key: '',
        model: cfg.model || '',
      }
      llmKeyMasked.value = cfg.api_key_masked || ''
      llmKeyChanged.value = false
    }
    if (cfg?.configured) llmStatus.value = 'ready'
  } catch (e) {
    // 后端没起来时，尝试从 localStorage 兼容读取
    currentRole.value = _readUserRole()
    try {
      const raw = localStorage.getItem('ai-td-llm-legacy')
      if (raw) {
        const parsed = JSON.parse(raw)
        llmForm.value = { ...llmForm.value, ...parsed }
      }
    } catch { /* ignore */ }
  }
}

async function saveLlmSettings() {
  if (!isAdmin.value) {
    window.$toast?.('仅管理员可修改 LLM 统一配置，请联系管理员', 'error')
    return
  }
  settingsSaving.value = true
  try {
    const payload = {
      base_url: llmForm.value.base_url,
      model: llmForm.value.model,
    }
    // api_key 留空且没改 → 不传，保留旧值
    if (llmKeyChanged.value && llmForm.value.api_key) {
      payload.api_key = llmForm.value.api_key
    }
    await saveLlmConfigApi(payload)
    window.$toast?.('已保存 LLM 统一配置（公司全员立即生效）', 'success')
    llmKeyChanged.value = false
    llmForm.value.api_key = ''
    settingsVisible.value = false
    checkLLM()
  } catch (e) {
    window.$toast?.('保存 LLM 配置失败: ' + (e?.message || e), 'error')
  } finally {
    settingsSaving.value = false
  }
}

async function clearLlmSettings() {
  if (!isAdmin.value) {
    window.$toast?.('仅管理员可清空 LLM 统一配置', 'error')
    return
  }
  if (!confirm('确定要清空公司统一 LLM 配置吗？清空后所有用户立即无法调用 LLM。')) return
  try {
    await clearLlmConfigApi()
    llmForm.value = { base_url: '', api_key: '', model: '' }
    llmKeyMasked.value = ''
    llmStatus.value = 'missing'
    window.$toast?.('已清空 LLM 统一配置', 'info')
    settingsVisible.value = false
  } catch (e) {
    window.$toast?.('清空失败: ' + (e?.message || e), 'error')
  }
}

// ---- 系统提示词 ----
async function showPrompt() {
  promptLoading.value = true
  promptVisible.value = true
  promptContent.value = ''
  try {
    const r = await getSystemPrompt({ methodology: promptMethodology.value })
    promptContent.value = r?.system_prompt || '（空）'
  } catch (e) {
    promptContent.value = '// 加载失败：' + (e?.message || e)
    ElMessage.error('获取系统提示词失败')
  } finally {
    promptLoading.value = false
  }
}
async function copyPrompt() {
  if (!promptContent.value) return
  try {
    await navigator.clipboard.writeText(promptContent.value)
    ElMessage.success('提示词已复制')
  } catch (e) {
    ElMessage.warning('复制失败，请手动复制')
  }
}

// ---- 导出 ----
async function exportJson() {
  if (!lastResultId.value) {
    ElMessage.warning('暂无可导出的结果，请先完成一次建模')
    return
  }
  try {
    await downloadResult(lastResultId.value, 'json')
    ElMessage.success('已导出 JSON 结果')
  } catch (e) {
    ElMessage.error('导出失败：' + (e?.message || e))
  }
}

// ---- 轮询逻辑（操作 store，组件销毁后仍可后台运行）----
function startTaskPolling(taskId) {
  store.startPolling(async () => {
    try {
      const t = await getTask(taskId)
      const status = t?.status
      const backendLog = Array.isArray(t?.log) ? t.log : []
      for (const m of backendLog) {
        if (!m) continue
        const text = typeof m === 'string' ? m : (m?.message || m?.msg)
        if (!text) continue
        if (store.analyzeLogs.some((x) => x.msg === text)) continue
        store.appendLog(text)
      }
      if (status === 'pending' || status === 'queued') {
        store.appendLog('排队中，等待 LLM 资源…')
      } else if (status === 'running' || status === 'processing') {
        const p = typeof t?.progress === 'number' ? t.progress : 0
        const idx = t?.step_index || 0
        const steps = Array.isArray(t?.steps) ? t.steps : []
        const active = steps[idx] || t?.stage || '正在分析…'
        store.updateProgress(p, active)
        store.addStep(active)
        for (let i = 0; i <= idx && i < steps.length; i++) {
          store.addStep(steps[i])
        }
      } else if (status === 'success' || status === 'succeeded' || status === 'completed') {
        const taskResult = t?.result || {}
        store.finishAnalysis({
          model: taskResult.model,
          summary: taskResult.summary,
          stats: taskResult.stats,
          result_id: taskResult.result_id || t?.id,
          dfd_autofix: Array.isArray(taskResult.dfd_autofix) ? taskResult.dfd_autofix : [],
          cache_meta: taskResult.cache_meta || null,
        })
        router.push('/threat-modeling/results')
      } else if (status === 'error' || status === 'failed') {
        store.failAnalysis(t?.error || t?.message || '未知错误')
        ElMessage.error('建模失败：' + (t?.error || t?.message || '未知错误'))
      } else if (status === 'cancelled' || status === 'canceled') {
        store.cancelAnalysis()
        ElMessage.info('任务已取消')
      } else if (status === 'interrupted') {
        // 后端重启导致任务中断：与业务失败区分开，给出可执行的指引，
        // 而不是让进度条永远停在原地。
        store.interruptAnalysis(
          t?.error || '服务重启导致任务中断，请重新发起建模'
        )
        ElMessage.warning({
          message: t?.error || '任务已中断：后端服务重启。请回到「建模输入」重新发起。',
          duration: 6000,
          showClose: true,
        })
      }
    } catch (err) {
      // P2-X-2：不要静默吞错误。404 = 后端 task 已不存在（reload / 过期清理 / 后端
      // 内存被清），给用户清晰提示而不是让进度条永远卡在 0%。
      const status = err?.response?.status
      if (status === 404) {
        store.interruptAnalysis('后端已无此任务（可能被清理或后端重启）')
        ElMessage.error({
          message: '任务已中断：后端找不到此任务（可能后端已重启）。请回到「建模输入」重新发起。',
          duration: 6000,
          showClose: true,
        })
        // 跳回输入页，让用户重新操作
        if (activeTab.value !== 'input') router.push('/threat-modeling/input')
      } else {
        // 其他错误（网络抖动 / 5xx / 后端未启动）—— 静默 + console 即可，
        // 下一次轮询会再试
        console.warn('[poll]', err)
      }
    }
  }, 1500)
}

// ---- 建模流程 ----
async function onAnalyzeRequest(payload) {
  if (store.analyzing) return
  store.startAnalysis('')
  router.push('/threat-modeling/analysis')
  try {
    // P0-6：透传 InputPanel 算好的 input_fingerprint，后端做 in-flight 去重时用
    // （后端会再用同样的算法自己算一遍交叉验证，**不**直接信任客户端传值）。
    const submitResp = await analyze(payload)
    const taskId = submitResp?.task_id || submitResp?.id
    if (!taskId) throw new Error('提交任务失败：未返回 task_id')
    store.currentTaskId = taskId
    store.updateProgress(0, '任务已提交，等待后端返回进度…')
    store.appendLog('任务已提交 (ID: ' + taskId.slice(0, 8) + ')')
    if (submitResp?.deduped) {
      store.appendLog('P0-1：同输入 5 秒内复用已注册任务（去重命中）')
    }
    startTaskPolling(taskId)
  } catch (err) {
    store.failAnalysis(err?.response?.data?.detail || err?.message || err)
    ElMessage.error('提交失败：' + (err?.response?.data?.detail || err?.message || err))
  }
}

// ---- 进度日志视觉分类 ----
// 按消息文本推断语义（不依赖 store 改 schema），
// 给每行加左侧图标 + 颜色 + 最新行高亮，把「文本流」变成「步骤列表」。
function classifyLog(msg) {
  const m = String(msg || '')
  if (/失败|错误|中断/.test(m)) return 'err'
  if (/已识别|已解析|已生成|已建立|已提交|已就绪|完成/.test(m)) return 'ok'
  if (/排队中/.test(m)) return 'wait'
  if (/正在|解析|识别|提取|建立|调用/.test(m)) return 'doing'
  return 'info'
}
function logIcon(msg) {
  switch (classifyLog(msg)) {
    case 'ok':   return '✓'
    case 'err':  return '✕'
    case 'wait': return '⏳'
    case 'doing':return '⋯'
    default:     return '·'
  }
}

async function onCancelAnalyze() {
  const tid = store.currentTaskId
  if (tid) {
    try { await cancelTask(tid) } catch (e) { /* ignore */ }
  }
  store.cancelAnalysis()
  ElMessage.info('已取消建模')
}

async function onModelingFinished(payload) {
  if (payload && (payload.model || payload.summary || payload.stats)) {
    store.setResult({
      id: payload.result_id,
      title: payload.title || '',
      methodology: payload.methodology || '',
      created_at: payload.created_at || Date.now() / 1000,
      summary: payload.summary,
      stats: payload.stats,
      dfd_autofix: payload.dfd_autofix,
    })
    return
  }
  const rid = payload?.result_id || payload?.id || payload
  if (!rid) return
  try {
    const detail = await getResultDetail(rid)
    store.setResult(detail)
  } catch (e) {
    console.warn('[onModelingFinished]', e)
  }
}

function onErrorToast(payload) {
  const msg = typeof payload === 'string' ? payload : (payload?.message || '发生错误')
  if (!msg) return
  ElMessage.error(msg)
}

// ---- 结果切换 ----
function onRemodel() {
  router.push('/threat-modeling/input')
}

function onOpenHistoryResult(detail) {
  if (!detail?.model) return
  store.setResult(detail)
}

// 详情页返回：去掉 :id 触发 v-else 切回 ResultsPanel 列表
function onBackFromDetail() {
  router.push('/threat-modeling/results')
}

async function restoreLatestResult() {
  try {
    const list = await listResults({ page: 1, pageSize: 1 })
    const first = list?.items?.[0]
    if (!first) return
    if (store.model) return
    const detail = await getResultDetail(first.id)
    if (!detail?.model) return
    store.setResult(detail)
  } catch (e) {
    console.warn('[restoreLatestResult]', e)
  }
}

// ---- 生命周期 ----
onMounted(() => {
  // 恢复持久化的 LLM 配置到表单（localStorage 读，弹窗打开即可看到）
  loadLlmConfig()
  checkBackend()
  checkLLM()
  heartbeatTimer = setInterval(() => checkBackend(), 15000)
  restoreLatestResult()

  // P2-X-1：F5 刷新恢复 — 不再依赖 store.analyzing（刷新后一定为 false），
  // 直接从 sessionStorage 读 taskId（store 初始化时已自动读出）。
  // 若有 taskId 就说明上次有过在途任务，**总是**跳到 analysis 并启动轮询。
  // 后续行为：
  //   - 后端 task 还在跑：轮询拿到 running，进度继续走
  //   - 后端 task 已成功：finishAnalysis 自动跳到 results
  //   - 后端 task 不存在（reload 等原因）：P2-X-2 兜底，显示清晰提示
  if (store.currentTaskId) {
    // 强制 analyzing=true，否则 mid-progress 块（v-if=analyzing）不显示。
    // 这一步必须在 push /analysis 之前，否则首屏看不到进度面板。
    store.analyzing = true
    if (activeTab.value !== 'analysis') router.push('/threat-modeling/analysis')
    startTaskPolling(store.currentTaskId)
  }
})

onUnmounted(() => {
  // 只清理心跳定时器，不停止轮询！轮询在 store 中继续后台运行
  heartbeatTimer && clearInterval(heartbeatTimer)
})
</script>

<style scoped>
.threat-page {
  /* 不要固定 calc(100vh - N px) —— 当 header/视口变化时算错会让 .rp-list 高度=0 滑不动 */
  /* 用 height:100% 而不是 flex:1 —— 父级 el-main 是 block 不是 flex 容器,flex:1 无效会让整页按内容自然高度堆叠成数千 px */
  height: 100%;
  min-height: 0;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

/* 顶部工具条 */
.threat-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 0 8px;
  flex-shrink: 0;
}
.toolbar-tabs :deep(.el-tabs__header) {
  margin: 0;
}
.toolbar-tabs :deep(.el-tabs__content) {
  padding: 0;
}
.toolbar-right {
  display: flex;
  align-items: center;
  gap: 10px;
}
.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 2px 10px;
  border-radius: 20px;
  font-size: 12px;
  border: 1px solid #e2e8f0;
  background: #fff;
  color: #475569;
  cursor: pointer;
}
.status-badge .dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #94a3b8;
}
.status-badge.online .dot,
.status-badge.ready .dot {
  background: #22c55e;
}
.status-badge.offline .dot,
.status-badge.missing .dot {
  background: #ef4444;
}

/* Tab 页通用 */
.threat-tab {
  flex: 1;
  min-height: 0;
  overflow: hidden;
}

/* Tab 1: 建模输入
   .threat-tab 是 block（不是 flex 容器），InputPanel 的 height: 100% 需要一个
   有确定高度的父级才能撑满。这里显式给 height 并去掉左右 padding，
   由 InputPanel 内部的引导栏/工作区自己控制留白。 */
.threat-input-tab {
  display: flex;
  flex-direction: column;
  padding: 0;
}

/* Tab 2: 数据流图与威胁分析 */
.threat-analysis-tab {
  height: 100%;
  /* 作为 .side-reopen 的定位上下文：折叠把手要贴着画布区右缘浮着 */
  position: relative;
}

/* Tab 3: 建模结果列表 / 详情
   .threat-tab 是 block（不是 flex 容器），子项 .rd-panel 的 flex: 1 在 block 父级里无效。
   必须 height: 100% 撑满 .threat-tab 的受限高度，
   display: flex column 让 .rd-panel 的 flex: 1 真正生效（高度 = 父 - .rd-head）。
   对称参考 .threat-analysis-tab / .analysis-grid。 */
.threat-results-tab {
  height: 100%;
  display: flex;
  flex-direction: column;
}
.analysis-grid {
  display: grid;
  /* 右栏展开时给足宽度：
     360px 时 4 个 KPI 各只有 ~78px（数字挤、标签折行），威胁标题也被截断；
     460px 下 KPI 2×2 每格 ~105px、威胁标题可显示 2 行，
     在"右栏信息舒展"与"画布不被压"之间取更靠画布的平衡点。
     用 min() 兜底：窄屏（<1100px）按 42% 收缩，避免画布被压没。 */
  --side-w: min(460px, 42%);
  grid-template-columns: 1fr var(--side-w);
  /* 关键: 显式 grid-template-rows,否则 track 高度=内容高度,grid item 会被撑成几千 px */
  grid-template-rows: minmax(0, 1fr);
  gap: 12px;
  height: 100%;
  min-height: 0;
  transition: grid-template-columns 0.22s ease;
}
/* 折叠态：右栏列宽 0，gap 也归零，画布铺满 */
.analysis-grid.side-collapsed {
  --side-w: 0px;
  gap: 0;
}
.analysis-grid.side-collapsed > .analysis-col-side {
  display: none;
}
/* 画布列：右栏紧贴导致画布内容视觉"偏右"，给画布列右侧加 12px padding，
   让画布实际可视区域往左推，跟左边的留白趋于对称。
   （右栏可折叠后这里不需要 16px 那么大，缩到 12px 把宽度还给画布。） */
.mid-graph {
  /* 保留 flex / display / overflow 等原有规则不变 */
  padding-right: 12px;
}
.analysis-col {
  min-width: 0;
  min-height: 0;
  border-radius: 12px;
  border: 1px solid #e2e8f0;
  background: #fff;
}
/* 右栏内部的 ThreatPanel 用 flex column 让 .threat-list 拿到"剩余高度"独立滚动，
   这里不再额外加 overflow；否则滚动会先在外层吃掉，列表本身 .threat-list 的
   overflow-y: auto 永远不生效。 */
.analysis-col-side {
  overflow: hidden;
}
.analysis-col-main {
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.cache-meta-banner {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 10px 12px 0;
  padding: 8px 12px;
  border-radius: 8px;
  font-size: 12px;
  line-height: 1.4;
  flex-shrink: 0;
}
.cache-meta-banner.hit {
  color: #166534;
  background: #ecfdf5;
  border: 1px solid #a7f3d0;
}
.cache-meta-banner.fresh {
  color: #7c2d12;
  background: #fff7ed;
  border: 1px solid #fed7aa;
}
.cmb-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.cache-meta-banner.hit .cmb-dot {
  background: #16a34a;
}
.cache-meta-banner.fresh .cmb-dot {
  background: #ea580c;
}
.cmb-text {
  flex: 1;
}
.mid-progress,
.mid-graph {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
}
.mid-graph {
  overflow: hidden;
}
.mid-graph > :deep(.x6-graph),
.mid-graph > :deep(.dfd-container) {
  flex: 1;
}
.mid-progress {
  /* 分析进度面板：纵向三段——头部（标题+取消按钮） / 进度条 / 日志列表。
     三段独立卡片化，避免「一大块白板」造成的视觉坍塌。 */
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 18px 20px;
  min-height: 0;
  flex: 1;
}
.progress-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
}
.head-l {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}
/* 脉冲小圆点：跟「AI 分析中」标题绑定，强调「正在运行」。 */
.head-pulse {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--primary, #2563eb);
  box-shadow: 0 0 0 0 rgba(37, 99, 235, 0.45);
  flex-shrink: 0;
  animation: head-pulse 1.6s ease-out infinite;
}
@keyframes head-pulse {
  0%   { box-shadow: 0 0 0 0 rgba(37, 99, 235, 0.5); }
  70%  { box-shadow: 0 0 0 8px rgba(37, 99, 235, 0); }
  100% { box-shadow: 0 0 0 0 rgba(37, 99, 235, 0); }
}
.progress-title {
  font-weight: 600;
  color: var(--text, #1e293b);
  font-size: 14px;
}
.progress-stage {
  font-size: 12px;
  color: var(--text-faint, #64748b);
  background: var(--c-bg-soft, #f1f5f9);
  border: 1px solid var(--c-line, #e2e8f0);
  padding: 2px 9px;
  border-radius: 999px;
  max-width: 60%;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
/* 取消按钮：放在头部右侧对齐，跟标题同基线。
   实心 type="danger"（红底白字）+ 阴影 + hover 加深，
   高亮"这是个会立即终止流程的危险操作"。 */
.cancel-btn {
  margin-left: 12px;
  font-size: 12px;
  font-weight: 600;
  box-shadow: 0 2px 8px rgba(220, 38, 38, 0.25);
}
.cancel-btn:hover {
  box-shadow: 0 4px 12px rgba(220, 38, 38, 0.35);
}
.cancel-btn .cancel-ico {
  margin-right: 4px;
  font-size: 13px;
}
.progress-bar-wrap {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
}
.progress-bar-wrap :deep(.el-progress) {
  flex: 1;
}
.progress-bar-num {
  font-family: var(--font-mono, 'JetBrains Mono', Consolas, monospace);
  font-size: 12px;
  font-weight: 700;
  color: var(--primary, #2563eb);
  min-width: 40px;
  text-align: right;
  font-variant-numeric: tabular-nums;
}
/* 画布编辑工具条 —— 与下方 DfdGraph 的 .graph-head 共享同一基线，
   两行视觉上是连续的"工具栏 + 筛选 chip"组合，避免错位。 */
.graph-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 5px 14px;
  min-height: 32px;
  border-bottom: 1px solid var(--border-light, #e2e8f0);
  background: linear-gradient(180deg, #f8fafc, #f1f5f9);
  flex-shrink: 0;
  font-size: 11.5px;
}
/* 左组：标题 + 模式切换 + 提示；右组：保存状态 + 保存按钮 */
.gt-left, .gt-right {
  display: flex;
  align-items: center;
  gap: 10px;
}
.gt-title {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11.5px;
  font-weight: 600;
  color: var(--text, #334155);
  padding: 3px 9px 3px 8px;
  border-radius: 5px;
  background: #fff;
  border: 1px solid var(--border-light, #e2e8f0);
  letter-spacing: 0.2px;
}
.gt-title-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: linear-gradient(135deg, #7c3aed, #06b6d4);
  box-shadow: 0 0 0 2px rgba(124, 58, 237, 0.12);
}
.gt-toggle {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  color: #475569;
  font-weight: 500;
  user-select: none;
  padding: 3px 9px;
  border-radius: 5px;
  background: #fff;
  border: 1px solid var(--border-light, #e2e8f0);
  transition: all 0.15s;
}
.gt-toggle:hover {
  border-color: #7c3aed;
  color: #5b21b6;
}
.gt-toggle input {
  cursor: pointer;
  accent-color: #7c3aed;
  width: 14px;
  height: 14px;
  margin: 0;
}
.gt-toggle-text {
  font-size: 11.5px;
  font-weight: 600;
}
.gt-hint {
  color: #94a3b8;
  font-size: 11px;
  padding: 0 4px;
}
.gt-saving {
  color: #d97706;
  font-size: 11px;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 8px;
  background: rgba(217, 119, 6, 0.08);
  border: 1px solid rgba(217, 119, 6, 0.25);
  border-radius: 5px;
}
.gt-btn {
  font-family: inherit;
  font-size: 11.5px;
  padding: 3px 12px;
  border-radius: 5px;
  border: 1px solid #cbd5e1;
  background: #fff;
  color: #475569;
  cursor: pointer;
  font-weight: 500;
}
.gt-btn:hover:not(:disabled) {
  border-color: #7c3aed;
  color: #7c3aed;
  background: rgba(124, 58, 237, 0.04);
}
.gt-btn:disabled {
  opacity: 0.45;
  cursor: not-allowed;
  color: #94a3b8;
  border-color: #e2e8f0;
}

/* —— 工具条上的画布规模总览 —— */
.gt-stats {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-size: 11px;
  color: #64748b;
  font-variant-numeric: tabular-nums;
}
.gts-item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
}
.gts-item.threat {
  color: #b91c1c;
  font-weight: 600;
}
.gts-item.threat.zero {
  color: #94a3b8;
  font-weight: 500;
}
.gts-item.cover {
  color: #15803d;
  font-weight: 600;
}
.gts-sep {
  width: 1px;
  height: 11px;
  background: #cbd5e1;
}
.gts-ico {
  width: 7px;
  height: 7px;
  border-radius: 2px;
  display: inline-block;
}
.gts-ico.node { background: #2563eb; }
.gts-ico.flow { background: #0891b2; height: 2px; border-radius: 1px; }
.gts-ico.threat { background: #dc2626; border-radius: 50%; }
.gts-ico.cover { background: #16a34a; border-radius: 50%; }

/* —— 工具条图标按钮（折叠右栏） —— */
.gt-icon-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  padding: 0;
  border-radius: 5px;
  border: 1px solid #cbd5e1;
  background: #fff;
  color: #475569;
  cursor: pointer;
  transition: all 0.15s;
}
.gt-icon-btn:hover {
  border-color: #7c3aed;
  color: #7c3aed;
  background: rgba(124, 58, 237, 0.05);
}

/* —— 右栏折叠后的召回把手 —— */
.side-reopen {
  position: absolute;
  z-index: 20;
  top: 50%;
  right: 0;
  transform: translateY(-50%);
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 9px 7px 9px 9px;
  font-family: inherit;
  font-size: 11px;
  font-weight: 600;
  color: #fff;
  background: linear-gradient(135deg, #7c3aed, #6366f1);
  border: none;
  border-radius: 8px 0 0 8px;
  box-shadow: -2px 0 10px rgba(99, 102, 241, 0.28);
  cursor: pointer;
  writing-mode: vertical-rl;
  letter-spacing: 0.14em;
  transition: padding-right 0.15s, box-shadow 0.15s;
}
.side-reopen:hover {
  padding-right: 12px;
  box-shadow: -3px 0 14px rgba(99, 102, 241, 0.42);
}
.side-reopen svg {
  writing-mode: horizontal-tb;
  flex-shrink: 0;
}
.progress-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.progress-title {
  font-weight: 600;
  color: #1e293b;
}
.progress-stage {
  font-size: 12px;
  color: #64748b;
}
.progress-log {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  /* 日志列表：深色终端风格背景（用户偏好）。
     深蓝���底 + 浅色文本 + 细边框，让分类色（绿/红/蓝/黄）的图标更跳。 */
  background: #0f172a;
  border: 1px solid #1e293b;
  border-radius: 10px;
  padding: 8px 10px;
  font-size: 12.5px;
  scrollbar-width: thin;
  scrollbar-color: #475569 transparent;
}
.progress-log::-webkit-scrollbar {
  width: 6px;
}
.progress-log::-webkit-scrollbar-thumb {
  background: #475569;
  border-radius: 3px;
}
.progress-log::-webkit-scrollbar-thumb:hover {
  background: #64748b;
}
.log-row {
  /* 每行三段：图标圆点 + 时间戳 + 文本。
     深色背景下用浅色文本；分类图标自带浅色发光边框，确保绿/红/蓝/黄
     在 #0f172a 上仍可识别。 */
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 5px 8px;
  border-radius: 6px;
  color: #cbd5e1;
  transition: background 0.15s;
}
.log-row + .log-row {
  margin-top: 1px;
}
.log-row:hover {
  background: rgba(255, 255, 255, 0.04);
}
.log-row.log-latest {
  /* 最新一行（仅建模中）：左侧 2px 蓝色竖条 + 深蓝半透背景，
     让用户一眼能定位"现在跑到哪了"。 */
  background: rgba(37, 99, 235, 0.18);
  border-left: 2px solid #60a5fa;
  padding-left: 6px;
  color: #f1f5f9;
  font-weight: 500;
}
/* 分类图标圆点：深色背景版用饱和度更高的描边色 + 半透明背景 */
.log-dot {
  flex-shrink: 0;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  display: grid;
  place-items: center;
  font-size: 11px;
  font-weight: 700;
  line-height: 1;
  background: #1e293b;
  border: 1px solid #334155;
  color: #94a3b8;
}
.log-ok    .log-dot { color: #34d399; border-color: #065f46; background: rgba(16, 185, 129, 0.12); }
.log-err   .log-dot { color: #f87171; border-color: #991b1b; background: rgba(239, 68, 68, 0.12); }
.log-doing .log-dot { color: #60a5fa; border-color: #1d4ed8; background: rgba(37, 99, 235, 0.16); }
.log-wait  .log-dot { color: #fbbf24; border-color: #92400e; background: rgba(245, 158, 11, 0.14); }
/* doing 行的 ⋯ 抖动一下，提示"仍在进行" */
@keyframes log-dot-pulse {
  0%, 100% { opacity: 1; }
  50%      { opacity: 0.45; }
}
.log-doing .log-dot {
  animation: log-dot-pulse 1.2s ease-in-out infinite;
}
.log-time {
  color: #64748b;
  font-size: 10.5px;
  font-variant-numeric: tabular-nums;
  flex-shrink: 0;
  min-width: 48px;
}
.log-text {
  color: #e2e8f0;
  word-break: break-word;
}
.log-empty {
  color: #64748b;
  padding: 6px 8px;
}
.cancel-btn {
  align-self: flex-start;
}
.mid-empty {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 8px;
  color: #64748b;
}

/* 系统提示词弹窗 */
.prompt-body {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
}
.prompt-content {
  max-height: 50vh;
  overflow: auto;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 14px;
  font-family: Consolas, monospace;
  font-size: 13px;
  color: #334155;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
