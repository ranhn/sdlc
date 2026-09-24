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
        <div ref="canvasCardRef" class="analysis-col analysis-col-main">
          <!-- 建模中：一体化「任务控制台」——横向流水线 + KPI 数字带 + 日志台，
               全部收纳在一屏内；不再左/中/右三块摊开，也不再与右栏重复展示指标。 -->
          <div v-if="analyzing" class="mid-progress">
            <!-- 行 1：状态标题 + 大号百分比 + 取消 -->
            <header class="progress-head">
              <div class="head-l">
                <span class="head-pulse" aria-hidden="true" />
                <span class="progress-title">AI 威胁建模分析中</span>
                <span class="progress-stage">{{ analyzeStage || '处理中…' }}</span>
                <span v-if="totalElapsedText" class="head-elapsed" title="任务总耗时">
                  <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true">
                    <circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" stroke-width="1.6" />
                    <path d="M8 4.6V8l2.4 1.6" fill="none" stroke="currentColor" stroke-width="1.6"
                          stroke-linecap="round" stroke-linejoin="round" />
                  </svg>
                  总耗时 {{ totalElapsedText }}
                </span>
              </div>
              <div class="head-r">
                <!-- 进度徽标：与左侧「阶段 / 总耗时」同族的 pill（同高同圆角），
                     数字单独用 <b> 承载等宽 + tabular-nums —— 每秒跳动时宽度不抖，
                     "40%" 才是表头右侧稳定的视觉锚点（裸蓝字悬着会显得零散）。 -->
                <span class="progress-pct" :class="{ done: (analyzeProgress || 0) >= 100 }">
                  <b>{{ analyzeProgress }}</b><i>%</i>
                </span>
                <el-button class="cancel-btn" size="small" type="danger" plain @click="onCancelAnalyze">
                  <el-icon class="cancel-ico"><Close /></el-icon>
                  <span>取消建模</span>
                </el-button>
              </div>
            </header>

            <!-- 行 2：横向流水线。历史形态是三排横线叠在一起：
                 ① 顶部独立全宽进度条 ② 步骤之间的连接线 ③ 每张卡片内的阶段进度条
                 —— 三条线粗细/颜色都相近、y 只差十几像素，看着很乱。
                 现在收敛成一条体系：
                   · 全局进度 = 贴着卡片**顶边**的一条全宽线（.stepper::before/::after
                     消费 --pipe-pct），不再单独占一行；
                   · 阶段进度 = 连接线自身的填充（.step-line 里的 .step-line-fill），
                     也不再另起一行。 -->
            <ol class="stepper" :style="{ '--pipe-pct': (analyzeProgress || 0) + '%' }">
              <li
                v-for="(s, i) in pipeline"
                :key="i"
                class="step"
                :class="'step-' + s.state"
              >
                <div class="step-top">
                  <span class="step-node" aria-hidden="true">
                    <svg v-if="s.state === 'done'" viewBox="0 0 16 16" width="10" height="10">
                      <path d="M3.5 8.5l3 3 6-6.5" fill="none" stroke="currentColor"
                            stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" />
                    </svg>
                    <i v-else-if="s.state === 'active'" class="step-node-dot" />
                  </span>
                  <!-- 连接线同时是阶段进度条：done=满、active=按 sub_progress 填充 -->
                  <span v-if="i < pipeline.length - 1" class="step-line" aria-hidden="true">
                    <i class="step-line-fill" :style="{ width: (s.pct || 0) + '%' }" />
                  </span>
                  <span v-if="s.duration != null" class="step-time">{{ fmtDuration(s.duration) }}</span>
                </div>
                <span class="step-label">{{ s.short }}</span>
                <span v-if="s.summary && s.state !== 'active'" class="step-summary">{{ s.summary }}</span>
                <span v-else-if="s.state === 'active'" class="step-summary doing">
                  <span class="pipe-ellipsis"><i /><i /><i /></span>
                  <span>{{ s.summary || '进行中…' }}</span>
                </span>
              </li>
            </ol>

            <!-- 行 3：日志台（自适应剩余高度，自动滚到底）+ 右侧严重度侧栏（有数据时才出现） -->
            <div class="mc-bottom">
              <div class="log-console">
                <!-- 终端标题栏：三圆点 + 标题 + 实时徽标，
                     让深色日志区看起来是「有意的终端组件」而非突兀黑块 -->
                <div class="log-chrome">
                  <span class="chrome-dots" aria-hidden="true"><i /><i /><i /></span>
                  <span class="chrome-title">实时日志</span>
                  <span class="chrome-badge">{{ visibleLogs.length }} 条 · 自动滚动</span>
                </div>
                <div ref="logBoxRef" class="progress-log">
                  <div
                    v-for="(log, i) in visibleLogs"
                    :key="log.msg + i"
                    class="log-row"
                    :class="['log-' + classifyLog(log), { 'log-latest': i === visibleLogs.length - 1 && analyzing }]"
                  >
                    <span class="log-dot" aria-hidden="true">{{ logIcon(log) }}</span>
                    <span class="log-time">{{ log.time }}</span>
                    <span class="log-text">{{ log.msg }}</span>
                  </div>
                  <span v-if="!visibleLogs.length" class="log-empty">准备建模…</span>
                </div>
                <button
                  v-if="detailLogs.length"
                  class="log-toggle"
                  type="button"
                  @click="showDetailLogs = !showDetailLogs"
                >
                  <svg viewBox="0 0 16 16" width="10" height="10" aria-hidden="true"
                       :class="{ open: showDetailLogs }">
                    <path d="M3 6l5 5 5-5" fill="none" stroke="currentColor" stroke-width="1.9"
                          stroke-linecap="round" stroke-linejoin="round" />
                  </svg>
                  {{ showDetailLogs ? '收起详细日志' : `展开 ${detailLogs.length} 条详细日志` }}
                </button>
              </div>

              <aside v-if="liveMetrics.threatBySeverity" class="mc-side">
                <div class="mc-side-block">
                  <span class="mc-side-title">威胁严重度</span>
                  <div class="sev-chips">
                    <span
                      v-for="(n, k) in liveMetrics.threatBySeverity"
                      :key="k"
                      class="sev-chip"
                      :class="'sev-' + String(k).toLowerCase()"
                    >
                      {{ k }} <b>{{ n }}</b>
                    </span>
                  </div>
                </div>
              </aside>
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
                <!-- 节点类型图例（外部实体 / 处理 / 数据存储 / AI 组件）：
                     原在画布图例的第 1 排，按反馈并入工具条这一排。
                     四类都是高亮开关（点一下只亮该类节点、再点恢复）；
                     造型与配色由 DfdGraph 的 nodeLegend 提供 —— 仍是同一份
                     dfd_spec，这里只渲染，不复制第二套色点。 -->
                <span class="gt-legend" role="group" aria-label="节点类型高亮">
                  <button
                    v-for="it in nodeLegend"
                    :key="it.type"
                    type="button"
                    class="gtl-item"
                    :class="{ active: activeHighlight === it.type }"
                    :title="it.title"
                    @click="onLegendToggle(it.type)"
                  >
                    <svg width="20" height="12" viewBox="0 0 24 12" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
                      <path v-if="it.kind === 'cylinder'" :d="it.path" :fill="it.fill"
                            :stroke="it.stroke" stroke-width="1.1" />
                      <rect v-else x="0.75" y="0.75" width="22.5" height="10.5" :rx="it.rx"
                            :fill="it.fill" :stroke="it.stroke" :stroke-width="it.sw" />
                    </svg>
                    <span class="gtl-label">{{ it.label }}</span>
                  </button>
                </span>
                <!-- 画布规模总览（节点 / 数据流 / 威胁 / 覆盖）已按反馈移到右栏
                     「威胁分析」标题下 —— 这些数字讲的是"威胁分析"的结果，
                     放回它归属的面板里；工具条只留与画布直接相关的控件。 -->
                <!-- 模式切换：用 button + 图标（锁 / 铅笔）替代裸 <input type=checkbox>。
                     原生复选框的尺寸、圆角、颜色都不受控，夹在一排自定义图标按钮里
                     是这块最刺眼的"杂"；换成同款 24px 胶囊后整行形状语言统一。 -->
                <button
                  type="button"
                  class="gt-toggle"
                  role="switch"
                  :aria-checked="canvasEditable"
                  :title="canvasEditable ? '退出编辑，恢复只读浏览' : '进入编辑：可拖拽节点、双击改名、Delete 删除'"
                  @click="canvasEditable = !canvasEditable"
                >
                  <!-- 只读：锁；编辑：铅笔（与右侧图标按钮同一套 13px 线性图标） -->
                  <svg v-if="!canvasEditable" width="13" height="13" viewBox="0 0 20 20" fill="none" aria-hidden="true">
                    <rect x="4.2" y="8.6" width="11.6" height="8.4" rx="1.8" stroke="currentColor" stroke-width="1.4" />
                    <path d="M6.9 8.6V6.4a3.1 3.1 0 0 1 6.2 0v2.2" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" />
                  </svg>
                  <svg v-else width="13" height="13" viewBox="0 0 20 20" fill="none" aria-hidden="true">
                    <path d="M13.4 3.6l3 3-8.3 8.3-3.5.6.6-3.5 8.2-8.4Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" />
                  </svg>
                  <span class="gt-toggle-text">{{ canvasEditable ? '编辑模式' : '只读模式' }}</span>
                </button>
                <span v-if="canvasEditable" class="gt-hint">
                  拖拽 · 双击改名 · Delete 删除
                </span>
              </div>
              <div class="gt-right">
                <span v-if="layoutSaving" class="gt-saving">保存中…</span>
                <!-- 保存只在编辑模式下有意义：只读时它永远是 disabled 的灰字，
                     常驻只会让右组多一个"用不了"的控件（截图里那行浅灰文字就是它）。 -->
                <button
                  v-if="canvasEditable"
                  class="gt-btn"
                  :disabled="!layoutDirty"
                  @click="saveLayout"
                >
                  保存布局
                </button>
                <!-- 适配视图：缩放到整图可见。两种模式同一行为、同一画布 -->
                <button
                  class="gt-icon-btn"
                  title="适配视图：缩放到整图可见"
                  @click="onFitViewClick"
                >
                  <svg width="13" height="13" viewBox="0 0 20 20" fill="none" aria-hidden="true">
                    <path d="M3 8V3h5M17 8V3h-5M3 12v5h5M17 12v5h-5" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" />
                  </svg>
                </button>
                <!-- 全屏展示：把**整张 DFD 卡片**（工具条 + 图例 + 画布）投到全屏，
                     右栏「威胁分析」自然离屏，等于画布独占整宽 + 整高。
                     进全屏后滚轮缩放 / 拖拽平移照旧生效（X6 的 mousewheel
                     zoomAtMousePosition 与 panning 都开着），Esc 或本按钮退出。 -->
                <button
                  class="gt-icon-btn"
                  :title="isFullscreen ? '退出全屏（Esc）' : '全屏展示：整屏看 DFD，滚轮可缩放'"
                  @click="toggleFullscreen"
                >
                  <!-- 进入全屏：对角向外 -->
                  <svg v-if="!isFullscreen" width="13" height="13" viewBox="0 0 20 20" fill="none" aria-hidden="true">
                    <path d="M8 3H3v5M12 17h5v-5"
                          fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" />
                  </svg>
                  <!-- 退出全屏：对角向内 -->
                  <svg v-else width="13" height="13" viewBox="0 0 20 20" fill="none" aria-hidden="true">
                    <path d="M3 8h5V3M17 12h-5v5"
                          fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" />
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

            <!-- DFD 画布：只读与编辑**共用同一套 X6 矢量画布**，切模式零跳变。
                 历史版本只读时改铺后端 PNG——那是静态位图，虽然与报告导出
                 像素一致，却让"只读看到什么"和"编辑看到什么"变成两套渲染，
                 且丢失点选联动/定位/悬停（位图没有命中层）。现在样式常量已
                 收敛到 dfd_spec（含线型），两种模式观感一致，交互完整保留。 -->
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
          <!-- 建模期间的实时指标已并入左侧「任务控制台」，右栏保持威胁清单位，
               任务完成即就地填充，前后衔接无跳变。 -->
          <ThreatPanel
            :model="model"
            :result-id="lastResultId"
            :stats="lastSummary?.stats"
            :graph-stats="graphStats"
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
        ref="resultsPanelRef"
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
import { ElMessage, ElMessageBox } from 'element-plus'
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
const analyzeStepIndex = computed(() => store.analyzeStepIndex)
const liveMetrics = computed(() => store.analyzeMetrics || {})
const analyzeLogs = computed(() => store.analyzeLogs)
const model = computed(() => store.model)
const lastResultId = computed(() => store.lastResultId)
const lastSummary = computed(() => store.lastSummary)
const lastDfdAutofix = computed(() => store.lastDfdAutofix)
const resultKey = computed(() => store.resultKey)

// ---- 计时心跳：让「进行中阶段」的耗时、阶段进度条与总耗时每秒跳动 ----
// computed 不随时间自动重算，靠 nowTick 建立依赖；任务结束即停表。
const nowTick = ref(0)
let elapsedTimer = null
watch(analyzing, (on) => {
  if (on && !elapsedTimer) {
    elapsedTimer = setInterval(() => { nowTick.value++ }, 1000)
  } else if (!on && elapsedTimer) {
    clearInterval(elapsedTimer)
    elapsedTimer = null
  }
}, { immediate: true })
onUnmounted(() => {
  if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null }
})

/** 秒数 -> 「42s」「3m 05s」紧凑格式 */
function fmtDuration(sec) {
  if (sec == null || !isFinite(sec)) return ''
  const s = Math.max(0, Math.round(sec))
  if (s < 60) return `${s}s`
  const mm = Math.floor(s / 60)
  const ss = s % 60
  return ss ? `${mm}m ${String(ss).padStart(2, '0')}s` : `${mm}m`
}

// 总耗时：运行中按本地时钟每秒跳动（起始用后端 started_at，跨刷新准确）；
// 结束后用后端 elapsed 定值（不再受本地时钟影响）。
const totalElapsedText = computed(() => {
  nowTick.value // 心跳依赖：运行中每秒重算
  let sec = null
  const startMs = store.taskStartedAt
  if (startMs && analyzing.value) {
    sec = (Date.now() - startMs) / 1000
  } else {
    sec = store.taskElapsed
  }
  return sec != null ? fmtDuration(sec) : ''
})

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

// ---- 全屏展示 ----
// 全屏的元素是**整张 DFD 卡片**（工具条 + 图例 + X6 画布），不是裸 canvas：
//   · 图例、适配视图、退出按钮都还在，用户不用先退出全屏才能操作；
//   · 右栏「威胁分析」在卡片之外，进全屏后自然离屏 —— 等于画布独占整宽 + 整高。
// 滚轮缩放/拖拽平移在全屏下无需额外处理：X6 的 mousewheel（zoomAtMousePosition）
// 与 panning 一直开着，且画布容器尺寸变化会被 DfdGraph 的 ResizeObserver 捕获。
const canvasCardRef = ref(null)
const isFullscreen = ref(false)

async function toggleFullscreen() {
  try {
    if (document.fullscreenElement) await document.exitFullscreen()
    else await canvasCardRef.value?.requestFullscreen?.()
  } catch (e) {
    // 常见于 iframe 未开 allowfullscreen / 浏览器策略拒绝：给出可读提示而不是静默失败
    ElMessage.error('全屏切换失败：' + (e?.message || e))
  }
}

/** 全屏状态同步：用户按 Esc 或浏览器 UI 退出时，按钮图标也要跟着回到"进入全屏" */
function onFullscreenChange() {
  isFullscreen.value = !!document.fullscreenElement
  // 尺寸变化有过渡动画，等布局稳定后再适配一次，
  // 否则 X6 会按旧 viewport 缩放 → 图缩在左上角
  setTimeout(() => {
    try { dfdGraphRef.value?.fitView?.() } catch (_) {}
  }, 280)
}

onMounted(() => document.addEventListener('fullscreenchange', onFullscreenChange))
onUnmounted(() => document.removeEventListener('fullscreenchange', onFullscreenChange))
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
// 概要文案（tooltip）随这组数字一起搬到了 ThreatPanel 里（statsTitle），
// 这里只负责算数：nodes / flows / threats / coverage 四个值。

// ---- 工具条上的节点类型图例（原在画布图例第 1 排）----
// 规格仍只有一份：DfdGraph 用 defineExpose 给出 nodeLegend（含造型 / 配色）
// 与高亮开关，这里只做渲染 + 点击转发。图还没挂载时返回空数组 → 工具条自然
// 少这一组，不会渲染出 4 个没有颜色的空壳。
const nodeLegend = computed(() => dfdGraphRef.value?.nodeLegend || [])
const activeHighlight = computed(() => dfdGraphRef.value?.activeHighlight || null)
function onLegendToggle(type) {
  dfdGraphRef.value?.toggleHighlight?.(type)
}


// ---- 当前登录用户（威胁评审需要记录评审人）----
const userStore = useUserStore()
const currentUser = computed(() => ({
  username: userStore.username,
  role: userStore.role,
}))

// ---- 画布选中 → 右侧威胁列表联动 ----
// 点击 DFD 节点后，右侧只显示该组件的威胁；点空白处恢复全量列表。
const selectedCellId = ref(null)

/**
 * 选中信任边界时，威胁要取界内成员元素的（边界本身不挂威胁）。
 *
 * 与画布上的成员判定同口径：元素的中心点落在边界矩形内即算成员
 * （DfdGraph.boundaryChildrenBBox 用的是同一条规则，边界框宽度也由它算）。
 * 不这么做的话，点选一个边界会显示"暂无威胁记录"，与悬浮浮层给的聚合数字自相矛盾。
 */
function boundaryMemberCells(bCell, cells) {
  const bp = bCell?.position
  const bs = bCell?.size
  if (!bp || !bs) return []
  return cells.filter((c) => {
    if (c.id === bCell.id) return false
    if (c.shape === 'tm.BoundaryBox' || c.shape === 'tm.Text') return false
    if (c.source && c.target) return false          // 数据流不是容器成员
    const p = c.position
    if (!p) return false
    const sz = c.size || { width: 180, height: 60 }
    const cx = p.x + sz.width / 2
    const cy = p.y + sz.height / 2
    return cx >= bp.x && cx <= bp.x + bs.width && cy >= bp.y && cy <= bp.y + bs.height
  })
}

/** 把选中元素的信息 + 其威胁装成 ThreatPanel 期望的结构 */
const selectedThreatsPayload = computed(() => {
  const id = selectedCellId.value
  if (!id) return null
  const cells = store.model?.detail?.diagrams?.[0]?.cells || []
  const cell = cells.find((c) => String(c.id) === String(id))
  if (!cell) return null
  const isBoundary = cell.shape === 'tm.BoundaryBox'
  // 边界：摊平界内每个成员的威胁（_cellName 记"谁挂的"，面板上的"挂载在 XX"才指得准）
  const sources = isBoundary
    ? boundaryMemberCells(cell, cells).map((m) => ({ cell: m, kind: m.shape }))
    : [{ cell, kind: cell.kind || cell.data?.kind || '' }]
  return {
    cellId: cell.id,
    cellName: cell.data?.name || '未命名元素',
    // 边界容器：面板标题与计数口径都要说清"这是界内合计"
    isBoundary,
    memberCount: isBoundary ? sources.length : 0,
    // 注入 _cellId / _cellName / _cellKind：ThreatPanel 的"定位"按钮与
    // "挂载在 XX" chip 依赖这三个字段；否则走 selectedThreats 分支时
    // 会因 v-if="t._cellId" 不成立而整块不渲染。
    threats: sources.flatMap(({ cell: src, kind }) =>
      (src.threats || []).map((t) => ({
        ...t,
        _cellName: src.data?.name || '',
        _cellId: src.id,
        _cellKind: kind || '',
      })),
    ),
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

// ---- 只读 / 编辑共用同一套 X6 画布 ----
// 两种模式只差"能不能改"（editable），渲染器是同一个，切模式零跳变。
// 观感一致由样式常量单一来源（dfd_spec → /api/dfd/spec → DfdGraph）保证。
// 只读下仍完整保留平移、滚轮缩放、点选联动、威胁定位、悬停详情。

/** 适配视图：缩放到整图可见（两种模式同一行为） */
function onFitViewClick() {
  dfdGraphRef.value?.fitView?.()
}

// 结果切换 / 切回画布 tab 后重新适配一次，避免换模型后停留在旧视口
watch(
  [activeTab, resultKey],
  async () => {
    if (activeTab.value !== 'analysis') return
    await nextTick()
    // DfdGraph 首次渲染是异步的，稍等一拍再适配
    setTimeout(() => dfdGraphRef.value?.fitView?.(), 120)
  }
)

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
    // 落库后后端会用新坐标重算全部 route / 标签落点（result_store.update_layout
    // → recompute_layout_hints）。必须把这份**重算结果**取回来重新渲染：
    // 拖动期间前端只是就地平移折点（保持与后端同构的近似），
    // 若不回填，页面会停留在近似值上，与导出 PNG 再次分叉。
    try {
      const detail = await getResultDetail(rid)
      store.setResult(detail)
    } catch (e) {
      // 回填失败不影响保存本身：坐标已落库，刷新页面即可拿到新 route
      console.warn('[saveLayout] 重新拉取模型失败', e)
    }
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
// 成功收尾的延时句柄：100% 完成态短暂停留后再跳结果页（见轮询 success 分支）
let finishTimer = null
// 连续 404 计数（见下方 catch 分支）：刷新/网络抖动不要一次就判「任务已中断」
let poll404Count = 0
const resultsPanelRef = ref(null)
function startTaskPolling(taskId) {
  // 新一轮轮询前清掉可能残留的收尾定时器（快速重发任务时防串扰）
  if (finishTimer) {
    clearTimeout(finishTimer)
    finishTimer = null
  }
  poll404Count = 0
  store.startPolling(async () => {
    try {
      const t = await getTask(taskId)
      poll404Count = 0
      const status = t?.status
      // 合并后端日志（保留 level 与真实时间戳，前端据此分级降噪）
      store.mergeLogs(Array.isArray(t?.log) ? t.log : [])
      if (status === 'pending' || status === 'queued') {
        if (!store.analyzeLogs.some((x) => x.msg.includes('排队中'))) {
          store.appendLog('排队中，等待 LLM 资源…', 'warn')
        }
      } else if (status === 'running' || status === 'processing') {
        const p = typeof t?.progress === 'number' ? t.progress : 0
        const idx = t?.step_index || 0
        const steps = Array.isArray(t?.steps) ? t.steps : []
        const active = steps[idx] || t?.stage || '正在分析…'
        store.updateProgress(p, active)
        // 同步阶段/指标/计时（权威数据源），注意不写日志——日志由 mergeLogs 负责
        store.syncTaskMeta({
          steps,
          stepIndex: idx,
          metrics: t?.metrics || {},
          stage: active,
          timings: Array.isArray(t?.stage_timings) ? t.stage_timings : [],
          startedAt: t?.started_at,
          elapsed: t?.elapsed,
        })
      } else if (status === 'success' || status === 'succeeded' || status === 'completed') {
        // 先在进度面板上呈现 100% 完成态，短暂停留后再跳结果页。
        // 「构建模型 / 风险评估报告」是毫秒级本地操作，后端常在 LLM 阶段心跳值
        // （如 62%）附近瞬间 complete；若立刻 finishAnalysis + 跳转，analyzing
        // 置 false 会直接隐藏进度面板，100% 完成态从未被渲染——用户看到的是
        // 「62% 直接结束」。因此先停轮询、落定计时与进度，1.2s 后再收尾。
        store.stopPolling()
        // 收尾同步：把后端的最终计时（定值）落进 store，供「总耗时」展示
        store.syncTaskMeta({
          timings: Array.isArray(t?.stage_timings) ? t.stage_timings : [],
          startedAt: t?.started_at,
          elapsed: t?.elapsed,
        })
        store.updateProgress(100, '建模完成')
        if (finishTimer) clearTimeout(finishTimer)
        finishTimer = setTimeout(() => {
          finishTimer = null
          // 等待期间用户可能已取消/重置（analyzing 被置 false）→ 不再收尾
          if (!store.analyzing) return
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
          // 三个 tab 是 v-show 常驻挂载，ResultsPanel 的历史列表只在 onMounted
          // 拉一次；建模完成后主动刷新，否则要手动刷新页面才能看到最新结果。
          resultsPanelRef.value?.reload?.()
        }, 1200)
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
      // 但要先容错：刷新页面、网络抖动、后端滚动重启的**那一瞬间**都有可能 404，
      // 一次就判「任务已中断」会把后端其实还在正常跑的任务在前端判死
      // （面板消失、稍后结果又冒出来 —— 用户感受就是"刷新把任务弄断了"）。
      // 因此连续 3 次 404（≈4.5s）才认定任务真的不存在。
      const status = err?.response?.status
      if (status === 404) {
        poll404Count += 1
        if (poll404Count < 3) {
          console.warn(`[poll] 第 ${poll404Count} 次 404，继续重试（视作刷新/重启瞬间的抖动）`)
          return
        }
        poll404Count = 0
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
        poll404Count = 0
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
      // 后端按"同 owner + 同输入指纹 + 任务在跑/刚跑完"去重：直接复用已有任务，
      // 不会再跑一轮模型、也不会多落一份结果（否则同一份输入会出现两份建模结果）。
      store.appendLog('同一份输入刚提交过，复用已有任务/结果（未重复调用模型）', 'detail')
      ElMessage.info({
        message: '输入与上次相同：已复用上次的建模任务/结果，未重复建模。如需重新生成，请稍后再提交。',
        duration: 4000,
      })
    }
    startTaskPolling(taskId)
  } catch (err) {
    store.failAnalysis(err?.response?.data?.detail || err?.message || err)
    ElMessage.error('提交失败：' + (err?.response?.data?.detail || err?.message || err))
  }
}

// ══════════════════════════════════════════════════════════════
// 进度区：阶段流水线 + 日志分级降噪
// ══════════════════════════════════════════════════════════════

// 详细日志是否展开（默认收起，把「一大片文字」压成「里程碑列表」）
const showDetailLogs = ref(false)

/**
 * 阶段流水线：把后端 steps + step_index 渲染成横向步进条。
 * state: done（已完成，打勾）/ active（进行中，脉冲）/ todo（未开始）
 * short : 卡片上展示的短标签（后端 step 是长句，横排卡片放不下）
 * summary: 该阶段的产出摘要（取自实时指标，让"做完了什么"一目了然）
 */
const pipeline = computed(() => {
  const steps = analyzeSteps.value || []
  const idx = analyzeStepIndex.value || 0
  const m = liveMetrics.value || {}
  const stepsN = Math.max(1, steps.length)
  nowTick.value // 心跳依赖：进行中阶段的耗时与进度条每秒刷新
  return steps.map((label, i) => {
    const state = i < idx ? 'done' : (i === idx ? 'active' : 'todo')
    // 阶段内进度：由全局 progress 反推（后端 progress = (idx+sub)/N*100）。
    // 进行中保底 4%（阶段刚起步时 0% 的空条没有"活着"的感觉），封顶 99%
    //（100% 留给阶段真正切换的瞬间，避免"看着满了却还没勾"的矛盾）。
    let pct = 0
    if (state === 'done') {
      pct = 100
    } else if (state === 'active') {
      const sub = ((analyzeProgress.value || 0) / 100) * stepsN - i
      pct = Math.max(4, Math.min(99, Math.round(sub * 100)))
    }
    return {
      label,
      short: shortStepLabel(label),
      state,
      summary: stageSummary(i, state, m, steps.length),
      duration: state === 'todo' ? null : store.stepDuration(i),
      pct,
    }
  })
})

/** 后端阶段名是完整句（如「解析需求与架构文档，提取 DFD 元素」），
 *  横向卡片只放得下短语。按关键词映射，未命中时截断兜底。 */
function shortStepLabel(s) {
  const m = String(s || '')
  if (/解析|提取/.test(m)) return '文档解析 · DFD 提取'
  // 报告步（如「生成 STRIDE 风险评估报告」）必须先于方法论匹配，
  // 否则会被 STRIDE 命中，与第 2 步「STRIDE 威胁识别」重名
  if (/报告|评估/.test(m)) return '风险评估报告'
  const mm = m.match(/STRIDE|MAESTRO|PASTA|攻击树/i)
  if (mm) return `${mm[0].toUpperCase()} 威胁识别`
  if (/威胁分析|威胁识别/.test(m)) return '威胁识别'
  if (/模型/.test(m)) return '威胁模型构建'
  return m.length > 12 ? m.slice(0, 12) + '…' : m
}

/**
 * 阶段产出摘要：用真实指标说话，避免"进度条走到哪"这种无信息量的表达。
 * 注意只在状态匹配时输出对应指标，否则会串台（比如 DFD 阶段显示威胁数）。
 */
function stageSummary(i, state, m, total) {
  if (state === 'todo') return ''
  const isLast = i === total - 1
  // 步骤 0（DFD 提取）：实体/数据流是本步产出；自校验也发生在 DFD 阶段，
  // 证据挂在这里，而不是串台到「STRIDE 威胁识别」卡片上
  if (i === 0 && m.componentCount != null) {
    const base = `${m.componentCount} 个实体 · ${m.flowCount ?? 0} 条数据流`
    if (m.selfcheckDegraded) return `${base} · 自校验降级跳过`
    if (m.selfcheckFindings != null) return `${base} · 自校正 ${m.selfcheckFixed ?? 0} 项`
    return base
  }
  // 步骤 1（STRIDE 分析）：威胁数是本步产出
  if (i === 1 && m.threatCount != null) {
    return `识别 ${m.threatCount} 条威胁`
  }
  // 步骤 2（构建 Threat Dragon 模型）：完成后的证据
  if (i === 2 && state === 'done') {
    return '威胁模型已生成'
  }
  if (isLast && state === 'active') return '生成模型与报告…'
  return ''
}

/** 日志行视觉分类：优先用后端 level（权威），缺失时按文本推断（老任务兜底） */
function classifyLog(log) {
  const lv = typeof log === 'object' ? log?.level : undefined
  const m = String(typeof log === 'object' ? log?.msg : log || '')
  // 后端 level 优先：warn/error 直接映射；detail 用中性灰（不再是"红色错误"）
  if (lv === 'error') return 'err'
  if (lv === 'warn') return 'wait'
  if (lv === 'detail') return 'info'
  // 以下为无 level 时的文本推断兜底（老任务快照没有 level 字段）。
  // 判定顺序：终态 -> 排队/降级 -> 中性明细 -> 进行时。
  // 关键：「完成」「识别出」等终态词必须排在 doing 之前，否则
  // 「结构自校验完成」会被"校验"命中、「识别出 N 个组件」会被"识别"命中而误判为进行中。
  if (/失败|错误|中断/.test(m)) return 'err'
  if (/识别出|已解析|已生成|已建立|已提交|已就绪|已合并|完成|就绪|已校正/.test(m)) return 'ok'
  if (/排队中|降级|跳过|未命中/.test(m)) return 'wait'
  if (/^\[(结构自查)\]/.test(m)) return 'info'
  // 进行时：动名词，或以「中…」收尾（如「DFD AI 自校验中…」）
  if (/正在|解析|识别|提取|建立|调用|自校验|构建|分析/.test(m)) return 'doing'
  if (/中…?$/.test(m)) return 'doing'
  return 'info'
}
function logIcon(log) {
  switch (classifyLog(log)) {
    case 'ok':   return '✓'
    case 'err':  return '✕'
    case 'wait': return '!'
    case 'doing':return '⋯'
    default:     return '·'
  }
}

// 里程碑日志（默认展示）：过滤掉 detail 明细
const milestoneLogs = computed(() =>
  analyzeLogs.value.filter((l) => (l.level || 'milestone') !== 'detail')
)
// 明细日志（默认折叠）：自校验逐条结果等
const detailLogs = computed(() =>
  analyzeLogs.value.filter((l) => (l.level || 'milestone') === 'detail')
)
const visibleLogs = computed(() =>
  showDetailLogs.value ? analyzeLogs.value : milestoneLogs.value
)

// ---- 日志台自动滚底：新里程碑到达时始终让最新行可见 ----
const logBoxRef = ref(null)
watch(
  () => analyzeLogs.value.length,
  async () => {
    if (!analyzing.value) return
    await nextTick()
    const el = logBoxRef.value
    if (el) el.scrollTop = el.scrollHeight
  }
)

async function onCancelAnalyze() {
  const tid = store.currentTaskId
  // 二次确认：一轮建模要跑若干次 LLM 调用（1~3 分钟），误触一下整轮就白跑。
  // 历史上出现过"点到取消后任务直接没了"的反馈 —— 取消是**不可逆**的破坏性
  // 操作，必须让用户明确确认（而不是点了立即生效）。
  try {
    await ElMessageBox.confirm(
      '取消后本轮建模会立即终止，已经跑过的阶段不会保留，需要重新发起。确定取消吗？',
      '取消建模',
      {
        type: 'warning',
        confirmButtonText: '确定取消',
        cancelButtonText: '继续建模',
        distinguishCancelAndClose: true,
      },
    )
  } catch (e) {
    return // 用户点了「继续建模」或关闭弹窗：什么都不做
  }
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
    // 让用户在控制台里**直接看到**"刷新不影响任务"：建模跑在后端协程里，
    // 刷新/关标签页只是前端断开轮询，后端照常推进；恢复轮询即可无缝接上。
    // （appendLog 按内容去重，反复刷新不会刷屏。）
    store.appendLog('已恢复上次任务，后端仍在继续运行（刷新 / 关闭页面都不会中断建模）')
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
/* 全屏态：卡片去掉圆角与描边、铺满整屏。内部已是 flex 链
   （工具条 / 图例 / .mid-graph flex:1），画布自然撑满整屏，无需额外高度规则。 */
.analysis-col-main:fullscreen,
.analysis-col-main:-webkit-full-screen {
  border: none;
  border-radius: 0;
  background: #fff;
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
  /* 一体化「任务控制台」：标题行 / 横向流水线 / KPI 带 / 日志台+侧栏。
     四行紧凑收纳，flex:1 填满画布列高度，整屏无滚动。 */
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 16px 18px;
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
/* 总耗时徽标：时钟图标 + 「3m 05s」，运行中每秒跳动 */
.head-elapsed {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-left: 10px;
  padding: 2px 9px;
  border-radius: 999px;
  background: var(--c-bg-soft, #f1f5f9);
  border: 1px solid var(--c-line, #e2e8f0);
  color: var(--text-faint, #64748b);
  font-size: 11px;
  font-family: var(--font-mono, 'JetBrains Mono', Consolas, monospace);
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
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

/* ══════════════════════════════════════════════════════════════
   建模「任务控制台」：横向流水线 + KPI 数字带 + 日志台，一屏收纳。
   旧版纵向时间轴 / 分段进度条 / 右栏重复指标均已废弃——
   所有进度信息合并到这一块面板里，不再跨栏摊开。
   ══════════════════════════════════════════════════════════════ */

/* ── 行 1 右侧：大号百分比 + 取消按钮 ── */
.head-r {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
}
/* 进度徽标：与「阶段 / 总耗时」同族的 pill。
   数字走等宽 + tabular-nums（每秒跳动宽度不抖），% 比数字小一档、
   亮一档并贴住基线，读起来是"40 个百分点"而不是"40 加一个角标"。 */
.progress-pct {
  display: inline-flex;
  align-items: baseline;
  gap: 1px;
  padding: 2px 11px 3px;
  border: 1px solid #bfdbfe;
  border-radius: 999px;
  background: #eff6ff;
  color: #1d4ed8;
  line-height: 1.1;
  transition: background 0.25s, border-color 0.25s, color 0.25s;
}
.progress-pct b {
  font-family: var(--font-mono, 'JetBrains Mono', Consolas, monospace);
  font-size: 21px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  letter-spacing: -0.5px;
}
.progress-pct i {
  font-style: normal;
  font-family: var(--font-mono, 'JetBrains Mono', Consolas, monospace);
  font-size: 12px;
  font-weight: 600;
  margin-left: 1px;
  color: #60a5fa;
}
/* 走完 100%：与流水线里的"已完成"同色（emerald），给最后一步一个收尾信号 */
.progress-pct.done {
  background: #ecfdf5;
  border-color: #a7f3d0;
  color: #047857;
}
.progress-pct.done i {
  color: #34d399;
}
/* ── 全局进度条已并入流水线（不再是"行 1.5"） ──
   这里原本是一条独立的全宽细进度条，而流水线内部还有"步骤连接线"和
   每张卡片下的"阶段进度条"——三条横线 y 只差十几像素、粗细颜色又相近，
   叠在一起很乱。现在：
     · 全局进度 → .stepper::before/::after 画在卡片**顶边**（仍是一条全宽线，
       只是归属流水线本体，不再单独占一行）；
     · 阶段进度 → 连接线自身的填充（.step-line-fill）。
   fill-sheen 保留：给"进行中"的连接线一段掠过的高光。 */
@keyframes fill-sheen {
  from { transform: translateX(-100%); }
  to   { transform: translateX(100%); }
}

/* ── 行 2：横向流水线（步进条 + 顶边全局进度） ── */
.stepper {
  position: relative;
  overflow: hidden;              /* 顶边进度条随卡片圆角裁切 */
  list-style: none;
  margin: 0;
  padding: 14px 16px 12px;
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 0 10px;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  background: linear-gradient(180deg, #fbfdff, #f6f9fd);
  flex-shrink: 0;
}
/* 全局进度：贴在卡片顶边的一条 3px 线（轨道 ::before + 填充 ::after），
   宽度由模板绑定的 --pipe-pct（= analyzeProgress%）驱动。 */
.stepper::before,
.stepper::after {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  height: 3px;
}
.stepper::before {
  right: 0;
  background: #eef2f7;
}
.stepper::after {
  width: var(--pipe-pct, 0%);
  max-width: 100%;
  background: linear-gradient(90deg, #60a5fa, #2563eb);
  transition: width 0.6s cubic-bezier(0.22, 1, 0.36, 1);
}
.step {
  display: flex;
  flex-direction: column;
  min-width: 0;
}
/* 顶部行：状态节点 → 连接线 → 右侧耗时 */
.step-top {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 8px;
}
.step-node {
  position: relative;
  z-index: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  flex-shrink: 0;
  background: #fff;
  border: 2px solid #cbd5e1;
  color: transparent;
  transition: background 0.25s, border-color 0.25s, color 0.25s;
}
.step-done .step-node {
  background: #10b981;
  border-color: #10b981;
  color: #fff;
}
/* 进行中：蓝底 + 中心白点 + 脉冲环 */
.step-active .step-node {
  border-color: var(--primary, #2563eb);
  background: var(--primary, #2563eb);
  animation: step-node-pulse 1.8s ease-out infinite;
}
.step-node-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #fff;
}
@keyframes step-node-pulse {
  0%   { box-shadow: 0 0 0 0 rgba(37, 99, 235, 0.45); }
  70%  { box-shadow: 0 0 0 7px rgba(37, 99, 235, 0); }
  100% { box-shadow: 0 0 0 0 rgba(37, 99, 235, 0); }
}
/* 连接线：从本节点延伸到下一张卡片，**同时**是该阶段的进度条
   （填充比例 = 该阶段完成度，见 .step-line-fill）。
   这样"阶段走到哪"就长在流水线本体上，不需要卡片里再横一条线。 */
.step-line {
  position: relative;
  flex: 1;
  height: 4px;
  border-radius: 2px;
  background: #e2e8f0;
  overflow: hidden;
}
.step-line-fill {
  display: block;
  height: 100%;
  border-radius: 2px;
  background: #cbd5e1;
  transition: width 0.6s ease;
}
.step-done .step-line-fill {
  background: #34d399;
}
.step-active .step-line-fill {
  position: relative;
  background: linear-gradient(90deg, #60a5fa, var(--primary, #2563eb));
}
/* 进行中：沿填充段掠过高光，给"正在推进"的连续反馈 */
.step-active .step-line-fill::after {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.5), transparent);
  animation: fill-sheen 1.8s ease-in-out infinite;
}
.step-time {
  font-family: var(--font-mono, 'JetBrains Mono', Consolas, monospace);
  font-size: 10px;
  color: #94a3b8;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
.step-label {
  font-size: 12.5px;
  line-height: 1.4;
  color: #64748b;
  font-weight: 500;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.step-done .step-label {
  color: #334155;
}
.step-active .step-label {
  color: var(--primary, #1d4ed8);
  font-weight: 700;
}
/* 产出摘要：完成=绿、进行中=蓝（.doing），是「这步真干了活」的证据 */
.step-summary {
  margin-top: 4px;
  align-self: flex-start;
  max-width: 100%;
  font-size: 11px;
  line-height: 1.5;
  color: #0f766e;
  background: rgba(16, 185, 129, 0.08);
  border-left: 2px solid #34d399;
  padding: 2px 7px;
  border-radius: 0 4px 4px 0;
  word-break: break-word;
  animation: summary-in 0.32s ease both;
}
.step-summary.doing {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: #1d4ed8;
  background: rgba(37, 99, 235, 0.07);
  border-left-color: #60a5fa;
}
@keyframes summary-in {
  from { opacity: 0; transform: translateY(-3px); }
  to   { opacity: 1; transform: translateY(0); }
}
/* 进行中的三点省略动画 */
.pipe-ellipsis {
  display: inline-flex;
  gap: 2px;
  align-items: center;
}
.pipe-ellipsis i {
  width: 3px;
  height: 3px;
  border-radius: 50%;
  background: currentColor;
  animation: ellipsis-bounce 1.1s ease-in-out infinite;
}
.pipe-ellipsis i:nth-child(2) { animation-delay: 0.16s; }
.pipe-ellipsis i:nth-child(3) { animation-delay: 0.32s; }
@keyframes ellipsis-bounce {
  0%, 60%, 100% { opacity: 0.3; transform: translateY(0); }
  30%           { opacity: 1;   transform: translateY(-2px); }
}

/* 展开详细日志的折叠按钮：终端底栏样式（浅灰虚线按钮在深色容器里会突兀） */
.log-toggle {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 5px;
  flex-shrink: 0;
  width: 100%;
  padding: 6px;
  font-size: 11px;
  font-family: inherit;
  color: #94a3b8;
  background: #0b1222;
  border: none;
  border-top: 1px solid #1e293b;
  cursor: pointer;
  transition: color 0.15s, background 0.15s;
}
.log-toggle:hover {
  color: #bfdbfe;
  background: #101a30;
}
.log-toggle svg {
  transition: transform 0.2s ease;
}
.log-toggle svg.open {
  transform: rotate(180deg);
}

/* ── 行 4：日志台（占主要高度）+ 紧凑分布侧栏 ── */
.mc-bottom {
  display: flex;
  gap: 12px;
  flex: 1;
  min-height: 0;
}
.log-console {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  /* 终端化容器：chrome 头 + 日志区 + 折叠按钮统一包进深色圆角壳，
     黑色大块从此有明确边界和组件语义 */
  background: #0f172a;
  border: 1px solid #1e293b;
  border-radius: 10px;
  overflow: hidden;
}
/* 终端标题栏 */
.log-chrome {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 12px;
  background: #0b1222;
  border-bottom: 1px solid #1e293b;
  flex-shrink: 0;
}
.chrome-dots {
  display: inline-flex;
  gap: 5px;
}
.chrome-dots i {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.chrome-dots i:nth-child(1) { background: #f87171; }
.chrome-dots i:nth-child(2) { background: #fbbf24; }
.chrome-dots i:nth-child(3) { background: #34d399; }
.chrome-title {
  font-size: 11px;
  font-weight: 600;
  color: #94a3b8;
  letter-spacing: 0.05em;
}
.chrome-badge {
  margin-left: auto;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 10.5px;
  color: #64748b;
  font-variant-numeric: tabular-nums;
}
.chrome-badge::before {
  content: '';
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #34d399;
  animation: chrome-blink 1.6s ease-in-out infinite;
}
@keyframes chrome-blink {
  0%, 100% { opacity: 1; }
  50%      { opacity: 0.35; }
}
.mc-side {
  width: 218px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 10px 12px;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  background: #fff;
  overflow-y: auto;
}
.mc-side-block {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
/* 相邻块之间加虚线分隔，右栏多块时结构更清晰 */
.mc-side-block + .mc-side-block {
  border-top: 1px dashed #e2e8f0;
  padding-top: 10px;
}
.mc-side-title {
  font-size: 11px;
  font-weight: 600;
  color: #64748b;
}
/* 严重度 chip */
.sev-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}
.sev-chip {
  font-size: 10.5px;
  padding: 2px 8px;
  border-radius: 999px;
  background: #f1f5f9;
  color: #475569;
  border: 1px solid #e2e8f0;
}
.sev-chip b {
  font-weight: 700;
  margin-left: 2px;
}
.sev-chip.sev-critical { background: #fef2f2; color: #b91c1c; border-color: #fecaca; }
.sev-chip.sev-high     { background: #fff7ed; color: #c2410c; border-color: #fed7aa; }
.sev-chip.sev-medium   { background: #fffbeb; color: #b45309; border-color: #fde68a; }
.sev-chip.sev-low      { background: #f0fdf4; color: #15803d; border-color: #bbf7d0; }
/* 窄屏：流水线两行折行、侧栏挪到日志下方 */
@media (max-width: 1180px) {
  .stepper {
    grid-template-columns: repeat(2, 1fr);
    gap: 12px 10px;
  }
  .step-line {
    display: none;
  }
  .mc-bottom {
    flex-direction: column;
  }
  .mc-side {
    width: auto;
    flex-direction: row;
    flex-wrap: wrap;
  }
  .mc-side-block {
    flex: 1;
    min-width: 200px;
  }
}
/* 只读 / 编辑共用 X6 画布，无需额外样式 */
/* 画布编辑工具条 —— 与下方 DfdGraph 的 .graph-head 共享同一基线，
   两行视觉上是连续的"工具栏 + 筛选 chip"组合，避免错位。 */
/* 画布头部 = 工具条（本文件）+ 图例（DfdGraph 的 .legend），两块拼成
   **一整条**头部带：这里不再画自己的横线、也不单独铺渐变，改成与图例同族的
   略深一档底色，靠"色调台阶"分区 —— 避免"三条同色带 + 两条横线"叠在一起发碎。
   左右内缩统一 14px，与图例左右对齐。 */
.graph-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  /* 折行发生在**组之间**：内容装不下时整个右组（保存 + 视图操作）整体挪到第二行，
     而不是把 3 个图标按钮拆成 2+1 这种没有语义的断点（实测窄卡片下就是这样断的）。 */
  flex-wrap: wrap;
  gap: 4px 10px;
  padding: 4px 14px;
  min-height: 32px;
  background: #f1f5f9;
  flex-shrink: 0;
  font-size: 11.5px;
}
/* 左组：标题 + 节点类型图例 + 模式切换；右组：保存状态 + 保存按钮 + 视图操作组。
   左组允许内部折行（图例真的放不下时自己换行）；右组保持整体不拆。 */
.gt-left, .gt-right {
  display: flex;
  align-items: center;
  gap: 6px 10px;
  min-width: 0;
}
.gt-left { flex-wrap: wrap; }
.gt-right { flex-wrap: nowrap; }
/* 标题 / 模式开关 / 保存按钮 / 图标按钮：统一 24px 高 + 同一套边框色与 6px 圆角，
   整行才有"一条基线、一套形状"的秩序感（此前 22/23/24px 与两三种边框色混排）。 */
.gt-title {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 24px;
  font-size: 11.5px;
  font-weight: 600;
  color: var(--text, #334155);
  padding: 0 9px 0 8px;
  border-radius: 6px;
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
  height: 24px;
  padding: 0 9px;
  border-radius: 6px;
  background: #fff;
  border: 1px solid var(--border-light, #e2e8f0);
  font-family: inherit;
  font-size: 11.5px;
  font-weight: 500;
  color: #475569;
  cursor: pointer;
  user-select: none;
  transition: all 0.15s;
}
.gt-toggle:hover {
  border-color: #7c3aed;
  color: #5b21b6;
}
/* 编辑模式（role=switch 打开）：紫调高亮，跟"正在改布局"的状态对齐 */
.gt-toggle[aria-checked='true'] {
  border-color: #7c3aed;
  color: #5b21b6;
  background: rgba(124, 58, 237, 0.07);
}
/* 去掉鼠标点击后的默认黑色描边（截图里图例首项那圈黑框就是浏览器 focus ring），
   只在键盘 Tab 聚焦时给品牌色光圈 —— 鼠标用户不该看到"选中框"。 */
.gt-toggle:focus {
  outline: none;
}
.gt-toggle:focus-visible {
  outline: 2px solid rgba(124, 58, 237, 0.45);
  outline-offset: 1px;
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
  height: 24px;
  padding: 0 12px;
  border-radius: 6px;
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

/* 画布规模总览（.gt-stats / .gts-*）已随这组指标一起搬到
   ThreatPanel.vue（那里的 .tp-stats / .tps-*），工具条不再保留对应样式。 */

/* —— 工具条上的节点类型图例（原在画布图例第 1 排） —— */
/* 4 个 chip 与「DFD 画布」标题、模式开关同排。做成**无边框 + 品牌色胶囊反馈**：
   这一排已经有 3 个带边框的控件，再给 4 个边框会糊成一片；
   hover / active 的浅底 + 内描边与图例时代完全一致，用户不需要重新学。 */
.gt-legend {
  display: inline-flex;
  align-items: center;
  /* 9px：4 个 chip 加上标题、模式开关、右侧图标组要在笔记本宽度（卡片 ~600px）
     里排成一排；实测 10px 以上会把工具条挤成两排（且图标组被拆成 2+1） */
  gap: 9px;
  row-gap: 4px;
  flex-wrap: wrap;
  min-width: 0;
}
.gtl-item {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  height: 22px;
  /* 左右 5px 内衬 + 等量负外边距：胶囊底有呼吸感，但排版占位仍按内容算 */
  padding: 0 5px;
  margin: 0 -5px;
  border: none;
  border-radius: 999px;
  background: transparent;
  font-family: inherit;
  /* 10.5px（比图例时代小 1px）：4 个芯片进工具条的宽度预算里，字号是最后一项可省的开销 */
  font-size: 10.5px;
  font-weight: 600;
  color: var(--text, #334155);
  cursor: pointer;
  transition: background 0.15s, color 0.15s, box-shadow 0.15s;
}
.gtl-item svg {
  display: inline-block;
  flex-shrink: 0;
  /* 圆柱顶盖的弧线略超出 viewBox，overflow 必须放开，否则顶盖被切平 */
  overflow: visible;
}
/* 鼠标点击不留浏览器默认黑框（focus ring 在工具条上格外显脏），
   键盘 Tab 聚焦才给品牌色光圈。 */
.gtl-item:focus {
  outline: none;
}
.gtl-item:focus-visible {
  outline: 2px solid rgba(124, 58, 237, 0.45);
  outline-offset: 1px;
}
.gtl-item:hover {
  background: var(--bg-active, rgba(37, 99, 235, 0.06));
  color: var(--primary, #2563eb);
}
/* 高亮打开：浅色底 + 1px 内描边（不用整块深色填充，避免像贴了块膏药） */
.gtl-item.active {
  background: var(--primary-soft, rgba(37, 99, 235, 0.08));
  color: var(--primary, #2563eb);
  box-shadow: inset 0 0 0 1px var(--primary-border, rgba(37, 99, 235, 0.28));
}
/* 标签自带深色，hover / active 时要一起跟着变主题色 */
.gtl-item:hover .gtl-label,
.gtl-item.active .gtl-label {
  color: inherit;
}
/* 注：一度在标题与图例之间加过一条 1px 竖线做分组，实测宽度预算太紧
   （笔记本卡片 ~590px 时整条工具条会被挤成两排）——标题本身是白底描边胶囊，
   与后面的扁平 chip 已有形态差异，竖线属于可省的开销，故移除。 */

/* —— 工具条图标按钮（适配视图 / 全屏 / 折叠右栏） —— */
.gt-icon-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  padding: 0;
  border-radius: 6px;
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
/* 三个视图操作按钮彼此收拢（10px → 5px），读起来是一"组"；
   与左侧信息区仍保留 10px，右组不再是一排等距散落的方块。 */
.gt-icon-btn + .gt-icon-btn {
  margin-left: -5px;
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
/* 历史遗留的重复定义已移除：.progress-head / .progress-title / .progress-stage
   在「建模进度区」段落中已有完整定义，此处重复会按 CSS 先后顺序覆盖新版样式。 */
.progress-log {
  /* 位于 .progress-side（flex column）内：占满剩余高度并独立滚动。
     加 min-height:120px 保证极窄视口下仍能看到若干行，不会塌成 0。 */
  flex: 1;
  min-height: 120px;
  overflow-y: auto;
  /* 日志列表：深色终端风格背景（用户偏好）。
     深蓝打底 + 浅色文本 + 细边框，让分类色（绿/红/蓝/黄）的图标更跳。 */
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
  /* P2 微交互：新日志淡入 + 轻微上移，避免"硬刷"造成的跳跃感 */
  animation: log-in 0.24s ease both;
}
@keyframes log-in {
  from { opacity: 0; transform: translateY(-2px); }
  to   { opacity: 1; transform: translateY(0); }
}
@media (prefers-reduced-motion: reduce) {
  .log-row,
  .step-summary,
  .step-node,
  .step-line-fill::after,
  .chrome-badge::before,
  .kpi b.pending { animation: none; }
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
/* info（自校验明细等）：整体压暗一档，视觉上"是背景信息，不是告警"。
   这是修正「正常自检被渲染成满屏红」的关键——明细行不再有攻击性色彩。 */
.log-info .log-text {
  color: #94a3b8;
}
.log-info .log-dot {
  color: #94a3b8;
  border-color: #334155;
  background: #1e293b;
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
