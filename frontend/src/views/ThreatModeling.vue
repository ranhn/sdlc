<template>
  <div ref="pageRef" class="threat-page">
    <!-- 顶部工具条 -->
    <div class="threat-toolbar">
      <div class="toolbar-left">
        <span class="page-title">AI 威胁建模 / {{ pageTitle }}</span>
      </div>
      <div class="toolbar-right">
        <span
          class="status-badge"
          :class="backendStatus"
          @click="onBackendBadgeClick"
          :title="backendBadge.title"
        >
          <span class="dot" /> 后端：{{ backendBadge.text }}
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
      <div class="analysis-grid">
        <div class="analysis-col analysis-col-main">
          <!-- 分析进度 -->
          <div v-if="analyzing" class="mid-progress">
            <div class="progress-head">
              <span class="progress-title">AI 威胁建模分析中…</span>
              <span class="progress-stage">{{ analyzeStage || '处理中…' }}</span>
            </div>
            <el-progress
              :percentage="analyzeProgress"
              :stroke-width="8"
              :color="'var(--primary)'"
              :show-text="false"
            />
            <div class="progress-log">
              <div v-for="(log, i) in analyzeLogs" :key="i" class="log-row">
                <span class="log-time">{{ log.time }}</span>
                <span class="log-text">{{ log.msg }}</span>
              </div>
              <span v-if="!analyzeLogs.length" class="log-empty">准备建模…</span>
            </div>
            <el-button class="cancel-btn" size="small" plain type="danger" @click="onCancelAnalyze">
              取消建模
            </el-button>
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

            <DfdGraph v-if="activeTab === 'analysis'" :key="resultKey" :model="model" :dfd-autofix="lastDfdAutofix" />
            <div v-else class="mid-empty">
              <el-icon :size="48" color="#cbd5e1"><DataAnalysis /></el-icon>
              <p>配置输入后点击「开始建模」，将在此绘制 DFD 数据流图</p>
            </div>
          </div>
        </div>

        <div class="analysis-col analysis-col-side">
          <ThreatPanel :model="model" :result-id="lastResultId" :stats="lastSummary?.stats" />
        </div>
      </div>
    </div>

    <!-- Tab 3: 建模结果 -->
    <div v-show="activeTab === 'results'" class="threat-tab threat-results-tab">
      <ResultsPanel
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
    <el-dialog v-model="settingsVisible" title="LLM 服务配置" width="520px" top="10vh">
      <el-form :model="llmForm" label-width="96px">
        <el-form-item label="API 地址">
          <el-input v-model="llmForm.base_url" placeholder="https://api.openai.com/v1" />
        </el-form-item>
        <el-form-item label="API Key">
          <el-input v-model="llmForm.api_key" type="password" show-password placeholder="sk-…" />
        </el-form-item>
        <el-form-item label="模型">
          <el-input v-model="llmForm.model" placeholder="gpt-4o" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="settingsVisible = false">取消</el-button>
        <el-button plain @click="clearLlmConfig">清空配置</el-button>
        <el-button type="primary" :loading="settingsSaving" @click="saveLlmConfig">
          保存配置
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
import { Document, Download, DataAnalysis } from '@element-plus/icons-vue'

import InputPanel from '../components/threat/InputPanel.vue'
import DfdGraph from '../components/threat/DfdGraph.vue'
import ThreatPanel from '../components/threat/ThreatPanel.vue'
import ResultsPanel from '../components/threat/ResultsPanel.vue'
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
} from '@/api/threat.js'
import { useThreatAnalysisStore } from '@/store/threat-analysis.js'
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

// ---- 弹窗 ----
const promptVisible = ref(false)
const promptContent = ref('')
const promptLoading = ref(false)
const promptMethodology = ref('STRIDE')
const methodologies = ['STRIDE', 'STRIDE-AI', 'CIA', 'CIADIE', 'LINDDUN', 'PLOT4ai', 'EOP']

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

// ---- LLM 配置 ----
function loadLlmConfig() {
  try {
    const raw = localStorage.getItem('ai-td-llm')
    if (raw) {
      const parsed = JSON.parse(raw)
      llmForm.value = { ...llmForm.value, ...parsed }
      if (parsed?.base_url || parsed?.api_key || parsed?.model) {
        llmStatus.value = 'ready'
      }
    }
  } catch (e) { /* ignore */ }
}
function saveLlmConfig() {
  settingsSaving.value = true
  try {
    localStorage.setItem('ai-td-llm', JSON.stringify(llmForm.value))
    const f = llmForm.value || {}
    if (f.base_url || f.api_key || f.model) {
      llmStatus.value = 'ready'
    }
    window.$toast?.('已保存 LLM 配置（本次会话生效）', 'success')
    settingsVisible.value = false
  } catch (e) {
    window.$toast?.('保存失败：' + (e?.message || e), 'error')
  } finally {
    settingsSaving.value = false
  }
}
function clearLlmConfig() {
  localStorage.removeItem('ai-td-llm')
  llmForm.value = { base_url: '', api_key: '', model: '' }
  checkLLM()
  window.$toast?.('已清除 LLM 配置', 'info')
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
      }
    } catch (err) {
      console.warn('[poll]', err)
    }
  }, 1500)
}

// ---- 建模流程 ----
async function onAnalyzeRequest(payload) {
  if (store.analyzing) return
  store.startAnalysis('')
  router.push('/threat-modeling/analysis')
  try {
    const submitResp = await analyze(payload)
    const taskId = submitResp?.task_id || submitResp?.id
    if (!taskId) throw new Error('提交任务失败：未返回 task_id')
    store.currentTaskId = taskId
    store.updateProgress(0, '任务已提交，等待后端返回进度…')
    store.appendLog('任务已提交 (ID: ' + taskId.slice(0, 8) + ')')
    startTaskPolling(taskId)
  } catch (err) {
    store.failAnalysis(err?.response?.data?.detail || err?.message || err)
    ElMessage.error('提交失败：' + (err?.response?.data?.detail || err?.message || err))
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
  checkBackend()
  checkLLM()
  heartbeatTimer = setInterval(() => checkBackend(), 15000)
  restoreLatestResult()

  // 若 store 中有正在进行的任务（用户切出去又切回来），恢复轮询
  if (store.analyzing && store.currentTaskId) {
    router.push('/threat-modeling/analysis')
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
  height: calc(100vh - 100px);
  min-height: 600px;
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

/* Tab 1: 建模输入 */
.threat-input-tab {
  padding: 0 8px;
}

/* Tab 2: 数据流图与威胁分析 */
.threat-analysis-tab {
  height: 100%;
}
.analysis-grid {
  display: grid;
  grid-template-columns: 1fr 380px;
  gap: 12px;
  height: 100%;
  min-height: 0;
}
.analysis-col {
  min-width: 0;
  min-height: 0;
  overflow-y: auto;
  border-radius: 12px;
  border: 1px solid #e2e8f0;
  background: #fff;
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
  gap: 14px;
  padding: 24px;
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
  background: #0f172a;
  border-radius: 8px;
  padding: 12px;
  font-family: 'JetBrains Mono', Consolas, monospace;
  font-size: 12px;
}
.log-row {
  color: #94a3b8;
  line-height: 1.7;
}
.log-time {
  color: #64748b;
}
.log-text {
  color: #cbd5e1;
}
.log-empty {
  color: #64748b;
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
