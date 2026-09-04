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
              :show-text="true"
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
  getLlmConfig,
  saveLlmConfig as saveLlmConfigApi,
  clearLlmConfig as clearLlmConfigApi,
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
  /* 关键: 显式 grid-template-rows,否则 track 高度=内容高度,grid item 会被撑成几千 px */
  grid-template-rows: minmax(0, 1fr);
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
