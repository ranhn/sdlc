import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

/**
 * 威胁建模分析状态 Store
 * 将分析状态从组件级提升到全局，解决路由切换导致分析中断的问题。
 */
export const useThreatAnalysisStore = defineStore('threat-analysis', () => {
  // ---- 分析状态 ----
  const analyzing = ref(false)
  const currentTaskId = ref('')
  const analyzeProgress = ref(0)
  const analyzeStage = ref('')
  const analyzeSteps = ref([])
  const analyzeLogs = ref([])

  // ---- 结果数据 ----
  const model = ref(null)
  const lastResultId = ref('')
  const lastSummary = ref(null)
  const lastDfdAutofix = ref([])
  const resultKey = ref(Date.now())

  // ---- 轮询引用（组件销毁后需要重新绑定）----
  let pollTimer = null

  const isAnalyzing = computed(() => analyzing.value)
  const hasTask = computed(() => !!currentTaskId.value)
  const hasResult = computed(() => !!lastResultId.value)

  // ---- 日志操作 ----
  function appendLog(msg) {
    if (!msg) return
    const text = typeof msg === 'string' ? msg : (msg?.message || msg?.msg || String(msg))
    if (!text) return
    analyzeLogs.value.push({ time: fmtTime(), msg: text })
    if (analyzeLogs.value.length > 80) analyzeLogs.value.shift()
  }

  function fmtTime(d) {
    d = d || new Date()
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`
  }

  // ---- 开始分析 ----
  function startAnalysis(taskId) {
    analyzing.value = true
    currentTaskId.value = taskId
    analyzeProgress.value = 0
    analyzeStage.value = '正在提交任务…'
    analyzeSteps.value = []
    analyzeLogs.value = []
    appendLog('正在提交建模任务…')
    appendLog('任务已提交 (ID: ' + taskId.slice(0, 8) + ')')
  }

  // ---- 更新进度 ----
  function updateProgress(progress, stage) {
    analyzeProgress.value = Math.max(0, Math.min(100, Math.round(progress)))
    if (stage) analyzeStage.value = stage
  }

  function addStep(step) {
    if (step && !analyzeSteps.value.includes(step)) {
      analyzeSteps.value.push(step)
      appendLog(step)
    }
  }

  // ---- 完成分析 ----
  function finishAnalysis(payload) {
    analyzing.value = false
    analyzeProgress.value = 100
    analyzeStage.value = '建模完成'
    appendLog('建模完成，正在加载结果…')

    if (payload) {
      lastResultId.value = payload.result_id || ''
      model.value = payload.model || null
      lastSummary.value = {
        id: payload.result_id,
        title: payload.title || '',
        methodology: payload.methodology || '',
        created_at: payload.created_at || Date.now() / 1000,
        summary: payload.summary,
        stats: payload.stats,
        cache_meta: payload.cache_meta || null,
      }
      lastDfdAutofix.value = Array.isArray(payload.dfd_autofix) ? [...payload.dfd_autofix] : []
      resultKey.value = Date.now()
    }
    stopPolling()
  }

  // ---- 失败/取消 ----
  function failAnalysis(errorMsg) {
    analyzing.value = false
    appendLog('失败：' + (errorMsg || '未知错误'))
    stopPolling()
  }

  function cancelAnalysis() {
    analyzing.value = false
    analyzeProgress.value = 0
    analyzeStage.value = ''
    appendLog('已取消建模')
    stopPolling()
  }

  // ---- 轮询管理 ----
  function startPolling(callback, interval = 1500) {
    stopPolling()
    pollTimer = setInterval(callback, interval)
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer)
      pollTimer = null
    }
  }

  // ---- 设置结果（从详情加载）----
  function setResult(detail) {
    if (!detail) return
    model.value = detail.model || null
    lastResultId.value = detail.id || ''
    lastSummary.value = {
      id: detail.id,
      title: detail.title || '',
      methodology: detail.methodology || '',
      created_at: detail.created_at || Date.now() / 1000,
      summary: detail.summary || '',
      stats: detail.stats || {},
    }
    lastDfdAutofix.value = Array.isArray(detail?.dfd_autofix) ? [...detail.dfd_autofix] : []
    resultKey.value = Date.now()
  }

  // ---- 清理（用户主动重置）----
  function reset() {
    analyzing.value = false
    currentTaskId.value = ''
    analyzeProgress.value = 0
    analyzeStage.value = ''
    analyzeSteps.value = []
    analyzeLogs.value = []
    stopPolling()
  }

  return {
    // state
    analyzing,
    currentTaskId,
    analyzeProgress,
    analyzeStage,
    analyzeSteps,
    analyzeLogs,
    model,
    lastResultId,
    lastSummary,
    lastDfdAutofix,
    resultKey,
    // computed
    isAnalyzing,
    hasTask,
    hasResult,
    // actions
    appendLog,
    startAnalysis,
    updateProgress,
    addStep,
    finishAnalysis,
    failAnalysis,
    cancelAnalysis,
    startPolling,
    stopPolling,
    setResult,
    reset,
  }
})
