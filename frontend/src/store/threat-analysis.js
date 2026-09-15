import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

/**
 * 威胁建模分析状态 Store
 * 将分析状态从组件级提升到全局，解决路由切换导致分析中断的问题。
 */
export const useThreatAnalysisStore = defineStore('threat-analysis', () => {
  // ---- sessionStorage 持久化（防 F5 刷新丢失任务）----
  // P2-X-1：刷新后 store 会被重建，analyzing/currentTaskId 全部重置为 false/''。
  // 这里把"在途任务"的 taskId 写进 sessionStorage（关浏览器即清，符合任务临时性）。
  // ThreatModeling.vue 的 onMounted 检测到该 key 后会自动恢复轮询。
  // 注意：P2-X-2（404 提示）配合使用，404 时也会清掉这个 key，避免幽灵任务。
  const TASK_ID_KEY = 'ai-td-task-id'

  function _loadPersistedTaskId() {
    try {
      return sessionStorage.getItem(TASK_ID_KEY) || ''
    } catch {
      return ''
    }
  }
  function _savePersistedTaskId(taskId) {
    try {
      if (taskId) sessionStorage.setItem(TASK_ID_KEY, taskId)
    } catch { /* 隐私模式禁用时静默 */ }
  }
  function _clearPersistedTaskId() {
    try { sessionStorage.removeItem(TASK_ID_KEY) } catch { /* ignore */ }
  }

  // ---- 分析状态 ----
  // 启动时从 sessionStorage 还原 currentTaskId（仅 id，不还原 analyzing/进度——
  // 因为进度/状态都以后端实时为准，首次轮询会刷新到最新值）
  const analyzing = ref(false)
  const currentTaskId = ref(_loadPersistedTaskId())
  const analyzeProgress = ref(0)
  const analyzeStage = ref(currentTaskId.value ? '恢复中：正在向后端查询任务状态…' : '')
  // 全量阶段名（后端 steps，长度=流水线步骤数）——用于左栏阶段流水线渲染
  const analyzeSteps = ref([])
  // 当前阶段下标（0 基，来自后端 step_index）——流水线用它区分 已完成/进行中/未开始
  const analyzeStepIndex = ref(0)
  // 后端透出的实时指标快照（componentCount/flowCount/selfcheckFixed…）
  // 用于「建模中」右栏仪表盘，任务完成前就有真实数据可看。
  const analyzeMetrics = ref({})
  // 各阶段耗时（step_index -> 进入该阶段的 epoch 秒），用于流水线展示「2.3s」
  const stepStartedAt = ref({})
  // 日志：带 level 分级（milestone/detail/warn/error），前端据此降噪折叠
  const analyzeLogs = ref(currentTaskId.value ? [
    { time: '00:00:00', msg: '检测到上次未完成的任务，正在自动恢复轮询…', level: 'milestone' },
  ] : [])

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
  /**
   * 追加日志。第二个参数可为字符串级别（milestone/detail/warn/error），
   * 也可传入完整对象 { message, level, ts }（后端轮询时用）。
   * 未指定 level 时按 milestone 处理，保持向后兼容。
   */
  function appendLog(msg, level) {
    if (!msg) return
    let text, lv, ts
    if (typeof msg === 'object' && msg !== null && !Array.isArray(msg)) {
      text = msg.message || msg.msg || ''
      lv = msg.level
      ts = msg.ts
    } else {
      text = typeof msg === 'string' ? msg : (msg?.message || msg?.msg || String(msg))
    }
    if (!text) return
    analyzeLogs.value.push({
      time: ts != null ? fmtTime(new Date(ts * 1000)) : fmtTime(),
      msg: text,
      level: normLevel(lv),
    })
    if (analyzeLogs.value.length > 200) analyzeLogs.value.shift()
  }

  /** 日志级别白名单归一化，未知值退化为 milestone（默认展示） */
  function normLevel(lv) {
    const s = String(lv || '').toLowerCase()
    return ['milestone', 'detail', 'warn', 'error'].includes(s) ? s : 'milestone'
  }

  /** 批量合并后端日志（按 msg 去重），保留后端 level 与真实时间戳 */
  function mergeLogs(entries) {
    if (!Array.isArray(entries)) return
    for (const e of entries) {
      if (!e) continue
      const text = typeof e === 'string' ? e : (e?.message || e?.msg)
      if (!text) continue
      if (analyzeLogs.value.some((x) => x.msg === text)) continue
      appendLog({ message: text, level: e?.level, ts: e?.time })
    }
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
    analyzeStepIndex.value = 0
    analyzeMetrics.value = {}
    stepStartedAt.value = {}
    analyzeLogs.value = []
    // 重要：开始新建模时清掉上次的结果数据。
    // 否则分析页右栏 ThreatPanel 会一直展示「上一次的」KPI/严重度/威胁列表，
    // 与左侧正在跑的新任务脱节，给用户「数据不一致」的错觉。
    // 注意：failAnalysis 不清——失败时保留旧结果给用户作回退。
    // cancelAnalysis 也不清——用户主动取消时可继续看上次结果。
    model.value = null
    lastResultId.value = ''
    lastSummary.value = null
    lastDfdAutofix.value = []
    resultKey.value = Date.now()
    // P2-X-1：写 sessionStorage，F5 刷新后 ThreatModeling.vue 的 onMounted
    // 会读到该 key 并自动恢复轮询
    _savePersistedTaskId(taskId)
    appendLog('正在提交建模任务…')
    appendLog('任务已提交 (ID: ' + taskId.slice(0, 8) + ')')
  }

  // ---- 更新进度 ----
  function updateProgress(progress, stage) {
    analyzeProgress.value = Math.max(0, Math.min(100, Math.round(progress)))
    if (stage) analyzeStage.value = stage
  }

  /**
   * 用后端权威数据同步「阶段」相关状态（steps / step_index / metrics）。
   * 注意：不写日志——日志由 mergeLogs 单独合并，否则每次轮询都会重复追加。
   */
  function syncTaskMeta({ steps, stepIndex, metrics, stage } = {}) {
    if (Array.isArray(steps) && steps.length) analyzeSteps.value = steps
    if (typeof stepIndex === 'number' && stepIndex >= 0) {
      const prev = analyzeStepIndex.value
      analyzeStepIndex.value = stepIndex
      // 首次进入某阶段时记录起始时间，供流水线展示阶段耗时
      if (prev !== stepIndex && !stepStartedAt.value[stepIndex]) {
        stepStartedAt.value = { ...stepStartedAt.value, [stepIndex]: Date.now() }
      }
    }
    if (metrics && typeof metrics === 'object') {
      analyzeMetrics.value = { ...analyzeMetrics.value, ...metrics }
    }
    if (stage) analyzeStage.value = stage
  }

  function addStep(step) {
    if (step && !analyzeSteps.value.includes(step)) {
      analyzeSteps.value.push(step)
      appendLog(step)
    }
  }

  /** 取某阶段已耗时（秒，一位小数）；进行中的阶段按当前时间实时算 */
  function stepDuration(i) {
    const start = stepStartedAt.value[i]
    if (!start) return null
    // 下一阶段的开始时间即为本阶段结束时间；最后阶段用「现在」
    const next = stepStartedAt.value[i + 1]
    const end = next || (analyzing.value ? Date.now() : null)
    if (!end) return null
    return Math.max(0, (end - start) / 1000)
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
    // P2-X-1：完成也清 sessionStorage，避免下次刷新误把已结束的任务当成"在途"
    _clearPersistedTaskId()
    stopPolling()
  }

  // ---- 失败/取消 ----
  function failAnalysis(errorMsg) {
    analyzing.value = false
    appendLog('失败：' + (errorMsg || '未知错误'))
    // P2-X-1：终态清除 sessionStorage（轮询不会再来）
    _clearPersistedTaskId()
    stopPolling()
  }

  function cancelAnalysis() {
    analyzing.value = false
    analyzeProgress.value = 0
    analyzeStage.value = ''
    appendLog('已取消建模')
    _clearPersistedTaskId()
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
    analyzeStepIndex.value = 0
    analyzeMetrics.value = {}
    stepStartedAt.value = {}
    analyzeLogs.value = []
    _clearPersistedTaskId()
    stopPolling()
  }

  // ---- 标记任务已中断（后端 404 / 后端 reload 等导致任务丢失）----
  // 区别于 failAnalysis：failAnalysis 是"后端知道任务失败了"，这里是"连任务都找不到了"
  function interruptAnalysis(reason) {
    analyzing.value = false
    analyzeProgress.value = 0
    analyzeStage.value = '任务已中断'
    appendLog('中断：' + (reason || '任务在后端已不存在（可能后端重启）'))
    _clearPersistedTaskId()
    stopPolling()
  }

  return {
    // state
    analyzing,
    currentTaskId,
    analyzeProgress,
    analyzeStage,
    analyzeSteps,
    analyzeStepIndex,
    analyzeMetrics,
    stepStartedAt,
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
    mergeLogs,
    startAnalysis,
    updateProgress,
    syncTaskMeta,
    stepDuration,
    addStep,
    finishAnalysis,
    failAnalysis,
    cancelAnalysis,
    interruptAnalysis,
    startPolling,
    stopPolling,
    setResult,
    reset,
  }
})
