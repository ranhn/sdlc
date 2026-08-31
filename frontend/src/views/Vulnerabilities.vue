<template>
  <div class="vulns">
    <div class="page-header">
      <span class="page-title">提交漏洞</span>
      <div class="header-actions">
        <el-dropdown v-if="canExport" @command="doExport" trigger="click">
          <el-button>
            <el-icon><Download /></el-icon>&nbsp;批量导出
            <el-icon class="el-icon--right"><ArrowDown /></el-icon>
          </el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="csv">导出为 CSV</el-dropdown-item>
              <el-dropdown-item command="docx">导出为 Word（.docx）</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        <el-button type="primary" @click="openCreate">
          <el-icon><Plus /></el-icon>&nbsp;提交漏洞
        </el-button>
      </div>
    </div>

    <!-- 筛选 -->
    <el-card shadow="never" class="filter-card">
      <el-form inline>
        <el-form-item label="状态">
          <el-select v-model="filters.status" clearable placeholder="全部状态" style="width: 140px" @change="load">
            <el-option label="待确认" value="pending" />
            <el-option label="已确认" value="confirmed" />
            <el-option label="修复中" value="fixing" />
            <el-option label="待复测" value="retest" />
            <el-option label="已修复" value="fixed" />
            <el-option label="已关闭" value="closed" />
            <el-option label="已忽略" value="ignored" />
          </el-select>
        </el-form-item>
        <el-form-item label="等级">
          <el-select v-model="filters.severity" clearable placeholder="全部等级" style="width: 120px" @change="load">
            <el-option label="严重" value="critical" /><el-option label="高危" value="high" />
            <el-option label="中危" value="medium" /><el-option label="低危" value="low" />
          </el-select>
        </el-form-item>
        <el-form-item label="系统">
          <el-select v-model="filters.system_id" clearable filterable placeholder="全部系统" style="width: 160px" @change="load">
            <el-option v-for="s in systems" :key="s.id" :label="s.name" :value="s.id" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-checkbox v-model="filters.mine" @change="load">只看我的</el-checkbox>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- 列表 -->
    <el-table :data="list" v-loading="loading" stripe class="vuln-table" :show-overflow-tooltip="true">
      <el-table-column type="index" :index="(idx) => list.length - idx" width="48" align="center" />
      <el-table-column label="标题" min-width="260" show-overflow-tooltip>
        <template #default="{ row }">
          <el-link type="primary" :underline="false" @click="openDetail(row)">{{ row.title }}</el-link>
        </template>
      </el-table-column>
      <el-table-column prop="system_name" label="所属系统" min-width="100" align="center" />
      <el-table-column label="等级" width="70" align="center">
        <template #default="{ row }">
          <el-tag :type="severityType[row.severity]" effect="dark" size="small">{{ severityName[row.severity] }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="vuln_type" label="类型" min-width="90" align="center" />
      <el-table-column label="状态" width="80" align="center">
        <template #default="{ row }">
          <el-tag :type="statusType[row.status]" size="small">{{ statusNames[row.status] }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="assignee_name" label="负责人" min-width="110" align="center" show-overflow-tooltip>
        <template #default="{ row }">{{ row.assignee_name || '—' }}</template>
      </el-table-column>
      <el-table-column prop="created_at" label="提交时间" width="150" align="center">
        <template #default="{ row }">{{ fmt(row.created_at) }}</template>
      </el-table-column>
      <el-table-column label="操作" width="70" align="center" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" size="small" @click="openDetail(row)">详情</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 新建漏洞弹窗 -->
    <el-dialog v-model="createVisible" title="提交漏洞" width="640px" :close-on-click-modal="false">
      <el-form ref="createRef" :model="createForm" :rules="createRules" label-width="90px" @paste="onPaste">
        <el-form-item label="漏洞标题" prop="title">
          <el-input v-model="createForm.title" placeholder="请输入漏洞标题" />
        </el-form-item>
        <el-form-item label="所属系统" prop="system_id">
          <el-select v-model="createForm.system_id" clearable filterable placeholder="选择系统">
            <el-option v-for="s in systems" :key="s.id" :label="s.name" :value="s.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="修复负责人">
          <el-select v-model="createForm.assignee_id" clearable filterable placeholder="可留空，由安全专家指派" style="width: 100%">
            <el-option v-for="u in users" :key="u.id" :value="u.id">
              <span style="display: inline-block; width: 160px">{{ u.username }}</span>
              <span>{{ u.full_name || '—' }}</span>
            </el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="等级" prop="severity">
          <el-radio-group v-model="createForm.severity">
            <el-radio-button value="critical">严重</el-radio-button>
            <el-radio-button value="high">高危</el-radio-button>
            <el-radio-button value="medium">中危</el-radio-button>
            <el-radio-button value="low">低危</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="漏洞类型" prop="vuln_type">
          <el-select v-model="createForm.vuln_type" placeholder="请选择漏洞类型" style="width: 100%" filterable allow-create>
            <el-option v-for="t in vulnTypes" :key="t" :label="t" :value="t" />
          </el-select>
        </el-form-item>
        <el-form-item label="漏洞描述">
          <el-input v-model="createForm.description" type="textarea" :rows="3" placeholder="描述漏洞位置与现象" />
        </el-form-item>
        <el-form-item label="复现步骤" prop="reproduce_steps">
          <div class="steps-list">
            <div v-for="(s, idx) in createForm.steps" :key="s.id" class="step-row" :data-step-idx="idx">
              <div class="step-no">{{ idx + 1 }}</div>
              <el-input v-model="s.desc" type="textarea" :rows="2" placeholder="这一步做了什么、观察到什么" class="step-desc" />
              <div class="step-shot">
                <el-image v-if="s.img" :src="s.img" :preview-src-list="stepImgList" :initial-index="stepImgList.indexOf(s.img)" fit="cover" class="step-thumb" hide-on-click-modal />
                <el-upload v-if="!s.img" :auto-upload="false" :limit="1" list-type="picture-card" accept="image/*"
                  :show-file-list="false" :on-change="(file) => onStepFile(idx, file)">
                  <el-icon><Plus /></el-icon>
                </el-upload>
                <el-button v-if="s.img" link type="danger" size="small" class="step-shot-del" @click="removeStepImg(idx)">移除</el-button>
              </div>
              <el-button v-if="createForm.steps.length > 1" link type="danger" size="small" @click="removeStep(idx)">删步</el-button>
            </div>
          </div>
          <el-button link type="primary" size="small" @click="addStep" :disabled="createForm.steps.length >= 6">+ 添加步骤</el-button>
          <div class="tip">每步可粘贴或选择截图，步骤 1-6 步</div>
        </el-form-item>
        <el-form-item label="影响范围">
          <el-input v-model="createForm.impact" type="textarea" :rows="2" placeholder="可能造成的影响" />
        </el-form-item>
      </el-form>
      <el-image-viewer v-if="previewVisible" :url-list="previewList" :initial-index="previewIndex" @close="previewVisible = false" />
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="submitCreate">提交</el-button>
      </template>
    </el-dialog>

    <!-- 详情抽屉 -->
    <el-drawer v-model="detailVisible" size="620px" :title="`漏洞 #${current?.id} · ${current?.title}`">
      <template v-if="current">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="等级">
            <el-tag :type="severityType[current.severity]" effect="dark">{{ severityName[current.severity] }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="statusType[current.status]">{{ statusNames[current.status] }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="所属系统">{{ current.system_name || '—' }}</el-descriptions-item>
          <el-descriptions-item label="类型">{{ current.vuln_type || '—' }}</el-descriptions-item>
          <el-descriptions-item label="提交人">{{ current.reporter_name }}</el-descriptions-item>
          <el-descriptions-item label="负责人">{{ current.assignee_name || '未指派' }}</el-descriptions-item>
          <el-descriptions-item label="提交时间">{{ fmt(current.created_at) }}</el-descriptions-item>
        </el-descriptions>

        <div class="sec-title">漏洞描述</div>
        <el-text>{{ current.description || '无' }}</el-text>

        <div class="sec-title">复现步骤</div>
        <div v-if="renderSteps(current).length" class="detail-steps">
          <div v-for="(s, i) in renderSteps(current)" :key="i" class="detail-step">
            <div class="detail-step-no">{{ s.step_no }}</div>
            <div class="detail-step-body">
              <div class="detail-step-desc">{{ s.desc }}</div>
              <el-image v-if="s.img" :src="s.img" :preview-src-list="detailImgs" :initial-index="detailImgs.indexOf(s.img)" fit="cover" class="shot" hide-on-click-modal />
            </div>
          </div>
        </div>
        <el-text v-else><pre class="pre">{{ current.reproduce_steps || '无' }}</pre></el-text>

        <div class="sec-title">影响范围</div>
        <el-text>{{ current.impact || '无' }}</el-text>

        <div v-if="!renderSteps(current).length && current.screenshots && current.screenshots.length" class="sec-title">截图证据</div>
        <el-image v-if="!renderSteps(current).length" v-for="(img, i) in current.screenshots" :key="i" :src="img" :preview-src-list="current.screenshots"
          fit="cover" class="shot" />

        <!-- 操作区 -->
        <div class="sec-title">状态操作</div>
        <div class="actions">
          <el-button v-if="can('confirm')" type="success" size="small" @click="doAction('confirm')">确认</el-button>
          <el-button v-if="can('start_fix')" type="warning" size="small" @click="doAction('start_fix')">开始修复</el-button>
          <el-button v-if="can('finish_fix')" type="warning" size="small" @click="doAction('finish_fix')">修复完成</el-button>
          <el-button v-if="can('pass_retest')" type="success" size="small" @click="doAction('pass_retest')">复测通过</el-button>
          <el-button v-if="can('close')" type="primary" size="small" @click="doAction('close')">关闭</el-button>
          <el-button v-if="can('assign')" type="info" size="small" @click="openAssign">指派</el-button>
          <el-button v-if="can('reject')" type="danger" size="small" plain @click="openReject">驳回</el-button>
        </div>

        <!-- 流程图 -->
        <div class="sec-title">状态流转</div>
        <el-steps :active="flowActive" simple class="flow-steps">
          <el-step title="提交" /><el-step title="确认" /><el-step title="修复" /><el-step title="复测" /><el-step title="关闭" />
        </el-steps>

        <!-- 评论 -->
        <div class="sec-title">评论</div>
        <div v-for="c in comments" :key="c.id" class="comment">
          <b>{{ c.username }}</b> · {{ fmt(c.created_at) }}
          <div>{{ c.content }}</div>
        </div>
        <div class="comment-input">
          <el-input v-model="newComment" placeholder="添加评论" @keyup.enter="addComment" />
          <el-button type="primary" @click="addComment">发送</el-button>
        </div>
      </template>
    </el-drawer>

    <!-- 指派弹窗 -->
    <el-dialog v-model="assignVisible" title="指派负责人" width="400px">
      <el-select v-model="assignTo" placeholder="选择负责人" style="width: 100%" filterable>
        <el-option v-for="u in users" :key="u.id" :value="u.id">
          <span style="display: inline-block; width: 160px">{{ u.username }}</span>
          <span>{{ u.full_name || '—' }}</span>
        </el-option>
      </el-select>
      <template #footer>
        <el-button @click="assignVisible = false">取消</el-button>
        <el-button type="primary" @click="submitAssign">确定</el-button>
      </template>
    </el-dialog>

    <!-- 驳回弹窗 -->
    <el-dialog v-model="rejectVisible" title="驳回漏洞" width="400px">
      <el-input v-model="rejectReason" type="textarea" :rows="3" placeholder="请输入驳回原因" />
      <template #footer>
        <el-button @click="rejectVisible = false">取消</el-button>
        <el-button type="danger" @click="submitReject">确定驳回</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElImageViewer } from 'element-plus'
import { vulnApi, systemApi, adminApi } from '../api'
import { useUserStore } from '../store/user'

const store = useUserStore()
const route = useRoute()
const canExport = computed(() => store.role === 'admin' || store.role === 'secops')
const list = ref([])
const systems = ref([])
const users = ref([])
const loading = ref(false)
const filters = reactive({ status: '', severity: '', system_id: null, mine: false })

const statusNames = {
  draft: '草稿', pending: '待确认', confirmed: '已确认', fixing: '修复中', retest: '待复测',
  fixed: '已修复', closed: '已关闭', rejected: '已驳回', ignored: '已忽略',
}
const statusType = { draft: 'info', pending: 'warning', confirmed: 'primary', fixing: 'warning', retest: 'warning', fixed: 'success', closed: 'success', rejected: 'danger', ignored: 'info' }
const severityName = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
const severityType = { critical: 'danger', high: 'warning', medium: '', low: 'info' }
const vulnTypes = ['SQL注入', 'XSS', '越权', '信息泄露', '弱口令', '扫号', '组件漏洞', '命令执行', '文件上传', '反序列化', 'SSRF', 'CSRF', '逻辑漏洞', '其他']
const actionRoles = {
  confirm: ['admin', 'secops'], reject: ['admin', 'secops'], ignore: ['admin', 'secops'],
  start_fix: ['admin', 'secops', 'dev'], finish_fix: ['admin', 'secops', 'dev', 'tester'],
  pass_retest: ['admin', 'secops', 'tester'], close: ['admin', 'secops'],
  assign: ['admin', 'secops'],
}
// 各动作允许的前置状态（与后端 state_machine.ACTION_RULES 保持一致）
const actionFrom = {
  confirm: ['pending'],
  reject: ['pending'],
  ignore: ['pending', 'confirmed'],
  start_fix: ['confirmed'],
  finish_fix: ['fixing'],
  pass_retest: ['retest'],
  close: ['fixed'],
  assign: ['pending', 'confirmed', 'fixing', 'retest', 'fixed'],
}
const flowMap = { pending: 1, confirmed: 2, fixing: 3, retest: 4, fixed: 5, closed: 6 }

function can(action) {
  if (!current.value) return false
  if (!actionRoles[action]?.includes(store.role)) return false
  if (actionFrom[action] && !actionFrom[action].includes(current.value.status)) return false
  return true
}

// 新建
const createVisible = ref(false)
const submitting = ref(false)
const createRef = ref()
const createForm = reactive({
  title: '', system_id: null, severity: 'medium', vuln_type: '',
  description: '', impact: '', assignee_id: null,
  steps: [{ id: 's1', desc: '', img: null }],
})
const createRules = {
  title: [{ required: true, message: '请输入标题', trigger: 'blur' }],
  system_id: [{ required: true, message: '请选择所属系统', trigger: 'change' }],
  severity: [{ required: true, message: '请选择等级', trigger: 'change' }],
  vuln_type: [{ required: true, message: '请输入漏洞类型', trigger: 'blur' }],
}
let _stepSeq = 1
function newStep() { return { id: 's' + (++_stepSeq), desc: '', img: null } }
function addStep() {
  if (createForm.steps.length >= 6) return ElMessage.warning('最多 6 步')
  createForm.steps.push(newStep())
}
function removeStep(idx) {
  if (createForm.steps.length <= 1) return
  createForm.steps.splice(idx, 1)
}
function removeStepImg(idx) {
  if (createForm.steps[idx]) createForm.steps[idx].img = null
}
function onStepFile(idx, file) {
  const reader = new FileReader()
  reader.onload = (e) => {
    if (createForm.steps[idx]) createForm.steps[idx].img = e.target.result
  }
  reader.readAsDataURL(file.raw)
}
const stepImgList = computed(() => createForm.steps.map((s) => s.img).filter(Boolean))
function openCreate() {
  Object.assign(createForm, {
    title: '', system_id: null, severity: 'medium', vuln_type: '',
    description: '', impact: '', assignee_id: null,
  })
  createForm.steps = [newStep()]
  createVisible.value = true
}
function onPaste(e) {
  if (!createVisible.value) return
  const items = e.clipboardData?.items
  if (!items || items.length === 0) return
  const target = e.target
  const row = target?.closest?.('[data-step-idx]')
  const idx = row ? Number(row.dataset.stepIdx) : createForm.steps.length - 1
  const step = createForm.steps[idx]
  if (!step) return
  if (step.img) return ElMessage.warning(`第 ${idx + 1} 步已有截图，请先移除`)
  for (const it of items) {
    if (it.kind === 'file' && it.type.startsWith('image/')) {
      const blob = it.getAsFile()
      if (!blob) continue
      const reader = new FileReader()
      reader.onload = (ev) => {
        if (createForm.steps[idx]) createForm.steps[idx].img = ev.target.result
      }
      reader.readAsDataURL(blob)
      e.preventDefault()
      break
    }
  }
}
async function submitCreate() {
  await createRef.value.validate()
  const validSteps = createForm.steps.filter((s) => (s.desc || '').trim() || s.img)
  if (validSteps.length === 0) return ElMessage.warning('请至少填写一步复现步骤')
  submitting.value = true
  const reproduce_steps = validSteps.map((s, i) => (s.desc || '').trim() || `步骤 ${i + 1}`).join('\n')
  const step_screenshots = validSteps
    .map((s, i) => s.img ? { step_no: i + 1, data_url: s.img } : null)
    .filter(Boolean)
  const screenshots = step_screenshots.map((s) => s.data_url)
  try {
    await vulnApi.create({
      title: createForm.title,
      system_id: createForm.system_id,
      severity: createForm.severity,
      vuln_type: createForm.vuln_type,
      description: createForm.description,
      impact: createForm.impact,
      assignee_id: createForm.assignee_id,
      reproduce_steps,
      screenshots,
      step_screenshots,
    })
    ElMessage.success('漏洞提交成功')
    createVisible.value = false
    load()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '提交失败')
  } finally { submitting.value = false }
}

// 详情
const detailVisible = ref(false)
const current = ref(null)
const comments = ref([])
const newComment = ref('')
const assignVisible = ref(false)
const assignTo = ref(null)
const rejectVisible = ref(false)
const rejectReason = ref('')
const flowActive = computed(() => (current.value ? flowMap[current.value.status] || 0 : 0))
function renderSteps(v) {
  if (!v || !v.step_screenshots || !v.step_screenshots.length) return []
  const lines = (v.reproduce_steps || '').split('\n')
  return v.step_screenshots.map((ss) => ({
    step_no: ss.step_no,
    desc: lines[ss.step_no - 1] || `步骤 ${ss.step_no}`,
    img: ss.data_url,
  }))
}
const detailImgs = computed(() => renderSteps(current.value).map((s) => s.img).filter(Boolean))

async function openDetail(row) {
  const res = await vulnApi.detail(row.id)
  current.value = res.data
  detailVisible.value = true
  loadComments(row.id)
}
async function loadComments(id) {
  const res = await vulnApi.comments(id)
  comments.value = res.data
}
async function addComment() {
  if (!newComment.value.trim()) return
  await vulnApi.addComment(current.value.id, { comment: newComment.value })
  newComment.value = ''
  loadComments(current.value.id)
}
function extractErrorMsg(e, fallback = '操作失败') {
  const data = e?.response?.data
  if (typeof data?.detail === 'string') return data.detail
  if (Array.isArray(data?.detail)) return data.detail.map(d => d.msg || JSON.stringify(d)).join('; ')
  if (typeof data === 'string') return data
  return fallback
}
async function doAction(action) {
  try {
    await vulnApi.action(current.value.id, action, { comment: '' })
    ElMessage.success('操作成功')
    openDetail(current.value)
    load()
  } catch (e) {
    ElMessage.error(extractErrorMsg(e))
  }
}
function openReject() { rejectVisible.value = true }
async function submitReject() {
  if (!rejectReason.value.trim()) return ElMessage.warning('请输入驳回原因')
  await vulnApi.reject(current.value.id, { reason: rejectReason.value })
  ElMessage.success('已驳回')
  rejectVisible.value = false
  openDetail(current.value)
  load()
}
async function submitAssign() {
  if (assignTo.value == null) return ElMessage.warning('请选择负责人')
  await vulnApi.assign(current.value.id, { assignee_id: assignTo.value })
  ElMessage.success('指派成功')
  assignVisible.value = false
  openDetail(current.value)
}
function openAssign() {
  assignTo.value = current.value?.assignee_id ?? null
  assignVisible.value = true
}

function fmt(d) { return d ? d.replace('T', ' ').slice(0, 16) : '' }

async function doExport(fmt) {
  if (!canExport.value) return ElMessage.warning('仅管理员/安全专家可导出')
  const params = {}
  if (filters.status) params.status = filters.status
  if (filters.severity) params.severity = filters.severity
  if (filters.system_id) params.system_id = filters.system_id
  if (filters.mine) params.mine = true
  try {
    const res = await vulnApi.export(fmt, params)
    const ext = fmt === 'csv' ? 'csv' : 'docx'
    const blob = new Blob([res.data], { type: res.data.type || (fmt === 'csv' ? 'text/csv' : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const ts = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14)
    a.download = `vulns_${ts}.${ext}`
    document.body.appendChild(a); a.click(); document.body.removeChild(a)
    URL.revokeObjectURL(url)
    ElMessage.success(`已导出 ${fmt === 'csv' ? 'CSV' : 'Word'} 文件`)
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '导出失败')
  }
}

async function load() {
  loading.value = true
  try {
    const params = {}
    if (filters.status) params.status = filters.status
    if (filters.severity) params.severity = filters.severity
    if (filters.system_id) params.system_id = filters.system_id
    if (filters.mine) params.mine = true
    const res = await vulnApi.list(params)
    list.value = res.data
  } finally { loading.value = false }
}

onMounted(async () => {
  load()
  try { systems.value = (await systemApi.list()).data } catch {}
  try { users.value = (await adminApi.users()).data } catch {}
  // 兼容审计日志等外部跳转：?id=123 直接打开该漏洞详情
  const qid = Number(route.query.id)
  if (qid && Number.isFinite(qid)) {
    try {
      const res = await vulnApi.detail(qid)
      current.value = res.data
      detailVisible.value = true
      loadComments(qid)
    } catch (e) {
      // 静默失败：可能权限不足或漏洞已删
    }
  }
})
</script>

<style scoped>
.vulns { height: 100%; display: flex; flex-direction: column; }
.vulns .page-header { flex-shrink: 0; }
.header-actions { display: flex; gap: 8px; align-items: center; }
.filter-card { margin-bottom: 12px; flex-shrink: 0; }
.filter-card :deep(.el-card__body) { padding: 12px; }
.vuln-table { background: #fff; border-radius: 10px; }
.vuln-table :deep(.el-table__cell) { padding: 6px 0 !important; }
.vuln-table :deep(.el-table .cell) { padding-left: 8px; padding-right: 8px; word-break: keep-all; white-space: nowrap; }
.tip { font-size: 12px; color: #94a3b8; margin-top: 6px; }
.sec-title { font-weight: 600; margin: 16px 0 8px; color: #0f172a; }
.pre { white-space: pre-wrap; font-family: inherit; margin: 0; }
.shot { width: 90px; height: 90px; margin: 4px; border-radius: 6px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; }
.steps-list { display: flex; flex-direction: column; gap: 10px; width: 100%; }
.step-row { display: flex; align-items: flex-start; gap: 10px; padding: 10px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; }
.step-no { width: 26px; height: 26px; line-height: 26px; text-align: center; background: #3b82f6; color: #fff; border-radius: 50%; flex-shrink: 0; font-size: 13px; }
.step-desc { flex: 1; }
.step-shot { width: 92px; height: 92px; flex-shrink: 0; position: relative; }
.step-thumb { width: 90px; height: 90px; border-radius: 6px; border: 1px solid #e2e8f0; }
.step-shot-del { position: absolute; bottom: -6px; right: -6px; background: #fff; border-radius: 10px; padding: 0 6px; }
.step-row :deep(.el-upload--picture-card) { width: 90px; height: 90px; }
.step-row :deep(.el-upload--picture-card .el-upload) { width: 90px; height: 90px; }
.detail-steps { display: flex; flex-direction: column; gap: 10px; }
.detail-step { display: flex; gap: 10px; padding: 10px; background: #f8fafc; border-radius: 8px; }
.detail-step-no { width: 28px; height: 28px; line-height: 28px; text-align: center; background: #3b82f6; color: #fff; border-radius: 50%; flex-shrink: 0; }
.detail-step-body { flex: 1; }
.detail-step-desc { white-space: pre-wrap; margin-bottom: 6px; color: #0f172a; }
.comment { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 8px 12px; margin-bottom: 8px; font-size: 13px; }
.comment-input { display: flex; gap: 8px; }
</style>
