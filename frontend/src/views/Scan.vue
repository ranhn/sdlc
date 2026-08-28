<template>
  <div class="scan">
    <div class="page-header">
      <span class="page-title">漏洞扫描 / {{ pageTitle }}</span>
      <el-button v-if="isSecops && tab === 'components'" type="primary" plain @click="compVisible = true">新增组件</el-button>
      <el-button v-if="isSecops && tab === 'cves'" type="primary" plain @click="cveVisible = true">新增 CVE</el-button>
      <el-button v-if="isSecops && tab === 'components'" type="primary" @click="scanVisible = true">
        <el-icon><Aim /></el-icon>&nbsp;触发扫描
      </el-button>
    </div>

    <!-- 组件清单 -->
    <div v-if="tab === 'components'">
      <div class="tab-head">
        <el-select v-model="sysFilter" clearable filterable placeholder="按系统筛选" style="width: 180px" @change="loadComponents">
          <el-option v-for="s in systems" :key="s.id" :label="s.name" :value="s.id" />
        </el-select>
      </div>
      <el-table :data="components" v-loading="loadingComp" stripe>
        <el-table-column prop="name" label="组件名称" min-width="160" />
        <el-table-column prop="version" label="版本" width="120" />
        <el-table-column prop="vendor" label="厂商" width="140" />
        <el-table-column prop="system_name" label="所属系统" width="140" />
        <el-table-column prop="license" label="许可证" width="120" />
        <el-table-column label="操作" width="90">
          <template #default="{ row }">
            <el-button v-if="isSecops" link type="danger" size="small" @click="removeComponent(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- CVE 情报库 -->
    <div v-if="tab === 'cves'">
      <el-table :data="cves" v-loading="loadingCve" stripe>
        <el-table-column prop="cve_id" label="CVE 编号" width="140">
          <template #default="{ row }"><el-tag size="small">{{ row.cve_id }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="component" label="组件" width="140" />
        <el-table-column prop="description" label="描述" min-width="220" show-overflow-tooltip />
        <el-table-column prop="severity" label="等级" width="90">
          <template #default="{ row }"><el-tag :type="sevType[row.severity]" effect="dark">{{ sevName[row.severity] }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="cvss" label="CVSS" width="80" />
        <el-table-column label="操作" width="90">
          <template #default="{ row }">
            <el-button v-if="isSecops" link type="danger" size="small" @click="removeCve(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 扫描任务 -->
    <div v-if="tab === 'tasks'">
      <el-table :data="tasks" v-loading="loadingTasks" stripe>
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="system_name" label="系统" width="140" />
        <el-table-column prop="engine" label="引擎" width="100" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }"><el-tag :type="taskStatusType[row.status]" size="small">{{ taskStatus[row.status] }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="found_count" label="发现数" width="90" />
        <el-table-column prop="created_at" label="扫描时间" width="160">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="120">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="viewTaskResults(row)">结果</el-button>
            <el-button v-if="isSecops && row.status === 'completed' && row.found_count > 0" link type="success" size="small" @click="linkAll(row)">全部转单</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 扫描结果 -->
    <div v-if="tab === 'results'">
      <div v-if="currentTask" class="result-head">
        任务 #{{ currentTask.id }} · {{ currentTask.system_name }}
        <el-button size="small" @click="currentTask = null">关闭</el-button>
      </div>
      <el-table :data="taskResults" v-loading="loadingResults" stripe>
        <el-table-column prop="component_name" label="组件" width="140" />
        <el-table-column prop="cve_id" label="CVE" width="120" />
        <el-table-column prop="title" label="问题" min-width="200" />
        <el-table-column label="等级" width="90">
          <template #default="{ row }"><el-tag :type="sevType[row.severity]" effect="dark">{{ sevName[row.severity] }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="is_false_positive" label="误报" width="80">
          <template #default="{ row }"><el-tag v-if="row.is_false_positive" type="info">是</el-tag><span v-else>否</span></template>
        </el-table-column>
        <el-table-column prop="linked_vuln_id" label="漏洞单" width="80">
          <template #default="{ row }">
            <el-tag v-if="row.linked_vuln_id" type="success" size="small">#{{ row.linked_vuln_id }}</el-tag>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <el-button v-if="isSecops && !row.linked_vuln_id" link type="primary" size="small" @click="linkResult(row)">转漏洞单</el-button>
            <el-button v-if="isSecops" link size="small" @click="toggleFp(row)">
              {{ row.is_false_positive ? '取消误报' : '标记误报' }}
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 新增组件 -->
    <el-dialog v-model="compVisible" title="新增组件" width="440px">
      <el-form :model="compForm" label-width="80px">
        <el-form-item label="名称"><el-input v-model="compForm.name" /></el-form-item>
        <el-form-item label="版本"><el-input v-model="compForm.version" /></el-form-item>
        <el-form-item label="厂商"><el-input v-model="compForm.vendor" /></el-form-item>
        <el-form-item label="许可证"><el-input v-model="compForm.license" /></el-form-item>
        <el-form-item label="系统">
          <el-select v-model="compForm.system_id" filterable style="width: 100%">
            <el-option v-for="s in systems" :key="s.id" :label="s.name" :value="s.id" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer><el-button @click="compVisible = false">取消</el-button><el-button type="primary" @click="submitComponent">保存</el-button></template>
    </el-dialog>

    <!-- 新增CVE -->
    <el-dialog v-model="cveVisible" title="新增 CVE" width="520px">
      <el-form :model="cveForm" label-width="80px">
        <el-form-item label="编号"><el-input v-model="cveForm.cve_id" placeholder="CVE-2024-XXXX" /></el-form-item>
        <el-form-item label="组件"><el-input v-model="cveForm.component" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="cveForm.description" type="textarea" :rows="3" /></el-form-item>
        <el-form-item label="等级">
          <el-select v-model="cveForm.severity" style="width: 140px">
            <el-option label="严重" value="critical" /><el-option label="高危" value="high" />
            <el-option label="中危" value="medium" /><el-option label="低危" value="low" />
          </el-select>
        </el-form-item>
        <el-form-item label="CVSS"><el-input v-model="cveForm.cvss" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="cveVisible = false">取消</el-button><el-button type="primary" @click="submitCve">保存</el-button></template>
    </el-dialog>

    <!-- 触发扫描 -->
    <el-dialog v-model="scanVisible" title="触发扫描" width="440px">
      <el-form label-width="80px">
        <el-form-item label="目标系统">
          <el-select v-model="scanSystemId" filterable style="width: 100%">
            <el-option v-for="s in systems" :key="s.id" :label="s.name" :value="s.id" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer><el-button @click="scanVisible = false">取消</el-button><el-button type="primary" :loading="scanning" @click="submitScan">开始扫描</el-button></template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, watch, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { scanApi, systemApi } from '../api'
import { useUserStore } from '../store/user'

const route = useRoute()
const router = useRouter()
const store = useUserStore()
const isSecops = computed(() => ['admin', 'secops'].includes(store.role))
const tab = computed(() => {
  const p = route.path
  if (p.includes('/cves')) return 'cves'
  if (p.includes('/tasks')) return 'tasks'
  if (p.includes('/results')) return 'results'
  return 'components'
})
const pageTitle = computed(() => {
  const titles = { components: '组件清单', cves: 'CVE 情报库', tasks: '扫描任务', results: '扫描结果' }
  return titles[tab.value] || '组件清单'
})
const systems = ref([])

const components = ref([])
const cves = ref([])
const tasks = ref([])
const taskResults = ref([])
const currentTask = ref(null)
const sysFilter = ref(null)
const loadingComp = ref(false)
const loadingCve = ref(false)
const loadingTasks = ref(false)
const loadingResults = ref(false)

const sevName = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
const sevType = { critical: 'danger', high: 'warning', medium: '', low: 'info' }
const taskStatus = { pending: '待执行', running: '运行中', completed: '已完成', failed: '失败' }
const taskStatusType = { pending: 'info', running: 'warning', completed: 'success', failed: 'danger' }

const compVisible = ref(false)
const compForm = reactive({ name: '', version: '', vendor: '', license: '', system_id: null })
const cveVisible = ref(false)
const cveForm = reactive({ cve_id: '', component: '', description: '', severity: 'high', cvss: '' })
const scanVisible = ref(false)
const scanSystemId = ref(null)
const scanning = ref(false)

function fmt(d) { return d ? d.replace('T', ' ').slice(0, 16) : '' }

async function loadComponents() {
  loadingComp.value = true
  try { components.value = (await scanApi.components({ system_id: sysFilter.value || undefined })).data } finally { loadingComp.value = false }
}
async function loadCves() { loadingCve.value = true; try { cves.value = (await scanApi.cves()).data } finally { loadingCve.value = false } }
async function loadTasks() { loadingTasks.value = true; try { tasks.value = (await scanApi.tasks()).data } finally { loadingTasks.value = false } }

async function submitComponent() {
  try { await scanApi.addComponent(compForm); ElMessage.success('已添加'); compVisible.value = false; loadComponents() }
  catch (e) { ElMessage.error(e.response?.data?.detail || '添加失败') }
}
async function removeComponent(row) {
  await ElMessageBox.confirm(`删除组件 ${row.name}？`, '提示', { type: 'warning' })
  await scanApi.removeComponent(row.id); loadComponents()
}
async function submitCve() {
  try { await scanApi.addCve(cveForm); ElMessage.success('已添加'); cveVisible.value = false; loadCves() }
  catch (e) { ElMessage.error(e.response?.data?.detail || '添加失败') }
}
async function removeCve(row) {
  await ElMessageBox.confirm(`删除 ${row.cve_id}？`, '提示', { type: 'warning' })
  await scanApi.removeCve(row.id); loadCves()
}
async function submitScan() {
  if (!scanSystemId.value) return ElMessage.warning('请选择系统')
  scanning.value = true
  try { await scanApi.runScan(scanSystemId.value); ElMessage.success('扫描已触发'); scanVisible.value = false; setTimeout(loadTasks, 1000) }
  catch (e) { ElMessage.error(e.response?.data?.detail || '触发失败') } finally { scanning.value = false }
}
async function viewTaskResults(row) {
  currentTask.value = row
  router.push('/scan/results')
  loadingResults.value = true
  try { taskResults.value = (await scanApi.taskResults(row.id)).data } finally { loadingResults.value = false }
}
async function linkResult(row) {
  await scanApi.link(row.id); ElMessage.success('已转漏洞单'); viewTaskResults(currentTask.value)
}
async function toggleFp(row) {
  await scanApi.falsePositive(row.id); viewTaskResults(currentTask.value)
}
async function linkAll(row) {
  const res = await scanApi.linkAll(row.id); ElMessage.success(`已转 ${res.data.linked} 条`); viewTaskResults(row)
}

// 按当前子页面加载对应数据
function loadByTab() {
  if (tab.value === 'components') loadComponents()
  if (tab.value === 'cves') loadCves()
  if (tab.value === 'tasks') loadTasks()
}

onMounted(() => {
  systemApi.list().then((r) => (systems.value = r.data)).catch(() => {})
  loadByTab()
})

// 路由切换时重新加载对应数据
watch(tab, loadByTab)
</script>

<style scoped>
.tab-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
.result-head { margin-bottom: 12px; font-weight: 600; color: #0f172a; }
</style>
