<template>
  <div class="baseline">
    <div class="page-header">
      <span class="page-title">安全基线</span>
      <div class="header-right">
        <el-select v-model="systemId" filterable placeholder="选择系统" style="width: 200px" @change="loadItems">
          <el-option v-for="s in systems" :key="s.id" :label="s.name" :value="s.id" />
        </el-select>
        <el-button v-if="canEdit" type="primary" plain @click="itemVisible = true">新增检查项</el-button>
      </div>
    </div>

    <!-- 合规率总览 -->
    <el-row :gutter="16" class="stat-row">
      <el-col :span="6">
        <el-card shadow="never" class="stat"><div class="num">{{ stats.overall ?? 0 }}%</div><div class="lbl">整体合规率</div></el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never" class="stat"><div class="num">{{ stats.item_count ?? 0 }}</div><div class="lbl">检查项总数</div></el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="never" class="stat">
          <div class="sys-comp">
            <div v-for="s in stats.systems || []" :key="s.system_id" class="sys-row">
              <span class="sys-name">{{ s.system_name }}</span>
              <el-progress :percentage="s.compliance || 0" :stroke-width="10" />
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 五个基线横排切换 -->
    <div class="baseline-tabs">
      <div
        v-for="(name, key) in typeNameMap"
        :key="key"
        class="baseline-tab"
        :class="{ active: baselineType === key }"
        @click="switchType(key)"
      >
        {{ name }}
      </div>
    </div>

    <!-- 基线条目评估 -->
    <el-card shadow="never">
      <template #header><span class="card-title">{{ currentSystem ? currentSystem.name : '' }} 基线条目评估</span></template>
      <el-table :data="items" v-loading="loadingItems" stripe>
        <el-table-column prop="category_name" label="分类" width="120" />
        <el-table-column prop="item_name" label="检查项" min-width="200" />
        <el-table-column prop="item_description" label="要求" min-width="180" show-overflow-tooltip />
        <el-table-column label="等级" width="80">
          <template #default="{ row }"><el-tag :type="sevType[row.severity]" size="small">{{ sevName[row.severity] }}</el-tag></template>
        </el-table-column>
        <el-table-column label="检查方式" width="100">
          <template #default="{ row }">{{ row.check_method === 'automated' ? '自动' : '人工' }}</template>
        </el-table-column>
        <el-table-column label="评估结果" width="150">
          <template #default="{ row }">
            <el-select v-if="canEdit" v-model="row.status" size="small" :disabled="row.status === 'pending' && !isSecopsEdit" @change="(v) => saveItem(row, v)">
              <el-option label="通过" value="pass" /><el-option label="不通过" value="fail" /><el-option label="不适用" value="na" />
            </el-select>
            <el-tag v-else :type="resultType[row.status]" size="small">{{ resultName[row.status] }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="证据/备注" min-width="160">
          <template #default="{ row }">
            <el-input v-if="canEdit" v-model="row.evidence" size="small" placeholder="证据" @blur="saveItem(row, row.status)" />
            <span v-else>{{ row.evidence || '—' }}</span>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 新增检查项 -->
    <el-dialog v-model="itemVisible" title="新增检查项" width="480px" @open="onItemDialogOpen">
      <el-form :model="itemForm" label-width="90px">
        <el-form-item label="基线类型">
          <el-select v-model="itemForm.baseline_type" style="width: 100%" @change="loadDialogCategories">
            <el-option v-for="(name, key) in typeNameMap" :key="key" :label="name" :value="key" />
          </el-select>
        </el-form-item>
        <el-form-item label="分类">
          <el-select v-model="itemForm.category_id" style="width: 100%">
            <el-option v-for="c in dialogCategories" :key="c.id" :label="c.name" :value="c.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="检查项"><el-input v-model="itemForm.name" /></el-form-item>
        <el-form-item label="要求"><el-input v-model="itemForm.description" type="textarea" :rows="2" /></el-form-item>
        <el-form-item label="等级">
          <el-select v-model="itemForm.severity" style="width: 140px">
            <el-option label="严重" value="critical" /><el-option label="高危" value="high" /><el-option label="中危" value="medium" /><el-option label="低危" value="low" />
          </el-select>
        </el-form-item>
        <el-form-item label="检查方式">
          <el-radio-group v-model="itemForm.check_method">
            <el-radio-button value="manual">人工</el-radio-button>
            <el-radio-button value="automated">自动</el-radio-button>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer><el-button @click="itemVisible = false">取消</el-button><el-button type="primary" @click="saveItemMaster">保存</el-button></template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { baselineApi, systemApi } from '../api'
import { useUserStore } from '../store/user'

const store = useUserStore()
const canEdit = computed(() => ['admin', 'secops'].includes(store.role))
const isSecopsEdit = computed(() => ['admin', 'secops'].includes(store.role))
const systems = ref([])
const currentSystem = ref(null)
const systemId = ref(null)
const items = ref([])
const categories = ref([])
const stats = reactive({ overall: 0, item_count: 0, systems: [] })
const loadingItems = ref(false)
const itemVisible = ref(false)
const dialogCategories = ref([])
const itemForm = reactive({ baseline_type: 'security_requirement', category_id: null, name: '', description: '', severity: 'medium', check_method: 'manual' })

async function loadDialogCategories() {
  try {
    dialogCategories.value = (await baselineApi.categories(itemForm.baseline_type)).data
  } catch { dialogCategories.value = [] }
}
function onItemDialogOpen() {
  itemForm.baseline_type = baselineType.value
  itemForm.category_id = null
  itemForm.name = ''
  itemForm.description = ''
  itemForm.severity = 'medium'
  itemForm.check_method = 'manual'
  loadDialogCategories()
}

const baselineType = ref('security_requirement')
const typeNameMap = {
  security_requirement: '安全需求基线',
  app_dev: 'APP开发安全基线',
  frontend_dev: '前端开发安全基线',
  backend_dev: '后端开发安全基线',
  firmware_dev: '固件开发安全基线',
}
function switchType(key) {
  if (baselineType.value === key) return
  baselineType.value = key
  loadCategories()
  loadStats()
  if (systemId.value) loadItems()
}

const sevName = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
const sevType = { critical: 'danger', high: 'warning', medium: '', low: 'info' }
const resultName = { pending: '未检查', pass: '通过', fail: '不通过', na: '不适用' }
const resultType = { pending: 'info', pass: 'success', fail: 'danger', na: 'warning' }

async function loadStats() { try { Object.assign(stats, (await baselineApi.stats(baselineType.value)).data) } catch {} }
async function loadItems() {
  if (!systemId.value) { items.value = []; return }
  loadingItems.value = true
  try {
    items.value = (await baselineApi.systemItems(systemId.value, baselineType.value)).data
    currentSystem.value = systems.value.find((s) => s.id === systemId.value) || null
  } finally { loadingItems.value = false }
}
async function saveItem(row, status) {
  if (!status || status === 'pending') return
  try {
    await baselineApi.updateItem(systemId.value, row.item_id, { status, evidence: row.evidence })
    ElMessage.success('已保存')
    loadStats()
  } catch (e) { ElMessage.error(e.response?.data?.detail || '保存失败') }
}
async function saveItemMaster() {
  try {
    await baselineApi.createItem({ ...itemForm })
    ElMessage.success('已添加')
    itemVisible.value = false
    loadStats()
  }
  catch (e) { ElMessage.error(e.response?.data?.detail || '保存失败') }
}

async function loadCategories() {
  try { categories.value = (await baselineApi.categories(baselineType.value)).data } catch {}
}

onMounted(async () => {
  systems.value = (await systemApi.list()).data
  loadStats()
  loadCategories()
})
</script>

<style scoped>
.header-right { display: flex; gap: 12px; }
.baseline-tabs { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }
.baseline-tab {
  flex: 1;
  min-width: 160px;
  padding: 14px 16px;
  border-radius: 10px;
  border: 1px solid #e2e8f0;
  background: #fff;
  font-size: 14px;
  font-weight: 600;
  color: #475569;
  text-align: center;
  cursor: pointer;
  transition: all .2s;
  white-space: nowrap;
}
.baseline-tab:hover { border-color: #3b82f6; color: #3b82f6; }
.baseline-tab.active {
  border-color: #3b82f6;
  background: #eff6ff;
  color: #2563eb;
  box-shadow: 0 2px 8px rgba(59,130,246,.15);
}
.stat-row { margin-bottom: 16px; }
.stat { text-align: center; }
.stat .num { font-size: 30px; font-weight: 700; color: #0f172a; }
.stat .lbl { font-size: 13px; color: #64748b; margin-top: 4px; }
.sys-row { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
.sys-name { width: 90px; font-size: 13px; color: #334155; flex-shrink: 0; }
.sys-comp .el-progress { flex: 1; }
.card-title { font-weight: 600; color: #1e293b; }
</style>
