<template>
  <div class="systems">
    <div class="page-header">
      <span class="page-title">系统资产</span>
      <el-button v-if="canEdit" type="primary" @click="openForm()">
        <el-icon><Plus /></el-icon>&nbsp;新增系统
      </el-button>
    </div>

    <el-card shadow="never">
      <el-table :data="list" v-loading="loading" stripe>
        <el-table-column prop="name" label="系统名称" min-width="180" />
        <el-table-column prop="description" label="描述" min-width="220" show-overflow-tooltip />
        <el-table-column prop="owner_name" label="负责人" width="120">
          <template #default="{ row }">{{ row.owner_name || '—' }}</template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="statusType[row.status]" size="small">{{ statusName[row.status] }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="160">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
        <el-table-column v-if="canEdit" label="操作" width="130" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="openForm(row)">编辑</el-button>
            <el-button link type="danger" size="small" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="visible" :title="form.id ? '编辑系统' : '新增系统'" width="460px">
      <el-form :model="form" label-width="80px">
        <el-form-item label="系统名称"><el-input v-model="form.name" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="form.description" type="textarea" :rows="3" /></el-form-item>
        <el-form-item label="负责人">
          <el-select v-model="form.owner_id" clearable filterable placeholder="选择负责人">
            <el-option v-for="u in users" :key="u.id" :label="u.full_name || u.username" :value="u.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="状态">
          <el-select v-model="form.status">
            <el-option label="运行中" value="running" /><el-option label="开发中" value="dev" /><el-option label="已下线" value="offline" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer><el-button @click="visible = false">取消</el-button><el-button type="primary" @click="save">保存</el-button></template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { systemApi, adminApi } from '../api'
import { useUserStore } from '../store/user'

const store = useUserStore()
const canEdit = computed(() => ['admin', 'secops'].includes(store.role))
const list = ref([])
const users = ref([])
const loading = ref(false)
const visible = ref(false)
const form = reactive({ id: null, name: '', description: '', owner_id: null, status: 'running' })

const statusName = { running: '运行中', dev: '开发中', offline: '已下线' }
const statusType = { running: 'success', dev: 'warning', offline: 'info' }
function fmt(d) { return d ? d.replace('T', ' ').slice(0, 16) : '' }

async function load() { loading.value = true; try { list.value = (await systemApi.list()).data } finally { loading.value = false } }
function openForm(row) {
  Object.assign(form, row ? { id: row.id, name: row.name, description: row.description, owner_id: row.owner_id, status: row.status } : { id: null, name: '', description: '', owner_id: null, status: 'running' })
  visible.value = true
}
async function save() {
  try {
    if (form.id) await systemApi.update(form.id, form)
    else await systemApi.create(form)
    ElMessage.success('已保存'); visible.value = false; load()
  } catch (e) { ElMessage.error(e.response?.data?.detail || '保存失败') }
}
async function remove(row) {
  try {
    await ElMessageBox.confirm(`确认删除系统「${row.name}」？`, '删除确认', { type: 'warning' })
    await systemApi.del(row.id)
    ElMessage.success('已删除'); load()
  } catch (e) {
    if (e === 'cancel') return
    ElMessage.error(e.response?.data?.detail || '删除失败')
  }
}

onMounted(async () => { load(); if (canEdit.value) { try { users.value = (await adminApi.users()).data } catch {} } })
</script>
