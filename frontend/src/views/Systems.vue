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
          <el-select v-model="form.owner_id" clearable filterable :loading="usersLoading" placeholder="选择负责人">
            <!-- label 用 userLabel()：含英文用户名，否则只能按中文名搜（见 utils/userLabel.js） -->
            <el-option v-for="u in users" :key="u.id" :label="userLabel(u)" :value="u.id" />
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
import { fmtDateTime } from '../utils/time'
import { userLabel } from '../utils/userLabel'

const store = useUserStore()
const canEdit = computed(() => ['admin', 'secops'].includes(store.role))
const list = ref([])
const users = ref([])
const usersLoading = ref(false)
let usersLoaded = false
const loading = ref(false)
const visible = ref(false)
const form = reactive({ id: null, name: '', description: '', owner_id: null, status: 'running' })

const statusName = { running: '运行中', dev: '开发中', offline: '已下线' }
const statusType = { running: 'success', dev: 'warning', offline: 'info' }
function fmt(d) { return fmtDateTime(d) }

async function load() { loading.value = true; try { list.value = (await systemApi.list()).data } finally { loading.value = false } }

/**
 * 负责人下拉的人员列表**按需加载**：飞书通讯录同步后公司有 1600+ 人，
 * 全量约 580KB，而这一页只有编辑弹窗用得到 —— 以前在 onMounted 就拉，
 * 等于每次打开「系统资产」都白等一次下载。现在改为弹窗打开时拉一次，
 * 且用只返回 id/用户名/姓名的 /users/pick（约 60KB）。
 */
async function ensureUsers() {
  if (!canEdit.value || usersLoaded) return
  usersLoaded = true
  usersLoading.value = true
  try { users.value = (await adminApi.userPicks()).data || [] }
  catch { usersLoaded = false }   // 失败允许下次重试
  finally { usersLoading.value = false }
}

async function openForm(row) {
  // 先等人员列表就绪再回填 owner_id —— Element 解析"已选项显示名"时要能在选项里
  // 找到这个人（否则会短暂显示成数字 id）。
  await ensureUsers()
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
    await doDelete(row, false)
  } catch (e) {
    if (e === 'cancel') return
    ElMessage.error(e.response?.data?.detail || '删除失败')
  }
}

async function doDelete(row, force) {
  try {
    await systemApi.del(row.id, force)
    ElMessage.success(force ? '已强制级联删除' : '已删除')
    load()
  } catch (e) {
    const status = e?.response?.status
    const detail = e?.response?.data?.detail
    if (status === 409 && detail && !force) {
      // 有关联数据，询问是否强制级联删除
      try {
        await ElMessageBox.confirm(
          `${detail}\n\n是否同时删除该系统下的所有关联数据（漏洞/组件/扫描/基线）？此操作不可恢复！`,
          '存在关联数据',
          { type: 'error', confirmButtonText: '强制级联删除', cancelButtonText: '取消', confirmButtonClass: 'el-button--danger' }
        )
        await doDelete(row, true)
      } catch (e2) {
        if (e2 === 'cancel') return
        ElMessage.error(e2?.response?.data?.detail || '删除失败')
      }
    } else {
      ElMessage.error(detail || '删除失败')
    }
  }
}

onMounted(() => { load() })   // 人员列表改为打开弹窗时按需加载（见 ensureUsers）
</script>
