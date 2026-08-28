<template>
  <div class="users">
    <div class="page-header">
      <span class="page-title">人员管理</span>
      <div class="header-tools">
        <el-input
          v-model="searchKey"
          placeholder="搜索用户名 / 姓名 / 邮箱"
          clearable
          style="width: 260px"
          @input="onSearchInput"
          @clear="onSearchInput"
        >
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-button
          v-if="isAdmin"
          :disabled="!feishuEnabled"
          :loading="syncing"
          @click="onFeishuSync"
        >
          <el-icon><Connection /></el-icon>&nbsp;从飞书同步
        </el-button>
        <el-tooltip v-if="isAdmin && !feishuEnabled" content="飞书未配置（FEISHU_APP_ID / FEISHU_APP_SECRET）" placement="top">
          <el-icon class="hint-icon"><QuestionFilled /></el-icon>
        </el-tooltip>
        <el-button type="primary" @click="visible = true">
          <el-icon><Plus /></el-icon>&nbsp;新增用户
        </el-button>
      </div>
    </div>

    <el-card shadow="never">
      <el-table :data="list" v-loading="loading" stripe>
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="username" label="用户名" min-width="120">
          <template #default="{ row }">
            {{ row.username }}
            <el-tag v-if="row.feishu_open_id" size="small" type="info" effect="plain" style="margin-left: 6px">飞书</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="full_name" label="姓名" min-width="120" />
        <el-table-column prop="email" label="邮箱" min-width="180">
          <template #default="{ row }"><span class="muted">{{ row.email || '—' }}</span></template>
        </el-table-column>
        <el-table-column label="角色" width="120">
          <template #default="{ row }"><el-tag size="small">{{ row.role_name }}</el-tag></template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="row.is_active ? 'success' : 'info'" size="small">{{ row.is_active ? '启用' : '禁用' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="最近同步" width="160">
          <template #default="{ row }"><span class="muted">{{ formatSyncTime(row.last_synced_at) }}</span></template>
        </el-table-column>
        <el-table-column label="操作" width="200">
          <template #default="{ row }">
            <el-button link :type="row.is_active ? 'danger' : 'success'" size="small" @click="toggle(row)">
              {{ row.is_active ? '禁用' : '启用' }}
            </el-button>
            <el-button link type="warning" size="small" @click="openChangePassword(row)">改密</el-button>
            <el-button link type="danger" size="small" @click="del(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="!loading && list.length === 0" class="empty-tip">
        {{ searchKey ? '没有匹配的用户' : '暂无用户' }}
      </div>
    </el-card>

    <el-dialog v-model="visible" title="新增用户" width="480px">
      <el-form :model="form" :rules="rules" ref="formRef" label-width="90px">
        <el-form-item label="用户名" prop="username"><el-input v-model="form.username" /></el-form-item>
        <el-form-item label="姓名" prop="full_name"><el-input v-model="form.full_name" /></el-form-item>
        <el-form-item label="密码" prop="password"><el-input v-model="form.password" type="password" show-password /></el-form-item>
        <el-form-item label="邮箱"><el-input v-model="form.email" /></el-form-item>
        <el-form-item label="角色" prop="role_id">
          <el-select v-model="form.role_id" style="width: 100%">
            <el-option v-for="r in roles" :key="r.id" :label="r.name" :value="r.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="部门">
          <el-select v-model="form.department_id" clearable style="width: 100%">
            <el-option v-for="d in departments" :key="d.id" :label="d.name" :value="d.id" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer><el-button @click="visible = false">取消</el-button><el-button type="primary" :loading="saving" @click="save">保存</el-button></template>
    </el-dialog>

    <el-dialog v-model="syncDialog" title="飞书同步结果" width="520px">
      <div v-if="syncResult" class="sync-summary">
        <div class="stat"><span class="num">{{ syncResult.total }}</span><span class="lbl">总数</span></div>
        <div class="stat success"><span class="num">+{{ syncResult.created }}</span><span class="lbl">新建</span></div>
        <div class="stat"><span class="num">{{ syncResult.updated }}</span><span class="lbl">更新</span></div>
        <div class="stat danger" v-if="syncResult.failed > 0"><span class="num">{{ syncResult.failed }}</span><span class="lbl">失败</span></div>
      </div>
      <el-table v-if="syncResult?.details?.length" :data="syncResult.details" max-height="240" size="small">
        <el-table-column prop="open_id" label="open_id" />
        <el-table-column prop="error" label="错误" />
      </el-table>
      <template #footer>
        <el-button type="primary" @click="syncDialog = false; load()">知道了</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="showPwd" title="修改密码" width="400px">
      <el-form :model="pwdForm" label-width="80px">
        <el-form-item label="用户">
          <span>{{ pwdForm.username }}</span>
        </el-form-item>
        <el-form-item label="新密码" required>
          <el-input v-model="pwdForm.new_password" type="password" show-password placeholder="至少8位，含大小写字母和数字" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showPwd = false">取消</el-button>
        <el-button type="primary" @click="submitPassword">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { adminApi, feishuApi } from '../api'
import { useUserStore } from '../store/user'

const userStore = useUserStore()
const isAdmin = computed(() => userStore.role === 'admin')

const list = ref([])
const roles = ref([])
const departments = ref([])
const loading = ref(false)
const visible = ref(false)
const saving = ref(false)
const formRef = ref()
const searchKey = ref('')
const feishuEnabled = ref(false)
const syncing = ref(false)
const syncDialog = ref(false)
const syncResult = ref(null)
const showPwd = ref(false)
const pwdForm = reactive({ id: null, username: '', new_password: '' })

const form = reactive({ username: '', full_name: '', password: '', email: '', role_id: null, department_id: null })
const rules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  full_name: [{ required: true, message: '请输入姓名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
  role_id: [{ required: true, message: '请选择角色', trigger: 'change' }],
}

let searchTimer = null
function onSearchInput() {
  if (searchTimer) clearTimeout(searchTimer)
  searchTimer = setTimeout(() => load(), 300)
}

async function load() {
  loading.value = true
  try {
    const params = searchKey.value ? { q: searchKey.value.trim() } : undefined
    list.value = (await adminApi.users(params)).data
  } finally {
    loading.value = false
  }
}

async function toggle(row) {
  await adminApi.toggleUser(row.id)
  ElMessage.success(row.is_active ? '已禁用' : '已启用')
  load()
}

function openChangePassword(row) {
  pwdForm.id = row.id
  pwdForm.username = row.username
  pwdForm.new_password = ''
  showPwd.value = true
}

async function submitPassword() {
  if (!pwdForm.new_password || pwdForm.new_password.length < 8) {
    ElMessage.warning('密码至少8位')
    return
  }
  try {
    await adminApi.changePassword(pwdForm.id, { new_password: pwdForm.new_password })
    ElMessage.success('密码重置成功')
    showPwd.value = false
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '重置失败')
  }
}

async function del(row) {
  try {
    await ElMessageBox.confirm(`确定删除用户「${row.full_name || row.username}」吗？此操作不可恢复。`, '删除确认', {
      confirmButtonText: '删除',
      cancelButtonText: '取消',
      type: 'warning',
    })
    await adminApi.deleteUser(row.id)
    ElMessage.success('删除成功')
    load()
  } catch (e) {
    if (e !== 'cancel') {
      ElMessage.error(e.response?.data?.detail || '删除失败')
    }
  }
}

async function save() {
  await formRef.value.validate()
  saving.value = true
  try {
    await adminApi.createUser(form)
    ElMessage.success('创建成功')
    visible.value = false
    Object.assign(form, { username: '', full_name: '', password: '', email: '', role_id: null, department_id: null })
    load()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '创建失败')
  } finally {
    saving.value = false
  }
}

async function checkFeishu() {
  if (!isAdmin.value) return
  try {
    const r = await feishuApi.config()
    feishuEnabled.value = r.data.enabled
  } catch {
    feishuEnabled.value = false
  }
}

async function onFeishuSync() {
  syncing.value = true
  try {
    const r = await feishuApi.sync()
    syncResult.value = r.data
    syncDialog.value = true
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '飞书同步失败')
  } finally {
    syncing.value = false
  }
}

function formatSyncTime(t) {
  if (!t) return '—'
  try {
    const d = new Date(t)
    if (isNaN(d.getTime())) return '—'
    const pad = (n) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
  } catch {
    return '—'
  }
}

onMounted(async () => {
  load()
  roles.value = (await adminApi.roles()).data
  departments.value = (await adminApi.departments()).data
  checkFeishu()
})
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.page-title { font-size: 18px; font-weight: 600; }
.header-tools { display: flex; gap: 12px; align-items: center; }
.muted { color: #909399; }
.hint-icon { color: #c0c4cc; cursor: help; }
.empty-tip { text-align: center; color: #909399; padding: 32px 0; font-size: 14px; }
.sync-summary { display: flex; gap: 12px; margin-bottom: 16px; }
.sync-summary .stat {
  flex: 1; text-align: center; padding: 12px; background: #f5f7fa; border-radius: 6px;
}
.sync-summary .num { display: block; font-size: 20px; font-weight: 600; color: #303133; }
.sync-summary .lbl { display: block; font-size: 12px; color: #909399; margin-top: 4px; }
.sync-summary .success .num { color: #67c23a; }
.sync-summary .danger .num { color: #f56c6c; }
</style>
