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
          <!-- 同步要跑 40~60s（遍历全公司部门），按钮上直接写清楚，避免用户以为卡死 -->
          <el-icon><Connection /></el-icon>&nbsp;{{ syncing ? '同步中，约 1 分钟…' : '从飞书同步' }}
        </el-button>
        <el-tooltip v-if="isAdmin && !feishuEnabled" content="飞书未配置（FEISHU_APP_ID / FEISHU_APP_SECRET）" placement="top">
          <el-icon class="hint-icon"><QuestionFilled /></el-icon>
        </el-tooltip>
        <el-button v-if="isPrivileged" type="primary" @click="visible = true">
          <el-icon><Plus /></el-icon>&nbsp;新增用户
        </el-button>
      </div>
    </div>

    <el-card shadow="never">
      <!-- 只渲染当前页的 12 条（pagedList），不是全量 1600+ 条 -->
      <el-table :data="pagedList" v-loading="loading" stripe>
        <!-- ID 列显示"从 0 开始的连续序号、跨页递增"，而不是数据库主键：
             合并/删除过账号后主键会出现跳号（0,1,2,3,4,8,9…），看起来像缺数据 -->
        <el-table-column type="index" :index="rowIndex" label="ID" width="60" align="center" />
        <!-- 用户名 = 英文名（飞书同步时写入，如 Tracy.Yang / John Villanueva）。
             不再在名字后面挂「飞书」标签：用户名本来就被挤，而且右边"最近同步"列
             已经有时间/空值可以区分是不是同步来的账号 -->
        <el-table-column prop="username" label="用户名" min-width="150" />
        <el-table-column prop="full_name" label="姓名" min-width="110" />
        <el-table-column prop="email" label="邮箱" min-width="180">
          <template #default="{ row }"><span class="muted">{{ row.email || '—' }}</span></template>
        </el-table-column>
        <!-- 部门：飞书同步时按部门树自动落库（open_department_id → 本地部门），
             统一归一到二级部门，名字较长所以给宽一点 -->
        <el-table-column prop="department_name" label="部门" min-width="150">
          <template #default="{ row }"><span class="muted">{{ row.department_name || '—' }}</span></template>
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
        <el-table-column label="操作" width="260">
          <template #default="{ row }">
            <template v-if="canTargetUser(row)">
              <el-button link type="primary" size="small" @click="openEdit(row)">编辑</el-button>
              <el-button link :type="row.is_active ? 'danger' : 'success'" size="small" @click="toggle(row)">
                {{ row.is_active ? '禁用' : '启用' }}
              </el-button>
              <el-button link type="warning" size="small" @click="openChangePassword(row)">改密</el-button>
              <el-button link type="danger" size="small" @click="del(row)">删除</el-button>
            </template>
            <el-tag v-else-if="row.role_code === 'admin'" size="small" type="info" effect="plain">仅超级管理员可操作</el-tag>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="!loading && list.length === 0" class="empty-tip">
        {{ searchKey ? '没有匹配的用户' : '暂无用户' }}
      </div>
      <!-- 分页：每页 12 条。列表全量拉回来在前端切片 ——
           1600+ 人一次性渲染会明显卡顿，而且没人会翻到第 100 页。 -->
      <div v-if="list.length > PAGE_SIZE" class="user-pager">
        <el-pagination
          v-model:current-page="page"
          :page-size="PAGE_SIZE"
          :total="list.length"
          :pager-count="7"
          layout="total, prev, pager, next, jumper"
          background
        />
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
        <div class="stat" v-if="syncResult.deactivated > 0"><span class="num">{{ syncResult.deactivated }}</span><span class="lbl">停用</span></div>
        <div class="stat" v-if="syncResult.merged > 0"><span class="num">{{ syncResult.merged }}</span><span class="lbl">合并手工账号</span></div>
        <div class="stat" v-if="syncResult.dept_created > 0"><span class="num">+{{ syncResult.dept_created }}</span><span class="lbl">新建部门</span></div>
        <div class="stat" v-else-if="syncResult.dept_total > 0"><span class="num">{{ syncResult.dept_total }}</span><span class="lbl">飞书部门</span></div>
      </div>
      <el-table v-if="syncResult?.details?.length" :data="syncResult.details" max-height="240" size="small">
        <el-table-column prop="open_id" label="open_id" />
        <el-table-column prop="error" label="错误" />
      </el-table>
      <template #footer>
        <el-button type="primary" @click="syncDialog = false; load()">知道了</el-button>
      </template>
    </el-dialog>

    <!-- 编辑用户：可改姓名/邮箱/角色/部门（管理员与安全专家可用，安全专家看不到 admin 行的入口） -->
    <el-dialog v-model="editVisible" title="编辑用户" width="480px" :close-on-click-modal="false">
      <el-form :model="editForm" label-width="90px">
        <el-form-item label="用户名">
          <!-- 用户名不可改：改了用户就用原账号登不进来；飞书同步的用户名就是英文名 -->
          <el-input :model-value="editForm.username" disabled />
        </el-form-item>
        <el-form-item label="姓名"><el-input v-model="editForm.full_name" /></el-form-item>
        <el-form-item label="邮箱"><el-input v-model="editForm.email" /></el-form-item>
        <el-form-item label="角色">
          <el-select v-model="editForm.role_id" style="width: 100%">
            <el-option v-for="r in roles" :key="r.id" :label="r.name" :value="r.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="部门">
          <el-select v-model="editForm.department_id" clearable filterable style="width: 100%">
            <el-option v-for="d in departments" :key="d.id" :label="d.name" :value="d.id" />
          </el-select>
        </el-form-item>
      </el-form>
      <div v-if="editForm.feishu" class="edit-tip">
        该账号来自飞书同步：姓名 / 邮箱 / 部门会在下次同步时被飞书数据覆盖，<b>角色不会被覆盖</b>。
      </div>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="editSaving" @click="saveEdit">保存</el-button>
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
const isPrivileged = computed(() => ['admin', 'secops'].includes(userStore.role))
// secops 不能对 admin 角色账号做写操作（后端已 403 兜底，前端这里隐藏按钮避免误点）
const canTargetUser = (row) => isAdmin.value || row.role_code !== 'admin'

const list = ref([])
const page = ref(1)
const PAGE_SIZE = 12   // 每页 12 条（与漏洞列表页保持一致），其余翻页
// 列表接口是按搜索条件全量返回的，这里前端切页
const pagedList = computed(() => {
  const start = (page.value - 1) * PAGE_SIZE
  return list.value.slice(start, start + PAGE_SIZE)
})

/** ID 列：从 0 开始、跨页连续递增（第 1 页 0~11、第 2 页 12~23…） */
function rowIndex(idx) {
  return (page.value - 1) * PAGE_SIZE + idx
}
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
const editVisible = ref(false)
const editSaving = ref(false)
const editForm = reactive({
  id: null, username: '', full_name: '', email: '',
  role_id: null, department_id: null, feishu: false,
})

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
  // 换了搜索词就回到第 1 页，否则可能停在一个"搜索结果里并不存在"的页码上
  searchTimer = setTimeout(() => load(true), 300)
}

async function load(resetPage = false) {
  loading.value = true
  try {
    const params = searchKey.value ? { q: searchKey.value.trim() } : undefined
    list.value = (await adminApi.users(params)).data
    if (resetPage) {
      page.value = 1
    } else {
      // 删除/搜索后当前页可能超界（例如最后一页只剩 1 条又被删掉）→ 退回最后一页，
      // 否则会出现"表格空着、但总数不为 0"的怪状态
      const maxPage = Math.max(1, Math.ceil(list.value.length / PAGE_SIZE))
      if (page.value > maxPage) page.value = maxPage
    }
  } finally {
    loading.value = false
  }
}

async function toggle(row) {
  await adminApi.toggleUser(row.id)
  ElMessage.success(row.is_active ? '已禁用' : '已启用')
  load()
}

function openEdit(row) {
  Object.assign(editForm, {
    id: row.id,
    username: row.username,
    full_name: row.full_name || '',
    email: row.email || '',
    role_id: row.role_id,
    department_id: row.department_id || null,
    feishu: !!row.feishu_open_id,   // 来自飞书的账号：提示姓名/部门会被同步覆盖
  })
  editVisible.value = true
}

async function saveEdit() {
  editSaving.value = true
  try {
    await adminApi.updateUser(editForm.id, {
      full_name: editForm.full_name,
      email: editForm.email,
      role_id: editForm.role_id,
      department_id: editForm.department_id,
    })
    ElMessage.success('已保存')
    editVisible.value = false
    load()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '保存失败')
  } finally {
    editSaving.value = false
  }
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
/* 分页条：贴在表格下方、右对齐（与漏洞列表页的分页样式保持一致） */
.user-pager { display: flex; justify-content: flex-end; padding: 12px 4px 2px; }
/* 编辑弹窗里的提示：飞书同步账号的哪些字段会被覆盖 */
.edit-tip {
  margin-top: -4px; padding: 8px 12px; background: #fdf6ec;
  border: 1px solid #f5dab1; border-radius: 6px; font-size: 12px;
  color: #b88230; line-height: 1.6;
}
.sync-summary { display: flex; gap: 12px; margin-bottom: 16px; }
.sync-summary .stat {
  flex: 1; text-align: center; padding: 12px; background: #f5f7fa; border-radius: 6px;
}
.sync-summary .num { display: block; font-size: 20px; font-weight: 600; color: #303133; }
.sync-summary .lbl { display: block; font-size: 12px; color: #909399; margin-top: 4px; }
.sync-summary .success .num { color: #67c23a; }
.sync-summary .danger .num { color: #f56c6c; }
</style>
