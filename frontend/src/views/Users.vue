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
        <!-- 启用/禁用筛选：人员管理页最常做的判断就是"谁被停用了"（飞书同步识别出的离职账号
             就在这一档里，对应同步弹窗的「本轮已停用」名单）。按钮上直接带条数 ——
             不用点进去才知道有没有，也能一眼看出"禁用 0"是不是真的没人被停。
             实现在前端过滤：列表本来就是**全量拉回、前端切页**（1600+ 条只渲染 12 行），
             所以等价于后端过滤，而且不必动后端（也就省掉"必须重启后端"这道工序）。 -->
        <el-radio-group v-model="statusFilter" @change="onStatusChange">
          <el-radio-button value="all">全部 {{ statusCounts.all }}</el-radio-button>
          <el-radio-button value="active">启用 {{ statusCounts.active }}</el-radio-button>
          <el-radio-button value="disabled">禁用 {{ statusCounts.disabled }}</el-radio-button>
        </el-radio-group>
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
      <!-- 只渲染当前页的 12 条（pagedList），不是全量 1600+ 条。
           tight-table（全局样式，见 src/styles/main.css）：单元格不换行 + 内边距 12→6px；
           配合表级 show-overflow-tooltip —— 姓名/邮箱/部门这些"读全才有意义"的字段都在
           同一行显示，实在过长的（超长部门名等）截断后 hover 能看全。 -->
      <el-table :data="pagedList" v-loading="loading" stripe
                class="tight-table" show-overflow-tooltip>
        <!-- ID 列显示"从 0 开始的连续序号、跨页递增"，而不是数据库主键：
             合并/删除过账号后主键会出现跳号（0,1,2,3,4,8,9…），看起来像缺数据 -->
        <el-table-column type="index" :index="rowIndex" label="ID" width="56" align="center" />
        <!-- 用户名 = 英文名（飞书同步时写入，如 Tracy.Yang / John Villanueva）。
             不再在名字后面挂「飞书」标签：用户名本来就被挤，而且右边"最近同步"列
             已经有时间/空值可以区分是不是同步来的账号 -->
        <el-table-column prop="username" label="用户名" min-width="140" />
        <!-- 姓名/邮箱/部门：这三列是"读全才有意义"的文本，宽度按实际内容给足
             （姓名如 Leigh Ann Bauman ≈117px、邮箱 leihann.bauman@vesync.com ≈205px），
             以前窄了会折成两行 —— 既读不全、又把行高撑成两行。 -->
        <el-table-column prop="full_name" label="姓名" min-width="130" />
        <el-table-column prop="email" label="邮箱" min-width="215">
          <template #default="{ row }"><span class="muted">{{ row.email || '—' }}</span></template>
        </el-table-column>
        <!-- 部门：飞书同步时按部门树自动落库（open_department_id → 本地部门），
             统一归一到二级部门，名字较长（如 US Product Innovation ≈145px）所以给宽一点 -->
        <el-table-column prop="department_name" label="部门" min-width="168">
          <template #default="{ row }"><span class="muted">{{ row.department_name || '—' }}</span></template>
        </el-table-column>
        <!-- 角色/状态/最近同步/操作：都是固定宽度（不参与富余宽度分配），
             按"标签/时间/三个按钮的实际宽度"给，富余宽度让给姓名/邮箱/部门这些可伸缩列。 -->
        <el-table-column label="角色" width="96">
          <template #default="{ row }"><el-tag size="small">{{ row.role_name }}</el-tag></template>
        </el-table-column>
        <el-table-column label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="row.is_active ? 'success' : 'info'" size="small">{{ row.is_active ? '启用' : '禁用' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="最近同步" width="142">
          <template #default="{ row }"><span class="muted">{{ formatSyncTime(row.last_synced_at) }}</span></template>
        </el-table-column>
        <el-table-column label="操作" width="255">
          <template #default="{ row }">
            <template v-if="canTargetUser(row)">
              <el-button link type="primary" size="small" @click="openEdit(row)">编辑</el-button>
              <el-button link :type="row.is_active ? 'danger' : 'success'" size="small" @click="toggle(row)">
                {{ row.is_active ? '禁用' : '启用' }}
              </el-button>
              <!-- 只保留「重置密码」：一键恢复初始口令 + 飞书私信把账号和口令发给本人
                   （首次登录强制改密）。原来的「改密」（管理员自己拟一个新密码）已删除 ——
                   两个入口功能重叠、管理员分不清该点哪个；"想指定具体密码"由本人登录后
                   自助修改满足（顶栏 → 修改密码）。 -->
              <el-tooltip content="恢复为初始密码，并通过飞书私信把账号和密码发给本人（首次登录必须改密）" placement="top" :show-after="200">
                <el-button link type="warning" size="small" @click="resetPassword(row)">重置密码</el-button>
              </el-tooltip>
              <el-button link type="danger" size="small" @click="del(row)">删除</el-button>
            </template>
            <el-tag v-else-if="row.role_code === 'admin'" size="small" type="info" effect="plain">仅超级管理员可操作</el-tag>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="!loading && filteredList.length === 0" class="empty-tip">{{ emptyTip }}</div>
      <!-- 分页：每页 12 条。列表全量拉回来在前端切片 ——
           1600+ 人一次性渲染会明显卡顿，而且没人会翻到第 100 页。
           分页总数用**筛选后**的条数：否则选「禁用」时会出现"总数 1618、表格里只有 2 行"的矛盾。 -->
      <div v-if="filteredList.length > PAGE_SIZE" class="user-pager">
        <el-pagination
          v-model:current-page="page"
          :page-size="PAGE_SIZE"
          :total="filteredList.length"
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
        <!-- 停用统计**始终显示**（含 0）：0 有两种含义 —— "本轮确实没人离职" 与
             "停用环节被安全阀跳过"。原来只在 >0 时显示，后者就彻底看不见了
             （实测：同步里只要有 1 个失败，整个停用环节就被跳过，而弹窗毫无提示）。 -->
        <div class="stat"><span class="num">{{ syncResult.deactivated }}</span><span class="lbl">停用</span></div>
        <div class="stat" v-if="syncResult.merged > 0"><span class="num">{{ syncResult.merged }}</span><span class="lbl">合并手工账号</span></div>
        <div class="stat" v-if="syncResult.dept_created > 0"><span class="num">+{{ syncResult.dept_created }}</span><span class="lbl">新建部门</span></div>
        <div class="stat" v-else-if="syncResult.dept_total > 0"><span class="num">{{ syncResult.dept_total }}</span><span class="lbl">飞书部门</span></div>
      </div>
      <!-- 停用被安全阀跳过时必须说清楚：否则管理员会以为"离职的人已经处理了" -->
      <el-alert v-if="deactivateSkipped" type="warning" :closable="false" show-icon
                :title="deactivateSkipped" style="margin-bottom: 10px" />
      <!-- 停用了谁：直接列出来（以前只给一个数字，想知道是谁得翻库或跑脚本）。
           管理员据此核对"这几位是不是真离职"；若是误伤（例如只是移出了同步可见范围），
           到「人员管理」点「启用」即可恢复。 -->
      <div v-if="syncResult?.deactivated_users?.length" class="deact-box">
        <b>本轮已停用（飞书通讯录里已不存在的账号）</b>
        <ul>
          <li v-for="n in syncResult.deactivated_users" :key="n">{{ n }}</li>
        </ul>
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
// 启用/禁用筛选（all / active / disabled）。放在前端过滤的原因见模板里的注释：
// 列表本来就是按搜索条件**全量返回**、再前端切页的，所以两种做法结果一致。
const statusFilter = ref('all')
const filteredList = computed(() => {
  if (statusFilter.value === 'active') return list.value.filter((u) => u.is_active)
  if (statusFilter.value === 'disabled') return list.value.filter((u) => !u.is_active)
  return list.value
})
// 三个按钮上的条数：选完搜索词后跟着变（口径 = 当前搜索结果里各状态各有多少）
const statusCounts = computed(() => ({
  all: list.value.length,
  active: list.value.filter((u) => u.is_active).length,
  disabled: list.value.filter((u) => !u.is_active).length,
}))
// 换筛选条件要回到第 1 页：否则可能停在"新条件下不存在"的页码上，表格空着但总数不为 0
function onStatusChange() {
  page.value = 1
}
const emptyTip = computed(() => {
  if (searchKey.value) return '没有匹配的用户'
  if (statusFilter.value === 'disabled') return '没有已禁用的账号'
  if (statusFilter.value === 'active') return '没有已启用的账号'
  return '暂无用户'
})
const pagedList = computed(() => {
  const start = (page.value - 1) * PAGE_SIZE
  return filteredList.value.slice(start, start + PAGE_SIZE)
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
/**
 * 本轮同步是否因**安全阀**跳过了"离职停用"（后端把原因塞在 details[].skipped_deactivate）。
 *
 * 为什么要单独提出来展示：后端的设计是"有任何部门拉取失败 / 本轮人数不足库内 50%
 * 就整个跳过停用" —— 这是对的（宁可不处理，也不能误停全库），但弹窗里原本完全看不到，
 * 管理员会把"停用 0"读成"没人离职"，从而以为离职账号已经自动禁用了。
 */
const deactivateSkipped = computed(
  () => (syncResult.value?.details || [])
    .find((d) => d && d.skipped_deactivate)?.skipped_deactivate || '',
)
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
      // 删除/搜索/筛选后当前页可能超界（例如最后一页只剩 1 条又被删掉）→ 退回最后一页，
      // 否则会出现"表格空着、但总数不为 0"的怪状态
      const maxPage = Math.max(1, Math.ceil(filteredList.value.length / PAGE_SIZE))
      if (page.value > maxPage) page.value = maxPage
    }
  } finally {
    loading.value = false
  }
}

async function toggle(row) {
  await adminApi.toggleUser(row.id)
  const nowActive = !row.is_active
  // 在「启用 / 禁用」筛选下，改完状态这一行就会离开当前视图 —— 提示里说明一句，
  // 否则看起来像"刚点的那行被删掉了"。
  const leftView = (statusFilter.value === 'active' && !nowActive)
    || (statusFilter.value === 'disabled' && nowActive)
  ElMessage.success(`${nowActive ? '已启用' : '已禁用'}${leftView ? '，该账号已移出当前筛选' : ''}`)
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

/**
 * 一键重置为初始口令，并让后端把「账号 + 初始密码」私信给本人。
 *
 * 这是**唯一**的密码管理入口（原来的「改密」已删除：与它功能重叠）。重置 = 恢复到初始口令
 * （FEISHU_DEFAULT_PASSWORD）+ 首次登录强制改密。后端是**同步发送**，所以这里能拿到确定结果：
 * 发出去了 / 没发出去+原因。
 * 通知没发出去时把口令显示出来，管理员可直接线下告知（口令本来就是默认值）。
 */
async function resetPassword(row) {
  try {
    await ElMessageBox.confirm(
      `确定把「${row.full_name || row.username}」的密码重置为初始密码吗？`
      + '重置后会通过飞书私信把账号和初始密码发给本人，他首次登录必须修改密码。',
      '重置初始密码',
      { confirmButtonText: '重置并通知本人', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return          // 用户点了取消：什么都不做（ElMessageBox 取消是 reject，不是异常）
  }
  try {
    const res = await adminApi.resetPassword(row.id)
    const data = res.data || {}
    if (data.notified) {
      ElMessage.success('已重置为初始密码，并已通过飞书私信通知本人')
    } else {
      ElMessage.warning(
        `已重置为初始密码（${data.password || '默认口令'}），但飞书通知未发出：`
        + `${data.error || '未知原因'}`,
      )
    }
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
    // 未处理异常时后端返回的是**纯文本** "Internal Server Error"（不是 JSON，没有 detail），
    // 只取 detail 会退化成干巴巴的"飞书同步失败"，排查时等于没有信息。
    // 这里把「字符串响应 / detail / 原生错误消息 + HTTP 状态码」都显示出来。
    const d = e?.response?.data
    const reason = (typeof d === 'string' && d.trim())
      || d?.detail
      || e?.message
      || '未知原因'
    const status = e?.response?.status
    ElMessage.error(`飞书同步失败：${String(reason).slice(0, 200)}${status ? `（HTTP ${status}）` : ''}`)
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
/* 工具栏：搜索框 + 启停筛选 + 飞书同步 + 新增用户。加上筛选后控件变多，
   窄窗口（或浏览器缩放到 125% 时）允许换行，避免把标题挤掉或把按钮压变形 */
.header-tools { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; justify-content: flex-end; }
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
/* 本轮被停用的账号名单：红底便于一眼看到，内部可滚动（范围异常时可能一次停用很多人） */
.deact-box {
  margin-bottom: 10px; padding: 8px 10px;
  background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px;
  font-size: 12.5px; line-height: 1.6; color: #b91c1c;
}
.deact-box ul { margin: 4px 0 0; padding-left: 18px; max-height: 96px; overflow-y: auto; }
.sync-summary { display: flex; gap: 12px; margin-bottom: 16px; }
.sync-summary .stat {
  flex: 1; text-align: center; padding: 12px; background: #f5f7fa; border-radius: 6px;
}
.sync-summary .num { display: block; font-size: 20px; font-weight: 600; color: #303133; }
.sync-summary .lbl { display: block; font-size: 12px; color: #909399; margin-top: 4px; }
.sync-summary .success .num { color: #67c23a; }
.sync-summary .danger .num { color: #f56c6c; }
</style>
