<template>
  <router-view />
  <!-- 首次登录强制改密弹窗（飞书同步用户） -->
  <el-dialog
    v-model="showChangePwd"
    title="首次登录 - 请修改密码"
    width="440px"
    :close-on-click-modal="false"
    :close-on-press-escape="false"
    :show-close="false"
  >
    <el-alert type="warning" :closable="false" style="margin-bottom: 16px">
      检测到您的密码为系统初始密码，首次登录必须修改后方可继续使用。
    </el-alert>
    <el-form ref="formRef" :model="form" :rules="rules" label-width="100px">
      <el-form-item label="旧密码" prop="old_password">
        <el-input v-model="form.old_password" type="password" show-password />
      </el-form-item>
      <el-form-item label="新密码" prop="new_password">
        <el-input v-model="form.new_password" type="password" show-password />
      </el-form-item>
      <el-form-item label="确认新密码" prop="confirm">
        <el-input v-model="form.confirm" type="password" show-password />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button type="primary" :loading="saving" @click="submit">确认修改</el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, reactive, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { authApi } from './api'
import { useUserStore } from './store/user'

const store = useUserStore()
const showChangePwd = ref(false)
const saving = ref(false)
const formRef = ref()
const form = reactive({ old_password: '', new_password: '', confirm: '' })

const validateConfirm = (_, value, cb) => {
  if (value !== form.new_password) cb(new Error('两次输入的密码不一致'))
  else cb()
}
const rules = {
  old_password: [{ required: true, message: '请输入旧密码', trigger: 'blur' }],
  new_password: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 8, max: 64, message: '密码长度需 8-64 位', trigger: 'blur' },
  ],
  confirm: [
    { required: true, message: '请再次输入新密码', trigger: 'blur' },
    { validator: validateConfirm, trigger: 'blur' },
  ],
}

watch(
  () => store.mustChangePassword,
  (v) => {
    showChangePwd.value = !!v
    if (v) {
      form.old_password = ''
      form.new_password = ''
      form.confirm = ''
    }
  },
  { immediate: true }
)

async function submit() {
  await formRef.value.validate()
  saving.value = true
  try {
    await authApi.changePassword({ old_password: form.old_password, new_password: form.new_password })
    store.clearMustChangePassword()
    ElMessage.success('密码修改成功')
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '修改失败')
  } finally {
    saving.value = false
  }
}
</script>

<style>
html, body, #app { height: 100%; margin: 0; padding: 0; font-family: 'PingFang SC', 'Microsoft YaHei', -apple-system, sans-serif; }
</style>
