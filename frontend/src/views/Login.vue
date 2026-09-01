<template>
  <div class="login-wrap">
    <div class="login-panel">
      <div class="brand">
        <div class="brand-logo">V</div>
        <div class="brand-name">VeSync SDLC 安全平台</div>
        <div class="brand-sub">软件开发生命周期安全管理与 AI 威胁建模</div>
      </div>
      <el-form ref="formRef" :model="form" :rules="rules" class="login-form" @keyup.enter="handleLogin">
        <div class="form-title">账号登录</div>
        <el-form-item prop="username">
          <el-input v-model="form.username" size="large" placeholder="请输入用户名" :prefix-icon="User" />
        </el-form-item>
        <el-form-item prop="password">
          <el-input v-model="form.password" size="large" type="password" show-password placeholder="请输入密码" :prefix-icon="Lock" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" size="large" class="login-btn" :loading="loading" @click="handleLogin">
            登 录
          </el-button>
        </el-form-item>
        <div v-if="error" class="error">{{ error }}</div>
      </el-form>
    </div>
    <div class="login-footer">© 2026 VeSync · Security Development Lifecycle Platform</div>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { User, Lock } from '@element-plus/icons-vue'
import { authApi } from '../api'
import { useUserStore } from '../store/user'

const router = useRouter()
const route = useRoute()
const store = useUserStore()
const formRef = ref()
const loading = ref(false)
const error = ref('')

const form = reactive({ username: '', password: '' })
const rules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
}

async function handleLogin() {
  error.value = ''
  try {
    await formRef.value.validate()
  } catch {
    return
  }
  loading.value = true
  try {
    const res = await authApi.login(form)
    // authApi.login 已经解包 response.data，res 直接是后端返回的 body
    const data = res
    // 登录接口返回 { access_token, token_type, role, full_name, username, must_change_password }
    const user = {
      username: data.username || form.username,
      real_name: data.full_name || form.username,
      role: data.role,
    }
    store.setLogin(data.access_token, user, data.must_change_password)
    ElMessage.success('登录成功')
    router.push(route.query.redirect || '/dashboard')
  } catch (e) {
    error.value = e.response?.data?.detail || '用户名或密码错误'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-wrap {
  height: 100vh; display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 55%, #164e63 100%);
  position: relative;
}
.login-panel {
  width: 400px; background: rgba(255,255,255,0.98); border-radius: 16px;
  padding: 40px 36px; box-shadow: 0 20px 60px rgba(0,0,0,0.3);
}
.brand { text-align: center; margin-bottom: 28px; }
.brand-logo {
  width: 52px; height: 52px; margin: 0 auto 12px; border-radius: 12px;
  background: linear-gradient(135deg,#3b82f6,#8b5cf6); color: #fff;
  display: flex; align-items: center; justify-content: center;
  font-size: 26px; font-weight: 800;
}
.brand-name { font-size: 20px; font-weight: 700; color: #0f172a; }
.brand-sub { font-size: 12px; color: #64748b; margin-top: 6px; }
.form-title { font-size: 16px; font-weight: 600; color: #1e293b; margin-bottom: 20px; }
.login-btn { width: 100%; font-weight: 600; letter-spacing: 4px; }
.error { color: #ef4444; font-size: 13px; text-align: center; margin-top: 4px; }
.login-footer {
  position: absolute; bottom: 24px; color: rgba(255,255,255,0.5); font-size: 12px;
}
</style>
