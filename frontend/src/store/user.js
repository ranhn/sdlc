import { defineStore } from 'pinia'

/**
 * 从 JWT 里取出 sub（= 用户 id）。**只解码、不验签**。
 *
 * 为什么不验签：它只用于"按钮可见性 / 是不是我负责的"这类前端展示判断，
 * 真正的鉴权始终在后端按 token 判定 —— 前端不需要也无法验签。
 *
 * 为什么需要这个兜底：登录接口早期**不返回 id**，老会话的 localStorage.user 里
 * 就没有 id，于是"这条漏洞是不是我负责的"永远判为 false —— 表现为修复人看不到
 * 「确认 / 驳回」按钮（实测踩过）。有了它，老会话无需重新登录即可恢复正常。
 */
function userIdFromToken(token) {
  try {
    const part = String(token || '').split('.')[1]
    if (!part) return null
    const b64 = part.replace(/-/g, '+').replace(/_/g, '/')
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4)
    const id = Number(JSON.parse(atob(padded))?.sub)
    return Number.isFinite(id) && id > 0 ? id : null
  } catch {
    return null
  }
}

export const useUserStore = defineStore('user', {
  state: () => ({
    token: localStorage.getItem('token') || '',
    user: JSON.parse(localStorage.getItem('user') || 'null'),
    mustChangePassword: JSON.parse(localStorage.getItem('mustChangePassword') || 'false'),
  }),
  getters: {
    isLogin: (s) => !!s.token,
    role: (s) => s.user?.role || s.user?.role_code || '',
    username: (s) => s.user?.username || '',
    displayName: (s) => s.user?.full_name || s.user?.real_name || s.user?.username || '',
    /** 当前用户 id：优先用登录接口返回的，老会话则从 token 的 sub 解出来 */
    userId: (s) => s.user?.id ?? userIdFromToken(s.token),
  },
  actions: {
    setLogin(token, user, mustChangePassword = false) {
      this.token = token
      this.user = user
      this.mustChangePassword = !!mustChangePassword
      localStorage.setItem('token', token)
      localStorage.setItem('user', JSON.stringify(user))
      localStorage.setItem('mustChangePassword', JSON.stringify(this.mustChangePassword))
    },
    clearMustChangePassword() {
      this.mustChangePassword = false
      localStorage.setItem('mustChangePassword', 'false')
    },
    logout() {
      this.token = ''
      this.user = null
      this.mustChangePassword = false
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      localStorage.removeItem('mustChangePassword')
    },
  },
})
