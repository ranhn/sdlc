import { defineStore } from 'pinia'

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
    displayName: (s) => s.user?.real_name || s.user?.username || '',
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
