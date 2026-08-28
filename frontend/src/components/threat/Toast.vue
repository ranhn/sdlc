<template>
  <div class="toast-root">
    <!-- Toast 通知 -->
    <transition-group name="toast">
      <div
        v-for="t in toasts"
        :key="t.id"
        class="toast"
        :class="'toast-' + t.type"
        @click="dismiss(t.id)"
      >
        <span class="toast-icon">{{ iconOf(t.type) }}</span>
        <span class="toast-msg">{{ t.message }}</span>
        <span class="toast-x">×</span>
        <span class="toast-bar" :class="'bar-' + t.type" :style="{ animationDuration: t.duration + 'ms' }"></span>
      </div>
    </transition-group>

    <!-- 确认弹层 -->
    <transition name="fade">
      <div v-if="confirmState" class="confirm-mask" @click.self="resolve(false)">
        <div class="confirm-box">
          <div class="confirm-icon" :class="{ 'danger-icon': confirmState.danger }">{{ confirmState.icon || '❓' }}</div>
          <h3 class="confirm-title">{{ confirmState.title }}</h3>
          <p v-if="confirmState.message" class="confirm-msg">{{ confirmState.message }}</p>
          <div class="confirm-actions">
            <button class="btn" @click="resolve(false)">{{ confirmState.cancelText || '取消' }}</button>
            <button class="btn btn-primary" :class="{ danger: confirmState.danger }" @click="resolve(true)">
              {{ confirmState.okText || '确定' }}
            </button>
          </div>
        </div>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref, reactive, onBeforeUnmount } from 'vue'

const toasts = ref([])
const confirmState = ref(null)
let toastId = 0
let confirmResolver = null

/** 展示一条自动消失的 toast 通知 */
function toast(message, type = 'info', duration = 3500) {
  const id = ++toastId
  toasts.value.push({ id, message, type, duration })
  setTimeout(() => dismiss(id), duration)
  return id
}

function dismiss(id) {
  toasts.value = toasts.value.filter((t) => t.id !== id)
}

/** 弹出确认框，返回 Promise<boolean> */
function confirm(options) {
  const opts =
    typeof options === 'string'
      ? { title: options }
      : options
  confirmState.value = {
    title: opts.title || '请确认',
    message: opts.message || '',
    okText: opts.okText || '确定',
    cancelText: opts.cancelText || '取消',
    danger: !!opts.danger,
    icon: opts.icon || '❓',
  }
  return new Promise((resolve) => {
    confirmResolver = resolve
  })
}

function resolve(value) {
  confirmState.value = null
  if (confirmResolver) {
    confirmResolver(value)
    confirmResolver = null
  }
}

function iconOf(type) {
  return {
    success: '✅',
    error: '❌',
    warning: '⚠️',
    info: 'ℹ️',
  }[type] || 'ℹ️'
}

defineExpose({ toast, confirm })

// 暴露全局调用入口：window.$toast / window.$confirm，任何组件可直接调用
if (typeof window !== 'undefined') {
  window.$toast = toast
  window.$confirm = confirm
}

onBeforeUnmount(() => {
  if (confirmResolver) {
    confirmResolver(false)
    confirmResolver = null
  }
})
</script>

<style scoped>
.toast-root {
  position: fixed;
  top: 70px;
  right: 20px;
  z-index: 1000;
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-width: 400px;
}
.toast {
  position: relative;
  display: flex;
  align-items: center;
  gap: 11px;
  padding: 12px 14px;
  border-radius: 10px;
  font-size: 13px;
  box-shadow: var(--shadow-lg);
  border: 1px solid var(--border);
  cursor: pointer;
  background: var(--bg-elevated);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  color: var(--text);
  overflow: hidden;
}
.toast:hover {
  transform: translateY(-1px);
}
.toast-icon {
  width: 22px;
  height: 22px;
  display: grid;
  place-items: center;
  border-radius: 6px;
  font-size: 12px;
  flex-shrink: 0;
  color: var(--text-on-primary);
}
.toast-success .toast-icon { background: var(--success); }
.toast-error .toast-icon { background: var(--danger); }
.toast-warning .toast-icon { background: var(--warning); }
.toast-info .toast-icon { background: var(--primary); }
.toast-msg {
  flex: 1;
  line-height: 1.5;
  word-break: break-all;
}
.toast-x {
  opacity: 0.5;
  font-size: 15px;
  transition: opacity 0.15s;
}
.toast-x:hover {
  opacity: 1;
}
.toast-success {
  border-color: var(--success-border);
}
.toast-error {
  border-color: var(--danger-border);
}
.toast-warning {
  border-color: var(--warning-border);
}
.toast-info {
  border-color: var(--primary-border);
}
.toast-bar {
  position: absolute;
  left: 0;
  bottom: 0;
  height: 2px;
  width: 100%;
  transform-origin: left;
  animation: toast-progress linear forwards;
}
.toast-bar.bar-success { background: var(--success); }
.toast-bar.bar-error { background: var(--danger); }
.toast-bar.bar-warning { background: var(--warning); }
.toast-bar.bar-info { background: var(--primary); }
@keyframes toast-progress {
  from { transform: scaleX(1); }
  to { transform: scaleX(0); }
}
.toast-enter-active,
.toast-leave-active {
  transition: opacity 0.25s, transform 0.25s;
}
.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateX(30px) scale(0.96);
}
.toast-move {
  transition: transform 0.3s;
}

.confirm-mask {
  position: fixed;
  inset: 0;
  background: var(--bg-overlay);
  backdrop-filter: blur(6px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1100;
}
.confirm-box {
  width: min(420px, 92%);
  background: var(--bg-elevated);
  backdrop-filter: blur(24px) saturate(180%);
  -webkit-backdrop-filter: blur(24px) saturate(180%);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
  padding: 26px 26px 22px;
  text-align: center;
  position: relative;
  overflow: hidden;
}
.confirm-box::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
  background: var(--primary-gradient);
  opacity: 0.6;
}
.confirm-icon {
  width: 54px;
  height: 54px;
  margin: 0 auto 14px;
  display: grid;
  place-items: center;
  border-radius: 14px;
  font-size: 26px;
  background: var(--primary-gradient-soft);
  border: 1px solid var(--primary-border);
}
.confirm-icon.danger-icon {
  background: var(--danger-soft);
  border-color: var(--danger-border);
}
.confirm-title {
  font-size: 16.5px;
  font-weight: 700;
  margin: 0 0 6px;
  color: var(--text);
}
.confirm-msg {
  font-size: 13px;
  color: var(--text-dim);
  line-height: 1.6;
  margin: 0 0 20px;
  white-space: pre-wrap;
  word-break: break-all;
}
.confirm-actions {
  display: flex;
  gap: 10px;
  justify-content: center;
}
.confirm-actions .btn {
  min-width: 100px;
  padding: 10px 18px;
}
.btn.danger {
  background: var(--danger);
  border-color: var(--danger);
  color: var(--text-on-primary);
  box-shadow: 0 4px 12px rgba(239, 68, 68, 0.30);
}
.btn.danger:hover {
  filter: brightness(1.10);
}
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.25s;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
