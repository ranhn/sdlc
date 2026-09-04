<template>
  <div class="results-panel panel">
    <Toast ref="toastRef" />
    <div class="rp-head">
      <div class="rp-head-l">
        <div class="rp-head-icon">
          <svg viewBox="0 0 20 20" width="18" height="18" aria-hidden="true">
            <rect x="3" y="4" width="14" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="1.5" />
            <path d="M3 8h14" fill="none" stroke="currentColor" stroke-width="1.5" />
            <path d="M6 12h2M10 12h4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
          </svg>
        </div>
        <div>
          <div class="rp-title-row">
            <h2 class="rp-title">威胁建模结果</h2>
            <span class="rp-count-pill">{{ total }} 条记录</span>
            <span class="rp-scope-pill" :class="canViewAll ? 'scope-all' : 'scope-mine'">
              {{ canViewAll ? '全部结果' : '我的结果' }}
            </span>
          </div>
          <span class="rp-sub">
            历史建模记录，可导出 Markdown / JSON / CSV / Word 报告
            <template v-if="!canViewAll">
              · 当前仅显示你建模的记录（{{ currentUsername || '未登录' }}）
            </template>
          </span>
        </div>
      </div>
      <div class="rp-toolbar">
        <input
          v-model="keyword"
          class="rp-search"
          type="text"
          placeholder="搜索标题…"
          @keyup.enter="load(1)"
        />
        <select v-model="methodologyFilter" class="rp-filter-select" @change="load(1)">
          <option value="">全部方法论</option>
          <option v-for="m in methodologyOptions" :key="m.value" :value="m.value">
            {{ m.label }}
          </option>
        </select>
        <button class="btn btn-sm" :disabled="loading" @click="load(1)">
          <span class="btn-ico">⟳</span>
          {{ loading ? '加载中…' : '刷新' }}
        </button>
      </div>
    </div>

    <!-- 加载/空态 -->
    <div v-if="loading" class="rp-state">正在加载历史结果…</div>
    <div v-else-if="!items.length" class="rp-empty">
      暂无匹配的建模结果。先在「开始建模」页面完成一次 AI 威胁建模，结果会自动保存在这里。
    </div>

    <!-- 结果列表（item 体点击 → 跳详情页） -->
    <div v-else class="rp-list">
      <div
        v-for="item in items"
        :key="item.id"
        class="rp-item"
      >
        <div class="rp-item-bar" @click="goDetail(item.id)">
          <div class="rp-item-main">
            <span class="rp-item-title">{{ item.title }}</span>
            <div class="rp-item-meta">
              <span class="rp-tag">{{ tMethodology(item.methodology) }}</span>
              <span class="rp-time">{{ fmtTime(item.created_at) }}</span>
              <span class="rp-stat">
                {{ item.stats?.componentCount ?? '-' }} 组件 ·
                {{ item.stats?.flowCount ?? '-' }} 数据流 ·
                {{ item.stats?.threatCount ?? '-' }} 威胁
              </span>
              <span class="rp-stat rp-owner" :title="ownerTitle(item)">
                建模人：{{ ownerLabel(item) }}
              </span>
            </div>
          </div>
          <div class="rp-item-actions">
            <!-- TODO: 导出按钮暂时隐藏(2026-09-04 用户反馈)。
                 原因: .rp-export-menu 用 position:absolute 展开下拉,
                 被 .rp-list / .rp-panel 链路的 overflow 裁剪,导致点击后下拉显示不全。
                 注意: ResultDetail.vue 里的"详情页导出"也有同样问题,
                 修复时两份一起改(共用 doExport 逻辑,共用同一组修复方案)。
                 修复后把 v-if="false" 改回 v-if="true" 即可恢复。 -->
            <div v-if="false" class="rp-export-group" @click.stop>
              <button
                class="rp-icon-btn rp-export"
                title="导出报告"
                @click="doExport(item, 'md')"
              >
                导出 ▾
              </button>
              <div class="rp-export-menu">
                <button @click="doExport(item, 'md')">Markdown 报告</button>
                <button @click="doExport(item, 'json')">Threat Dragon JSON</button>
                <button @click="doExport(item, 'csv')">CSV 威胁清单</button>
                <button @click="doExport(item, 'docx')">Word 报告 (.docx)</button>
              </div>
            </div>
            <button
              class="rp-icon-btn rp-rename"
              title="重命名标题"
              :disabled="!canModify(item)"
              @click.stop="openRename(item)"
            >
              重命名
            </button>
            <button
              v-if="canDelete(item)"
              class="rp-icon-btn rp-del"
              title="删除此结果"
              @click.stop="doDelete(item)"
            >
              删除
            </button>
            <span class="rp-caret" title="点击查看详情">›</span>
          </div>
        </div>
      </div>
    </div>

    <!-- 分页：常驻底部，1 页时按钮置灰 -->
    <div v-if="pages >= 1" class="rp-pagination">
      <button
        class="btn btn-sm"
        :disabled="page <= 1"
        @click="load(page - 1)"
      >‹ 上一页</button>
      <span class="rp-page-info">第 {{ page }} / {{ pages }} 页</span>
      <button
        class="btn btn-sm"
        :disabled="page >= pages"
        @click="load(page + 1)"
      >下一页 ›</button>
    </div>

    <!-- 重命名标题弹窗 -->
    <div v-if="renameVisible" class="rp-modal-mask" @click.self="closeRename">
      <div class="rp-modal">
        <div class="rp-modal-head">
          <h3>重命名结果标题</h3>
          <button class="rp-modal-close" @click="closeRename">×</button>
        </div>
        <div class="rp-modal-body">
          <p class="rp-modal-hint">
            给这条威胁建模记录起个好记的名字，方便后续在「搜索结果」中快速定位。
          </p>
          <input
            v-model="renameTitle"
            class="rp-modal-input"
            type="text"
            maxlength="60"
            placeholder="输入新的标题…"
            @keyup.enter="doRename"
          />
        </div>
        <div class="rp-modal-foot">
          <button class="btn btn-sm" @click="closeRename">取消</button>
          <button
            class="btn btn-sm btn-primary"
            :disabled="renaming || !renameTitle.trim()"
            @click="doRename"
          >{{ renaming ? '保存中…' : '保存' }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import Toast from './Toast.vue'
import {
  listResults,
  deleteResult,
  renameResult,
  exportResult,
  downloadResult,
} from '@/api/threat.js'
import { tMethodology } from '../../utils/i18n.js'
import { useUserStore } from '@/store/user'

const router = useRouter()
const toastRef = ref(null)
const toast = (msg, type = 'info') => toastRef.value?.toast(msg, type)
const confirmBox = (opts) => toastRef.value?.confirm(opts)

// 列表项点击 → 跳到详情页（嵌套路由 /threat-modeling/results/:id）
function goDetail(id) {
  router.push(`/threat-modeling/results/${id}`)
}

// 当前用户与权限：admin / secops 可查看与操作所有结果；其他角色仅能操作自己建模的结果
const userStore = useUserStore()
const currentRole = computed(() => userStore.role || '')
const currentUsername = computed(() => userStore.username || '')
const canViewAll = computed(() => ['admin', 'secops'].includes(currentRole.value))
function isOwner(item) {
  return !!(item && item.owner_username && currentUsername.value &&
    item.owner_username === currentUsername.value)
}
/** 写操作权限：重命名/删除。admin/secops 任意；其他用户仅自己。 */
function canModify(item) {
  return canViewAll.value || isOwner(item)
}
/** 删除按钮的可见性：与 canModify 一致，UI 上隐藏。 */
function canDelete(item) {
  return canModify(item)
}
/** 显示用的「建模人」标签：优先显示后端返回的中文姓名，其次用户名，匿名兜底。 */
function ownerLabel(item) {
  if (!item) return '-'
  const u = item.owner_username || currentUsername.value || ''
  const n = item.owner_display_name || ''
  if (n && n !== u) return `${u} · ${n}`  // username · 中文名
  return u || n || '匿名'
}
/** 鼠标悬浮提示：username · displayName，便于识别 */
function ownerTitle(item) {
  if (!item) return ''
  const u = item.owner_username || currentUsername.value || ''
  const n = item.owner_display_name || ''
  if (u && n && n !== u) return `${u} · ${n}`
  return u || n || '匿名'
}

// 列表分页 / 筛选 / 搜索
const items = ref([])
const loading = ref(false)
const page = ref(1)
// 每页 7 条
const pageSize = ref(7)
const pages = ref(0)
const total = ref(0)
const keyword = ref('')
const methodologyFilter = ref('')
const methodologyOptions = [
  { value: 'STRIDE', label: 'STRIDE' },
  { value: 'STRIDE-AI', label: 'STRIDE-AI' },
  { value: 'CIA', label: 'CIA' },
  { value: 'CIADIE', label: 'CIADIE' },
  { value: 'LINDDUN', label: 'LINDDUN' },
  { value: 'PLOT4ai', label: 'PLOT4ai' },
  { value: 'EOP', label: 'EOP' },
]

function fmtTime(epoch) {
  if (!epoch) return '-'
  const d = new Date(epoch * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

async function load(targetPage) {
  if (targetPage) page.value = targetPage
  loading.value = true
  try {
    const data = await listResults({
      page: page.value,
      page_size: pageSize.value,
      methodology: methodologyFilter.value || undefined,
      keyword: keyword.value || undefined,
    })
    items.value = data.items || []
    total.value = data.total || 0
    page.value = data.page || 1
    pages.value = data.pages || 0
  } catch (e) {
    toast('加载历史结果失败：' + (e?.response?.data?.detail || e?.message), 'error')
  } finally {
    loading.value = false
  }
}

const FORMAT_MAP = {
  md: { type: 'text/markdown;charset=utf-8', ext: 'md' },
  json: { type: 'application/json;charset=utf-8', ext: 'json' },
  csv: { type: 'text/csv;charset=utf-8', ext: 'csv' },
  docx: { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', ext: 'docx' },
}
async function doExport(item, format = 'md') {
  if (!item) return
  try {
    if (format === 'docx') {
      // Word 为二进制，走 blob 下载
      await downloadResult(item.id, format)
      toast(`已导出 ${item.title}（DOCX）`, 'success')
      return
    }
    const { data, headers } = await exportResult(item.id, format)
    const fmt = FORMAT_MAP[format] || FORMAT_MAP.md
    const blob = new Blob([data], { type: fmt.type })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    // 优先使用后端返回的 Content-Disposition 文件名
    const cd = headers?.['content-disposition'] || ''
    const match = cd.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/)
    a.download = match ? decodeURIComponent(match[1].replace(/['"]/g, '')) : `threat-model-${item.id}.${fmt.ext}`
    a.click()
    URL.revokeObjectURL(url)
    toast(`已导出 ${item.title}（${format.toUpperCase()}）`, 'success')
  } catch (e) {
    toast('导出失败：' + (e?.response?.data?.detail || e?.message), 'error')
  }
}

async function doDelete(item) {
  if (!item) return
  const ok = await confirmBox({
    title: '删除建模结果',
    message: `确定删除「${item.title}」？此操作不可撤销。`,
    okText: '删除',
    danger: true,
    icon: '🗑️',
  })
  if (!ok) return
  try {
    await deleteResult(item.id)
    items.value = items.value.filter((i) => i.id !== item.id)
    total.value = Math.max(0, total.value - 1)
    toast('已删除', 'success')
  } catch (e) {
    toast('删除失败：' + (e?.response?.data?.detail || e?.message), 'error')
  }
}

// —— 重命名标题 ——
const renameVisible = ref(false)
const renameTitle = ref('')
const renaming = ref(false)
const renameTarget = ref(null)

function openRename(item) {
  renameTarget.value = item
  renameTitle.value = item.title || ''
  renameVisible.value = true
  // 弹窗打开后聚焦输入框
  setTimeout(() => {
    const el = document.querySelector('.rp-modal-input')
    el?.focus()
    el?.select()
  }, 50)
}

function closeRename() {
  if (renaming.value) return
  renameVisible.value = false
  renameTarget.value = null
}

async function doRename() {
  const title = renameTitle.value.trim()
  if (!title || !renameTarget.value) return
  renaming.value = true
  try {
    await renameResult(renameTarget.value.id, title)
    renameTarget.value.title = title
    toast('标题已更新', 'success')
    renameVisible.value = false
    renameTarget.value = null
  } catch (e) {
    toast('重命名失败：' + (e?.response?.data?.detail || e?.message), 'error')
  } finally {
    renaming.value = false
  }
}

onMounted(() => load(1))
</script>

<style scoped>
.results-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
  padding: 16px 20px;
  gap: 14px;
  background: var(--bg-panel);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
}
.rp-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
  gap: 16px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
}
.rp-head-l {
  display: flex;
  align-items: center;
  gap: 12px;
}
.rp-head-icon {
  width: 38px;
  height: 38px;
  border-radius: 10px;
  display: grid;
  place-items: center;
  background: var(--primary-gradient);
  color: var(--text-on-primary);
  box-shadow: 0 4px 14px rgba(91, 156, 255, 0.35);
  flex-shrink: 0;
}
.rp-title-row {
  display: flex;
  align-items: center;
  gap: 10px;
}
.rp-title {
  font-size: 16px;
  font-weight: 700;
  color: var(--text);
  letter-spacing: 0.2px;
}
.rp-count-pill {
  font-size: 11px;
  font-weight: 600;
  padding: 2px 10px;
  border-radius: var(--radius-pill);
  background: var(--primary-soft);
  color: var(--primary);
  border: 1px solid var(--primary-border);
  font-family: var(--font-mono);
}
.rp-scope-pill {
  font-size: 11px;
  font-weight: 600;
  padding: 2px 10px;
  border-radius: var(--radius-pill);
  font-family: var(--font-mono);
  white-space: nowrap;
}
.rp-scope-pill.scope-all {
  background: var(--success-soft);
  color: var(--success);
  border: 1px solid var(--success-border);
}
.rp-scope-pill.scope-mine {
  background: var(--warning-soft);
  color: var(--warning);
  border: 1px solid var(--warning-border);
}
.rp-owner {
  color: var(--text-faint);
  font-family: var(--font-mono);
}
.rp-sub {
  font-size: 11.5px;
  color: var(--text-faint);
  margin-top: 2px;
  display: block;
}
.rp-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
}
.rp-search {
  padding: 6px 10px;
  font-size: 12px;
  background: var(--bg-panel-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text);
  outline: none;
  box-shadow: none;
  min-width: 0;
  -webkit-appearance: none;
  appearance: none;
  width: 170px;
  transition: all 0.2s;
  line-height: 1;
  height: 32px;
  box-sizing: border-box;
}
.rp-search:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px var(--primary-soft);
  width: 200px;
}
.rp-filter-select {
  padding: 6px 10px;
  font-size: 12px;
  background: var(--bg-panel-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text);
  cursor: pointer;
  line-height: 1;
  height: 32px;
  box-sizing: border-box;
}
.rp-filter-select:focus {
  outline: none;
  border-color: var(--primary);
}
.btn-ico {
  display: inline-block;
  font-size: 12px;
}
.rp-pagination {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  padding: 12px 0 0;
  flex-shrink: 0;
  border-top: 1px solid var(--border);
}
.rp-page-info {
  font-size: 12.5px;
  color: var(--text-dim);
  font-family: var(--font-mono);
}
.rp-export-group {
  position: relative;
  display: inline-block;
}
.rp-export-group:hover .rp-export-menu {
  display: flex;
}
.rp-export-menu {
  display: none;
  position: absolute;
  right: 0;
  top: 100%;
  z-index: 20;
  flex-direction: column;
  min-width: 168px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  box-shadow: var(--shadow);
  overflow: hidden;
}
.rp-export-menu button {
  padding: 9px 14px;
  font-size: 12.5px;
  text-align: left;
  color: var(--text);
  background: transparent;
  border: none;
  cursor: pointer;
  transition: background 0.15s;
  display: flex;
  align-items: center;
  gap: 6px;
}
.rp-export-menu button:hover {
  background: var(--primary-soft);
  color: var(--primary);
}
.rp-export-menu button:first-child {
  border-radius: var(--radius-sm) var(--radius-sm) 0 0;
}
.rp-export-menu button:last-child {
  border-radius: 0 0 var(--radius-sm) var(--radius-sm);
}
.rp-list {
  flex: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-right: 2px;
}
.rp-state,
.rp-empty {
  padding: 32px 16px;
  text-align: center;
  font-size: 13px;
  color: var(--text-faint);
  border: 1px dashed var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-panel-2);
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}
.rp-item {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-panel-2);
  overflow: hidden;
  transition: border-color 0.2s, box-shadow 0.2s, transform 0.15s;
}
.rp-item:hover {
  border-color: var(--primary-border);
  box-shadow: var(--shadow-sm);
}
.rp-item-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 12px 14px;
  cursor: pointer;
  transition: background 0.15s;
}
.rp-item-bar:hover {
  background: var(--bg-active);
}
.rp-item-main {
  flex: 1;
  min-width: 0;
}
.rp-item-title {
  font-size: 13.5px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 8px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text);
}
.rp-item-title::before {
  content: '';
  width: 4px;
  height: 16px;
  border-radius: 2px;
  background: var(--primary-gradient);
  flex-shrink: 0;
}
.rp-item-meta {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 5px;
  font-size: 11.5px;
  color: var(--text-faint);
  padding-left: 12px;
  flex-wrap: wrap;
}
.rp-tag {
  padding: 1px 7px;
  border-radius: 10px;
  font-size: 10.5px;
  background: var(--info-soft);
  color: var(--info);
  border: 1px solid var(--info-border);
}
.rp-item-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}
.rp-icon-btn {
  font-size: 11.5px;
  padding: 3px 9px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text);
  cursor: pointer;
}
.rp-icon-btn:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}
.rp-icon-btn:hover:not(:disabled) {
  filter: brightness(1.2);
}
.rp-export {
  color: var(--info);
  border-color: var(--info-border);
}
.rp-del {
  color: var(--danger);
  border-color: var(--danger-border);
}
.rp-rename {
  color: var(--primary);
  border-color: var(--primary-border);
}
.rp-caret {
  color: var(--text-faint);
  font-size: 16px;
  line-height: 1;
  padding: 0 4px;
  transition: color 0.15s, transform 0.15s;
}
.rp-item-bar:hover .rp-caret {
  color: var(--primary);
  transform: translateX(2px);
}

/* —— 重命名弹窗 —— */
.rp-modal-mask {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.45);
  backdrop-filter: blur(3px);
  -webkit-backdrop-filter: blur(3px);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  animation: rp-fade 0.16s ease-out;
}
.rp-modal {
  width: 420px;
  max-width: calc(100vw - 40px);
  background: var(--bg-panel-solid);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-lg);
  overflow: hidden;
  animation: rp-pop 0.18s cubic-bezier(0.2, 0.8, 0.3, 1.2);
}
.rp-modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
}
.rp-modal-head h3 {
  font-size: 14px;
  font-weight: 700;
  margin: 0;
}
.rp-modal-close {
  background: transparent;
  border: none;
  color: var(--text-faint);
  font-size: 18px;
  line-height: 1;
  cursor: pointer;
  padding: 2px 6px;
  border-radius: 6px;
}
.rp-modal-close:hover {
  color: var(--danger);
  background: var(--bg-hover);
}
.rp-modal-body {
  padding: 16px;
}
.rp-modal-hint {
  font-size: 12px;
  color: var(--text-dim);
  line-height: 1.6;
  margin: 0 0 12px;
}
.rp-modal-input {
  width: 100%;
  padding: 9px 12px;
  font-size: 13px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  background: var(--bg-panel-2);
  color: var(--text);
  outline: none;
  transition: border-color 0.16s, box-shadow 0.16s;
}
.rp-modal-input:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px var(--primary-soft);
}
.rp-modal-foot {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  padding: 12px 16px;
  border-top: 1px solid var(--border);
  background: var(--bg-panel-2);
}
@keyframes rp-fade {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
}
@keyframes rp-pop {
  from {
    opacity: 0;
    transform: translateY(8px) scale(0.98);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}
</style>
