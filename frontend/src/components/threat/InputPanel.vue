<template>
  <div class="input-panel">
    <!-- 头部 -->
    <header class="panel-head">
      <div class="head-l">
        <div class="head-icon">
          <svg viewBox="0 0 20 20" width="16" height="16" aria-hidden="true">
            <path d="M3 6h14M3 10h14M3 14h9" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" />
          </svg>
        </div>
        <div class="head-text">
          <h3>AI 威胁建模输入</h3>
          <p>粘贴文档 → AI 生成 DFD 与威胁列表</p>
        </div>
      </div>
    </header>

    <div class="panel-body">
      <!-- 威胁建模标题 -->
      <section class="field field-grow-title">
        <div class="field-head">
          <label>
            <span class="field-num">01</span>
            <span>威胁建模标题</span>
            <span class="optional">（可选）</span>
          </label>
        </div>
        <div class="ta-wrap">
          <input
            v-model="title"
            class="title-input"
            type="text"
            placeholder="例如：用户管理系统威胁建模、电商平台支付模块安全分析…"
            maxlength="60"
          />
        </div>
      </section>

      <!-- 需求文档 -->
      <section class="field field-grow-req">
        <div class="field-head">
          <label>
            <span class="field-num">02</span>
            <span>系统需求文档</span>
            <span class="required">*</span>
          </label>
          <div class="field-head-r">
            <span class="char-count" :class="{ ok: requirements.length >= 10 }">
              {{ requirements.length }} / 10
            </span>
            <button
              class="upload-btn"
              type="button"
              :disabled="uploadingReq"
              @click="pickFile('requirements')"
            >
              <span v-if="uploadingReq" class="mini-spinner" />
              <svg v-else viewBox="0 0 20 20" width="12" height="12" aria-hidden="true">
                <path d="M10 3v8M6 7l4-4 4 4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" />
                <path d="M3 13v3a1 1 0 001 1h12a1 1 0 001-1v-3" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" />
              </svg>
              <span>{{ uploadingReq ? '解析中…' : '上传文档' }}</span>
            </button>
          </div>
        </div>
        <div class="ta-wrap">
          <textarea
            v-model="requirements"
            rows="4"
            placeholder="粘贴或上传系统需求文档，例如：&#10;1、系统包含用户管理、订单、支付模块；&#10;2、用户通过 Web 登录，数据存入 MySQL；&#10;3、支持第三方支付回调（微信/支付宝）等。"
          ></textarea>
        </div>
        <div v-if="reqAttachment" class="field-actions">
          <div class="attachment-chip">
            <svg viewBox="0 0 20 20" width="13" height="13" aria-hidden="true">
              <path d="M6 4h8a1 1 0 011 1v12l-2.5-1.5L10 17l-2.5-1.5L5 17V5a1 1 0 011-1z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" />
            </svg>
            <span class="att-name" :title="reqAttachment.filename">{{ reqAttachment.filename }}</span>
            <span v-if="reqAttachment.image_count" class="att-imgs">{{ reqAttachment.image_count }} 张架构图</span>
            <button class="att-remove" type="button" title="移除附件" @click="removeAttachment('requirements')">✕</button>
          </div>
        </div>
      </section>

      <!-- 架构设计 -->
      <section class="field field-grow-arch">
        <div class="field-head">
          <label>
            <span class="field-num">03</span>
            <span>产品架构设计文档</span>
            <span class="optional">（可选）</span>
          </label>
          <div class="field-head-r">
            <button
              class="upload-btn"
              type="button"
              :disabled="uploadingArch"
              @click="pickFile('architecture')"
            >
              <span v-if="uploadingArch" class="mini-spinner" />
              <svg v-else viewBox="0 0 20 20" width="12" height="12" aria-hidden="true">
                <path d="M10 3v8M6 7l4-4 4 4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" />
                <path d="M3 13v3a1 1 0 001 1h12a1 1 0 001-1v-3" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" />
              </svg>
              <span>{{ uploadingArch ? '解析中…' : '上传文档' }}</span>
            </button>
          </div>
        </div>
        <div class="ta-wrap">
          <textarea
            v-model="architecture"
            rows="4"
            placeholder="粘贴或上传架构设计文档，例如：&#10;1、前端 Vue 应用 → 后端 API → 数据库；&#10;2、Redis 缓存、消息队列、对象存储等。"
          ></textarea>
        </div>
        <div v-if="archAttachment" class="field-actions">
          <div class="attachment-chip">
            <svg viewBox="0 0 20 20" width="13" height="13" aria-hidden="true">
              <path d="M6 4h8a1 1 0 011 1v12l-2.5-1.5L10 17l-2.5-1.5L5 17V5a1 1 0 011-1z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" />
            </svg>
            <span class="att-name" :title="archAttachment.filename">{{ archAttachment.filename }}</span>
            <span v-if="archAttachment.image_count" class="att-imgs">{{ archAttachment.image_count }} 张架构图</span>
            <button class="att-remove" type="button" title="移除附件" @click="removeAttachment('architecture')">✕</button>
          </div>
        </div>
      </section>

      <!-- 方法论 + CTA（同一行） -->
      <div class="cta-row">
        <el-select
          v-model="methodology"
          class="methodology-select"
          placeholder="选择威胁建模方法论"
          popper-class="methodology-popper"
        >
          <el-option
            v-for="m in methodologyOptions"
            :key="m.value"
            :label="m.label"
            :value="m.value"
          >
            <div class="methodology-option">
              <span class="mo-label">{{ m.label }}</span>
              <span class="mo-desc">{{ m.desc }}</span>
            </div>
          </el-option>
        </el-select>
        <button
          class="btn btn-primary analyze-btn"
          :disabled="analyzing || !canAnalyze"
          @click="submit"
        >
          <span v-if="!analyzing" class="cta-content">
            <svg viewBox="0 0 20 20" width="16" height="16" aria-hidden="true">
              <path d="M10 2L2 6l8 4 8-4-8-4z" fill="currentColor" opacity="0.85" />
              <path d="M2 10l8 4 8-4M2 14l8 4 8-4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
            </svg>
            <span>开始 AI 威胁建模</span>
          </span>
          <span v-else class="loading">
            <span class="spinner"></span>
            <span>AI 正在分析文档…</span>
          </span>
        </button>
      </div>

      <!-- 输入指纹 / 稳定性提示 -->
      <div class="fp-hint">
        <div class="fp-row">
          <span class="fp-dot" :class="{ same: replayAvailable }" />
          <span class="fp-text">
            <template v-if="replayAvailable">
              输入与上次一致，再次分析将命中结果缓存（秒级、结果一致）
            </template>
            <template v-else>
              每次分析使用固定模型种子 + 结构化输出，结果可复现
            </template>
          </span>
        </div>
        <div v-if="currentFingerprint" class="fp-meta">
          <span class="fp-label">输入指纹</span>
          <code class="fp-value">{{ currentFingerprint.slice(0, 16) }}…</code>
          <button
            v-if="replayAvailable"
            class="fp-replay"
            type="button"
            @click="submit(true)"
          >
            重放上次相同输入
          </button>
        </div>
      </div>

    </div>

    <!-- 模板抽屉（固定在输入面板底部，不参与 panel-body 滚动，避免被裁切） -->
      <section class="example-box">
        <div
          class="example-head"
          role="button"
          tabindex="0"
          :aria-expanded="showExample"
          @click.stop="toggleShowExample"
          @keydown.enter.stop.prevent="toggleShowExample"
          @keydown.space.stop.prevent="toggleShowExample"
        >
          <span class="ex-l">
            <svg viewBox="0 0 20 20" width="14" height="14" aria-hidden="true">
              <path d="M3 4h14v12H3z" fill="none" stroke="currentColor" stroke-width="1.5" />
              <path d="M3 8h14M7 4v12" fill="none" stroke="currentColor" stroke-width="1.5" />
            </svg>
            <span>示例输入 / 场景模板</span>
            <span v-if="templates.length" class="ex-count">{{ templates.length }} 个模板</span>
          </span>
          <span class="arrow" :class="{ open: showExample }">▾</span>
        </div>
        <transition name="slide">
          <div v-if="showExample" class="example-body">
            <div v-if="templates.length" class="template-grid">
              <button
                v-for="tpl in templates"
                :key="tpl.id"
                class="template-card"
                :class="{ active: activeTemplate?.id === tpl.id }"
                @click="fillTemplate(tpl)"
                type="button"
              >
                <div class="tpl-name">
                  <span class="tpl-icon">🧩</span>
                  <span>{{ tpl.name }}</span>
                </div>
                <div class="tpl-desc">{{ tpl.description }}</div>
                <div v-if="tpl.tags?.length" class="tpl-tags">
                  <span v-for="tag in tpl.tags" :key="tag" class="tpl-tag">{{ tag }}</span>
                </div>
              </button>
            </div>

          </div>
        </transition>
      </section>

      <!-- 隐藏的文档上传 file input -->
      <input
        ref="fileInput"
        type="file"
        :accept="ACCEPT"
        style="display: none"
        @change="handleFileSelected"
      />
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount, watch } from 'vue'
import { listTemplates, computeInputFingerprint, uploadDocument } from '@/api/threat.js'

const emit = defineEmits(['analyze', 'error', 'upload', 'show-settings'])

const props = defineProps({
  analyzing: { type: Boolean, default: false },
})

const requirements = ref('')
const architecture = ref('')
const title = ref('')
const showExample = ref(false)
const templates = ref([])
const activeTemplate = ref(null)

// —— 文档上传 ——
const ACCEPT = '.txt,.md,.markdown,.pdf,.docx'
const MAX_IMAGE_TOTAL_BYTES = 8 * 1024 * 1024
const MAX_IMAGE_SINGLE_BYTES = 3 * 1024 * 1024
const uploadingReq = ref(false)
const uploadingArch = ref(false)
const reqAttachment = ref(null)
const archAttachment = ref(null)
const fileInput = ref(null)
const fileTarget = ref('')

function pickFile(target) {
  fileTarget.value = target
  if (!fileInput.value) return
  fileInput.value.value = ''
  fileInput.value.click()
}

function attachTarget(key) {
  if (key === 'requirements') return reqAttachment
  if (key === 'architecture') return archAttachment
  return null
}

async function handleFileSelected(e) {
  const file = e.target?.files?.[0]
  if (!file) return
  const target = fileTarget.value
  const flag =
    target === 'requirements' ? uploadingReq :
    target === 'architecture' ? uploadingArch : null
  if (flag) flag.value = true
  try {
    const res = await uploadDocument(file)
    if (!res.attachment_id) {
      emit('error', '文档上传失败，请重试')
      return
    }
    const att = {
      attachment_id: res.attachment_id,
      filename: res.filename || file.name,
      image_count: res.image_count || 0,
      images: capAttachmentImages(res.images || []),
      text: res.extracted || '',
    }
    const t = attachTarget(target)
    if (t) t.value = att
    // 将解析出的文档文本内容回传到对应输入框（无论是否有图片）
    if (att.text.trim()) {
      if (target === 'requirements') requirements.value = att.text
      else if (target === 'architecture') architecture.value = att.text
    }
    emit('upload', [att])
  } catch (err) {
    const detail = err?.message || '文档解析失败，请检查文件格式'
    emit('error', detail)
  } finally {
    if (flag) flag.value = false
  }
}

function removeAttachment(target) {
  const t = attachTarget(target)
  if (t) t.value = null
}

const methodologyOptions = [
  {
    value: 'STRIDE',
    label: 'STRIDE',
    desc: '欺骗 / 篡改 / 否认 / 泄露 / 拒绝 / 提权 — 通用软件安全威胁建模',
  },
  {
    value: 'STRIDE-AI',
    label: 'STRIDE-AI',
    desc: 'AI 威胁：提示注入 / RAG 投毒 / Agent 滥用 / 模型窃取',
  },
  {
    value: 'CIA',
    label: 'CIA',
    desc: '机密性 / 完整性 / 可用性 — 数据安全基础框架',
  },
  {
    value: 'CIADIE',
    label: 'CIADIE',
    desc: 'CIA + 分布式 / 不可变 / 临时性 — 云原生扩展框架',
  },
  {
    value: 'LINDDUN',
    label: 'LINDDUN',
    desc: '隐私威胁建模：链接性 / 可识别性 / 不可检测 / 合规',
  },
  {
    value: 'PLOT4ai',
    label: 'PLOT4ai',
    desc: 'AI 系统安全与伦理：可访问 / 识别 / 安全 / 伦理',
  },
  {
    value: 'EOP',
    label: 'EOP',
    desc: 'OWASP Cornucopia：认证 / 授权 / 密码学 / 会话管理',
  },
]
const methodology = ref('STRIDE')

function toggleShowExample() {
  showExample.value = !showExample.value
}

const canAnalyze = computed(() => {
  if (requirements.value.trim().length >= 10) return true
  if (reqAttachment.value && (reqAttachment.value.text.trim().length >= 10 || reqAttachment.value.image_count > 0)) return true
  return false
})

function capAttachmentImages(images) {
  if (!Array.isArray(images) || !images.length) return images
  const out = []
  let total = 0
  for (const im of images) {
    if (typeof im !== 'string') continue
    if (im.length > MAX_IMAGE_SINGLE_BYTES) continue
    if (total + im.length > MAX_IMAGE_TOTAL_BYTES) break
    out.push(im)
    total += im.length
  }
  return out
}

function collectAttachmentImages() {
  const out = []
  for (const att of [reqAttachment.value, archAttachment.value]) {
    if (att?.images?.length) out.push(...att.images)
  }
  return capAttachmentImages(out)
}

const currentFingerprint = ref('')
const lastSubmittedFingerprint = ref('')
const replayAvailable = ref(false)
let fingerprintTimer = null

async function refreshFingerprint() {
  const fp = await computeInputFingerprint({
    title: title.value,
    requirements: requirements.value,
    architecture: architecture.value,
    images: collectAttachmentImages(),
    methodology: methodology.value,
  })
  currentFingerprint.value = fp
  replayAvailable.value = !!(lastSubmittedFingerprint.value && lastSubmittedFingerprint.value === fp)
}

watch(
  [title, requirements, architecture, methodology],
  () => {
    clearTimeout(fingerprintTimer)
    fingerprintTimer = setTimeout(refreshFingerprint, 300)
  },
  { immediate: true },
)
watch(
  () => [reqAttachment.value, archAttachment.value].map((a) => (a ? a.attachment_id + (a.image_count || 0) : '')),
  () => {
    clearTimeout(fingerprintTimer)
    fingerprintTimer = setTimeout(refreshFingerprint, 300)
  },
)

function submit(isReplay = false) {
  if (!canAnalyze.value) {
    emit('error', '请至少输入 10 个字符的需求文档内容，或上传一份需求文档')
    return
  }
  const reqText = requirements.value.trim() ||
    (reqAttachment.value?.text || '').trim()
  const archText = architecture.value.trim() ||
    (archAttachment.value?.text || '').trim()
  const payload = {
    title: title.value.trim(),
    requirements: reqText,
    architecture: archText,
    attachments: collectAttachmentImages(),
    methodology: methodology.value,
  }
  try {
    const raw = localStorage.getItem('ai-td-llm')
    if (raw) {
      const llm = JSON.parse(raw)
      const filtered = {}
      if (llm?.base_url) filtered.base_url = llm.base_url
      if (llm?.api_key) filtered.api_key = llm.api_key
      if (llm?.model) filtered.model = llm.model
      if (Object.keys(filtered).length) payload.llm = filtered
    }
  } catch (e) {
    /* 忽略 */
  }
  computeInputFingerprint({
    title: payload.title,
    requirements: reqText,
    architecture: archText,
    images: payload.attachments,
    methodology: payload.methodology,
  }).then((fp) => {
    lastSubmittedFingerprint.value = fp
    currentFingerprint.value = fp
    replayAvailable.value = false
  })
  emit('analyze', payload)
}

const EXAMPLE = {
  requirements: `在线商城系统需求文档

1. 用户模块：支持用户注册、登录、找回密码。用户凭据存储于 MySQL 数据库。
2. 商品模块：管理员可维护商品信息（名称、价格、库存），商品数据存储于 MySQL。
3. 购物车与订单：用户添加商品到购物车，提交订单后进入支付流程。
4. 支付模块：对接第三方支付平台（微信支付/支付宝），支付成功后通过回调通知更新订单状态。
5. 缓存与性能：热门商品信息使用 Redis 缓存，降低数据库压力。
6. 日志与审计：所有订单操作记录审计日志，便于追溯。`,
  architecture: `在线商城系统架构设计

- 前端：Vue 3 Web 应用（Nginx 托管），用户通过浏览器访问。
- 网关层：Nginx 反向代理 + API 网关，统一入口，负责限流与转发。
- 后端：Node.js/Express 微服务，包含用户服务、商品服务、订单服务、支付服务。
- 数据库：MySQL（主从），保存用户、商品、订单数据；Redis 缓存热点数据。
- 外部依赖：第三方支付平台（通过 HTTPS 回调），SMTP 邮件服务（发送验证邮件）。
- 部署：Docker + K8s，云上部署（公有云）。
- 信任边界：用户浏览器与公网之间、网关与内网服务之间、服务与数据库之间均存在信任边界。`,
}

function fillExample() {
  title.value = ''
  requirements.value = EXAMPLE.requirements
  architecture.value = EXAMPLE.architecture
  showExample.value = false
}

async function loadTemplates() {
  try {
    const res = await listTemplates()
    templates.value = res.items || []
  } catch (e) {
    templates.value = []
  }
}

function fillTemplate(tpl) {
  title.value = tpl.name || ''
  requirements.value = tpl.requirements || ''
  architecture.value = tpl.architecture || ''
  if (tpl.methodology) methodology.value = tpl.methodology
  activeTemplate.value = tpl
  emit('error', '')
}

onMounted(loadTemplates)
</script>

<style scoped>
.input-panel {
  width: 100%;
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
}

/* —— 头部 —— */
.panel-head {
  display: flex;
  align-items: center;
  justify-content: flex-start;
  gap: 10px;
  padding: 10px 0 12px;
}
.head-l {
  display: flex;
  align-items: center;
  gap: 11px;
}
.head-icon {
  width: 32px;
  height: 32px;
  display: grid;
  place-items: center;
  border-radius: 9px;
  background: linear-gradient(135deg, #3b82f6, #1d4ed8);
  color: #fff;
  box-shadow: 0 3px 10px rgba(59,130,246,0.30);
}
.head-text {
  display: flex;
  align-items: baseline;
  gap: 10px;
}
.head-text h3 {
  font-size: 14px;
  font-weight: 700;
  color: #1e293b;
  line-height: 1.2;
  letter-spacing: 0.1px;
}
.head-text p {
  font-size: 11px;
  color: #94a3b8;
}

/* —— 主体 —— */
.panel-body {
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 10px;
  flex: 1;
  min-height: 0;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.field-grow-title {
  flex-shrink: 0;
}
.field-grow-req,
.field-grow-arch {
  flex: 1 1 0;
  min-height: 130px;
}
.field-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 2px;
}
.field-head-r {
  display: inline-flex;
  align-items: center;
  gap: 10px;
}
.field-head label {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-size: 12px;
  font-weight: 600;
  color: #475569;
}
.field-num {
  display: inline-grid;
  place-items: center;
  width: 20px;
  height: 20px;
  font-family: ui-monospace, SFMono-Regular, monospace;
  font-size: 10.5px;
  font-weight: 700;
  color: #94a3b8;
  background: #f1f5f9;
  border: 1px solid #e2e8f0;
  border-radius: 5px;
}
.required {
  color: #ef4444;
  font-weight: 700;
}
.optional {
  color: #94a3b8;
  font-weight: 400;
  font-size: 11px;
}
.char-count {
  font-family: ui-monospace, SFMono-Regular, monospace;
  font-size: 10.5px;
  color: #94a3b8;
}
.char-count.ok {
  color: #10b981;
  font-weight: 600;
}

.ta-wrap {
  display: flex;
  align-items: center;
  width: 100%;
  flex: 1;
  min-height: 0;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  background: #fff;
  transition: border-color 0.15s, box-shadow 0.15s;
  overflow: hidden;
}
.ta-wrap:focus-within {
  border-color: #bfdbfe;
  box-shadow: 0 0 0 3px rgba(59,130,246,0.1);
}
.field textarea {
  flex: 1;
  width: 100%;
  height: 100%;
  padding: 8px 12px;
  border: none;
  outline: none;
  background: transparent;
  resize: none;
  font-size: 12.5px;
  line-height: 1.6;
  font-family: inherit;
  color: #334155;
}
.title-input {
  flex: 1;
  width: 100%;
  padding: 8px 12px;
  border: none;
  outline: none;
  background: transparent;
  font-size: 13px;
  line-height: 1.4;
  font-family: inherit;
  color: #334155;
}

/* —— 上传文档 —— */
.field-actions {
  display: flex;
  align-items: center;
  justify-content: flex-start;
  gap: 6px;
  margin-top: 4px;
}
.attachment-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  max-width: 100%;
  padding: 4px 8px 4px 9px;
  font-size: 11px;
  color: #2563eb;
  background: #eff6ff;
  border: 1px solid #bfdbfe;
  border-radius: 999px;
  overflow: hidden;
}
.attachment-chip .att-name {
  max-width: 180px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 600;
}
.attachment-chip .att-imgs {
  font-size: 10px;
  color: #94a3b8;
  background: #fff;
  border: 1px solid #e2e8f0;
  padding: 1px 6px;
  border-radius: 999px;
  white-space: nowrap;
}
.att-remove {
  display: grid;
  place-items: center;
  width: 16px;
  height: 16px;
  font-size: 10px;
  line-height: 1;
  color: #94a3b8;
  background: transparent;
  border: none;
  border-radius: 50%;
  cursor: pointer;
  transition: all 0.15s;
  flex: none;
}
.att-remove:hover {
  color: #fff;
  background: #ef4444;
}
.upload-btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 9px;
  font-size: 11px;
  font-weight: 500;
  color: #475569;
  background: #f8fafc;
  border: 1px dashed #e2e8f0;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.16s cubic-bezier(0.4, 0, 0.2, 1);
}
.upload-btn:hover:not(:disabled) {
  color: #2563eb;
  border-color: #bfdbfe;
  background: rgba(59,130,246,0.06);
}
.upload-btn:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}
.mini-spinner {
  width: 12px;
  height: 12px;
  border: 1.5px solid #e2e8f0;
  border-top-color: #2563eb;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}
@keyframes spin {
  to { transform: rotate(360deg); }
}

/* —— 方法论下拉框（el-select） —— */
.cta-row {
  display: flex;
  align-items: stretch;
  gap: 10px;
  margin-top: 2px;
  flex-shrink: 0;
}
.cta-row .methodology-select {
  width: 220px;
  flex-shrink: 0;
}
.methodology-select :deep(.el-input__wrapper) {
  background: #f8fafc;
  border-radius: 6px;
  box-shadow: 0 0 0 1px #e2e8f0 inset;
}
.methodology-select :deep(.el-input__wrapper.is-focus) {
  box-shadow: 0 0 0 1px #3b82f6 inset, 0 0 0 2px rgba(59,130,246,0.22);
}
/* —— CTA —— */
.analyze-btn {
  flex: 1;
  padding: 10px 16px;
  font-size: 14px;
  border: none;
  border-radius: 6px;
  background: linear-gradient(135deg, #3b82f6, #1d4ed8);
  color: #fff;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}
.analyze-btn:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(59,130,246,0.35);
}
.analyze-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
.cta-content {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  justify-content: center;
}
.loading {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.spinner {
  width: 14px;
  height: 14px;
  border: 2px solid rgba(255,255,255,0.3);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

/* —— 输入指纹 / 稳定性提示 —— */
.fp-hint {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 8px 10px;
  background: #eff6ff;
  border: 1px solid #bfdbfe;
  border-radius: 6px;
  flex-shrink: 0;
}
.fp-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.fp-dot {
  width: 7px;
  height: 7px;
  flex: none;
  border-radius: 50%;
  background: #2563eb;
  box-shadow: 0 0 0 3px #dbeafe;
}
.fp-dot.same {
  background: #10b981;
  box-shadow: 0 0 0 3px #d1fae5;
}
.fp-text {
  font-size: 11.5px;
  line-height: 1.45;
  color: #475569;
}
.fp-meta {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.fp-label {
  font-size: 10.5px;
  color: #94a3b8;
}
.fp-value {
  font-family: ui-monospace, SFMono-Regular, monospace;
  font-size: 10.5px;
  color: #475569;
  background: #fff;
  border: 1px solid #e2e8f0;
  padding: 1px 6px;
  border-radius: 4px;
}
.fp-replay {
  margin-left: auto;
  font-size: 11px;
  font-weight: 600;
  padding: 3px 9px;
  color: #059669;
  background: #d1fae5;
  border: 1px solid #a7f3d0;
  border-radius: 999px;
  cursor: pointer;
  transition: all 0.15s;
}
.fp-replay:hover {
  filter: brightness(1.05);
  transform: translateY(-1px);
}

/* —— 模板抽屉 —— */
.example-box {
  flex-shrink: 0;
  border: 1px solid #e2e8f0;
  border-top: none;
  border-radius: 0 0 6px 6px;
  background: #f8fafc;
  overflow: hidden;
}
.example-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 12px;
  cursor: pointer;
  font-size: 12.5px;
  font-weight: 500;
  color: #475569;
  user-select: none;
  background: transparent;
  width: 100%;
  border: none;
  text-align: left;
  transition: background 0.18s;
  outline: none;
}
.example-head:focus-visible {
  outline: 2px solid #3b82f6;
  outline-offset: -2px;
}
.example-head:hover {
  color: #2563eb;
  background: #f1f5f9;
}
.ex-l {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.ex-count {
  font-size: 10.5px;
  font-weight: 500;
  color: #94a3b8;
  background: #fff;
  padding: 1px 7px;
  border-radius: 999px;
  border: 1px solid #e2e8f0;
}
.arrow {
  transition: transform 0.2s;
  font-size: 10px;
  color: #94a3b8;
}
.arrow.open {
  transform: rotate(180deg);
}

.example-body {
  padding: 4px 12px 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  border-top: 1px solid #e2e8f0;
}

.template-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 6px;
  max-height: 240px;
  overflow-y: auto;
  padding-right: 2px;
}
.template-card {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 10px 12px;
  text-align: left;
  background: #fff;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.18s;
  color: #1e293b;
}
.template-card:hover {
  border-color: #bfdbfe;
  transform: translateY(-1px);
  box-shadow: 0 2px 8px rgba(0,0,0,0.06);
}
.template-card.active {
  border-color: #3b82f6;
  background: #eff6ff;
  box-shadow: 0 0 0 1px #3b82f6;
}
.tpl-name {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12.5px;
  font-weight: 600;
  color: #1e293b;
}
.tpl-icon { font-size: 13px; }
.tpl-desc {
  font-size: 11.5px;
  line-height: 1.5;
  color: #475569;
}
.tpl-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 2px;
}
.tpl-tag {
  display: inline-block;
  padding: 1px 7px;
  font-size: 10.5px;
  font-weight: 500;
  border-radius: 999px;
  background: #06b6d4;
  color: white;
  opacity: 0.85;
}

.tpl-actions {
  display: flex;
  justify-content: flex-start;
  border-top: 1px dashed #e2e8f0;
  padding-top: 8px;
}
.tpl-actions .btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  font-size: 12px;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  background: #fff;
  cursor: pointer;
}
.tpl-actions .btn:hover {
  border-color: #bfdbfe;
  background: #f8fafc;
}
</style>

<style>
/* 方法论下拉项样式（el-select 下拉通过 teleport 渲染到 body，需用全局样式） */
.methodology-popper .el-select-dropdown__item {
  height: auto;
  min-height: 44px;
  line-height: 1.45;
  padding: 7px 12px;
  white-space: normal;
}
.methodology-option {
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.mo-label {
  font-size: 12.5px;
  font-weight: 600;
  color: #1e293b;
}
.mo-desc {
  font-size: 11px;
  color: #94a3b8;
  line-height: 1.4;
}
.methodology-popper .el-select-dropdown__item.is-selected .mo-label {
  color: #2563eb;
}
</style>
