<template>
  <div class="input-panel">
    <!-- ═══ 左侧引导栏：步骤 + 场景模板 + 输入建议 ═══ -->
    <aside class="guide-rail">
      <div class="rail-head">
        <div class="head-icon">
          <svg viewBox="0 0 20 20" width="15" height="15" aria-hidden="true">
            <path d="M10 2L2 6l8 4 8-4-8-4z" fill="currentColor" opacity="0.9" />
            <path d="M2 10l8 4 8-4M2 14l8 4 8-4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
          </svg>
        </div>
        <div class="head-text">
          <h3>AI 威胁建模</h3>
          <p>文档 → DFD + 威胁清单</p>
        </div>
      </div>

      <!-- 步骤指示器 -->
      <ol class="rail-steps">
        <li v-for="(s, i) in railSteps" :key="s.key" class="rail-step" :class="s.state" :title="s.tip || ''">
          <span class="rs-idx">
            <svg v-if="s.state === 'done'" viewBox="0 0 16 16" width="9" height="9" aria-hidden="true">
              <path d="M3 8.5l3.2 3.2L13 5" fill="none" stroke="currentColor" stroke-width="2.4"
                    stroke-linecap="round" stroke-linejoin="round" />
            </svg>
            <template v-else>{{ i + 1 }}</template>
          </span>
          <span class="rs-body">
            <span class="rs-label">{{ s.label }}</span>
            <span v-if="s.hint" class="rs-hint">{{ s.hint }}</span>
          </span>
        </li>
      </ol>

      <!-- 场景模板 -->
      <div class="rail-block">
        <div class="rb-head">
          <span class="rb-title">场景模板</span>
          <span v-if="templates.length" class="rb-count">{{ templates.length }}</span>
        </div>
        <div v-if="templates.length" class="tpl-list">
          <button
            v-for="tpl in templates"
            :key="tpl.id"
            type="button"
            class="tpl-row"
            :class="{ active: activeTemplate?.id === tpl.id }"
            :title="tpl.description"
            @click="fillTemplate(tpl)"
          >
            <span class="tpl-dot" />
            <span class="tpl-row-name">{{ tpl.name }}</span>
            <svg class="tpl-arrow" viewBox="0 0 16 16" width="10" height="10" aria-hidden="true">
              <path d="M6 3l5 5-5 5" fill="none" stroke="currentColor" stroke-width="1.9"
                    stroke-linecap="round" stroke-linejoin="round" />
            </svg>
          </button>
        </div>
        <p v-else class="rail-empty">暂无模板，可直接在右侧填写</p>
      </div>

      <!-- 核心能力：把引导栏下方空白填实，同时向用户说明产品价值 -->
      <div class="rail-block">
        <div class="rb-head">
          <span class="rb-title">核心能力</span>
        </div>
        <ul class="feat-list">
          <li v-for="f in features" :key="f.title" class="feat-row">
            <span class="feat-icon">
              <svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor"
                   stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path :d="f.path" />
              </svg>
            </span>
            <span class="feat-body">
              <span class="feat-title">{{ f.title }}</span>
              <span class="feat-desc">{{ f.desc }}</span>
            </span>
          </li>
        </ul>
      </div>
    </aside>

    <!-- ═══ 右侧：步骤化输入工作区 ═══ -->
    <div class="work-area">
      <div class="work-scroll">
        <!-- Step 01 标题 -->
        <section class="card card--compact">
          <div class="card-head">
            <span class="card-num">01</span>
            <div class="card-title-wrap">
              <h4>建模标题 <span class="tag-req">必填</span></h4>
              <p class="card-sub">用于在结果列表中识别本次建模</p>
            </div>
          </div>
          <div class="ta-wrap ta-wrap--line">
            <input
              v-model="title"
              class="title-input"
              type="text"
              placeholder="例如：电商平台支付模块安全分析"
              maxlength="60"
            />
          </div>
        </section>

        <!-- Step 02 需求文档 -->
        <section class="card card--grow">
          <div class="card-head">
            <span class="card-num card-num--req">02</span>
            <div class="card-title-wrap">
              <h4>系统需求文档 <span class="tag-req">必填</span></h4>
              <p class="card-sub">功能描述、参与角色、涉及的数据类型</p>
            </div>
            <div class="card-head-r">
              <span class="char-pill" :class="{ ok: requirements.length >= 10 }">
                {{ requirements.length }}<i>/10</i>
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
                <span>{{ uploadingReq ? '解析中…' : '上传' }}</span>
              </button>
            </div>
          </div>

          <div class="ta-wrap">
            <textarea
              v-model="requirements"
              rows="4"
              placeholder="粘贴或上传系统需求文档，例如：&#10;1、系统包含用户管理、订单、支付模块；&#10;2、用户通过 Web 登录，数据存入 MySQL；&#10;3、支持第三方支付回调（微信/支付宝）等。"
              @paste="onPaste($event, 'requirements')"
            ></textarea>
          </div>

          <div v-if="reqAttachment" class="field-actions">
            <div class="attachment-chip">
              <svg viewBox="0 0 20 20" width="12" height="12" aria-hidden="true">
                <path d="M6 4h8a1 1 0 011 1v12l-2.5-1.5L10 17l-2.5-1.5L5 17V5a1 1 0 011-1z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" />
              </svg>
              <span class="att-name" :title="reqAttachment.filename">{{ reqAttachment.filename }}</span>
              <span v-if="reqAttachment.image_count" class="att-imgs">{{ reqAttachment.image_count }} 图</span>
              <button class="att-remove" type="button" title="移除附件" @click="removeAttachment('requirements')">✕</button>
            </div>
          </div>
        </section>

        <!-- Step 03 架构文档 -->
        <section class="card card--grow">
          <div class="card-head">
            <span class="card-num">03</span>
            <div class="card-title-wrap">
              <h4>产品架构设计 <span class="tag-opt">可选</span></h4>
              <p class="card-sub">服务拆分、调用链路、信任边界</p>
            </div>
            <div class="card-head-r">
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
                <span>{{ uploadingArch ? '解析中…' : '上传' }}</span>
              </button>
            </div>
          </div>

          <div class="ta-wrap">
            <textarea
              v-model="architecture"
              rows="4"
              placeholder="粘贴或上传架构设计文档，例如：&#10;1、前端 Vue 应用 → 后端 API → 数据库；&#10;2、Redis 缓存、消息队列、对象存储等。"
              @paste="onPaste($event, 'architecture')"
            ></textarea>
          </div>

          <div v-if="archAttachment" class="field-actions">
            <div class="attachment-chip">
              <svg viewBox="0 0 20 20" width="12" height="12" aria-hidden="true">
                <path d="M6 4h8a1 1 0 011 1v12l-2.5-1.5L10 17l-2.5-1.5L5 17V5a1 1 0 011-1z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" />
              </svg>
              <span class="att-name" :title="archAttachment.filename">{{ archAttachment.filename }}</span>
              <span v-if="archAttachment.image_count" class="att-imgs">{{ archAttachment.image_count }} 图</span>
              <button class="att-remove" type="button" title="移除附件" @click="removeAttachment('architecture')">✕</button>
            </div>
          </div>
        </section>

        <!-- 粘贴图缩略图（P0-3：多模态发送给 AI） -->
        <div v-if="pastedImages.length" class="pasted-images">
          <div class="pi-head">
            <span class="pi-title">已粘贴的架构图</span>
            <span class="pi-hint">多模态发送给 AI</span>
            <button class="pi-clear" type="button" @click="clearPastedImages">清空</button>
          </div>
          <div class="pi-grid">
            <div v-for="(img, i) in pastedImages" :key="i" class="pi-item">
              <img :src="img.dataUri" :alt="img.name" />
              <span class="pi-name" :title="img.name">{{ img.name }}</span>
              <button class="pi-remove" type="button" title="移除" @click="removePastedImage(i)">✕</button>
            </div>
          </div>
        </div>

        <!-- 缓存命中提示（默认隐藏，仅命中缓存时显示） -->
        <div v-if="replayAvailable" class="fp-hint fp-hint--replay">
          <div class="fp-row">
            <span class="fp-dot same" />
            <span class="fp-text">输入与上次一致，再次分析将命中结果缓存（秒级、结果一致）</span>
            <button class="fp-replay" type="button" @click="submit(true)">重放上次输入</button>
          </div>
        </div>
      </div>

      <!-- ═══ 固定操作条 ═══ -->
      <footer class="action-bar">
        <div class="ab-left">
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
          <span class="ab-method-desc">{{ currentMethodologyDesc }}</span>
        </div>

        <button
          class="btn btn-primary analyze-btn"
          :disabled="analyzing || !canAnalyze"
          @click="submit"
        >
          <span v-if="!analyzing" class="cta-content">
            <svg viewBox="0 0 20 20" width="15" height="15" aria-hidden="true">
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
      </footer>
    </div>

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

// —— P0-3：用户直接在 textarea 粘贴的图片（架构图/数据流图） ——
const pastedImages = ref([])   // [{ dataUri, name, bytes }]

const MAX_PASTED_COUNT = 10
const MAX_PASTED_SINGLE = 3 * 1024 * 1024

function removePastedImage(idx) {
  pastedImages.value.splice(idx, 1)
}
function clearPastedImages() {
  pastedImages.value = []
}

async function onPaste(ev, _target) {
  // 只处理图片类型粘贴（P0-3：让粘贴图进 LLM 多模态）
  const items = ev?.clipboardData?.items
  if (!items || !items.length) return
  const imageItems = []
  for (const it of items) {
    if (it.kind === 'file' && it.type && it.type.startsWith('image/')) {
      imageItems.push(it)
    }
  }
  if (!imageItems.length) return
  // 阻止默认粘贴（避免图片被转成 base64 文本塞进 textarea）
  ev.preventDefault()
  for (const it of imageItems) {
    if (pastedImages.value.length >= MAX_PASTED_COUNT) {
      emit('error', `粘贴图最多 ${MAX_PASTED_COUNT} 张，超出已忽略`)
      break
    }
    const file = it.getAsFile()
    if (!file) continue
    if (file.size > MAX_PASTED_SINGLE) {
      emit('error', `粘贴图「${file.name || '未命名'}」超过 ${Math.round(MAX_PASTED_SINGLE / 1024 / 1024)}MB，已忽略`)
      continue
    }
    try {
      const dataUri = await readAsDataURI(file)
      // 去重：与已有 pastedImages 比 data URI
      if (pastedImages.value.some((p) => p.dataUri === dataUri)) continue
      pastedImages.value.push({
        dataUri,
        name: file.name || `粘贴图 ${pastedImages.value.length + 1}`,
        bytes: file.size,
      })
    } catch (e) {
      emit('error', `读取粘贴图失败：${e?.message || e}`)
    }
  }
}

function readAsDataURI(file) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader()
    fr.onload = () => resolve(String(fr.result || ''))
    fr.onerror = () => reject(fr.error || new Error('FileReader failed'))
    fr.readAsDataURL(file)
  })
}

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
      image_original_count: res.image_original_count || 0,
      image_truncated: !!res.image_truncated,
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

    // P1-5 / P1-6：后端 warnings 与截断告知（Pillow 缺失/超张数/超 4MB）
    if (Array.isArray(res.warnings) && res.warnings.length) {
      for (const w of res.warnings) emit('error', w)
    }
    if (res.image_truncated) {
      const orig = res.image_original_count || 0
      const kept = res.image_count || 0
      if (res.image_oversized) {
        emit(
          'error',
          `附件「${att.filename}」中有 ${res.image_oversized} 张图超过 4MB，已自动忽略（仅保留 ${kept}/${orig} 张）`,
        )
      } else {
        emit(
          'error',
          `附件「${att.filename}」含 ${orig} 张架构图，超过单附件上限 24 张，仅保留前 ${kept} 张`,
        )
      }
    }
  } catch (err) {
    // 优先用后端返回的 detail（包含 422 真实原因），其次用 axios message
    const detail =
      err?.response?.data?.detail ||
      err?.response?.data?.message ||
      err?.message ||
      '文档解析失败，请检查文件格式'
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
  {
    value: 'MAESTRO',
    label: 'MAESTRO',
    desc: 'OWASP 多智能体框架：目标劫持 / 工具滥用 / 权限扩散 / 记忆投毒',
  },
]
const methodology = ref('STRIDE')

const currentMethodologyDesc = computed(
  () => methodologyOptions.find((m) => m.value === methodology.value)?.desc || '',
)

// —— 左侧「核心能力」条目：标题 + 一句短介绍（≤14 字，保证单行） ——
const features = [
  {
    title: '8 种方法论覆盖',
    desc: 'STRIDE / LINDDUN / MAESTRO 等',
    path: 'M2 13V3M2 13h12M4.5 10.5l3-4 2.5 2.5 4.5-5.5',
  },
  {
    title: '文档直接解析',
    desc: '需求 / 架构文档自动抽取',
    path: 'M9 1.5H4a1 1 0 00-1 1v11a1 1 0 001 1h8a1 1 0 001-1V5.5L9 1.5zM9 1.5v4h4',
  },
  {
    title: '结果可复现',
    desc: '固定种子，随时复测比对',
    path: 'M13.5 8a5.5 5.5 0 11-1.7-3.97M13.5 2v3.5H10',
  },
]

// —— 左侧步骤指示器：随输入完成度自动推进 ——
const railSteps = computed(() => {
  const hasReq = requirements.value.trim().length >= 10 ||
    (reqAttachment.value?.image_count || 0) > 0
  const hasArch = architecture.value.trim().length > 0 ||
    (archAttachment.value?.image_count || 0) > 0
  const hasTitle = title.value.trim().length > 0
  const defs = [
    { key: 'title', label: '填写标题', hint: '', done: hasTitle, current: !hasTitle },
    { key: 'req', label: '录入需求文档', hint: '', done: hasReq, current: !hasReq && hasTitle, tip: '≥ 10 字（程序硬约束）' },
    { key: 'arch', label: '补充架构设计', hint: '', done: hasArch },
    { key: 'method', label: '选择方法论', hint: '', done: true },
  ]
  let currentAssigned = false
  return defs.map((d) => {
    let state = 'todo'
    if (d.done) state = 'done'
    else if (!currentAssigned) {
      state = 'current'
      currentAssigned = true
    }
    return { ...d, state }
  })
})

function toggleShowExample() {
  showExample.value = !showExample.value
}

const canAnalyze = computed(() => {
  // 标题必填（非空白字符）
  if (title.value.trim().length === 0) return false
  // 需求文档必填：文本 ≥ 10 字，或附件含文本/图片
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

// P0-3：把粘贴图的 data URI 列表抽出来给后端
function collectPastedImages() {
  return pastedImages.value.map((p) => p.dataUri).filter(Boolean)
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
    images: [...collectAttachmentImages(), ...collectPastedImages()],
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
  () => [
    reqAttachment.value ? reqAttachment.value.attachment_id + (reqAttachment.value.image_count || 0) : '',
    archAttachment.value ? archAttachment.value.attachment_id + (archAttachment.value.image_count || 0) : '',
    pastedImages.value.length,
  ],
  () => {
    clearTimeout(fingerprintTimer)
    fingerprintTimer = setTimeout(refreshFingerprint, 300)
  },
)

async function submit(isReplay = false) {
  if (!canAnalyze.value) {
    if (title.value.trim().length === 0) {
      emit('error', '请先填写建模标题')
    } else {
      emit('error', '请至少输入 10 个字符的需求文档内容，或上传一份需求文档')
    }
    return
  }
  // P0-4：子组件级防抖——不依赖父组件 disabled（按钮 disabled 是 reactive，
  // 双击两个不同 button 时父组件 store.analyzing 检查可能因 event loop 调度
  // 在同一 tick 内被绕过）。父组件 onAnalyzeRequest 仍会再 check 一遍。
  if (props.analyzing) return
  const reqText = requirements.value.trim() ||
    (reqAttachment.value?.text || '').trim()
  const archText = architecture.value.trim() ||
    (archAttachment.value?.text || '').trim()
  const payload = {
    title: title.value.trim(),
    requirements: reqText,
    architecture: archText,
    attachments: collectAttachmentImages(),
    pasted_images: collectPastedImages(),
    methodology: methodology.value,
  }
  // 不再从前端 localStorage 取 LLM 配置。
  // 管理员在公司统一配置 LLM 后，所有用户（包括本用户）发起分析时，
  // 后端会自动用统一配置（见 llm_config_store.py）。
  // —— 这就是"管理员配一次，全员都能用"的实现。
  // 如果用户想要覆盖（仅 admin 调试用），可在此按需读旧 key 'ai-td-llm-legacy'。
  // P0-5：等 fingerprint 算完再 emit（之前是 fire-and-forget，后端收到的 input_fingerprint
  // 永远是空，in-flight 去重失效）。fingerprint 错误时回退为空串，后端会自己再算一次。
  let fp = ''
  try {
    fp = (await computeInputFingerprint({
      title: payload.title,
      requirements: reqText,
      architecture: archText,
      images: [...(payload.attachments || []), ...(payload.pasted_images || [])],
      methodology: payload.methodology,
    })) || ''
  } catch (_e) {
    fp = ''
  }
  lastSubmittedFingerprint.value = fp
  currentFingerprint.value = fp
  replayAvailable.value = false
  emit('analyze', { ...payload, input_fingerprint: fp })
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
  // 切换模板后清空"输入指纹 / 缓存命中"状态：指纹会随 watcher 重新计算
  currentFingerprint.value = ''
  lastSubmittedFingerprint.value = ''
  replayAvailable.value = false
}

onMounted(loadTemplates)
</script>

<style scoped>
/* ══════════════════════════════════════════════════════════════════
   设计 token —— 统一色彩 / 圆角 / 描边 / 阴影，避免散落的魔法值
   ══════════════════════════════════════════════════════════════════ */
.input-panel {
  --c-primary: #2563eb;
  --c-primary-soft: #eff6ff;
  --c-primary-line: #bfdbfe;
  --c-text: #0f172a;
  --c-text-2: #475569;
  --c-text-3: #64748b;
  --c-text-4: #94a3b8;
  --c-line: #e2e8f0;
  --c-line-soft: #eef2f7;
  --c-bg: #ffffff;
  --c-bg-soft: #f8fafc;
  --r-sm: 6px;
  --r-md: 9px;
  --r-lg: 12px;
  --sh-1: 0 1px 2px rgba(15, 23, 42, 0.04);
  --sh-2: 0 2px 8px rgba(15, 23, 42, 0.06);

  width: 100%;
  height: 100%;
  display: flex;
  gap: 12px;
  min-height: 0;
  overflow: hidden;
}

/* ══════════════════════ 左侧引导栏 ══════════════════════ */
.guide-rail {
  width: 232px;
  flex: none;
  /* 内容不足时随内容收高，不再被右侧主区拉长留出大片空白 */
  align-self: flex-start;
  max-height: 100%;
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 0;
  padding: 12px 10px;
  background: var(--c-bg-soft);
  border: 1px solid var(--c-line);
  border-radius: var(--r-lg);
  overflow-y: auto;
}

.rail-head {
  display: flex;
  /* stretch 让 .head-text 撑到与图标同高，h3 贴顶、p 贴底，
     与图标的视觉基线对齐。 */
  align-items: stretch;
  gap: 9px;
  padding: 0 2px 10px;
  border-bottom: 1px solid var(--c-line);
}
.head-icon {
  width: 28px;
  height: 28px;
  flex: none;
  display: grid;
  place-items: center;
  border-radius: 8px;
  background: linear-gradient(135deg, #3b82f6, #1d4ed8);
  color: #fff;
  box-shadow: 0 3px 8px rgba(37, 99, 235, 0.28);
}
/* 让 h3 / p 撑满图标高度(28px)：h3 贴顶、p 贴底，
   与图标的视觉基线自然对齐，不再"上半高下半空"。 */
.head-text {
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  min-height: 28px;
  flex: 1;
  min-width: 0;
}
.head-text h3 {
  font-size: 13px;
  font-weight: 700;
  color: var(--c-text);
  line-height: 1.25;
  letter-spacing: 0.1px;
  margin: 0;
}
.head-text p {
  font-size: 10.5px;
  line-height: 1.4;
  color: var(--c-text-4);
  margin: 0;
}

/* —— 步骤指示器 —— */
.rail-steps {
  display: flex;
  flex-direction: column;
  gap: 2px;
  list-style: none;
  margin: 0;
  padding: 0;
}
.rail-step {
  position: relative;
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 6px 6px 6px 2px;
  border-radius: var(--r-sm);
}
/* 步骤连线 */
.rail-step::after {
  content: '';
  position: absolute;
  left: 14.5px;
  top: 28px;
  width: 1.5px;
  height: calc(100% - 20px);
  background: var(--c-line);
}
.rail-step:last-child::after { display: none; }

.rs-idx {
  width: 22px;
  height: 22px;
  flex: none;
  display: grid;
  place-items: center;
  z-index: 1;
  font-size: 11.5px;
  font-weight: 700;
  font-family: ui-monospace, SFMono-Regular, monospace;
  /* 待办态：序号 2/3 加深一档，让 4 步节奏均衡，
     不再被 current 行的蓝底衬得"塌"下去。 */
  color: var(--c-text-3);
  background: var(--c-bg);
  border: 1.5px solid var(--c-line-soft);
  border-radius: 50%;
  transition: all 0.2s;
}
.rail-step.done .rs-idx {
  color: #fff;
  background: #10b981;
  border-color: #10b981;
}
.rail-step.current .rs-idx {
  color: #fff;
  background: var(--c-primary);
  border-color: var(--c-primary);
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.14);
}
.rs-body {
  display: flex;
  flex-direction: column;
  gap: 1px;
  min-width: 0;
  padding-top: 1px;
}
.rs-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--c-text-2);
  line-height: 1.35;
}
.rail-step.done .rs-label { color: var(--c-text-4); }
.rail-step.current .rs-label { color: var(--c-primary); }
.rs-hint {
  font-size: 11px;
  color: var(--c-text-4);
  line-height: 1.4;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 168px;
}

/* —— 引导栏区块 —— */
.rail-block {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding-top: 10px;
  border-top: 1px solid var(--c-line);
  min-height: 0;
}
.rb-head {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 0 2px;
}
.rb-title {
  font-size: 10.5px;
  font-weight: 700;
  color: var(--c-text-4);
  letter-spacing: 0.6px;
  text-transform: uppercase;
}
.rb-count {
  font-size: 10px;
  font-weight: 600;
  color: var(--c-text-3);
  background: #fff;
  border: 1px solid var(--c-line);
  border-radius: 999px;
  padding: 0 6px;
}

/* —— 场景模板列表 —— */
.tpl-list {
  display: flex;
  flex-direction: column;
  gap: 2px;
  /* 模板少时按内容高度，模板多时才在栏内滚动 */
  max-height: min(210px, 32vh);
  overflow-y: auto;
  margin: 0 -3px;
  padding: 0 3px;
}
.tpl-row {
  display: flex;
  align-items: center;
  gap: 7px;
  width: 100%;
  padding: 6px 7px;
  text-align: left;
  font-size: 11.5px;
  color: var(--c-text-2);
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--r-sm);
  cursor: pointer;
  transition: all 0.15s;
}
.tpl-row:hover {
  color: var(--c-primary);
  background: #fff;
  border-color: var(--c-primary-line);
}
.tpl-row.active {
  color: var(--c-primary);
  font-weight: 600;
  background: var(--c-primary-soft);
  border-color: var(--c-primary-line);
}
.tpl-dot {
  width: 5px;
  height: 5px;
  flex: none;
  border-radius: 50%;
  background: #cbd5e1;
  transition: all 0.15s;
}
.tpl-row:hover .tpl-dot,
.tpl-row.active .tpl-dot {
  background: var(--c-primary);
  box-shadow: 0 0 0 2.5px rgba(37, 99, 235, 0.14);
}
.tpl-row-name {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.tpl-arrow {
  flex: none;
  opacity: 0;
  color: var(--c-primary);
  transition: all 0.15s;
}
.tpl-row:hover .tpl-arrow,
.tpl-row.active .tpl-arrow {
  opacity: 1;
  transform: translateX(1px);
}
.rail-empty {
  font-size: 10.5px;
  color: var(--c-text-4);
  padding: 2px;
  line-height: 1.5;
}

/* —— 核心能力条目 —— */
.feat-list {
  display: flex;
  flex-direction: column;
  gap: 9px;
  list-style: none;
  margin: 0;
  padding: 0;
}
.feat-row {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  min-width: 0;
}
.feat-icon {
  width: 22px;
  height: 22px;
  flex: none;
  /* 两行文字时图标贴顶会偏上，下移 5px 与标题行视觉居中对齐 */
  margin-top: 5px;
  display: grid;
  place-items: center;
  color: var(--c-primary);
  background: var(--c-primary-soft);
  border: 1px solid var(--c-primary-line);
  border-radius: 6px;
}
.feat-body {
  display: flex;
  flex-direction: column;
  gap: 1px;
  min-width: 0;
}
.feat-title {
  font-size: 11.5px;
  font-weight: 600;
  color: var(--c-text-2);
  line-height: 1.4;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  min-width: 0;
}
/* 一句短介绍：正常单行；偶发溢出时省略号兜底，不换行撑高 */
.feat-desc {
  font-size: 10.5px;
  color: var(--c-text-4);
  line-height: 1.45;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  min-width: 0;
}

/* ══════════════════════ 右侧工作区 ══════════════════════ */
.work-area {
  flex: 1;
  min-width: 0;
  min-height: 0;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
/* .work-scroll 不再自己滚动，改为让内部卡片按剩余高度弹性分配，
   使整页刚好占满视口、不出现右侧滚动条。
   前提：每一层 flex 容器都必须显式 min-height: 0，否则 flex 项默认
   min-height: auto 会阻止收缩，卡片会被内容顶高、再次溢出。 */
.work-scroll {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  gap: 10px;
  overflow: hidden;
  padding: 2px 2px 2px 2px;
}

/* —— 输入卡片 —— */
.card {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 12px 14px;
  background: var(--c-bg);
  border: 1px solid var(--c-line);
  border-radius: var(--r-lg);
  box-shadow: var(--sh-1);
  transition: border-color 0.18s, box-shadow 0.18s;
  flex: none;
  min-height: 0;
}
.card:focus-within {
  border-color: var(--c-primary-line);
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.07), var(--sh-2);
}
/* .card--grow: 文档输入卡片。02/03 平分 .work-scroll 的剩余高度
   （01 标题卡按内容自适应），使整页刚好占满视口。
   min-height: 0 是必需的：否则 flex 项默认 min-height:auto，
   卡片会被 textarea 内容顶高，父级再次溢出。 */
.card--grow {
  flex: 1 1 0;
  min-height: 0;
}
/* .card--compact: 01 标题卡。只有一行输入，按内容定高、
   不参与 02/03 的高度平分。 */
.card--compact {
  flex: none;
  gap: 6px;
  padding: 10px 14px 12px;
}
/* 标题行：编号 + 标题/描述 + 右侧操作（字符计数/上传）垂直居中 */
.card-head {
  display: flex;
  align-items: center;
  gap: 9px;
}
.card-head-r {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  margin-left: auto;
  flex: none;
}
.card-num {
  width: 21px;
  height: 21px;
  flex: none;
  display: grid;
  place-items: center;
  font-size: 10px;
  font-weight: 700;
  font-family: ui-monospace, SFMono-Regular, monospace;
  color: var(--c-text-3);
  background: var(--c-bg-soft);
  border: 1px solid var(--c-line);
  border-radius: var(--r-sm);
}
.card-num--req {
  color: var(--c-primary);
  background: var(--c-primary-soft);
  border-color: var(--c-primary-line);
}
/* 主标题与副标题同行：主标题 + 标签 + 描述 横向排列，整体垂直居中 */
.card-title-wrap {
  display: flex;
  flex-direction: row;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px 8px;
  min-width: 0;
}
.card-title-wrap h4 {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12.5px;
  font-weight: 700;
  color: var(--c-text);
  line-height: 1.35;
  white-space: nowrap;
}
.card-sub {
  font-size: 10.5px;
  color: var(--c-text-4);
  line-height: 1.4;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.tag-req,
.tag-opt {
  font-size: 9.5px;
  font-weight: 600;
  padding: 1px 5px;
  border-radius: 4px;
  line-height: 1.5;
}
.tag-req {
  color: #dc2626;
  background: #fef2f2;
  border: 1px solid #fecaca;
}
.tag-opt {
  color: var(--c-text-4);
  background: var(--c-bg-soft);
  border: 1px solid var(--c-line);
}

/* 字符计数 */
.char-pill {
  font-size: 10px;
  font-family: ui-monospace, SFMono-Regular, monospace;
  color: var(--c-text-4);
  background: var(--c-bg-soft);
  border: 1px solid var(--c-line);
  border-radius: 999px;
  padding: 1px 7px;
  transition: all 0.18s;
}
.char-pill i {
  font-style: normal;
  opacity: 0.6;
}
.char-pill.ok {
  color: #059669;
  background: #ecfdf5;
  border-color: #a7f3d0;
}

/* —— 输入框容器 —— */
/* 撑满所属卡片：卡片已被 .card--grow 拉伸到剩余高度，
   这里用 flex:1 吃掉卡片内除标题外的全部空间，避免卡片下方留空白。
   min-height 给一个下限，防止窗口很矮时输入区被压扁。 */
.ta-wrap {
  display: flex;
  flex: 1;
  border: 1px solid var(--c-line);
  border-radius: var(--r-md);
  background: var(--c-bg);
  transition: border-color 0.16s, box-shadow 0.16s, background 0.16s;
  overflow: hidden;
  min-height: 96px;
}
.ta-wrap:hover {
  border-color: #cbd5e1;
}
.ta-wrap:focus-within {
  border-color: var(--c-primary);
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
  background: #fff;
}
/* 01 标题卡的单行输入：覆盖 .ta-wrap 的 flex:1，按内容定高 */
.ta-wrap--line {
  flex: none;
  min-height: 38px;
}
/* textarea 直接挂在 .ta-wrap 下（模板中不存在 .field 容器），
   因此选择器必须基于 .ta-wrap，否则样式完全不生效——
   这正是"输入框只占左侧一小块、右侧大片空白"的根因。 */
.ta-wrap textarea {
  flex: 1;
  width: 100%;
  /* height:100% + min-height:0 让 textarea 严格撑满容器高度，
     高度由 .ta-wrap 决定，不再撑高父级。 */
  height: 100%;
  min-height: 0;
  padding: 9px 12px;
  border: none;
  outline: none;
  background: transparent;
  resize: none;
  font-size: 12.5px;
  line-height: 1.65;
  font-family: inherit;
  color: var(--c-text-2);
  overflow-y: auto;
  display: block;
  box-sizing: border-box;
}
.ta-wrap textarea::placeholder {
  color: #b6c2d2;
  line-height: 1.65;
}
.title-input {
  flex: 1;
  width: 100%;
  padding: 8px 12px;
  border: none;
  outline: none;
  background: transparent;
  font-size: 12.5px;
  line-height: 1.45;
  font-family: inherit;
  color: var(--c-text);
}
.title-input::placeholder {
  color: #b6c2d2;
}

/* —— 上传 / 附件 —— */
.field-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex: none;
}
.attachment-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  max-width: 100%;
  padding: 3px 7px 3px 8px;
  font-size: 10.5px;
  color: var(--c-primary);
  background: var(--c-primary-soft);
  border: 1px solid var(--c-primary-line);
  border-radius: 999px;
  overflow: hidden;
}
.attachment-chip .att-name {
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 600;
}
.attachment-chip .att-imgs {
  font-size: 9.5px;
  font-weight: 600;
  color: var(--c-text-3);
  background: #fff;
  border: 1px solid var(--c-line);
  padding: 0 5px;
  border-radius: 999px;
  white-space: nowrap;
}
.att-remove {
  display: grid;
  place-items: center;
  width: 15px;
  height: 15px;
  font-size: 9px;
  line-height: 1;
  color: var(--c-text-4);
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
  gap: 4px;
  padding: 4px 9px;
  font-size: 11px;
  font-weight: 500;
  color: var(--c-text-2);
  background: var(--c-bg-soft);
  border: 1px solid var(--c-line);
  border-radius: var(--r-sm);
  cursor: pointer;
  transition: all 0.16s;
  flex: none;
}
.upload-btn:hover:not(:disabled) {
  color: var(--c-primary);
  border-color: var(--c-primary-line);
  background: var(--c-primary-soft);
}
.upload-btn:disabled {
  opacity: 0.65;
  cursor: not-allowed;
}
.mini-spinner {
  width: 11px;
  height: 11px;
  border: 1.5px solid var(--c-line);
  border-top-color: var(--c-primary);
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}
@keyframes spin {
  to { transform: rotate(360deg); }
}

/* ══════════════════════ 固定操作条 ══════════════════════ */
.action-bar {
  flex: none;
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  background: var(--c-bg);
  border: 1px solid var(--c-line);
  border-radius: var(--r-lg);
  box-shadow: var(--sh-2);
}
.ab-left {
  display: flex;
  align-items: center;
  gap: 10px;
  flex: 1;
  min-width: 0;
}
.methodology-select {
  width: 190px;
  flex: none;
}
.methodology-select :deep(.el-input__wrapper) {
  background: var(--c-bg-soft);
  border-radius: var(--r-sm);
  box-shadow: 0 0 0 1px var(--c-line) inset;
  transition: box-shadow 0.16s;
}
.methodology-select :deep(.el-input__wrapper:hover) {
  box-shadow: 0 0 0 1px #cbd5e1 inset;
}
.methodology-select :deep(.el-input__wrapper.is-focus) {
  box-shadow: 0 0 0 1px var(--c-primary) inset, 0 0 0 3px rgba(37, 99, 235, 0.1);
}
.methodology-select :deep(.el-select__selected-item) {
  font-size: 12.5px;
  font-weight: 600;
}
.ab-method-desc {
  flex: 1;
  min-width: 0;
  font-size: 11px;
  line-height: 1.4;
  color: var(--c-text-4);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* —— 主 CTA —— */
.analyze-btn {
  flex: none;
  min-width: 186px;
  padding: 9px 20px;
  font-size: 13px;
  font-family: inherit;
  border: none;
  border-radius: var(--r-md);
  background: linear-gradient(135deg, #3b82f6, #1d4ed8);
  color: #fff;
  font-weight: 600;
  cursor: pointer;
  box-shadow: 0 2px 6px rgba(37, 99, 235, 0.3);
  transition: all 0.18s cubic-bezier(0.4, 0, 0.2, 1);
}
.analyze-btn:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 5px 14px rgba(37, 99, 235, 0.36);
}
.analyze-btn:active:not(:disabled) {
  transform: translateY(0);
  box-shadow: 0 1px 3px rgba(37, 99, 235, 0.3);
}
.analyze-btn:disabled {
  background: #cbd5e1;
  box-shadow: none;
  cursor: not-allowed;
}
.cta-content {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  justify-content: center;
}
.loading {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.spinner {
  width: 13px;
  height: 13px;
  border: 2px solid rgba(255, 255, 255, 0.32);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

/* —— 缓存命中提示 —— */
.fp-hint {
  flex: none;
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 8px 11px;
  background: #ecfdf5;
  border: 1px solid #a7f3d0;
  border-radius: var(--r-md);
}
.fp-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.fp-dot {
  width: 6px;
  height: 6px;
  flex: none;
  border-radius: 50%;
  background: var(--c-primary);
}
.fp-dot.same {
  background: #10b981;
  box-shadow: 0 0 0 3px #d1fae5;
}
.fp-text {
  flex: 1;
  min-width: 0;
  font-size: 11px;
  line-height: 1.45;
  color: #047857;
}
.fp-replay {
  flex: none;
  font-size: 10.5px;
  font-weight: 600;
  padding: 3px 9px;
  color: #fff;
  background: #059669;
  border: none;
  border-radius: 999px;
  cursor: pointer;
  transition: all 0.15s;
}
.fp-replay:hover {
  background: #047857;
  transform: translateY(-1px);
}

/* —— 粘贴图列表（P0-3） —— */
.pasted-images {
  flex: none;
  display: flex;
  flex-direction: column;
  gap: 7px;
  padding: 10px 12px;
  background: var(--c-bg-soft);
  border: 1px dashed #cbd5e1;
  border-radius: var(--r-md);
}
.pi-head {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 11px;
  color: var(--c-text-3);
}
.pi-title {
  font-weight: 700;
  font-size: 11px;
  color: var(--c-text-2);
}
.pi-hint {
  flex: 1;
  color: var(--c-text-4);
  font-size: 10.5px;
}
.pi-clear {
  font-size: 10px;
  color: #ef4444;
  background: #fff;
  border: 1px solid #fecaca;
  border-radius: 999px;
  padding: 1px 8px;
  cursor: pointer;
  transition: all 0.15s;
}
.pi-clear:hover {
  background: #fef2f2;
}
.pi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(78px, 1fr));
  gap: 7px;
  max-height: 130px;
  overflow-y: auto;
  padding-right: 2px;
}
.pi-item {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 3px;
  background: #fff;
  border: 1px solid var(--c-line);
  border-radius: var(--r-sm);
  padding: 4px;
  overflow: hidden;
  transition: all 0.15s;
}
.pi-item:hover {
  border-color: var(--c-primary-line);
  box-shadow: var(--sh-2);
}
.pi-item img {
  width: 100%;
  height: 54px;
  object-fit: cover;
  border-radius: 4px;
  background: var(--c-bg-soft);
}
.pi-name {
  font-size: 9.5px;
  color: var(--c-text-3);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  text-align: center;
}
.pi-remove {
  position: absolute;
  top: 3px;
  right: 3px;
  width: 15px;
  height: 15px;
  font-size: 9px;
  line-height: 1;
  color: var(--c-text-3);
  background: rgba(255, 255, 255, 0.94);
  border: 1px solid var(--c-line);
  border-radius: 50%;
  cursor: pointer;
  display: grid;
  place-items: center;
  transition: all 0.15s;
}
.pi-remove:hover {
  color: #fff;
  background: #ef4444;
  border-color: #ef4444;
}

/* —— 滚动条精修（商业级细节） —— */
.work-scroll::-webkit-scrollbar,
.guide-rail::-webkit-scrollbar,
.tpl-list::-webkit-scrollbar,
.pi-grid::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}
.work-scroll::-webkit-scrollbar-thumb,
.guide-rail::-webkit-scrollbar-thumb,
.tpl-list::-webkit-scrollbar-thumb,
.pi-grid::-webkit-scrollbar-thumb {
  background: #dbe3ec;
  border-radius: 999px;
  border: 2px solid transparent;
  background-clip: content-box;
}
.work-scroll::-webkit-scrollbar-thumb:hover,
.guide-rail::-webkit-scrollbar-thumb:hover,
.tpl-list::-webkit-scrollbar-thumb:hover,
.pi-grid::-webkit-scrollbar-thumb:hover {
  background: #c3cedb;
  background-clip: content-box;
}
.work-scroll::-webkit-scrollbar-track,
.guide-rail::-webkit-scrollbar-track,
.tpl-list::-webkit-scrollbar-track,
.pi-grid::-webkit-scrollbar-track {
  background: transparent;
}

/* —— 窄屏降级：引导栏收起为横向 —— */
@media (max-width: 1180px) {
  .guide-rail {
    width: 196px;
  }
  .ab-method-desc {
    display: none;
  }
}
@media (max-width: 980px) {
  .input-panel {
    flex-direction: column;
  }
  .guide-rail {
    width: 100%;
    flex: none;
    align-self: stretch;
    max-height: 168px;
  }
  .tpl-list {
    max-height: 96px;
  }
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
  color: #0f172a;
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
