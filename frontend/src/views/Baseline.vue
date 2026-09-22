<template>
  <div class="baseline">
    <!-- ===== 页头 ===== -->
    <header class="page-header">
      <div class="head-l">
        <h2 class="page-title">安全基线</h2>
        <p class="head-sub">按需求绑定基线范围，只统计范围内条目的合规率</p>
      </div>
      <div class="head-r">
        <el-button @click="openLibrary">基线模板库</el-button>
        <el-button v-if="canManage" type="primary" @click="openCreate">新增需求</el-button>
      </div>
    </header>

    <!-- ===== 概览：合规率环 + 关键指标 + 条目构成 ===== -->
    <section class="hero">
      <div class="hero-ring">
        <div class="ring-wrap">
          <svg viewBox="0 0 120 120" class="ring">
            <circle class="ring-bg" cx="60" cy="60" :r="RING_R" />
            <circle class="ring-fg" cx="60" cy="60" :r="RING_R"
                    :stroke="ringColor" :stroke-dasharray="RING_C" :stroke-dashoffset="ringOffset"
                    transform="rotate(-90 60 60)" />
          </svg>
          <div class="ring-center">
            <div class="ring-num" :class="rateLevel(overview.compliance)">
              {{ overview.compliance }}<span class="pct">%</span>
            </div>
            <div class="ring-lbl">整体合规率</div>
          </div>
        </div>
        <div class="ring-state" :class="rateLevel(overview.compliance)">{{ complianceState }}</div>
        <div class="ring-target">
          <template v-if="overview.compliance >= BASELINE_TARGET">
            已达标 · 目标 {{ BASELINE_TARGET }}%
          </template>
          <template v-else>
            目标 {{ BASELINE_TARGET }}% · 还差 {{ (BASELINE_TARGET - overview.compliance).toFixed(1) }}pt
          </template>
        </div>
      </div>

      <div class="hero-body">
        <div class="kpis">
          <div v-for="k in kpis" :key="k.label" class="kpi">
            <div class="kpi-lbl">{{ k.label }}</div>
            <div class="kpi-num" :class="{ danger: k.danger }">{{ k.value }}</div>
            <div class="kpi-hint">{{ k.hint }}</div>
          </div>
        </div>

        <div class="stack-wrap">
          <div class="stack-head">
            <span>范围内条目构成</span>
            <span class="stack-total">应评 {{ overview.bound_items }} 项</span>
          </div>
          <div class="stack-bar">
            <span v-for="s in stackSegments" :key="s.key" class="seg"
                  :style="{ width: s.pct + '%', background: s.color }" :title="`${s.label} ${s.value} 项`">
              <b v-if="s.pct >= 10">{{ s.value }}</b>
            </span>
          </div>
          <div class="legend">
            <span v-for="s in stackSegments" :key="s.key" class="lg">
              <i :style="{ background: s.color }" />{{ s.label }}<b>{{ s.value }}</b>
            </span>
          </div>
        </div>
      </div>
    </section>
    <p class="hero-note">
      合规率 = 通过 ÷ (应评 − 不适用)，只统计各需求已绑定的基线；同一检查项在多条需求里只算一次。
    </p>

    <!-- ===== 需求列表 ===== -->
    <section class="list-card">
      <div class="list-head">
        <span class="list-title">基线需求</span>
        <span class="list-hint">展开某条需求 → 按绑定基线分组评估；未绑定的基线不会出现在里面</span>
        <div class="list-tools">
          <div class="seg-filter">
            <button v-for="f in REQ_FILTERS" :key="f.value" :class="{ on: reqFilter === f.value }"
                    @click="reqFilter = f.value">
              {{ f.label }} <b>{{ reqFilterCount[f.value] }}</b>
            </button>
          </div>
          <el-input v-model="reqSearch" placeholder="搜索系统 / 需求名" clearable style="width: 196px" />
        </div>
      </div>

      <!-- 首屏骨架 -->
      <div v-if="loadingReqs && !requirements.length" class="skeleton">
        <div v-for="i in 3" :key="i" class="sk-row">
          <el-skeleton animated>
            <template #template>
              <div class="sk-inner">
                <el-skeleton-item variant="circle" style="width:36px;height:36px" />
                <div style="flex:1">
                  <el-skeleton-item variant="text" style="width:34%" />
                  <el-skeleton-item variant="text" style="width:60%;margin-top:8px" />
                </div>
                <el-skeleton-item variant="text" style="width:80px" />
              </div>
            </template>
          </el-skeleton>
        </div>
      </div>

      <!-- 空状态 -->
      <div v-else-if="!requirements.length" class="empty">
        <svg class="empty-art" viewBox="0 0 64 64" fill="none">
          <rect x="12" y="8" width="40" height="48" rx="6" stroke="#cbd5e1" stroke-width="2" />
          <path d="M22 22h20M22 32h20M22 42h12" stroke="#e2e8f0" stroke-width="2" stroke-linecap="round" />
          <circle cx="46" cy="46" r="11" fill="#2563eb" />
          <path d="M41.5 46.5l3 3 6-6.5" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
        <div class="empty-title">还没有基线需求</div>
        <div class="empty-desc">
          新增需求 = 选一个系统 + 勾选这轮要做哪几个基线（可多选），创建后展开逐项评估。
        </div>
        <el-button v-if="canManage" type="primary" @click="openCreate">新增需求</el-button>
        <div v-else class="empty-desc">由管理员或安全专家创建后，你负责的系统会出现在这里。</div>
      </div>

      <!-- 有需求，但被筛选/搜索挡住了 -->
      <div v-else-if="!sortedRequirements.length" class="filter-empty">
        当前筛选或搜索条件下没有需求
        <el-button link type="primary" @click="resetReqFilter">清除筛选</el-button>
      </div>

      <!-- 需求卡片 -->
      <article v-for="r in sortedRequirements" :key="r.id" class="req" :class="{ open: isOpen(r.id) }">
        <div class="req-top" @click="toggleExpand(r)">
          <span class="chev" :class="{ open: isOpen(r.id) }" />
          <div class="avatar" :style="{ background: avatarBg(r.system_name) }">{{ initial(r.system_name) }}</div>

          <div class="req-main">
            <div class="req-line1">
              <span class="sys">{{ r.system_name }}</span>
              <span class="req-name">{{ r.name }}</span>
              <span class="pill" :class="r.status === 'done' ? 'pill-done' : 'pill-run'">
                {{ r.status === 'done' ? '已完成' : '进行中' }}
              </span>
              <span v-if="isOverdue(r)" class="pill pill-late">已逾期</span>
            </div>
            <div class="req-line2">
              <!-- 列表只回答"哪条线有问题"：短名 + 百分比 + 不通过数（明细放 tooltip 与展开区） -->
              <div v-for="b in r.baselines" :key="b.type" class="bchip" :class="{ zero: b.total === 0 }"
                   :title="chipTitle(b)">
                <span class="bchip-name">{{ shortLabel(b.label) }}</span>
                <span class="bchip-pct" :class="{ zero: b.progress === 0 }">{{ b.progress }}%</span>
                <span v-if="b.fail_count" class="bchip-fail">{{ b.fail_count }} 不通过</span>
                <i class="bchip-line" :style="{ width: b.progress + '%', background: barColor(b) }" />
              </div>
            </div>
          </div>

          <div class="metric">
            <!-- 0% 用中性灰且小一档：一屏里"没做"的行不该和"有问题"的行抢视线 -->
            <div class="metric-num" :class="r.compliance > 0 ? rateLevel(r.compliance) : 'zero'">
              {{ r.compliance }}<span class="pct">%</span>
            </div>
            <div class="metric-lbl">合规率</div>
          </div>

          <div class="metric metric-bar">
            <div class="track"><i :style="{ width: r.progress + '%' }" /></div>
            <div class="metric-lbl">{{ assessed(r) }}/{{ r.bound_items }} 已评估</div>
          </div>

          <div class="who">
            <div class="who-name">{{ r.owner_name || '未指派' }}</div>
            <div class="who-due" :class="{ late: isOverdue(r) }">
              截止 {{ r.due_date ? r.due_date.slice(0, 10) : '—' }}
            </div>
          </div>

          <div class="row-actions" @click.stop>
            <el-button v-if="canManage" link type="primary" @click="openEdit(r)">编辑绑定</el-button>
            <!-- 次级操作只在悬停该行时出现：一屏几十个按钮常亮会盖过数据本身 -->
            <template v-if="canManage">
              <el-button link class="secondary" @click="toggleStatus(r)">
                {{ r.status === 'done' ? '重新开启' : '标记完成' }}
              </el-button>
              <el-button link type="danger" class="secondary" @click="removeReq(r)">删除</el-button>
            </template>
          </div>
        </div>

        <!-- 展开：只含本需求绑定的基线 -->
        <div v-if="isOpen(r.id)" class="req-detail" v-loading="detailLoading[r.id]">
          <div class="detail-bar">
            <span class="detail-title">评估条目</span>
            <div class="seg-filter">
              <button v-for="f in FILTERS" :key="f.value" :class="{ on: curFilter(r.id) === f.value }"
                      @click="filters[r.id] = f.value">
                {{ f.label }} <b>{{ countOf(r.id)[f.key] }}</b>
              </button>
            </div>
            <span class="detail-tip">
              {{ canEvaluate(r) ? '点击下方结果即可评估（自动保存）' : '只读：你不是本需求负责人' }}
            </span>
          </div>

          <div v-if="!detailLoading[r.id] && !visibleGroups(r.id).length" class="detail-empty">
            {{ detailEmptyTip(r.id) }}
          </div>

          <div v-for="g in visibleGroups(r.id)" :key="g.key" class="bl-panel" :class="{ collapsed: !isBaselineOpen(r.id, g.key) }">
            <div class="bl-panel-head" @click="toggleBaseline(r.id, g.key)">
              <span class="chev sm" :class="{ open: isBaselineOpen(r.id, g.key) }" />
              <span class="bl-name">{{ g.label }}</span>
              <span class="bl-total">{{ g.total }} 项</span>
              <span class="bl-track"><i :style="{ width: g.progress + '%', background: g.barColor }" /></span>
              <span class="bl-counts">
                <span class="c pass">通过 {{ g.stats.pass }}</span>
                <span class="c fail">不通过 {{ g.stats.fail }}</span>
                <span class="c na">不适用 {{ g.stats.na }}</span>
                <span class="c pending">未评估 {{ g.stats.pending }}</span>
              </span>
            </div>

            <div v-show="isBaselineOpen(r.id, g.key)" class="bl-panel-body">
              <div v-for="cat in g.categories" :key="cat.name" class="cat">
                <div class="cat-head">
                  <span class="cat-name">{{ cat.name }}</span>
                  <span class="cat-cnt">{{ cat.items.length }}</span>
                </div>
                <el-table :data="cat.items" size="small" :row-class-name="rowClass" class="item-table">
                  <!-- 与模板库同一处理：检查项定宽，「要求」独占剩余宽度（这段是被逐条评估时最需要读全的） -->
                  <el-table-column prop="item_name" label="检查项" width="196" show-overflow-tooltip />
                  <el-table-column prop="item_description" label="要求" min-width="300" show-overflow-tooltip />
                  <el-table-column label="检查方式" width="86">
                    <template #default="{ row }">{{ row.check_method === 'automated' ? '自动' : '人工' }}</template>
                  </el-table-column>
                  <el-table-column label="评估结果" width="196">
                    <template #default="{ row }">
                      <div v-if="canEvaluate(r)" class="seg">
                        <button v-for="o in RESULT_OPTS" :key="o.value" :class="[o.value, { on: row.status === o.value }]"
                                @click="saveItem(r, row, o.value)">{{ o.label }}</button>
                      </div>
                      <span v-else class="pill" :class="resultPillClass(row.status)">{{ resultName[row.status] }}</span>
                    </template>
                  </el-table-column>
                  <el-table-column label="证据 / 备注" min-width="190">
                    <template #default="{ row }">
                      <el-input v-if="canEvaluate(r)" v-model="row.evidence" size="small"
                                :placeholder="row.status === 'pending' ? '先选评估结果' : '补充证据或说明'"
                                :disabled="row.status === 'pending'" @blur="saveEvidence(r, row)" />
                      <span v-else class="muted">{{ row.evidence || '—' }}</span>
                    </template>
                  </el-table-column>
                </el-table>
              </div>
            </div>
          </div>
        </div>
      </article>
    </section>

    <!-- ===== 新增 / 编辑需求 ===== -->
    <el-dialog v-model="reqVisible" :title="reqForm.id ? '编辑需求' : '新增基线需求'" width="620px" @open="onReqDialogOpen">
      <el-form :model="reqForm" label-width="92px" class="req-form">
        <el-form-item label="系统">
          <el-select v-model="reqForm.system_id" filterable placeholder="选择系统" style="width: 100%"
                     :disabled="!!reqForm.id">
            <el-option v-for="s in systems" :key="s.id" :label="s.name" :value="s.id" />
          </el-select>
          <div v-if="reqForm.id" class="form-tip">系统不可改（换系统 = 另建一条需求）</div>
        </el-form-item>
        <el-form-item label="需求名称">
          <el-input v-model="reqForm.name" placeholder="留空自动生成「系统名-基线评估」" />
        </el-form-item>
        <el-form-item label="绑定基线">
          <div class="pick-list">
            <div v-for="t in baselineTypes" :key="t.key" class="pick"
                 :class="{ on: reqForm.types[t.key], zero: t.item_count === 0 }"
                 @click="toggleType(t)">
              <span class="pick-tick">{{ reqForm.types[t.key] ? '✓' : '' }}</span>
              <span class="pick-name">{{ t.label }}</span>
              <span class="pick-cnt">{{ t.item_count }} 项 / {{ t.category_count }} 分类</span>
              <span v-if="t.item_count === 0" class="pick-zero">暂无数据，需先导入</span>
            </div>
          </div>
          <div class="pick-sum">
            已选 <b>{{ selectedTypeCount }}</b> 个基线，合计 <b>{{ selectedItemCount }}</b> 个检查项
            <span v-if="selectedTypeCount && !selectedItemCount" class="danger-text">
              （所选基线都还没有检查项，请先在模板库导入/新增）
            </span>
          </div>
        </el-form-item>
        <el-form-item label="负责人">
          <el-select v-model="reqForm.owner_id" filterable clearable :loading="usersLoading"
                     placeholder="可选（负责人可自行填写评估）"
                     style="width: 100%" @visible-change="(v) => v && ensureUsers()">
            <!-- 与「指派负责人」同一套：英文名（=用户名）+ 中文名两列。
                必须显式传 :label —— Element 的本地过滤只比对 label，缺了就退化成比对
                 数字 id，搜 "eric" 会显示"无匹配数据"（见 utils/userLabel.js 的源码说明）；
                下拉是 teleport 到 body 的，所以两列用**行内样式**（scoped 样式够不着）。 -->
            <el-option v-for="u in picks" :key="u.id" :value="u.id" :label="userLabel(u)">
              <span style="display: inline-block; width: 150px">{{ u.username }}</span>
              <span style="color: #909399; font-size: 12px">{{ u.full_name || '—' }}</span>
            </el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="截止日期">
          <el-date-picker v-model="reqForm.due_date" type="date" style="width: 100%"
                          value-format="YYYY-MM-DDTHH:mm:ss" placeholder="可选" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="reqVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="submitReq">
          {{ reqForm.id ? '保存' : '创建' }}
        </el-button>
      </template>
    </el-dialog>

    <!-- ===== 基线模板库 ===== -->
    <el-drawer v-model="libVisible" title="基线模板库" size="76%" @open="openLibraryData">
      <div class="lib-head">
        <div class="lib-types">
          <button v-for="t in baselineTypes" :key="t.key" class="lib-tab" :class="{ on: libType === t.key }"
                  @click="switchLibType(t.key)">
            {{ t.label }}<b>{{ t.item_count }}</b>
          </button>
        </div>
        <div class="lib-tools">
          <el-input v-model="libSearch" placeholder="搜索检查项 / 要求" clearable style="width: 220px" />
          <el-button v-if="canManage" type="primary" plain @click="openItemDialog">新增检查项</el-button>
        </div>
      </div>

      <el-table :data="filteredLibItems" v-loading="libLoading" size="small" :row-class-name="alwaysPlain" class="item-table">
        <!-- 前两列定宽 + 「要求」独占剩余宽度：
             要求是这一屏最该读全的内容（长句多），此前它和「检查项」平分弹性宽度，
             结果整段被截成"...",还得逐行 hover 看 tooltip。定宽前两列后，要求列左移约 120px 且更宽。 -->
        <el-table-column prop="category_name" label="控制模块" width="128" />
        <el-table-column prop="name" label="检查项" width="200" show-overflow-tooltip />
        <el-table-column prop="description" label="要求" min-width="320" show-overflow-tooltip />
        <el-table-column label="检查方式" width="86">
          <template #default="{ row }">{{ row.check_method === 'automated' ? '自动' : '人工' }}</template>
        </el-table-column>
        <el-table-column label="必填" width="66">
          <template #default="{ row }">{{ row.is_required ? '是' : '否' }}</template>
        </el-table-column>
        <el-table-column v-if="canManage" label="操作" width="72">
          <template #default="{ row }">
            <el-button link type="danger" @click="removeItem(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="lib-note">
        共 {{ filteredLibItems.length }} 条{{ libSearch ? '（已按关键词过滤）' : '' }}。这里维护的是"模板"：
        需求绑定某个基线后，该基线下全部检查项就是这次要评的条目。
      </div>

      <el-dialog v-model="itemVisible" title="新增检查项" width="480px" append-to-body @open="onItemDialogOpen">
        <el-form :model="itemForm" label-width="90px">
          <el-form-item label="基线类型">
            <el-select v-model="itemForm.baseline_type" style="width: 100%" @change="loadDialogCategories">
              <el-option v-for="t in baselineTypes" :key="t.key" :label="t.label" :value="t.key" />
            </el-select>
          </el-form-item>
          <el-form-item label="控制模块">
            <el-select v-model="itemForm.category_id" style="width: 100%" placeholder="选择控制模块">
              <el-option v-for="c in dialogCategories" :key="c.id" :label="c.name" :value="c.id" />
            </el-select>
          </el-form-item>
          <el-form-item label="检查项"><el-input v-model="itemForm.name" /></el-form-item>
          <el-form-item label="要求"><el-input v-model="itemForm.description" type="textarea" :rows="2" /></el-form-item>
          <el-form-item label="检查方式">
            <el-radio-group v-model="itemForm.check_method">
              <el-radio-button value="manual">人工</el-radio-button>
              <el-radio-button value="automated">自动</el-radio-button>
            </el-radio-group>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="itemVisible = false">取消</el-button>
          <el-button type="primary" @click="saveItemMaster">保存</el-button>
        </template>
      </el-dialog>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { adminApi, baselineApi, systemApi } from '../api'
import { useUserStore } from '../store/user'
// 达标线 + 合规率档位/颜色：与首页共用同一份口径（别再各自写常量）
import { BASELINE_TARGET, RATE_COLORS, rateColor, rateLevel } from '../utils/baseline'
// 人员下拉的 label：英文名 + 中文名（与「指派负责人」同一套实现）
import { userLabel } from '../utils/userLabel'

const store = useUserStore()
const canManage = computed(() => ['admin', 'secops'].includes(store.role))

// ============ 概览 ============
const overview = reactive({ requirement_count: 0, system_count: 0, done_count: 0, bound_items: 0,
  compliance: 0, progress: 0, pass_count: 0, fail_count: 0, na_count: 0, pending_count: 0 })

const assessedTotal = computed(() => overview.pass_count + overview.fail_count + overview.na_count)

const kpis = computed(() => ([
  { label: '基线需求', value: overview.requirement_count, hint: `${overview.done_count} 个已完成` },
  { label: '覆盖系统', value: overview.system_count, hint: '已纳入基线评估' },
  { label: '评估进度', value: `${overview.progress}%`, hint: `${assessedTotal.value}/${overview.bound_items} 已评估` },
  { label: '待评估', value: overview.pending_count, hint: '尚未给出结论' },
  { label: '不通过', value: overview.fail_count, hint: '需要整改', danger: overview.fail_count > 0 },
]))

// 条目构成条（分母 = 应评条目；合规率的分母还要再减掉"不适用"）
const stackSegments = computed(() => {
  const total = Math.max(1, overview.bound_items)
  const raw = [
    { key: 'pass', label: '通过', value: overview.pass_count, color: RATE_COLORS.good },
    { key: 'fail', label: '不通过', value: overview.fail_count, color: RATE_COLORS.bad },
    { key: 'na', label: '不适用', value: overview.na_count, color: RATE_COLORS.mid },
    { key: 'pending', label: '未评估', value: overview.pending_count, color: RATE_COLORS.none },
  ]
  return raw.map((s) => ({ ...s, pct: (s.value / total) * 100 }))
})

// 合规率环（r=52 → 周长 ≈ 326.7）
const RING_R = 52
const RING_C = Number((2 * Math.PI * RING_R).toFixed(2))
/**
 * 环上实际画出的比例。
 * 为什么给 3% 下限：低合规率是常态，2% 时按真实比例画只有一个小点，看起来像"控件坏了"；
 * 给一段最小可见弧长，再把"还差多少"写在下面，读数才是准确的（数字仍是真实值）。
 */
const ringDrawn = computed(() => {
  const c = Math.min(100, Math.max(0, overview.compliance))
  return c <= 0 ? 0 : Math.max(c, 3)
})
const ringOffset = computed(() => RING_C * (1 - ringDrawn.value / 100))
const ringColor = computed(() => rateColor(overview.compliance))

/** 环下的状态词：把百分比翻译成结论，避免"2.2% 是好还是坏"全靠猜。
    档位来自共享口径（rateLevel），所以这里的文案与颜色永远和首页一致。 */
const complianceState = computed(() => {
  if (!overview.bound_items) return '尚未纳入评估'
  switch (rateLevel(overview.compliance)) {
    case 'good': return '已达标'
    case 'mid': return '接近目标'
    case 'none': return '尚未开始'
    default: return '需重点整改'
  }
})

/** 基线名的短写（列表里 5 条基线要排得下，明细放 tooltip）。 */
function shortLabel(label) {
  return String(label || '').replace(/安全基线$/, '').replace(/基线$/, '')
}
function chipTitle(b) {
  return `${b.label} · ${b.total} 项 · 通过 ${b.pass_count} / 不通过 ${b.fail_count} / 不适用 ${b.na_count} / 未评估 ${b.pending_count}`
}

async function loadOverview() {
  try { Object.assign(overview, (await baselineApi.overview()).data) }
  catch { /* 概览失败不影响主列表 */ }
}

// ============ 颜色 ============
// 合规率的档位与颜色统一来自 src/utils/baseline.js（与首页同一份口径）：
//   rateLevel(v) → 'good' | 'mid' | 'bad' | 'none'（可直接当 CSS 类名用）
//   rateColor(v) → 对应色值

/** 单基线进度条颜色：有"不通过"优先标红（要整改），做满了变绿，其余蓝。
    注意与合规率档位不同 —— 这里看的是"做没做"，不是"合不合规"。 */
function barColor(b) {
  if (b.fail_count) return RATE_COLORS.bad
  if (b.progress >= 100) return RATE_COLORS.good
  return '#2563eb'
}

// ============ 类型目录 ============
const baselineTypes = ref([])
async function loadTypes() {
  try { baselineTypes.value = (await baselineApi.types()).data } catch { baselineTypes.value = [] }
}
function labelOf(key) { return baselineTypes.value.find((t) => t.key === key)?.label || key }

// ============ 需求列表 ============
const requirements = ref([])
const loadingReqs = ref(false)
const systems = ref([])
const expanded = ref([])
const detailItems = reactive({})
const detailLoading = reactive({})
const filters = reactive({})
const openBaselines = reactive({})
const autoOpened = {}
let usersLoaded = false
const usersLoading = ref(false)
const picks = ref([])

// 列表筛选：状态 + 关键词（数据本就全量在前端，零后端改动）
const REQ_FILTERS = [
  { value: 'all', label: '全部' },
  { value: 'in_progress', label: '进行中' },
  { value: 'done', label: '已完成' },
  { value: 'late', label: '已逾期' },
]
const reqFilter = ref('all')
const reqSearch = ref('')
const reqFilterCount = computed(() => ({
  all: requirements.value.length,
  in_progress: requirements.value.filter((r) => r.status !== 'done').length,
  done: requirements.value.filter((r) => r.status === 'done').length,
  late: requirements.value.filter((r) => isOverdue(r)).length,
}))
function resetReqFilter() { reqFilter.value = 'all'; reqSearch.value = '' }

const sortedRequirements = computed(() => {
  const q = reqSearch.value.trim().toLowerCase()
  const rows = requirements.value.filter((r) => {
    if (reqFilter.value === 'late') {
      if (!isOverdue(r)) return false
    } else if (reqFilter.value !== 'all' && r.status !== reqFilter.value) {
      return false
    }
    if (q && !`${r.system_name} ${r.name}`.toLowerCase().includes(q)) return false
    return true
  })
  return rows.sort((a, b) => {
    if (a.status !== b.status) return a.status === 'done' ? 1 : -1
    return b.id - a.id
  })
})

async function loadRequirements() {
  loadingReqs.value = true
  try { requirements.value = (await baselineApi.requirements()).data } catch { /* 保留旧数据 */ }
  finally { loadingReqs.value = false }
}

function isOpen(rid) { return expanded.value.includes(rid) }

/** 展开 = 只用一次点击展开第一条基线；不重置用户手动收起的面板（见 ensureDetail）。 */
function toggleExpand(r) {
  if (isOpen(r.id)) { expanded.value = expanded.value.filter((id) => id !== r.id); return }
  expanded.value = [...expanded.value, r.id]
  if (openBaselines[r.id] === undefined) openBaselines[r.id] = []
  if (filters[r.id] === undefined) filters[r.id] = 'all'
  ensureDetail(r.id)
}

async function ensureDetail(rid, force = false) {
  if (!force && detailItems[rid]) return
  detailLoading[rid] = true
  try {
    detailItems[rid] = (await baselineApi.requirementItems(rid)).data
    if (filters[rid] === undefined) filters[rid] = 'all'
    if (!autoOpened[rid]) {
      autoOpened[rid] = true
      const first = groupOf(detailItems[rid])[0]
      openBaselines[rid] = first ? [first.key] : []
    }
  } catch { detailItems[rid] = detailItems[rid] || [] }
  finally { detailLoading[rid] = false }
}

/** 按基线 → 分类两级分组（统计用全量，展示可过滤）。 */
function groupOf(items) {
  const byKey = new Map()
  for (const it of items) {
    if (!byKey.has(it.baseline_type)) {
      byKey.set(it.baseline_type, {
        key: it.baseline_type, label: it.baseline_label || labelOf(it.baseline_type),
        total: 0, stats: { pass: 0, fail: 0, na: 0, pending: 0 }, categories: [],
      })
    }
    const g = byKey.get(it.baseline_type)
    g.total += 1
    g.stats[(it.status in g.stats) ? it.status : 'pending'] += 1
    let cat = g.categories.find((c) => c.name === (it.category_name || '未分类'))
    if (!cat) { cat = { name: it.category_name || '未分类', items: [] }; g.categories.push(cat) }
    cat.items.push(it)
  }
  for (const g of byKey.values()) {
    const assessedN = g.stats.pass + g.stats.fail + g.stats.na
    g.progress = g.total ? Math.round((assessedN / g.total) * 1000) / 10 : 0
    // 颜色规则与列表卡上的 chip 保持一致（有"不通过"优先标红）
    g.barColor = barColor({ fail_count: g.stats.fail, progress: g.progress })
  }
  return [...byKey.values()]
}

function visibleGroups(rid) {
  const f = curFilter(rid)
  const all = detailItems[rid] || []
  if (!all.length) return []
  const shown = f === 'all' ? all
    : all.filter((i) => (f === 'pending' ? i.status === 'pending' : i.status === f))
  if (!shown.length) return []
  const keep = new Set(shown.map((i) => i.item_id))
  return groupOf(all)
    .map((g) => ({ ...g, categories: g.categories
      .map((c) => ({ ...c, items: c.items.filter((i) => keep.has(i.item_id)) }))
      .filter((c) => c.items.length) }))
    .filter((g) => g.categories.length)
}

const FILTERS = [
  { key: 'all', value: 'all', label: '全部' },
  { key: 'pending', value: 'pending', label: '未评估' },
  { key: 'fail', value: 'fail', label: '不通过' },
]
function curFilter(rid) { return filters[rid] || 'all' }
function countOf(rid) {
  const all = detailItems[rid] || []
  return {
    all: all.length,
    pending: all.filter((i) => i.status === 'pending').length,
    fail: all.filter((i) => i.status === 'fail').length,
  }
}
function detailEmptyTip(rid) {
  const all = detailItems[rid] || []
  if (!all.length) return '本需求绑定的基线还没有检查项 —— 到「基线模板库」导入或新增后，再回来评估'
  return '当前筛选下没有条目'
}
function isBaselineOpen(rid, key) { return (openBaselines[rid] || []).includes(key) }
function toggleBaseline(rid, key) {
  const cur = openBaselines[rid] || []
  openBaselines[rid] = cur.includes(key) ? cur.filter((k) => k !== key) : [...cur, key]
}
function assessed(r) { return r.pass_count + r.fail_count + r.na_count }

function initial(name) { return (name || '?').trim().slice(0, 1) }
const AVATAR_BG = ['#e0edff', '#e8f7ee', '#fdeee0', '#f2e8ff', '#e0f5f7']
function avatarBg(name) {
  let h = 0
  for (const ch of String(name || '')) h = (h * 31 + ch.charCodeAt(0)) % 997
  return AVATAR_BG[h % AVATAR_BG.length]
}

// ============ 评估 ============
const resultName = { pending: '未评估', pass: '通过', fail: '不通过', na: '不适用' }
const resultPillClass = (s) => `pill-${s}`
const RESULT_OPTS = [
  { value: 'pass', label: '通过' },
  { value: 'fail', label: '不通过' },
  { value: 'na', label: '不适用' },
]
const rowClass = ({ row }) => `st-${row.status}`
const alwaysPlain = () => 'st-plain'

function canEvaluate(r) {
  return canManage.value || (r.owner_id && r.owner_id === store.userId)
}

async function saveItem(r, row, status) {
  if (row.status === status) return                 // 点当前项不重复提交
  const prev = row.status
  row.status = status
  try {
    await baselineApi.updateRequirementItem(r.id, row.item_id, { status, evidence: row.evidence })
    ElMessage.success('已保存')
    await refreshAfterChange(r.id)
  } catch (e) {
    row.status = prev
    ElMessage.error(e.response?.data?.detail || '保存失败')
  }
}

async function saveEvidence(r, row) {
  if (row.status === 'pending') return               // 没结论时后端不收（状态必填 pass/fail/na）
  try {
    await baselineApi.updateRequirementItem(r.id, row.item_id, { status: row.status, evidence: row.evidence })
    ElMessage.success('备注已保存')
    await refreshAfterChange(r.id, false)
  } catch (e) { ElMessage.error(e.response?.data?.detail || '保存失败') }
}

/** 评估后刷新：行上的进度/合规率 + 概览 + 该需求的条目统计（不动展开状态）。 */
async function refreshAfterChange(rid, reloadItems = true) {
  await Promise.all([
    loadRequirements(),
    loadOverview(),
    reloadItems ? ensureDetail(rid, true) : Promise.resolve(),
  ])
}

// ============ 需求增删改 ============
const reqVisible = ref(false)
const saving = ref(false)
const reqForm = reactive({ id: null, system_id: null, name: '', types: {}, owner_id: null, due_date: null })

const selectedTypeCount = computed(() => baselineTypes.value.filter((t) => reqForm.types[t.key]).length)
const selectedItemCount = computed(() => baselineTypes.value
  .filter((t) => reqForm.types[t.key])
  .reduce((sum, t) => sum + (t.item_count || 0), 0))

function resetReqForm() {
  reqForm.id = null
  reqForm.system_id = null
  reqForm.name = ''
  reqForm.types = Object.fromEntries(baselineTypes.value.map((t) => [t.key, false]))
  reqForm.owner_id = null
  reqForm.due_date = null
}
function toggleType(t) {
  if (!t.item_count) return ElMessage.warning(`「${t.label}」下还没有检查项，先在模板库导入或新增`)
  reqForm.types[t.key] = !reqForm.types[t.key]
}
function openCreate() { resetReqForm(); reqVisible.value = true }
function openEdit(r) {
  reqForm.id = r.id
  reqForm.system_id = r.system_id
  reqForm.name = r.name
  reqForm.types = Object.fromEntries(baselineTypes.value.map((t) => [t.key, r.baseline_types.includes(t.key)]))
  reqForm.owner_id = r.owner_id || null
  reqForm.due_date = r.due_date || null
  reqVisible.value = true
}
function onReqDialogOpen() { if (!reqForm.id) resetReqForm() }

async function submitReq() {
  const keys = baselineTypes.value.filter((t) => reqForm.types[t.key]).map((t) => t.key)
  if (!reqForm.system_id) return ElMessage.warning('请选择系统')
  if (!keys.length) return ElMessage.warning('请至少绑定一个基线')
  saving.value = true
  try {
    const name = (reqForm.name || '').trim()
    if (reqForm.id) {
      // 编辑：名称留空 = 不改（后端把空名视为非法，不能拿它当"清空"用）
      const payload = { baseline_types: keys, owner_id: reqForm.owner_id, due_date: reqForm.due_date }
      if (name) payload.name = name
      await baselineApi.updateRequirement(reqForm.id, payload)
      ElMessage.success('已保存（解绑的基线不再计入分母；原有评估结论保留）')
    } else {
      await baselineApi.createRequirement({
        system_id: reqForm.system_id, baseline_types: keys, name: name || null,
        owner_id: reqForm.owner_id, due_date: reqForm.due_date,
      })
      ElMessage.success('需求已创建，展开即可逐项评估')
    }
    const editedId = reqForm.id
    reqVisible.value = false
    await Promise.all([loadRequirements(), loadOverview(), loadTypes()])
    // 绑定范围变了 → 已展开的那条要重拉，否则表里还是旧范围
    if (editedId && expanded.value.includes(editedId)) await ensureDetail(editedId, true)
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '保存失败')
  } finally { saving.value = false }
}

async function toggleStatus(r) {
  const next = r.status === 'done' ? 'in_progress' : 'done'
  try {
    await baselineApi.updateRequirement(r.id, { status: next })
    ElMessage.success(next === 'done' ? '已标记完成' : '已重新开启')
    await loadRequirements()
  } catch (e) { ElMessage.error(e.response?.data?.detail || '操作失败') }
}

async function removeReq(r) {
  try {
    await ElMessageBox.confirm(
      `删除需求「${r.name}」？已填的评估结论会保留（它们属于系统，不属于这条需求）。`,
      '删除确认', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' })
  } catch { return }
  try {
    await baselineApi.removeRequirement(r.id)
    ElMessage.success('已删除')
    expanded.value = expanded.value.filter((id) => id !== r.id)
    delete detailItems[r.id]
    await Promise.all([loadRequirements(), loadOverview()])
  } catch (e) { ElMessage.error(e.response?.data?.detail || '删除失败') }
}

function isOverdue(r) {
  if (!r.due_date || r.status === 'done') return false
  return r.due_date.slice(0, 10) < new Date().toISOString().slice(0, 10)
}

async function ensureUsers() {
  if (usersLoaded) return
  usersLoaded = true
  usersLoading.value = true
  try {
    picks.value = (await adminApi.userPicks()).data || []
  } catch (e) {
    // 失败不算"已加载"：下次打开弹窗还能重试。
    // 错误必须报出来 —— 空 catch 时接口 403 只会表现为"下拉是空的"，看不出是权限问题。
    usersLoaded = false
    ElMessage.error(e.response?.data?.detail || '加载人员列表失败')
  } finally {
    usersLoading.value = false
  }
}

// ============ 基线模板库 ============
const libVisible = ref(false)
const libType = ref('security_requirement')
const libItems = ref([])
const libLoading = ref(false)
const libSearch = ref('')

const filteredLibItems = computed(() => {
  const q = libSearch.value.trim().toLowerCase()
  if (!q) return libItems.value
  return libItems.value.filter((i) => `${i.name} ${i.description || ''} ${i.category_name || ''}`
    .toLowerCase().includes(q))
})

function openLibrary() { libVisible.value = true }
async function openLibraryData() { await Promise.all([loadTypes(), loadLibItems()]) }
function switchLibType(key) { libType.value = key; loadLibItems() }

async function loadLibItems() {
  libLoading.value = true
  try { libItems.value = (await baselineApi.items({ baseline_type: libType.value })).data }
  catch { libItems.value = [] }
  finally { libLoading.value = false }
}

const itemVisible = ref(false)
const dialogCategories = ref([])
// 不含 severity：界面上不出现「等级」（基线表没有等级依据，团队口径是只看合规率）
const itemForm = reactive({ baseline_type: 'security_requirement', category_id: null, name: '',
  description: '', check_method: 'manual' })

function onItemDialogOpen() {
  itemForm.baseline_type = libType.value
  itemForm.category_id = null
  itemForm.name = ''
  itemForm.description = ''
  itemForm.check_method = 'manual'
  loadDialogCategories()
}
async function loadDialogCategories() {
  try { dialogCategories.value = (await baselineApi.categories(itemForm.baseline_type)).data }
  catch { dialogCategories.value = [] }
}
function openItemDialog() { itemVisible.value = true; onItemDialogOpen() }

async function saveItemMaster() {
  if (!itemForm.category_id) return ElMessage.warning('请选择控制模块')
  if (!itemForm.name || itemForm.name.trim().length < 2) return ElMessage.warning('检查项名称至少 2 个字')
  try {
    await baselineApi.createItem({ ...itemForm })
    ElMessage.success('已添加')
    itemVisible.value = false
    await Promise.all([loadLibItems(), loadTypes()])
  } catch (e) { ElMessage.error(e.response?.data?.detail || '保存失败') }
}

async function removeItem(row) {
  try {
    await ElMessageBox.confirm(
      `删除检查项「${row.name}」？所有系统在该项上的评估结论也会一并删除。`,
      '删除确认', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' })
  } catch { return }
  try {
    await baselineApi.removeItem(row.id)
    ElMessage.success('已删除')
    await Promise.all([loadLibItems(), loadTypes(), loadRequirements(), loadOverview()])
  } catch (e) { ElMessage.error(e.response?.data?.detail || '删除失败') }
}

// ============ 初始化 ============
onMounted(async () => {
  try { systems.value = (await systemApi.list()).data } catch { systems.value = [] }
  await loadTypes()
  resetReqForm()
  await Promise.all([loadRequirements(), loadOverview()])
})
</script>

<style scoped>
/* ===== 设计令牌：整页统一口径（一处改、全局对齐）===== */
.baseline {
  --c-text: #0f172a;
  --c-sub: #475569;
  --c-muted: #94a3b8;
  --c-line: #e8edf5;
  --c-line-soft: #f1f5f9;
  --c-bg-soft: #f8fafc;
  --c-primary: #2563eb;
  --c-primary-soft: #eff6ff;
  --c-pass: #16a34a;
  --c-fail: #dc2626;
  --c-na: #f59e0b;
  --r-card: 14px;
  --r-pill: 999px;
  --sh-1: 0 1px 2px rgba(15, 23, 42, .04);
  --sh-2: 0 10px 24px rgba(15, 23, 42, .08);
  color: var(--c-text);
}
.baseline :deep(*) { box-sizing: border-box; }
.pct { font-size: 14px; font-weight: 600; margin-left: 1px; }
.muted { color: var(--c-muted); font-size: 12px; }
.danger-text { color: var(--c-fail); }

/* ===== 页头 ===== */
.head-l { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.head-sub { margin: 0; font-size: 13px; color: var(--c-muted); }
.head-r { display: flex; gap: 10px; }

/* ===== 概览区 ===== */
.hero {
  display: flex; gap: 26px; align-items: center;
  background: #fff; border: 1px solid var(--c-line); border-radius: var(--r-card);
  padding: 20px 24px; margin-bottom: 10px; box-shadow: var(--sh-1);
}
.hero-ring {
  width: 152px; flex-shrink: 0;
  display: flex; flex-direction: column; align-items: center; gap: 6px;
}
.ring-wrap { position: relative; width: 132px; height: 132px; }
.ring { width: 132px; height: 132px; display: block; }
.ring-bg { fill: none; stroke: #e5eaf2; stroke-width: 10; }
.ring-fg { fill: none; stroke-width: 10; stroke-linecap: round; transition: stroke-dashoffset .6s ease, stroke .3s; }
.ring-center {
  position: absolute; inset: 0; display: flex; flex-direction: column;
  align-items: center; justify-content: center;
}
.ring-num { font-size: 30px; font-weight: 700; line-height: 1.1; font-variant-numeric: tabular-nums; }
.ring-num.good { color: var(--c-pass); }
.ring-num.mid { color: var(--c-na); }
.ring-num.bad { color: var(--c-fail); }
.ring-num.none { color: #94a3b8; }
.ring-lbl { font-size: 12px; color: var(--c-muted); margin-top: 2px; }
.ring-state { font-size: 12.5px; font-weight: 600; }
.ring-state.good { color: var(--c-pass); }
.ring-state.mid { color: var(--c-na); }
.ring-state.bad { color: var(--c-fail); }
.ring-state.none { color: var(--c-muted); }
.ring-target {
  font-size: 11.5px; color: var(--c-muted); background: var(--c-bg-soft);
  border: 1px solid var(--c-line); border-radius: var(--r-pill); padding: 1px 9px;
  font-variant-numeric: tabular-nums;
}

.hero-body { flex: 1; min-width: 0; }
/* 固定 5 列等宽铺满，右侧不留空（截图里那块空白就是这么来的）。
   注意别用 auto-fit：它会按最小宽度拆出 8 条轨道，5 张卡只占前 5 条，右侧照样空。 */
.kpis { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 10px; }
@media (max-width: 1280px) {
  .kpis { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
.kpi {
  background: var(--c-bg-soft);
  border: 1px solid var(--c-line); border-radius: 10px; padding: 10px 12px;
}
.kpi-lbl { font-size: 12px; color: var(--c-muted); }
.kpi-num {
  font-size: 20px; font-weight: 700; line-height: 1.3;
  font-variant-numeric: tabular-nums; margin-top: 2px;
}
.kpi-num.danger { color: var(--c-fail); }
.kpi-hint { font-size: 11px; color: #b6c2d2; margin-top: 1px; }

.stack-wrap { margin-top: 14px; }
.stack-head {
  display: flex; justify-content: space-between; align-items: baseline;
  font-size: 12px; color: var(--c-sub); margin-bottom: 6px;
}
.stack-total { color: var(--c-muted); }
.stack-bar {
  display: flex; height: 10px; border-radius: var(--r-pill);
  overflow: hidden; background: var(--c-line-soft);
}
.stack-bar .seg {
  display: flex; align-items: center; justify-content: center;
  overflow: hidden; transition: width .5s ease;
}
/* 段够宽时把数字写在段里，省掉"看图例对照颜色"这一步 */
.stack-bar .seg b { font-size: 10px; font-weight: 700; color: #fff; line-height: 1; }
.legend { display: flex; gap: 16px; flex-wrap: wrap; margin-top: 8px; font-size: 12px; color: var(--c-sub); }
.legend .lg { display: inline-flex; align-items: center; gap: 6px; }
.legend i { width: 8px; height: 8px; border-radius: 2px; display: inline-block; }
.legend b { font-variant-numeric: tabular-nums; margin-left: 2px; }
.hero-note { margin: 0 0 14px 2px; font-size: 12px; color: #b6c2d2; }

/* ===== 列表卡 ===== */
.list-card {
  background: #fff; border: 1px solid var(--c-line); border-radius: var(--r-card);
  box-shadow: var(--sh-1); overflow: hidden;
}
.list-head {
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  padding: 12px 18px; border-bottom: 1px solid var(--c-line-soft);
}
.list-title { font-weight: 600; }
.list-hint { font-size: 12px; color: var(--c-muted); }
.list-tools { margin-left: auto; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.filter-empty { padding: 26px 18px; text-align: center; color: var(--c-muted); font-size: 13px; }

/* 骨架 */
.skeleton { padding: 16px 18px; }
.sk-row { padding: 10px 0; border-bottom: 1px dashed var(--c-line-soft); }
.sk-row:last-child { border-bottom: none; }
.sk-inner { display: flex; align-items: center; gap: 14px; }

/* 空状态 */
.empty { text-align: center; padding: 46px 20px 52px; }
.empty-art { width: 64px; height: 64px; margin-bottom: 12px; }
.empty-title { font-size: 15px; font-weight: 600; margin-bottom: 6px; }
.empty-desc { font-size: 13px; color: var(--c-muted); line-height: 1.9; margin-bottom: 14px; }

/* ===== 需求卡 ===== */
.req { border-bottom: 1px solid var(--c-line-soft); transition: background .18s; }
.req:last-child { border-bottom: none; }
.req-top {
  display: flex; align-items: center; gap: 14px; padding: 14px 18px;
  cursor: pointer; transition: background .18s;
  /* 窄窗口/缩放 125% 时让右侧信息整体换行，避免把系统名与基线 chip 挤扁 */
  flex-wrap: wrap;
}
.req-top:hover { background: #fbfcfe; }
.req.open .req-top { background: #fbfdff; }

.chev {
  width: 0; height: 0; flex-shrink: 0;
  border-left: 5px solid #c3ccd9; border-top: 4px solid transparent; border-bottom: 4px solid transparent;
  transition: transform .2s ease;
}
.chev.open { transform: rotate(90deg); border-left-color: var(--c-primary); }
.chev.sm { border-left-width: 4px; border-top-width: 3.5px; border-bottom-width: 3.5px; }

.avatar {
  width: 34px; height: 34px; border-radius: 10px; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  font-size: 15px; font-weight: 700; color: #334155;
}

.req-main { flex: 1; min-width: 0; }
.req-line1 { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.sys { font-size: 14px; font-weight: 600; }
.req-name { font-size: 13px; color: var(--c-sub); }
.req-line2 { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 8px; }

.pill {
  display: inline-block; padding: 1px 8px; border-radius: var(--r-pill);
  font-size: 12px; line-height: 18px; border: 1px solid transparent;
}
.pill-run { background: var(--c-primary-soft); color: var(--c-primary); border-color: #dbe8ff; }
.pill-done { background: #eafaf0; color: #15803d; border-color: #d3f0de; }
.pill-late { background: #fef2f2; color: var(--c-fail); border-color: #fbdcdc; }
.pill-pass { background: #eafaf0; color: #15803d; border-color: #d3f0de; }
.pill-fail { background: #fef2f2; color: var(--c-fail); border-color: #fbdcdc; }
.pill-na { background: #fff8ec; color: #b45309; border-color: #fbeacb; }
.pill-pending { background: #f4f6f9; color: #64748b; border-color: #e8edf5; }

/* 单基线 chip：短名 + 百分比 + 不通过数；进度做成 chip 底部 2px 细线，省下横向空间 */
.bchip {
  position: relative; overflow: hidden;
  display: inline-flex; align-items: baseline; gap: 6px;
  background: #f8fafc; border: 1px solid var(--c-line);
  border-radius: 8px; padding: 3px 9px 5px; font-size: 11.5px; color: var(--c-sub);
}
.bchip.zero { opacity: .55; }
.bchip-name { font-weight: 600; color: #334155; }
.bchip-pct { font-variant-numeric: tabular-nums; color: #334155; }
.bchip-pct.zero { color: var(--c-muted); font-weight: 400; }
.bchip-fail { color: var(--c-fail); }
.bchip-line { position: absolute; left: 0; bottom: 0; height: 2px; transition: width .4s ease; }

.metric { width: 86px; flex-shrink: 0; text-align: right; }
.metric-num { font-size: 19px; font-weight: 700; font-variant-numeric: tabular-nums; line-height: 1.2; }
.metric-num.good { color: var(--c-pass); }
.metric-num.mid { color: var(--c-na); }
.metric-num.bad { color: var(--c-fail); }
.metric-num.none { color: #cbd5e1; }
/* 0% 小一档 + 中性色：一屏里"还没做"的行不该和"有问题"的行抢视线 */
.metric-num.zero { font-size: 15px; color: #cbd5e1; }
.metric-lbl { font-size: 11px; color: var(--c-muted); margin-top: 2px; }
.metric-bar { width: 190px; }
.track { height: 6px; border-radius: var(--r-pill); background: #eef2f7; overflow: hidden; }
.track i { display: block; height: 100%; border-radius: var(--r-pill); background: linear-gradient(90deg, #60a5fa, #2563eb); transition: width .4s ease; }

.who { width: 128px; flex-shrink: 0; font-size: 13px; color: var(--c-sub); }
.who-name { font-weight: 500; }
.who-due { font-size: 12px; color: var(--c-muted); margin-top: 2px; }
.who-due.late { color: var(--c-fail); }
/* 主操作常显、次级操作悬停才出：一屏几十个按钮常亮会盖过数据本身 */
.row-actions { flex-shrink: 0; white-space: nowrap; display: flex; align-items: center; }
.row-actions .secondary { opacity: 0; transition: opacity .18s; }
.req-top:hover .row-actions .secondary,
.req-top:focus-within .row-actions .secondary { opacity: 1; }

/* ===== 展开详情 ===== */
.req-detail { background: #fbfdff; border-top: 1px solid var(--c-line-soft); padding: 14px 18px 6px 66px; }
.detail-bar { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; margin-bottom: 12px; }
.detail-title { font-size: 13px; font-weight: 600; }
.detail-tip { font-size: 12px; color: var(--c-muted); }

.seg-filter { display: inline-flex; background: #eef2f7; border-radius: var(--r-pill); padding: 2px; }
.seg-filter button {
  border: 0; background: transparent; cursor: pointer; font-size: 12px; color: var(--c-sub);
  padding: 4px 12px; border-radius: var(--r-pill); transition: all .16s;
}
.seg-filter button.on { background: #fff; color: var(--c-primary); box-shadow: var(--sh-1); font-weight: 600; }
.seg-filter b { font-variant-numeric: tabular-nums; margin-left: 2px; }

.bl-panel { border: 1px solid var(--c-line); border-radius: 12px; background: #fff; margin-bottom: 10px; overflow: hidden; }
.bl-panel-head {
  display: flex; align-items: center; gap: 12px; padding: 11px 14px;
  cursor: pointer; background: #fff; transition: background .16s;
}
.bl-panel-head:hover { background: var(--c-bg-soft); }
.bl-name { font-size: 13px; font-weight: 600; }
.bl-total { font-size: 12px; color: var(--c-muted); }
.bl-track { width: 90px; height: 5px; border-radius: var(--r-pill); background: #eef2f7; overflow: hidden; }
.bl-track i { display: block; height: 100%; border-radius: var(--r-pill); transition: width .4s ease; }
.bl-counts { margin-left: auto; display: flex; gap: 12px; font-size: 12px; }
.bl-counts .c { color: var(--c-muted); }
.bl-counts .c.pass { color: #15803d; }
.bl-counts .c.fail { color: var(--c-fail); }
.bl-counts .c.na { color: #b45309; }
.bl-panel-body { padding: 4px 14px 12px; border-top: 1px solid var(--c-line-soft); }

.cat { margin-top: 12px; }
.cat-head { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.cat-name { font-size: 12.5px; font-weight: 600; color: #334155; }
.cat-cnt {
  font-size: 11px; color: var(--c-muted); background: var(--c-bg-soft);
  border: 1px solid var(--c-line); border-radius: var(--r-pill); padding: 0 6px; line-height: 16px;
}
.detail-empty { font-size: 13px; color: var(--c-muted); padding: 12px 0 18px; }

/* 三段式结果控件：点一下即保存，比下拉少两次交互 */
.seg { display: inline-flex; gap: 4px; }
.seg button {
  border: 1px solid var(--c-line); background: #fff; color: #64748b; cursor: pointer;
  font-size: 12px; padding: 2px 9px; border-radius: 8px; transition: all .16s; line-height: 20px;
}
.seg button:hover { border-color: #c7d7f5; color: var(--c-primary); }
.seg button.on.pass { background: #eafaf0; border-color: #86efac; color: #15803d; font-weight: 600; }
.seg button.on.fail { background: #fef2f2; border-color: #fca5a5; color: var(--c-fail); font-weight: 600; }
.seg button.on.na { background: #fff8ec; border-color: #fcd34d; color: #b45309; font-weight: 600; }

/* 表格：紧凑、行首状态色条、表头浅底 */
.item-table :deep(.el-table__header th) {
  background: var(--c-bg-soft); color: #64748b; font-weight: 600; font-size: 12px;
}
.item-table :deep(.el-table__cell) { padding: 6px 0; font-size: 13px; }
.item-table :deep(.el-table__row.st-pass td:first-child) { box-shadow: inset 3px 0 0 var(--c-pass); }
.item-table :deep(.el-table__row.st-fail td:first-child) { box-shadow: inset 3px 0 0 var(--c-fail); }
.item-table :deep(.el-table__row.st-na td:first-child) { box-shadow: inset 3px 0 0 var(--c-na); }

/* ===== 弹窗 ===== */
.req-form { padding-right: 6px; }
.form-tip { font-size: 12px; color: var(--c-muted); }
.pick-list { display: flex; flex-direction: column; gap: 6px; width: 100%; }
.pick {
  display: flex; align-items: center; gap: 10px; padding: 9px 12px;
  border: 1px solid var(--c-line); border-radius: 10px; cursor: pointer; transition: all .16s;
}
.pick:hover { border-color: #c7d7f5; background: #fbfdff; }
.pick.on { border-color: var(--c-primary); background: var(--c-primary-soft); }
.pick.zero { opacity: .62; cursor: not-allowed; background: var(--c-bg-soft); }
.pick-tick {
  width: 16px; height: 16px; border-radius: 5px; border: 1px solid #cbd5e1; background: #fff;
  font-size: 11px; line-height: 14px; text-align: center; color: #fff; flex-shrink: 0;
}
.pick.on .pick-tick { background: var(--c-primary); border-color: var(--c-primary); }
.pick-name { font-size: 13px; font-weight: 500; }
.pick-cnt { font-size: 12px; color: var(--c-muted); margin-left: auto; }
.pick-zero { font-size: 11px; color: var(--c-fail); margin-left: 8px; }
.pick-sum { font-size: 12px; color: var(--c-sub); margin-top: 8px; }
.pick-sum b { font-variant-numeric: tabular-nums; color: var(--c-text); }

/* ===== 模板库抽屉 ===== */
.lib-head {
  display: flex; align-items: center; justify-content: space-between;
  gap: 12px; flex-wrap: wrap; margin-bottom: 14px;
}
.lib-types { display: inline-flex; gap: 6px; flex-wrap: wrap; }
.lib-tab {
  border: 1px solid var(--c-line); background: #fff; cursor: pointer;
  border-radius: var(--r-pill); padding: 5px 14px; font-size: 13px; color: var(--c-sub);
  transition: all .16s;
}
.lib-tab:hover { border-color: #c7d7f5; color: var(--c-primary); }
.lib-tab.on { background: var(--c-primary); border-color: var(--c-primary); color: #fff; font-weight: 600; }
.lib-tab b { font-variant-numeric: tabular-nums; margin-left: 6px; opacity: .85; font-weight: 600; }
.lib-tools { display: flex; gap: 10px; align-items: center; }
.lib-note { font-size: 12px; color: var(--c-muted); margin-top: 12px; line-height: 1.8; }
</style>
