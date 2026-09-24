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
      <!-- 口径说明从下方那行常驻文字挪到这里：需要时悬停可见，不需要时不占屏幕 -->
      <div class="hero-ring"
           title="合规率 = 通过 ÷ 应评（「不适用」也计入分母）；只统计各需求已绑定的基线，同一检查项在多条需求里只算一次">

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

    <!-- ===== 需求列表 ===== -->
    <section class="list-card">
      <div class="list-head">
        <span class="list-title">基线需求</span>
        <div class="list-tools">
          <div class="seg-filter">
            <button v-for="f in REQ_FILTERS" :key="f.value"
                    :class="{ on: reqFilter === f.value, zero: !reqFilterCount[f.value] }"
                    @click="reqFilter = f.value">
              {{ f.label }} <b>{{ reqFilterCount[f.value] }}</b>
            </button>
          </div>
          <el-input v-model="reqSearch" placeholder="搜索系统 / 需求名" clearable style="width: 196px" />
          <!-- 到期提醒：系统每天 9:00 自动发一次（见 backend/app/baseline_reminder.py），
               这里用于补发或提前提醒 —— 去重按天记，手动发过当天不会再自动发一遍 -->
          <el-button v-if="canManage" size="small" plain :loading="dueBusy"
                     title="给「即将到期 / 已逾期」的需求负责人补发飞书提醒（每天每人最多一条）"
                     @click="notifyDue">到期提醒</el-button>
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
      <article v-for="r in pagedRequirements" :key="r.id" class="req" :class="{ open: isOpen(r.id) }">
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
              <!-- 这里原本有个「已评完 · 标记完成」的提示徽标：与右侧操作区里的「标记完成」
                   是**同一个动作的第二个入口**（页面上出现两个"标记完成"），已去掉。
                   现在改由后端在全部评完时**自动收口**（见 _autoclose_if_done），
                   行上就只留这一个状态词：进行中 / 已完成。 -->
            </div>
            <div class="req-line2">
              <!-- 列表只回答"哪条线有问题"：短名 + 百分比 + 不通过数（明细放 tooltip 与展开区） -->
              <!-- 按反馈：所有绑定基线**全部平铺**，不折叠、不做 +N -->
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
            <!-- 两个百分比并排最容易混：这里把口径写进悬停说明 ——
                 合规率 = 做对了多少，进度 = 做了多少 -->
            <div class="metric-num" :class="r.compliance > 0 ? rateLevel(r.compliance) : 'zero'"
                 title="合规率 = 通过 ÷ 应评（含「不适用」）—— 做对了多少">
              {{ r.compliance }}<span class="pct">%</span>
            </div>
            <div class="metric-lbl">合规率</div>
          </div>

          <div class="metric metric-bar">
            <div class="track" title="评估进度 = 有结论的条目 ÷ 应评 —— 做了多少">
              <i :style="{ width: r.progress + '%' }" />
            </div>
            <div class="metric-lbl" title="评估进度 = 有结论的条目 ÷ 应评 —— 做了多少">
              已评估 {{ assessed(r) }}/{{ r.bound_items }}
            </div>
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
              <!-- 「缺说明」只在真有这种条目时出现（v-show 不用 v-if：v-if 与 v-for 同元素，
                   Vue 会给出"两者同时用很危险"的告警）——没有它时多一个 0 的 chip 只是噪音 -->
              <button v-for="f in FILTERS" :key="f.value" v-show="f.key !== 'nofix' || countOf(r.id).nofix"
                      :class="{ on: curFilter(r.id) === f.value }"
                      @click="filters[r.id] = f.value">
                {{ f.label }} <b>{{ countOf(r.id)[f.key] }}</b>
              </button>
            </div>
            <!-- 未评估的条目分散在几个基线里：一键只看未评估，并跳到下一组 -->
            <button v-if="canEvaluate(r) && countOf(r.id).pending" class="detail-jump"
                    title="只看未评估的，并跳到下一组未评估"
                    @click="jumpNextPending(r)">
              跳到下一个未评估
            </button>
            <!-- 导出 = 能送审的台账：结论 + 依据 + 评估人 + 时间，一次一份需求 -->
            <button class="detail-jump" title="导出本需求全部条目的结论与依据为 CSV（留档 / 送审用）"
                    @click="exportDetail(r)">导出 CSV</button>
            <!-- 只在只读时提示原因；可评估的人点一下就知道，不需要这行字 -->
            <span v-if="!canEvaluate(r)" class="detail-tip">只读：你不是本需求负责人</span>
          </div>

          <div v-if="!detailLoading[r.id] && !visibleGroups(r.id).length" class="detail-empty">
            {{ detailEmptyTip(r.id) }}
          </div>

          <div v-for="g in visibleGroups(r.id)" :key="g.key" class="bl-panel"
               :class="{ collapsed: !isBaselineOpen(r.id, g.key) }" :data-key="`${r.id}-${g.key}`">
            <div class="bl-panel-head" @click="toggleBaseline(r.id, g.key)">
              <span class="chev sm" :class="{ open: isBaselineOpen(r.id, g.key) }" />
              <span class="bl-name">{{ g.label }}</span>
              <span class="bl-total">{{ g.total }} 项</span>
              <span class="bl-track"><i :style="{ width: g.progress + '%', background: g.barColor }" /></span>
              <!-- 一组几十上百项、绝大多数是「通过」：一键填完未评估的那些 -->
              <button v-if="canEvaluate(r) && g.stats.pending" class="bl-bulk"
                      :disabled="bulkBusy === r.id + '-' + g.key"
                      title="只填「未评估」的；已有结论（尤其「不通过」）不会被覆盖"
                      @click.stop="bulkPass(r, g, r.id + '-' + g.key)">
                全部通过 {{ g.stats.pending }}
              </button>
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
                  <el-table-column prop="item_description" label="要求" min-width="300"
                                   show-overflow-tooltip class-name="cell-wrap2" />
                  <!-- 「检查方式」列去掉了：全库只有"人工"一个值，"自动"没有任何代码在读
                       （后端已显式拒绝该选项）→ 留着反而像"漏配了自动项" -->
                  <el-table-column label="评估结果" width="224">
                    <template #default="{ row }">
                      <div v-if="canEvaluate(r)" class="seg">
                        <button v-for="o in RESULT_OPTS" :key="o.value" :class="[o.value, { on: row.status === o.value }]"
                                @click="saveItem(r, row, o.value)">{{ o.label }}</button>
                        <!-- 撤销：只在这条已有结论时出现，且悬停该行才显形（平时不抢视线）——
                             手滑点错不该只能被另一个结论顶替 -->
                        <button v-if="row.status !== 'pending'" class="seg-undo"
                                title="重置为未评估（结论与说明一并清空）"
                                @click="resetItem(r, row)">撤销</button>
                      </div>
                      <span v-else class="pill" :class="resultPillClass(row.status)">{{ resultName[row.status] }}</span>
                      <!-- 存量数据里"不通过却没写说明"的，红字标出来（新提交已被后端拦住） -->
                      <span v-if="missingWhy(row)" class="miss"
                            title="「不通过」必须写明整改要求 / 判定依据 / 证据链接">缺说明</span>
                    </template>
                  </el-table-column>
                  <el-table-column label="证据 / 备注" min-width="190">
                    <template #default="{ row }">
                      <el-input v-if="canEvaluate(r)" v-model="row.evidence" size="small"
                                :class="{ 'need-why': missingWhy(row) }"
                                :placeholder="row.status === 'pending' ? '先选评估结果'
                                  : (missingWhy(row) ? '不通过必须写依据' : '补充证据或说明')"
                                :disabled="row.status === 'pending'" @blur="saveEvidence(r, row)" />
                      <span v-else class="muted">
                        <b v-if="missingWhy(row)" class="miss">缺说明</b>{{ row.evidence || '—' }}
                      </span>
                    </template>
                  </el-table-column>
                </el-table>
              </div>
            </div>
          </div>
        </div>
      </article>

      <!-- 一屏 4 条，其余翻页：与「漏洞提交」页的分页条同一套（右对齐 + 可跳页） -->
      <div v-if="sortedRequirements.length > REQ_PAGE_SIZE" class="req-pager">
        <el-pagination
          v-model:current-page="reqPage"
          :page-size="REQ_PAGE_SIZE"
          :total="sortedRequirements.length"
          :pager-count="7"
          layout="total, prev, pager, next, jumper"
          background
        />
      </div>
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
          <!-- 控制模块维护：模块名是给人看的，建错了总得能改（删除有检查项时会被拦住） -->
          <el-button v-if="canManage" plain @click="openCatManage">控制模块</el-button>
          <el-button v-if="canManage" type="primary" plain @click="openItemDialog">新增检查项</el-button>
        </div>
      </div>

      <el-table :data="filteredLibItems" v-loading="libLoading" size="small"
                :row-class-name="alwaysPlain" :span-method="libSpan" class="item-table">
        <!-- 前两列定宽 + 「要求」独占剩余宽度：
             要求是这一屏最该读全的内容（长句多），此前它和「检查项」平分弹性宽度，
             结果整段被截成"...",还得逐行 hover 看 tooltip。定宽前两列后，要求列左移约 120px 且更宽。 -->
        <el-table-column prop="category_name" label="控制模块" width="128" />
        <el-table-column prop="name" label="检查项" width="200" show-overflow-tooltip />
        <el-table-column prop="description" label="要求" min-width="320"
                         show-overflow-tooltip class-name="cell-wrap2" />
        <!-- 「检查方式」列去掉了：全库只有"人工"一个值，"自动"没有任何代码在读
             （后端已显式拒绝该选项）→ 留着反而像"漏配了自动项" -->
        <!-- 「必填」列去掉了：全库只有"是"一个值（is_required 没有任何业务逻辑在读） -->
        <el-table-column v-if="canManage" label="操作" width="112">
          <template #default="{ row }">
            <!-- 编辑不影响已有评估结论；删除会（确认弹窗里有提示）→ 能改就别删 -->
            <el-button link type="primary" @click="openItemEdit(row)">编辑</el-button>
            <el-button link type="danger" @click="removeItem(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="lib-note">
        共 {{ filteredLibItems.length }} 条{{ libSearch ? '（已按关键词过滤）' : '' }}。这里维护的是"模板"：
        需求绑定某个基线后，该基线下全部检查项就是这次要评的条目。
      </div>

      <el-dialog v-model="itemVisible" :title="itemForm.id ? '编辑检查项' : '新增检查项'" width="480px" append-to-body @open="onItemDialogOpen">
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
          <!-- 「检查方式」表单项去掉了：只有"人工"一个值可选，选了也没有代码去执行自动扫描
               （后端已显式拒绝 automated）→ 留着等于对着界面承诺一个不存在的自动化 -->
        </el-form>
        <template #footer>
          <el-button @click="itemVisible = false">取消</el-button>
          <el-button type="primary" @click="saveItemMaster">保存</el-button>
        </template>
      </el-dialog>

      <!-- 控制模块维护：改名 / 删除（模块名是给人看的，写错必须能修）。
           删除只在模块下**没有检查项**时允许 —— 删条目会连带删掉各系统的评估结论，
           所以这里也会先把数量摆出来，让人自己决定这些条目去哪。 -->
      <el-dialog v-model="catVisible" title="控制模块" width="560px" append-to-body>
        <div class="cat-tools">
          <el-input v-model="newCatName" placeholder="新模块名称，如「接口安全」" clearable
                    style="width: 240px" @keyup.enter="addCategory" />
          <el-button type="primary" plain :disabled="!newCatName.trim()" @click="addCategory">新增</el-button>
          <span class="muted">当前基线：{{ labelOf(libType) }}</span>
        </div>
        <el-table :data="libCategories" v-loading="catLoading" size="small"
                  :row-class-name="alwaysPlain" class="item-table">
          <el-table-column prop="name" label="名称" min-width="180" />
          <el-table-column label="检查项" width="80">
            <template #default="{ row }">
              <span :class="{ muted: !catItemCount(row.id) }">{{ catItemCount(row.id) }}</span>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="130">
            <template #default="{ row }">
              <el-button link type="primary" @click="renameCategory(row)">改名</el-button>
              <el-button link type="danger" @click="removeCategory(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-dialog>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, reactive, ref, watch } from 'vue'
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

// 只留 3 个盒子：原来的「待评估」「不通过」与下方「范围内条目构成」那条分段条**完全重复**
// （同一个数同屏报两次，只会让人多看两眼）；构成条里各自项数已经写明了。
const kpis = computed(() => ([
  { label: '基线需求', value: overview.requirement_count, hint: `${overview.done_count} 个已完成` },
  { label: '覆盖系统', value: overview.system_count, hint: '已纳入基线评估' },
  { label: '评估进度', value: `${overview.progress}%`, hint: `${assessedTotal.value}/${overview.bound_items} 已评估` },
]))

// 条目构成条（分母 = 应评条目；合规率的分母也是它 —— 「不适用」同样计入）
const stackSegments = computed(() => {
  const total = Math.max(1, overview.bound_items)
  const raw = [
    { key: 'pass', label: '通过', value: overview.pass_count, color: RATE_COLORS.good },
    { key: 'fail', label: '不通过', value: overview.fail_count, color: RATE_COLORS.bad },
    // 「不适用」用中性灰：它是「这条不适用」，不是「接近目标」（原来借用 mid 的橙色会读错）
    { key: 'na', label: '不适用', value: overview.na_count, color: '#94a3b8' },
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

// 环下原本还有一行状态词（需重点整改 / 接近目标 / 已达标…）：按反馈去掉 ——
// 同一件事下面那行「目标 80% · 还差 59.8pt」已经说清，再加一个形容词只是重复。
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

const bulkBusy = ref('')          // 正在批量处理的那一组（禁用按钮 + 防重复点）
const pendingCursor = reactive({})  // 需求 id → 上次跳到哪条基线（轮流跳，不是永远第一组）

/** 「全部通过」：后端默认只填未评估的（已有结论不覆盖），这里只做确认 + 刷新。 */
async function bulkPass(r, g, key) {
  const n = g.stats.pending
  if (!n) return
  try {
    await ElMessageBox.confirm(
      `把「${g.label}」里 ${n} 个「未评估」的检查项全部标记为「通过」？` +
      '\n\n已有结论的（尤其「不通过」）不会被覆盖，之后仍可逐条修改。',
      '批量评估', { type: 'warning', confirmButtonText: '全部标记通过', cancelButtonText: '取消' })
  } catch { return }
  bulkBusy.value = key
  try {
    const { data } = await baselineApi.bulkResult(r.id, { baseline_type: g.key, status: 'pass' })
    ElMessage.success(`已标记 ${data.changed} 项通过` +
      (data.skipped ? `，跳过已有结论 ${data.skipped} 项` : ''))
    // 必须与单条评估走同一条刷新路径：行上的合规率 / 已评估数来自 /requirements 列表，
    // 只刷明细和概览的话，那两个数字会一直是旧的（用户反馈"更新之后没有实时刷新"）。
    await refreshAfterChange(r.id, true)
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || '批量评估失败')
  } finally { bulkBusy.value = '' }
}

/** 跳到"下一组未评估"：展开明细 → 只看未评估 → 展开下一组基线并滚动过去。 */
async function jumpNextPending(r) {
  if (!isOpen(r.id)) toggleExpand(r)
  await ensureDetail(r.id)
  const pend = (detailItems[r.id] || []).filter((i) => i.status === 'pending')
  if (!pend.length) {
    ElMessage.success('这条需求已经没有未评估的条目了')
    return
  }
  const keys = [...new Set(pend.map((i) => i.baseline_type))]
  const cur = pendingCursor[r.id]
  const next = keys[(Math.max(0, keys.indexOf(cur)) + (cur ? 1 : 0)) % keys.length]
  pendingCursor[r.id] = next
  filters[r.id] = 'pending'
  openBaselines[r.id] = [next]
  await nextTick()
  document.querySelector(`.bl-panel[data-key="${r.id}-${next}"]`)
    ?.scrollIntoView({ behavior: 'smooth', block: 'center' })
}

// （曾有一版把「已完成且无问题」的基线折成 +N 小标签，按反馈去掉了 —— 全部平铺更直观。）

// ============ 类型目录 ============
const baselineTypes = ref([])
async function loadTypes() {
  try { baselineTypes.value = (await baselineApi.types()).data } catch { baselineTypes.value = [] }
}
function labelOf(key) { return baselineTypes.value.find((t) => t.key === key)?.label || key }

// ============ 需求列表 ============
const requirements = ref([])
const loadingReqs = ref(false)
// 列表分页：一屏固定 4 条 —— 需求只会越建越多，一页堆十几个会把「哪条有问题」淹掉
const REQ_PAGE_SIZE = 4
const reqPage = ref(1)

const systems = ref([])
const expanded = ref([])
const detailItems = reactive({})
const detailLoading = reactive({})
const filters = reactive({})
const openBaselines = reactive({})
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

/** 当前页渲染的需求。分页只影响渲染 —— 筛选计数、概览统计仍基于全量。 */
const pagedRequirements = computed(() => {
  const start = (reqPage.value - 1) * REQ_PAGE_SIZE
  return sortedRequirements.value.slice(start, start + REQ_PAGE_SIZE)
})
// 换筛选/搜索就回到第 1 页；数据变少（删需求/改完成状态）时把页码收回来，别停在空白页
watch([() => reqFilter.value, () => reqSearch.value], () => { reqPage.value = 1 })
watch(() => sortedRequirements.value.length, () => {
  const maxPage = Math.max(1, Math.ceil(sortedRequirements.value.length / REQ_PAGE_SIZE))
  if (reqPage.value > maxPage) reqPage.value = maxPage
})

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
    // 展开需求时**只列基线面板，不自动展开其中任何一条**：一上来就把几十上百个条目铺开，
    // 会盖掉"这条需求一共绑了几条基线、各自进度/不通过多少"这个更该先看到的信息；
    // 谁先做、按什么顺序做，让评估的人自己点开（「跳到下一个未评估」也会按需展开它要去的那组）。
    // 顺带修掉一个竞争：下面 jumpNextPending 会先设好 openBaselines = [目标组]，
    // 若这里再"自动展开第一条"，异步回来时会把用户正要跳过去的那组覆盖掉。
    if (openBaselines[rid] === undefined) openBaselines[rid] = []
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
    : all.filter((i) => (f === 'pending' ? i.status === 'pending'
      : f === 'nofix' ? missingWhy(i) : i.status === f))
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
  // 「不通过却没写说明」单独可筛：存量数据里这是最该先收拾的一批
  { key: 'nofix', value: 'nofix', label: '缺说明' },
]
function curFilter(rid) { return filters[rid] || 'all' }
function countOf(rid) {
  const all = detailItems[rid] || []
  return {
    all: all.length,
    pending: all.filter((i) => i.status === 'pending').length,
    fail: all.filter((i) => i.status === 'fail').length,
    nofix: all.filter(missingWhy).length,
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
/** 「不通过」却没写说明 = 只有判定、没有依据。新提交已被后端拦住，这个判定是给存量数据用的。 */
function missingWhy(row) {
  return row.status === 'fail' && !(row.evidence || '').trim()
}
const rowClass = ({ row }) => `st-${row.status}`
const alwaysPlain = () => 'st-plain'


function canEvaluate(r) {
  return canManage.value || (r.owner_id && r.owner_id === store.userId)
}

async function saveItem(r, row, status) {
  if (row.status === status) return                 // 点当前项不重复提交
  const prev = row.status
  let evidence = row.evidence
  // 「不通过」必须带依据（后端同样会拦）：干脆在这一刻把依据要到手 ——
  // 与其事后在一张长表里追着补，不如点下去的时候就问清楚。用户取消 = 什么都不改。
  if (status === 'fail' && !(evidence || '').trim()) {
    try {
      const { value } = await ElMessageBox.prompt(
        '写明整改要求、判定依据或证据链接（会出现在导出的台账里）',
        '「不通过」需说明依据',
        { confirmButtonText: '保存', cancelButtonText: '取消',
          inputPlaceholder: '如：接口未鉴权，可越权读取他人数据；要求 9/30 前完成整改',
          inputValidator: (v) => (v && v.trim() ? true : '说明不能为空') })
      evidence = value.trim()
    } catch { return }                              // 取消 → 状态与说明都不动
  }
  row.status = status
  row.evidence = evidence
  try {
    await baselineApi.updateRequirementItem(r.id, row.item_id, { status, evidence })
    ElMessage.success('已保存')
    await refreshAfterChange(r.id)
  } catch (e) {
    row.status = prev
    ElMessage.error(e.response?.data?.detail || '保存失败')
  }
}

/** 撤销结论（回到未评估）：后端会把说明 / 评估人 / 评估时间一并清空。 */
async function resetItem(r, row) {
  try {
    await ElMessageBox.confirm('重置为未评估？该条的结论与说明会一并清空。', '撤销评估结果',
      { confirmButtonText: '重置', cancelButtonText: '取消', type: 'warning' })
  } catch { return }
  const prev = { status: row.status, evidence: row.evidence }
  row.status = 'pending'
  row.evidence = ''
  try {
    await baselineApi.updateRequirementItem(r.id, row.item_id, { status: 'pending' })
    ElMessage.success('已重置为未评估')
    await refreshAfterChange(r.id)
  } catch (e) {
    Object.assign(row, prev)
    ElMessage.error(e.response?.data?.detail || '重置失败')
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

/** 导出本需求的评估明细（CSV）。后端生成 + 带 BOM，这里只负责把 blob 存成文件。 */
async function exportDetail(r) {
  try {
    const res = await baselineApi.exportRequirement(r.id)
    const blob = new Blob([res.data], { type: res.data.type || 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const ts = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14)
    // 文件名带上系统名便于辨认（去掉不能进文件名的字符；中文名浏览器自己能处理）
    const who = String(r.system_name || 'system').replace(/[\\/:*?"<>|]/g, '')
    a.download = `baseline-${who}-${r.id}-${ts}.csv`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    ElMessage.success('已导出评估明细 CSV')
  } catch (e) {
    // 出错时后端返回的是 JSON 而不是文件流，blob 里读不出 detail → 给通用提示
    ElMessage.error(e.response?.data?.detail || '导出失败')
  }
}

/** 评估后刷新：行上的进度/合规率 + 概览 + 该需求的条目统计（不动展开状态）。 */
async function refreshAfterChange(rid, reloadItems = true) {
  await Promise.all([
    loadRequirements(),
    loadOverview(),
    reloadItems ? ensureDetail(rid, true) : Promise.resolve(),
  ])
}

// ============ 到期提醒（手动补发）============
const dueBusy = ref(false)
/** 手动跑一轮到期提醒。系统每天 9:00 也会自动发（同一个去重口径：每人每天最多一条）。 */
async function notifyDue() {
  dueBusy.value = true
  try {
    const { data } = await baselineApi.notifyDue({})
    if (!data.due) return ElMessage.success('没有即将到期或已逾期的需求，无需提醒')
    if (data.sent) {
      return ElMessage.success(`已提醒 ${data.sent} 位负责人（待提醒 ${data.due} 条，跳过 ${data.skipped} 条）`)
    }
    // 一条都没发出去：把第一个原因说出来（最常见的是"飞书未启用"或"负责人是手工账号"）
    const why = (data.details || []).find((d) => d.skip)
    ElMessage.warning(`没有发出提醒：${why ? why.skip : '暂无可发送对象'}`)
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '触发失败')
  } finally {
    dueBusy.value = false
  }
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

// ============ 控制模块维护（改名 / 删除）============
const catVisible = ref(false)
const catLoading = ref(false)
const libCategories = ref([])
const newCatName = ref('')

async function openCatManage() {
  catVisible.value = true
  newCatName.value = ''
  await loadLibCategories()
}
async function loadLibCategories() {
  catLoading.value = true
  try { libCategories.value = (await baselineApi.categories(libType.value)).data }
  catch { libCategories.value = [] }
  finally { catLoading.value = false }
}
/** 某模块下有多少检查项（用未过滤的全量算，搜索时也要数对） */
function catItemCount(catId) {
  return (libItems.value || []).filter((i) => i.category_id === catId).length
}
async function addCategory() {
  const name = newCatName.value.trim()
  if (!name) return
  try {
    await baselineApi.createCategory({ name, baseline_type: libType.value })
    newCatName.value = ''
    ElMessage.success('已新增控制模块')
    await refreshCategoryViews()
  } catch (e) { ElMessage.error(e.response?.data?.detail || '新增失败') }
}
async function renameCategory(row) {
  try {
    const res = await ElMessageBox.prompt('新的模块名称', '改名控制模块', {
      inputValue: row.name,
      inputValidator: (v) => (v && v.trim() ? true : '名称不能为空'),
    })
    await baselineApi.updateCategory(row.id, { name: res.value.trim() })
    ElMessage.success('已改名')
    await refreshCategoryViews()
  } catch (e) {
    // 取消弹窗不是错误（它没有 response）；只有接口报错才提示
    if (e && e.response) ElMessage.error(e.response.data?.detail || '改名失败')
  }
}
async function removeCategory(row) {
  const n = catItemCount(row.id)
  if (n) return ElMessage.warning(`「${row.name}」下还有 ${n} 个检查项：请先删除或移到其它控制模块`)
  try {
    await ElMessageBox.confirm(`删除控制模块「${row.name}」？`, '删除控制模块',
      { confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning' })
  } catch { return }
  try {
    await baselineApi.removeCategory(row.id)
    ElMessage.success('已删除')
    await refreshCategoryViews()
  } catch (e) { ElMessage.error(e.response?.data?.detail || '删除失败') }
}
/** 模块变了 → 模块清单 / 检查项表格 / 类型计数 / 新增弹窗的下拉一起刷新（别留旧名字） */
async function refreshCategoryViews() {
  await Promise.all([loadLibCategories(), loadLibItems(), loadTypes()])
  if (itemVisible.value) await loadDialogCategories()
}

const itemVisible = ref(false)
const dialogCategories = ref([])
// 不含 severity：界面上不出现「等级」（基线表没有等级依据，团队口径是只看合规率）
const itemForm = reactive({ id: null, baseline_type: 'security_requirement', category_id: null,
  name: '', description: '', check_method: 'manual' })

function onItemDialogOpen() {
  itemForm.id = null
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

/** 编辑检查项：复用同一个弹窗（先等模块选项就绪再回填，避免短暂显示成 id）。 */
/**
 * 模板库「控制模块」合并单元格：同一模块的**连续行只显示一次**。
 * 原样逐行重复（"接口安全 / 接口安全 / 接口安全…"）会让整列看起来像数据重复出错，
 * 而它其实只是分组信息 —— 合并后一眼能看出"这一屏属于哪几个模块、各多少条"。
 * 只在当前筛选结果内合并（搜索后同一模块的几行仍然挨在一起，合并依旧成立）。
 */
function libSpan({ rowIndex, columnIndex }) {
  if (columnIndex !== 0) return
  const rows = filteredLibItems.value || []
  const cur = rows[rowIndex]
  if (!cur) return
  if (rowIndex > 0 && rows[rowIndex - 1].category_name === cur.category_name) {
    return { rowspan: 0, colspan: 0 }        // 与上一行同模块 → 被上面的合并吃掉
  }
  let span = 1
  while (rowIndex + span < rows.length
    && rows[rowIndex + span].category_name === cur.category_name) span += 1
  return { rowspan: span, colspan: 1 }
}

async function openItemEdit(row) {
  itemVisible.value = true
  onItemDialogOpen()
  await loadDialogCategories()
  Object.assign(itemForm, {
    id: row.id, category_id: row.category_id, name: row.name,
    description: row.description, check_method: row.check_method || 'manual',
  })
}


async function saveItemMaster() {
  if (!itemForm.category_id) return ElMessage.warning('请选择控制模块')
  if (!itemForm.name || itemForm.name.trim().length < 2) return ElMessage.warning('检查项名称至少 2 个字')
  try {
    const { id, ...payload } = itemForm          // id 不能进 payload（新增接口不认它）
    if (id) await baselineApi.updateItem(id, payload)
    else await baselineApi.createItem(payload)
    ElMessage.success(id ? '已保存' : '已添加')
    itemVisible.value = false
    // 检查项/绑定范围一变，列表行与概览的口径都跟着变 → 一起刷新（别留旧数字）
    await Promise.all([loadLibItems(), loadTypes(), loadRequirements(), loadOverview()])
    // 名称/要求也显示在已展开的需求明细里 → 一并重拉，免得还挂着旧文案
    await Promise.all(expanded.value.map((rid) => ensureDetail(rid, true)))
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
/* 计数为 0 的筛选项淡显；当前选中的保持实心（它是"现在看到的这一屏"） */
.seg-filter button.zero:not(.on) { opacity: .45; }
/* 控制模块维护弹窗：输入行与表格留白 */
.cat-tools { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }

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
/* 「全部通过」：一组几十项、绝大多数是通过时最省力的入口 */
.bl-bulk { flex-shrink: 0; font-size: 11px; color: #2563eb; background: #eff6ff;
  border: 1px solid #bfdbfe; border-radius: 999px; padding: 1px 9px; cursor: pointer; }
.bl-bulk:hover { background: #dbeafe; }
.bl-bulk:disabled { opacity: .5; cursor: default; }
/* 「跳到下一个未评估」：安静的中性按钮，别与筛选 pill 抢视线 */
.detail-jump { font-size: 11px; color: #475569; background: #f1f5f9;
  border: 1px solid #e2e8f0; border-radius: 999px; padding: 1px 9px; cursor: pointer; }
.detail-jump:hover { background: #e2e8f0; }
/* 分页条：贴着列表下方、右对齐（与「漏洞提交」页的 .vuln-pager 同一套观感） */
.req-pager { display: flex; justify-content: flex-end; padding: 10px 4px 2px; }



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
/* 撤销入口：平时隐身，悬停该行才显形（次级操作不该和"通过/不通过"抢点击区） */
.seg .seg-undo { padding: 2px 7px; font-size: 11px; color: #94a3b8; opacity: 0; }
.item-table :deep(.el-table__row:hover) .seg-undo { opacity: 1; }
.seg .seg-undo:hover { border-color: #fca5a5; color: var(--c-fail); }
/* 「不通过」却没写说明：红字标出 + 输入框描红，直接把"该补依据"指出来 */
.miss { margin-left: 6px; font-size: 11px; color: var(--c-fail); }
.muted .miss { margin-right: 4px; }
.need-why :deep(.el-input__wrapper) { box-shadow: 0 0 0 1px #fca5a5 inset; }

/* 表格：紧凑、行首状态色条、表头浅底 */
.item-table :deep(.el-table__header th) {
  background: var(--c-bg-soft); color: #64748b; font-weight: 600; font-size: 12px;
}
.item-table :deep(.el-table__cell) { padding: 6px 0; font-size: 13px; }
/* 「要求」折 2 行：长句是这一屏最该读全的内容，单行截成"..."等于把关键信息藏起来
   （hover 仍有完整 tooltip；折 2 行也保证了行高一致） */
.item-table :deep(.cell-wrap2 .cell) {
  white-space: normal; display: -webkit-box; -webkit-line-clamp: 2;
  -webkit-box-orient: vertical; overflow: hidden; line-height: 1.5;
}
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
