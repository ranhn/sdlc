<template>
  <div class="rd-panel panel">
    <Toast ref="toastRef" />

    <!-- 顶部：返回 + 标题 + meta + 操作 -->
    <div class="rd-head">
      <button class="rd-back" @click="goBack" title="返回结果列表">← 返回</button>
      <div class="rd-head-main">
        <h2 class="rd-title">{{ detail?.title || '加载中…' }}</h2>
        <div class="rd-meta">
          <span class="pill pill--primary">{{ tMethodology(detail?.methodology) }}</span>
          <span class="rd-time">{{ fmtTime(detail?.created_at) }}</span>
          <span class="rd-stat">建模人：{{ ownerLabel(detail) }}</span>
        </div>
      </div>
      <div class="rd-actions">
        <div class="rd-export-group" @click.stop>
          <button class="rd-icon-btn rd-export" @click="doExport(detail, 'md')">导出 ▾</button>
          <div class="rd-export-menu">
            <button @click="doExport(detail, 'md')">Markdown 报告</button>
            <button @click="doExport(detail, 'json')">Threat Dragon JSON</button>
            <button @click="doExport(detail, 'csv')">CSV 威胁清单</button>
            <button @click="doExport(detail, 'docx')">Word 报告 (.docx)</button>
          </div>
        </div>
        <button
          class="rd-icon-btn rd-compare"
          title="与另一次建模结果对比，查看威胁的新增/消失/变化"
          @click="openCompare"
        >版本对比</button>
        <button
          class="rd-icon-btn rd-rename"
          :disabled="!canModify(detail)"
          @click="openRename(detail)"
        >重命名</button>
        <button
          v-if="canDelete(detail)"
          class="rd-icon-btn rd-del"
          @click="doDelete(detail)"
        >删除</button>
      </div>
    </div>

    <!-- 加载/空/错误态 -->
    <div v-if="loading" class="rd-state">正在加载详情…</div>
    <div v-else-if="!detail" class="rd-state">
      未找到该结果（可能已被删除或 id 无效）
      <button class="btn btn-sm rd-clear" @click="goBack">返回列表</button>
    </div>

    <!-- 详情内容：两列布局（左主+右栏，各自独立上下滚动） -->
    <div v-else class="rd-body">
    <div class="rd-content">
      <!-- 4 个 KPI 卡 -->
      <div class="rd-stats">
        <div class="rd-stat-card">
          <span class="rd-stat-ico comp">◇</span>
          <div class="rd-stat-body">
            <span class="rd-stat-num">{{ detail.stats?.componentCount ?? '-' }}</span>
            <span class="rd-stat-label">组件</span>
          </div>
        </div>
        <div class="rd-stat-card">
          <span class="rd-stat-ico flow">⇄</span>
          <div class="rd-stat-body">
            <span class="rd-stat-num">{{ detail.stats?.flowCount ?? '-' }}</span>
            <span class="rd-stat-label">数据流</span>
          </div>
        </div>
        <div class="rd-stat-card">
          <span class="rd-stat-ico threat">⚠</span>
          <div class="rd-stat-body">
            <span class="rd-stat-num">{{ detail.stats?.threatCount ?? '-' }}</span>
            <span class="rd-stat-label">威胁</span>
          </div>
        </div>
        <div class="rd-stat-card risk" :class="'lvl-' + riskLevel(detail).key">
          <span class="rd-stat-ico risk">!</span>
          <div class="rd-stat-body">
            <span class="rd-stat-num">{{ riskCount(detail) }}</span>
            <span class="rd-stat-label">{{ riskLevel(detail).label }}</span>
          </div>
        </div>
      </div>

      <!-- 风险等级徽章：列表卡片上原有的徽章移到详情页，并结合威胁明细
           给出"最高等级 + 高危计数"的总览。 -->
      <div v-if="riskCount(detail) > 0" class="rd-risk-banner" :class="'risk-' + riskLevel(detail).key">
        <span class="rd-risk-badge" :class="'sev-' + riskLevel(detail).key">
          {{ riskLevel(detail).label }}
        </span>
        <span class="rd-risk-text">
          共 <b>{{ riskCount(detail) }}</b> 条高危及以上威胁
          <template v-if="riskLevel(detail).key === 'Critical'">
            （其中严重 {{ detail.stats?.threatCountBySeverity?.Critical || 0 }} 条，
            高风险 {{ detail.stats?.threatCountBySeverity?.High || 0 }} 条）
          </template>
          ，建议优先处置。
        </span>
      </div>

      <!-- 合规影响面概览：完整明细在右栏"合规影响面"卡片，此处给出
           抬头即可见的一句话结论，说明这是影响面而非合规结论。 -->
      <div v-if="complianceList.length" class="rd-compliance-bar">
        <span class="rd-comp-bar-label">合规影响面</span>
        <div class="rd-compliance">
          <span
            v-for="c in complianceList"
            :key="'top-' + c.code"
            class="rd-compliance-chip"
            :class="{ covered: isComplianceHit(c) }"
            :title="complianceTitle(c)"
          >
            {{ c.label || c.code }}
            <b v-if="c.relatedThreatCount"> {{ c.relatedThreatCount }}</b>
          </span>
        </div>
        <span class="rd-comp-hint" title="仅表示威胁类型触及了法规域的关注范围，不代表合规达标">
          不代表合规结论
        </span>
      </div>

      <!-- 严重度 + 类型 chips（点击切换筛选） -->
      <div class="rd-chips">
        <span
          v-for="sev in sevOrdered"
          :key="sev.key"
          class="rd-sev-chip"
          :class="['sev-' + sev.key, { 'chip-active': activeSeverities.has(sev.key) }]"
          :title="activeSeverities.has(sev.key) ? '点击取消筛选' : '点击仅查看此严重度'"
          @click="toggleFilter('severity', sev.key)"
        >
          {{ tSeverity(sev.key) }} × {{ detail.stats?.threatCountBySeverity?.[sev.key] ?? 0 }}
        </span>
        <template v-if="availableTypes.length">
          <span class="rd-sep">·</span>
          <span
            v-for="t in availableTypes"
            :key="t"
            class="rd-type-chip"
            :class="{ 'chip-active': activeTypes.has(t) }"
            :title="t"
            @click="toggleFilter('type', t)"
          >
            {{ tType(t) }} × {{ typeCount(t) }}
          </span>
        </template>
      </div>

      <!-- 威胁明细标题 -->
      <div class="rd-threat-title">
        <h4>
          威胁明细
          <span class="rd-filter-count">
            <template v-if="hasFilter">已筛选 {{ filteredThreatList.length }} / {{ threatList.length }}</template>
            <template v-else>共 {{ threatList.length }}</template>
          </span>
        </h4>
        <div class="rd-threat-actions">
          <button v-if="hasFilter" class="btn btn-sm rd-clear" @click="clearFilters">清空筛选</button>
        </div>
      </div>

      <!-- 威胁列表 -->
      <div v-if="!threatList.length" class="rd-state">该模型未识别到威胁。</div>
      <div v-else-if="!filteredThreatList.length" class="rd-state">
        当前筛选条件下没有威胁。
        <button class="btn btn-sm rd-clear" @click="clearFilters">清空筛选</button>
      </div>
      <div v-else class="rd-threat-list thin-scroll">
        <div
          v-for="t in filteredThreatList"
          :key="t.threatId || t.title + t.number"
          :id="'threat-' + (t.threatId || t.id)"
          class="rd-threat"
        >
          <div class="rd-threat-head">
            <span class="rd-sev-badge" :class="'sev-' + t.severity">{{ tSeverity(t.severity) }}</span>
            <span class="rd-threat-title-text">{{ t.title }}</span>
            <span class="rd-threat-type" :title="t.type">{{ tType(t.type) }}</span>
            <span class="rd-threat-comp" :title="t.component">@ {{ t.component }}</span>
            <select
              class="rd-status-select"
              :class="'status-' + (t.status || 'Open')"
              :value="t.status || 'Open'"
              :title="canModify(detail) ? '点击修改处置状态' : '仅建模人/系统管理员/安全专家可修改'"
              :disabled="!canModify(detail)"
              @change="changeThreatStatus(detail, t, $event)"
              @click.stop
            >
              <option value="Open">Open</option>
              <option value="In Progress">进行中</option>
              <option value="Mitigated">已缓解</option>
              <option value="Accepted">已接受</option>
            </select>
            <label
              class="rd-oos-toggle"
              :class="{ active: !!t.outOfScope }"
              :title="t.outOfScope ? '已标记为范围外，点击取消' : '标记为不在范围内'"
              @click.stop
            >
              <input
                type="checkbox"
                :checked="!!t.outOfScope"
                @change="$event => toggleOOS(detail, t, $event)"
              />
              <span>{{ t.outOfScope ? '范围外' : '范围内' }}</span>
            </label>
          </div>
          <p class="rd-threat-desc">{{ t.description }}</p>
          <p v-if="t.mitigation" class="rd-threat-mit">
            <strong>缓解：</strong>{{ t.mitigation }}
          </p>
          <div class="rd-threat-meta">
            <span v-if="t.cwe">CWE：{{ t.cwe }}</span>
            <!-- 方法论取任务级 detail.methodology：单条威胁上没有 methodology
                 字段（后端落盘只有 modelType），沿用 t.methodology 会恒为
                 false 导致该标签永不显示。 -->
            <span v-if="detail?.methodology">方法论：{{ tMethodology(detail.methodology) }}</span>
            <span v-if="t.source === 'manual'" class="rd-manual-badge" title="由安全工程师手工补充">手工录入</span>
            <button
              v-if="canModify(detail)"
              class="rd-edit-threat"
              title="编辑这条威胁的描述/缓解措施等"
              @click.stop="openEditThreat(t)"
            >编辑</button>
            <button
              v-if="canModify(detail)"
              class="rd-del-threat"
              title="删除这条威胁（AI 误报或经评估不适用）"
              @click.stop="removeThreat(t)"
            >删除</button>
            <button
              class="rd-to-vuln"
              :disabled="!canModify(detail) || converting.has(t.threatId)"
              :title="canModify(detail)
                ? '在漏洞管理中创建一条整改工单'
                : '仅建模人/系统管理员/安全专家可转单'"
              @click.stop="convertToVuln(t)"
            >
              <template v-if="converting.has(t.threatId)">提交中…</template>
              <template v-else-if="vulnLinks[t.threatId]">已转漏洞单 #{{ vulnLinks[t.threatId] }}</template>
              <template v-else>转漏洞工单</template>
            </button>
          </div>
        </div>
      </div>
    </div>

    <aside class="rd-side thin-scroll">
      <!-- 4 张子卡：元信息 + 严重度分布 + 类型分布 + 高危 Top 5 -->
      <div class="rd-side-card">
        <h5>结果信息</h5>
        <dl class="rd-side-meta">
          <dt>建模人</dt><dd>{{ ownerLabel(detail) }}</dd>
          <dt>创建时间</dt><dd>{{ fmtTime(detail?.created_at) }}</dd>
          <dt>方法论</dt><dd>{{ tMethodology(detail?.methodology) }}</dd>
          <dt>结果 ID</dt><dd class="rd-mono">{{ detail?.id }}</dd>
        </dl>
      </div>

      <div class="rd-side-card">
        <h5>严重度分布</h5>
        <div class="rd-side-bars">
          <div
            v-for="sev in SEV_ORDER"
            :key="sev"
            v-show="(detail.stats?.threatCountBySeverity?.[sev] || 0) > 0"
            class="rd-side-bar-row"
          >
            <span class="rd-side-bar-label">{{ tSeverity(sev) }}</span>
            <div class="rd-side-bar-track">
              <div class="rd-side-bar-fill" :class="'sev-' + sev" :style="{ width: barPct(sev) + '%' }"></div>
            </div>
            <span class="rd-side-bar-num">{{ detail.stats?.threatCountBySeverity?.[sev] || 0 }}</span>
          </div>
        </div>
      </div>

      <div v-if="availableTypes.length" class="rd-side-card">
        <h5>类型分布</h5>
        <div class="rd-side-types">
          <span v-for="t in availableTypes" :key="t" class="rd-side-type-chip">
            {{ tType(t) }} × {{ typeCount(t) }}
          </span>
        </div>
      </div>

      <!-- 度量指标：回答「评估做得够好吗」（Threat Modeling Manifesto 第四问） -->
      <div v-if="metrics" class="rd-side-card">
        <h5>度量指标</h5>
        <div class="rd-metric-list">
          <div class="rd-metric-row">
            <span class="rd-metric-label" title="已被识别出威胁的元素占全部建模元素（组件+数据流）的比例">
              威胁覆盖度
            </span>
            <div class="rd-metric-track">
              <div
                class="rd-metric-fill"
                :class="metricLevel(metrics.coverageRate)"
                :style="{ width: pctOf(metrics.coverageRate) + '%' }"
              ></div>
            </div>
            <span class="rd-metric-num">{{ formatRate(metrics.coverageRate) }}</span>
          </div>
          <p class="rd-metric-hint">
            已覆盖 {{ metrics.modeledElements ?? 0 }} / {{ metrics.totalElements ?? 0 }} 个元素
          </p>

          <div class="rd-metric-row">
            <span class="rd-metric-label" title="高危及以上威胁中已缓解/不适用的比例">
              风险收敛率
            </span>
            <div class="rd-metric-track">
              <div
                class="rd-metric-fill"
                :class="metricLevel(metrics.riskConvergence)"
                :style="{ width: pctOf(metrics.riskConvergence) + '%' }"
              ></div>
            </div>
            <span class="rd-metric-num">{{ formatRate(metrics.riskConvergence) }}</span>
          </div>
          <p class="rd-metric-hint">高危威胁的处置进度</p>

          <template v-if="metrics.owaspLlmCoverRate != null">
            <div class="rd-metric-row">
              <span class="rd-metric-label" title="OWASP Top 10 for LLM 清单中已被本次建模覆盖的条目占比">
                LLM 风险覆盖
              </span>
              <div class="rd-metric-track">
                <div
                  class="rd-metric-fill"
                  :class="metricLevel(metrics.owaspLlmCoverRate)"
                  :style="{ width: pctOf(metrics.owaspLlmCoverRate) + '%' }"
                ></div>
              </div>
              <span class="rd-metric-num">{{ formatRate(metrics.owaspLlmCoverRate) }}</span>
            </div>
            <p v-if="metrics.owaspLlmCovered?.length" class="rd-metric-hint">
              已覆盖：{{ metrics.owaspLlmCovered.join('、') }}
            </p>
          </template>

          <template v-if="atlasList.length">
            <div class="rd-metric-sub">MITRE ATLAS 技术覆盖</div>
            <div class="rd-atlas">
              <span
                v-for="a in atlasList"
                :key="a.id"
                class="rd-atlas-chip"
                :title="`${a.name_zh || a.name}（${a.tactic_label}）：${a.description}`"
              >
                <b>{{ a.id }}</b> {{ a.name_zh || a.name }}
                <i v-if="a.hits > 1">×{{ a.hits }}</i>
              </span>
            </div>
          </template>

          <template v-if="dreadAvg">
            <div class="rd-metric-sub">DREAD 平均分</div>
            <div class="rd-dread-avg">
              <div v-for="d in dreadAvg" :key="d.key" class="rd-dread-avg-item">
                <span class="rd-dread-avg-name">{{ d.label }}</span>
                <span class="rd-dread-avg-track">
                  <span class="rd-dread-avg-fill" :style="{ width: (d.value / 10) * 100 + '%' }"></span>
                </span>
                <span class="rd-dread-avg-num">{{ d.value }}</span>
              </div>
            </div>
          </template>
        </div>
      </div>

      <!-- 合规影响面：展示本次建模的威胁触达了哪些法规域。
           注意语义——这是"影响面"而非"合规结论"：识别出越多种类的威胁
           反而会让命中数上升，所以页面上必须显式声明不代表合规达标。 -->
      <div v-if="complianceList.length" class="rd-side-card">
        <h5>
          合规影响面
          <span class="rd-comp-hint" title="仅表示威胁类型触及了法规域的关注范围，不代表合规达标">
            不代表合规结论
          </span>
        </h5>
        <div class="rd-compliance">
          <span
            v-for="c in complianceList"
            :key="c.code"
            class="rd-compliance-chip"
            :class="{ covered: isComplianceHit(c) }"
            :title="complianceTitle(c)"
          >
            {{ c.label || c.code }}
            <b v-if="c.relatedThreatCount"> {{ c.relatedThreatCount }}</b>
          </span>
        </div>
      </div>

      <div v-if="topRisks.length" class="rd-side-card">
        <h5>高危优先 · Top {{ topRisks.length }}</h5>
        <div class="rd-side-risks">
          <div
            v-for="t in topRisks"
            :key="t.threatId || t.id || t.title"
            class="rd-side-risk"
            @click="scrollToThreat(t)"
          >
            <span class="rd-sev-badge" :class="'sev-' + t.severity">{{ tSeverity(t.severity) }}</span>
            <span class="rd-side-risk-title" :title="t.title">{{ t.title }}</span>
          </div>
        </div>
      </div>
    </aside>
    </div>

    <!-- 重命名弹窗 -->
    <div v-if="renameVisible" class="rd-modal-mask" @click.self="closeRename">
      <div class="rd-modal">
        <div class="rd-modal-head">
          <h3>重命名结果标题</h3>
          <button class="rd-modal-close" @click="closeRename">×</button>
        </div>
        <div class="rd-modal-body">
          <p class="rd-modal-hint">
            给这条威胁建模记录起个好记的名字，方便后续在「搜索结果」中快速定位。
          </p>
          <input
            v-model="renameTitle"
            class="rd-modal-input"
            type="text"
            maxlength="60"
            placeholder="输入新的标题…"
            @keyup.enter="doRename"
          />
        </div>
        <div class="rd-modal-foot">
          <button class="btn btn-sm" @click="closeRename">取消</button>
          <button
            class="btn btn-sm btn-primary"
            :disabled="renaming || !renameTitle.trim()"
            @click="doRename"
          >{{ renaming ? '保存中…' : '保存' }}</button>
        </div>
      </div>
    </div>

    <!-- 编辑威胁弹窗 -->
    <div v-if="editVisible" class="rd-modal-mask" @click.self="closeEditThreat">
      <div class="rd-modal rd-modal-wide">
        <div class="rd-modal-head">
          <h3>编辑威胁</h3>
          <button class="rd-modal-close" @click="closeEditThreat">×</button>
        </div>
        <div class="rd-modal-body">
          <div class="rd-field">
            <label class="rd-field-lbl">标题</label>
            <input v-model="editForm.title" class="rd-modal-input" type="text" maxlength="300" />
          </div>
          <div class="rd-field-row">
            <div class="rd-field">
              <label class="rd-field-lbl">威胁类型</label>
              <input v-model="editForm.type" class="rd-modal-input" type="text" placeholder="如 Spoofing" />
            </div>
            <div class="rd-field">
              <label class="rd-field-lbl">严重度</label>
              <select v-model="editForm.severity" class="rd-modal-input">
                <option v-for="s in SEV_ORDER" :key="s" :value="s">{{ tSeverity(s) }}</option>
              </select>
            </div>
            <div class="rd-field">
              <label class="rd-field-lbl">状态</label>
              <select v-model="editForm.status" class="rd-modal-input">
                <option v-for="s in THREAT_STATUS_OPTIONS" :key="s.value" :value="s.value">{{ s.label }}</option>
              </select>
            </div>
          </div>
          <div class="rd-field">
            <label class="rd-field-lbl">描述</label>
            <textarea v-model="editForm.description" class="rd-modal-textarea" rows="3"></textarea>
          </div>
          <div class="rd-field">
            <label class="rd-field-lbl">缓解措施</label>
            <textarea v-model="editForm.mitigation" class="rd-modal-textarea" rows="3"></textarea>
          </div>
          <div class="rd-field">
            <label class="rd-field-lbl">关联 CWE</label>
            <input v-model="editForm.cwe" class="rd-modal-input" type="text" placeholder="如 CWE-287" />
          </div>
        </div>
        <div class="rd-modal-foot">
          <button class="btn btn-sm" @click="closeEditThreat">取消</button>
          <button
            class="btn btn-sm btn-primary"
            :disabled="savingThreat || !editForm.title.trim()"
            @click="saveThreat"
          >{{ savingThreat ? '保存中…' : '保存' }}</button>
        </div>
      </div>
    </div>

    <!-- 版本对比弹窗 -->
    <div v-if="compareVisible" class="rd-modal-mask" @click.self="closeCompare">
      <div class="rd-modal rd-modal-wide">
        <div class="rd-modal-head">
          <h3>版本对比</h3>
          <button class="rd-modal-close" @click="closeCompare">×</button>
        </div>
        <div class="rd-modal-body">
          <p class="rd-modal-hint">
            选择一次历史建模作为<b>基线</b>，对比本次建模相比基线新增、消失、变化的威胁。
          </p>
          <select v-model="compareBaseId" class="rd-modal-input">
            <option value="">请选择基线结果…</option>
            <option v-for="o in compareOptions" :key="o.id" :value="o.id">
              {{ fmtTime(o.created_at) }} · {{ o.title }}（{{ o.stats?.threatCount ?? '-' }} 威胁）
            </option>
          </select>

          <div v-if="diffData" class="rd-diff">
            <!-- 对比摘要 -->
            <div class="rd-diff-summary">
              <div class="rd-diff-sum-card added">
                <span class="rd-diff-sum-num">+{{ diffData.summary.added }}</span>
                <span class="rd-diff-sum-lbl">新增威胁</span>
              </div>
              <div class="rd-diff-sum-card removed">
                <span class="rd-diff-sum-num">-{{ diffData.summary.removed }}</span>
                <span class="rd-diff-sum-lbl">消失威胁</span>
              </div>
              <div class="rd-diff-sum-card changed">
                <span class="rd-diff-sum-num">{{ diffData.summary.changed }}</span>
                <span class="rd-diff-sum-lbl">发生变化</span>
              </div>
              <div class="rd-diff-sum-card">
                <span class="rd-diff-sum-num">{{ diffData.summary.unchanged }}</span>
                <span class="rd-diff-sum-lbl">保持一致</span>
              </div>
            </div>
            <p class="rd-diff-net" :class="netClass">
              {{ netText }}
            </p>

            <!-- 新增 -->
            <div v-if="diffData.added.length" class="rd-diff-group">
              <h6 class="rd-diff-h added">新增威胁（{{ diffData.added.length }}）</h6>
              <div v-for="(t, i) in diffData.added" :key="'a' + i" class="rd-diff-row">
                <span class="rd-sev-badge" :class="'sev-' + t.severity">{{ tSeverity(t.severity) }}</span>
                <span class="rd-diff-title">{{ t.title }}</span>
                <span class="rd-diff-elem" :title="t.type">@ {{ t.elementName }}</span>
              </div>
            </div>

            <!-- 变化 -->
            <div v-if="diffData.changed.length" class="rd-diff-group">
              <h6 class="rd-diff-h changed">发生变化的威胁（{{ diffData.changed.length }}）</h6>
              <div v-for="(t, i) in diffData.changed" :key="'c' + i" class="rd-diff-row">
                <span class="rd-sev-badge" :class="'sev-' + t.severity">{{ tSeverity(t.severity) }}</span>
                <span class="rd-diff-title">{{ t.title }}</span>
                <span class="rd-diff-elem">@ {{ t.elementName }}</span>
                <span class="rd-diff-changes">
                  <span v-for="(v, f) in t.changes" :key="f" class="rd-diff-change">
                    {{ diffFieldLabel(f) }}：{{ formatDiffVal(f, v.from) }} → {{ formatDiffVal(f, v.to) }}
                  </span>
                </span>
              </div>
            </div>

            <!-- 消失 -->
            <div v-if="diffData.removed.length" class="rd-diff-group">
              <h6 class="rd-diff-h removed">消失的威胁（{{ diffData.removed.length }}）</h6>
              <div v-for="(t, i) in diffData.removed" :key="'r' + i" class="rd-diff-row">
                <span class="rd-sev-badge" :class="'sev-' + t.severity">{{ tSeverity(t.severity) }}</span>
                <span class="rd-diff-title">{{ t.title }}</span>
                <span class="rd-diff-elem">@ {{ t.elementName }}</span>
              </div>
            </div>

            <p v-if="!diffData.summary.added && !diffData.summary.removed && !diffData.summary.changed" class="rd-diff-same">
              两次建模的威胁完全一致，架构变更未引入新的风险。
            </p>
          </div>
        </div>
        <div class="rd-modal-foot">
          <button class="btn btn-sm" @click="closeCompare">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick } from 'vue'
import Toast from './Toast.vue'
import {
  getResultDetail,
  deleteResult,
  renameResult,
  exportResult,
  downloadResult,
  updateThreatStatus as apiUpdateThreatStatus,
  convertThreatToVuln,
  listResults,
  diffResult,
  editThreat,
  deleteThreat,
} from '@/api/threat.js'
import { tSeverity, tType, tMethodology } from '../../utils/i18n.js'
import { useUserStore } from '@/store/user'

const props = defineProps({
  resultId: { type: [String, Number], required: true },
})

// 通知父组件：用户已打开这条历史记录；返回事件由父组件决定跳转目标
const emit = defineEmits(['back', 'open-result'])

const toastRef = ref(null)
const toast = (msg, type = 'info') => toastRef.value?.toast(msg, type)
const confirmBox = (opts) => toastRef.value?.confirm(opts)

// 数据
const detail = ref(null)
const loading = ref(false)
const error = ref(null)

// 权限
const userStore = useUserStore()
const currentRole = computed(() => userStore.role || '')
const currentUsername = computed(() => userStore.username || '')
const canViewAll = computed(() => ['admin', 'secops'].includes(currentRole.value))
function isOwner(item) {
  return !!(item && item.owner_username && currentUsername.value &&
    item.owner_username === currentUsername.value)
}
function canModify(item) {
  return canViewAll.value || isOwner(item)
}

// ---- 度量指标 ----
// 后端在 stats.metrics 里已经算好覆盖度/收敛率/OWASP 覆盖/合规映射，
// 此前只出现在导出报告中，这里把它们呈现给用户。
const metrics = computed(() => detail.value?.stats?.metrics || null)

/** 合规映射列表（含影响面字段） */
const complianceList = computed(() => {
  const list = metrics.value?.compliance
  return Array.isArray(list) ? list : []
})

/**
 * 该合规域是否被本次建模的威胁触达。
 * 兼容旧数据字段 covered，新字段为 hit。
 */
function isComplianceHit(c) {
  return !!(c?.hit ?? c?.covered)
}

/**
 * 合规域悬浮提示：说清命中含义、依据来源，并强调不代表合规达标。
 */
function complianceTitle(c) {
  if (!c) return ''
  const bits = []
  bits.push(
    isComplianceHit(c)
      ? `本次建模有 ${c.relatedThreatCount || 0} 条威胁触达该域`
      : '本次建模未触达该域',
  )
  if (c.relatedTypes?.length) bits.push(`命中类型：${c.relatedTypes.join('、')}`)
  if (c.basis) bits.push(`依据：${c.basis}${c.version ? `（${c.version}）` : ''}`)
  if (c.note) bits.push(c.note)
  bits.push('※ 仅表示影响面，不代表合规达标')
  return bits.join('\n')
}

/**
 * MITRE ATLAS 覆盖：后端在 metrics.atlasCovered 里给出命中的技术编号，
 * 这里把它拼成带中文名与命中次数的芯片列表。
 * 名称字典从后端目录接口拿不到（避免额外请求），因此内置一份精简映射。
 */
const ATLAS_NAME_MAP = {
  'AML.T0000': { zh: '检索公开技术资料', tactic: '侦察' },
  'AML.T0008': { zh: '获取攻击基础设施', tactic: '资源准备' },
  'AML.T0010': { zh: 'AI 供应链投毒', tactic: '资源准备' },
  'AML.T0018': { zh: '模型后门', tactic: '持久化' },
  'AML.T0020': { zh: '训练数据投毒', tactic: '投毒' },
  'AML.T0024': { zh: '通过推理接口窃取数据', tactic: '数据外泄' },
  'AML.T0040.002': { zh: '构造对抗性提示', tactic: '攻击准备' },
  'AML.T0043': { zh: '构造对抗样本', tactic: '防御规避' },
  'AML.T0044': { zh: '完全控制模型', tactic: '影响' },
  'AML.T0051': { zh: '提示注入', tactic: '攻击准备' },
  'AML.T0054': { zh: '越狱绕过安全限制', tactic: '数据外泄' },
  'AML.T0057': { zh: '窃取本机数据', tactic: '影响' },
}
const atlasList = computed(() => {
  const ids = metrics.value?.atlasCovered
  if (!Array.isArray(ids) || !ids.length) return []
  const hits = metrics.value?.atlasHits || {}
  return ids.map((id) => {
    const meta = ATLAS_NAME_MAP[id] || {}
    return {
      id,
      name_zh: meta.zh || '',
      name: meta.zh || '',
      tactic_label: meta.tactic || '',
      description: '',
      hits: hits[id] || 1,
    }
  })
})

/** DREAD 五维平均分（仅 STRIDE-AI 有） */
const DREAD_AVG_META = [
  { key: 'damage', label: '危害' },
  { key: 'reproducibility', label: '可重复性' },
  { key: 'exploitability', label: '可利用性' },
  { key: 'affectedUsers', label: '受影响面' },
  { key: 'discoverability', label: '可发现性' },
]
const dreadAvg = computed(() => {
  const d = metrics.value?.dreadAverage
  if (!d) return null
  const rows = DREAD_AVG_META
    .filter((m) => typeof d[m.key] === 'number')
    .map((m) => ({ ...m, value: Number(d[m.key]).toFixed(1) }))
  return rows.length ? rows : null
})

/** 比率转百分比数值（0~1 -> 0~100） */
function pctOf(rate) {
  const n = Number(rate)
  if (!Number.isFinite(n)) return 0
  return Math.max(0, Math.min(100, n * 100))
}

/** 比率格式化为百分数字符串 */
function formatRate(rate) {
  const n = Number(rate)
  if (!Number.isFinite(n)) return '—'
  return `${(n * 100).toFixed(0)}%`
}

/**
 * 指标健康度：用于给进度条上色。
 * 覆盖度/收敛率越高越好，因此 >=0.7 绿、>=0.4 黄、其余红。
 */
function metricLevel(rate) {
  const n = Number(rate)
  if (!Number.isFinite(n)) return 'lvl-low'
  if (n >= 0.7) return 'lvl-good'
  if (n >= 0.4) return 'lvl-mid'
  return 'lvl-low'
}

// ---- 威胁的手工编辑 ----
const THREAT_STATUS_OPTIONS = [
  { value: 'Open', label: 'Open（待处理）' },
  { value: 'In Progress', label: '进行中' },
  { value: 'Mitigated', label: '已缓解' },
  { value: 'Accepted', label: '已接受' },
  { value: 'NotApplicable', label: '不适用' },
]

const editVisible = ref(false)
const savingThreat = ref(false)
const editingThreatId = ref(null)
const editForm = ref({
  title: '', type: '', severity: 'Medium', status: 'Open',
  description: '', mitigation: '', cwe: '',
})

function openEditThreat(t) {
  editingThreatId.value = t.threatId
  editForm.value = {
    title: t.title || '',
    type: t.type || '',
    severity: t.severity || 'Medium',
    status: t.status || 'Open',
    description: t.description || '',
    mitigation: t.mitigation || '',
    cwe: t.cwe || '',
  }
  editVisible.value = true
}

function closeEditThreat() {
  editVisible.value = false
  editingThreatId.value = null
}

async function saveThreat() {
  const tid = editingThreatId.value
  if (!tid || !editForm.value.title.trim()) return
  savingThreat.value = true
  try {
    await editThreat(props.resultId, tid, {
      title: editForm.value.title.trim(),
      type: editForm.value.type.trim() || undefined,
      severity: editForm.value.severity,
      status: editForm.value.status,
      description: editForm.value.description,
      mitigation: editForm.value.mitigation,
      cwe: editForm.value.cwe,
    })
    toast('威胁已更新', 'success')
    closeEditThreat()
    await load()
  } catch (e) {
    toast('保存失败：' + (e?.response?.data?.detail || e?.message), 'error')
  } finally {
    savingThreat.value = false
  }
}

async function removeThreat(t) {
  const ok = await confirmBox({
    title: '删除威胁',
    message: `确定删除「${t.title}」？此操作不可撤销。`,
    okText: '删除',
    danger: true,
    icon: '⚠️',
  })
  if (!ok) return
  try {
    await deleteThreat(props.resultId, t.threatId)
    toast('威胁已删除', 'success')
    await load()
  } catch (e) {
    toast('删除失败：' + (e?.response?.data?.detail || e?.message), 'error')
  }
}

// ---- 版本对比 ----
const compareVisible = ref(false)
const compareBaseId = ref('')
const compareOptions = ref([])
const diffData = ref(null)

/** 打开对比弹窗：加载可选的历史结果（排除当前这条） */
async function openCompare() {
  compareVisible.value = true
  diffData.value = null
  compareBaseId.value = ''
  if (compareOptions.value.length) return
  try {
    const res = await listResults({ page: 1, pageSize: 100 })
    compareOptions.value = (res.items || []).filter(
      (i) => String(i.id) !== String(props.resultId)
    )
  } catch (e) {
    toast('加载历史结果失败：' + (e?.message || e), 'error')
  }
}

function closeCompare() {
  compareVisible.value = false
  diffData.value = null
  compareBaseId.value = ''
}

// 选择基线后自动拉取对比结果
watch(compareBaseId, async (baseId) => {
  if (!baseId) {
    diffData.value = null
    return
  }
  try {
    diffData.value = await diffResult(props.resultId, baseId)
  } catch (e) {
    diffData.value = null
    toast('对比失败：' + (e?.response?.data?.detail || e?.message), 'error')
  }
})

/** 净变化文案：威胁变多还是变少 */
const netText = computed(() => {
  const s = diffData.value?.summary
  if (!s) return ''
  const d = s.netChange
  const base = `威胁总数 ${s.oldTotal} → ${s.newTotal}`
  if (d > 0) return `${base}，净增 ${d} 条，本次架构变更引入了更多风险`
  if (d < 0) return `${base}，净减 ${-d} 条，风险有所收敛`
  return `${base}，数量持平`
})

const netClass = computed(() => {
  const s = diffData.value?.summary
  if (!s) return ''
  if (s.netChange > 0) return 'net-up'
  if (s.netChange < 0) return 'net-down'
  return 'net-flat'
})

const DIFF_FIELD_LABELS = {
  severity: '严重度',
  status: '状态',
  type: '威胁类型',
  outOfScope: '范围外',
}
function diffFieldLabel(f) {
  return DIFF_FIELD_LABELS[f] || f
}
function formatDiffVal(field, v) {
  if (field === 'severity') return tSeverity(v)
  if (field === 'outOfScope') return v ? '是' : '否'
  return v ?? '—'
}

// ---- 转漏洞工单 ----
// 正在提交的威胁 ID 集合；threatId -> vuln_id 记录已转出的工单用于回显
const converting = ref(new Set())
const vulnLinks = ref({})

async function convertToVuln(t) {
  const threatId = t?.threatId
  if (!threatId) {
    toast('缺少威胁标识，无法转单', 'error')
    return
  }
  if (converting.value.has(threatId)) return
  converting.value = new Set(converting.value).add(threatId)
  try {
    const res = await convertThreatToVuln(props.resultId, threatId, { skip_duplicate: true })
    vulnLinks.value = { ...vulnLinks.value, [threatId]: res.vuln_id }
    if (res.created) {
      toast(`已转为漏洞单 #${res.vuln_id}：${res.title}`, 'success')
    } else {
      toast(`该威胁已存在未关闭的漏洞单 #${res.vuln_id}，未重复创建`, 'info')
    }
  } catch (e) {
    toast('转漏洞单失败：' + (e?.response?.data?.detail || e?.message), 'error')
  } finally {
    const next = new Set(converting.value)
    next.delete(threatId)
    converting.value = next
  }
}
function canDelete(item) {
  return canModify(item)
}
function ownerLabel(item) {
  if (!item) return '-'
  const u = item.owner_username || currentUsername.value || ''
  const n = item.owner_display_name || ''
  if (n && n !== u) return `${u} · ${n}`
  return u || n || '匿名'
}

// 严重度顺序
const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low']
const sevOrdered = computed(() => SEV_ORDER.map((key) => ({ key })))

// 筛选状态
const activeSeverities = ref(new Set())
const activeTypes = ref(new Set())
function toggleFilter(kind, key) {
  const target = kind === 'severity' ? activeSeverities : activeTypes
  if (target.value.has(key)) target.value.delete(key)
  else target.value.add(key)
  target.value = new Set(target.value)
}
function clearFilters() {
  activeSeverities.value = new Set()
  activeTypes.value = new Set()
}

function fmtTime(epoch) {
  if (!epoch) return '-'
  const d = new Date(epoch * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

// 威胁聚合
const threatList = computed(() => {
  if (!detail.value) return []
  const diagrams = detail.value.model?.detail?.diagrams || []
  const out = []
  for (const diagram of diagrams) {
    const cells = diagram.cells || []
    const nameById = {}
    for (const c of cells) nameById[c.id] = c.data?.name || ''
    for (const c of cells) {
      for (const t of c.threats || []) {
        out.push({ ...t, component: nameById[c.id] || '' })
      }
    }
  }
  return out
})

const availableTypes = computed(() => {
  const set = new Set()
  for (const t of threatList.value) if (t.type) set.add(t.type)
  return Array.from(set)
})

function typeCount(typeKey) {
  return threatList.value.filter((t) => t.type === typeKey).length
}

function riskCount(d) {
  const bySev = d?.stats?.threatCountBySeverity || {}
  return (bySev.Critical || 0) + (bySev.High || 0)
}

/**
 * 风险等级：由严重度分布推导出的整体风险档位。
 * 判定优先级 —— 有严重(Critical) 即"严重"；否则有高风险(High) 即"高风险"；
 * 再退到中/低风险。与列表卡片的徽章语义保持一致。
 */
function riskLevel(d) {
  const bySev = d?.stats?.threatCountBySeverity || {}
  const c = bySev.Critical || 0
  const h = bySev.High || 0
  if (c > 0) return { key: 'Critical', label: '严重风险' }
  if (h > 0) return { key: 'High', label: '高风险' }
  if (bySev.Medium > 0) return { key: 'Medium', label: '中风险' }
  if (bySev.Low > 0) return { key: 'Low', label: '低风险' }
  return { key: 'Low', label: '暂无风险' }
}

// 严重度柱状图百分比（按该 severity 在总威胁数中的占比）
function barPct(sev) {
  const bySev = detail.value?.stats?.threatCountBySeverity || {}
  const total = SEV_ORDER.reduce((s, k) => s + (bySev[k] || 0), 0)
  if (total === 0) return 0
  return Math.round(((bySev[sev] || 0) / total) * 100)
}

// 高危 Top 5 索引（按 severity 优先级排序，Critical > High）
const topRisks = computed(() => {
  const order = { Critical: 0, High: 1, Medium: 2, Low: 3 }
  return [...threatList.value]
    .filter((t) => t.severity === 'Critical' || t.severity === 'High')
    .sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9))
    .slice(0, 5)
})

// 点击 Top 5 → 滚动到对应威胁（先清掉筛选，保证目标可见，再 smooth scroll + 高亮闪烁）
function scrollToThreat(t) {
  const id = t.threatId || t.id
  if (!id) return
  if (hasFilter.value) clearFilters()
  nextTick(() => {
    const el = document.getElementById('threat-' + id)
    if (!el) return
    el.scrollIntoView({ behavior: 'smooth', block: 'center' })
    el.classList.add('rd-threat-flash')
    setTimeout(() => el.classList.remove('rd-threat-flash'), 1500)
  })
}

const hasFilter = computed(
  () => activeSeverities.value.size > 0 || activeTypes.value.size > 0
)
const filteredThreatList = computed(() => {
  if (!hasFilter.value) return threatList.value
  return threatList.value.filter((t) => {
    const sevOk = activeSeverities.value.size === 0 || activeSeverities.value.has(t.severity)
    const typeOk = activeTypes.value.size === 0 || activeTypes.value.has(t.type)
    return sevOk && typeOk
  })
})

// 加载 + 响应 resultId 变化
async function load() {
  if (!props.resultId) return
  loading.value = true
  error.value = null
  detail.value = null
  try {
    const d = await getResultDetail(props.resultId)
    detail.value = d
    // 通知父组件：用户已"打开"这条历史记录 → 切回建模页时应显示这张图
    emit('open-result', d)
  } catch (e) {
    error.value = e?.response?.data?.detail || e?.message || '加载失败'
    toast('加载详情失败：' + error.value, 'error')
  } finally {
    loading.value = false
  }
}
async function loadDetailSilent() {
  try {
    detail.value = await getResultDetail(props.resultId)
  } catch (e) {
    // 静默：状态修改失败已经在上层 toast 过
  }
}

// 加载 + 响应 resultId 变化
watch(() => props.resultId, (v) => { if (v) load() }, { immediate: true })

// 返回
function goBack() {
  emit('back')
}

// 导出
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

// 删除（删除后回列表）
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
    toast('已删除', 'success')
    goBack()
  } catch (e) {
    toast('删除失败：' + (e?.response?.data?.detail || e?.message), 'error')
  }
}

// 重命名
const renameVisible = ref(false)
const renameTitle = ref('')
const renaming = ref(false)
function openRename(item) {
  if (!item) return
  renameTitle.value = item.title || ''
  renameVisible.value = true
  setTimeout(() => {
    const el = document.querySelector('.rd-modal-input')
    el?.focus()
    el?.select()
  }, 50)
}
function closeRename() {
  if (renaming.value) return
  renameVisible.value = false
}
async function doRename() {
  const title = renameTitle.value.trim()
  if (!title || !detail.value) return
  renaming.value = true
  try {
    await renameResult(detail.value.id, title)
    detail.value.title = title
    toast('标题已更新', 'success')
    renameVisible.value = false
  } catch (e) {
    toast('重命名失败：' + (e?.response?.data?.detail || e?.message), 'error')
  } finally {
    renaming.value = false
  }
}

// 状态修改 + 范围外切换（与 ResultsPanel 行为完全一致）
async function changeThreatStatus(item, t, e) {
  const newStatus = e?.target?.value
  const tid = t.threatId || t.id
  if (!tid) {
    toast('该威胁无可用标识，无法更新', 'error')
    return
  }
  const prev = t.status || 'Open'
  t.status = newStatus
  try {
    await apiUpdateThreatStatus(item.id, tid, newStatus)
    await loadDetailSilent()
  } catch (err) {
    t.status = prev
    toast('更新状态失败：' + (err?.response?.data?.detail || err?.message), 'error')
  }
}
async function toggleOOS(item, t, e) {
  const newVal = !!e?.target?.checked
  const tid = t.threatId || t.id
  if (!tid) {
    toast('该威胁无可用标识，无法更新', 'error')
    return
  }
  const prev = !!t.outOfScope
  t.outOfScope = newVal
  try {
    await apiUpdateThreatStatus(item.id, tid, t.status || 'Open', { outOfScope: newVal })
    await loadDetailSilent()
  } catch (err) {
    t.outOfScope = prev
    toast('更新范围标记失败：' + (err?.response?.data?.detail || err?.message), 'error')
  }
}
</script>

<style scoped>
/* 卡片外观（白底 / 1px 描边 / 圆角 / 浅阴影）由全局 .panel 提供，此处只写布局。
   height: 100% 而非 flex: 1: .threat-results-tab 已加 display: flex column，但 height: 100%
   更稳——不依赖任何父级是 flex 容器，只要 .threat-results-tab 撑满 .threat-tab 的受限高度即可。 */
.rd-panel {
  height: 100%;
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
  padding: 14px 16px;
  gap: 12px;
}
.rd-head {
  display: flex;
  align-items: center;
  gap: 12px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--c-line, #e2e8f0);
  flex-shrink: 0;
}
.rd-back {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-family: inherit;
  font-size: 11.5px;
  font-weight: 500;
  height: 28px;
  box-sizing: border-box;
  padding: 0 11px;
  border: 1px solid var(--c-line, #e2e8f0);
  background: var(--c-bg-soft, #f8fafc);
  color: var(--c-text-2, #475569);
  border-radius: var(--c-r-sm, 6px);
  cursor: pointer;
  flex-shrink: 0;
  transition: all 0.16s;
}
.rd-back:hover {
  border-color: var(--c-primary-line, #bfdbfe);
  color: var(--c-primary, #2563eb);
  background: var(--c-primary-soft, #eff6ff);
}
.rd-head-main {
  flex: 1;
  min-width: 0;
}
.rd-title {
  font-size: 14px;
  font-weight: 700;
  color: var(--c-text, #0f172a);
  letter-spacing: 0.1px;
  margin: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.rd-meta {
  display: flex;
  align-items: center;
  gap: 9px;
  margin-top: 4px;
  font-size: 10.5px;
  color: var(--c-text-4, #94a3b8);
  flex-wrap: wrap;
}
/* 方法论标签改用全局 .pill.pill--primary */
.rd-time,
.rd-stat {
  color: var(--c-text-4, #94a3b8);
  font-family: var(--font-mono);
}
.rd-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}
/* 操作按钮：3px -> 4px 内边距 + 28px 高度，扩大点击热区 */
.rd-icon-btn {
  display: inline-flex;
  align-items: center;
  font-family: inherit;
  font-size: 11.5px;
  font-weight: 500;
  height: 28px;
  box-sizing: border-box;
  padding: 0 10px;
  border-radius: var(--c-r-sm, 6px);
  border: 1px solid var(--c-line, #e2e8f0);
  background: var(--c-bg-soft, #f8fafc);
  color: var(--c-text-2, #475569);
  cursor: pointer;
  transition: all 0.16s;
  white-space: nowrap;
}
.rd-icon-btn:disabled { opacity: 0.45; cursor: not-allowed; }
.rd-export:hover:not(:disabled),
.rd-rename:hover:not(:disabled) {
  color: var(--c-primary, #2563eb);
  border-color: var(--c-primary-line, #bfdbfe);
  background: var(--c-primary-soft, #eff6ff);
}
.rd-del:hover:not(:disabled) {
  color: var(--danger);
  border-color: var(--danger-border);
  background: var(--danger-soft);
}
.rd-export-group { position: relative; display: inline-block; }
.rd-export-group:hover .rd-export-menu { display: flex; }
.rd-export-menu {
  display: none;
  position: absolute;
  right: 0;
  top: calc(100% + 4px);
  z-index: 20;
  flex-direction: column;
  min-width: 168px;
  background: var(--c-bg, #fff);
  border: 1px solid var(--c-line, #e2e8f0);
  border-radius: var(--c-r-md, 9px);
  box-shadow: var(--shadow-lg);
  overflow: hidden;
}
.rd-export-menu button {
  padding: 9px 14px;
  font-size: 12px;
  font-family: inherit;
  text-align: left;
  color: var(--c-text-2, #475569);
  background: transparent;
  border: none;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 6px;
  transition: background 0.15s, color 0.15s;
}
.rd-export-menu button:hover { background: var(--c-primary-soft, #eff6ff); color: var(--c-primary, #2563eb); }

.rd-body {
  flex: 1;
  display: grid;
  grid-template-columns: 1fr 320px;
  /* 关键: 显式 grid-template-rows,否则 track 高度=内容高度,grid item 会被撑成几千 px */
  /* → 子项的 overflow-y: auto 永远触发不了,无论怎么加 min-height: 0 都白搭 */
  /* 和 ThreatModeling.vue .analysis-grid 的修法完全一致 */
  grid-template-rows: minmax(0, 1fr);
  gap: 14px;
  min-height: 0;
}
.rd-content {
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding-right: 6px;
  min-height: 0;
}

/* 右侧栏：自己上下滚动 */
.rd-side {
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 10px;
  min-height: 0;
  padding-right: 4px;
}
.rd-side-card {
  background: var(--c-bg-soft, #f8fafc);
  border: 1px solid var(--c-line, #e2e8f0);
  border-radius: var(--c-r-md, 9px);
  padding: 12px 13px;
  flex-shrink: 0;
}
.rd-side-card h5 {
  font-size: 11px;
  font-weight: 700;
  color: var(--c-text-3, #64748b);
  letter-spacing: 0.5px;
  text-transform: uppercase;
  margin: 0 0 9px;
  display: flex;
  align-items: center;
  gap: 6px;
}
.rd-side-card h5::before {
  content: '';
  width: 3px;
  height: 11px;
  background: linear-gradient(180deg, #3b82f6, #1d4ed8);
  border-radius: 2px;
  flex-shrink: 0;
}
.rd-side-meta {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 7px 10px;
  font-size: 11.5px;
  margin: 0;
}
.rd-side-meta dt {
  color: var(--c-text-4, #94a3b8);
  font-weight: 500;
  white-space: nowrap;
}
.rd-side-meta dd {
  margin: 0;
  color: var(--c-text, #0f172a);
  word-break: break-all;
}
.rd-mono {
  font-family: var(--font-mono);
  font-size: 10.5px;
  color: var(--c-text-3, #64748b);
}
.rd-side-bars {
  display: flex;
  flex-direction: column;
  gap: 7px;
}
.rd-side-bar-row {
  display: grid;
  grid-template-columns: 52px 1fr 26px;
  align-items: center;
  gap: 8px;
  font-size: 11px;
}
.rd-side-bar-label { color: var(--c-text-2, #475569); font-weight: 600; }
.rd-side-bar-track {
  height: 7px;
  background: var(--bg-hover);
  border-radius: 4px;
  overflow: hidden;
}
.rd-side-bar-fill {
  height: 100%;
  border-radius: 4px;
  transition: width 0.4s;
}
.rd-side-bar-fill.sev-Critical { background: var(--critical); }
.rd-side-bar-fill.sev-High { background: var(--high); }
.rd-side-bar-fill.sev-Medium { background: var(--medium); }
.rd-side-bar-fill.sev-Low { background: var(--success); }
.rd-side-bar-num {
  font-family: var(--font-mono);
  font-weight: 700;
  color: var(--c-text, #0f172a);
  text-align: right;
}
.rd-side-types {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}
.rd-side-type-chip {
  font-size: 10px;
  padding: 1px 7px;
  border-radius: 999px;
  background: #fff;
  color: var(--c-text-3, #64748b);
  border: 1px solid var(--c-line, #e2e8f0);
  font-weight: 600;
  font-family: var(--font-mono);
}
.rd-side-risks {
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.rd-side-risk {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 6px 8px;
  border-radius: var(--c-r-sm, 6px);
  background: #fff;
  border: 1px solid var(--c-line, #e2e8f0);
  cursor: pointer;
  transition: border-color 0.15s, background 0.15s;
}
.rd-side-risk:hover {
  border-color: var(--c-primary-line, #bfdbfe);
  background: var(--c-primary-soft, #eff6ff);
}
.rd-side-risk-title {
  font-size: 11px;
  color: var(--c-text, #0f172a);
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Top 5 跳转时高亮动画 */
.rd-threat-flash {
  animation: rd-threat-pulse 1.5s ease-out;
  border-color: var(--primary) !important;
}
@keyframes rd-threat-pulse {
  0% { box-shadow: 0 0 0 0 var(--primary-soft); background: var(--primary-soft); }
  100% { box-shadow: 0 0 0 8px transparent; background: transparent; }
}
.rd-state {
  padding: 32px 16px;
  text-align: center;
  font-size: 12.5px;
  color: var(--c-text-3, #64748b);
  border: 1px dashed var(--c-line, #e2e8f0);
  border-radius: var(--c-r-md, 9px);
  background: var(--c-bg-soft, #f8fafc);
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  flex-wrap: wrap;
}

.rd-stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
}
/* KPI 卡：横向布局（图标 + 数字/标签），比纵向居中更省高度、信息密度更高 */
.rd-stat-card {
  display: flex;
  align-items: center;
  gap: 10px;
  background: var(--c-bg-soft, #f8fafc);
  border: 1px solid var(--c-line, #e2e8f0);
  border-radius: var(--c-r-md, 9px);
  padding: 10px 12px;
  transition: border-color 0.18s, background 0.18s;
}
.rd-stat-card:hover {
  border-color: var(--c-primary-line, #bfdbfe);
  background: #fff;
}
.rd-stat-ico {
  width: 26px;
  height: 26px;
  flex: none;
  display: grid;
  place-items: center;
  border-radius: 7px;
  font-size: 12px;
  color: var(--c-primary, #2563eb);
  background: var(--c-primary-soft, #eff6ff);
  border: 1px solid var(--c-primary-line, #bfdbfe);
}
.rd-stat-ico.flow { color: #0891b2; background: #ecfeff; border-color: #a5f3fc; }
.rd-stat-ico.threat { color: #d97706; background: #fffbeb; border-color: #fde68a; }
.rd-stat-ico.risk { color: #dc2626; background: #fef2f2; border-color: #fecaca; }
/* 数字回归实色：原先用 background-clip:text 渐变，导致 1x 屏上小字号对比度不足、
   且与「建模输入」页的实色文字语言不一致。 */
.rd-stat-num {
  display: block;
  font-size: 19px;
  font-weight: 700;
  line-height: 1.15;
  font-family: var(--font-mono);
  color: var(--c-text, #0f172a);
}
.rd-stat-card.risk .rd-stat-num { color: #dc2626; }
/* 高危风险卡按风险档位换色：无高危时不应继续显示刺眼的红色 */
.rd-stat-card.risk.lvl-High .rd-stat-num { color: var(--high); }
.rd-stat-card.risk.lvl-Medium .rd-stat-num { color: var(--medium); }
.rd-stat-card.risk.lvl-Low .rd-stat-num { color: var(--c-text-4, #94a3b8); }
.rd-stat-body {
  min-width: 0;
  display: flex;
  flex-direction: column;
  justify-content: center;
}
.rd-stat-label {
  display: block;
  font-size: 10px;
  color: var(--c-text-4, #94a3b8);
  font-weight: 500;
  line-height: 1.35;
}

/* —— 风险等级横幅（列表卡片的风险徽章移到详情页后的总览） —— */
.rd-risk-banner {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 12px;
  border-radius: var(--c-r-md, 9px);
  border: 1px solid var(--critical-border);
  background: var(--critical-soft);
  font-size: 12px;
  color: var(--c-text-2, #475569);
}
.rd-risk-badge {
  flex-shrink: 0;
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}
.rd-risk-badge.sev-Critical {
  background: var(--critical); color: #fff;
}
.rd-risk-badge.sev-High {
  background: var(--high-soft); color: var(--high);
  border: 1px solid var(--high-border);
}
.rd-risk-banner.risk-High {
  border-color: var(--high-border);
  background: var(--high-soft);
}
.rd-risk-banner.risk-Medium {
  border-color: var(--medium-border);
  background: var(--medium-soft);
}
.rd-risk-banner.risk-Low {
  border-color: var(--success-border);
  background: var(--success-soft);
}
.rd-risk-badge.sev-Medium {
  background: var(--medium-soft); color: var(--medium);
  border: 1px solid var(--medium-border);
}
.rd-risk-badge.sev-Low {
  background: var(--success-soft); color: var(--success);
  border: 1px solid var(--success-border);
}
.rd-risk-text b {
  font-family: var(--font-mono);
  font-weight: 700;
  color: var(--critical);
}

/* —— 合规影响面概览条（抬头即可见，明细在右栏） —— */
.rd-compliance-bar {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  padding: 8px 12px;
  border-radius: var(--c-r-md, 9px);
  border: 1px solid var(--c-line, #e2e8f0);
  background: var(--c-bg-soft, #f8fafc);
}
.rd-comp-bar-label {
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.5px;
  color: var(--c-text-3, #64748b);
  text-transform: uppercase;
  flex-shrink: 0;
}

.rd-chips {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}
.rd-sev-chip,
.rd-type-chip {
  font-size: 11px;
  font-weight: 500;
  padding: 3px 10px;
  border-radius: 999px;
  cursor: pointer;
  user-select: none;
  transition: border-color 0.15s, box-shadow 0.15s, background 0.15s;
}
.rd-sev-chip:active,
.rd-type-chip:active { transform: scale(0.97); }
/* 选中态：用外圈 ring 而不是 inset box-shadow + filter 亮度，
   避免低对比色（如 Low 绿）在高亮后看不清文字。 */
.chip-active {
  box-shadow: 0 0 0 2px #fff, 0 0 0 4px var(--c-primary, #2563eb);
}
.rd-sev-chip.sev-Critical { background: var(--critical-soft); color: var(--critical); border: 1px solid var(--critical-border); }
.rd-sev-chip.sev-High { background: var(--high-soft); color: var(--high); border: 1px solid var(--high-border); }
.rd-sev-chip.sev-Medium { background: var(--medium-soft); color: var(--medium); border: 1px solid var(--medium-border); }
.rd-sev-chip.sev-Low { background: var(--success-soft); color: var(--success); border: 1px solid var(--success-border); }
.rd-sep { color: var(--c-text-4, #94a3b8); font-size: 11px; margin: 0 2px; }
.rd-type-chip {
  background: var(--c-bg-soft, #f8fafc);
  color: var(--c-text-3, #64748b);
  border: 1px solid var(--c-line, #e2e8f0);
}
.rd-type-chip:hover {
  color: var(--c-primary, #2563eb);
  border-color: var(--c-primary-line, #bfdbfe);
}

.rd-threat-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin: 4px 0 10px;
  padding-left: 10px;
  position: relative;
}
.rd-threat-title::before {
  content: '';
  position: absolute;
  left: 0;
  top: 2px;
  bottom: 2px;
  width: 3px;
  border-radius: 2px;
  background: linear-gradient(180deg, #3b82f6, #1d4ed8);
}
.rd-threat-title h4 {
  font-size: 12.5px;
  font-weight: 700;
  color: var(--c-text, #0f172a);
  margin: 0;
  display: flex;
  align-items: center;
  gap: 7px;
}
.rd-filter-count {
  font-size: 10px;
  font-weight: 600;
  padding: 1px 7px;
  border-radius: 999px;
  color: var(--c-text-3, #64748b);
  background: var(--c-bg-soft, #f8fafc);
  border: 1px solid var(--c-line, #e2e8f0);
  font-family: var(--font-mono);
}
.rd-threat-actions { display: flex; gap: 6px; align-items: center; }
.rd-clear { color: var(--c-primary, #2563eb); border-color: var(--c-primary-line, #bfdbfe); background: var(--c-bg-soft, #f8fafc); }
.rd-clear:hover { background: var(--c-primary-soft, #eff6ff); }

.rd-threat-list { display: flex; flex-direction: column; gap: 8px; }
.rd-threat {
  background: var(--c-bg, #fff);
  border: 1px solid var(--c-line, #e2e8f0);
  border-radius: var(--c-r-md, 9px);
  padding: 11px 13px;
  transition: border-color 0.16s, box-shadow 0.16s;
}
.rd-threat:hover {
  border-color: var(--c-primary-line, #bfdbfe);
  box-shadow: var(--c-sh-2, 0 2px 8px rgba(15, 23, 42, 0.06));
}
.rd-threat-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.rd-sev-badge {
  font-size: 10px; font-weight: 700; padding: 2px 8px;
  border-radius: 999px; flex-shrink: 0; letter-spacing: 0.2px;
}
.rd-sev-badge.sev-Critical { background: var(--critical-soft); color: var(--critical); border: 1px solid var(--critical-border); }
.rd-sev-badge.sev-High { background: var(--high-soft); color: var(--high); border: 1px solid var(--high-border); }
.rd-sev-badge.sev-Medium { background: var(--medium-soft); color: var(--medium); border: 1px solid var(--medium-border); }
.rd-sev-badge.sev-Low { background: var(--success-soft); color: var(--success); border: 1px solid var(--success-border); }
.rd-threat-title-text {
  font-size: 12.5px; font-weight: 600; flex: 1; min-width: 0; color: var(--c-text, #0f172a);
  line-height: 1.45;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.rd-threat-type,
.rd-threat-comp {
  font-size: 10px;
  padding: 1px 7px;
  border-radius: 999px;
  font-weight: 600;
  font-family: var(--font-mono);
  white-space: nowrap;
}
.rd-threat-type {
  color: var(--c-primary, #2563eb);
  background: var(--c-primary-soft, #eff6ff);
  border: 1px solid var(--c-primary-line, #bfdbfe);
}
.rd-threat-comp {
  color: var(--c-text-3, #64748b);
  background: var(--c-bg-soft, #f8fafc);
  border: 1px solid var(--c-line, #e2e8f0);
  font-weight: 500;
  overflow: hidden; text-overflow: ellipsis; max-width: 180px;
}
.rd-status-select {
  font-family: inherit;
  font-size: 10.5px; font-weight: 600; padding: 1px 6px 1px 8px;
  border-radius: 999px; flex-shrink: 0; cursor: pointer; outline: none;
  appearance: none; -webkit-appearance: none;
  background-image: linear-gradient(45deg, transparent 50%, currentColor 50%),
                    linear-gradient(135deg, currentColor 50%, transparent 50%);
  background-position: calc(100% - 10px) 50%, calc(100% - 7px) 50%;
  background-size: 3px 3px, 3px 3px;
  background-repeat: no-repeat;
  padding-right: 18px;
}
.rd-status-select.status-Open { background-color: var(--c-primary-soft, #eff6ff); color: var(--c-primary, #2563eb); border: 1px solid var(--c-primary-line, #bfdbfe); }
.rd-status-select.status-Mitigated { background-color: var(--success-soft); color: var(--success); border: 1px solid var(--success-border); }
.rd-status-select.status-Accepted { background-color: var(--warning-soft); color: var(--warning); border: 1px solid var(--warning-border); }
.rd-status-select.status-InProgress,
.rd-status-select.status-In-Progress { background-color: var(--info-soft); color: var(--info); border: 1px solid var(--info-border); }
.rd-status-select:focus { outline: 2px solid var(--c-primary, #2563eb); outline-offset: 1px; }
.rd-status-select:disabled { cursor: not-allowed; opacity: 0.7; }
.rd-oos-toggle {
  display: inline-flex; align-items: center; gap: 3px;
  font-size: 10.5px; font-weight: 600; padding: 1px 8px;
  border-radius: 999px; background: var(--c-bg-soft, #f8fafc);
  border: 1px solid var(--c-line, #e2e8f0); color: var(--c-text-3, #64748b);
  cursor: pointer; user-select: none; flex-shrink: 0;
  transition: background 0.15s, border-color 0.15s, color 0.15s;
}
.rd-oos-toggle input { position: absolute; opacity: 0; pointer-events: none; width: 0; height: 0; }
.rd-oos-toggle.active { background: var(--bg-hover); color: var(--c-text-4, #94a3b8); border-color: var(--border-strong); border-style: dashed; }
.rd-oos-toggle:hover { border-color: var(--c-primary-line, #bfdbfe); color: var(--c-primary, #2563eb); }
.rd-threat-desc {
  font-size: 12px; color: var(--c-text-2, #475569); line-height: 1.65;
  margin: 8px 0 0; word-break: break-word;
  background: var(--c-bg-soft, #f8fafc); border-radius: var(--c-r-sm, 6px);
  padding: 9px 11px; border-left: 2px solid var(--c-line, #e2e8f0);
}
.rd-threat-mit {
  font-size: 12px; color: #047857; line-height: 1.6;
  margin: 6px 0 0; word-break: break-word;
  background: var(--success-soft); border-radius: var(--c-r-sm, 6px);
  padding: 9px 11px; border-left: 2px solid var(--success-border);
}
.rd-threat-mit strong { color: var(--success); margin-right: 4px; }
.rd-threat-meta { display: flex; gap: 12px; font-size: 10.5px; color: var(--c-text-4, #94a3b8); margin-top: 8px; flex-wrap: wrap; align-items: center; }

/* ---- 度量指标 ---- */
.rd-metric-list { display: flex; flex-direction: column; gap: 6px; }
.rd-metric-row { display: flex; align-items: center; gap: 8px; }
.rd-metric-label { font-size: 11px; color: var(--c-text-2, #475569); width: 72px; flex-shrink: 0; }
.rd-metric-track {
  flex: 1; height: 6px; background: var(--bg-hover); border-radius: 3px;
  overflow: hidden;
}
.rd-metric-fill { display: block; height: 100%; border-radius: 3px; transition: width 0.3s; }
.rd-metric-fill.lvl-good { background: linear-gradient(90deg, #059669, #34d399); }
.rd-metric-fill.lvl-mid { background: linear-gradient(90deg, #d97706, #fbbf24); }
.rd-metric-fill.lvl-low { background: linear-gradient(90deg, #dc2626, #f87171); }
.rd-metric-num {
  font-family: var(--font-mono); font-size: 11px; font-weight: 600; color: var(--c-text-2, #475569);
  width: 36px; text-align: right; flex-shrink: 0;
}
.rd-metric-hint { font-size: 10px; color: var(--c-text-4, #94a3b8); margin: -2px 0 2px 80px; }
.rd-metric-sub {
  font-size: 10.5px; font-weight: 600; color: var(--c-text-3, #64748b);
  margin-top: 4px; padding-top: 6px; border-top: 1px dashed var(--c-line, #e2e8f0);
}
.rd-dread-avg { display: flex; flex-direction: column; gap: 5px; margin-top: 5px; }
.rd-atlas { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 5px; }
.rd-atlas-chip {
  font-size: 10px; padding: 1px 7px; border-radius: 999px;
  color: #0369a1; background: #f0f9ff;
  border: 1px solid #bae6fd;
  cursor: help;
  font-family: var(--font-mono);
}
.rd-atlas-chip b { font-weight: 600; margin-right: 3px; }
.rd-atlas-chip i { font-style: normal; opacity: 0.7; margin-left: 3px; }
.rd-dread-avg-item { display: flex; align-items: center; gap: 8px; }
.rd-dread-avg-name { font-size: 10.5px; color: var(--c-text-4, #94a3b8); width: 58px; flex-shrink: 0; }
.rd-dread-avg-track {
  flex: 1; height: 6px; background: var(--bg-hover); border-radius: 3px;
  overflow: hidden;
}
.rd-dread-avg-fill {
  display: block; height: 100%; border-radius: 3px;
  background: linear-gradient(90deg, var(--c-violet), #a78bfa);
}
.rd-dread-avg-num {
  font-family: var(--font-mono); font-size: 10.5px; color: var(--c-text-4, #94a3b8);
  width: 26px; text-align: right; flex-shrink: 0;
}
.rd-compliance { display: flex; flex-wrap: wrap; gap: 5px; }
/* "不代表合规结论"语义提示：低饱和中性色，避免被当成警告 */
.rd-comp-hint {
  margin-left: 6px;
  padding: 0 6px;
  border-radius: 999px;
  font-size: 9.5px;
  font-weight: 500;
  color: #64748b;
  background: #f1f5f9;
  border: 1px solid #e2e8f0;
  cursor: help;
  vertical-align: middle;
}
.rd-compliance-chip {
  font-size: 10px; padding: 1px 7px; border-radius: 999px;
  color: var(--c-text-4, #94a3b8); background: #fff;
  border: 1px solid var(--c-line, #e2e8f0);
}
/* 命中数：等宽加粗，让"触达强度"可扫读 */
.rd-compliance-chip b {
  font-family: var(--font-mono);
  font-weight: 700;
}
.rd-compliance-chip.covered {
  color: #059669; background: #ecfdf5;
  border-color: #a7f3d0; font-weight: 500;
}

/* ---- 版本对比 ---- */
.rd-modal-wide { max-width: 780px; width: 92vw; }
.rd-diff { margin-top: 14px; display: flex; flex-direction: column; gap: 12px; }
.rd-diff-summary { display: flex; gap: 10px; }
.rd-diff-sum-card {
  flex: 1; display: flex; flex-direction: column; align-items: center; gap: 2px;
  padding: 10px 6px; border-radius: var(--c-r-md, 9px);
  background: var(--c-bg-soft, #f8fafc); border: 1px solid var(--c-line, #e2e8f0);
}
.rd-diff-sum-card.added { background: var(--danger-soft); border-color: var(--danger-border); }
.rd-diff-sum-card.removed { background: var(--success-soft); border-color: var(--success-border); }
.rd-diff-sum-card.changed { background: var(--warning-soft); border-color: var(--warning-border); }
.rd-diff-sum-num { font-family: var(--font-mono); font-size: 17px; font-weight: 700; }
.rd-diff-sum-card.added .rd-diff-sum-num { color: var(--danger); }
.rd-diff-sum-card.removed .rd-diff-sum-num { color: var(--success); }
.rd-diff-sum-card.changed .rd-diff-sum-num { color: var(--warning); }
.rd-diff-sum-lbl { font-size: 10px; color: var(--c-text-4, #94a3b8); }
.rd-diff-net { font-size: 11.5px; color: var(--c-text-2, #475569); margin: 0; line-height: 1.55; }
.rd-diff-net.net-up { color: var(--danger); }
.rd-diff-net.net-down { color: var(--success); }
.rd-diff-group { display: flex; flex-direction: column; gap: 5px; }
.rd-diff-h {
  font-size: 11.5px; font-weight: 700; margin: 0 0 2px;
  padding-bottom: 5px; border-bottom: 1px solid var(--c-line, #e2e8f0);
}
.rd-diff-h.added { color: var(--danger); }
.rd-diff-h.removed { color: var(--success); }
.rd-diff-h.changed { color: var(--warning); }
.rd-diff-row {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  padding: 7px 10px; border-radius: var(--c-r-sm, 6px);
  background: var(--c-bg-soft, #f8fafc); font-size: 11.5px;
}
.rd-diff-title { color: var(--c-text, #0f172a); font-weight: 500; }
.rd-diff-elem { color: var(--c-text-4, #94a3b8); font-size: 10.5px; font-family: var(--font-mono); }
.rd-diff-changes { display: flex; gap: 8px; flex-wrap: wrap; margin-left: auto; }
.rd-diff-change {
  font-size: 10px; color: var(--warning);
  background: var(--warning-soft); border: 1px solid var(--warning-border);
  border-radius: 999px; padding: 1px 7px;
}
.rd-diff-same {
  font-size: 11.5px; color: #047857; text-align: center;
  padding: 12px; background: var(--success-soft);
  border-radius: var(--c-r-md, 9px); margin: 0;
}
.rd-icon-btn.rd-compare:hover:not(:disabled) {
  color: var(--c-violet);
  border-color: var(--c-violet-line);
  background: var(--c-violet-soft);
}

/* ---- 威胁编辑 ---- */
.rd-manual-badge {
  font-size: 10px; padding: 1px 7px; border-radius: 999px;
  color: var(--c-violet); background: var(--c-violet-soft);
  border: 1px solid var(--c-violet-line);
  font-weight: 600;
}
.rd-edit-threat, .rd-del-threat {
  font-size: 10.5px; font-weight: 500; font-family: inherit; cursor: pointer;
  height: 22px; box-sizing: border-box; padding: 0 9px;
  border-radius: var(--c-r-sm, 6px);
  border: 1px solid var(--c-line, #e2e8f0);
  background: var(--c-bg-soft, #f8fafc); color: var(--c-text-3, #64748b);
  transition: color 0.15s, border-color 0.15s, background 0.15s;
}
.rd-edit-threat:hover {
  color: var(--c-primary, #2563eb);
  border-color: var(--c-primary-line, #bfdbfe);
  background: var(--c-primary-soft, #eff6ff);
}
.rd-del-threat:hover {
  color: var(--danger);
  border-color: var(--danger-border);
  background: var(--danger-soft);
}
.rd-field { display: flex; flex-direction: column; gap: 4px; margin-bottom: 10px; flex: 1; }
.rd-field-row { display: flex; gap: 10px; }
.rd-field-lbl { font-size: 11px; color: var(--c-text-2, #475569); font-weight: 500; }
.rd-modal-textarea {
  width: 100%; box-sizing: border-box; resize: vertical;
  font-family: inherit; font-size: 12px; line-height: 1.55;
  padding: 8px 10px; border-radius: var(--c-r-sm, 6px);
  border: 1px solid var(--c-line, #e2e8f0); background: var(--c-bg-soft, #f8fafc);
  color: var(--c-text, #0f172a);
  transition: border-color 0.16s, box-shadow 0.16s, background 0.16s;
}
.rd-modal-textarea:focus {
  outline: none;
  border-color: var(--c-primary, #2563eb);
  background: #fff;
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
}

.rd-to-vuln {
  margin-left: auto; font-size: 10.5px; font-weight: 500; font-family: inherit;
  color: var(--c-violet);
  background: var(--c-violet-soft);
  border: 1px solid var(--c-violet-line);
  border-radius: var(--c-r-sm, 6px);
  height: 22px; box-sizing: border-box; padding: 0 9px; cursor: pointer;
  transition: background 0.15s, border-color 0.15s;
}
.rd-to-vuln:hover:not(:disabled) {
  background: var(--c-violet-soft);
  border-color: var(--c-violet-line-strong);
}
.rd-to-vuln:disabled { opacity: 0.55; cursor: not-allowed; }

.rd-modal-mask {
  position: fixed; inset: 0; background: rgba(15, 23, 42, 0.45);
  backdrop-filter: blur(3px); -webkit-backdrop-filter: blur(3px);
  z-index: 1000; display: flex; align-items: center; justify-content: center;
  animation: rd-fade 0.16s ease-out;
}
.rd-modal {
  width: 420px; max-width: calc(100vw - 40px);
  background: var(--c-bg, #fff);
  border: 1px solid var(--c-line, #e2e8f0); border-radius: var(--c-r-lg, 12px);
  box-shadow: 0 18px 48px rgba(15, 23, 42, 0.22); overflow: hidden;
  animation: rd-pop 0.18s cubic-bezier(0.2, 0.8, 0.3, 1.2);
}
.rd-modal-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 16px; border-bottom: 1px solid var(--c-line, #e2e8f0);
}
.rd-modal-head h3 { font-size: 13px; font-weight: 700; color: var(--c-text, #0f172a); margin: 0; }
.rd-modal-close {
  background: transparent; border: none; color: var(--c-text-4, #94a3b8);
  font-size: 18px; line-height: 1; cursor: pointer;
  padding: 2px 6px; border-radius: var(--c-r-sm, 6px);
}
.rd-modal-close:hover { color: var(--danger); background: var(--c-bg-soft, #f8fafc); }
.rd-modal-body { padding: 16px; }
.rd-modal-hint {
  font-size: 11px; color: var(--c-text-3, #64748b);
  line-height: 1.6; margin: 0 0 12px;
}
.rd-modal-input {
  width: 100%; box-sizing: border-box;
  padding: 9px 12px; font-size: 12.5px; font-family: inherit;
  border: 1px solid var(--c-line, #e2e8f0); border-radius: var(--c-r-sm, 6px);
  background: var(--c-bg-soft, #f8fafc); color: var(--c-text, #0f172a); outline: none;
  transition: border-color 0.16s, box-shadow 0.16s, background 0.16s;
}
.rd-modal-input:focus {
  border-color: var(--c-primary, #2563eb);
  background: #fff;
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
}
.rd-modal-foot {
  display: flex; justify-content: flex-end; gap: 8px;
  padding: 10px 16px; border-top: 1px solid var(--c-line, #e2e8f0);
  background: var(--c-bg-soft, #f8fafc);
}
@keyframes rd-fade { from { opacity: 0; } to { opacity: 1; } }
@keyframes rd-pop { from { opacity: 0; transform: translateY(8px) scale(0.98); } to { opacity: 1; transform: translateY(0) scale(1); } }
</style>
