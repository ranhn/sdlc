<template>
  <div class="vulns">
    <div class="page-header">
      <span class="page-title">提交漏洞</span>
      <div class="header-actions">
        <el-dropdown v-if="canExport" @command="(fmt) => doExport(fmt)" trigger="click">
          <el-button>
            <el-icon><Download /></el-icon>&nbsp;{{ selectedIds.length > 0 ? `批量导出已选 ${selectedIds.length} 条` : '批量导出' }}
            <el-icon class="el-icon--right"><ArrowDown /></el-icon>
          </el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="csv">{{ selectedIds.length > 0 ? `导出已选 ${selectedIds.length} 条为 CSV` : '导出全部筛选结果为 CSV' }}</el-dropdown-item>
              <el-dropdown-item command="docx">{{ selectedIds.length > 0 ? `导出已选 ${selectedIds.length} 条为 Word` : '导出全部筛选结果为 Word' }}</el-dropdown-item>
              <el-dropdown-item v-if="selectedIds.length > 0" divided command="clear">清空选择</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        <el-button type="primary" @click="openCreate">
          <el-icon><Plus /></el-icon>&nbsp;提交漏洞
        </el-button>
      </div>
    </div>

    <!-- 筛选：宽度按"最长选项够用"给（不是越大越好）——6 个筛选项在 1280 屏也要排成一行，
         间距与 label 内边距见全局 .filter-form（src/styles/main.css）。
         占位统一用「全部」：label 已经写明筛什么，写"全部状态/全部等级"纯属重复且更占地。 -->
    <el-card shadow="never" class="filter-card">
      <el-form inline class="filter-form">
        <el-form-item label="状态">
          <el-select v-model="filters.status" clearable placeholder="全部" style="width: 112px" @change="load(true)">
            <el-option label="待确认" value="pending" />
            <el-option label="已确认" value="confirmed" />
            <el-option label="修复中" value="fixing" />
            <el-option label="待复测" value="retest" />
            <el-option label="已修复" value="fixed" />
            <el-option label="已关闭" value="closed" />
            <!-- 只展示「已驳回」：页面上没有任何"忽略"入口（详情里的状态操作只有
                 确认/修复/复测/关闭/指派/驳回），库里也没有 ignored 数据。
                 但 value 里仍带上 ignored —— 老环境的历史数据万一有该状态，
                 不至于从筛选里"消失"（它照样能被筛出来，状态列显示「已忽略」）。 -->
            <el-option label="已驳回" value="rejected,ignored" />
          </el-select>
        </el-form-item>
        <el-form-item label="等级">
          <el-select v-model="filters.severity" clearable placeholder="全部" style="width: 88px" @change="load(true)">
            <el-option label="严重" value="critical" /><el-option label="高危" value="high" />
            <el-option label="中危" value="medium" /><el-option label="低危" value="low" />
          </el-select>
        </el-form-item>
        <!-- 漏洞大类：筛的是**一级大类**（根因维度，如 访问控制 / 注入类），
             和表格「类型」列展示的二级子类（如 越权 / CSRF）不是一回事，所以标成"大类"。
             选项直接来自 vulnTypeGroups —— 与提交漏洞时的级联选择同一份定义，
             以后增删类型只改那一处，不会出现"能选到但筛不出来"。 -->
        <el-form-item label="漏洞大类">
          <!-- 宽 132：最长的大类名「业务逻辑与并发」在框内会省略，但下拉列表里是完整的 -->
          <el-select v-model="filters.vuln_category" clearable placeholder="全部" style="width: 132px" @change="load(true)">
            <el-option v-for="g in vulnTypeGroups" :key="g.label" :label="g.label" :value="g.label" />
          </el-select>
        </el-form-item>
        <el-form-item label="系统">
          <el-select v-model="filters.system_id" clearable filterable placeholder="全部" style="width: 132px" @change="load(true)">
            <el-option v-for="s in systems" :key="s.id" :label="s.name" :value="s.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="来源">
          <el-select v-model="filters.is_external" clearable placeholder="全部" style="width: 96px" @change="load(true)">
            <el-option label="内部提交" :value="false" />
            <el-option label="外部报告" :value="true" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-checkbox v-model="filters.mine" @change="load(true)">只看我的</el-checkbox>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- 列表（服务端分页，每页 12 条，分页见表格下方 .vuln-pager） -->
    <!-- border：Element Plus 的列宽拖拽**必须**在表格上开 border 才会出现拖拽手柄
         （列的 resizable 默认为 true，但没 border 就拖不动）。开 border 后每列可左右拖宽，
         长标题拖宽后就能读全。列宽在刷新/重新进入页面后会回到默认（未做持久化）。 -->
    <el-table
      :data="list"
      v-loading="loading"
      stripe
      border
      class="vuln-table tight-table"
      :show-overflow-tooltip="true"
      ref="tableRef"
      row-key="id"
      @selection-change="onSelectionChange"
    >
      <!-- reserve-selection：翻页后已勾选的行仍然保留（批量导出跨页有效） -->
      <el-table-column v-if="canExport" type="selection" width="40" align="center" :reserve-selection="true" />
      <el-table-column type="index" :index="rowIndex" width="44" align="center" />
      <!-- 标题：这张表里唯一"信息密度高、又必须读全"的列，权重给到最大。
           Element 会把富余宽度按 min-width 比例分给 min-width 列，所以标题权重越大、
           别的列压得越紧，它拿到的实际宽度就越多（配合 .cell 的窄内边距）。
           截断时 hover 有 tooltip（表级 show-overflow-tooltip 已开）。 -->
      <el-table-column label="标题" min-width="320" show-overflow-tooltip>
        <template #default="{ row }">
          <el-link type="primary" :underline="false" @click="openDetail(row)">{{ row.title }}</el-link>
        </template>
      </el-table-column>
      <el-table-column prop="system_name" label="所属系统" min-width="92" align="center" />
      <!-- 接口地址普遍很长，本来就靠 tooltip 看全，宽度让给标题 -->
      <el-table-column label="接口地址" min-width="170" align="center">
        <template #default="{ row }">
          <el-tooltip v-if="row.api_endpoint" :content="row.api_endpoint" placement="top" :show-after="300">
            <el-link type="primary" :underline="false" @click.stop="openDetail(row)">{{ clip(row.api_endpoint) }}</el-link>
          </el-tooltip>
          <span v-else>—</span>
        </template>
      </el-table-column>
      <el-table-column label="等级" width="64" align="center">
        <template #default="{ row }">
          <el-tag :type="severityType[row.severity]" effect="dark" size="small">{{ severityName[row.severity] }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="vuln_type" label="类型" min-width="104" align="center" />
      <el-table-column label="来源" width="64" align="center">
        <template #default="{ row }">
          <el-tag v-if="row.is_external" type="danger" size="small">外部</el-tag>
          <el-tag v-else type="info" size="small">内部</el-tag>
        </template>
      </el-table-column>
      <!-- 状态/负责人：都是 2~3 个汉字 + 一个标签，按"够用就行"给宽，避免折行 -->
      <el-table-column label="状态" width="76" align="center">
        <template #default="{ row }">
          <el-tag :type="statusType[row.status]" size="small">{{ statusNames[row.status] }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="assignee_name" label="负责人" min-width="92" align="center" show-overflow-tooltip>
        <template #default="{ row }">{{ row.assignee_name || '—' }}</template>
      </el-table-column>
      <el-table-column prop="created_at" label="提交时间" width="138" align="center">
        <template #default="{ row }">{{ fmt(row.created_at) }}</template>
      </el-table-column>
      <el-table-column label="操作" width="112" align="center" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" size="small" @click="openDetail(row)">详情</el-button>
          <el-tooltip
            v-if="!canEdit(row)"
            :content="row.status === 'closed' ? '已关闭漏洞不可编辑' : '当前角色/身份不可编辑'"
            placement="top"
            :show-after="200"
          >
            <el-button link type="warning" size="small" disabled>编辑</el-button>
          </el-tooltip>
          <el-button v-else link type="warning" size="small" @click="openEdit(row)">编辑</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 分页：服务端分页（接口按页返回，total 由服务端给），每页 12 条 -->
    <div class="vuln-pager">
      <el-pagination
        v-model:current-page="page"
        :page-size="pageSize"
        :total="total"
        :pager-count="7"
        layout="total, prev, pager, next, jumper"
        background
        @current-change="onPageChange"
      />
    </div>

    <!-- 新建/编辑漏洞弹窗（编辑时 title 改为"编辑漏洞"，submitCreate 按 editingId 走 PATCH） -->
    <el-dialog v-model="createVisible" :title="editingId ? '编辑漏洞' : '提交漏洞'" width="640px" :close-on-click-modal="false">
      <el-form ref="createRef" :model="createForm" :rules="createRules" label-width="90px" @paste="onPaste">
        <el-form-item label="漏洞标题" prop="title">
          <el-input v-model="createForm.title" placeholder="请输入漏洞标题" />
        </el-form-item>
        <el-form-item label="接口地址" prop="api_endpoint">
          <el-input v-model="createForm.api_endpoint" placeholder="如：GET /api/v1/users/:id（便于开发直接定位修复）" maxlength="500" show-word-limit />
        </el-form-item>
        <el-form-item label="所属系统" prop="system_id">
          <el-select v-model="createForm.system_id" clearable filterable placeholder="选择系统">
            <el-option v-for="s in systems" :key="s.id" :label="s.name" :value="s.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="修复负责人">
          <el-select v-model="createForm.assignee_id" clearable filterable :loading="usersLoading" placeholder="可留空，由安全专家指派" style="width: 100%">
            <!-- label 用 userLabel()：里面带上了英文用户名，否则只按中文名搜（见 utils/userLabel.js 说明） -->
            <el-option v-for="u in users" :key="u.id" :value="u.id" :label="userLabel(u)">
              <span style="display: inline-block; width: 160px">{{ u.full_name || u.username }}</span>
              <span style="color: #909399; font-size: 12px">{{ u.username }}</span>
            </el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="等级" prop="severity">
          <el-radio-group v-model="createForm.severity">
            <el-radio-button value="critical">严重</el-radio-button>
            <el-radio-button value="high">高危</el-radio-button>
            <el-radio-button value="medium">中危</el-radio-button>
            <el-radio-button value="low">低危</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="漏洞类型" prop="vuln_path">
          <el-cascader
            v-model="createForm.vuln_path"
            :options="vulnTypeOptions"
            :props="{ expandTrigger: 'hover' }"
            placeholder="先选大类，再选具体类型"
            filterable
            clearable
            style="width: 100%"
          />
        </el-form-item>
        <el-form-item label="漏洞来源">
          <el-radio-group v-model="createForm.is_external" @change="onSourceChange">
            <el-radio-button :value="false">内部提交</el-radio-button>
            <el-radio-button :value="true">外部报告</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="createForm.is_external" label="外部来源">
          <el-input v-model="createForm.external_source" placeholder="如：CNVD-2024-001、渗透测试报告、SRC平台" maxlength="100" show-word-limit />
        </el-form-item>
        <el-form-item label="漏洞描述">
          <el-input v-model="createForm.description" type="textarea" :rows="3" placeholder="描述漏洞位置与现象" />
        </el-form-item>
        <el-form-item label="复现步骤" prop="reproduce_steps">
          <div class="steps-list">
            <div v-for="(s, idx) in createForm.steps" :key="s.id" class="step-row" :data-step-idx="idx">
              <div class="step-no">{{ idx + 1 }}</div>
              <el-input v-model="s.desc" type="textarea" :rows="2" placeholder="这一步做了什么、观察到什么" class="step-desc" />
              <div class="step-shots">
                <div v-for="(im, ii) in s.imgs" :key="ii" class="step-thumb-wrap">
                  <el-image :src="im" :preview-src-list="s.imgs" :initial-index="ii" fit="cover" class="step-thumb" hide-on-click-modal />
                  <el-button link type="danger" size="small" class="step-shot-del" @click="removeStepImg(idx, ii)">移除</el-button>
                </div>
                <!-- 每步最多 3 张。上限由我们自己控（不是 el-upload 的 :limit）：
                     它的计数按内部 fileList，我们用 on-change 自己收图、删图时不会同步，
                     会出现"删了一张却再也加不上"的怪状态。满了就不渲染上传框。 -->
                <el-upload v-if="s.imgs.length < MAX_STEP_IMGS" :auto-upload="false" multiple list-type="picture-card"
                  accept="image/*" :show-file-list="false" :on-change="(file) => onStepFile(idx, file)">
                  <el-icon><Plus /></el-icon>
                </el-upload>
              </div>
              <el-button v-if="createForm.steps.length > 1" link type="danger" size="small" @click="removeStep(idx)">删步</el-button>
            </div>
          </div>
          <el-button link type="primary" size="small" @click="addStep" :disabled="createForm.steps.length >= 6">+ 添加步骤</el-button>
          <div class="tip">步骤框内可换行，换行仍算同一步；要新起一步请点「+ 添加步骤」（最多 6 步）。每步最多 3 张截图，可粘贴或选择</div>
        </el-form-item>
        <el-form-item label="影响范围">
          <el-input v-model="createForm.impact" type="textarea" :rows="2" placeholder="可能造成的影响" />
        </el-form-item>
        <el-form-item label="修复建议">
          <el-input v-model="createForm.fix_suggestion" type="textarea" :rows="3" placeholder="给出修复方向、改造方案、参考链接或代码示例，便于研发直接采纳" maxlength="2000" show-word-limit />
        </el-form-item>
      </el-form>
      <el-image-viewer v-if="previewVisible" :url-list="previewList" :initial-index="previewIndex" @close="previewVisible = false" />
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="submitCreate">{{ editingId ? '保存修改' : '提交' }}</el-button>
      </template>
    </el-dialog>

    <!-- 详情抽屉 -->
    <el-drawer v-model="detailVisible" size="620px">
      <template #header>
        <el-tooltip :content="current?.title" placement="top" :show-after="300" :disabled="!needTip(current?.title)">
          <span class="drawer-title">漏洞 #{{ current?.id }} · {{ clip(current?.title) }}</span>
        </el-tooltip>
      </template>
      <template v-if="current">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="等级">
            <el-tag :type="severityType[current.severity]" effect="dark">{{ severityName[current.severity] }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="statusType[current.status]">{{ statusNames[current.status] }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="所属系统">{{ current.system_name || '—' }}</el-descriptions-item>
          <el-descriptions-item label="接口地址">
            <el-tooltip v-if="current.api_endpoint" :content="current.api_endpoint" placement="top" :show-after="300" :disabled="!needTip(current.api_endpoint)">
              <el-link type="primary" :underline="false" :href="current.api_endpoint" target="_blank" rel="noopener" class="wrap-link">{{ clip(current.api_endpoint) }}</el-link>
            </el-tooltip>
            <span v-else>—</span>
          </el-descriptions-item>
          <el-descriptions-item label="类型">{{ current.vuln_type || '—' }}</el-descriptions-item>
          <el-descriptions-item label="来源">
            <el-tag v-if="current.is_external" type="danger" size="small">外部</el-tag>
            <el-tag v-else type="info" size="small">内部</el-tag>
            <span v-if="current.is_external && current.external_source" class="ext-src"> · {{ current.external_source }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="提交人">{{ current.reporter_name }}</el-descriptions-item>
          <el-descriptions-item label="负责人">{{ current.assignee_name || '未指派' }}</el-descriptions-item>
          <el-descriptions-item label="提交时间">{{ fmt(current.created_at) }}</el-descriptions-item>
        </el-descriptions>

        <!-- 驳回原因：被驳回的漏洞最该先看到"为什么驳回"。
             此前驳回原因只写进了 DB（rejection_reason + vuln_flow.comment），详情里没有任何地方显示。 -->
        <div v-if="current.status === 'rejected' && current.rejection_reason" class="reject-banner">
          <b>驳回原因</b>
          <span>{{ current.rejection_reason }}</span>
        </div>

        <div class="sec-title">漏洞描述</div>
        <pre class="pre">{{ current.description || '无' }}</pre>

        <div class="sec-title">复现步骤</div>
        <div v-if="renderSteps(current).length" class="detail-steps">
          <div v-for="(s, i) in renderSteps(current)" :key="i" class="detail-step">
            <div class="detail-step-no">{{ s.step_no }}</div>
            <div class="detail-step-body">
              <div class="detail-step-desc">{{ s.desc }}</div>
              <div v-if="s.imgs.length" class="detail-shots">
                <el-image v-for="(im, ii) in s.imgs" :key="ii" :src="im" :preview-src-list="s.imgs" :initial-index="ii" fit="cover" class="shot" hide-on-click-modal />
              </div>
            </div>
          </div>
        </div>
        <pre v-else class="pre">{{ current.reproduce_steps || '无' }}</pre>

        <div class="sec-title">影响范围</div>
        <pre class="pre">{{ current.impact || '无' }}</pre>

        <template v-if="current.fix_suggestion">
          <div class="sec-title">修复建议</div>
          <pre class="pre">{{ current.fix_suggestion }}</pre>
        </template>

        <div v-if="!renderSteps(current).length && current.screenshots && current.screenshots.length" class="sec-title">截图证据</div>
        <el-image v-if="!renderSteps(current).length" v-for="(img, i) in current.screenshots" :key="i" :src="img" :preview-src-list="current.screenshots"
          fit="cover" class="shot" />

        <!-- 操作区 -->
        <div class="sec-title">状态操作</div>
        <div class="actions">
          <el-button v-if="canEdit(current)" type="warning" size="small" @click="openEdit(current)">编辑漏洞</el-button>
          <el-button v-if="can('confirm')" type="success" size="small" @click="doAction('confirm')">确认</el-button>
          <el-button v-if="can('start_fix')" type="warning" size="small" @click="doAction('start_fix')">开始修复</el-button>
          <el-button v-if="can('finish_fix')" type="warning" size="small" @click="doAction('finish_fix')">修复完成</el-button>
          <el-button v-if="can('pass_retest')" type="success" size="small" @click="doAction('pass_retest')">复测通过</el-button>
          <el-button v-if="can('close')" type="primary" size="small" @click="doAction('close')">关闭</el-button>
          <el-button v-if="can('assign')" type="info" size="small" @click="openAssign">指派</el-button>
          <el-button v-if="can('reject')" type="danger" size="small" plain @click="openReject">驳回</el-button>
        </div>

        <!-- 流程图（当前处在哪一阶段）+ 真实流转记录。
             流转记录里带着每次操作的意见，驳回原因就写在这里（后端一直有存、前端此前没取没显示）。 -->
        <div class="sec-title">状态流转</div>
        <el-steps :active="flowActive" simple class="flow-steps">
          <el-step title="提交" /><el-step title="确认" /><el-step title="修复" /><el-step title="复测" /><el-step title="关闭" />
        </el-steps>
        <div v-if="flows.length" class="flow-list">
          <div v-for="f in flows" :key="f.id" class="flow-item">
            <div class="flow-head">
              <span>{{ fmt(f.created_at) }}</span>
              <span>{{ f.operator_name || '—' }}</span>
              <!-- from == to：状态没变的操作（如「指派负责人」）—— 只显示一个状态，
                   否则会读成"待确认 → 待确认"这种没信息量的箭头；变更内容在 comment 里。 -->
              <span v-if="f.from_status && f.from_status === f.to_status">
                <b>{{ statusNames[f.to_status] || f.to_status }}</b>
              </span>
              <span v-else>
                {{ statusNames[f.from_status] || f.from_status || '—' }} →
                <b>{{ statusNames[f.to_status] || f.to_status }}</b>
              </span>
            </div>
            <div v-if="f.comment" class="flow-comment">{{ f.comment }}</div>
          </div>
        </div>
        <div v-else class="tip">暂无流转记录</div>

        <!-- 评论 -->
        <div class="sec-title">评论</div>
        <div v-for="c in comments" :key="c.id" class="comment">
          <b>{{ c.username }}</b> · {{ fmt(c.created_at) }}
          <div>{{ c.content }}</div>
        </div>
        <div class="comment-input">
          <el-input v-model="newComment" placeholder="添加评论" @keyup.enter="addComment" />
          <el-button type="primary" @click="addComment">发送</el-button>
        </div>
      </template>
    </el-drawer>

    <!-- 指派弹窗 -->
    <el-dialog v-model="assignVisible" title="指派负责人" width="400px">
      <el-select v-model="assignTo" placeholder="选择负责人" style="width: 100%" filterable :loading="usersLoading">
        <!-- ⚠️ 这里原来没传 :label —— Element 的本地过滤只比对 label，拿不到就退化成
             比对 value（数字 id），于是搜任何名字都显示"无匹配数据"。
             现在统一用 userLabel()（用户名 + 中文名），大小写由 Element 用 RegExp(query,'i') 处理。 -->
        <el-option v-for="u in users" :key="u.id" :value="u.id" :label="userLabel(u)">
          <span style="display: inline-block; width: 160px">{{ u.username }}</span>
          <span>{{ u.full_name || '—' }}</span>
        </el-option>
      </el-select>
      <template #footer>
        <el-button @click="assignVisible = false">取消</el-button>
        <el-button type="primary" @click="submitAssign">确定</el-button>
      </template>
    </el-dialog>

    <!-- 驳回弹窗 -->
    <el-dialog v-model="rejectVisible" title="驳回漏洞" width="400px">
      <el-input v-model="rejectReason" type="textarea" :rows="3" placeholder="请输入驳回原因" />
      <template #footer>
        <el-button @click="rejectVisible = false">取消</el-button>
        <el-button type="danger" @click="submitReject">确定驳回</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, nextTick } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElImageViewer } from 'element-plus'
import { vulnApi, systemApi, adminApi } from '../api'
import { useUserStore } from '../store/user'
import { fmtDateTime } from '../utils/time'
import { userLabel } from '../utils/userLabel'

const store = useUserStore()
const route = useRoute()
const canExport = computed(() => store.role === 'admin' || store.role === 'secops')
// 取 store.userId：带 JWT sub 兜底，老会话也能拿到 id
//（此前取 store.user.id，导致"提交人可编辑自己的漏洞"这类判断静默失效）
const currentUserId = computed(() => store.userId)
const list = ref([])
const systems = ref([])
const users = ref([])
const usersLoading = ref(false)
let usersLoaded = false
const loading = ref(false)
const filters = reactive({ status: '', severity: '', vuln_category: '', system_id: null, is_external: '', mine: false })
// 表格多选状态:用于批量导出已选漏洞
const tableRef = ref()
const selectedIds = ref([])

// ---- 分页：**服务端分页**，每页 12 条 ----
// 列表接口按页返回 { items, total }：筛选与排序都在库里完成，前端只拿当前页，
// 不再"全量拉回 + 前端切片"。total 是**筛选命中的总数**（与分页参数无关），
// 分页组件的页数与序号都基于它；配合 row-key + reserve-selection，跨页勾选不丢
// （导出走 /export，不受分页影响，仍按当前筛选条件导全部）。
const page = ref(1)
const pageSize = ref(12)
const total = ref(0)
const pageCount = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))

/** 序号跨页连续：列表按提交时间倒序（最新在最上），序号 = 命中总数 - 当前页内偏移 */
function rowIndex(idx) {
  return total.value - ((page.value - 1) * pageSize.value + idx)
}

/** 翻页后把列表顶部滚回视口（表格 auto height、整页滚动，不是内部滚动） */
function onPageChange(p) {
  if (p && p !== page.value) page.value = p   // 兜底：Element 会把新页码传进来
  load()                                      // 服务端分页：翻页必须重新请求该页
  nextTick(() => tableRef.value?.$el?.scrollIntoView?.({ block: 'start' }))
}

function onSelectionChange(rows) {
  selectedIds.value = rows.map((r) => r.id)
}

const statusNames = {
  draft: '草稿', pending: '待确认', confirmed: '已确认', fixing: '修复中', retest: '待复测',
  fixed: '已修复', closed: '已关闭', rejected: '已驳回', ignored: '已忽略',
}
const statusType = { draft: 'info', pending: 'warning', confirmed: 'primary', fixing: 'warning', retest: 'warning', fixed: 'success', closed: 'success', rejected: 'danger', ignored: 'info' }
const severityName = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
const severityType = { critical: 'danger', high: 'warning', medium: '', low: 'info' }
// 漏洞类型分类(按根因维度归类,共 10 大类 60 项)
// 设计原则:每条唯一可判定(一个漏洞只能选一项)、指向修复动作、可统计
// 载体/位置类信息(如"日志泄露""源码泄露""中间件")不单列为类型,写入漏洞标题/详情
const vulnTypeGroups = [
  {
    label: '注入类',
    options: [
      'SQL注入', 'NoSQL注入', '命令注入', '模板注入(SSTI)', '表达式注入(SpEL/OGNL)',
      'LDAP注入', 'XPath注入', 'CRLF注入', 'XXE', '反序列化',
    ],
  },
  {
    label: '跨站与客户端',
    options: ['XSS', 'CSRF', '点击劫持', '原型链污染', 'CORS配置不当'],
  },
  {
    label: '访问控制',
    options: [
      '未授权访问', '越权', '水平越权(IDOR)', '垂直越权/提权',
      '权限缺失', '目录遍历/任意文件读取', '任意文件写入',
    ],
  },
  {
    label: '认证与会话',
    options: [
      '认证绕过', '弱口令', '扫号/撞库', '验证码缺陷', 'JWT缺陷',
      '会话固定', '会话管理缺陷', '密码重置逻辑缺陷', 'MFA绕过',
    ],
  },
  {
    label: '信息泄露',
    options: ['信息泄露', '敏感数据明文传输', '敏感数据明文存储'],
  },
  {
    label: '业务逻辑与并发',
    options: ['业务逻辑缺陷', '支付/金额篡改', '竞态条件', '重放攻击'],
  },
  {
    label: '服务端与配置',
    options: [
      'SSRF', '文件上传', '拒绝服务(DoS)', '安全配置错误', '开放重定向',
      '组件漏洞', '容器/K8s配置缺陷', '子域名接管', '供应链投毒',
    ],
  },
  {
    label: '密码学与凭据',
    options: ['密码学/加密缺陷', '硬编码凭据', '密钥管理缺陷', '证书校验缺失', '不安全随机数'],
  },
  {
    label: 'AI/LLM安全',
    options: [
      '提示注入', '系统提示泄露', '模型越权调用', 'RAG知识库投毒',
      '训练数据投毒', 'Agent过度代理', '无限Token消耗',
    ],
  },
  {
    label: '其他',
    options: ['其他'],
  },
]
// cascader 选项:一级大类为父节点,二级子类为叶子节点(严格两级联动)
const vulnTypeOptions = vulnTypeGroups.map((g) => ({
  value: g.label,
  label: g.label,
  children: g.options.map((t) => ({ value: t, label: t })),
}))
// 二级子类 -> 一级大类 反查表(含历史值兜底,用于编辑旧漏洞时补全大类)
const typeToCategory = {
  // 历史值兜底(已通过后端迁移回填 vuln_category,此处仅作前端保险)
  '扫号': '认证与会话',
  '逻辑漏洞': '业务逻辑与并发',
  '路径遍历/任意文件': '访问控制',
  '命令执行': '注入类',
}
vulnTypeGroups.forEach((g) => g.options.forEach((t) => { typeToCategory[t] = g.label }))
function categoryOfType(t) {
  return t ? (typeToCategory[t] || '') : ''
}
const actionRoles = {
  // 已移除 ignore：没有"忽略"入口，后端状态机也不再提供该动作（与后端 state_machine 对齐）
  confirm: ['admin', 'secops'], reject: ['admin', 'secops'],
  start_fix: ['admin', 'secops', 'dev'], finish_fix: ['admin', 'secops', 'dev', 'tester'],
  pass_retest: ['admin', 'secops', 'tester'], close: ['admin', 'secops'],
  assign: ['admin', 'secops'],
}
// 各动作允许的前置状态（与后端 state_machine.ACTION_RULES 保持一致）
const actionFrom = {
  confirm: ['pending'],
  reject: ['pending'],
  start_fix: ['confirmed'],
  finish_fix: ['fixing'],
  pass_retest: ['retest'],
  close: ['fixed'],
  assign: ['pending', 'confirmed', 'fixing', 'retest', 'fixed'],
}
const flowMap = { pending: 1, confirmed: 2, fixing: 3, retest: 4, fixed: 5, closed: 6 }

function can(action) {
  if (!current.value) return false
  if (!actionRoles[action]?.includes(store.role)) return false
  if (actionFrom[action] && !actionFrom[action].includes(current.value.status)) return false
  return true
}
// 编辑权限：提交人本人 / 管理员 / 安全专家；且漏洞非 closed（closed 不可改）
function canEdit(row) {
  if (!row) return false
  if (row.status === 'closed') return false
  const role = store.role
  if (role === 'admin' || role === 'secops') return true
  if (currentUserId.value != null && row.reporter_id === currentUserId.value) return true
  return false
}

// 新建/编辑
const createVisible = ref(false)
const submitting = ref(false)
const createRef = ref()
const editingId = ref(null)  // null=新建；数字=编辑该 id 的漏洞
const createForm = reactive({
  title: '', system_id: null, severity: 'medium', vuln_path: [],
  description: '', impact: '', assignee_id: null,
  is_external: false, external_source: '',
  api_endpoint: '',
  fix_suggestion: '',
  steps: [{ id: 's1', desc: '', img: null }],
})
const createRules = {
  title: [{ required: true, message: '请输入标题', trigger: 'blur' }],
  api_endpoint: [{ required: true, message: '请输入接口地址', trigger: 'blur' }],
  system_id: [{ required: true, message: '请选择所属系统', trigger: 'change' }],
  severity: [{ required: true, message: '请选择等级', trigger: 'change' }],
  vuln_path: [{ required: true, message: '请选择漏洞类型', trigger: 'change' }],
}
let _stepSeq = 1
function newStep() { return { id: 's' + (++_stepSeq), desc: '', imgs: [] } }
/** 每步最多几张截图 */
const MAX_STEP_IMGS = 3

/* —— 复现步骤的存取格式 ——
   后端只有 reproduce_steps 一个文本字段，历史格式是「一行一步」，于是**步骤内部
   换行会被当成新步骤**（用户反馈：在步骤 1 的框里敲回车接着写，展示出来就变成步骤 2）。
   现在存成「编号块」：

     1. 打开登录页
        输入用户名密码
     2. 点击提交

   即每步以 `1. ` 开头（行首），步骤内部的换行原样保留、续行缩进两格。
   解析时只看行首的编号行来切块 —— 于是用户在步骤里自己写「1. xxx」也不会被切开。
   老数据（没有任何编号行）仍按「一行一步」解析，历史记录不受影响。 */
const STEP_HEAD_RE = /^\d+\s*[.、)）]\s*/
/** 步骤数组 → 存档文本（见上方格式说明） */
function stepsToText(steps) {
  return steps
    .map((s, i) => {
      const body = String(s.desc || '').trim() || `步骤 ${i + 1}`
      return `${i + 1}. ` + body.replace(/\n/g, '\n  ')
    })
    .join('\n')
}
/** 存档文本 → 步骤文案数组（新格式按编号块，老格式一行一步） */
function parseStepsText(text) {
  const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n')
  const heads = []
  lines.forEach((l, i) => { if (STEP_HEAD_RE.test(l)) heads.push(i) })
  if (!heads.length) return lines.map((l) => l.trim()).filter(Boolean)
  return heads
    .map((start, k) => {
      const end = k + 1 < heads.length ? heads[k + 1] : lines.length
      const body = [lines[start].replace(STEP_HEAD_RE, ''), ...lines.slice(start + 1, end)]
        // 去掉续行的 2 格缩进；首行本身没缩进，替换无副作用
        .map((l) => l.replace(/^ {1,2}/, ''))
      return body.join('\n').trim()
    })
    .filter(Boolean)
}
function addStep() {
  if (createForm.steps.length >= 6) return ElMessage.warning('最多 6 步')
  createForm.steps.push(newStep())
}
function removeStep(idx) {
  if (createForm.steps.length <= 1) return
  createForm.steps.splice(idx, 1)
}
function removeStepImg(idx, ii) {
  createForm.steps[idx]?.imgs.splice(ii, 1)
}
function onStepFile(idx, file) {
  const step = createForm.steps[idx]
  if (!step) return
  if (step.imgs.length >= MAX_STEP_IMGS) return ElMessage.warning(`每步最多 ${MAX_STEP_IMGS} 张截图`)
  const reader = new FileReader()
  reader.onload = (e) => {
    const s = createForm.steps[idx]
    // 多选/连续选择时回调是并发的，落库前再判一次上限
    if (s && s.imgs.length < MAX_STEP_IMGS) s.imgs.push(e.target.result)
  }
  reader.readAsDataURL(file.raw)
}
function openCreate() {
  editingId.value = null
  Object.assign(createForm, {
    title: '', system_id: null, severity: 'medium',
    description: '', impact: '', assignee_id: null,
    is_external: false, external_source: '',
    api_endpoint: '',
    fix_suggestion: '',
  })
  createForm.vuln_path = []
  createForm.steps = [newStep()]
  createVisible.value = true
  ensureUsers()          // 弹窗打开时才拉人员列表（见 ensureUsers 说明）
}

// 编辑：先把 row 现有数据填回表单。
// 由于现有 step 编辑器以「每步独立 desc + img」建模，需要把后端的
// reproduce_steps 多行字符串 + step_screenshots 列表 还原成 steps 数组。
async function openEdit(row) {
  if (!canEdit(row)) return ElMessage.warning('当前状态或角色不可编辑')
  // 先等人员列表就绪再回填 assignee_id：Element 解析"已选项显示名"时要能在选项里
  // 找到这个人（本地过滤模式）。顺序反了会短暂显示成数字 id。
  await ensureUsers()
  try {
    const res = await vulnApi.detail(row.id)
    const v = res.data
    editingId.value = v.id
    Object.assign(createForm, {
      title: v.title || '',
      system_id: v.system_id ?? null,
      severity: v.severity || 'medium',
      description: v.description || '',
      impact: v.impact || '',
      assignee_id: v.assignee_id ?? null,
      is_external: !!v.is_external,
      external_source: v.external_source || '',
      api_endpoint: v.api_endpoint || '',
      fix_suggestion: v.fix_suggestion || '',
    })
    // 两级类型回填：优先用后端返回的大类；历史数据无大类时按子类反查所属大类
    const cat = v.vuln_category || categoryOfType(v.vuln_type)
    createForm.vuln_path = cat && v.vuln_type ? [cat, v.vuln_type] : []
    // 反解步骤：走 parseStepsText（新格式按编号块切、老数据一行一步）；按 step_no 匹配图片
    const descs = parseStepsText(v.reproduce_steps)
    // 一步可能有多张图（step_screenshots 里同一个 step_no 会有多条），按序号收成数组
    const shotsByNo = {}
    ;(v.step_screenshots || []).forEach((ss) => {
      if (!ss || !ss.data_url) return
      ;(shotsByNo[ss.step_no] = shotsByNo[ss.step_no] || []).push(ss.data_url)
    })
    const restored = descs.length
      ? descs.map((desc, i) => ({ id: 's' + (++_stepSeq), desc, imgs: shotsByNo[i + 1] || [] }))
      : [newStep()]
    // 编辑时如果只有 1 个空步骤（用户原表单空），保留一个空白 step 便于编辑
    createForm.steps = restored.length ? restored : [newStep()]
    createVisible.value = true
  } catch (e) {
    ElMessage.error(extractErrorMsg(e, '加载漏洞失败'))
  }
}
function onPaste(e) {
  if (!createVisible.value) return
  const items = e.clipboardData?.items
  if (!items || items.length === 0) return
  const target = e.target
  const row = target?.closest?.('[data-step-idx]')
  const idx = row ? Number(row.dataset.stepIdx) : createForm.steps.length - 1
  const step = createForm.steps[idx]
  if (!step) return
  if (step.imgs.length >= MAX_STEP_IMGS) {
    return ElMessage.warning(`第 ${idx + 1} 步已有 ${MAX_STEP_IMGS} 张截图`)
  }
  for (const it of items) {
    if (it.kind === 'file' && it.type.startsWith('image/')) {
      const blob = it.getAsFile()
      if (!blob) continue
      const reader = new FileReader()
      reader.onload = (ev) => {
        const s = createForm.steps[idx]
        if (s && s.imgs.length < MAX_STEP_IMGS) s.imgs.push(ev.target.result)
      }
      reader.readAsDataURL(blob)
      e.preventDefault()
      break
    }
  }
}
async function submitCreate() {
  await createRef.value.validate()
  const validSteps = createForm.steps.filter((s) => (s.desc || '').trim() || s.imgs.length)
  if (validSteps.length === 0) return ElMessage.warning('请至少填写一步复现步骤')
  submitting.value = true
  // 存档格式见 stepsToText：步骤内部换行保留，不再「一行一步」
  const reproduce_steps = stepsToText(validSteps)
  // 一步最多 3 张图：同一个 step_no 允许多条（后端 step_screenshots 就是列表）
  const step_screenshots = validSteps.flatMap((s, i) =>
    s.imgs.map((data_url) => ({ step_no: i + 1, data_url })),
  )
  const screenshots = step_screenshots.map((s) => s.data_url)
  const payload = {
    title: createForm.title,
    system_id: createForm.system_id,
    severity: createForm.severity,
    vuln_category: createForm.vuln_path?.[0] || null,
    vuln_type: createForm.vuln_path?.[1] || null,
    description: createForm.description,
    impact: createForm.impact,
    assignee_id: createForm.assignee_id,
    reproduce_steps,
    screenshots,
    step_screenshots,
    is_external: createForm.is_external,
    external_source: createForm.is_external ? (createForm.external_source || null) : null,
    api_endpoint: createForm.api_endpoint.trim(),
    fix_suggestion: createForm.fix_suggestion?.trim() || null,
  }
  try {
    if (editingId.value) {
      // 编辑模式：PATCH。后端使用 exclude_unset，只覆盖请求里的字段，
      // 但前端一次性把可见字段全发，便于交互直观。
      await vulnApi.update(editingId.value, payload)
      ElMessage.success('已保存修改')
      createVisible.value = false
      // 详情抽屉开着同一条时刷新详情；**列表始终要刷** —— 原来写成 if/else 只刷一边，
      // 于是"改了标题/等级/负责人之后，表格里那一行还是旧值"（与这里注释的
      // "刷新详情 + 列表"自相矛盾，用户反馈的"指派后页面没更新"是同一类漏刷）。
      if (current.value?.id === editingId.value) {
        await openDetail(current.value)
      }
      load()
    } else {
      await vulnApi.create(payload)
      ElMessage.success('漏洞提交成功')
      createVisible.value = false
      load()
    }
  } catch (e) {
    ElMessage.error(extractErrorMsg(e, editingId.value ? '保存失败' : '提交失败'))
  } finally { submitting.value = false }
}

// 详情
const detailVisible = ref(false)
const current = ref(null)
const comments = ref([])
// 流转记录（含各次操作的意见，如「驳回：xxx」）—— 详情里要展示，见 状态流转 区块
const flows = ref([])
const newComment = ref('')
const assignVisible = ref(false)
const assignTo = ref(null)
const rejectVisible = ref(false)
const rejectReason = ref('')
const flowActive = computed(() => (current.value ? flowMap[current.value.status] || 0 : 0))
function renderSteps(v) {
  if (!v) return []
  // 改: 之前只遍历 v.step_screenshots,导致没截图的步骤直接丢失(用户反馈步骤 3 文字在但截图没有时就整步消失)。
  // 现在按 parseStepsText 解出的步骤逐条渲染，按序号匹配 step_screenshots 里的截图（一步可多张，
  // 同一个 step_no 会有多条）；没有截图的步骤也保留，imgs 为空数组即可。
  // 注意：**不能按行拆**了 —— 步骤内部的换行属于同一步（见 stepsToText/parseStepsText）。
  const descs = parseStepsText(v.reproduce_steps)
  const shotsByNo = {}
  ;(v.step_screenshots || []).forEach((ss) => {
    if (!ss || !ss.data_url) return
    ;(shotsByNo[ss.step_no] = shotsByNo[ss.step_no] || []).push(ss.data_url)
  })
  return descs.map((desc, i) => ({
    step_no: i + 1,
    desc,
    imgs: shotsByNo[i + 1] || [],
  }))
}

async function openDetail(row) {
  const res = await vulnApi.detail(row.id)
  current.value = res.data
  detailVisible.value = true
  loadComments(row.id)
  loadFlows(row.id)
}
async function loadFlows(id) {
  try {
    flows.value = (await vulnApi.flows(id)).data || []
  } catch {
    // 流转记录拉不到不影响详情主体（状态、描述、操作按钮都还在），静默降级
    flows.value = []
  }
}
async function loadComments(id) {
  const res = await vulnApi.comments(id)
  comments.value = res.data
}
async function addComment() {
  if (!newComment.value.trim()) return
  await vulnApi.addComment(current.value.id, { comment: newComment.value })
  newComment.value = ''
  loadComments(current.value.id)
}
function extractErrorMsg(e, fallback = '操作失败') {
  const data = e?.response?.data
  if (typeof data?.detail === 'string') return data.detail
  if (Array.isArray(data?.detail)) return data.detail.map(d => d.msg || JSON.stringify(d)).join('; ')
  if (typeof data === 'string') return data
  return fallback
}
async function doAction(action) {
  try {
    await vulnApi.action(current.value.id, action, { comment: '' })
    ElMessage.success('操作成功')
    openDetail(current.value)
    load()
  } catch (e) {
    ElMessage.error(extractErrorMsg(e))
  }
}
/**
 * 「漏洞来源」切换：切回「内部提交」时清掉外部来源。
 *
 * 这个 handler 此前**只出现在模板里、脚本里没有定义**（点单选按钮只会往控制台抛错），
 * 结果是"先选外部报告填了 CNVD 编号、再改回内部提交"时，那个编号会跟着内部漏洞一起提交。
 */
function onSourceChange(isExternal) {
  if (!isExternal) createForm.external_source = ''
}

function openReject() { rejectVisible.value = true }
async function submitReject() {
  if (!rejectReason.value.trim()) return ElMessage.warning('请输入驳回原因')
  try {
    await vulnApi.reject(current.value.id, { reason: rejectReason.value })
    ElMessage.success('已驳回')
    rejectVisible.value = false
    await openDetail(current.value)
    load()
  } catch (e) {
    // 与 submitAssign 同理：失败必须报出来，否则"点了没反应"（无权限 403 时尤其误导）
    ElMessage.error(extractErrorMsg(e, '驳回失败'))
  }
}
async function submitAssign() {
  if (assignTo.value == null) return ElMessage.warning('请选择负责人')
  try {
    await vulnApi.assign(current.value.id, { assignee_id: assignTo.value })
    ElMessage.success('指派成功')
    assignVisible.value = false
    // **列表和详情都要刷新**：以前这里只 `openDetail()`（刷新抽屉里的「负责人」），
    // 表格那一列还是旧的人 —— 用户反馈"指派人之后页面没有立即更新"就是这个
    // （紧邻的 submitReject 本来就是两样都刷，只有指派漏了）。
    // 重新拉列表还顺带处理了"在「只看我的」筛选下把漏洞转派给别人后该行应消失"。
    await openDetail(current.value)
    load()
  } catch (e) {
    // 以前没有 catch：接口失败（例如无权限 403）时既没提示、弹窗也不关，
    // 只在控制台留一个未处理的 Promise 拒绝，看起来像"没反应"。
    ElMessage.error(extractErrorMsg(e, '指派失败'))
  }
}
async function openAssign() {
  // 同样先确保人员列表就绪（指派弹窗默认选中"当前负责人"，理由同 openEdit）
  await ensureUsers()
  assignTo.value = current.value?.assignee_id ?? null
  assignVisible.value = true
}

// 时间格式化：后端返回的是 UTC（naive 或带 +00:00/Z），这里统一按浏览器本地时区显示
function fmt(d) { return fmtDateTime(d) }

// 长文本（如接口 URL）截断显示，超出即省略
const CLIP_LEN = 40
function clip(text) {
  if (!text) return text
  const s = String(text)
  return s.length > CLIP_LEN ? s.slice(0, CLIP_LEN) + '…' : s
}
function needTip(text) {
  return !!text && String(text).length > CLIP_LEN
}

async function doExport(fmt, idsOverride) {
  if (!canExport.value) return ElMessage.warning('仅管理员/安全专家可导出')
  // "清空选择" 指令
  if (fmt === 'clear') {
    tableRef.value?.clearSelection()
    selectedIds.value = []
    ElMessage.info('已清空选择')
    return
  }
  // 优先用调用方传入的 ids（单条导出走这里），其次用表格当前已选
  const ids = Array.isArray(idsOverride) && idsOverride.length
    ? idsOverride
    : (selectedIds.value.length ? selectedIds.value.slice() : null)
  const params = {}
  if (filters.status) params.status = filters.status
  if (filters.severity) params.severity = filters.severity
  if (filters.vuln_category) params.vuln_category = filters.vuln_category
  if (filters.system_id) params.system_id = filters.system_id
  // 来源和大类此前没传给导出接口：页面上筛了「外部报告」，导出的文件里却是全部 ——
  // 导出按钮写的是"导出当前筛选结果"，所以筛选条件必须原样带过去。
  if (filters.is_external !== null && filters.is_external !== undefined && filters.is_external !== '') {
    params.is_external = filters.is_external
  }
  if (filters.mine) params.mine = true
  if (ids && ids.length) params.ids = ids.join(',')
  try {
    const res = await vulnApi.export(fmt, params)
    const ext = fmt === 'csv' ? 'csv' : 'docx'
    const blob = new Blob([res.data], { type: res.data.type || (fmt === 'csv' ? 'text/csv' : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const ts = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14)
    const tag = ids && ids.length ? `selected${ids.length}` : 'all'
    a.download = `vulns_${tag}_${ts}.${ext}`
    document.body.appendChild(a); a.click(); document.body.removeChild(a)
    URL.revokeObjectURL(url)
    const tip = ids && ids.length
      ? `已导出 ${ids.length} 条为 ${fmt === 'csv' ? 'CSV' : 'Word'}`
      : `已导出当前筛选的全部结果为 ${fmt === 'csv' ? 'CSV' : 'Word'}`
    ElMessage.success(tip)
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '导出失败')
  }
}

/**
 * 拉取漏洞列表。
 * @param {boolean} resetPage 过滤条件变化时传 true（回到第 1 页）。
 *   状态流转等"就地操作"后不传，停在原页；此时若列表变短会收敛到最后一个
 *   有效页，避免停在一个空白页（看起来像数据丢了）。
 */
async function load(resetPage = false) {
  if (resetPage) page.value = 1   // 筛选条件变了就回第 1 页（必须在拼参数之前）
  loading.value = true
  try {
    const params = { page: page.value, page_size: pageSize.value }
    if (filters.status) params.status = filters.status
    if (filters.severity) params.severity = filters.severity
    if (filters.vuln_category) params.vuln_category = filters.vuln_category
    if (filters.system_id) params.system_id = filters.system_id
    if (filters.is_external !== null && filters.is_external !== undefined && filters.is_external !== '') {
      params.is_external = filters.is_external
    }
    if (filters.mine) params.mine = true
    const res = await vulnApi.list(params)
    list.value = res.data.items || []        // 服务端分页：这里只有当前页
    total.value = res.data.total ?? 0
    if (page.value > pageCount.value) {
      // 数据变少（删除/筛选后）时收敛到最后一个有效页，避免停在空白页（看起来像数据丢了）
      page.value = pageCount.value
      await load()
    }
  } finally { loading.value = false }
}

/**
 * 人员列表**按需加载**（本项目最大的一个页面加载开销）。
 *
 * 以前在 onMounted 里就拉：飞书通讯录同步后公司有 1600+ 人，`GET /api/users`
 * 一次约 580KB，每次刷新页面都要下载 + JSON 解析一遍 ——
 * 而这两个人员下拉（提交漏洞的「修复负责人」、详情里的「指派」）只有点开弹窗才用得到。
 * 现在改成弹窗打开时再拉、且整个页面生命周期只拉一次（usersLoaded 记住结果），
 * 同时改用只返回 id/用户名/姓名的 /users/pick（约 60KB）。
 */
async function ensureUsers() {
  if (usersLoaded) return
  usersLoaded = true
  usersLoading.value = true
  try {
    users.value = (await adminApi.userPicks()).data || []
  } catch (e) {
    usersLoaded = false   // 失败不算"已加载"，下次打开弹窗可以重试
    // 必须报出来：以前是空 catch，接口 403 时下拉只是"空的"，看不出是权限问题
    ElMessage.error(extractErrorMsg(e, '加载人员列表失败'))
  } finally {
    usersLoading.value = false
  }
}

onMounted(async () => {
  load()
  try { systems.value = (await systemApi.list()).data } catch {}
  // 兼容审计日志等外部跳转：?id=123 直接打开该漏洞详情
  const qid = Number(route.query.id)
  if (qid && Number.isFinite(qid)) {
    try {
      // 复用 openDetail：评论、状态流转记录一起加载
      // （此前这里手写了一遍"取详情 + 开抽屉 + 拉评论"，漏了流转记录，导致 ?id= 进来时看不到驳回原因）
      await openDetail({ id: qid })
    } catch (e) {
      // 静默失败：可能权限不足或漏洞已删
    }
  }
})
</script>

<style scoped>
.vulns { height: 100%; display: flex; flex-direction: column; }
.vulns .page-header { flex-shrink: 0; }
.header-actions { display: flex; gap: 8px; align-items: center; }
.filter-card { margin-bottom: 12px; flex-shrink: 0; }
.filter-card :deep(.el-card__body) { padding: 12px; }
.vuln-table { background: #fff; border-radius: 10px; }
/* 分页条：贴着表格下方、右对齐（Element 默认居中，跟表格右缘对齐更像后台列表） */
.vuln-pager { display: flex; justify-content: flex-end; padding: 10px 4px 2px; flex-shrink: 0; }
/* 列间距/不换行由全局 .tight-table 提供（src/styles/main.css），不再本页各写一份：
   同一段样式原来在这里和 VulnFix.vue 各写了一遍，两处选择器都写错且静默失效。 */
/* 操作列三个按钮(详情/编辑/导出)水平+垂直对齐,统一行高 */
.vuln-table :deep(.cell) .el-button.is-link { line-height: 1; padding: 4px 6px; vertical-align: middle; }
.tip { font-size: 12px; color: #94a3b8; margin-top: 6px; }
.sec-title { font-weight: 600; margin: 16px 0 8px; color: #0f172a; }
.pre { white-space: pre-wrap; font-family: inherit; margin: 0; }
.shot { width: 90px; height: 90px; margin: 4px; border-radius: 6px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; }
/* 驳回原因：贴在顶部信息区下面，红底一眼可见 */
.reject-banner {
  display: flex; align-items: flex-start; gap: 8px;
  margin-top: 10px; padding: 8px 12px;
  background: #fef0f0; border: 1px solid #fbc4c4; border-radius: 8px;
  font-size: 13px; line-height: 1.5; color: #b91c1c; word-break: break-word;
}
.reject-banner b { flex-shrink: 0; }
/* 流转记录：时间 / 操作人 / 状态变化 + 意见（驳回原因就在这里） */
.flow-list { display: flex; flex-direction: column; gap: 6px; margin-top: 8px; }
.flow-item { padding: 8px 10px; background: #f8fafc; border-radius: 8px; }
.flow-head { display: flex; flex-wrap: wrap; gap: 10px; font-size: 12px; color: #64748b; }
.flow-head b { color: #0f172a; }
.flow-comment { margin-top: 4px; font-size: 13px; color: #0f172a; white-space: pre-wrap; word-break: break-word; }
.steps-list { display: flex; flex-direction: column; gap: 10px; width: 100%; }
.step-row { display: flex; align-items: flex-start; gap: 10px; padding: 10px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; }
.step-no { width: 26px; height: 26px; line-height: 26px; text-align: center; background: #3b82f6; color: #fff; border-radius: 50%; flex-shrink: 0; font-size: 13px; }
.step-desc { flex: 1; }
/* 每步最多 3 张截图：横向排开、放不下就换行（不再是一�.step-thumb-wrap { width: 90px; height: 90px; position: relative; flex-shrink: 0; }
.step-thumb { width: 90px; height: 90px; border-radius: 6px; border: 1px solid #e2e8f0; }
.step-shot-del { position: absolute; bottom: -6px; right: -6px; background: #fff; border-radius: 10px; padding: 0 6px; }
.step-row :deep(.el-upload--picture-card) { width: 90px; height: 90px; }
.step-row :deep(.el-upload--picture-card .el-upload) { width: 90px; height: 90px; }
.detail-steps { display: flex; flex-direction: column; gap: 10px; }
.detail-step { display: flex; gap: 10px; padding: 10px; background: #f8fafc; border-radius: 8px; }
.detail-step-no { width: 28px; height: 28px; line-height: 28px; text-align: center; background: #3b82f6; color: #fff; border-radius: 50%; flex-shrink: 0; }
.detail-step-body { flex: 1; }
.detail-step-desc { white-space: pre-wrap; margin-bottom: 6px; color: #0f172a; }
/* 一步多张图：并排铺开 */
.detail-shots { display: flex; flex-wrap: wrap; gap: 2px; }
.comment { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 8px 12px; margin-bottom: 8px; font-size: 13px; }
.comment-input { display: flex; gap: 8px; }
.drawer-title { font-weight: 600; font-size: 16px; color: #0f172a; word-break: break-all; }
.wrap-link { word-break: break-all; white-space: normal; }
</style>
