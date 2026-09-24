<template>
  <div class="dashboard">
    <!-- 统计卡片 -->
    <el-row :gutter="16" class="stat-row">
      <el-col :span="4" v-for="s in statCards" :key="s.label">
        <!-- 口径说明（如「已修复」其实是闭环口径）：鼠标悬停卡片时提示 -->
        <el-tooltip :content="s.tip" placement="bottom" :disabled="!s.tip">
          <el-card shadow="hover" class="stat-card" :class="{ clickable: !!s.to }" @click="drill(s)">
            <div class="stat-inner">
              <div class="stat-icon" :style="{ background: s.bg, color: s.color }">
                <el-icon :size="22"><component :is="s.icon" /></el-icon>
              </div>
              <div class="stat-info">
                <div class="stat-value">{{ s.value }}</div>
                <div class="stat-label">
                  <span>{{ s.label }}</span>
                  <span v-if="s.sub && s.sub.text" class="stat-sub" :class="s.sub.tone">{{ s.sub.text }}</span>
                </div>
              </div>
            </div>
          </el-card>
        </el-tooltip>
      </el-col>
    </el-row>

    <!-- 趋势图 + 风险排行 -->
    <el-row :gutter="16" class="chart-row">
      <el-col :span="16">
        <el-card shadow="hover">
          <template #header>
            <div style="display:flex;align-items:center;justify-content:space-between">
              <span class="card-title">漏洞趋势</span>
              <!-- 数据截至：这页的数字是"某一刻的快照"，要能看出是什么时候的 -->
              <span class="dash-updated" style="flex:1;text-align:right">截至 {{ updatedAt || '—' }}</span>
              <el-button size="small" text :loading="loading" title="刷新整页数据" @click="reload">
                <el-icon><component is="Refresh" /></el-icon>
              </el-button>
              <el-select v-model="trendRange" size="small" style="width:100px" @change="reloadTrend">
                <el-option label="近一个月" :value="30" />
                <el-option label="近半年" :value="180" />
                <el-option label="近一年" :value="365" />
                <el-option label="全部" :value="0" />
              </el-select>
            </div>
          </template>
          <div ref="trendRef" class="chart-lg"></div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card shadow="hover">
          <template #header><span class="card-title">系统风险排行 TOP5</span></template>
          <div ref="topRef" class="chart-sm"></div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 分布图 -->
    <el-row :gutter="16" class="chart-row">
      <el-col :span="8">
        <el-card shadow="hover">
          <!-- 口径仍是「未修复」（各扇区之和 = 「未修复」卡，不是漏洞总数）；标题按反馈不再写口径。 -->          <template #header><span class="card-title">漏洞等级分布</span></template>
          <div ref="sevRef" class="chart-sm"></div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card shadow="hover">
          <template #header><span class="card-title">漏洞类型分布</span></template>
          <div ref="typeRef" class="chart-sm"></div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card shadow="hover">
          <!-- 补充说明放**卡片头部**，不要塞进 ECharts 的标题：
              之前把"（2 个系统已纳入 · 待评估 259 项）"写成了 gauge 的 name，那串文字画在
               canvas 里、和中间的大数字挤在一起（看着像重影），而且卡片窄时还被裁掉。
               现在图里只留数字，说明用 HTML 放在头部右侧，自然就不会重叠。 -->
          <template #header>
            <div class="card-head-row">
              <span class="card-title">安全基线整体合规率</span>
              <span class="card-sub">{{ baselineNote }}</span>
            </div>
          </template>
          <!-- 小环 + 按系统的合规率（最差的在最上面）：
               整体一个数字看不出问题在谁身上 —— 这张卡要能直接指出"哪个系统欠账"。
               数据来自 /baseline/requirements/overview 的 systems（与基线页同一口径）。 -->
          <div class="base-card">
            <div ref="baseRef" class="base-gauge"></div>
            <div class="base-systems">
              <div v-if="baseSystems.length" class="bsys-caption">按系统合规率（低 → 高）</div>
              <div v-for="s in baseSystems" :key="s.system_id" class="bsys"
                   :title="`${s.system_name}：应评 ${s.bound_items} 项 · 通过 ${s.pass_count} / 不通过 ${s.fail_count} / 不适用 ${s.na_count} / 未评估 ${s.pending_count}；合规率 = 通过 ÷ 适用项 ${s.applicable}`">
                <span class="bsys-name">{{ s.system_name }}</span>
                <span class="bsys-track"><i :style="{ width: s.barWidth + '%', background: s.color }" /></span>
                <span class="bsys-pct" :style="{ color: s.color }">{{ s.compliance }}%</span>
              </div>
              <div v-if="!baseSystems.length" class="bsys-empty">尚未创建基线需求</div>
              <div v-else-if="baseHidden" class="bsys-more">还有 {{ baseHidden }} 个系统未显示</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount, reactive, computed } from 'vue'
import * as echarts from 'echarts'
import { dashboardApi, baselineApi } from '../api'
// 达标线 + 合规率档位/颜色：与「安全基线」页共用同一份口径
import { BASELINE_TARGET, rateColor } from '../utils/baseline'
import { useRouter } from 'vue-router'
import { useUserStore } from '../store/user'
import { fmtDateTime } from '../utils/time'

const trendRef = ref()
const topRef = ref()
const sevRef = ref()
const typeRef = ref()
const baseRef = ref()                 // 基线合规率环（原名 statusRef：这里画的不是"状态分布"）
const router = useRouter()
const store = useUserStore()

// 首页两张卡是**严格互补**的一对（未修复 + 已修复 = 漏洞总数），钻取值必须与后端同一套
// 划分，否则点进去的条数与卡片对不上。
// 未修复 = 还没修好的（待确认 / 已确认 / 修复中）
const UNFIXED = 'pending,confirmed,fixing'
// 已修复 = 待复测 + 已修复 + 已关闭 + 已驳回（待复测 = 研发已修好、等验收）
const REPAIRED = 'retest,fixed,closed,rejected,ignored'

const trendRange = ref(30)
const loading = ref(false)
const updatedAt = ref('')             // 数据截至 HH:MM（这页是"某一刻的快照"，必须写出来）
const baselineNote = ref('')          // 基线卡头部的补充说明（原本塞在图表里，会和大数字重叠）
// 基线卡的"按系统"行（后端已按合规率升序返回：最差的在最前）
const baseSystemsAll = ref([])
const baseShown = 5                      // 卡片最多显示几个系统
const baseSystems = computed(() => baseSystemsAll.value.slice(0, baseShown).map((s) => ({
  ...s,
  color: rateColor(s.compliance),      // 达标绿 / 接近橙 / 有问题红 / 未开始灰（共享口径）
  // 极小值也给 3% 的可见宽度：否则 1~2% 在这么细的条上等于"没画"（看着像数据丢了）
  barWidth: s.compliance > 0 ? Math.max(s.compliance, 3) : 0,
})))
const baseHidden = computed(() => Math.max(0, baseSystemsAll.value.length - baseShown))
let charts = []
let trendChart = null

// 卡片悬浮的「口径」说明：**一句话说清算式即可**，不写整段解释
// （悬停时糊一大片反而没人看，用户反馈"口径说明太长了"）。
const statCards = reactive([
  { key: 'total', label: '漏洞总数', value: 0, icon: 'Warning', bg: '#eff6ff', color: '#3b82f6',
    tip: '含已闭环', to: {},
    sub: { text: '', tone: '' } },
  {
    // 「未修复 / 已修复」是一对**严格互补**的口径：两张卡相加 = 漏洞总数，
    // 这页不会再出现"9 + 8 = 17 > 总数 16"这种看起来算错的账。
    // （旧口径「未闭环 = 非终态」把"已修复但没关闭"的漏洞同时算进两张卡，只能靠解释。）
    key: 'unfixed',
    label: '未修复', value: 0, icon: 'RemoveFilled', bg: '#fef3c7', color: '#f59e0b',
    tip: '待确认 + 已确认 + 修复中',
    to: { status: UNFIXED },
    sub: { text: '', tone: '' },
  },
  {
    key: 'fixed',
    label: '已修复', value: 0, icon: 'CircleCheck', bg: '#dcfce7', color: '#22c55e',
    // 口径与漏洞列表状态列一致：这几种状态都算"已修复"，趋势图「已修复」线同口径。
    // （后端还额外把历史遗留的 ignored 一起计入，但页面上不再提这个状态了）
    tip: '待复测 + 已修复 + 已关闭 + 已驳回',
    to: { status: REPAIRED },
    sub: { text: '', tone: '' },
  },
  {
    key: 'severity',
    label: '高危', value: 0, icon: 'BellFilled', bg: '#fee2e2', color: '#ef4444',
    // 这张卡取的是"严重 + 高危"两个等级之和，标签只写「高危」容易误解，用短 tip 点明
    tip: '严重 + 高危',
    to: { status: UNFIXED, severity: 'critical,high' },
    sub: { text: '', tone: '' },
  },
  {
    // 「已修复率」= 已修复 ÷ 总数，分子**就是**左边「已修复」那张卡的数字 ——
    // 这样"8/16 = 50%"在页面上自己能核对上（旧名「闭环率」分母含"待复测"却不算进分子，
    // 于是"卡 8"与"50%"各说各话）。
    key: 'rate',
    label: '已修复率', value: '0%', icon: 'TrendCharts', bg: '#f3e8ff', color: '#8b5cf6',
    tip: '已修复 ÷ 总数',
    sub: { text: '', tone: '' },
  },
  {
    // 原为「平均修复时长」：样本只来自已闭环的漏洞，闭环量少（甚至为 0）时数字没有意义，
    // 而显示成 0h 会被读成"修复飞快"（用户反馈"这个数字没有意义"）。换成「待确认」——
    // 修复人还没受理、卡在整条链路第一步的数量，首页上唯一"需要人去推动"的数字
    // （与「漏洞修复」页的「确认 / 驳回」同一环）。
    key: 'pending',
    label: '待确认', value: 0, icon: 'Clock', bg: '#ecfeff', color: '#06b6d4',
    tip: '「未修复」的子集',
    to: { status: 'pending' },
    sub: { text: '', tone: '' },
  },
])

/** 环比文案：统一"较上月"（周环比在数据量小时噪声太大，±1 更像抖动） */
function fmtDelta(n) {
  return n ? `较上月 ${n > 0 ? '+' : ''}${n}` : '较上月 持平'
}

const severityColor = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6' }

/**
 * 给 6 张卡各写第二行小字（标签右边、同一行 —— 卡片高度不变）。
 * **六张统一按月**：计数卡 = "当前值 − 上月同一口径"；已修复率 = 与上月的百分比涨跌。
 * 不用周环比：这个数据量下 ±1 更像抖动，读起来像趋势其实是噪声。
 */
function applyCardSubs(o) {
  const set = (key, text, tone = 'flat') => {
    const card = statCards.find((s) => s.key === key)
    if (!card || !card.sub) return       // 防御：漏配 key 不该让整页数字停更
    card.sub.text = text
    card.sub.tone = tone
  }

  // ⚠️ 快照缺失时**不要默认成 0**：那会把"当前值"当成环比显示（曾出现「高危 +5」，
  // 其实是 5−0；真实是 +1）。宁可这行空着，也不要一个静默错误的数字。
  const snap = o.snapshot_30d
  const toneOf = (num, upIsGood) => (!num ? 'flat' : (num > 0) === upIsGood ? 'good' : 'bad')
  // 计数卡统一用法：与"上月同一口径"作差（upIsGood 决定涨是绿还是红）
  const diff = (key, now, prev, upIsGood) => {
    const d = now - prev
    set(key, fmtDelta(d), toneOf(d, upIsGood))
  }

  if (snap) {
    diff('total', o.total, snap.total, false)                      // 漏洞变多 → 不是好事
    diff('unfixed', o.unfixed, snap.unfixed, false)                // 未修复变多 → 欠债在涨
    diff('severity', o.critical + o.high, snap.severity, false)    // 高危变多 → 坏
    diff('pending', o.pending ?? 0, snap.pending, false)           // 卡点变多 → 坏
    diff('fixed', o.fixed_total ?? 0, snap.repaired, true)         // 已修复变多 → 好

    // 已修复率：**较上月的百分比涨跌**（相对变化）—— 上月为 0 时分母为 0，给横线
    const base = snap.rate
    if (base > 0) {
      const pct = Math.round(((o.fix_rate - base) / base) * 1000) / 10
      set('rate', `较上月 ${pct > 0 ? '+' : ''}${pct}%`, toneOf(pct, true))
    } else {
      set('rate', '较上月 —')
    }
  }
}

/** 卡片点击 → 漏洞列表（带筛选）。非管理员会被守卫转发到「漏洞修复」，
 *  那里只列"指派给我"的漏洞，所以直接指向该页、别让路由再转一次。 */
function drill(card) {
  if (!card || !card.to) return
  const isSecops = ['admin', 'secops'].includes(store.role)
  router.push({ name: isSecops ? 'vulnerabilities' : 'vuln-fix', query: { ...card.to } })
}

function renderCharts() {
  if (!trendRef.value) return
  charts.forEach((c) => c && c.dispose())
  charts = []
  // 趋势
  let t = echarts.init(trendRef.value)
  trendChart = t
  charts.push(t)
  // 系统风险排行
  let top = echarts.init(topRef.value)
  charts.push(top)
  // 三个分布饼图
  let sev = echarts.init(sevRef.value)
  let ty = echarts.init(typeRef.value)
  let base = echarts.init(baseRef.value)
  charts.push(sev, ty, base)
  loadAndRender(t, top, sev, ty, base)
}

/** 手动刷新（趋势卡头部那个按钮）：重建图表实例 + 重拉数据。 */
function reload() {
  renderCharts()
}

function renderTrend(chart, data) {
  const dates = data.map((d) => d.date)
  chart.setOption({
    tooltip: { trigger: 'axis' },
    // 两条线：新增 / 已修复 —— 都是"每天**发生**的事"，口径与上方两张卡一致。
    // （后端还返回未修复存量"截至当天还欠多少"，按反馈不在图上画了；要画回来加一条
    //   series + 第二个 yAxis 即可，见 /trend 的 unfixed 字段。）
    legend: { data: ['新增', '已修复'], right: 6, top: 0, itemWidth: 12, itemHeight: 8, textStyle: { fontSize: 11 } },
    grid: { left: 40, right: 20, top: 30, bottom: 30 },
    xAxis: { type: 'category', data: dates },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      { name: '新增', type: 'line', smooth: true, data: data.map((d) => d.created), itemStyle: { color: '#3b82f6' }, areaStyle: { opacity: 0.1 } },
      { name: '已修复', type: 'line', smooth: true, data: data.map((d) => d.repaired), itemStyle: { color: '#22c55e' }, areaStyle: { opacity: 0.1 } },
    ],
  }, true)
}

async function reloadTrend() {
  if (!trendChart) return
  try {
    // days 必须原样传（0 也要传）：写 `|| undefined` 会把「全部」的 0 变成"不传"，
    // 后端按默认 30 天返回 —— 选「全部」实际只看近一个月。
    const trend = await dashboardApi.trend({ days: trendRange.value })
    renderTrend(trendChart, trend.data)
  } catch (e) { console.error(e) }
}

function disposeAll() {
  charts.forEach((c) => c && c.dispose())
  charts = []
  trendChart = null
}

async function loadAndRender(t, top, sev, ty, base) {
  loading.value = true
  try {
    // 每个请求各自兜底：**一个接口挂掉不该让整页变 0**。
    // 曾出现 /top 报 500 → Promise.all 整体 reject → 6 张卡全 0、所有图空白，
    // 看起来像"平台没数据了"（实际只是系统排行那个接口的问题）。
    const safe = (p, name) => p.catch((e) => {
      console.error(`[dashboard] ${name} 加载失败：`, e)
      return null
    })
    const [ov, trend, dist, topR, bl] = await Promise.all([
      safe(dashboardApi.overview(), 'overview'),
      // 图表用**选定区间**（原来固定 days:30 —— 点"刷新"会把用户选的区间悄悄改回去）
      safe(dashboardApi.trend({ days: trendRange.value }), 'trend'),
      safe(dashboardApi.distribution(), 'distribution'),
      safe(dashboardApi.top(), 'top'),
      safe(baselineApi.overview(), 'baseline'),   // 与基线页同一口径（按需求绑定范围）
    ])
    const o = ov && ov.data
    if (o) {
      // 按 key 赋值：卡片顺序以后再调整，这里不用跟着改下标
      const card = Object.fromEntries(statCards.map((c) => [c.key, c]))
      card.total.value = o.total
      card.unfixed.value = o.unfixed
      card.fixed.value = o.fixed_total ?? o.closed
      card.severity.value = o.critical + o.high
      card.rate.value = o.fix_rate + '%'
      card.pending.value = o.pending ?? 0
      // 6 张卡的第二行小字（统一"较上月"，基数来自后端 /overview 的 snapshot_30d）
      applyCardSubs(o)
    }

    if (trend) renderTrend(t, trend.data)

    // 系统风险排行（横向柱状 TOP5，柱长=漏洞数，更直观；风险分放 tooltip）
    const sys = ((topR && topR.data && topR.data.top_systems) || []).slice(0, 5).reverse()
    top.setOption({
      tooltip: {
        trigger: 'item',
        formatter: (p) => `${p.name}<br/>漏洞数：${p.value}<br/>风险分：${p.data.risk}`,
      },
      grid: { left: 18, right: 30, top: 10, bottom: 10, containLabel: true },
      xAxis: { type: 'value', max: (v) => Math.ceil(v.max * 1.15) || 1, minInterval: 1 },
      yAxis: {
        type: 'category',
        data: sys.map((s) => s.name),
        // left:0 + containLabel 让 yAxis 区按内容自动分配宽度,业务系统名展示完整不被截断
        axisLabel: { overflow: 'truncate', width: 110, ellipsis: '…', align: 'right' },
      },
      series: [{
        type: 'bar',
        data: sys.map((s) => ({ value: s.count, risk: s.risk, name: s.name })),
        itemStyle: { color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [{ offset: 0, color: '#3b82f6' }, { offset: 1, color: '#8b5cf6' }]) },
        label: {
          show: true,
          position: 'insideRight',
          distance: 8,
          color: '#fff',
          fontWeight: 600,
          formatter: '{c}',
        },
      }],
    })

    const sevData = ((dist && dist.data && dist.data.by_severity) || []).map((i) => ({ name: i.name, value: i.value, itemStyle: { color: severityColor[i.name] || '#94a3b8' } }))
    sev.setOption(pieOption(sevData, '等级'))
    // 漏洞类型分布：按一级大类统计（10 类固定，无需聚合兜底）
    // 注意：不能再用 TOP5+「其他」聚合 —— 分类体系里已存在真实的「其他」大类，会与之撞名导致扇区重复
    const sortedCats = [...((dist && dist.data && dist.data.by_category) || [])].sort((a, b) => b.value - a.value)
    const typeData = sortedCats.map((i, idx) => ({
      name: i.name,
      value: i.value,
      itemStyle: { color: i.name === '其他' ? '#94a3b8' : palette[idx % palette.length] },
    }))
    ty.setOption(pieOption(typeData, '大类'))
    // 安全基线整体合规率（仪表盘）
    // 口径与「安全基线」页保持一致：只统计**需求已绑定的基线范围**，且同一检查项在多条
    // 需求里只算一次。之前用的是 baselineApi.stats()（分母 = 系统数 × 全库全部条目数）——
    // 没做过基线的系统也在拉低这个数字，首页和基线页会互相打架。
    const blData = (bl && bl.data) || {}
    const overall = blData.compliance ?? 0
    const sysCount = blData.system_count ?? 0
    const pendingItems = blData.pending_count ?? 0
    // 头部只写"纳入了多少系统"（目标值已经画在环里了，不重复）
    baselineNote.value = sysCount ? `${sysCount} 个系统已纳入` : '尚未创建基线需求'
    baseSystemsAll.value = blData.systems || []
    // 小环（卡片左侧 ~128px）：去掉刻度与轴标签，只留"底环 + 进度弧 + 中心数字"
    // —— 与「安全基线」页的合规率环同一套视觉；卡片右侧让给"按系统"列表。
    const baseColor = rateColor(overall)      // 档位/颜色来自 utils/baseline.js（与基线页同一份）
    base.setOption({
      tooltip: { trigger: 'item' },
      series: [{
        type: 'gauge',
        // 整圆（而不是 210°/-30° 的开口仪表盘）：旁边两张是完整甜甜圈，
        // 开口形状放大后底部那个"缺口"特别扎眼，而且缺口正是原来放刻度文字的位置，
        // 文字去掉后那块空白就纯属多余 → 改成整圆，三张卡才像一套
        startAngle: 90, endAngle: -270,
        min: 0, max: 100,
        radius: '94%', center: ['50%', '50%'],
        // 环加厚到 20px：旁边甜甜圈带宽约占半径 30%，环太细在同样直径下会显得"空"
        progress: { show: true, width: 20, itemStyle: { color: baseColor } },
        axisLine: { lineStyle: { width: 20, color: [[1, '#eef2f7']] } },
        pointer: { show: false },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        anchor: { show: false },
        // 环内只放两行短文字：数字 + "目标 80%"（提供参照，且短到不会和数字抢位置）；
        // 卡片头部的副标题因此改成只写"纳入了多少系统"，不再重复目标值
        title: { show: true, offsetCenter: [0, '36%'], fontSize: 11, color: '#94a3b8' },
        detail: {
          valueAnimation: true, offsetCenter: [0, '-2%'],
          formatter: '{value}%', fontSize: 25, fontWeight: 700, color: baseColor,
        },
        data: [{ value: overall, name: `目标 ${BASELINE_TARGET}%` }],
      }],
    })

    // 数据截至：页面所有数字都是这一刻的快照，写出来免得把旧数据当实时
    updatedAt.value = fmtDateTime(new Date().toISOString()).slice(11)   // HH:MM
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
}

const palette = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899', '#84cc16']

function pieOption(data, name) {
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0, type: 'scroll' },
    series: [{
      name, type: 'pie', radius: ['40%', '68%'], center: ['50%', '45%'],
      data, label: { show: true, formatter: '{b}\n{d}%' },
    }],
  }
}

onMounted(() => {
  setTimeout(renderCharts, 100)
  window.addEventListener('resize', () => charts.forEach((c) => c && c.resize()))
})
onBeforeUnmount(disposeAll)
</script>

<style scoped>
.dashboard { height: 100%; display: flex; flex-direction: column; }
.dashboard :deep(.el-card) { margin-bottom: 0; }
.dashboard :deep(.el-card__body) { padding: 10px; }
.dashboard :deep(.el-card__header) { padding: 8px 12px; }
.stat-row { margin-bottom: 10px; flex-shrink: 0; }
.stat-card .stat-inner { display: flex; align-items: center; gap: 10px; }
/* 可点的卡片给出鼠标手型（否则"能点"只存在于实现里） */
.stat-card.clickable { cursor: pointer; }
.stat-info { min-width: 0; }
.stat-icon { width: 40px; height: 40px; border-radius: 9px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.stat-value { font-size: 20px; font-weight: 700; color: #0f172a; line-height: 1.1; }
/* 标签与第二行小字同一行：卡片高度不变（6 张卡等高，多一行会把整排撑高、错位） */
.stat-label { display: flex; align-items: baseline; gap: 5px; min-width: 0; font-size: 12px; color: #64748b; margin-top: 2px; }
.stat-label > span:first-child { overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
.stat-sub { flex-shrink: 0; font-size: 10px; white-space: nowrap; }
.stat-sub.good { color: #16a34a; }
.stat-sub.bad { color: #dc2626; }
.stat-sub.flat { color: #94a3b8; }
.chart-row { margin-bottom: 10px; flex: 1; min-height: 0; }
.chart-row .el-col { height: 100%; }
.chart-row .el-col .el-card { height: 100%; display: flex; flex-direction: column; }
.chart-row .el-col .el-card :deep(.el-card__body) { flex: 1; min-height: 0; }
.chart-lg, .chart-sm { height: 100%; }
.card-title { font-weight: 600; color: #1e293b; font-size: 13px; }
/* 卡片头部：标题左、补充说明右（说明用 HTML，不占图表画布） */
.card-head-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.dash-updated { font-size: 11px; color: #94a3b8; white-space: nowrap; }
.card-sub {
  font-size: 11px; color: #94a3b8; white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis;
}
/* 基线卡：左环 + 右"按系统"列表（整体数字之外的落点是"哪个系统欠账"）。
   环的宽度按"和旁边两张饼图视觉等大"来定：那两张饼图占满各自卡片宽度、
   直径由卡片高度决定(≈150px)，所以这里给 170px 宽的容器 → 环直径 ≈150px，三张卡看起来才是一套。 */
.base-card { height: 100%; display: flex; align-items: center; gap: 14px; }
.base-gauge { width: 170px; height: 100%; flex-shrink: 0; }
.base-systems { flex: 1; min-width: 0; display: flex; flex-direction: column; justify-content: center; gap: 7px; }
.bsys-caption { font-size: 11px; color: #94a3b8; }
.bsys { display: flex; align-items: center; gap: 8px; font-size: 11.5px; }
.bsys-name {
  width: 68px; flex-shrink: 0; color: #334155;
  overflow: hidden; white-space: nowrap; text-overflow: ellipsis;
}
.bsys-track { flex: 1; height: 7px; border-radius: 999px; background: #eef2f7; overflow: hidden; }
.bsys-track i { display: block; height: 100%; border-radius: 999px; transition: width .4s ease; }
.bsys-pct { width: 40px; text-align: right; font-weight: 600; font-variant-numeric: tabular-nums; }
.bsys-empty, .bsys-more { font-size: 11px; color: #94a3b8; }
</style>
