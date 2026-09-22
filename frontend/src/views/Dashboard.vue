<template>
  <div class="dashboard">
    <!-- 统计卡片 -->
    <el-row :gutter="16" class="stat-row">
      <el-col :span="4" v-for="s in statCards" :key="s.label">
        <!-- 口径说明（如「已修复」其实是闭环口径）：鼠标悬停卡片时提示 -->
        <el-tooltip :content="s.tip" placement="bottom" :disabled="!s.tip">
          <el-card shadow="hover" class="stat-card">
            <div class="stat-inner">
              <div class="stat-icon" :style="{ background: s.bg, color: s.color }">
                <el-icon :size="22"><component :is="s.icon" /></el-icon>
              </div>
              <div class="stat-info">
                <div class="stat-value">{{ s.value }}</div>
                <div class="stat-label">{{ s.label }}</div>
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
          <template #header><span class="card-title">漏洞等级分布</span></template>
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
            <div ref="statusRef" class="base-gauge"></div>
            <div class="base-systems">
              <div v-if="baseSystems.length" class="bsys-caption">按系统合规率（低 → 高）</div>
              <div v-for="s in baseSystems" :key="s.system_id" class="bsys"
                   :title="`${s.system_name}：应评 ${s.bound_items} 项 · 通过 ${s.pass_count} / 不通过 ${s.fail_count} / 未评估 ${s.pending_count}`">
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

const trendRef = ref()
const topRef = ref()
const sevRef = ref()
const typeRef = ref()
const statusRef = ref()
const trendRange = ref(30)
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
  { label: '漏洞总数', value: 0, icon: 'Warning', bg: '#eff6ff', color: '#3b82f6' },
  {
    label: '待修复', value: 0, icon: 'RemoveFilled', bg: '#fef3c7', color: '#f59e0b',
    tip: '未闭环（不含草稿）',
  },
  {
    label: '高危', value: 0, icon: 'BellFilled', bg: '#fee2e2', color: '#ef4444',
    // 这张卡取的是"严重 + 高危"两个等级之和，标签只写「高危」容易误解，用短 tip 点明
    tip: '严重 + 高危',
  },
  {
    label: '已修复', value: 0, icon: 'CircleCheck', bg: '#dcfce7', color: '#22c55e',
    // 口径与漏洞列表状态列一致：这几种状态都算"已修复"，趋势图「修复」线同口径。
    // （后端还额外把历史遗留的 ignored 一起计入，但页面上不再提这个状态了）
    tip: '已修复 + 已关闭 + 已驳回',
  },
  {
    label: '修复率', value: '0%', icon: 'TrendCharts', bg: '#f3e8ff', color: '#8b5cf6',
    tip: '已修复 / 漏洞总数',
  },
  {
    // 原为「平均修复时长」：样本只来自已闭环的漏洞，闭环量少（甚至为 0）时数字没有意义，
    // 而显示成 0h 会被读成"修复飞快"（用户反馈"这个数字没有意义"）。换成「待确认」——
    // 修复人还没受理、卡在整条链路第一步的数量，首页上唯一"需要人去推动"的数字
    // （与「漏洞修复」页的「确认 / 驳回」同一环）。
    label: '待确认', value: 0, icon: 'Clock', bg: '#ecfeff', color: '#06b6d4',
    tip: '状态为待确认的漏洞数',
  },
])

const severityColor = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6' }

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
  let st = echarts.init(statusRef.value)
  charts.push(sev, ty, st)
  loadAndRender(t, top, sev, ty, st)
}

function renderTrend(chart, data) {
  const dates = data.map((d) => d.date)
  chart.setOption({
    tooltip: { trigger: 'axis' },
    legend: { data: ['新增', '修复'] },
    grid: { left: 40, right: 20, top: 30, bottom: 30 },
    xAxis: { type: 'category', data: dates },
    yAxis: { type: 'value', minInterval: 1 },
    // 「修复」= 状态为已修复 / 已关闭 / 已驳回 的漏洞（状态列里这几种都算已修复），
    // 与上方「已修复」卡片、修复率同口径，故不再单列「驳回」线
    series: [
      { name: '新增', type: 'line', smooth: true, data: data.map((d) => d.created), itemStyle: { color: '#3b82f6' }, areaStyle: { opacity: 0.1 } },
      { name: '修复', type: 'line', smooth: true, data: data.map((d) => d.fixed), itemStyle: { color: '#22c55e' }, areaStyle: { opacity: 0.1 } },
    ],
  }, true)
}

async function reloadTrend() {
  if (!trendChart) return
  try {
    const trend = await dashboardApi.trend({ days: trendRange.value || undefined })
    renderTrend(trendChart, trend.data)
  } catch (e) { console.error(e) }
}

function disposeAll() {
  charts.forEach((c) => c && c.dispose())
  charts = []
  trendChart = null
}

async function loadAndRender(t, top, sev, ty, st) {
  try {
    const [ov, trend, dist, topR, bl] = await Promise.all([
      dashboardApi.overview(),
      dashboardApi.trend({ days: 30 }),
      dashboardApi.distribution(),
      dashboardApi.top(),
      baselineApi.overview(),   // 与基线页同一口径（按需求绑定范围，见上方注释）
    ])
    const o = ov.data
    statCards[0].value = o.total
    statCards[1].value = o.open
    statCards[2].value = o.critical + o.high
    statCards[3].value = o.fixed_total ?? o.closed
    statCards[4].value = o.fix_rate + '%'
    statCards[5].value = o.pending ?? 0

    renderTrend(t, trend.data)

    // 系统风险排行（横向柱状 TOP5，柱长=漏洞数，更直观；风险分放 tooltip）
    const sys = topR.data.top_systems.slice(0, 5).reverse()
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

    const sevData = dist.data.by_severity.map((i) => ({ name: i.name, value: i.value, itemStyle: { color: severityColor[i.name] || '#94a3b8' } }))
    sev.setOption(pieOption(sevData, '等级'))
    // 漏洞类型分布：按一级大类统计（10 类固定，无需聚合兜底）
    // 注意：不能再用 TOP5+「其他」聚合 —— 分类体系里已存在真实的「其他」大类，会与之撞名导致扇区重复
    const sortedCats = [...(dist.data.by_category || [])].sort((a, b) => b.value - a.value)
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
    const blData = bl.data || {}
    const overall = blData.compliance ?? 0
    const sysCount = blData.system_count ?? 0
    const pendingItems = blData.pending_count ?? 0
    // 头部只写"纳入了多少系统"（目标值已经画在环里了，不重复）
    baselineNote.value = sysCount ? `${sysCount} 个系统已纳入` : '尚未创建基线需求'
    baseSystemsAll.value = blData.systems || []
    // 小环（卡片左侧 ~128px）：去掉刻度与轴标签，只留"底环 + 进度弧 + 中心数字"
    // —— 与「安全基线」页的合规率环同一套视觉；卡片右侧让给"按系统"列表。
    const baseColor = rateColor(overall)      // 档位/颜色来自 utils/baseline.js（与基线页同一份）
    st.setOption({
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
  } catch (e) {
    console.error(e)
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
.stat-icon { width: 40px; height: 40px; border-radius: 9px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.stat-value { font-size: 20px; font-weight: 700; color: #0f172a; line-height: 1.1; }
.stat-label { font-size: 12px; color: #64748b; margin-top: 2px; }
.chart-row { margin-bottom: 10px; flex: 1; min-height: 0; }
.chart-row .el-col { height: 100%; }
.chart-row .el-col .el-card { height: 100%; display: flex; flex-direction: column; }
.chart-row .el-col .el-card :deep(.el-card__body) { flex: 1; min-height: 0; }
.chart-lg, .chart-sm { height: 100%; }
.card-title { font-weight: 600; color: #1e293b; font-size: 13px; }
/* 卡片头部：标题左、补充说明右（说明用 HTML，不占图表画布） */
.card-head-row { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
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
