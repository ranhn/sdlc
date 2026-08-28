<template>
  <div class="dashboard">
    <!-- 统计卡片 -->
    <el-row :gutter="16" class="stat-row">
      <el-col :span="4" v-for="s in statCards" :key="s.label">
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
          <template #header><span class="card-title">安全基线整体合规率</span></template>
          <div ref="statusRef" class="chart-sm"></div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount, reactive } from 'vue'
import * as echarts from 'echarts'
import { dashboardApi, baselineApi } from '../api'

const trendRef = ref()
const topRef = ref()
const sevRef = ref()
const typeRef = ref()
const statusRef = ref()
const trendRange = ref(30)
let charts = []
let trendChart = null

const statCards = reactive([
  { label: '漏洞总数', value: 0, icon: 'Warning', bg: '#eff6ff', color: '#3b82f6' },
  { label: '待修复', value: 0, icon: 'RemoveFilled', bg: '#fef3c7', color: '#f59e0b' },
  { label: '高危', value: 0, icon: 'BellFilled', bg: '#fee2e2', color: '#ef4444' },
  { label: '已修复', value: 0, icon: 'CircleCheck', bg: '#dcfce7', color: '#22c55e' },
  { label: '修复率', value: '0%', icon: 'TrendCharts', bg: '#f3e8ff', color: '#8b5cf6' },
  { label: '平均修复时长', value: '0h', icon: 'Timer', bg: '#ecfeff', color: '#06b6d4' },
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
      baselineApi.stats(),
    ])
    const o = ov.data
    statCards[0].value = o.total
    statCards[1].value = o.open
    statCards[2].value = o.critical + o.high
    statCards[3].value = o.closed
    statCards[4].value = o.fix_rate + '%'
    statCards[5].value = o.avg_fix_hours + 'h'

    renderTrend(t, trend.data)

    // 系统风险排行（横向柱状 TOP5）
    const sys = topR.data.top_systems.slice(0, 5).reverse()
    top.setOption({
      tooltip: {},
      grid: { left: 70, right: 30, top: 10, bottom: 10 },
      xAxis: { type: 'value' },
      yAxis: { type: 'category', data: sys.map((s) => s.name) },
      series: [{
        type: 'bar', data: sys.map((s) => s.risk),
        itemStyle: { color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [{ offset: 0, color: '#3b82f6' }, { offset: 1, color: '#8b5cf6' }]) },
        label: { show: true, position: 'right' },
      }],
    })

    const sevData = dist.data.by_severity.map((i) => ({ name: i.name, value: i.value, itemStyle: { color: severityColor[i.name] || '#94a3b8' } }))
    sev.setOption(pieOption(sevData, '等级'))
    // 漏洞类型分布：TOP5 + 其他
    const sortedTypes = [...dist.data.by_type].sort((a, b) => b.value - a.value)
    const top5 = sortedTypes.slice(0, 5)
    const others = sortedTypes.slice(5)
    const typeData = top5.map((i, idx) => ({ name: i.name, value: i.value, itemStyle: { color: palette[idx % palette.length] } }))
    if (others.length > 0) {
      const othersValue = others.reduce((sum, o) => sum + o.value, 0)
      typeData.push({ name: '其他', value: othersValue, itemStyle: { color: '#94a3b8' } })
    }
    ty.setOption(pieOption(typeData, '类型'))
    // 安全基线整体合规率（仪表盘）
    const blData = bl.data || {}
    const overall = blData.overall ?? 0
    const sysRows = blData.systems || []
    const passSystems = sysRows.filter((s) => s.compliance >= 80).length
    st.setOption({
      tooltip: { trigger: 'item' },
      series: [{
        type: 'gauge',
        startAngle: 210, endAngle: -30,
        min: 0, max: 100,
        radius: '100%', center: ['50%', '55%'],
        progress: { show: true, width: 16 },
        axisLine: { lineStyle: { width: 16, color: [[1, '#e2e8f0']] } },
        pointer: { show: false },
        axisTick: { show: false },
        splitLine: { length: 12, lineStyle: { width: 2, color: '#fff' } },
        axisLabel: { distance: 22, fontSize: 10, color: '#94a3b8' },
        anchor: { show: false },
        title: { show: true, offsetCenter: [0, '30%'], fontSize: 13, color: '#64748b' },
        detail: {
          valueAnimation: true, offsetCenter: [0, '-12%'],
          formatter: '{value}%', fontSize: 34, fontWeight: 700, color: overall >= 80 ? '#22c55e' : overall >= 60 ? '#f59e0b' : '#ef4444',
        },
        data: [{ value: overall, name: `整体合规率 (${passSystems}/${sysRows.length} 系统达标)` }],
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
</style>
