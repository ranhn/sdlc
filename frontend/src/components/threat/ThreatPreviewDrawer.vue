<template>
  <transition name="tpd-slide">
    <div
      class="tpd"
      :class="{ loading: !detail }"
      @mouseenter="$emit('mouseenter')"
      @mouseleave="$emit('mouseleave')"
    >
      <button class="tpd-close" title="关闭" @click="$emit('close')">×</button>

      <div class="tpd-head">
        <div class="tpd-title">{{ item.title }}</div>
        <div class="tpd-meta">
          <span class="tpd-method">{{ item.methodology }}</span>
          <span class="tpd-time">{{ fmtTime(item.created_at) }}</span>
        </div>
      </div>

      <div class="tpd-sev">
        <div class="tpd-bar" v-if="bySevTotal">
          <div
            v-for="sev in SEV_ORDER"
            :key="sev"
            v-show="bySev[sev]"
            class="tpd-bar-seg"
            :class="'sev-' + sev"
            :style="{ flex: bySev[sev] || 0 }"
            :title="`${tSeverity(sev)} x ${bySev[sev] || 0}`"
          ></div>
        </div>
        <div class="tpd-sev-stats" v-if="bySevTotal">
          <span
            v-for="sev in SEV_ORDER"
            :key="sev"
            v-show="bySev[sev]"
            class="tpd-sev-stat"
            :class="'sev-' + sev"
          >
            <strong>{{ bySev[sev] || 0 }}</strong> {{ tSeverity(sev) }}
          </span>
        </div>
        <div v-else class="tpd-empty">该模型未识别到威胁</div>
      </div>

      <div class="tpd-stats">
        <span class="tpd-stat"><strong>{{ item.stats?.componentCount ?? '-' }}</strong>组件</span>
        <span class="tpd-stat"><strong>{{ item.stats?.flowCount ?? '-' }}</strong>数据流</span>
        <span class="tpd-stat"><strong>{{ item.stats?.threatCount ?? 0 }}</strong>威胁</span>
      </div>

      <div v-if="topThreats.length" class="tpd-threats">
        <div class="tpd-threats-label">高危优先 · Top {{ topThreats.length }}</div>
        <div v-for="(t, i) in topThreats" :key="i" class="tpd-threat">
          <span class="tpd-threat-sev" :class="'sev-' + (t.severity || 'Low')">
            {{ tSeverity(t.severity) }}
          </span>
          <span class="tpd-threat-title" :title="t.title">{{ t.title }}</span>
        </div>
        <div v-if="moreCount" class="tpd-more">
          + 还有 {{ moreCount }} 个威胁 · 点击卡片查看完整
        </div>
      </div>
      <div v-else-if="detail && !topThreats.length" class="tpd-empty">该模型未识别到威胁</div>
      <div v-else class="tpd-empty tpd-loading">加载中…</div>
    </div>
  </transition>
</template>

<script setup>
import { computed } from 'vue'
import { tSeverity } from '../../utils/i18n.js'

const props = defineProps({
  item: { type: Object, required: true },
  detail: { type: Object, default: null },
})
defineEmits(['mouseenter', 'mouseleave', 'close'])

const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low']

const bySev = computed(() => props.item?.stats?.threatCountBySeverity || {})
const bySevTotal = computed(() =>
  Object.values(bySev.value).reduce((a, b) => a + (b || 0), 0)
)

const allThreats = computed(() => {
  if (!props.detail?.model?.detail) return []
  const out = []
  for (const d of props.detail.model.detail.diagrams || []) {
    for (const c of d.cells || []) {
      const cname = c.data?.name || ''
      for (const t of c.threats || []) {
        out.push({ ...t, component: cname })
      }
    }
  }
  return out
})

const topThreats = computed(() => {
  const order = { Critical: 0, High: 1, Medium: 2, Low: 3 }
  return [...allThreats.value]
    .sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9))
    .slice(0, 5)
})

const moreCount = computed(() => Math.max(0, allThreats.value.length - 5))

function fmtTime(epoch) {
  if (!epoch) return ''
  const d = new Date(epoch * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}
</script>

<style scoped>
.tpd {
  position: fixed;
  right: 16px;
  top: 80px;
  width: 360px;
  max-height: calc(100vh - 120px);
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  box-shadow: 0 16px 48px rgba(0, 0, 0, 0.18), 0 0 0 1px rgba(255, 255, 255, 0.04);
  padding: 16px 18px 14px;
  z-index: 90;
  display: flex;
  flex-direction: column;
  gap: 12px;
  overflow-y: auto;
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
}
.tpd-close {
  position: absolute;
  top: 10px;
  right: 10px;
  width: 24px;
  height: 24px;
  display: grid;
  place-items: center;
  background: transparent;
  border: none;
  color: var(--text-faint);
  font-size: 20px;
  line-height: 1;
  cursor: pointer;
  border-radius: 6px;
  transition: all 0.15s;
  font-family: inherit;
}
.tpd-close:hover { background: var(--bg-active); color: var(--text); }

.tpd-head { display: flex; flex-direction: column; gap: 4px; padding-right: 24px; }
.tpd-title {
  font-size: 14px;
  font-weight: 700;
  color: var(--text);
  overflow: hidden;
  text-overflow: ellipsis;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  line-height: 1.35;
}
.tpd-meta { display: flex; align-items: center; gap: 8px; font-size: 11px; color: var(--text-faint); }
.tpd-method {
  padding: 1px 6px;
  border-radius: 8px;
  background: var(--info-soft);
  color: var(--info);
  border: 1px solid var(--info-border);
  font-family: var(--font-mono);
  font-weight: 600;
  font-size: 10px;
}
.tpd-time { font-family: var(--font-mono); }

.tpd-sev { display: flex; flex-direction: column; gap: 6px; }
.tpd-bar {
  display: flex;
  height: 8px;
  border-radius: 4px;
  overflow: hidden;
  background: var(--bg-panel-2);
}
.tpd-bar-seg { transition: flex 0.3s; min-width: 0; }
.tpd-bar-seg.sev-Critical { background: var(--critical); }
.tpd-bar-seg.sev-High     { background: var(--high); }
.tpd-bar-seg.sev-Medium   { background: var(--medium); }
.tpd-bar-seg.sev-Low      { background: var(--low); }
.tpd-sev-stats { display: flex; flex-wrap: wrap; gap: 5px; }
.tpd-sev-stat {
  font-size: 10.5px;
  padding: 2px 7px;
  border-radius: 10px;
  font-weight: 500;
  background: var(--sev-bg, var(--bg-panel-2));
  color: var(--sev-c, var(--text-faint));
  border: 1px solid var(--sev-bd, var(--border));
  font-family: var(--font-mono);
  line-height: 1.2;
}
.tpd-sev-stat strong { font-weight: 700; margin-right: 2px; }

.tpd-stats {
  display: flex;
  gap: 12px;
  padding: 8px 10px;
  background: var(--bg-panel-2);
  border-radius: 6px;
  font-size: 11.5px;
  color: var(--text-dim);
  font-family: var(--font-mono);
}
.tpd-stat strong { color: var(--text); font-weight: 700; margin-right: 2px; }

.tpd-threats { display: flex; flex-direction: column; gap: 5px; }
.tpd-threats-label {
  font-size: 10.5px;
  color: var(--text-faint);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  font-weight: 600;
  margin-bottom: 2px;
}
.tpd-threat {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  padding: 4px 6px;
  border-radius: 5px;
  background: var(--bg-panel-2);
}
.tpd-threat:hover { background: var(--bg-active); }
.tpd-threat-sev {
  font-size: 10px;
  font-weight: 700;
  padding: 1px 6px;
  border-radius: 8px;
  flex-shrink: 0;
  background: var(--sev-bg, var(--bg-panel-2));
  color: var(--sev-c, var(--text-faint));
  border: 1px solid var(--sev-bd, var(--border));
  min-width: 36px;
  text-align: center;
}
.tpd-threat-title {
  color: var(--text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
  min-width: 0;
}
.tpd-more { font-size: 11px; color: var(--text-faint); text-align: center; padding: 4px 0 0; }
.tpd-empty { font-size: 11.5px; color: var(--text-faint); text-align: center; padding: 8px 0; }
.tpd-loading { color: var(--text-faint); font-style: italic; }

/* 严重度色（与 ResultsPanel 一致） */
.sev-Critical { --sev-c: var(--critical); --sev-bg: var(--critical-soft); --sev-bd: var(--critical-border); }
.sev-High     { --sev-c: var(--high);     --sev-bg: var(--high-soft);     --sev-bd: var(--high-border); }
.sev-Medium   { --sev-c: var(--medium);   --sev-bg: var(--medium-soft);   --sev-bd: var(--medium-border); }
.sev-Low      { --sev-c: var(--low);      --sev-bg: var(--low-soft);      --sev-bd: var(--low-border); }

.tpd-slide-enter-active, .tpd-slide-leave-active {
  transition: all 0.2s ease;
}
.tpd-slide-enter-from, .tpd-slide-leave-to {
  opacity: 0;
  transform: translateX(20px);
}
</style>
