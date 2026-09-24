/**
 * 安全基线的**共享口径**：达标线 + 合规率档位 / 颜色。
 *
 * 为什么单独抽一个文件：这条 80% 的达标线以前在
 *   · views/Baseline.vue  → const TARGET = 80
 *   · views/Dashboard.vue → const BASELINE_TARGET = 80
 * 各写了一份，只能靠注释互相提醒"改一处要一起改" —— 漏改就会出现
 * "同一个合规率，首页是橙色、基线页是红色"这种不一致。
 * 现在两页 import 同一份，改这里就够了。
 *
 * ⚠️ 与"进度"区分清楚：
 *   · 本文件管的是**合规率**（通过 ÷ 适用项，即 应评 − 不适用）的档位；
 *   · 列表里那些"做没做完"的进度条走另一套规则（有不通过优先红 / 做满绿 / 其余蓝），
 *     见 views/Baseline.vue 的 barColor()。
 */

/** 基线合规率达标线（%）：≥ 该值算达标（绿）。 */
export const BASELINE_TARGET = 80

/**
 * 合规率 → 档位。
 *   good（≥ 达标线）/ mid（≥ 60，接近目标）/ bad（> 0，需重点整改）/ none（= 0，尚未开始）
 * 档位名与 CSS 类名一致（Baseline.vue 的 .rate.good / .ring-num.mid …），
 * 所以模板里可以直接 :class="rateLevel(x)"。
 */
export function rateLevel(percent) {
  const v = Number(percent) || 0
  if (v >= BASELINE_TARGET) return 'good'
  if (v >= 60) return 'mid'
  return v > 0 ? 'bad' : 'none'
}

/** 档位 → 图形颜色（环、进度条）。文字色在 CSS 里，色值与这里刻意保持一致。 */
export const RATE_COLORS = {
  good: '#16a34a',
  mid: '#f59e0b',
  bad: '#dc2626',
  none: '#cbd5e1',
}

/** 合规率 → 颜色（图表/进度条直接用）。 */
export function rateColor(percent) {
  return RATE_COLORS[rateLevel(percent)]
}
