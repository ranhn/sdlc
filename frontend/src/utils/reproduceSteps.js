/**
 * 复现步骤的**存取与展示**：提交页（录入/编辑）、修复页与详情抽屉（展示）共用同一套解析。
 *
 * ## 为什么要有这个文件
 * 后端只有一个文本字段 `reproduce_steps`；"哪张截图属于哪一步"由 `step_screenshots` 里的
 * `step_no` 决定。两边解析如果不一致，就会出现"文字 3 步、截图对到第 2 步"这类错位，
 * 而且页面之间会互相打架 —— 所以解析与配对只能有一份实现。
 *
 * ## 存档格式（编号块）
 * 历史格式是「一行一步」，于是**步骤内部的换行会被当成新步骤**（用户反馈：在步骤 1 的框里
 * 敲回车接着写，展示出来就变成步骤 2）。现在存成：
 *
 *     1. 打开登录页
 *        输入用户名密码
 *     2. 点击提交
 *
 * 即每步以 `1. ` 开头（行首），步骤内部换行原样保留、续行缩进两格。解析只认行首的编号行，
 * 于是用户在步骤正文里自己写「1. xxx」也不会被切开。老数据（没有任何编号行）仍按
 * 「一行一步」解析，历史记录不受影响。
 */

/** 行首的步骤编号：`1.` / `1、` / `1)` / `1）` */
export const STEP_HEAD_RE = /^\d+\s*[.、)）]\s*/

/** 步骤数组 → 存档文本（空文案给「步骤 N」占位，避免整步消失） */
export function stepsToText(steps) {
  return steps
    .map((s, i) => {
      const body = String(s.desc || '').trim() || `步骤 ${i + 1}`
      return `${i + 1}. ` + body.replace(/\n/g, '\n  ')
    })
    .join('\n')
}

/** 存档文本 → 步骤文案数组（新格式按编号块切，老格式一行一步） */
export function parseStepsText(text) {
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

/**
 * 把「步骤文案」与「截图」按步号配对，供展示用（提交页详情、修复页都用它）。
 *
 * 两个刻意的处理：
 *   · **逐条按 parseStepsText 解出的步骤渲染**，而不是遍历 step_screenshots ——
 *     否则"这一步没有截图"时整步会凭空消失（用户反馈踩过）；
 *   · 一步可多张（同一个 step_no 会有多条），顺序按后端返回顺序。
 *
 * @param {object} v 漏洞对象（需要 reproduce_steps 与 step_screenshots）
 * @returns {Array<{step_no:number, desc:string, imgs:string[]}>}
 */
export function stepsWithShots(v) {
  const descs = parseStepsText(v && v.reproduce_steps)
  const shotsByNo = {}
  ;((v && v.step_screenshots) || []).forEach((ss) => {
    if (!ss || !ss.data_url) return
    ;(shotsByNo[ss.step_no] = shotsByNo[ss.step_no] || []).push(ss.data_url)
  })
  return descs.map((desc, i) => ({
    step_no: i + 1,
    desc,
    imgs: shotsByNo[i + 1] || [],
  }))
}
